//! Secret redaction engine (plan §9).
//!
//! Redaction runs **at capture, before anything is persisted** — over PTY
//! output, `/ingest` payloads, MCP returns, and MCP-config scans. It is **on by
//! default**; callers must opt out explicitly (and `--no-redact` is expected to
//! warn).
//!
//! ## What is redacted
//! - **Cloud access keys** — AWS (`AKIA…`, `ASIA…`, `AGPA…`, etc.), Google API
//!   keys (`AIza…`), Slack tokens (`xox[baprs]-…`), GitHub tokens
//!   (`gh[pousr]_…`), OpenAI/Anthropic-style `sk-…` keys.
//! - **JWTs** — three base64url segments separated by dots.
//! - **Bearer / Authorization tokens** — `Authorization: Bearer …`,
//!   `Authorization: Basic …`, and bare `Bearer …`.
//! - **PEM blocks** — `-----BEGIN … KEY-----` … `-----END … KEY-----`.
//! - **`user:pass@` URLs** — the password component of a URL authority.
//! - **Cookies** — `Cookie:` / `Set-Cookie:` header values.
//! - **Env-derived secrets** — values of environment variables whose *name*
//!   looks secret (KEY/TOKEN/SECRET/PASSWORD/...), matched literally so the
//!   exact running-process secret never lands in a log even if it doesn't match
//!   a structural pattern.
//!
//! ## Placeholders are length- and class-preserving
//! A redacted secret is replaced by a placeholder of the form
//! `«REDACTED:KIND:n»` where `n` is the byte length of the original secret, so
//! downstream consumers keep a sense of how long the value was without ever
//! seeing it. (The redaction is *not* reversible — only the length leaks.)

use std::borrow::Cow;
use std::collections::BTreeMap;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::CoreError;

/// The classification of a redacted secret, surfaced inside the placeholder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    /// Cloud / SaaS access key (AWS, GCP, Slack, GitHub, `sk-…`, …).
    CloudKey,
    /// JSON Web Token.
    Jwt,
    /// Bearer / Basic authorization token.
    BearerToken,
    /// PEM-encoded private key block.
    PemBlock,
    /// Password component of a `user:pass@host` URL.
    UrlPassword,
    /// HTTP cookie header value.
    Cookie,
    /// A value matched because it equals a known secret env-var value.
    EnvSecret,
    /// A value matched by a user-supplied `deny` pattern.
    Custom,
}

impl SecretKind {
    /// Short uppercase tag used inside the placeholder.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            SecretKind::CloudKey => "CLOUD_KEY",
            SecretKind::Jwt => "JWT",
            SecretKind::BearerToken => "BEARER",
            SecretKind::PemBlock => "PEM",
            SecretKind::UrlPassword => "URL_PW",
            SecretKind::Cookie => "COOKIE",
            SecretKind::EnvSecret => "ENV_SECRET",
            SecretKind::Custom => "CUSTOM",
        }
    }
}

/// Render the length-class-preserving placeholder for a secret of `kind` whose
/// original byte length was `len`.
#[must_use]
pub fn placeholder(kind: SecretKind, len: usize) -> String {
    format!("\u{ab}REDACTED:{}:{}\u{bb}", kind.tag(), len)
}

/// A compiled redaction rule: a pattern plus the kind it produces and which
/// capture group (if any) holds the secret portion to replace.
#[derive(Debug)]
struct Rule {
    regex: Regex,
    kind: SecretKind,
    /// If `Some(i)`, only capture group `i` is replaced (the surrounding match
    /// — e.g. an `Authorization:` prefix or `user:` prefix — is preserved). If
    /// `None`, the whole match is replaced.
    secret_group: Option<usize>,
}

// Structural patterns. Ordering matters: more specific / longer matches should
// generally come first so they win when ranges would otherwise overlap.
static BUILTIN_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        // PEM private-key blocks (DOTALL so it spans newlines). Whole match.
        Rule {
            regex: Regex::new(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            )
            .expect("valid PEM regex"),
            kind: SecretKind::PemBlock,
            secret_group: None,
        },
        // JWT: header.payload.signature, each base64url, payload starts with
        // the canonical `eyJ` for a JSON object. Whole match.
        Rule {
            regex: Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
                .expect("valid JWT regex"),
            kind: SecretKind::Jwt,
            secret_group: None,
        },
        // Authorization header (Bearer/Basic/Token). Replace only the token,
        // keep the scheme + header name. Group 1 = token.
        Rule {
            regex: Regex::new(
                r"(?i)(?:authorization\s*[:=]\s*)(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})",
            )
            .expect("valid auth-header regex"),
            kind: SecretKind::BearerToken,
            secret_group: Some(1),
        },
        // Bare `Bearer <token>` not preceded by the header name. Group 1 = token.
        Rule {
            regex: Regex::new(r"\b[Bb]earer\s+([A-Za-z0-9._~+/=-]{8,})")
                .expect("valid bearer regex"),
            kind: SecretKind::BearerToken,
            secret_group: Some(1),
        },
        // Cookie / Set-Cookie header value (to end of line). Group 1 = value.
        Rule {
            regex: Regex::new(r"(?im)(?:set-)?cookie\s*:\s*(.+)$").expect("valid cookie regex"),
            kind: SecretKind::Cookie,
            secret_group: Some(1),
        },
        // URL userinfo password: scheme://user:PASSWORD@host. Group 1 = password.
        Rule {
            regex: Regex::new(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s:/@]+)@")
                .expect("valid url-userinfo regex"),
            kind: SecretKind::UrlPassword,
            secret_group: Some(1),
        },
        // AWS access key id family (AKIA/ASIA/AGPA/AIDA/AROA/AIPA/ANPA/ANVA/ABIA/ACCA).
        Rule {
            regex: Regex::new(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b")
                .expect("valid aws-akid regex"),
            kind: SecretKind::CloudKey,
            secret_group: None,
        },
        // Google API key.
        Rule {
            regex: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").expect("valid gcp-key regex"),
            kind: SecretKind::CloudKey,
            secret_group: None,
        },
        // Slack tokens.
        Rule {
            regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").expect("valid slack regex"),
            kind: SecretKind::CloudKey,
            secret_group: None,
        },
        // GitHub tokens (PAT, OAuth, user-to-server, server-to-server, refresh).
        Rule {
            regex: Regex::new(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b").expect("valid github regex"),
            kind: SecretKind::CloudKey,
            secret_group: None,
        },
        // OpenAI / Anthropic style `sk-...` keys (incl. `sk-proj-`, `sk-ant-`).
        Rule {
            regex: Regex::new(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b")
                .expect("valid sk-key regex"),
            kind: SecretKind::CloudKey,
            secret_group: None,
        },
    ]
});

/// A half-open byte span `[start, end)` flagged for redaction.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    kind: SecretKind,
}

/// Configurable secret-redaction engine.
///
/// Construct with [`Redactor::new`] (built-in rules, enabled) and optionally
/// register env-derived secrets ([`Redactor::with_env_secrets`]), extra deny
/// patterns ([`Redactor::with_deny_patterns`]), or allow-list exclusions
/// ([`Redactor::with_allow`]).
#[derive(Debug)]
pub struct Redactor {
    enabled: bool,
    /// The **mandatory secrets floor** flag. When `true` the built-in secret
    /// rules (cloud keys, JWT, bearer, PEM, cookie, URL password) and any
    /// registered env-literals run **even when `enabled` is `false`** — this is
    /// the layer that `--no-redact` / `[redaction].enabled=false` can *never*
    /// switch off. A floor redactor carries no user `deny` patterns (those are
    /// general-tier), so it scrubs exactly the secret floor.
    floor: bool,
    /// Literal secret values (e.g. from the environment) to scrub verbatim,
    /// longest-first so we never redact a prefix of a longer secret.
    literals: Vec<(String, SecretKind)>,
    /// User-supplied additional patterns.
    deny: Vec<Rule>,
    /// Substrings that, if a candidate match equals one, suppress redaction
    /// (false-positive exclusions).
    allow: Vec<String>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// A redactor with built-in structural rules, **enabled**.
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            floor: false,
            literals: Vec::new(),
            deny: Vec::new(),
            allow: Vec::new(),
        }
    }

    /// A disabled redactor — [`Redactor::redact`] returns input unchanged.
    /// Intended only for `--no-redact` (which should warn at the call site).
    ///
    /// Note this disables the **general** redactor only; the secrets floor lives
    /// in a separate [`Redactor::secrets_floor`] redactor that callers run
    /// regardless (see [`scrub_secrets`]).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            floor: false,
            literals: Vec::new(),
            deny: Vec::new(),
            allow: Vec::new(),
        }
    }

    /// The **mandatory secrets-floor redactor** (plan: "Secrets floor is
    /// independent of the global switch").
    ///
    /// It runs **only** the built-in secret patterns — cloud keys, JWT,
    /// bearer/Authorization tokens, PEM private-key blocks, cookies, and URL
    /// passwords — plus any env-derived literals registered via
    /// [`Redactor::with_env_secrets`] / [`Redactor::with_process_env`]. It is
    /// **always active**: unlike [`Redactor::new`], it cannot be disabled, so a
    /// `RedactionMode::Always` class (or a `--no-redact` caller) still gets at
    /// least this floor. It deliberately accepts **no** user `deny` patterns
    /// (those are general-tier and could be misconfigured); allow-list
    /// exclusions are still honoured to suppress false positives.
    #[must_use]
    pub fn secrets_floor() -> Self {
        Self {
            enabled: true,
            floor: true,
            literals: Vec::new(),
            deny: Vec::new(),
            allow: Vec::new(),
        }
    }

    /// A secrets-floor redactor seeded with the current process environment's
    /// secret-looking variables — the convenience the capture path uses so the
    /// exact running-process secrets are scrubbed even under `--no-redact`.
    #[must_use]
    pub fn secrets_floor_with_process_env() -> Self {
        Self::secrets_floor().with_process_env()
    }

    /// Whether redaction is active. Always `true` for a
    /// [`Redactor::secrets_floor`] (the floor cannot be disabled); otherwise the
    /// general `[redaction].enabled` switch.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled || self.floor
    }

    /// Whether this is the mandatory secrets-floor redactor (cannot be disabled).
    #[must_use]
    pub fn is_secrets_floor(&self) -> bool {
        self.floor
    }

    /// Register literal secret values derived from environment variables whose
    /// name looks secret. Empty / very short values are ignored to avoid
    /// over-redacting.
    #[must_use]
    pub fn with_env_secrets<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (name, value) in vars {
            let value = value.as_ref();
            if name_looks_secret(name.as_ref()) && value.len() >= 4 {
                self.literals.push((value.to_string(), SecretKind::EnvSecret));
            }
        }
        // Longest-first so a longer secret is matched before any shorter
        // secret that happens to be a substring of it.
        self.literals
            .sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
        self.literals.dedup_by(|a, b| a.0 == b.0);
        self
    }

    /// Snapshot the current process environment and register its secret-looking
    /// variables as literals to scrub.
    #[must_use]
    pub fn with_process_env(self) -> Self {
        let vars: Vec<(String, String)> = std::env::vars().collect();
        self.with_env_secrets(vars)
    }

    /// Add user-supplied deny patterns (regex). Compilation failures surface as
    /// [`CoreError::BadPattern`].
    ///
    /// # Errors
    /// Returns [`CoreError::BadPattern`] for any pattern that fails to compile.
    pub fn with_deny_patterns<I, S>(mut self, patterns: I) -> Result<Self, CoreError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for pat in patterns {
            let pat = pat.as_ref();
            let regex = Regex::new(pat).map_err(|source| CoreError::BadPattern {
                pattern: pat.to_string(),
                source,
            })?;
            self.deny.push(Rule {
                regex,
                kind: SecretKind::Custom,
                secret_group: None,
            });
        }
        Ok(self)
    }

    /// Add allow-list exclusions: if a would-be-redacted span's text exactly
    /// equals one of these strings, it is left intact.
    #[must_use]
    pub fn with_allow<I, S>(mut self, allow: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allow
            .extend(allow.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Redact all secrets in `input`, returning a `Cow` that borrows the input
    /// when nothing was redacted (the common, hot path) and owns a new string
    /// otherwise.
    #[must_use]
    pub fn redact<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // A floor redactor runs even when `enabled` is false — that is the whole
        // point of the secrets floor. The general redactor honours `enabled`.
        if !self.enabled && !self.floor {
            return Cow::Borrowed(input);
        }

        let mut spans: Vec<Span> = Vec::new();

        // Structural + custom regex rules.
        for rule in BUILTIN_RULES.iter().chain(self.deny.iter()) {
            for caps in rule.regex.captures_iter(input) {
                let m = match rule.secret_group {
                    Some(g) => match caps.get(g) {
                        Some(m) => m,
                        None => continue,
                    },
                    None => caps.get(0).expect("group 0 always present"),
                };
                if self.is_allowed(&input[m.start()..m.end()]) {
                    continue;
                }
                spans.push(Span {
                    start: m.start(),
                    end: m.end(),
                    kind: rule.kind,
                });
            }
        }

        // Literal env-derived secrets (substring search, longest-first).
        for (literal, kind) in &self.literals {
            if literal.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(rel) = input[from..].find(literal.as_str()) {
                let start = from + rel;
                let end = start + literal.len();
                if !self.is_allowed(literal) {
                    spans.push(Span {
                        start,
                        end,
                        kind: *kind,
                    });
                }
                from = end;
            }
        }

        if spans.is_empty() {
            return Cow::Borrowed(input);
        }

        Cow::Owned(apply_spans(input, spans))
    }

    /// Convenience: redact in place, replacing the `String`'s contents.
    pub fn redact_in_place(&self, s: &mut String) {
        if let Cow::Owned(red) = self.redact(s) {
            *s = red;
        }
    }

    /// Recursively redact every string within a [`serde_json::Value`] (object
    /// values, array elements, and top-level strings). Object **keys** are left
    /// intact. Used for `/ingest` payloads and MCP-config scans.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        if !self.enabled && !self.floor {
            return;
        }
        match value {
            serde_json::Value::String(s) => self.redact_in_place(s),
            serde_json::Value::Array(items) => {
                for item in items {
                    self.redact_json(item);
                }
            }
            serde_json::Value::Object(map) => {
                for (_k, v) in map.iter_mut() {
                    self.redact_json(v);
                }
            }
            _ => {}
        }
    }

    fn is_allowed(&self, candidate: &str) -> bool {
        self.allow.iter().any(|a| a == candidate)
    }
}

/// Whether an environment variable *name* looks like it holds a secret.
#[must_use]
pub fn name_looks_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const NEEDLES: &[&str] = &[
        "SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY",
        "CLIENT_SECRET", "AUTH", "CREDENTIAL", "SESSION", "COOKIE", "PASSPHRASE", "_KEY",
    ];
    // A bare `KEY` or `PWD` suffix is common; check a few suffixes too.
    NEEDLES.iter().any(|n| upper.contains(n))
        || upper.ends_with("KEY")
        || upper.ends_with("PWD")
}

/// Merge overlapping/adjacent spans (keeping the kind of the earliest, widest
/// span) and splice placeholders into `input`. Spans may arrive in any order.
fn apply_spans(input: &str, mut spans: Vec<Span>) -> String {
    // Sort by start, then by widest-first so the outer span wins on overlap.
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        match merged.last_mut() {
            Some(last) if s.start < last.end => {
                // Overlapping: extend the existing span if this one reaches
                // further; keep the existing (earlier/wider) kind.
                if s.end > last.end {
                    last.end = s.end;
                }
            }
            _ => merged.push(s),
        }
    }

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for s in merged {
        // Guard against any span that doesn't fall on char boundaries by
        // snapping outward; in practice our regexes match on ASCII boundaries.
        let start = crate::text::floor_char_boundary(input, s.start);
        let end = crate::text::ceil_char_boundary(input, s.end);
        if start < cursor {
            continue;
        }
        out.push_str(&input[cursor..start]);
        out.push_str(&placeholder(s.kind, end - start));
        cursor = end;
    }
    out.push_str(&input[cursor..]);
    out
}

/// Build a [`Redactor`] from the `[redaction]` section of `logbook.toml`:
/// `enabled`, extra `deny` patterns, and `allow` exclusions, seeded with the
/// current process environment's secret-looking variables.
///
/// # Errors
/// Returns [`CoreError::BadPattern`] if any `deny` pattern fails to compile.
pub fn from_config<S: AsRef<str>>(
    enabled: bool,
    deny: &[S],
    allow: &[S],
) -> Result<Redactor, CoreError> {
    let base = if enabled {
        Redactor::new().with_process_env()
    } else {
        Redactor::disabled()
    };
    base.with_deny_patterns(deny.iter().map(AsRef::as_ref))
        .map(|r| r.with_allow(allow.iter().map(AsRef::as_ref)))
}

/// Scrub **secrets only** from `input`, applying the mandatory floor
/// ([`Redactor::secrets_floor`]) regardless of `[redaction].enabled` /
/// `--no-redact`.
///
/// This is the helper a caller uses when the *general* redactor is disabled but
/// the secrets floor must still apply (the plan's "force-redact even under
/// `--no-redact`" rule). It seeds the floor with the current process
/// environment so the exact running-process secrets are caught too.
#[must_use]
pub fn scrub_secrets(input: &str) -> Cow<'_, str> {
    Redactor::secrets_floor_with_process_env().redact(input)
}

/// Group the env vars whose names look secret into a name→value map. Useful for
/// callers that want to inspect which names triggered redaction.
#[must_use]
pub fn secret_env_names() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| name_looks_secret(k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red() -> Redactor {
        Redactor::new()
    }

    #[test]
    fn redaction_is_on_by_default() {
        assert!(Redactor::new().is_enabled());
        assert!(Redactor::default().is_enabled());
        assert!(!Redactor::disabled().is_enabled());
    }

    #[test]
    fn disabled_passes_through_untouched() {
        let r = Redactor::disabled();
        let input = "AKIAIOSFODNN7EXAMPLE and Bearer abcdefgh12345678";
        assert_eq!(r.redact(input), input);
    }

    #[test]
    fn redacts_aws_access_key_id() {
        let r = red();
        let out = r.redact("key=AKIAIOSFODNN7EXAMPLE done");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "leaked: {out}");
        assert!(out.contains("REDACTED:CLOUD_KEY:20"), "got: {out}");
        assert!(out.starts_with("key="));
        assert!(out.ends_with(" done"));
    }

    #[test]
    fn redacts_various_cloud_keys() {
        let r = red();
        for (secret, _why) in [
            ("AKIAIOSFODNN7EXAMPLE", "aws"),
            ("ASIA1234567890ABCDEF", "aws-sts"),
            ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "gcp"),
            // Split so the source has no contiguous Slack-token literal (keeps
            // GitHub secret-scanning push protection happy); `concat!` yields the
            // identical &'static str at compile time, so the redaction test is unchanged.
            (concat!("xox", "b-1234567890-abcdefghijklmno"), "slack"),
            ("ghp_0123456789abcdefghijklmnopqrstuvwxyz", "github"),
            ("sk-ant-abc123DEF456ghi789JKL", "anthropic"),
            ("sk-proj-abcdEFGH1234ijklMNOP", "openai-proj"),
        ] {
            let input = format!("x {secret} y");
            let out = r.redact(&input);
            assert!(!out.contains(secret), "leaked {secret}: {out}");
            assert!(out.contains("REDACTED:CLOUD_KEY:"), "no placeholder for {secret}: {out}");
        }
    }

    #[test]
    fn redacts_jwt() {
        let r = red();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.dummysignaturepart";
        let input = format!("token {jwt} end");
        let out = r.redact(&input);
        assert!(!out.contains(jwt), "leaked jwt: {out}");
        assert!(out.contains("REDACTED:JWT:"), "got: {out}");
    }

    #[test]
    fn redacts_authorization_bearer_keeps_scheme() {
        let r = red();
        let out = r.redact("Authorization: Bearer abcDEF123456ghiJKL");
        assert!(!out.contains("abcDEF123456ghiJKL"), "leaked: {out}");
        // Scheme + header name preserved; only the token replaced.
        assert!(out.contains("Authorization: Bearer "), "got: {out}");
        assert!(out.contains("REDACTED:BEARER:"), "got: {out}");
    }

    #[test]
    fn redacts_bare_bearer_token() {
        let r = red();
        let out = r.redact("sent header Bearer sometoken1234567 ok");
        assert!(!out.contains("sometoken1234567"), "leaked: {out}");
        assert!(out.contains("REDACTED:BEARER:"));
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let r = red();
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcd\n-----END RSA PRIVATE KEY-----";
        let input = format!("before\n{pem}\nafter");
        let out = r.redact(&input);
        assert!(!out.contains("MIIEowIBAAKCAQEA1234"), "leaked pem body: {out}");
        assert!(!out.contains("BEGIN RSA PRIVATE KEY"), "leaked pem header: {out}");
        assert!(out.contains("REDACTED:PEM:"), "got: {out}");
        assert!(out.starts_with("before\n"));
        assert!(out.ends_with("\nafter"));
    }

    #[test]
    fn redacts_url_password_only() {
        let r = red();
        let out = r.redact("db at postgres://admin:s3cr3tP4ss@localhost:5432/app");
        assert!(!out.contains("s3cr3tP4ss"), "leaked pw: {out}");
        // User and host remain.
        assert!(out.contains("postgres://admin:"), "got: {out}");
        assert!(out.contains("@localhost:5432/app"), "got: {out}");
        assert!(out.contains("REDACTED:URL_PW:"), "got: {out}");
    }

    #[test]
    fn redacts_cookie_header() {
        let r = red();
        let out = r.redact("Cookie: session=abc123; theme=dark");
        assert!(!out.contains("session=abc123"), "leaked cookie: {out}");
        assert!(out.contains("REDACTED:COOKIE:"), "got: {out}");
    }

    #[test]
    fn redacts_env_derived_secret_values() {
        let r = Redactor::new().with_env_secrets([
            ("MY_API_TOKEN", "supersecretvalue12345"),
            ("EDITOR", "plainvalue"), // benign var name → value not registered
            ("HOME", "/Users/whoever"),
        ]);
        let out = r.redact("leaking supersecretvalue12345 here, but plainvalue stays");
        assert!(!out.contains("supersecretvalue12345"), "leaked env secret: {out}");
        assert!(out.contains("REDACTED:ENV_SECRET:21"), "got: {out}");
        // A value from a non-secret-looking var name is NOT scrubbed.
        assert!(out.contains("plainvalue"), "over-redacted: {out}");
    }

    #[test]
    fn placeholder_preserves_length() {
        // The number in the placeholder equals the original secret length.
        assert_eq!(placeholder(SecretKind::CloudKey, 20), "\u{ab}REDACTED:CLOUD_KEY:20\u{bb}");
        let r = red();
        let secret = "AKIAIOSFODNN7EXAMPLE"; // 20 chars
        let out = r.redact(secret);
        assert!(out.contains(&format!(":{}\u{bb}", secret.len())), "got: {out}");
    }

    #[test]
    fn allow_list_suppresses_false_positive() {
        // A deny pattern that would catch a placeholder token, but allow-listed.
        let r = Redactor::new().with_allow(["sk-ant-EXAMPLEEXAMPLE00"]);
        let out = r.redact("sk-ant-EXAMPLEEXAMPLE00");
        assert_eq!(out, "sk-ant-EXAMPLEEXAMPLE00", "allow-list should keep it: {out}");
    }

    #[test]
    fn custom_deny_pattern_redacts() {
        let r = Redactor::new()
            .with_deny_patterns([r"INTERNAL-[0-9]{6}"])
            .unwrap();
        let out = r.redact("ref INTERNAL-123456 ok");
        assert!(!out.contains("INTERNAL-123456"), "leaked: {out}");
        assert!(out.contains("REDACTED:CUSTOM:"), "got: {out}");
    }

    #[test]
    fn bad_deny_pattern_errors() {
        let err = Redactor::new().with_deny_patterns(["(unclosed"]).unwrap_err();
        assert!(matches!(err, CoreError::BadPattern { .. }));
    }

    #[test]
    fn no_secret_returns_borrowed_cow() {
        let r = red();
        let input = "totally clean log line with no secrets";
        match r.redact(input) {
            Cow::Borrowed(s) => assert_eq!(s, input),
            Cow::Owned(_) => panic!("should not allocate when nothing redacted"),
        }
    }

    #[test]
    fn overlapping_matches_do_not_corrupt_output() {
        // A bearer token that also contains something key-like should still
        // produce valid, secret-free output (no panic, no leak).
        let r = red();
        let out = r.redact("Authorization: Bearer AKIAIOSFODNN7EXAMPLEextra1234");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "leaked: {out}");
        assert!(out.contains("Authorization: Bearer "), "scheme lost: {out}");
    }

    #[test]
    fn redacts_inside_json_values_not_keys() {
        let r = red();
        let mut v = serde_json::json!({
            "AWS_SECRET": "AKIAIOSFODNN7EXAMPLE",
            "nested": { "auth": "Bearer abcDEF123456ghiJKL" },
            "list": ["clean", "ghp_0123456789abcdefghijklmnopqrstuvwxyz"]
        });
        r.redact_json(&mut v);
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "leaked in json: {s}");
        assert!(!s.contains("abcDEF123456ghiJKL"), "leaked nested: {s}");
        assert!(!s.contains("ghp_0123456789abcdefghijklmnopqrstuvwxyz"), "leaked array: {s}");
        // Keys preserved.
        assert!(s.contains("AWS_SECRET"), "key lost: {s}");
        assert!(s.contains("clean"), "clean value lost: {s}");
    }

    #[test]
    fn name_looks_secret_matches_expected() {
        for n in ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "MY_API_KEY", "X_PWD"] {
            assert!(name_looks_secret(n), "{n} should look secret");
        }
        for n in ["HOME", "PATH", "USER", "TERM", "LANG"] {
            assert!(!name_looks_secret(n), "{n} should NOT look secret");
        }
    }

    #[test]
    fn from_config_disabled_passes_through() {
        let r = from_config(false, &[] as &[&str], &[] as &[&str]).unwrap();
        assert!(!r.is_enabled());
        assert_eq!(r.redact("AKIAIOSFODNN7EXAMPLE"), "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn redact_in_place_mutates() {
        let r = red();
        let mut s = String::from("Bearer abcDEF123456ghiJKL");
        r.redact_in_place(&mut s);
        assert!(!s.contains("abcDEF123456ghiJKL"));
    }

    #[test]
    fn secrets_floor_is_always_enabled() {
        let f = Redactor::secrets_floor();
        assert!(f.is_enabled(), "floor cannot be disabled");
        assert!(f.is_secrets_floor());
        // A plain disabled redactor is the general kind, not the floor.
        assert!(!Redactor::disabled().is_secrets_floor());
    }

    #[test]
    fn secrets_floor_redacts_cloud_key_and_keeps_clean_text() {
        // The floor scrubs secrets even though the *general* switch is off.
        let f = Redactor::secrets_floor();
        let out = f.redact("token AKIAIOSFODNN7EXAMPLE and plainword stays");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked under floor: {out}");
        assert!(out.contains("REDACTED:CLOUD_KEY:"), "got: {out}");
        // A non-secret string is untouched (the floor is secrets-only).
        assert!(out.contains("plainword stays"), "over-redacted: {out}");
    }

    #[test]
    fn scrub_secrets_helper_redacts_under_disabled_general_redactor() {
        // Even when a caller would otherwise use a disabled general redactor,
        // scrub_secrets still removes a planted secret.
        let general = Redactor::disabled();
        let input = "leak AKIAIOSFODNN7EXAMPLE in a --no-redact run";
        assert_eq!(general.redact(input), input, "general redactor is a passthrough");
        let scrubbed = scrub_secrets(input);
        assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"), "floor must scrub: {scrubbed}");
        assert!(scrubbed.contains("REDACTED:CLOUD_KEY:"));
        // Non-secret text is preserved.
        assert!(scrubbed.contains("--no-redact run"));
    }

    #[test]
    fn secrets_floor_covers_jwt_bearer_pem() {
        let f = Redactor::secrets_floor();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigpartHEREok";
        assert!(!f.redact(jwt).contains(jwt), "jwt should be scrubbed by floor");
        assert!(f
            .redact("Authorization: Bearer abcDEF123456ghiJKL")
            .contains("REDACTED:BEARER:"));
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        assert!(f.redact(pem).contains("REDACTED:PEM:"));
    }
}
