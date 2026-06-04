//! Per-run ingest bearer token (plan §4, review #v3.1/#v3.2).
//!
//! `POST /ingest` requires `Authorization: Bearer <token>`. The token is:
//! - **`generated`** (default): minted from OS entropy at startup and written
//!   to `collector.token` (`0600`);
//! - **`env`**: taken from `LOGBOOK_INGEST_TOKEN` (also mirrored to
//!   `collector.token`);
//! - **`off`**: no token — **dev/test only**, never a normal option.
//!
//! The token never lands in `collector.json` and the browser never reads
//! `collector.token`; it is injected at runtime (see [`crate::injected`]).

use crate::error::CollectorError;

/// The environment variable consulted in `env` mode (and as an override).
pub const ENV_VAR: &str = "LOGBOOK_INGEST_TOKEN";

/// How the ingest token is sourced (mirrors `logbook.toml [ingest] token_mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenMode {
    /// `LOGBOOK_INGEST_TOKEN` if it is set and non-empty, otherwise a fresh
    /// token minted at startup (default). This is **env-sensitive** — i.e.
    /// "env-or-generate", matching OpenLogs parity; it differs from
    /// [`TokenMode::Env`] only in that an unset variable is not an error.
    #[default]
    Generated,
    /// Require `LOGBOOK_INGEST_TOKEN`; an unset/empty variable is a hard error
    /// ([`CollectorError::MissingEnvToken`]).
    Env,
    /// No token. **Dev/test only** — every `/ingest` request is allowed.
    Off,
}

impl TokenMode {
    /// Parse the `logbook.toml` string form. Unknown values fall back to
    /// `generated` (the safe default).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "env" => TokenMode::Env,
            "off" => TokenMode::Off,
            _ => TokenMode::Generated,
        }
    }
}

/// A resolved ingest token. `None` inside means the token is disabled (`off`).
/// Cheap to clone.
#[derive(Clone, Debug)]
pub struct IngestToken(Option<String>);

impl IngestToken {
    /// Resolve a token for the given mode.
    ///
    /// # Errors
    /// Returns [`CollectorError::MissingEnvToken`] when `mode = Env` but the
    /// variable is unset/empty, or [`CollectorError::TokenGeneration`] if
    /// entropy is unavailable for `Generated`.
    pub fn resolve(mode: TokenMode) -> Result<Self, CollectorError> {
        match mode {
            TokenMode::Off => Ok(Self(None)),
            TokenMode::Env => {
                let v = std::env::var(ENV_VAR).unwrap_or_default();
                if v.trim().is_empty() {
                    Err(CollectorError::MissingEnvToken)
                } else {
                    Ok(Self(Some(v)))
                }
            }
            TokenMode::Generated => {
                // If the env var is present we honor it even in generated mode
                // (parity with OpenLogs' "env if set, else generate").
                if let Ok(v) = std::env::var(ENV_VAR) {
                    if !v.trim().is_empty() {
                        return Ok(Self(Some(v)));
                    }
                }
                Ok(Self(Some(generate_token()?)))
            }
        }
    }

    /// Wrap a known secret (used by tests and callers that already have one).
    #[must_use]
    pub fn from_secret(secret: impl Into<String>) -> Self {
        Self(Some(secret.into()))
    }

    /// A disabled token (`off` mode).
    #[must_use]
    pub fn disabled() -> Self {
        Self(None)
    }

    /// The token string, or `None` when disabled.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Whether a token is required (i.e. not `off`).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }
}

/// Mint a 256-bit token rendered as 64 lowercase hex chars by concatenating two
/// W3C-width trace ids (each 128 bits of OS entropy). Reusing the vetted
/// `logbook_core` generator keeps the entropy source in one place.
fn generate_token() -> Result<String, CollectorError> {
    let a = logbook_core::TraceId::try_new()
        .map_err(|e| CollectorError::TokenGeneration(e.to_string()))?;
    let b = logbook_core::TraceId::try_new()
        .map_err(|e| CollectorError::TokenGeneration(e.to_string()))?;
    Ok(format!("{}{}", a.to_hex(), b.to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// `IngestToken::resolve` reads the process-global `LOGBOOK_INGEST_TOKEN`,
    /// so any test that sets/clears it must run serially. Every env-touching
    /// test holds this guard for its whole body. Poisoning is ignored so one
    /// panicking test doesn't cascade-fail the rest.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Clear `LOGBOOK_INGEST_TOKEN`, run `f`, then restore the prior value.
    /// Keeps the env mutation scoped so other serialized tests see a clean slate.
    fn with_env_unset<T>(f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(ENV_VAR).ok();
        std::env::remove_var(ENV_VAR);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(ENV_VAR, v),
            None => std::env::remove_var(ENV_VAR),
        }
        out
    }

    /// Set `LOGBOOK_INGEST_TOKEN=value`, run `f`, then restore the prior value.
    fn with_env_set<T>(value: &str, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(ENV_VAR).ok();
        std::env::set_var(ENV_VAR, value);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(ENV_VAR, v),
            None => std::env::remove_var(ENV_VAR),
        }
        out
    }

    #[test]
    fn generated_token_is_64_hex_chars() {
        // Route through the REAL `resolve` with the env cleared, so this also
        // exercises the generate branch of `resolve(Generated)`.
        let _g = env_guard();
        let t = with_env_unset(|| IngestToken::resolve(TokenMode::Generated)).unwrap();
        let s = t.as_str().unwrap();
        assert_eq!(s.len(), 64, "256-bit token = 64 hex chars");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn two_generated_tokens_differ() {
        let _g = env_guard();
        let (a, b) = with_env_unset(|| {
            let a = IngestToken::resolve(TokenMode::Generated)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            let b = IngestToken::resolve(TokenMode::Generated)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            (a, b)
        });
        assert_ne!(a, b, "tokens must be unpredictable / distinct");
    }

    #[test]
    fn generated_mode_honors_env_token_when_set() {
        // The subtle "env if set, else generate" override (token.rs:66-74): a
        // present LOGBOOK_INGEST_TOKEN must be returned verbatim even in
        // Generated mode, NOT replaced by a fresh random token.
        let _g = env_guard();
        let t = with_env_set("env-supplied-token", || {
            IngestToken::resolve(TokenMode::Generated)
        })
        .unwrap();
        assert_eq!(t.as_str(), Some("env-supplied-token"));
    }

    #[test]
    fn generated_mode_ignores_blank_env_token() {
        // A whitespace-only env var is treated as unset, so Generated falls back
        // to minting a fresh 64-hex token rather than honoring the blank value.
        let _g = env_guard();
        let t = with_env_set("   ", || IngestToken::resolve(TokenMode::Generated)).unwrap();
        let s = t.as_str().unwrap();
        assert_eq!(s.len(), 64);
        assert_ne!(s.trim(), "", "blank env must not become the token");
    }

    #[test]
    fn env_mode_errors_when_unset() {
        // Fail-closed: Env mode with no variable is a hard error, never a
        // silently-disabled (None) token.
        let _g = env_guard();
        let err = with_env_unset(|| IngestToken::resolve(TokenMode::Env)).unwrap_err();
        assert!(
            matches!(err, CollectorError::MissingEnvToken),
            "Env mode must fail closed when unset, got: {err:?}"
        );
    }

    #[test]
    fn env_mode_errors_when_blank() {
        // An empty/whitespace variable is also rejected (same fail-closed path).
        let _g = env_guard();
        let err = with_env_set("   ", || IngestToken::resolve(TokenMode::Env)).unwrap_err();
        assert!(matches!(err, CollectorError::MissingEnvToken));
    }

    #[test]
    fn env_mode_honors_set_token() {
        let _g = env_guard();
        let t = with_env_set("the-env-token", || IngestToken::resolve(TokenMode::Env)).unwrap();
        assert_eq!(t.as_str(), Some("the-env-token"));
        assert!(t.is_enabled());
    }

    #[test]
    fn off_mode_has_no_token() {
        // Off mode does not consult the env at all; assert that explicitly.
        let _g = env_guard();
        let t = with_env_set("ignored-in-off-mode", || IngestToken::resolve(TokenMode::Off))
            .unwrap();
        assert!(t.as_str().is_none());
        assert!(!t.is_enabled());
    }

    #[test]
    fn parse_mode_strings() {
        assert_eq!(TokenMode::parse("env"), TokenMode::Env);
        assert_eq!(TokenMode::parse("OFF"), TokenMode::Off);
        assert_eq!(TokenMode::parse("generated"), TokenMode::Generated);
        assert_eq!(TokenMode::parse("garbage"), TokenMode::Generated);
    }
}
