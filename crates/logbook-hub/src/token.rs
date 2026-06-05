//! The hub bearer token — the fleet-receiver auth model (plan "Phase 4" → Hub:
//! "collector's loopback+token model for many endpoints").
//!
//! This mirrors the collector's [`IngestToken`](logbook_collector::IngestToken)
//! design exactly — a resolved `Option<secret>`, sourced `generated` (default) /
//! `env` / `off`, with the same fail-closed `env`-mode behavior — but is the
//! hub's *own* token (`LOGBOOK_HUB_TOKEN`) so a deployment can give the fleet
//! receiver a distinct credential from a local `/ingest` collector. Endpoints
//! forward to `POST /hub/ingest` with `Authorization: Bearer <token>`.
//!
//! The hub crate does not depend on `logbook-collector`, so the token type is
//! reproduced here rather than imported; the entropy source ([`TraceId`]) and
//! the constant-time comparison (in [`crate::server`]) are the same vetted code.

/// The environment variable consulted in `env` mode (and as an override in
/// `generated` mode). Distinct from the collector's `LOGBOOK_INGEST_TOKEN`.
pub const HUB_TOKEN_ENV: &str = "LOGBOOK_HUB_TOKEN";

/// How the hub bearer token is sourced. Mirrors the collector's
/// [`TokenMode`](logbook_collector::TokenMode).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenMode {
    /// `LOGBOOK_HUB_TOKEN` if set and non-empty, otherwise a fresh token minted
    /// at startup (default). "env-or-generate": an unset variable is not an
    /// error.
    #[default]
    Generated,
    /// Require `LOGBOOK_HUB_TOKEN`; an unset/empty variable is a hard error
    /// ([`HubError::MissingEnvToken`](crate::HubError::MissingEnvToken)).
    Env,
    /// No token. **Dev/test only** — every `/hub/ingest` request is allowed.
    Off,
}

impl TokenMode {
    /// Parse the string form (`logbook.toml`). Unknown values fall back to
    /// `generated` (the safe default), matching the collector.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "env" => TokenMode::Env,
            "off" => TokenMode::Off,
            _ => TokenMode::Generated,
        }
    }
}

/// A resolved hub bearer token. `None` inside means the token is disabled
/// (`off`). Cheap to clone.
#[derive(Clone, Debug)]
pub struct HubToken(Option<String>);

impl HubToken {
    /// Resolve a token for the given mode.
    ///
    /// # Errors
    /// Returns [`HubError::MissingEnvToken`](crate::HubError::MissingEnvToken)
    /// when `mode = Env` but the variable is unset/empty, or
    /// [`HubError::TokenGeneration`](crate::HubError::TokenGeneration) if entropy
    /// is unavailable for `Generated`.
    pub fn resolve(mode: TokenMode) -> crate::Result<Self> {
        match mode {
            TokenMode::Off => Ok(Self(None)),
            TokenMode::Env => {
                let v = std::env::var(HUB_TOKEN_ENV).unwrap_or_default();
                if v.trim().is_empty() {
                    Err(crate::HubError::MissingEnvToken { var: HUB_TOKEN_ENV })
                } else {
                    Ok(Self(Some(v)))
                }
            }
            TokenMode::Generated => {
                // env-if-set, else generate (parity with the collector).
                if let Ok(v) = std::env::var(HUB_TOKEN_ENV) {
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
/// W3C-width trace ids (each 128 bits of OS entropy). Reuses the vetted
/// `logbook_core` generator, exactly as the collector does.
fn generate_token() -> crate::Result<String> {
    let a = logbook_core::TraceId::try_new()
        .map_err(|e| crate::HubError::TokenGeneration(e.to_string()))?;
    let b = logbook_core::TraceId::try_new()
        .map_err(|e| crate::HubError::TokenGeneration(e.to_string()))?;
    Ok(format!("{}{}", a.to_hex(), b.to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// `HubToken::resolve` reads the process-global `LOGBOOK_HUB_TOKEN`, so any
    /// test that sets/clears it must run serially.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_env_unset<T>(f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(HUB_TOKEN_ENV).ok();
        std::env::remove_var(HUB_TOKEN_ENV);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(HUB_TOKEN_ENV, v),
            None => std::env::remove_var(HUB_TOKEN_ENV),
        }
        out
    }

    fn with_env_set<T>(value: &str, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(HUB_TOKEN_ENV).ok();
        std::env::set_var(HUB_TOKEN_ENV, value);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(HUB_TOKEN_ENV, v),
            None => std::env::remove_var(HUB_TOKEN_ENV),
        }
        out
    }

    #[test]
    fn generated_token_is_64_hex_chars() {
        let _g = env_guard();
        let t = with_env_unset(|| HubToken::resolve(TokenMode::Generated)).unwrap();
        let s = t.as_str().unwrap();
        assert_eq!(s.len(), 64, "256-bit token = 64 hex chars");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn two_generated_tokens_differ() {
        let _g = env_guard();
        let (a, b) = with_env_unset(|| {
            let a = HubToken::resolve(TokenMode::Generated)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            let b = HubToken::resolve(TokenMode::Generated)
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
        let _g = env_guard();
        let t = with_env_set("env-supplied-hub-token", || {
            HubToken::resolve(TokenMode::Generated)
        })
        .unwrap();
        assert_eq!(t.as_str(), Some("env-supplied-hub-token"));
    }

    #[test]
    fn env_mode_errors_when_unset() {
        let _g = env_guard();
        let err = with_env_unset(|| HubToken::resolve(TokenMode::Env)).unwrap_err();
        assert!(
            matches!(err, crate::HubError::MissingEnvToken { .. }),
            "Env mode must fail closed when unset, got: {err:?}"
        );
    }

    #[test]
    fn off_mode_has_no_token() {
        let _g = env_guard();
        let t = with_env_set("ignored-in-off-mode", || HubToken::resolve(TokenMode::Off)).unwrap();
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
