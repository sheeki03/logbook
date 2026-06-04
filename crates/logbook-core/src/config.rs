//! The single canonical `logbook.toml` schema (plan §9.1).
//!
//! Historically `logbook.toml` was parsed independently by `logbook-mcp`,
//! `logbook-inventory`, and `logbook-security`, each with its own
//! partially-overlapping structs, its own `CONFIG_FILENAME` const, and its own
//! missing-file-fallback loader. That let the two `[permissions]` views and the
//! duplicated `[scanners]` defaults drift apart. This module is the one home for
//! the whole schema so every crate can depend on the same field names and the
//! same load semantics.
//!
//! # Schema (the §9.1 example)
//! ```toml
//! [permissions]
//! enabled_writes         = ["security", "export"]
//! allowed_domains        = ["example.test"]
//! allow_browser_sessions = false
//! allow_dap              = false
//! allow_security_scans   = false
//!
//! [ingest]
//! token_mode = "generated"
//!
//! [redaction]
//! enabled = true
//! deny    = []
//! allow   = []
//!
//! [retention]
//! max_age_days = 14
//! max_db_mb    = 512
//!
//! [scanners]
//! semgrep     = "semgrep"
//! trivy       = "trivy"
//! cargo_audit = "cargo-audit"
//! ```
//!
//! # Load semantics
//! A **missing file is not an error** — it yields [`LogbookConfig::default`]
//! (the strict, read-only, redaction-on posture). A present-but-unreadable file
//! (permission denied, is-a-directory, …) or malformed TOML *is* a hard
//! [`ConfigError`]; callers that prefer to soft-degrade can map that to
//! `default()` themselves, but the default loader fails closed so a typo can't
//! silently widen permissions.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The conventional config filename, resolved against a workspace / out-dir
/// root.
pub const CONFIG_FILENAME: &str = "logbook.toml";

/// The `enabled_writes` token that turns on the continuous `inventory watch`
/// loop.
pub const INVENTORY_WATCH_WRITE: &str = "inventory_watch";

/// The full `logbook.toml` document. Every section is optional and defaults to
/// the safe posture, so a partial file degrades gracefully.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogbookConfig {
    /// `[permissions]` — the write-tool / watch permission model.
    pub permissions: Permissions,
    /// `[ingest]` — collector ingest settings.
    pub ingest: Ingest,
    /// `[redaction]` — secret-redaction switch and extra patterns.
    pub redaction: Redaction,
    /// `[retention]` — store retention limits.
    pub retention: Retention,
    /// `[scanners]` — security scanner binary names/paths.
    pub scanners: Scanners,
}

/// The `[permissions]` table (plan §9.1). All fields default to the strictest,
/// read-only posture so an absent table (or absent file) yields read-only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Permissions {
    /// Subset of the write categories to advertise
    /// (`browser`/`dap`/`security`/`export`/`inventory_watch`). Empty =
    /// read-only.
    pub enabled_writes: Vec<String>,
    /// Egress allowlist for browser navigation/replay. Empty blocks all
    /// external navigation (enforced by the browser write tools).
    pub allowed_domains: Vec<String>,
    /// Gate for browser session/navigate/replay/screenshot. Must be `true` *in
    /// addition to* listing `browser` in `enabled_writes`.
    pub allow_browser_sessions: bool,
    /// Gate for DAP logpoints (alpha). Must be `true` in addition to listing
    /// `dap` in `enabled_writes`.
    pub allow_dap: bool,
    /// Gate for `security_scan` / `scan_agent_diff`. Must be `true` in addition
    /// to listing `security` in `enabled_writes`.
    pub allow_security_scans: bool,
}

impl Permissions {
    /// Whether `enabled_writes` contains the given category token.
    #[must_use]
    pub fn lists_write(&self, token: &str) -> bool {
        self.enabled_writes.iter().any(|w| w == token)
    }

    /// Whether continuous `inventory watch` is enabled (listed in
    /// `enabled_writes`).
    #[must_use]
    pub fn inventory_watch_enabled(&self) -> bool {
        self.lists_write(INVENTORY_WATCH_WRITE)
    }
}

/// The `[ingest]` table — collector ingest settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ingest {
    /// Ingest-token mode (`generated` | `env` | `off`). Defaults to
    /// `generated`.
    pub token_mode: String,
}

impl Default for Ingest {
    fn default() -> Self {
        Self {
            token_mode: "generated".to_string(),
        }
    }
}

/// The `[redaction]` table — the secret-redaction master switch and extra
/// user-supplied patterns. Redaction is **on by default** (plan §9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Redaction {
    /// Redaction master switch. Default **on**.
    pub enabled: bool,
    /// Extra deny patterns (regex) to redact beyond the built-ins.
    pub deny: Vec<String>,
    /// False-positive exclusions (regex) to *keep* despite a built-in match.
    pub allow: Vec<String>,
}

impl Default for Redaction {
    fn default() -> Self {
        Self {
            enabled: true,
            deny: Vec::new(),
            allow: Vec::new(),
        }
    }
}

/// The `[retention]` table — store retention limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Retention {
    /// Maximum age of retained events, in days.
    pub max_age_days: u32,
    /// Maximum on-disk store size, in megabytes.
    pub max_db_mb: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_age_days: 14,
            max_db_mb: 512,
        }
    }
}

/// The `[scanners]` table — explicit binary names/paths for the v1 security
/// scanners. A bare name resolves against `PATH`; an absolute path runs that
/// exact binary. A missing binary is a soft-degrade, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Scanners {
    /// Path / name of the `semgrep` binary.
    pub semgrep: String,
    /// Path / name of the `trivy` binary.
    pub trivy: String,
    /// Path / name of the `cargo-audit` binary. The TOML key is `cargo_audit`.
    pub cargo_audit: String,
}

impl Default for Scanners {
    fn default() -> Self {
        Self {
            semgrep: "semgrep".to_string(),
            trivy: "trivy".to_string(),
            cargo_audit: "cargo-audit".to_string(),
        }
    }
}

impl LogbookConfig {
    /// Resolve the config path inside a root directory.
    #[must_use]
    pub fn path_in_root(root: impl AsRef<Path>) -> PathBuf {
        root.as_ref().join(CONFIG_FILENAME)
    }

    /// Parse a config from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] on malformed TOML or a schema mismatch.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load from an explicit file path.
    ///
    /// A **missing file is not an error** — it yields [`Self::default`]. A
    /// present-but-unreadable file or malformed TOML returns a [`ConfigError`]
    /// (fail closed).
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file exists but cannot be read or parsed.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }

    /// Load `<root>/logbook.toml`.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file exists but cannot be read or parsed.
    pub fn load_from_root(root: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::load_from_file(Self::path_in_root(root))
    }

    /// Load `<root>/logbook.toml`, soft-degrading to [`Self::default`] on **any**
    /// read or parse error (a missing, unreadable, or malformed file all yield
    /// defaults).
    ///
    /// Use this on best-effort read paths (e.g. the inventory scanner) where a
    /// bad config should not abort the operation; prefer [`Self::load_from_root`]
    /// on security-load-bearing paths that must fail closed.
    #[must_use]
    pub fn load_from_root_or_default(root: impl AsRef<Path>) -> Self {
        Self::load_from_file(Self::path_in_root(root)).unwrap_or_default()
    }
}

/// Errors loading or parsing `logbook.toml`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file exists but could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file exists but is not valid TOML / does not match the schema.
    #[error("failed to parse logbook.toml: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_strict_and_redaction_on() {
        let cfg = LogbookConfig::default();
        assert!(cfg.permissions.enabled_writes.is_empty());
        assert!(!cfg.permissions.inventory_watch_enabled());
        assert!(cfg.redaction.enabled);
        assert_eq!(cfg.scanners.semgrep, "semgrep");
        assert_eq!(cfg.scanners.cargo_audit, "cargo-audit");
        assert_eq!(cfg.ingest.token_mode, "generated");
        assert_eq!(cfg.retention.max_age_days, 14);
        assert_eq!(cfg.retention.max_db_mb, 512);
    }

    #[test]
    fn missing_file_yields_default() {
        let cfg = LogbookConfig::load_from_root("/nonexistent-dir-xyz").unwrap();
        assert_eq!(cfg, LogbookConfig::default());
    }

    #[test]
    fn full_schema_from_plan_parses() {
        let text = r#"
            [permissions]
            enabled_writes         = ["security", "export"]
            allowed_domains        = ["example.test"]
            allow_browser_sessions = false
            allow_dap              = false
            allow_security_scans   = true

            [ingest]
            token_mode = "generated"

            [redaction]
            enabled = true
            deny    = ["foo[0-9]+"]
            allow   = []

            [retention]
            max_age_days = 30
            max_db_mb    = 1024

            [scanners]
            semgrep     = "semgrep"
            trivy       = "/opt/trivy"
            cargo_audit = "cargo-audit"
        "#;
        let cfg = LogbookConfig::parse(text).unwrap();
        assert_eq!(
            cfg.permissions.enabled_writes,
            vec!["security".to_string(), "export".to_string()]
        );
        assert!(cfg.permissions.allow_security_scans);
        assert!(cfg.permissions.lists_write("export"));
        assert!(!cfg.permissions.inventory_watch_enabled());
        assert_eq!(cfg.permissions.allowed_domains, vec!["example.test".to_string()]);
        assert_eq!(cfg.redaction.deny, vec!["foo[0-9]+".to_string()]);
        assert_eq!(cfg.retention.max_age_days, 30);
        assert_eq!(cfg.scanners.trivy, "/opt/trivy");
    }

    #[test]
    fn partial_file_keeps_defaults_for_absent_sections() {
        let cfg = LogbookConfig::parse("[redaction]\nenabled = false\n").unwrap();
        assert!(!cfg.redaction.enabled);
        // Untouched sections keep their safe defaults.
        assert!(cfg.permissions.enabled_writes.is_empty());
        assert_eq!(cfg.scanners.semgrep, "semgrep");
        assert_eq!(cfg.ingest.token_mode, "generated");
    }

    #[test]
    fn inventory_watch_token() {
        let cfg = LogbookConfig::parse(
            "[permissions]\nenabled_writes = [\"inventory_watch\"]\n",
        )
        .unwrap();
        assert!(cfg.permissions.inventory_watch_enabled());
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(LogbookConfig::parse("this is = = not toml").is_err());
    }

    #[test]
    fn cargo_audit_key_is_snake_case() {
        let cfg = LogbookConfig::parse("[scanners]\ncargo_audit = \"ca\"\n").unwrap();
        assert_eq!(cfg.scanners.cargo_audit, "ca");
    }
}
