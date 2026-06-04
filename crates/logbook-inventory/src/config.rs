//! Minimal reader for the parts of `logbook.toml` the inventory cares about
//! (plan §9.1).
//!
//! The inventory is **local-only, read-only, observe-not-modify**. The only
//! permission it actually gates is the continuous `inventory watch` loop, which
//! requires `[permissions].enabled_writes` to contain `"inventory_watch"`.
//! `scan` and `report` never need a write grant.
//!
//! We deliberately parse only the fields we use and ignore everything else, so
//! this stays compatible as the full schema (browser/dap/security/export gates)
//! grows in sibling crates.

use std::path::Path;

use serde::Deserialize;

use crate::error::Result;

/// The conventional permission-file name at a project / out-dir root.
pub const CONFIG_FILENAME: &str = "logbook.toml";

/// The `enabled_writes` token that turns on continuous `inventory watch`.
pub const INVENTORY_WATCH_WRITE: &str = "inventory_watch";

/// The subset of `logbook.toml` the inventory reads. All sections are optional
/// so a missing or partial file degrades to safe defaults (read-only, redaction
/// on, scanners named by their bare command).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InventoryConfig {
    /// `[permissions]`.
    #[serde(default)]
    pub permissions: Permissions,
    /// `[redaction]`.
    #[serde(default)]
    pub redaction: Redaction,
    /// `[scanners]`.
    #[serde(default)]
    pub scanners: Scanners,
}

/// The `[permissions]` table (only the fields the inventory consults).
///
/// The derived `Default` is the conservative, read-only default: an empty
/// `enabled_writes` (no continuous `watch`, no other write grants).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Permissions {
    /// Subset of `["browser","dap","security","export","inventory_watch"]`.
    /// Empty (the shipped default) = read-only.
    #[serde(default)]
    pub enabled_writes: Vec<String>,
}

impl Permissions {
    /// Whether continuous `inventory watch` is enabled.
    #[must_use]
    pub fn inventory_watch_enabled(&self) -> bool {
        self.enabled_writes
            .iter()
            .any(|w| w == INVENTORY_WATCH_WRITE)
    }
}

/// The `[redaction]` table.
#[derive(Clone, Debug, Deserialize)]
pub struct Redaction {
    /// Redaction master switch. Default **on** (plan §9).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Extra deny patterns (regex).
    #[serde(default)]
    pub deny: Vec<String>,
    /// False-positive exclusions.
    #[serde(default)]
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

/// The `[scanners]` table — explicit binary names/paths; a missing binary is a
/// soft-degrade, not an error (plan §9.1).
#[derive(Clone, Debug, Deserialize)]
pub struct Scanners {
    /// Semgrep command/path.
    #[serde(default = "default_semgrep")]
    pub semgrep: String,
    /// Trivy command/path.
    #[serde(default = "default_trivy")]
    pub trivy: String,
    /// cargo-audit command/path.
    #[serde(default = "default_cargo_audit")]
    pub cargo_audit: String,
}

impl Default for Scanners {
    fn default() -> Self {
        Self {
            semgrep: default_semgrep(),
            trivy: default_trivy(),
            cargo_audit: default_cargo_audit(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_semgrep() -> String {
    "semgrep".to_string()
}
fn default_trivy() -> String {
    "trivy".to_string()
}
fn default_cargo_audit() -> String {
    "cargo-audit".to_string()
}

impl InventoryConfig {
    /// Load from a specific `logbook.toml` path. A genuinely **absent** file
    /// yields the safe defaults silently. A present-but-malformed file, or one
    /// that exists but cannot be read (permission denied, is-a-directory, an
    /// I/O error), also degrades to defaults but is logged at `warn` rather than
    /// being swallowed — so a mis-permissioned config does not silently drop the
    /// user's custom `[redaction]` patterns with no signal. (This posture
    /// mirrors the security-load-bearing `logbook.toml` loader in `logbook-mcp`,
    /// which distinguishes `NotFound` from other read errors.)
    #[must_use]
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str::<InventoryConfig>(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "malformed logbook.toml; using defaults");
                    Self::default()
                }
            },
            // A genuinely missing file is the legitimate default case.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            // Present-but-unreadable (permissions, is-a-directory, I/O): don't
            // swallow it — a defaulted config silently drops custom redaction.
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "could not read logbook.toml; using defaults (custom redaction patterns will not apply)");
                Self::default()
            }
        }
    }

    /// Load from `<dir>/logbook.toml`, falling back to defaults if absent.
    #[must_use]
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Self {
        Self::load(dir.as_ref().join(CONFIG_FILENAME))
    }

    /// Ensure continuous `inventory watch` is permitted; otherwise return
    /// [`crate::InventoryError::WatchNotEnabled`].
    ///
    /// # Errors
    /// Returns [`crate::InventoryError::WatchNotEnabled`] when
    /// `enabled_writes` does not contain `"inventory_watch"`.
    pub fn require_watch_enabled(&self) -> Result<()> {
        if self.permissions.inventory_watch_enabled() {
            Ok(())
        } else {
            Err(crate::error::InventoryError::WatchNotEnabled)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_safe_default() {
        let cfg = InventoryConfig::load("/nonexistent/logbook.toml");
        assert!(cfg.permissions.enabled_writes.is_empty());
        assert!(!cfg.permissions.inventory_watch_enabled());
        assert!(cfg.redaction.enabled, "redaction defaults on");
        assert_eq!(cfg.scanners.semgrep, "semgrep");
    }

    #[test]
    fn default_config_blocks_watch() {
        let cfg = InventoryConfig::default();
        assert!(cfg.require_watch_enabled().is_err());
    }

    #[test]
    fn watch_enabled_when_listed() {
        let toml = r#"
[permissions]
enabled_writes = ["inventory_watch"]
"#;
        let cfg: InventoryConfig = toml::from_str(toml).unwrap();
        assert!(cfg.permissions.inventory_watch_enabled());
        assert!(cfg.require_watch_enabled().is_ok());
    }

    #[test]
    fn parses_shipped_default_file_shape() {
        // Mirrors the repo's committed logbook.toml.
        let toml = r#"
[permissions]
enabled_writes         = []
allowed_domains        = []
allow_browser_sessions = false
allow_dap              = false
allow_security_scans   = false

[ingest]
token_mode = "generated"

[redaction]
enabled = true
deny    = []
allow   = []

[retention]
max_age_days = 14
max_db_mb    = 512

[scanners]
semgrep     = "semgrep"
trivy       = "trivy"
cargo_audit = "cargo-audit"
"#;
        let cfg: InventoryConfig = toml::from_str(toml).expect("shipped shape parses");
        assert!(!cfg.permissions.inventory_watch_enabled());
        assert!(cfg.redaction.enabled);
        assert_eq!(cfg.scanners.cargo_audit, "cargo-audit");
    }

    #[test]
    fn redaction_off_respected() {
        let toml = "[redaction]\nenabled = false\n";
        let cfg: InventoryConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.redaction.enabled);
    }
}
