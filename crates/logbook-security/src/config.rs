//! Scanner configuration — the `[scanners]` section of `logbook.toml` (plan
//! §9.1).
//!
//! ```toml
//! [scanners]                       # explicit paths; missing binary = soft-degrade, not error
//! semgrep     = "semgrep"
//! trivy       = "trivy"
//! cargo_audit = "cargo-audit"
//! ```
//!
//! Only the binary *paths* live here. Whether a scan is *allowed* to run is a
//! separate concern owned by the `[permissions]` model
//! (`allow_security_scans`, plan §9.1) — the CLI checks that before calling
//! [`crate::security_scan`]; this crate does not re-enforce it.
//!
//! We keep this struct dependency-light (no `toml` crate dependency): callers
//! that already parse `logbook.toml` construct it from the parsed values, and
//! the [`Default`] impl matches the shipped defaults so a crate-internal test
//! or a caller without an explicit config still gets the conventional binary
//! names (resolved against `PATH`).

use serde::{Deserialize, Serialize};

/// The kind of scanner logbook-security knows how to run in v1.
///
/// v1.5+ adds strix / pentagi / codeql / nuclei (plan §7a); those are
/// deliberately **not** modelled here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scanner {
    /// Semgrep static analysis (`semgrep --sarif` / `--json`).
    Semgrep,
    /// Trivy filesystem / dependency / config scan (`trivy fs --format json`).
    Trivy,
    /// `cargo audit --json` (RustSec advisory database).
    CargoAudit,
}

impl Scanner {
    /// All scanners logbook-security runs in v1, in a stable order.
    pub const ALL: [Scanner; 3] = [Scanner::Semgrep, Scanner::Trivy, Scanner::CargoAudit];

    /// The canonical lowercase source tag recorded on findings (matches the
    /// `findings.source` column and the `FindingBlock.source` field).
    #[must_use]
    pub const fn source_tag(self) -> &'static str {
        match self {
            Scanner::Semgrep => "semgrep",
            Scanner::Trivy => "trivy",
            Scanner::CargoAudit => "cargo-audit",
        }
    }

    /// A human-friendly display name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        self.source_tag()
    }
}

/// Resolved binary paths for the v1 scanners.
///
/// Each field is the program logbook will execute. A bare name (e.g.
/// `"semgrep"`) is resolved against the process `PATH`; an absolute path runs
/// that exact binary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannersConfig {
    /// Path / name of the `semgrep` binary.
    #[serde(default = "default_semgrep")]
    pub semgrep: String,
    /// Path / name of the `trivy` binary.
    #[serde(default = "default_trivy")]
    pub trivy: String,
    /// Path / name of the `cargo-audit` binary.
    #[serde(default = "default_cargo_audit", rename = "cargo_audit")]
    pub cargo_audit: String,
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

impl Default for ScannersConfig {
    /// The shipped defaults from `logbook.toml`: the conventional binary names,
    /// resolved against `PATH`.
    fn default() -> Self {
        Self {
            semgrep: default_semgrep(),
            trivy: default_trivy(),
            cargo_audit: default_cargo_audit(),
        }
    }
}

impl ScannersConfig {
    /// The configured program path for a given [`Scanner`].
    #[must_use]
    pub fn program(&self, scanner: Scanner) -> &str {
        match scanner {
            Scanner::Semgrep => &self.semgrep,
            Scanner::Trivy => &self.trivy,
            Scanner::CargoAudit => &self.cargo_audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_shipped_logbook_toml() {
        let c = ScannersConfig::default();
        assert_eq!(c.semgrep, "semgrep");
        assert_eq!(c.trivy, "trivy");
        assert_eq!(c.cargo_audit, "cargo-audit");
    }

    #[test]
    fn program_dispatches_per_scanner() {
        let c = ScannersConfig {
            semgrep: "/opt/semgrep".into(),
            trivy: "trivy".into(),
            cargo_audit: "cargo-audit".into(),
        };
        assert_eq!(c.program(Scanner::Semgrep), "/opt/semgrep");
        assert_eq!(c.program(Scanner::Trivy), "trivy");
        assert_eq!(c.program(Scanner::CargoAudit), "cargo-audit");
    }

    #[test]
    fn deserializes_from_toml_style_table_with_cargo_audit_rename() {
        // serde_json stands in for the `[scanners]` table shape; the key is the
        // snake_case `cargo_audit`, matching logbook.toml.
        let json = r#"{"semgrep":"sg","trivy":"tv","cargo_audit":"ca"}"#;
        let c: ScannersConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.semgrep, "sg");
        assert_eq!(c.cargo_audit, "ca");
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let c: ScannersConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c, ScannersConfig::default());
    }

    #[test]
    fn source_tags_are_stable() {
        assert_eq!(Scanner::Semgrep.source_tag(), "semgrep");
        assert_eq!(Scanner::Trivy.source_tag(), "trivy");
        assert_eq!(Scanner::CargoAudit.source_tag(), "cargo-audit");
    }
}
