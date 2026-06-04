//! `logbook security ...` — scan runner + SARIF/JSON import (plan §7a, §12),
//! wired to `logbook-security`.
//!
//! Two subcommands:
//! - `import <file>` — ingest an existing SARIF document; **no permission
//!   gate** (importing already-produced output is read-shaped).
//! - `scan [target]` — run Semgrep / Trivy / cargo-audit on demand. This is a
//!   *write* operation (it shells out to scanners) and is **gated** behind
//!   `[permissions].allow_security_scans` + `"security"` in `enabled_writes`
//!   (plan §5, §9.1). The CLI owns this gate; the crate does not re-enforce it.
//!
//! Every finding lands as an `Event{category:security}` on the timeline and a
//! row in the `findings` table.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Deserialize;

use logbook_mcp::{McpConfig, Permissions, WriteCategory};
use logbook_security::{import_sarif, security_scan, ScanReport, ScanStatus, ScannersConfig};
use logbook_store::Store;

/// Exit code returned when `security scan` could not actually scan: either no
/// scanner ran successfully, or (under `--strict`) some scanner errored. This
/// is distinct from `1` (a hard error / `Err`) so CI can tell a *failed-to-run*
/// scan apart from a generic failure, and never reads a false "clean" green.
const SCAN_INCOMPLETE_EXIT: i32 = 2;

/// `logbook security <subcommand>`.
#[derive(Debug, Args)]
pub struct SecurityArgs {
    /// Out-dir holding the logbook store findings are written to.
    #[arg(long, global = true, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root holding `logbook.toml` (permissions + `[scanners]`).
    #[arg(long, global = true, default_value = ".")]
    pub root: PathBuf,

    /// The security subcommand.
    #[command(subcommand)]
    pub command: SecurityCommand,
}

/// `security` subcommands.
#[derive(Debug, Subcommand)]
pub enum SecurityCommand {
    /// Import a SARIF document, persisting each result as a security finding.
    Import(ImportArgs),
    /// Run the configured scanners over a target directory (permission-gated).
    Scan(ScanArgs),
}

/// `security import <file>`.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Path to the SARIF (`.sarif` / JSON) document to import.
    pub file: PathBuf,
}

/// `security scan [target]`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Directory to scan. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Fail closed: exit non-zero if *any* scanner errored (not just when none
    /// ran). Use this in CI so a partially-broken scan never reads as a clean
    /// pass. Without it, scanner errors are warned about but the exit code
    /// still reflects only whether *anything* scanned successfully.
    #[arg(long)]
    pub strict: bool,
}

/// Dispatch a `security` invocation.
///
/// # Errors
/// Returns an error if the store cannot be opened, a permission gate blocks a
/// scan, or import/persistence fails.
pub fn run(args: SecurityArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;
    match &args.command {
        SecurityCommand::Import(import_args) => {
            let result = import_sarif(&store, &import_args.file)?;
            println!(
                "imported {} finding(s) from {} (trace {}).",
                result.imported,
                import_args.file.display(),
                result.trace_id
            );
            Ok(0)
        }
        SecurityCommand::Scan(scan_args) => {
            // Permission gate (plan §5, §9.1): the CLI enforces it before the
            // crate is asked to shell out to any scanner.
            let perms = load_permissions(&args.root)?;
            if !perms.category_enabled(WriteCategory::Security) {
                anyhow::bail!(
                    "security scans are disabled: add \"security\" to \
                     [permissions].enabled_writes and set allow_security_scans = true \
                     in {}/logbook.toml",
                    args.root.display()
                );
            }

            let scanners = load_scanners_config(&args.root);
            let outcome = security_scan(&store, &scanners, &scan_args.target)?;

            // Audit trail: print one line per scanner (incl. soft-degrades).
            for note in &outcome.report.notes {
                println!("  [{:?}] {}", note.status, note.note);
            }
            println!(
                "security scan complete: {} finding(s) persisted (trace {}).",
                outcome.imported.imported, outcome.imported.trace_id
            );

            // Fail closed. A security tool must never present a clean "complete"
            // result when scanners errored or nothing actually ran — that is a
            // dangerous false-negative in CI.
            report_scan_health(&outcome.report, scan_args.strict)
        }
    }
}

/// Inspect a [`ScanReport`] and decide the exit code, emitting loud stderr
/// warnings for any non-clean state. Returns the exit code to surface.
///
/// Outcomes:
/// - **all scanners missing** (`all_missing`): the documented soft-degrade —
///   warn that nothing was scanned, but succeed (exit `0`).
/// - **nothing ran but a scanner errored** (`!any_ran` && not all-missing): the
///   false-clean case — warn loudly and exit non-zero so CI fails closed.
/// - **some ran, some `Failed`**: name the failed scanners; exit non-zero only
///   under `--strict`, otherwise warn and succeed.
/// - **clean** (everything that was present ran): exit `0`.
fn report_scan_health(report: &ScanReport, strict: bool) -> anyhow::Result<i32> {
    let failed: Vec<&str> = report
        .notes
        .iter()
        .filter(|n| n.status == ScanStatus::Failed)
        .map(|n| n.scanner.display_name())
        .collect();

    if report.all_missing() {
        eprintln!(
            "logbook: note — no scanner binaries were found on PATH; \
             nothing was scanned (soft-degrade)."
        );
        return Ok(0);
    }

    if !report.any_ran() && !failed.is_empty() {
        // No scanner produced a result and at least one errored: the result is
        // NOT a clean bill of health. Fail closed regardless of --strict.
        // (An empty report, or one with no failures, falls through to Ok below;
        // the all-missing soft-degrade is already handled above.)
        eprintln!(
            "logbook: ERROR — no scanner ran successfully; {} scanner(s) failed ({}). \
             The scan did NOT complete and findings may be incomplete; treat this as a \
             failed scan, not a clean result.",
            failed.len(),
            failed.join(", ")
        );
        return Ok(SCAN_INCOMPLETE_EXIT);
    }

    if !failed.is_empty() {
        eprintln!(
            "logbook: WARNING — {} scanner(s) failed and were skipped ({}); \
             findings from those scanners are missing.",
            failed.len(),
            failed.join(", ")
        );
        if strict {
            eprintln!("logbook: --strict is set; failing because a scanner errored.");
            return Ok(SCAN_INCOMPLETE_EXIT);
        }
    }

    Ok(0)
}

/// Load `[permissions]` from `<root>/logbook.toml` (missing file = read-only).
fn load_permissions(root: &std::path::Path) -> anyhow::Result<Permissions> {
    let cfg = McpConfig::load_from_root(root)?;
    Ok(cfg.permissions().clone())
}

/// The `[scanners]` table of `logbook.toml`, parsed standalone. The security
/// crate keeps its config TOML-free, so the CLI does the parsing and hands over
/// resolved binary paths. A missing file / table falls back to the shipped
/// defaults (conventional binary names resolved against `PATH`).
#[derive(Debug, Default, Deserialize)]
struct ScannersTable {
    #[serde(default)]
    scanners: Option<ScannersConfig>,
}

fn load_scanners_config(root: &std::path::Path) -> ScannersConfig {
    let path = root.join("logbook.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ScannersConfig::default();
    };
    match toml::from_str::<ScannersTable>(&text) {
        Ok(t) => t.scanners.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, "could not parse [scanners]; using defaults");
            ScannersConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `ScanReport` and `ScanStatus` are already in scope via `super::*`; only
    // these two are additionally needed by the test fixtures.
    use logbook_security::{ScanNote, Scanner};

    fn note(scanner: Scanner, status: ScanStatus) -> ScanNote {
        ScanNote {
            scanner,
            program: scanner.display_name().to_string(),
            status,
            note: format!("{scanner:?} {status:?}"),
            findings: 0,
        }
    }

    fn report(statuses: &[(Scanner, ScanStatus)]) -> ScanReport {
        ScanReport {
            findings: Vec::new(),
            notes: statuses.iter().map(|&(s, st)| note(s, st)).collect(),
        }
    }

    #[test]
    fn scan_health_ok_when_all_ran() {
        let r = report(&[
            (Scanner::Semgrep, ScanStatus::Ran),
            (Scanner::Trivy, ScanStatus::Ran),
        ]);
        assert_eq!(report_scan_health(&r, false).unwrap(), 0);
        assert_eq!(report_scan_health(&r, true).unwrap(), 0);
    }

    #[test]
    fn scan_health_ok_when_all_missing_soft_degrade() {
        // Every scanner binary absent is the documented soft-degrade: succeed.
        let r = report(&[
            (Scanner::Semgrep, ScanStatus::SkippedMissing),
            (Scanner::Trivy, ScanStatus::SkippedMissing),
            (Scanner::CargoAudit, ScanStatus::SkippedMissing),
        ]);
        assert_eq!(report_scan_health(&r, false).unwrap(), 0);
        assert_eq!(report_scan_health(&r, true).unwrap(), 0);
    }

    #[test]
    fn scan_health_fails_closed_when_nothing_ran_but_a_scanner_failed() {
        // The false-clean case the finding describes: two missing + one Failed,
        // zero successful runs. Must NOT report a clean exit 0, even without
        // --strict.
        let r = report(&[
            (Scanner::Trivy, ScanStatus::SkippedMissing),
            (Scanner::CargoAudit, ScanStatus::SkippedMissing),
            (Scanner::Semgrep, ScanStatus::Failed),
        ]);
        assert_eq!(report_scan_health(&r, false).unwrap(), SCAN_INCOMPLETE_EXIT);
        assert_eq!(report_scan_health(&r, true).unwrap(), SCAN_INCOMPLETE_EXIT);
        assert!(!r.any_ran());
        assert!(!r.all_missing());
    }

    #[test]
    fn scan_health_partial_failure_exit_depends_on_strict() {
        // Some ran, one Failed: warn, but only fail the build under --strict.
        let r = report(&[
            (Scanner::Semgrep, ScanStatus::Ran),
            (Scanner::Trivy, ScanStatus::Failed),
        ]);
        assert_eq!(report_scan_health(&r, false).unwrap(), 0);
        assert_eq!(report_scan_health(&r, true).unwrap(), SCAN_INCOMPLETE_EXIT);
    }

    #[test]
    fn scan_health_empty_report_is_ok() {
        // No scanners configured/attempted at all: nothing failed, succeed.
        let r = ScanReport::default();
        assert_eq!(report_scan_health(&r, false).unwrap(), 0);
        assert_eq!(report_scan_health(&r, true).unwrap(), 0);
    }

    #[test]
    fn scan_arg_strict_parses() {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            cmd: SecurityCommand,
        }
        let t = T::try_parse_from(["x", "scan", "--strict", "/tmp"]).unwrap();
        match t.cmd {
            SecurityCommand::Scan(a) => {
                assert!(a.strict);
                assert_eq!(a.target, PathBuf::from("/tmp"));
            }
            SecurityCommand::Import(_) => panic!("expected scan"),
        }
    }

    #[test]
    fn scanners_table_parses_with_rename() {
        let toml = r#"
            [scanners]
            semgrep = "sg"
            trivy = "tv"
            cargo_audit = "ca"
        "#;
        let t: ScannersTable = toml::from_str(toml).unwrap();
        let c = t.scanners.unwrap();
        assert_eq!(c.semgrep, "sg");
        assert_eq!(c.trivy, "tv");
        assert_eq!(c.cargo_audit, "ca");
    }

    #[test]
    fn scanners_table_defaults_when_absent() {
        let t: ScannersTable = toml::from_str("[permissions]\nenabled_writes = []\n").unwrap();
        assert!(t.scanners.is_none());
    }

    #[test]
    fn missing_file_yields_default_scanners() {
        let dir = tempfile::tempdir().unwrap();
        let c = load_scanners_config(dir.path());
        assert_eq!(c, ScannersConfig::default());
    }

    #[test]
    fn scan_gate_blocks_when_permission_absent() {
        // A root with no logbook.toml => read-only default => scan blocked.
        let dir = tempfile::tempdir().unwrap();
        let perms = load_permissions(dir.path()).unwrap();
        assert!(!perms.category_enabled(WriteCategory::Security));
    }

    #[test]
    fn scan_gate_allows_when_fully_enabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("logbook.toml"),
            "[permissions]\nenabled_writes = [\"security\"]\nallow_security_scans = true\n",
        )
        .unwrap();
        let perms = load_permissions(dir.path()).unwrap();
        assert!(perms.category_enabled(WriteCategory::Security));
    }
}
