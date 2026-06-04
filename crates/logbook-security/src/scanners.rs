//! On-demand scanner execution (plan §7a) with **soft degradation**.
//!
//! v1 runs three scanners over a target directory:
//! - **Semgrep** — `semgrep --json --quiet --config auto <path>` (we parse
//!   native Semgrep JSON; `--sarif` would also work via [`crate::sarif`], but
//!   native JSON carries Semgrep's own severity directly).
//! - **Trivy** — `trivy fs --quiet --format json <path>`.
//! - **cargo-audit** — `cargo-audit audit --json` run *in* `<path>` (it reads
//!   `Cargo.lock` from the working directory).
//!
//! ## Soft degradation (the central contract, plan §9.1)
//! A **missing scanner binary is not an error.** When the program named in
//! `[scanners]` cannot be found on `PATH` (spawn fails with
//! [`std::io::ErrorKind::NotFound`]), the scanner is recorded as
//! [`ScanStatus::SkippedMissing`] with a human-readable [`ScanNote`], and the
//! overall scan continues with whatever other scanners are present. Only a
//! genuinely unexpected failure (a spawn error that is *not* "not found", or
//! output that fails to parse) is surfaced — and even then per-scanner, so one
//! broken scanner never sinks the others.

use std::path::Path;
use std::process::{Command, Output};

use serde::Deserialize;

use logbook_core::Severity;

use crate::config::{Scanner, ScannersConfig};
use crate::finding::Finding;

/// The outcome of attempting to run a single scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStatus {
    /// The scanner ran and its output was parsed (it may have produced zero
    /// findings — a clean result).
    Ran,
    /// The scanner binary was not found on `PATH`; soft-degraded.
    SkippedMissing,
    /// The scanner ran but something went wrong (non-NotFound spawn error, or
    /// output that did not parse). Recorded, not fatal.
    Failed,
}

/// A per-scanner record on a [`ScanReport`]: what we tried, what happened, and
/// a human-readable note (especially for the soft-degrade case).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanNote {
    /// Which scanner this note is about.
    pub scanner: Scanner,
    /// The program path we attempted to run.
    pub program: String,
    /// What happened.
    pub status: ScanStatus,
    /// Human-readable detail (e.g. "binary `semgrep` not found on PATH —
    /// skipped").
    pub note: String,
    /// Number of findings this scanner contributed.
    pub findings: usize,
}

/// The result of a [`run_scanners`] / [`crate::security_scan`] invocation: the
/// normalized findings plus a per-scanner audit trail. **No scanner being
/// present is still a successful (empty) report** — the notes explain why.
#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    /// All normalized findings, across every scanner that ran.
    pub findings: Vec<Finding>,
    /// One note per scanner attempted.
    pub notes: Vec<ScanNote>,
}

impl ScanReport {
    /// Whether at least one scanner actually ran.
    #[must_use]
    pub fn any_ran(&self) -> bool {
        self.notes.iter().any(|n| n.status == ScanStatus::Ran)
    }

    /// Whether every configured scanner was soft-degraded (missing binary).
    #[must_use]
    pub fn all_missing(&self) -> bool {
        !self.notes.is_empty()
            && self
                .notes
                .iter()
                .all(|n| n.status == ScanStatus::SkippedMissing)
    }
}

/// Run all v1 scanners over `target` with the given binary paths, returning a
/// [`ScanReport`]. Never hard-errors on a missing or broken scanner — see the
/// module docs.
#[must_use]
pub fn run_scanners(config: &ScannersConfig, target: &Path) -> ScanReport {
    let mut report = ScanReport::default();
    for scanner in Scanner::ALL {
        run_one(scanner, config, target, &mut report);
    }
    report
}

/// Run a single named scanner over `target`.
#[must_use]
pub fn run_scanner(scanner: Scanner, config: &ScannersConfig, target: &Path) -> ScanReport {
    let mut report = ScanReport::default();
    run_one(scanner, config, target, &mut report);
    report
}

fn run_one(scanner: Scanner, config: &ScannersConfig, target: &Path, report: &mut ScanReport) {
    let program = config.program(scanner).to_string();
    let mut cmd = build_command(scanner, &program, target);

    match cmd.output() {
        Ok(output) => match parse_output(scanner, &output) {
            Ok(mut findings) => {
                let n = findings.len();
                report.findings.append(&mut findings);
                report.notes.push(ScanNote {
                    scanner,
                    program,
                    status: ScanStatus::Ran,
                    note: format!("{} ran: {n} finding(s)", scanner.display_name()),
                    findings: n,
                });
            }
            Err(detail) => {
                tracing::warn!(scanner = scanner.source_tag(), %detail, "scanner output did not parse");
                report.notes.push(ScanNote {
                    scanner,
                    program,
                    status: ScanStatus::Failed,
                    note: format!("{} output did not parse: {detail}", scanner.display_name()),
                    findings: 0,
                });
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // The central soft-degrade path.
            tracing::info!(
                scanner = scanner.source_tag(),
                %program,
                "scanner binary not found on PATH — soft-degrading (skipped)"
            );
            report.notes.push(ScanNote {
                scanner,
                program: program.clone(),
                status: ScanStatus::SkippedMissing,
                note: format!(
                    "binary `{program}` for {} not found on PATH — skipped (soft-degrade)",
                    scanner.display_name()
                ),
                findings: 0,
            });
        }
        Err(err) => {
            // A real spawn failure (e.g. permission denied). Record, don't abort.
            tracing::warn!(scanner = scanner.source_tag(), %program, error = %err, "scanner failed to spawn");
            report.notes.push(ScanNote {
                scanner,
                program: program.clone(),
                status: ScanStatus::Failed,
                note: format!("failed to spawn `{program}` for {}: {err}", scanner.display_name()),
                findings: 0,
            });
        }
    }
}

/// Build the subprocess command for a scanner. Kept separate so it can be unit
/// tested without executing anything.
fn build_command(scanner: Scanner, program: &str, target: &Path) -> Command {
    let mut cmd = Command::new(program);
    match scanner {
        Scanner::Semgrep => {
            cmd.arg("--json")
                .arg("--quiet")
                // Use the auto config so semgrep picks sensible rulesets; the
                // scan is best-effort.
                .arg("--config")
                .arg("auto")
                .arg(target);
        }
        Scanner::Trivy => {
            cmd.arg("fs")
                .arg("--quiet")
                .arg("--format")
                .arg("json")
                .arg(target);
        }
        Scanner::CargoAudit => {
            // cargo-audit reads Cargo.lock from its working directory.
            cmd.arg("audit").arg("--json").current_dir(target);
        }
    }
    cmd
}

/// Dispatch native-output parsing by scanner. Returns `Err(detail)` when the
/// output could not be interpreted (recorded as [`ScanStatus::Failed`]).
fn parse_output(scanner: Scanner, output: &Output) -> std::result::Result<Vec<Finding>, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if stdout.is_empty() {
        // No JSON on stdout. For most scanners that means "nothing to report",
        // but it can also mean the tool printed its error to stderr. Treat a
        // non-success exit with empty stdout as a soft failure with context.
        if output.status.success() {
            return Ok(Vec::new());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "empty stdout, exit {:?}: {}",
            output.status.code(),
            stderr.trim().chars().take(200).collect::<String>()
        ));
    }
    match scanner {
        Scanner::Semgrep => parse_semgrep_json(stdout),
        Scanner::Trivy => parse_trivy_json(stdout),
        Scanner::CargoAudit => parse_cargo_audit_json(stdout),
    }
}

// ---- Semgrep native JSON --------------------------------------------------
//
// `{ "results": [ { "check_id": "...", "path": "...", "start": {"line": N},
//    "extra": { "message": "...", "severity": "ERROR|WARNING|INFO" } } ] }`

#[derive(Debug, Deserialize)]
struct SemgrepOut {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Debug, Deserialize)]
struct SemgrepResult {
    #[serde(default)]
    check_id: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    start: Option<SemgrepPos>,
    #[serde(default)]
    extra: Option<SemgrepExtra>,
}

#[derive(Debug, Default, Deserialize)]
struct SemgrepPos {
    #[serde(default)]
    line: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

fn parse_semgrep_json(input: &str) -> std::result::Result<Vec<Finding>, String> {
    let out: SemgrepOut = serde_json::from_str(input).map_err(|e| e.to_string())?;
    Ok(out
        .results
        .into_iter()
        .map(|r| {
            let extra = r.extra.unwrap_or_default();
            let mut f = Finding::new(Scanner::Semgrep.source_tag(), "semgrep.result");
            if let Some(id) = r.check_id {
                f = f.with_rule_id(id);
            }
            if let Some(sev) = extra.severity.as_deref().and_then(semgrep_severity) {
                f = f.with_severity(sev);
            }
            if let Some(path) = r.path {
                f = f.with_file(path);
            }
            if let Some(line) = r.start.and_then(|s| s.line) {
                f = f.with_line(line);
            }
            if let Some(msg) = extra.message {
                f = f.with_message(msg);
            }
            f
        })
        .collect())
}

/// Semgrep severities are `ERROR` / `WARNING` / `INFO` (and the newer
/// `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` in some rulesets).
fn semgrep_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "ERROR" | "HIGH" => Some(Severity::High),
        "WARNING" | "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "INFO" | "INFORMATIONAL" => Some(Severity::Info),
        _ => None,
    }
}

// ---- Trivy native JSON ----------------------------------------------------
//
// `{ "Results": [ { "Target": "...", "Vulnerabilities": [ { "VulnerabilityID":
//    "CVE-...", "PkgName": "...", "Severity": "CRITICAL|HIGH|...", "Title":
//    "...", "Description": "..." } ], "Misconfigurations": [ { "ID": "...",
//    "Severity": "...", "Title": "...", "Message": "..." } ] } ] }`

#[derive(Debug, Deserialize)]
struct TrivyOut {
    #[serde(default, rename = "Results")]
    results: Vec<TrivyResult>,
}

#[derive(Debug, Default, Deserialize)]
struct TrivyResult {
    #[serde(default, rename = "Target")]
    target: Option<String>,
    #[serde(default, rename = "Vulnerabilities")]
    vulnerabilities: Vec<TrivyVuln>,
    #[serde(default, rename = "Misconfigurations")]
    misconfigurations: Vec<TrivyMisconfig>,
}

#[derive(Debug, Default, Deserialize)]
struct TrivyVuln {
    #[serde(default, rename = "VulnerabilityID")]
    vulnerability_id: Option<String>,
    #[serde(default, rename = "PkgName")]
    pkg_name: Option<String>,
    #[serde(default, rename = "Severity")]
    severity: Option<String>,
    #[serde(default, rename = "Title")]
    title: Option<String>,
    #[serde(default, rename = "Description")]
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TrivyMisconfig {
    #[serde(default, rename = "ID")]
    id: Option<String>,
    #[serde(default, rename = "Severity")]
    severity: Option<String>,
    #[serde(default, rename = "Title")]
    title: Option<String>,
    #[serde(default, rename = "Message")]
    message: Option<String>,
}

fn parse_trivy_json(input: &str) -> std::result::Result<Vec<Finding>, String> {
    let out: TrivyOut = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let mut findings = Vec::new();
    for result in out.results {
        let target = result.target.clone();
        for v in result.vulnerabilities {
            let mut f = Finding::new(Scanner::Trivy.source_tag(), "trivy.vulnerability");
            if let Some(id) = v.vulnerability_id {
                f = f.with_rule_id(id);
            }
            if let Some(sev) = v.severity.as_deref().and_then(trivy_severity) {
                f = f.with_severity(sev);
            }
            if let Some(t) = &target {
                f = f.with_file(t.clone());
            }
            let msg = v
                .title
                .or(v.description)
                .or_else(|| v.pkg_name.map(|p| format!("vulnerability in {p}")));
            if let Some(m) = msg {
                f = f.with_message(m);
            }
            findings.push(f);
        }
        for m in result.misconfigurations {
            let mut f = Finding::new(Scanner::Trivy.source_tag(), "trivy.misconfiguration");
            if let Some(id) = m.id {
                f = f.with_rule_id(id);
            }
            if let Some(sev) = m.severity.as_deref().and_then(trivy_severity) {
                f = f.with_severity(sev);
            }
            if let Some(t) = &target {
                f = f.with_file(t.clone());
            }
            if let Some(msg) = m.title.or(m.message) {
                f = f.with_message(msg);
            }
            findings.push(f);
        }
    }
    Ok(findings)
}

/// Trivy severities are `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN`.
fn trivy_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "UNKNOWN" | "NONE" => Some(Severity::Info),
        _ => None,
    }
}

// ---- cargo-audit native JSON ----------------------------------------------
//
// `{ "vulnerabilities": { "list": [ { "advisory": { "id": "RUSTSEC-...",
//    "title": "...", "description": "..." }, "package": { "name": "...",
//    "version": "..." } } ] } }`
// cargo-audit does not emit a per-advisory severity by default, so advisories
// are recorded as High (a known vulnerable dependency is actionable), and
// warnings (yanked/unmaintained) as Low.

#[derive(Debug, Deserialize)]
struct CargoAuditOut {
    #[serde(default)]
    vulnerabilities: CargoAuditVulns,
    #[serde(default)]
    warnings: std::collections::BTreeMap<String, Vec<CargoAuditWarning>>,
}

#[derive(Debug, Default, Deserialize)]
struct CargoAuditVulns {
    #[serde(default)]
    list: Vec<CargoAuditVuln>,
}

#[derive(Debug, Deserialize)]
struct CargoAuditVuln {
    #[serde(default)]
    advisory: Option<CargoAdvisory>,
    #[serde(default)]
    package: Option<CargoPackage>,
}

#[derive(Debug, Default, Deserialize)]
struct CargoAdvisory {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CargoPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoAuditWarning {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    advisory: Option<CargoAdvisory>,
    #[serde(default)]
    package: Option<CargoPackage>,
}

fn parse_cargo_audit_json(input: &str) -> std::result::Result<Vec<Finding>, String> {
    let out: CargoAuditOut = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let mut findings = Vec::new();

    for v in out.vulnerabilities.list {
        let advisory = v.advisory.unwrap_or_default();
        let pkg = v.package.unwrap_or_default();
        let mut f = Finding::new(Scanner::CargoAudit.source_tag(), "cargo_audit.advisory")
            .with_severity(Severity::High);
        if let Some(id) = advisory.id {
            f = f.with_rule_id(id);
        }
        let msg = advisory_message(&advisory.title, &advisory.description, &pkg);
        if let Some(m) = msg {
            f = f.with_message(m);
        }
        findings.push(f);
    }

    for warnings in out.warnings.into_values() {
        for w in warnings {
            let advisory = w.advisory.unwrap_or_default();
            let pkg = w.package.unwrap_or_default();
            let mut f = Finding::new(Scanner::CargoAudit.source_tag(), "cargo_audit.warning")
                .with_severity(Severity::Low);
            if let Some(id) = advisory.id.clone() {
                f = f.with_rule_id(id);
            }
            let base = advisory_message(&advisory.title, &advisory.description, &pkg);
            let msg = match (w.kind, base) {
                (Some(kind), Some(m)) => Some(format!("{kind}: {m}")),
                (Some(kind), None) => Some(kind),
                (None, m) => m,
            };
            if let Some(m) = msg {
                f = f.with_message(m);
            }
            findings.push(f);
        }
    }

    Ok(findings)
}

fn advisory_message(
    title: &Option<String>,
    description: &Option<String>,
    pkg: &CargoPackage,
) -> Option<String> {
    let base = title.clone().or_else(|| description.clone());
    match (base, &pkg.name) {
        (Some(b), Some(name)) => {
            let ver = pkg.version.as_deref().unwrap_or("");
            Some(if ver.is_empty() {
                format!("{b} ({name})")
            } else {
                format!("{b} ({name} {ver})")
            })
        }
        (Some(b), None) => Some(b),
        (None, Some(name)) => Some(format!("advisory for {name}")),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn missing_binary_soft_degrades_not_errors() {
        // A program name that definitely is not on PATH.
        let config = ScannersConfig {
            semgrep: "logbook-no-such-semgrep-binary-xyz".into(),
            trivy: "logbook-no-such-trivy-binary-xyz".into(),
            cargo_audit: "logbook-no-such-cargo-audit-binary-xyz".into(),
        };
        let report = run_scanners(&config, &PathBuf::from("."));
        // No findings, three notes, all soft-degraded — and crucially, no panic
        // and no hard error.
        assert!(report.findings.is_empty());
        assert_eq!(report.notes.len(), 3);
        assert!(report.all_missing(), "all should be SkippedMissing");
        assert!(!report.any_ran());
        for note in &report.notes {
            assert_eq!(note.status, ScanStatus::SkippedMissing);
            assert!(note.note.contains("not found on PATH"), "note: {}", note.note);
        }
    }

    #[test]
    fn build_command_shapes_per_scanner() {
        let target = PathBuf::from("/some/dir");
        let semgrep = build_command(Scanner::Semgrep, "semgrep", &target);
        let args: Vec<_> = semgrep.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert!(args.contains(&"--json".to_string()));
        assert!(args.contains(&"/some/dir".to_string()));

        let trivy = build_command(Scanner::Trivy, "trivy", &target);
        let targs: Vec<_> = trivy.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(targs.first().map(String::as_str), Some("fs"));
        assert!(targs.contains(&"json".to_string()));

        let audit = build_command(Scanner::CargoAudit, "cargo-audit", &target);
        let aargs: Vec<_> = audit.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(aargs.first().map(String::as_str), Some("audit"));
        assert!(aargs.contains(&"--json".to_string()));
        // cargo-audit runs in the target dir, not as a positional arg.
        assert_eq!(audit.get_current_dir(), Some(target.as_path()));
    }

    #[test]
    fn parses_semgrep_native_json() {
        let json = r#"{
          "results": [
            {
              "check_id": "rust.lang.security.unsafe",
              "path": "src/main.rs",
              "start": { "line": 10 },
              "extra": { "message": "unsafe block", "severity": "ERROR" }
            }
          ]
        }"#;
        let findings = parse_semgrep_json(json).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.source, "semgrep");
        assert_eq!(f.rule_id.as_deref(), Some("rust.lang.security.unsafe"));
        assert_eq!(f.severity, Some(Severity::High));
        assert_eq!(f.file.as_deref(), Some("src/main.rs"));
        assert_eq!(f.line, Some(10));
    }

    #[test]
    fn parses_trivy_native_json() {
        let json = r#"{
          "Results": [
            {
              "Target": "Cargo.lock",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2024-1234",
                  "PkgName": "openssl",
                  "Severity": "CRITICAL",
                  "Title": "buffer overflow"
                }
              ],
              "Misconfigurations": [
                {
                  "ID": "DS001",
                  "Severity": "MEDIUM",
                  "Title": "missing user"
                }
              ]
            }
          ]
        }"#;
        let findings = parse_trivy_json(json).unwrap();
        assert_eq!(findings.len(), 2);
        let vuln = findings.iter().find(|f| f.type_ == "trivy.vulnerability").unwrap();
        assert_eq!(vuln.rule_id.as_deref(), Some("CVE-2024-1234"));
        assert_eq!(vuln.severity, Some(Severity::Critical));
        let misc = findings.iter().find(|f| f.type_ == "trivy.misconfiguration").unwrap();
        assert_eq!(misc.severity, Some(Severity::Medium));
    }

    #[test]
    fn parses_cargo_audit_native_json() {
        let json = r#"{
          "vulnerabilities": {
            "found": true,
            "count": 1,
            "list": [
              {
                "advisory": {
                  "id": "RUSTSEC-2021-0001",
                  "title": "memory corruption",
                  "description": "details here"
                },
                "package": { "name": "badcrate", "version": "0.1.0" }
              }
            ]
          },
          "warnings": {
            "unmaintained": [
              {
                "kind": "unmaintained",
                "advisory": { "id": "RUSTSEC-2020-0999", "title": "no longer maintained" },
                "package": { "name": "oldcrate", "version": "1.2.3" }
              }
            ]
          }
        }"#;
        let findings = parse_cargo_audit_json(json).unwrap();
        assert_eq!(findings.len(), 2);
        let vuln = findings.iter().find(|f| f.type_ == "cargo_audit.advisory").unwrap();
        assert_eq!(vuln.rule_id.as_deref(), Some("RUSTSEC-2021-0001"));
        assert_eq!(vuln.severity, Some(Severity::High));
        assert!(vuln.message.as_deref().unwrap().contains("badcrate"));
        let warn = findings.iter().find(|f| f.type_ == "cargo_audit.warning").unwrap();
        assert_eq!(warn.severity, Some(Severity::Low));
        assert!(warn.message.as_deref().unwrap().contains("unmaintained"));
    }

    #[test]
    fn empty_cargo_audit_clean_report() {
        let json = r#"{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;
        let findings = parse_cargo_audit_json(json).unwrap();
        assert!(findings.is_empty());
    }
}
