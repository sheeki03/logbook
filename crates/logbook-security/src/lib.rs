//! `logbook-security` — security scan runner + findings import (plan §7a).
//!
//! v1 scope (narrowed): run **Semgrep / Trivy / cargo-audit** on demand via
//! subprocess, and import **SARIF / JSON** scanner output. Every finding is
//! normalized into an `logbook-core` [`Event`] with `category = security` and
//! a [`FindingBlock`], then persisted to both the `events` table (the unified
//! timeline) and the dedicated `findings` table, correlated by `trace_id` /
//! `event_id` (plan §2).
//!
//! **Soft degradation is a contract, not an afterthought:** if a scanner
//! binary named in `logbook.toml`'s `[scanners]` is missing, the scan records
//! a note and continues — it does **not** hard-error (plan §9.1). See
//! [`scanners`].
//!
//! Deferred to v1.5+ (explicitly **not** here): strix / pentagi / codeql /
//! nuclei automation, auto-scan-on-agent-diff, and gate/annotate.
//!
//! # Entry points
//! - [`security_scan`] — run the configured scanners over a target directory
//!   and persist the findings; returns the [`ScanReport`] (findings + a
//!   per-scanner soft-degrade audit trail).
//! - [`import_sarif`] / [`import_sarif_str`] / [`import_sarif_value`] — import
//!   an existing SARIF document and persist each result as a security finding.
//! - [`persist_findings`] — the shared normalization+persistence core, exposed
//!   so callers importing native scanner JSON directly can reuse it.
//!
//! # Example
//! ```
//! use logbook_security::{import_sarif_str, ImportResult};
//! use logbook_store::Store;
//!
//! # fn main() -> logbook_security::Result<()> {
//! let store = Store::open_in_memory()?;
//! let sarif = r#"{
//!   "version": "2.1.0",
//!   "runs": [{
//!     "tool": { "driver": { "name": "Semgrep" } },
//!     "results": [{
//!       "ruleId": "rules.sqli", "level": "error",
//!       "message": { "text": "SQL injection" },
//!       "locations": [{ "physicalLocation": {
//!         "artifactLocation": { "uri": "src/db.rs" },
//!         "region": { "startLine": 12 } } }]
//!     }]
//!   }]
//! }"#;
//! let result: ImportResult = import_sarif_str(&store, sarif)?;
//! assert_eq!(result.imported, 1);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod finding;
pub mod sarif;
pub mod scanners;

use std::path::Path;

use logbook_core::{Event, MicrosTimestamp, TraceId};
use logbook_store::Store;

pub use config::{Scanner, ScannersConfig};
pub use error::{Result, SecurityError};
pub use finding::Finding;
pub use scanners::{run_scanner, run_scanners, ScanNote, ScanReport, ScanStatus};

// Re-export the core finding block + severity for callers building findings.
pub use logbook_core::{FindingBlock, Severity};

/// The result of persisting a batch of findings: how many were imported and the
/// `trace_id` they were correlated under (so a caller can immediately query the
/// timeline for them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportResult {
    /// Number of findings normalized + persisted.
    pub imported: usize,
    /// The W3C trace id all findings in this batch share.
    pub trace_id: String,
}

/// The result of a [`security_scan`]: the per-scanner [`ScanReport`] plus the
/// [`ImportResult`] describing what was persisted.
#[derive(Clone, Debug)]
pub struct ScanOutcome {
    /// Findings + per-scanner soft-degrade notes.
    pub report: ScanReport,
    /// Persistence summary.
    pub imported: ImportResult,
}

/// Run the configured scanners over `target` and persist their findings.
///
/// This is the `security_scan` entry point referenced by the MCP write tool of
/// the same name (plan §5). The CLI is responsible for the `[permissions]`
/// gate (`allow_security_scans`) **before** calling this; the function itself
/// runs whatever scanners are present and soft-degrades the rest.
///
/// All findings from one scan share a single `trace_id` so they cluster on the
/// timeline.
///
/// # Errors
/// Returns a [`SecurityError`] only if **persistence** fails (store write / id
/// generation). A missing or broken scanner is reflected in
/// [`ScanReport::notes`], not as an error.
pub fn security_scan(
    store: &Store,
    config: &ScannersConfig,
    target: impl AsRef<Path>,
) -> Result<ScanOutcome> {
    let report = run_scanners(config, target.as_ref());
    let imported = persist_findings(store, report.findings.clone())?;
    Ok(ScanOutcome { report, imported })
}

/// Run a single named scanner over `target` and persist its findings. Useful
/// when a caller wants just Semgrep, just Trivy, or just cargo-audit.
///
/// # Errors
/// As [`security_scan`].
pub fn security_scan_one(
    store: &Store,
    scanner: Scanner,
    config: &ScannersConfig,
    target: impl AsRef<Path>,
) -> Result<ScanOutcome> {
    let report = run_scanner(scanner, config, target.as_ref());
    let imported = persist_findings(store, report.findings.clone())?;
    Ok(ScanOutcome { report, imported })
}

/// Import a SARIF document from a file path, persisting each result as a
/// security finding.
///
/// # Errors
/// Returns [`SecurityError::ReadFile`] if the file cannot be read,
/// [`SecurityError::Parse`] if it is not valid SARIF JSON, or a store error if
/// persistence fails.
pub fn import_sarif(store: &Store, path: impl AsRef<Path>) -> Result<ImportResult> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| SecurityError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    import_sarif_str(store, &text)
}

/// Import a SARIF document from a JSON string, persisting each result as a
/// security finding.
///
/// # Errors
/// Returns [`SecurityError::Parse`] if the string is not valid SARIF JSON, or a
/// store error if persistence fails.
pub fn import_sarif_str(store: &Store, sarif: &str) -> Result<ImportResult> {
    let findings = sarif::parse_sarif_str(sarif)?;
    persist_findings(store, findings)
}

/// Import a SARIF document from an already-parsed [`serde_json::Value`].
///
/// # Errors
/// Returns [`SecurityError::Parse`] if the value is not structurally valid
/// SARIF, or a store error if persistence fails.
pub fn import_sarif_value(store: &Store, value: serde_json::Value) -> Result<ImportResult> {
    let findings = sarif::parse_sarif_value(value)?;
    persist_findings(store, findings)
}

/// Normalize a batch of [`Finding`]s into [`Event`]s and persist them to both
/// the `events` table and the `findings` table, correlated under a single fresh
/// `trace_id`.
///
/// This is the shared core behind [`security_scan`] and the `import_*`
/// functions. It is exposed so a caller that has parsed *native* scanner JSON
/// some other way (or wants to persist hand-built findings) can reuse the exact
/// same normalization + correlation + dual-write path.
///
/// Empty input is a no-op success (still returns a fresh, unused `trace_id`).
///
/// # Errors
/// Returns a [`SecurityError`] if the event batch insert or the `findings` row
/// inserts fail, or if id generation fails.
pub fn persist_findings(store: &Store, findings: Vec<Finding>) -> Result<ImportResult> {
    let trace = TraceId::new();
    let trace_hex = trace.to_hex();

    if findings.is_empty() {
        return Ok(ImportResult {
            imported: 0,
            trace_id: trace_hex,
        });
    }

    // Build events, keeping each finding paired with its generated event id and
    // creation timestamp so we can write the correlated `findings` rows.
    let mut events: Vec<Event> = Vec::with_capacity(findings.len());
    let mut rows: Vec<(Finding, String, MicrosTimestamp)> = Vec::with_capacity(findings.len());
    for finding in findings {
        let event = finding.clone().into_event(trace);
        let event_id = event.id.as_str().to_string();
        let created_at = event.timestamp;
        rows.push((finding, event_id, created_at));
        events.push(event);
    }
    let imported = events.len();

    // Two writer transactions (NOT one): `insert_batch` and `write` each take
    // the store's writer lock independently, so this dual-write is not atomic.
    // Accepted, documented limitation: the timeline `events` are the canonical
    // record (a security event renders on the timeline regardless), while the
    // `findings` table is a secondary index correlated by event_id / trace_id.
    // If step 2 fails after step 1, the index is degraded (a missing row) but
    // the timeline is not corrupted, and a re-import is idempotent enough to
    // repair it. True one-transaction atomicity would require a store API that
    // inserts events and arbitrary rows in a single tx (tracked as a follow-up).

    // 1. Persist the timeline events (canonical).
    store.insert_batch(events)?;

    // 2. Mirror into the `findings` secondary index. The closure must be
    //    `Send + 'static`, so move owned copies in.
    let trace_for_rows = trace_hex.clone();
    store.write(move |conn| {
        let tx = conn.transaction()?;
        for (finding, event_id, created_at) in &rows {
            finding::insert_finding_row(&tx, finding, event_id, &trace_for_rows, *created_at)?;
        }
        tx.commit()?;
        // (`&tx` coerces to `&Connection` via `Transaction`'s `Deref`.)
        Ok(())
    })?;

    Ok(ImportResult {
        imported,
        trace_id: trace_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{Category, Kind, Severity, Status};
    use logbook_store::{Query, Store};

    /// A small, multi-result SARIF document used by the import tests.
    const SAMPLE_SARIF: &str = r#"{
      "version": "2.1.0",
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "Semgrep",
              "rules": [
                { "id": "rules.sql-injection", "defaultConfiguration": { "level": "error" } },
                { "id": "rules.weak-hash", "properties": { "security-severity": "4.2" } }
              ]
            }
          },
          "results": [
            {
              "ruleId": "rules.sql-injection",
              "ruleIndex": 0,
              "level": "error",
              "message": { "text": "Possible SQL injection" },
              "locations": [
                { "physicalLocation": {
                    "artifactLocation": { "uri": "src/db.rs" },
                    "region": { "startLine": 42 } } }
              ]
            },
            {
              "ruleId": "rules.weak-hash",
              "ruleIndex": 1,
              "message": { "text": "Weak hash function" },
              "locations": [
                { "physicalLocation": {
                    "artifactLocation": { "uri": "src/crypto.rs" },
                    "region": { "startLine": 7 } } }
              ]
            },
            {
              "ruleId": "rules.todo",
              "level": "note",
              "message": { "text": "Leftover TODO marker" }
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn import_sarif_creates_one_security_event_per_result() {
        let store = Store::open_in_memory().unwrap();
        let result = import_sarif_str(&store, SAMPLE_SARIF).unwrap();

        // The core assertion from the plan's test requirement: each SARIF result
        // becomes a security finding event.
        assert_eq!(result.imported, 3, "three SARIF results → three findings");

        // All three are persisted on the shared trace, all category=security,
        // all kind=Finding, each carrying a finding block.
        let events = store.trace(&result.trace_id).unwrap();
        assert_eq!(events.len(), 3);
        for ev in &events {
            assert_eq!(ev.category, Category::Security, "event must be a security event");
            assert_eq!(ev.kind, Kind::Finding);
            assert_eq!(ev.operation, "scan");
            let block = ev.blocks.finding.as_ref().expect("finding block present");
            assert_eq!(block.source.as_deref(), Some("sarif"));
        }
    }

    #[test]
    fn imported_findings_are_queryable_by_security_category() {
        let store = Store::open_in_memory().unwrap();
        import_sarif_str(&store, SAMPLE_SARIF).unwrap();

        let security = store
            .query(&Query::new().category(Category::Security).limit(100))
            .unwrap();
        assert_eq!(security.len(), 3);
        // The SQL-injection one (level=error → High) should be an errored span.
        let sqli = security
            .iter()
            .find(|e| {
                e.blocks
                    .finding
                    .as_ref()
                    .and_then(|f| f.rule_id.as_deref())
                    == Some("rules.sql-injection")
            })
            .expect("sql-injection finding present");
        assert_eq!(sqli.status, Status::Error);
        assert_eq!(
            sqli.blocks.finding.as_ref().unwrap().severity,
            Some(Severity::High)
        );
        assert_eq!(sqli.blocks.finding.as_ref().unwrap().line, Some(42));
    }

    #[test]
    fn import_writes_correlated_findings_rows() {
        let store = Store::open_in_memory().unwrap();
        let result = import_sarif_str(&store, SAMPLE_SARIF).unwrap();

        // The dedicated findings table should carry the same three rows,
        // correlated to events by trace_id, and joinable to a real event id.
        let trace = result.trace_id.clone();
        let (count, joined): (i64, i64) = store
            .read(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM findings WHERE trace_id = ?1",
                    [&trace],
                    |r| r.get(0),
                )?;
                // Every findings.event_id must reference a real events.id.
                let joined: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM findings f \
                     JOIN events e ON e.id = f.event_id WHERE f.trace_id = ?1",
                    [&trace],
                    |r| r.get(0),
                )?;
                Ok((count, joined))
            })
            .unwrap();
        assert_eq!(count, 3, "three findings rows");
        assert_eq!(joined, 3, "every finding row joins to its event");
    }

    #[test]
    fn findings_row_severity_and_source_recorded() {
        let store = Store::open_in_memory().unwrap();
        let result = import_sarif_str(&store, SAMPLE_SARIF).unwrap();
        let trace = result.trace_id.clone();

        let high_count: i64 = store
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM findings WHERE trace_id = ?1 AND severity = 'high'",
                    [&trace],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(high_count, 1, "the level=error result is recorded as high");

        let trace2 = result.trace_id.clone();
        let sarif_source: i64 = store
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM findings WHERE trace_id = ?1 AND source = 'sarif'",
                    [&trace2],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(sarif_source, 3);
    }

    #[test]
    fn import_empty_sarif_is_noop_success() {
        let store = Store::open_in_memory().unwrap();
        let result = import_sarif_str(&store, r#"{"version":"2.1.0","runs":[]}"#).unwrap();
        assert_eq!(result.imported, 0);
        assert_eq!(store.count().unwrap(), 0);
        // A fresh (unused) trace id is still returned.
        assert_eq!(result.trace_id.len(), 32);
    }

    #[test]
    fn import_invalid_sarif_errors_without_persisting() {
        let store = Store::open_in_memory().unwrap();
        let err = import_sarif_str(&store, "{ not valid json").unwrap_err();
        assert!(matches!(err, SecurityError::Parse { .. }));
        assert_eq!(store.count().unwrap(), 0, "nothing persisted on parse error");
    }

    #[test]
    fn import_sarif_value_path_works() {
        let store = Store::open_in_memory().unwrap();
        let value: serde_json::Value = serde_json::from_str(SAMPLE_SARIF).unwrap();
        let result = import_sarif_value(&store, value).unwrap();
        assert_eq!(result.imported, 3);
    }

    #[test]
    fn import_sarif_from_file_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.sarif");
        std::fs::write(&path, SAMPLE_SARIF).unwrap();

        let store = Store::open_in_dir(dir.path()).unwrap();
        let result = import_sarif(&store, &path).unwrap();
        assert_eq!(result.imported, 3);
        assert_eq!(store.count().unwrap(), 3);
        store.shutdown().unwrap();
    }

    #[test]
    fn missing_sarif_file_is_read_error() {
        let store = Store::open_in_memory().unwrap();
        let err = import_sarif(&store, "/no/such/file.sarif").unwrap_err();
        assert!(matches!(err, SecurityError::ReadFile { .. }));
    }

    #[test]
    fn persist_findings_dual_writes_and_correlates() {
        let store = Store::open_in_memory().unwrap();
        let findings = vec![
            Finding::new("semgrep", "semgrep.result")
                .with_rule_id("R1")
                .with_severity(Severity::Critical)
                .with_file("a.rs")
                .with_line(1)
                .with_message("boom"),
            Finding::new("cargo-audit", "cargo_audit.advisory")
                .with_rule_id("RUSTSEC-2024-0001")
                .with_severity(Severity::High)
                .with_message("vulnerable dep"),
        ];
        let result = persist_findings(&store, findings).unwrap();
        assert_eq!(result.imported, 2);

        let events = store.trace(&result.trace_id).unwrap();
        assert_eq!(events.len(), 2);
        // Both are security events.
        assert!(events.iter().all(|e| e.category == Category::Security));

        let trace = result.trace_id.clone();
        let n: i64 = store
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM findings WHERE trace_id = ?1",
                    [&trace],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn security_scan_soft_degrades_when_no_scanners_present() {
        // With bogus scanner paths, the scan must succeed with zero findings and
        // a full set of soft-degrade notes — not error.
        let store = Store::open_in_memory().unwrap();
        let config = ScannersConfig {
            semgrep: "logbook-absent-semgrep-zzz".into(),
            trivy: "logbook-absent-trivy-zzz".into(),
            cargo_audit: "logbook-absent-cargo-audit-zzz".into(),
        };
        let dir = tempfile::tempdir().unwrap();
        let outcome = security_scan(&store, &config, dir.path()).unwrap();

        assert_eq!(outcome.imported.imported, 0);
        assert!(outcome.report.all_missing(), "all scanners soft-degraded");
        assert_eq!(outcome.report.notes.len(), 3);
        assert_eq!(store.count().unwrap(), 0);
    }
}
