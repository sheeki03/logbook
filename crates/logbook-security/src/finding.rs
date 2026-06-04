//! The normalized [`Finding`] — the common shape every importer/scanner
//! produces — plus its conversion into an `logbook-core` [`Event`] and its
//! persistence into the store's `findings` table (plan §2, §7a).
//!
//! Pipeline: scanner JSON / SARIF → [`Finding`] → [`Event`] (`category =
//! security`, with a [`FindingBlock`]) → `events` table **and** a
//! `findings` row correlated by `event_id` / `trace_id`.

use logbook_core::{
    Category, Event, FindingBlock, Kind, MicrosTimestamp, Severity, Status, TraceId,
};

/// A single normalized security finding, decoupled from any scanner's native
/// schema. Importers map their format onto this; [`Finding::into_event`] maps
/// it onto the unified event spine.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    /// The scanner / importer that produced it (`semgrep`, `trivy`,
    /// `cargo-audit`, `sarif`). Recorded verbatim as `findings.source` and
    /// `FindingBlock.source`.
    pub source: String,
    /// Stable rule / check / advisory identifier (e.g. a Semgrep rule id, a
    /// `RUSTSEC-…` id, a CVE, a SARIF `ruleId`).
    pub rule_id: Option<String>,
    /// Normalized severity.
    pub severity: Option<Severity>,
    /// Affected file path, relative to the scanned root when the scanner
    /// reports it that way.
    pub file: Option<String>,
    /// One-based line number, when reported.
    pub line: Option<u32>,
    /// Human-readable message / description.
    pub message: Option<String>,
    /// Fine-grained event `type` (e.g. `semgrep.result`, `trivy.vulnerability`,
    /// `cargo_audit.advisory`, `sarif.result`). Drives the `type` column.
    pub type_: String,
}

impl Finding {
    /// Construct a finding with just a source and an event type; fill the rest
    /// with the builder-style setters.
    #[must_use]
    pub fn new(source: impl Into<String>, type_: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            rule_id: None,
            severity: None,
            file: None,
            line: None,
            message: None,
            type_: type_.into(),
        }
    }

    /// Set the rule / advisory id.
    #[must_use]
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Set the severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the affected file.
    #[must_use]
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Set the line number.
    #[must_use]
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Set the message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// A short, human-friendly display name for the timeline: the rule id if we
    /// have one, otherwise a truncated message, otherwise the source.
    #[must_use]
    pub fn display_name(&self) -> String {
        if let Some(rule) = &self.rule_id {
            return rule.clone();
        }
        if let Some(msg) = &self.message {
            // Keep the first line, capped, so the timeline label stays tidy.
            let first = msg.lines().next().unwrap_or(msg).trim();
            let capped: String = first.chars().take(80).collect();
            if !capped.is_empty() {
                return capped;
            }
        }
        self.source.clone()
    }

    /// Normalize this finding into an `logbook-core` [`Event`] on `trace_id`.
    ///
    /// The event is `kind = Finding`, `category = Security`, `operation =
    /// "scan"`, carries a [`FindingBlock`], and is marked [`Status::Error`] for
    /// high/critical severities (so it surfaces as a problem on the timeline)
    /// and [`Status::Ok`] otherwise. The message is also mirrored into
    /// `Event::error` for high/critical so the existing error-centric views
    /// pick it up.
    ///
    /// **Redaction note:** strings here are expected to already be safe — they
    /// come from scanner output about *code*, not runtime secrets. The unified
    /// redaction pass (plan §9) still applies at the call boundary if a caller
    /// routes user-derived text through; this method does not itself redact.
    #[must_use]
    pub fn into_event(self, trace_id: TraceId) -> Event {
        let high = matches!(self.severity, Some(Severity::High | Severity::Critical));
        let name = self.display_name();

        let block = FindingBlock {
            source: Some(self.source.clone()),
            rule_id: self.rule_id.clone(),
            severity: self.severity,
            file: self.file.clone(),
            line: self.line,
            message: self.message.clone(),
        };

        let mut ev = Event::new(trace_id, Kind::Finding, Category::Security, self.type_)
            .with_op("scan")
            .with_name(name)
            .with_finding(block)
            .with_attr("scanner", self.source);

        if let Some(sev) = self.severity {
            ev = ev.with_attr("severity", sev.as_str());
        }
        if let Some(file) = &self.file {
            ev = ev.with_attr("file", file.clone());
        }
        if let Some(line) = self.line {
            ev = ev.with_attr("line", line);
        }

        if high {
            // Surface high/critical as errored spans (with the message echoed
            // into `error` so the error-centric timeline/MCP views catch it).
            let msg = self
                .message
                .clone()
                .or_else(|| self.rule_id.clone())
                .unwrap_or_else(|| "security finding".to_string());
            ev = ev.with_error(msg);
        } else {
            ev = ev.with_status(Status::Ok);
        }
        ev
    }
}

/// Insert a `findings` row correlated to an already-persisted event.
///
/// Mirrors the security-finding into the dedicated `findings` table (plan §2)
/// so the findings-centric queries don't have to scan the wide `events` table.
/// `event_id` / `trace_id` tie it back to the timeline event.
pub(crate) fn insert_finding_row(
    conn: &rusqlite::Connection,
    finding: &Finding,
    event_id: &str,
    trace_id: &str,
    created_at: MicrosTimestamp,
) -> logbook_store::Result<()> {
    // A fresh row id (W3C-trace-width hex), distinct from the event id.
    let id = TraceId::new().to_hex();
    conn.execute(
        "INSERT OR REPLACE INTO findings \
         (id, event_id, trace_id, source, rule_id, severity, file, line, message, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            id,
            event_id,
            trace_id,
            finding.source,
            finding.rule_id,
            finding.severity.map(Severity::as_str),
            finding.file,
            finding.line,
            finding.message,
            created_at.as_micros(),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::Status;

    #[test]
    fn into_event_sets_category_kind_and_block() {
        let f = Finding::new("semgrep", "semgrep.result")
            .with_rule_id("rules.sql-injection")
            .with_severity(Severity::High)
            .with_file("src/db.rs")
            .with_line(42)
            .with_message("possible SQL injection");
        let trace = TraceId::new();
        let ev = f.into_event(trace);

        assert_eq!(ev.category, Category::Security);
        assert_eq!(ev.kind, Kind::Finding);
        assert_eq!(ev.type_, "semgrep.result");
        assert_eq!(ev.operation, "scan");
        assert_eq!(ev.trace_id, trace);
        let block = ev.blocks.finding.expect("finding block present");
        assert_eq!(block.source.as_deref(), Some("semgrep"));
        assert_eq!(block.rule_id.as_deref(), Some("rules.sql-injection"));
        assert_eq!(block.severity, Some(Severity::High));
        assert_eq!(block.file.as_deref(), Some("src/db.rs"));
        assert_eq!(block.line, Some(42));
    }

    #[test]
    fn high_severity_is_errored_low_is_ok() {
        let trace = TraceId::new();
        let high = Finding::new("trivy", "trivy.vulnerability")
            .with_severity(Severity::Critical)
            .with_message("CVE-2024-9999")
            .into_event(trace);
        assert_eq!(high.status, Status::Error);
        assert_eq!(high.error.as_deref(), Some("CVE-2024-9999"));

        let low = Finding::new("trivy", "trivy.vulnerability")
            .with_severity(Severity::Low)
            .with_message("minor")
            .into_event(trace);
        assert_eq!(low.status, Status::Ok);
        assert!(low.error.is_none());
    }

    #[test]
    fn display_name_prefers_rule_then_message_then_source() {
        assert_eq!(
            Finding::new("s", "t").with_rule_id("R1").display_name(),
            "R1"
        );
        assert_eq!(
            Finding::new("s", "t")
                .with_message("first line\nsecond")
                .display_name(),
            "first line"
        );
        assert_eq!(Finding::new("bare-source", "t").display_name(), "bare-source");
    }
}
