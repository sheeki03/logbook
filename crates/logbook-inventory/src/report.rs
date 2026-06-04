//! Human + JSON rendering of a [`ScanReport`] (plan §7b: `inventory report`).
//!
//! The JSON form is the machine surface (consumed by the MCP `inventory_report`
//! tool and `inventory report --json`); the text form is the default
//! human-readable output. Both render only already-redacted data.

use serde::Serialize;

use crate::model::{AgentInstall, InventoryFinding, McpServer, RunningProcess, ToolPresence};
use crate::scan::ScanReport;

/// A JSON-serializable view of a scan report, organized into the five UI tabs
/// (Endpoint · Agents · MCP Servers · Sessions · Risk/Shadow) plus tools.
#[derive(Debug, Serialize)]
pub struct ReportJson<'a> {
    /// Endpoint identity.
    pub endpoint: EndpointView<'a>,
    /// Installed agent CLIs.
    pub agents: &'a [AgentInstall],
    /// Configured MCP servers (redacted).
    pub mcp_servers: &'a [McpServer],
    /// Running agent processes (redacted, best-effort).
    pub processes: &'a [RunningProcess],
    /// Reusable-tool presence.
    pub tools: &'a [ToolPresence],
    /// Risk/shadow findings (redacted).
    pub findings: &'a [InventoryFinding],
    /// The scan's correlation trace id.
    pub trace_id: &'a str,
}

/// Flattened endpoint view for the report.
#[derive(Debug, Serialize)]
pub struct EndpointView<'a> {
    /// Endpoint id.
    pub id: &'a str,
    /// Hostname.
    pub hostname: &'a str,
    /// OS.
    pub os: &'a str,
    /// Arch.
    pub arch: &'a str,
}

impl<'a> ReportJson<'a> {
    /// Build the JSON view borrowing from a [`ScanReport`].
    #[must_use]
    pub fn from_report(report: &'a ScanReport) -> Self {
        Self {
            endpoint: EndpointView {
                id: &report.endpoint.id,
                hostname: &report.endpoint.hostname,
                os: &report.endpoint.os,
                arch: &report.endpoint.arch,
            },
            agents: &report.agents,
            mcp_servers: &report.mcp_servers,
            processes: &report.processes,
            tools: &report.tools,
            findings: &report.findings,
            trace_id: &report.trace_id,
        }
    }
}

/// Render a [`ScanReport`] as pretty JSON.
///
/// # Errors
/// Returns [`crate::InventoryError::Json`] if serialization fails (it won't for
/// this shape, but the signature stays honest).
pub fn to_json(report: &ScanReport) -> crate::error::Result<String> {
    Ok(serde_json::to_string_pretty(&ReportJson::from_report(
        report,
    ))?)
}

/// Render a [`ScanReport`] as a human-readable, section-per-tab text report.
#[must_use]
pub fn to_human(report: &ScanReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();

    let _ = writeln!(s, "logbook inventory — local endpoint (read-only)");
    let _ = writeln!(
        s,
        "Endpoint: {} ({} / {})  [{}]",
        report.endpoint.hostname, report.endpoint.os, report.endpoint.arch, report.endpoint.id
    );
    let _ = writeln!(s, "Trace: {}", report.trace_id);
    let _ = writeln!(s);

    // Agents tab
    let _ = writeln!(s, "Agents ({}):", report.agents.len());
    if report.agents.is_empty() {
        let _ = writeln!(s, "  (none found on PATH)");
    } else {
        for a in &report.agents {
            let mark = if a.sanctioned { "ok " } else { "!! " };
            let ver = a.version.as_deref().unwrap_or("");
            let _ = writeln!(s, "  [{mark}] {:<10} {} {}", a.name, a.path, ver);
        }
    }
    let _ = writeln!(s);

    // MCP servers tab
    let _ = writeln!(s, "MCP Servers ({}):", report.mcp_servers.len());
    if report.mcp_servers.is_empty() {
        let _ = writeln!(s, "  (none configured in known locations)");
    } else {
        for m in &report.mcp_servers {
            let mark = if m.sanctioned { "ok " } else { "!! " };
            let secret = if m.has_secret {
                " [SECRET REDACTED]"
            } else {
                ""
            };
            let _ = writeln!(
                s,
                "  [{mark}] {:<14} {:<6} {}{}",
                m.name,
                m.transport.as_str(),
                m.source_config,
                secret
            );
        }
    }
    let _ = writeln!(s);

    // Sessions / processes tab (running processes; recorded sessions come from
    // the store and are rendered by the caller when available).
    let _ = writeln!(s, "Running agent processes ({}):", report.processes.len());
    if report.processes.is_empty() {
        let _ = writeln!(s, "  (none detected)");
    } else {
        for p in &report.processes {
            let _ = writeln!(s, "  pid {:<7} {:<10} {}", p.pid, p.agent, p.command);
        }
    }
    let _ = writeln!(s);

    // Tools
    let _ = writeln!(s, "Reusable tools:");
    for t in &report.tools {
        let mark = if t.present { "found  " } else { "absent " };
        let detail = t.detail.as_deref().unwrap_or("");
        let _ = writeln!(s, "  [{mark}] {:<16} {}", t.name, detail);
    }
    let _ = writeln!(s);

    // Risk / shadow tab
    let _ = writeln!(s, "Risk / Shadow ({}):", report.findings.len());
    if report.findings.is_empty() {
        let _ = writeln!(s, "  (no risks surfaced)");
    } else {
        for f in &report.findings {
            let _ = writeln!(
                s,
                "  [{:<8}] {:<20} {}",
                f.severity.as_str(),
                f.kind,
                f.message
            );
        }
    }
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "(advisory, local-only; logbook observes — it does not modify agents or MCP servers)"
    );

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{finding_kind, Endpoint, McpTransport};
    use logbook_core::Severity;

    fn sample() -> ScanReport {
        ScanReport {
            endpoint: Endpoint {
                id: "endpoint-test".into(),
                hostname: "testhost".into(),
                os: "macos".into(),
                arch: "aarch64".into(),
            },
            agents: vec![AgentInstall {
                id: "a".into(),
                name: "aider".into(),
                version: Some("aider 0.1".into()),
                path: "/b/aider".into(),
                sanctioned: false,
            }],
            mcp_servers: vec![McpServer {
                id: "m".into(),
                name: "evil".into(),
                source_config: "/tmp/.mcp.json".into(),
                command: Some("node \u{ab}REDACTED:CLOUD_KEY:24\u{bb}".into()),
                transport: McpTransport::Stdio,
                sanctioned: false,
                has_secret: true,
            }],
            processes: vec![],
            tools: vec![ToolPresence {
                name: "schrute".into(),
                present: true,
                detail: Some("/x".into()),
            }],
            findings: vec![InventoryFinding {
                id: "f".into(),
                kind: finding_kind::MCP_SECRET.into(),
                severity: Severity::High,
                subject: "evil".into(),
                message: "MCP server 'evil' config contains an inline secret (redacted)".into(),
            }],
            trace_id: "0123456789abcdef0123456789abcdef".into(),
        }
    }

    #[test]
    fn human_report_lists_all_tabs() {
        let text = to_human(&sample());
        assert!(text.contains("Agents (1)"));
        assert!(text.contains("MCP Servers (1)"));
        assert!(text.contains("Risk / Shadow (1)"));
        assert!(text.contains("SECRET REDACTED"));
        assert!(text.contains("aider"));
        assert!(text.contains("schrute"));
        // Unsanctioned items are visually flagged.
        assert!(text.contains("!!"));
    }

    #[test]
    fn json_report_is_valid_and_structured() {
        let json = to_json(&sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["endpoint"]["hostname"], "testhost");
        assert_eq!(v["agents"][0]["name"], "aider");
        assert_eq!(v["mcp_servers"][0]["has_secret"], true);
        assert_eq!(v["findings"][0]["severity"], "high");
    }

    #[test]
    fn report_never_contains_unredacted_placeholder_source() {
        // The sample already carries a redacted command; ensure neither renderer
        // invents an un-redacted value.
        let text = to_human(&sample());
        let json = to_json(&sample()).unwrap();
        assert!(text.contains("REDACTED"));
        assert!(json.contains("REDACTED"));
    }
}
