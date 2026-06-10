//! Human + JSON rendering of a [`ScanReport`] (plan §7b: `inventory report`).
//!
//! The JSON form is the machine surface (consumed by the MCP `inventory_report`
//! tool and `inventory report --json`); the text form is the default
//! human-readable output. Both render only already-redacted data.

use serde::Serialize;

use crate::model::{AgentInstall, InventoryFinding, McpServer, RunningProcess, ToolPresence};
use crate::scan::{ScanReport, SessionStoreSummary};

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
    /// Native conversation stores discovered on disk (read-only). Observe-only:
    /// what is *on disk*, not what is "unrecorded".
    pub conversation_stores: &'a [SessionStoreSummary],
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
            conversation_stores: &report.sessions,
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

    // Conversation Stores tab — native on-disk stores discovered read-only.
    write_conversation_stores(&mut s, &report.sessions);
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

/// Render the "Conversation Stores" section: native conversation stores found
/// on disk, grouped per tool, with **honest wording**.
///
/// The scan discovers what is *on disk* — it holds no store handle to subtract
/// sessions logbook has already imported — so it reports
/// "N native conversation stores discovered", **never** "N unrecorded". Each
/// tool line points at the `logbook import <tool>` command that would pull them
/// onto the timeline, and the section footer makes the observe-only meaning
/// explicit.
fn write_conversation_stores(s: &mut String, sessions: &[SessionStoreSummary]) {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let _ = writeln!(
        s,
        "Conversation Stores ({} discovered on disk, read-only):",
        sessions.len()
    );
    if sessions.is_empty() {
        let _ = writeln!(s, "  (no native conversation stores discovered)");
        return;
    }

    // Group by tool, counting stores and tracking the most-recent last-active.
    // BTreeMap keeps the per-tool output order stable (alphabetical).
    let mut by_tool: BTreeMap<&str, (usize, Option<i64>)> = BTreeMap::new();
    for store in sessions {
        let entry = by_tool.entry(store.tool.as_str()).or_insert((0, None));
        entry.0 += 1;
        if let Some(la) = store.last_active {
            entry.1 = Some(entry.1.map_or(la, |cur: i64| cur.max(la)));
        }
    }

    for (tool, (count, last_active)) in &by_tool {
        let noun = if *count == 1 { "store" } else { "stores" };
        let last = match last_active {
            Some(micros) => format!("  (last active {micros})"),
            None => String::new(),
        };
        // Honest wording: "N native conversation stores discovered", not
        // "N unrecorded".
        let _ = writeln!(
            s,
            "  {tool:<10} {count} native conversation {noun} discovered  →  run `logbook import {tool}`{last}"
        );
    }
    let _ = writeln!(
        s,
        "  (native stores found on disk; logbook has not necessarily imported them — \
         run `logbook import <tool>` to pull them onto the timeline)"
    );
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
            sessions: vec![
                SessionStoreSummary {
                    tool: "cursor".into(),
                    native_id: "composerData:abc".into(),
                    import_id: "fp1:composerData:abc".into(),
                    title: Some("Refactor scan".into()),
                    last_active: Some(1_700_000_000_000_000),
                    approx_messages: Some(12),
                    workspace: Some("/home/me/proj".into()),
                },
                SessionStoreSummary {
                    tool: "cursor".into(),
                    native_id: "composerData:def".into(),
                    import_id: "fp2:composerData:def".into(),
                    title: None,
                    last_active: None,
                    approx_messages: Some(3),
                    workspace: None,
                },
                SessionStoreSummary {
                    tool: "gemini".into(),
                    native_id: "sess-xyz".into(),
                    import_id: "fp3:sess-xyz".into(),
                    title: None,
                    last_active: Some(1_700_000_500_000_000),
                    approx_messages: Some(5),
                    workspace: Some("proj-hash".into()),
                },
            ],
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
        // Conversation stores surface in JSON under their honest key.
        assert_eq!(v["conversation_stores"][0]["tool"], "cursor");
        assert_eq!(v["conversation_stores"][0]["import_id"], "fp1:composerData:abc");
        assert_eq!(v["conversation_stores"][2]["tool"], "gemini");
    }

    #[test]
    fn conversation_stores_section_uses_honest_wording_and_counts() {
        let text = to_human(&sample());

        // Section header carries the total on-disk count.
        assert!(
            text.contains("Conversation Stores (3 discovered on disk, read-only):"),
            "missing section header in:\n{text}"
        );
        // Per-tool, honest "N native conversation stores discovered" wording —
        // plural for cursor (2 stores), singular for gemini (1 store).
        assert!(
            text.contains("cursor     2 native conversation stores discovered"),
            "missing cursor count line in:\n{text}"
        );
        assert!(
            text.contains("gemini     1 native conversation store discovered"),
            "missing gemini count line in:\n{text}"
        );
        // Each tool line points at the import command.
        assert!(text.contains("run `logbook import cursor`"));
        assert!(text.contains("run `logbook import gemini`"));
        // It must NEVER claim "unrecorded" — the scan has no store handle to
        // subtract already-imported sessions.
        assert!(
            !text.to_lowercase().contains("unrecorded"),
            "scan must not claim 'unrecorded':\n{text}"
        );
        // The observe-only meaning is made explicit.
        assert!(text.contains("has not necessarily imported them"));
    }

    #[test]
    fn conversation_stores_section_handles_empty() {
        let mut r = sample();
        r.sessions.clear();
        let text = to_human(&r);
        assert!(text.contains("Conversation Stores (0 discovered on disk, read-only):"));
        assert!(text.contains("(no native conversation stores discovered)"));
        assert!(!text.to_lowercase().contains("unrecorded"));
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
