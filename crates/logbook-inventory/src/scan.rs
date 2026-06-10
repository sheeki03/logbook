//! The discovery scan orchestrator (plan §7b).
//!
//! `scan` is **user-triggered and read-only**: it discovers installed agent
//! CLIs, configured MCP servers, running agent processes, and reusable tools;
//! derives advisory risk/shadow findings; and (when given a [`Store`]) persists
//! everything into the inventory tables plus a correlated
//! `Event{category: inventory}` summary on the timeline.

use std::path::{Path, PathBuf};

use logbook_core::{Category, Event, Kind, Redactor, Severity, Status, TraceId};
use logbook_store::Store;

use crate::agents::{scan_agents, AgentScanOptions};
use crate::config::InventoryConfig;
use crate::endpoint::local_endpoint;
use crate::error::Result;
use crate::mcp::{scan_mcp, McpScanOptions};
use crate::model::{
    finding_kind, AgentInstall, Endpoint, InventoryFinding, McpServer, RunningProcess, ToolPresence,
};
use crate::processes::scan_processes;
use crate::store_ext;
use crate::tools::{scan_tools, ToolScanOptions};

/// A slim, read-only projection of one native conversation store discovered by
/// [`logbook_import::discover_all_sessions`].
///
/// We surface a local projection rather than leaking
/// [`logbook_import::DiscoveredSession`] through the public [`ScanReport`]: the
/// report is `Serialize` (rendered by [`crate::report`]) and decoupled, whereas
/// the import type is a richer, non-serializable read handle (it carries a
/// `SessionLocator` and reopen path). This summary keeps only what the
/// "Conversation Stores" view needs and never carries payload bodies. It is
/// **observe-only**: a count of what is *on disk*, not what is "unrecorded" (the
/// scan has no store handle to subtract already-imported sessions).
#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionStoreSummary {
    /// The tool that owns the store (`cursor`, `gemini`, `continue`).
    pub tool: String,
    /// The tool's native session key (human-readable; not globally unique).
    pub native_id: String,
    /// The globally-unique import selector (`{origin_fingerprint}:{native_key}`),
    /// i.e. the `--session` argument to `logbook import <tool>`.
    pub import_id: String,
    /// A short human title for the session, if the store records one.
    pub title: Option<String>,
    /// Last-activity time in microseconds since the epoch, if the store records
    /// one.
    pub last_active: Option<i64>,
    /// A bounded structural message count, if obtainable without parsing bodies.
    pub approx_messages: Option<usize>,
    /// The workspace/project this session belongs to, if known.
    pub workspace: Option<String>,
}

impl SessionStoreSummary {
    /// Project a [`logbook_import::DiscoveredSession`] into the slim summary, the
    /// only `logbook-import` type that crosses into the public report.
    #[must_use]
    fn from_discovered(s: &logbook_import::DiscoveredSession) -> Self {
        Self {
            tool: s.tool.clone(),
            native_id: s.native_id.clone(),
            import_id: s.import_id.clone(),
            title: s.title.clone(),
            last_active: s.last_active.map(|t| t.as_micros()),
            approx_messages: s.approx_messages,
            workspace: s.workspace.clone(),
        }
    }
}

/// The full result of an inventory scan.
#[derive(Clone, Debug)]
pub struct ScanReport {
    /// The local endpoint.
    pub endpoint: Endpoint,
    /// Discovered agent CLIs.
    pub agents: Vec<AgentInstall>,
    /// Discovered MCP servers (already redacted).
    pub mcp_servers: Vec<McpServer>,
    /// Best-effort running agent processes (already redacted).
    pub processes: Vec<RunningProcess>,
    /// Reusable-tool presence (schrute, security-suite, scanners).
    pub tools: Vec<ToolPresence>,
    /// Native conversation stores discovered read-only on disk (Cursor/Gemini/
    /// Continue), surfaced so the user can `logbook import <tool>` them. This is
    /// observe-only: a body-free count of what is on disk, never a claim about
    /// what is already recorded.
    pub sessions: Vec<SessionStoreSummary>,
    /// Derived risk/shadow findings (already redacted).
    pub findings: Vec<InventoryFinding>,
    /// The correlation trace id for events emitted by this scan.
    pub trace_id: String,
}

impl ScanReport {
    /// Whether any risk/shadow finding was surfaced.
    #[must_use]
    pub fn has_risk(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// Inputs to a scan. The `home` / `project` dirs locate config files and tools;
/// the [`AgentScanOptions`] / [`McpScanOptions`] / [`ToolScanOptions`] are
/// derived from these and the config but can be overridden for tests.
#[derive(Clone, Debug)]
pub struct ScanContext {
    /// Home directory (for `~/.cursor/mcp.json`, schrute, etc.).
    pub home: PathBuf,
    /// Project directory (cwd) for `.mcp.json`, `.cursor/mcp.json`, etc.
    pub project: PathBuf,
    /// Parsed config (redaction patterns, scanner paths).
    pub config: InventoryConfig,
    /// Agent discovery options.
    pub agents: AgentScanOptions,
    /// MCP discovery options.
    pub mcp: McpScanOptions,
    /// Tool discovery options.
    pub tools: ToolScanOptions,
    /// Override for conversation-store discovery roots. `None` (the default)
    /// uses [`logbook_import::discovery::resolve`] (the real per-OS data dirs);
    /// tests inject a fixture dir via [`logbook_import::discovery::from_path`].
    pub session_roots: Option<logbook_import::DataRoots>,
}

impl ScanContext {
    /// Build a context from a home + project dir, reading `logbook.toml` from
    /// the project dir and using the real default discovery locations.
    #[must_use]
    pub fn discover(home: impl AsRef<Path>, project: impl AsRef<Path>) -> Self {
        let home = home.as_ref().to_path_buf();
        let project = project.as_ref().to_path_buf();
        let config = InventoryConfig::load_from_dir(&project);
        Self {
            agents: AgentScanOptions::default(),
            mcp: McpScanOptions::default(),
            tools: ToolScanOptions::with_home(&home),
            session_roots: None,
            home,
            project,
            config,
        }
    }

    /// The conversation-store discovery roots for this context: the
    /// [`session_roots`](Self::session_roots) override if set, else the real
    /// per-OS data dirs.
    #[must_use]
    fn session_roots(&self) -> logbook_import::DataRoots {
        self.session_roots
            .clone()
            .unwrap_or_else(logbook_import::discovery::resolve)
    }

    /// Build the redactor from this context's config, seeded with the process
    /// environment's secret-looking variables (plan §9).
    #[must_use]
    pub fn redactor(&self) -> Redactor {
        logbook_core::redact::from_config(
            self.config.redaction.enabled,
            &self.config.redaction.deny,
            &self.config.redaction.allow,
        )
        .unwrap_or_else(|_| {
            // A bad user deny-pattern shouldn't disable redaction; fall back to
            // built-ins + env secrets.
            tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
            Redactor::new().with_process_env()
        })
    }
}

/// Run a discovery scan, returning the report. Pure discovery — no persistence.
#[must_use]
pub fn scan(ctx: &ScanContext) -> ScanReport {
    let redactor = ctx.redactor();
    let endpoint = local_endpoint();

    let agents = scan_agents(&endpoint.id, &ctx.agents);
    let mcp_servers = scan_mcp(&endpoint.id, &ctx.home, &ctx.project, &ctx.mcp, &redactor);
    let processes = scan_processes(&redactor);
    let tools = scan_tools(&ctx.tools);
    let sessions = scan_sessions(ctx);
    let findings = derive_findings(&endpoint, &agents, &mcp_servers, &redactor);

    ScanReport {
        endpoint,
        agents,
        mcp_servers,
        processes,
        tools,
        sessions,
        findings,
        trace_id: TraceId::new().to_hex(),
    }
}

/// Discover native conversation stores read-only via `logbook-import`, projecting
/// each into a slim [`SessionStoreSummary`].
///
/// This is **observe-only and non-fatal** (inventory never modifies anything):
/// discovery reads no payload bodies, and any discovery [`logbook_import::Diag`]
/// (a locked store, an unreadable directory) is surfaced as a `tracing` note —
/// never an abort. A discovery that finds nothing simply yields an empty `Vec`,
/// leaving the existing agents/MCP/processes/findings behavior untouched.
fn scan_sessions(ctx: &ScanContext) -> Vec<SessionStoreSummary> {
    let roots = ctx.session_roots();
    let (discovered, diags) = logbook_import::discover_all_sessions(&roots);

    for d in &diags {
        // Non-fatal: surface, do not abort. `Diag::msg` is already free of
        // payload bodies (per the import-crate contract).
        match d.level {
            logbook_import::Level::Error => {
                tracing::warn!(origin = %d.origin.display(), "conversation-store discovery: {}", d.msg);
            }
            logbook_import::Level::Warn => {
                tracing::debug!(origin = %d.origin.display(), "conversation-store discovery: {}", d.msg);
            }
        }
    }

    discovered
        .iter()
        .map(SessionStoreSummary::from_discovered)
        .collect()
}

/// Run a scan **and persist** it to the inventory tables + emit a correlated
/// `Event{category: inventory}` summary and one finding event per risk.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if any persistence step fails.
pub fn scan_and_persist(ctx: &ScanContext, store: &Store) -> Result<ScanReport> {
    let report = scan(ctx);
    persist(&report, store)?;
    Ok(report)
}

/// Persist a [`ScanReport`] to the store: upsert the inventory tables and emit
/// timeline events.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if any write fails.
pub fn persist(report: &ScanReport, store: &Store) -> Result<()> {
    let ep_id = &report.endpoint.id;
    store_ext::upsert_endpoint(store, &report.endpoint)?;
    store_ext::upsert_agent_installs(store, ep_id, &report.agents)?;
    store_ext::upsert_mcp_servers(store, ep_id, &report.mcp_servers)?;
    // Refresh findings so a re-scan reflects the current state rather than
    // accumulating stale rows.
    store_ext::clear_inventory_findings(store, ep_id)?;
    store_ext::insert_inventory_findings(store, ep_id, &report.findings)?;

    // Emit a timeline summary event + one event per finding, all on the scan's
    // trace id so the UI can correlate them.
    let trace: TraceId = report.trace_id.parse().unwrap_or_else(|_| TraceId::new());
    let mut events = Vec::with_capacity(report.findings.len() + 1);
    events.push(summary_event(report, trace));
    for f in &report.findings {
        events.push(finding_event(f, trace));
    }
    store.insert_batch(events)?;
    Ok(())
}

/// Derive advisory risk/shadow findings from the discovery results (plan §7b):
/// unsanctioned agents, shadow MCP servers, and MCP configs carrying secrets.
#[must_use]
pub fn derive_findings(
    endpoint: &Endpoint,
    agents: &[AgentInstall],
    mcp_servers: &[McpServer],
    redactor: &Redactor,
) -> Vec<InventoryFinding> {
    let mut out = Vec::new();
    let _ = endpoint; // endpoint id is stamped at persist time

    for a in agents {
        if !a.sanctioned {
            out.push(finding(
                finding_kind::UNSANCTIONED_AGENT,
                Severity::Medium,
                &a.name,
                &format!(
                    "Unsanctioned agent CLI '{}' found on PATH at {}",
                    a.name, a.path
                ),
                redactor,
            ));
        }
    }

    for s in mcp_servers {
        if !s.sanctioned {
            out.push(finding(
                finding_kind::SHADOW_MCP,
                Severity::Medium,
                &s.name,
                &format!(
                    "Shadow/untracked MCP server '{}' configured in {}",
                    s.name, s.source_config
                ),
                redactor,
            ));
        }
        if s.has_secret {
            out.push(finding(
                finding_kind::MCP_SECRET,
                Severity::High,
                &s.name,
                &format!(
                    "MCP server '{}' config in {} contains an inline secret (redacted)",
                    s.name, s.source_config
                ),
                redactor,
            ));
        }
    }

    out
}

fn finding(
    kind: &str,
    severity: Severity,
    subject: &str,
    message: &str,
    redactor: &Redactor,
) -> InventoryFinding {
    InventoryFinding {
        id: format!("invf-{}", logbook_core::SessionId::generate().into_inner()),
        kind: kind.to_string(),
        severity,
        subject: redactor.redact(subject).into_owned(),
        message: redactor.redact(message).into_owned(),
    }
}

/// Build the per-scan summary event for the timeline.
fn summary_event(report: &ScanReport, trace: TraceId) -> Event {
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .count();
    let status = if report.has_risk() {
        Status::Error
    } else {
        Status::Ok
    };
    Event::new(trace, Kind::Finding, Category::Inventory, "inventory.scan")
        .with_op("scan")
        .with_name(format!(
            "inventory scan: {} agents, {} MCP servers, {} findings",
            report.agents.len(),
            report.mcp_servers.len(),
            report.findings.len()
        ))
        .with_status(status)
        .with_attr("endpoint", report.endpoint.hostname.clone())
        .with_attr(
            "agents",
            i64::try_from(report.agents.len()).unwrap_or(i64::MAX),
        )
        .with_attr(
            "mcp_servers",
            i64::try_from(report.mcp_servers.len()).unwrap_or(i64::MAX),
        )
        .with_attr(
            "processes",
            i64::try_from(report.processes.len()).unwrap_or(i64::MAX),
        )
        .with_attr(
            "conversation_stores",
            i64::try_from(report.sessions.len()).unwrap_or(i64::MAX),
        )
        .with_attr(
            "findings",
            i64::try_from(report.findings.len()).unwrap_or(i64::MAX),
        )
        .with_attr("high_findings", i64::try_from(high).unwrap_or(i64::MAX))
}

/// Build a timeline event for a single inventory finding.
fn finding_event(f: &InventoryFinding, trace: TraceId) -> Event {
    use logbook_core::FindingBlock;
    Event::new(trace, Kind::Finding, Category::Inventory, f.kind.clone())
        .with_op("risk")
        .with_name(f.message.clone())
        .with_status(Status::Error)
        .with_finding(FindingBlock {
            source: Some("inventory".to_string()),
            rule_id: Some(f.kind.clone()),
            severity: Some(f.severity),
            file: None,
            line: None,
            message: Some(f.message.clone()),
        })
        .with_attr("subject", f.subject.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn red() -> Redactor {
        Redactor::new()
    }

    fn write_fake_bin(dir: &Path, name: &str) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh\ntrue").unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn ep() -> Endpoint {
        Endpoint {
            id: "endpoint-test".into(),
            hostname: "test".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
        }
    }

    #[test]
    fn derive_flags_unsanctioned_agent_and_shadow_mcp() {
        let agents = vec![
            AgentInstall {
                id: "a1".into(),
                name: "claude".into(),
                version: None,
                path: "/b/claude".into(),
                sanctioned: true,
            },
            AgentInstall {
                id: "a2".into(),
                name: "aider".into(),
                version: None,
                path: "/b/aider".into(),
                sanctioned: false,
            },
        ];
        let servers = vec![McpServer {
            id: "m1".into(),
            name: "evil".into(),
            source_config: "/tmp/.mcp.json".into(),
            command: Some("x".into()),
            transport: crate::model::McpTransport::Stdio,
            sanctioned: false,
            has_secret: true,
        }];
        let findings = derive_findings(&ep(), &agents, &servers, &red());
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&finding_kind::UNSANCTIONED_AGENT));
        assert!(kinds.contains(&finding_kind::SHADOW_MCP));
        assert!(kinds.contains(&finding_kind::MCP_SECRET));
        // The mcp_secret finding is High severity.
        let secret = findings
            .iter()
            .find(|f| f.kind == finding_kind::MCP_SECRET)
            .unwrap();
        assert_eq!(secret.severity, Severity::High);
    }

    #[test]
    fn no_findings_when_all_sanctioned_and_clean() {
        let agents = vec![AgentInstall {
            id: "a".into(),
            name: "claude".into(),
            version: None,
            path: "/b/claude".into(),
            sanctioned: true,
        }];
        let servers = vec![McpServer {
            id: "m".into(),
            name: "schrute".into(),
            source_config: "/tmp/.mcp.json".into(),
            command: Some("node".into()),
            transport: crate::model::McpTransport::Stdio,
            sanctioned: true,
            has_secret: false,
        }];
        assert!(derive_findings(&ep(), &agents, &servers, &red()).is_empty());
    }

    #[test]
    fn end_to_end_scan_detects_planted_agent_and_mcp_and_persists() {
        // The plan's headline test: a planted fake agent CLI on PATH + a temp
        // .mcp.json are detected and surfaced; a secret in that .mcp.json is
        // redacted in output. Here we exercise discovery + persistence.
        let bindir = tempfile::tempdir().unwrap();
        write_fake_bin(bindir.path(), "aider"); // unsanctioned agent

        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".mcp.json"),
            r#"{ "mcpServers": { "evil": { "command": "node",
                 "env": { "API_KEY": "sk-ant-PLANTEDSECRET0123456789" } } } }"#,
        )
        .unwrap();

        let mut ctx = ScanContext::discover(home.path(), project.path());
        ctx.agents = AgentScanOptions::with_path(bindir.path().to_string_lossy());

        let store = Store::open_in_memory().unwrap();
        let report = scan_and_persist(&ctx, &store).unwrap();

        // Planted agent detected + flagged.
        assert!(report
            .agents
            .iter()
            .any(|a| a.name == "aider" && !a.sanctioned));
        // Planted MCP detected + flagged + has_secret.
        let evil = report
            .mcp_servers
            .iter()
            .find(|s| s.name == "evil")
            .expect("evil mcp detected");
        assert!(evil.has_secret);
        assert!(!evil.sanctioned);
        // Risk findings surfaced.
        assert!(report.has_risk());
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == finding_kind::UNSANCTIONED_AGENT));
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == finding_kind::MCP_SECRET));

        // Secret never appears anywhere in the serialized report.
        let serialized = serde_json::to_string(&report.mcp_servers).unwrap()
            + &serde_json::to_string(&report.findings).unwrap();
        assert!(
            !serialized.contains("sk-ant-PLANTEDSECRET0123456789"),
            "leaked secret: {serialized}"
        );

        // Persisted: inventory tables populated and timeline events emitted.
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::McpServers).unwrap(),
            1
        );
        assert!(
            store_ext::count_rows(&store, store_ext::InventoryTable::AgentInstalls).unwrap() >= 1
        );
        let inv_events = store
            .query(&logbook_store::Query::new().category(Category::Inventory))
            .unwrap();
        assert!(
            !inv_events.is_empty(),
            "inventory events should be on the timeline"
        );
        // None of the persisted events leak the secret either.
        let ev_json = serde_json::to_string(&inv_events).unwrap();
        assert!(
            !ev_json.contains("PLANTEDSECRET"),
            "timeline leaked secret: {ev_json}"
        );
    }

    #[test]
    fn scan_surfaces_discovered_conversation_stores_from_fixture_dir() {
        // Seed a recognizable Gemini store layout under a temp dir and inject it
        // as the session-discovery root; the scan must surface it read-only in
        // `ScanReport.sessions` with the expected tool + native id, without
        // touching the rest of the scan.
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let stores = tempfile::tempdir().unwrap();

        // `{root}/.gemini/tmp/{hash}/chats/session-*.json` — the standard layout
        // the Gemini source discovers (one file → one session).
        let session_file = stores
            .path()
            .join(".gemini")
            .join("tmp")
            .join("proj-hash")
            .join("chats")
            .join("session-0001.json");
        std::fs::create_dir_all(session_file.parent().unwrap()).unwrap();
        std::fs::write(
            &session_file,
            serde_json::json!({
                "sessionId": "scan-fixture-session",
                "projectHash": "proj-hash",
                "messages": [
                    { "type": "user", "content": "hi" },
                    { "type": "gemini", "content": "hello", "model": "gemini-2.0-flash" }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let mut ctx = ScanContext::discover(home.path(), project.path());
        // Inject the fixture dir as the only discovery root (no real data dirs).
        ctx.session_roots = Some(logbook_import::discovery::from_path(
            stores.path().to_path_buf(),
        ));

        let report = scan(&ctx);

        assert_eq!(
            report.sessions.len(),
            1,
            "expected one discovered store, got: {:#?}",
            report.sessions
        );
        let s = &report.sessions[0];
        assert_eq!(s.tool, "gemini");
        assert_eq!(s.native_id, "scan-fixture-session");
        assert_eq!(s.approx_messages, Some(2));
        // The import selector is `{origin_fingerprint}:{native_key}`.
        assert!(
            s.import_id.ends_with(":scan-fixture-session"),
            "import_id should select the native key: {}",
            s.import_id
        );
    }

    #[test]
    fn scan_sessions_is_empty_and_non_fatal_with_no_stores() {
        // With a discovery root that contains no recognizable store, discovery
        // finds nothing and the scan proceeds normally (observe-only).
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();

        let mut ctx = ScanContext::discover(home.path(), project.path());
        ctx.session_roots = Some(logbook_import::discovery::from_path(
            empty.path().to_path_buf(),
        ));

        let report = scan(&ctx);
        assert!(
            report.sessions.is_empty(),
            "no stores expected: {:#?}",
            report.sessions
        );
    }
}
