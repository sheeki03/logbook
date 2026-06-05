//! The rmcp server: the *only* module that touches `rmcp` types.
//!
//! [`LogbookServer`] wires every tool function from [`crate::tools`] into an
//! rmcp [`ToolRouter`]. Read tools are always present. Write tools are added to
//! the router too, then **disabled** (via [`ToolRouter::disable_route`]) for any
//! category not enabled in `logbook.toml`. rmcp's router hides disabled routes
//! from `tools/list` *and* rejects them in `tools/call`, so a write tool that
//! isn't enabled is both invisible and uncallable — the security property the
//! plan (§5, §9) requires.
//!
//! Tool *logic* never appears here; each handler is a thin adapter that
//! deserializes params, calls the matching `tools::*` function, and wraps the
//! `serde_json::Value` result in a [`CallToolResult`].

use logbook_store::Store;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};

use crate::config::Permissions;
use crate::params::*;

/// The logbook MCP server. Holds a shared [`Store`] handle and the (possibly
/// pre-disabled) [`ToolRouter`]. Cheap to clone.
#[derive(Clone)]
pub struct LogbookServer {
    store: Store,
    tool_router: ToolRouter<Self>,
}

/// Adapt a tool-logic result into an rmcp [`CallToolResult`]. Success becomes a
/// JSON text content block (the canonical, agent-readable shape); an `Err`
/// becomes a tool-level error result (not a protocol error), so the calling
/// agent gets a structured failure rather than a dropped connection.
fn into_result(outcome: anyhow::Result<serde_json::Value>) -> Result<CallToolResult, McpError> {
    match outcome {
        Ok(value) => {
            let text = serde_json::to_string(&value)
                .unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {e}\"}}"));
            Ok(CallToolResult::success(vec![Content::text(text)]))
        }
        Err(e) => Ok(CallToolResult::error(vec![Content::text(e.to_string())])),
    }
}

#[tool_router]
impl LogbookServer {
    // ---- READ tools (always advertised) --------------------------------

    /// List captured runs (log files), newest-first.
    #[tool(
        name = "list_log_files",
        description = "List captured runs (log files) with command, paths, and exit status.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_log_files(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::list_log_files(&self.store))
    }

    /// Tail the most recent log lines (optionally for one run).
    #[tool(
        name = "tail_log",
        description = "Return the most recent application-log events, newest-first; optionally scoped to a run.",
        annotations(read_only_hint = true)
    )]
    pub async fn tail_log(
        &self,
        Parameters(params): Parameters<TailLogParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::tail_log(&self.store, &params))
    }

    /// Full-text search across captured log/console text.
    #[tool(
        name = "search_logs",
        description = "Full-text search across captured log and console text (FTS5 MATCH syntax).",
        annotations(read_only_hint = true)
    )]
    pub async fn search_logs(
        &self,
        Parameters(params): Parameters<SearchLogsParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::search_logs(&self.store, &params))
    }

    /// Recent error events.
    #[tool(
        name = "get_errors",
        description = "Return recent error-status events, optionally scoped to one trace.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_errors(
        &self,
        Parameters(params): Parameters<GetErrorsParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::get_errors(&self.store, &params))
    }

    /// Status of a run (or the latest).
    #[tool(
        name = "get_run_status",
        description = "Return the run-index record and coarse status (running/ok/error) for a run, or the latest.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_run_status(
        &self,
        Parameters(params): Parameters<GetRunStatusParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::get_run_status(&self.store, &params))
    }

    /// Poll for log lines newer than a cursor.
    #[tool(
        name = "watch_log",
        description = "Poll for application-log events newer than a microsecond cursor; returns the next cursor.",
        annotations(read_only_hint = true)
    )]
    pub async fn watch_log(
        &self,
        Parameters(params): Parameters<WatchLogParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::watch_log(&self.store, &params))
    }

    /// Captured browser console events.
    #[tool(
        name = "browser_console",
        description = "Return captured browser console events, optionally scoped to a session or trace.",
        annotations(read_only_hint = true)
    )]
    pub async fn browser_console(
        &self,
        Parameters(params): Parameters<BrowserConsoleParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_console(&self.store, &params))
    }

    /// Captured browser network events.
    #[tool(
        name = "browser_network",
        description = "Return captured browser network events, optionally scoped to a session or trace.",
        annotations(read_only_hint = true)
    )]
    pub async fn browser_network(
        &self,
        Parameters(params): Parameters<BrowserNetworkParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_network(&self.store, &params))
    }

    /// One captured network request by event id.
    #[tool(
        name = "browser_get_request",
        description = "Fetch a single captured browser network event by its event id.",
        annotations(read_only_hint = true)
    )]
    pub async fn browser_get_request(
        &self,
        Parameters(params): Parameters<BrowserGetRequestParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_get_request(&self.store, &params))
    }

    /// Most recent captured DOM snapshot.
    #[tool(
        name = "browser_dom",
        description = "Return the most recent captured DOM snapshot for a session or trace.",
        annotations(read_only_hint = true)
    )]
    pub async fn browser_dom(
        &self,
        Parameters(params): Parameters<BrowserDomParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_dom(&self.store, &params))
    }

    /// The unified cross-category timeline.
    #[tool(
        name = "query_timeline",
        description = "Query the unified timeline with category/time/session/text filters.",
        annotations(read_only_hint = true)
    )]
    pub async fn query_timeline(
        &self,
        Parameters(params): Parameters<QueryTimelineParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::query_timeline(&self.store, &params))
    }

    /// Every event on a trace, oldest-first.
    #[tool(
        name = "get_trace",
        description = "Return every event sharing a trace id, oldest-first (timeline reading order).",
        annotations(read_only_hint = true)
    )]
    pub async fn get_trace(
        &self,
        Parameters(params): Parameters<GetTraceParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::get_trace(&self.store, &params))
    }

    /// Pivot from an event id to its full trace.
    #[tool(
        name = "correlate",
        description = "Resolve an event id to its trace and return every correlated event.",
        annotations(read_only_hint = true)
    )]
    pub async fn correlate(
        &self,
        Parameters(params): Parameters<CorrelateParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::correlate(&self.store, &params))
    }

    /// Security findings, newest-first.
    #[tool(
        name = "list_findings",
        description = "List security findings newest-first, with optional source and minimum-severity filters.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_findings(
        &self,
        Parameters(params): Parameters<ListFindingsParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::list_findings(&self.store, &params))
    }

    /// One finding by id.
    #[tool(
        name = "get_finding",
        description = "Fetch a single security finding by id.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_finding(
        &self,
        Parameters(params): Parameters<GetFindingParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::get_finding(&self.store, &params))
    }

    /// Evidence for a debug session.
    #[tool(
        name = "debug_fetch_evidence",
        description = "Return captured evidence (events on the session's trace) for a debug session.",
        annotations(read_only_hint = true)
    )]
    pub async fn debug_fetch_evidence(
        &self,
        Parameters(params): Parameters<DebugFetchEvidenceParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::debug_fetch_evidence(&self.store, &params))
    }

    /// Inventory: installed agent CLIs.
    #[tool(
        name = "inventory_list_agents",
        description = "List coding-agent CLIs discovered on this endpoint.",
        annotations(read_only_hint = true)
    )]
    pub async fn inventory_list_agents(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_list_agents(&self.store))
    }

    /// Inventory: configured MCP servers.
    #[tool(
        name = "inventory_list_mcp",
        description = "List MCP servers found in known config locations on this endpoint.",
        annotations(read_only_hint = true)
    )]
    pub async fn inventory_list_mcp(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_list_mcp(&self.store))
    }

    /// Inventory: recorded agent sessions.
    #[tool(
        name = "inventory_list_sessions",
        description = "List recorded `logbook agent <cli>` sessions, optionally filtered by agent.",
        annotations(read_only_hint = true)
    )]
    pub async fn inventory_list_sessions(
        &self,
        Parameters(params): Parameters<InventoryListSessionsParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_list_sessions(&self.store, &params))
    }

    /// Inventory: combined report.
    #[tool(
        name = "inventory_report",
        description = "Return a combined endpoint/agents/MCP/sessions/risk inventory snapshot.",
        annotations(read_only_hint = true)
    )]
    pub async fn inventory_report(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_report(&self.store))
    }

    /// Inventory: risk/shadow findings.
    #[tool(
        name = "inventory_findings",
        description = "List inventory risk/shadow findings (advisory, local-only), optionally filtered by kind.",
        annotations(read_only_hint = true)
    )]
    pub async fn inventory_findings(
        &self,
        Parameters(params): Parameters<InventoryFindingsParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_findings(&self.store, &params))
    }

    /// Sessions: list recorded agent sessions.
    #[tool(
        name = "session_list",
        description = "List recorded `logbook agent <cli>` sessions newest-first, annotated with action count and transcript presence; optionally filtered by agent.",
        annotations(read_only_hint = true)
    )]
    pub async fn session_list(
        &self,
        Parameters(params): Parameters<SessionListParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::session_list(&self.store, &params))
    }

    /// Sessions: one session in full.
    #[tool(
        name = "session_get",
        description = "Fetch one recorded session: its row, transcript pointer, diffed file actions, and the ordered events on its trace.",
        annotations(read_only_hint = true)
    )]
    pub async fn session_get(
        &self,
        Parameters(params): Parameters<SessionGetParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::session_get(&self.store, &params))
    }

    /// Sessions: the redacted file diffs of a session.
    #[tool(
        name = "session_diff",
        description = "Return the redacted per-file diffs (agent_actions) recorded for a session.",
        annotations(read_only_hint = true)
    )]
    pub async fn session_diff(
        &self,
        Parameters(params): Parameters<SessionDiffParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::session_diff(&self.store, &params))
    }

    /// Sessions: FTS search within a session.
    #[tool(
        name = "session_search",
        description = "Full-text search (FTS5 MATCH) over the events and commands captured under a single session.",
        annotations(read_only_hint = true)
    )]
    pub async fn session_search(
        &self,
        Parameters(params): Parameters<SessionSearchParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::session_search(&self.store, &params))
    }

    // ---- WRITE tools (gated; disabled unless enabled in logbook.toml) --

    /// Browser: navigate to a URL.
    #[tool(
        name = "browser_navigate",
        description = "WRITE: navigate the browser to a URL (gated by [permissions].allowed_domains)."
    )]
    pub async fn browser_navigate(
        &self,
        Parameters(params): Parameters<BrowserNavigateParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_navigate(&self.store, &params))
    }

    /// Browser: start recording.
    #[tool(name = "browser_record", description = "WRITE: start recording a browser session (gated).")]
    pub async fn browser_record(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_record(&self.store))
    }

    /// Browser: replay a recorded session.
    #[tool(name = "browser_replay", description = "WRITE: replay a recorded browser session (gated).")]
    pub async fn browser_replay(
        &self,
        Parameters(params): Parameters<BrowserReplayParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_replay(&self.store, &params))
    }

    /// Browser: take a screenshot.
    #[tool(name = "browser_screenshot", description = "WRITE: capture a browser screenshot (gated).")]
    pub async fn browser_screenshot(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_screenshot(&self.store))
    }

    /// Browser: start a session.
    #[tool(name = "browser_start_session", description = "WRITE: start a browser session (gated).")]
    pub async fn browser_start_session(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::browser_start_session(&self.store))
    }

    /// Debug: set a DAP logpoint (alpha).
    #[tool(
        name = "debug_set_logpoint",
        description = "WRITE: set a DAP logpoint at file:line (alpha; no source edit; gated)."
    )]
    pub async fn debug_set_logpoint(
        &self,
        Parameters(params): Parameters<DebugSetLogpointParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::debug_set_logpoint(&self.store, &params))
    }

    /// Debug: enable tracing.
    #[tool(name = "debug_enable_trace", description = "WRITE: enable debug tracing (gated).")]
    pub async fn debug_enable_trace(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::debug_enable_trace(&self.store))
    }

    /// Debug: start a session.
    #[tool(name = "debug_start_session", description = "WRITE: start a debug session (gated).")]
    pub async fn debug_start_session(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::debug_start_session(&self.store))
    }

    /// Debug: end a session.
    #[tool(name = "debug_end_session", description = "WRITE: end a debug session and detach (gated).")]
    pub async fn debug_end_session(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::debug_end_session(&self.store))
    }

    /// Security: run a scanner.
    #[tool(
        name = "security_scan",
        description = "WRITE: run a configured scanner (semgrep/trivy/cargo-audit) on demand (gated)."
    )]
    pub async fn security_scan(
        &self,
        Parameters(params): Parameters<SecurityScanParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::security_scan(&self.store, &params))
    }

    /// Security: scan an agent diff.
    #[tool(name = "scan_agent_diff", description = "WRITE: scan the diff produced by an agent session (gated).")]
    pub async fn scan_agent_diff(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::scan_agent_diff(&self.store))
    }

    /// Inventory: one-shot scan.
    #[tool(name = "inventory_scan", description = "WRITE: run a one-shot inventory scan (gated).")]
    pub async fn inventory_scan(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_scan(&self.store))
    }

    /// Inventory: continuous watch.
    #[tool(
        name = "inventory_watch",
        description = "WRITE: start continuous inventory watch (gated; opt-in, no always-on surveillance)."
    )]
    pub async fn inventory_watch(&self) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::inventory_watch(&self.store))
    }

    /// Export: emit an OTel-shaped payload for a trace.
    #[tool(name = "export_otel", description = "WRITE: export a trace as an OTel-shaped payload (gated).")]
    pub async fn export_otel(
        &self,
        Parameters(params): Parameters<ExportOtelParams>,
    ) -> Result<CallToolResult, McpError> {
        into_result(crate::tools::export_otel(&self.store, &params))
    }
}

impl LogbookServer {
    /// Build a server over `store`, applying `permissions`: every write tool not
    /// in an enabled category is **disabled** in the router (hidden from
    /// `tools/list`, rejected by `tools/call`).
    #[must_use]
    pub fn new(store: Store, permissions: &Permissions) -> Self {
        let mut router = Self::tool_router();
        for tool_name in permissions.disabled_write_tools() {
            // `disable_route` records the name even if (defensively) the route
            // is missing; here every name is a real route, so this hides it.
            router.disable_route(tool_name);
        }
        Self {
            store,
            tool_router: router,
        }
    }

    /// The names of the tools currently advertised (visible) by this server, in
    /// sorted order. This is exactly what a client sees from `tools/list`, and
    /// is the surface the tests assert against.
    #[must_use]
    pub fn advertised_tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        names
    }

    /// Serve this server over stdio until the peer disconnects.
    ///
    /// # Errors
    /// Returns an error if the transport fails to initialize or the service
    /// errors while running.
    pub async fn serve_stdio(self) -> anyhow::Result<()> {
        use rmcp::transport::io::stdio;
        use rmcp::ServiceExt;

        let running = self.serve(stdio()).await?;
        running.waiting().await?;
        Ok(())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LogbookServer {
    fn get_info(&self) -> ServerInfo {
        // `Implementation` is `#[non_exhaustive]`, so build it from the crate
        // env and then set the name/version we want.
        let mut implementation = Implementation::from_build_env();
        implementation.name = "logbook-mcp".into();
        implementation.version = env!("CARGO_PKG_VERSION").into();
        // `ServerInfo`/`InitializeResult` is `#[non_exhaustive]`; build it via
        // its constructor + builder methods rather than a struct literal.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::default())
            .with_server_info(implementation)
            .with_instructions(
                "logbook MCP surface: read-only observability over the local logbook store \
                 (logs, browser state, timeline, findings, endpoint inventory). Write tools are \
                 hidden unless enabled in logbook.toml [permissions].enabled_writes.",
            )
    }
}

/// Convenience: load permissions from `<root>/logbook.toml` and build a server.
///
/// # Errors
/// Returns an error if `logbook.toml` exists but cannot be parsed.
pub fn server_from_root(store: Store, root: impl AsRef<std::path::Path>) -> anyhow::Result<LogbookServer> {
    let cfg = crate::config::McpConfig::load_from_root(root)?;
    Ok(LogbookServer::new(store, cfg.permissions()))
}

/// A convenience type alias to keep the public surface tidy for callers that
/// just want the server type.
pub type Server = LogbookServer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{all_write_tools, McpConfig, WriteCategory};

    /// Every READ tool name the surface must always advertise (plan §5).
    const READ_TOOLS: &[&str] = &[
        "list_log_files",
        "tail_log",
        "search_logs",
        "get_errors",
        "get_run_status",
        "watch_log",
        "browser_console",
        "browser_network",
        "browser_get_request",
        "browser_dom",
        "query_timeline",
        "get_trace",
        "correlate",
        "list_findings",
        "get_finding",
        "debug_fetch_evidence",
        "inventory_list_agents",
        "inventory_list_mcp",
        "inventory_list_sessions",
        "inventory_report",
        "inventory_findings",
        "session_list",
        "session_get",
        "session_diff",
        "session_search",
    ];

    fn server_with(cfg_text: &str) -> LogbookServer {
        let store = Store::open_in_memory().unwrap();
        let cfg = McpConfig::parse(cfg_text).unwrap();
        LogbookServer::new(store, cfg.permissions())
    }

    #[test]
    fn default_permissions_advertise_only_read_tools() {
        // Read-only default: no [permissions] table at all.
        let server = server_with("");
        let names = server.advertised_tool_names();

        // All read tools present.
        for t in READ_TOOLS {
            assert!(names.contains(&t.to_string()), "missing read tool {t}");
        }
        // NO write tools present.
        for w in all_write_tools() {
            assert!(
                !names.contains(&w.to_string()),
                "write tool {w} must be hidden by default"
            );
        }
        // The visible set is exactly the read tools.
        assert_eq!(names.len(), READ_TOOLS.len(), "only read tools should be visible");
    }

    #[test]
    fn enabling_security_advertises_its_tools_only() {
        let server = server_with(
            r#"
            [permissions]
            enabled_writes = ["security"]
            allow_security_scans = true
            "#,
        );
        let names = server.advertised_tool_names();
        // Security write tools now visible.
        assert!(names.contains(&"security_scan".to_string()));
        assert!(names.contains(&"scan_agent_diff".to_string()));
        // Other write categories still hidden.
        assert!(!names.contains(&"browser_navigate".to_string()));
        assert!(!names.contains(&"export_otel".to_string()));
        assert!(!names.contains(&"inventory_scan".to_string()));
        assert!(!names.contains(&"debug_set_logpoint".to_string()));
        // Read tools still all present.
        for t in READ_TOOLS {
            assert!(names.contains(&t.to_string()), "read tool {t} vanished");
        }
        // Count = read + 2 security.
        assert_eq!(names.len(), READ_TOOLS.len() + 2);
    }

    #[test]
    fn security_listed_without_flag_stays_hidden() {
        // Listing the category but not setting allow_security_scans must NOT
        // advertise the tools (defense in depth: both gates required).
        let server = server_with(
            r#"
            [permissions]
            enabled_writes = ["security"]
            "#,
        );
        let names = server.advertised_tool_names();
        assert!(!names.contains(&"security_scan".to_string()));
        assert_eq!(names.len(), READ_TOOLS.len(), "no writes without the allow flag");
    }

    #[test]
    fn enabling_export_advertises_export_otel() {
        let server = server_with(
            r#"
            [permissions]
            enabled_writes = ["export"]
            "#,
        );
        let names = server.advertised_tool_names();
        assert!(names.contains(&"export_otel".to_string()));
        assert_eq!(names.len(), READ_TOOLS.len() + 1);
    }

    #[test]
    fn enabling_browser_requires_flag_then_advertises_all_browser_tools() {
        // Without the flag: hidden.
        let no_flag = server_with(
            r#"
            [permissions]
            enabled_writes = ["browser"]
            "#,
        );
        for t in WriteCategory::Browser.tools() {
            assert!(!no_flag.advertised_tool_names().contains(&t.to_string()));
        }

        // With the flag: all browser tools visible.
        let with_flag = server_with(
            r#"
            [permissions]
            enabled_writes = ["browser"]
            allow_browser_sessions = true
            "#,
        );
        let names = with_flag.advertised_tool_names();
        for t in WriteCategory::Browser.tools() {
            assert!(names.contains(&t.to_string()), "browser tool {t} should be visible");
        }
        assert_eq!(names.len(), READ_TOOLS.len() + WriteCategory::Browser.tools().len());
    }

    #[test]
    fn enabling_multiple_categories_unions_their_tools() {
        let server = server_with(
            r#"
            [permissions]
            enabled_writes = ["export", "inventory_watch"]
            "#,
        );
        let names = server.advertised_tool_names();
        assert!(names.contains(&"export_otel".to_string()));
        assert!(names.contains(&"inventory_scan".to_string()));
        assert!(names.contains(&"inventory_watch".to_string()));
        assert_eq!(
            names.len(),
            READ_TOOLS.len()
                + WriteCategory::Export.tools().len()
                + WriteCategory::InventoryWatch.tools().len()
        );
    }

    #[test]
    fn get_info_enables_tools_capability() {
        let server = server_with("");
        let info = server.get_info();
        assert!(info.capabilities.tools.is_some(), "tools capability must be advertised");
        assert_eq!(info.server_info.name, "logbook-mcp");
    }
}
