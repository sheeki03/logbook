//! Tool parameter and output types.
//!
//! Each tool that takes arguments has a `*Params` struct deriving
//! [`serde::Deserialize`] + [`schemars::JsonSchema`] (rmcp builds the tool's
//! input JSON Schema from the latter). These types are plain data — no `rmcp`
//! types leak in here, so the tool *logic* in [`crate::tools`] can be unit
//! tested without standing up an MCP server.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A sensible default row cap so an unbounded `query_timeline` / `search_logs`
/// can't return the whole store.
pub const DEFAULT_LIMIT: u32 = 200;

fn default_limit() -> u32 {
    DEFAULT_LIMIT
}

// ---------------------------------------------------------------------------
// Logs lane
// ---------------------------------------------------------------------------

/// `tail_log` — the most recent log lines, optionally for one run/session.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct TailLogParams {
    /// Restrict to a run key (slug/name) as listed by `list_log_files`. When
    /// omitted, the most recent run is used.
    #[serde(default)]
    pub run: Option<String>,
    /// Maximum number of lines to return (newest-first).
    #[serde(default = "default_limit")]
    pub limit: u32,
}

/// `search_logs` — full-text search across captured log/console text.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SearchLogsParams {
    /// FTS5 MATCH query (e.g. `connection refused`, `error AND timeout`).
    pub query: String,
    /// Maximum number of matching events to return.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

/// `get_errors` — recent error-status / error-level events.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetErrorsParams {
    /// Restrict to a single trace id (hex), if you already have one.
    #[serde(default)]
    pub trace_id: Option<String>,
    /// Maximum number of errors to return.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

// NOTE: the derived `Default` for these param structs would set `limit` to `0`
// (the `u32` default), which means `LIMIT 0` / no rows — a footgun. So every
// param struct carrying a `limit` gets a hand-written `Default` that uses
// `DEFAULT_LIMIT`. (The `#[serde(default = "default_limit")]` attribute only
// applies during *deserialization*, not `Default::default()`.)

impl Default for TailLogParams {
    fn default() -> Self {
        Self {
            run: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

impl Default for GetErrorsParams {
    fn default() -> Self {
        Self {
            trace_id: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `get_run_status` — status of one run (or the latest).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct GetRunStatusParams {
    /// Run key to look up. Omit for the most recent run.
    #[serde(default)]
    pub run: Option<String>,
}

/// `watch_log` — a one-shot poll for log lines newer than a cursor.
///
/// (True streaming is the collector/UI's job over SSE; the MCP read tool offers
/// a pull-based cursor so an agent can poll for what's new since it last looked.)
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct WatchLogParams {
    /// Only return events with `timestamp` strictly greater than this
    /// microsecond cursor. Omit to get the most recent window.
    #[serde(default)]
    pub since_micros: Option<i64>,
    /// Maximum number of lines to return.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for WatchLogParams {
    fn default() -> Self {
        Self {
            since_micros: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

// ---------------------------------------------------------------------------
// Browser lane
// ---------------------------------------------------------------------------

/// `browser_console` — captured browser console events.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BrowserConsoleParams {
    /// Restrict to a session id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Restrict to a trace id (hex).
    #[serde(default)]
    pub trace_id: Option<String>,
    /// Maximum number of events.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for BrowserConsoleParams {
    fn default() -> Self {
        Self {
            session_id: None,
            trace_id: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `browser_network` — captured browser network events.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BrowserNetworkParams {
    /// Restrict to a session id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Restrict to a trace id (hex).
    #[serde(default)]
    pub trace_id: Option<String>,
    /// Maximum number of events.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for BrowserNetworkParams {
    fn default() -> Self {
        Self {
            session_id: None,
            trace_id: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `browser_get_request` — one captured network request by event id.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BrowserGetRequestParams {
    /// The event id of the network event to fetch.
    pub event_id: String,
}

/// `browser_dom` — the most recent captured DOM snapshot for a session/trace.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct BrowserDomParams {
    /// Restrict to a session id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Restrict to a trace id (hex).
    #[serde(default)]
    pub trace_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Timeline lane
// ---------------------------------------------------------------------------

/// `query_timeline` — the unified cross-category timeline with filters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct QueryTimelineParams {
    /// Restrict to one category lane (`agent`, `browser`, `app_log`,
    /// `code_test`, `security`, `inventory`).
    #[serde(default)]
    pub category: Option<String>,
    /// Inclusive lower bound on `timestamp` (microseconds).
    #[serde(default)]
    pub since_micros: Option<i64>,
    /// Inclusive upper bound on `timestamp` (microseconds).
    #[serde(default)]
    pub until_micros: Option<i64>,
    /// Restrict to a session id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Optional FTS query to combine with the filters.
    #[serde(default)]
    pub query: Option<String>,
    /// Maximum number of events.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for QueryTimelineParams {
    fn default() -> Self {
        Self {
            category: None,
            since_micros: None,
            until_micros: None,
            session_id: None,
            query: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `get_trace` — every event sharing a trace id, oldest-first.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetTraceParams {
    /// The W3C trace id (32 hex chars).
    pub trace_id: String,
}

/// `correlate` — pivot from any event id to its full trace.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CorrelateParams {
    /// An event id to correlate from; the tool resolves its trace and returns
    /// every event on that trace.
    pub event_id: String,
}

// ---------------------------------------------------------------------------
// Findings lane
// ---------------------------------------------------------------------------

/// `list_findings` — security findings, newest-first, optionally filtered.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListFindingsParams {
    /// Restrict to a scanner source (`semgrep`, `trivy`, `cargo-audit`,
    /// `sarif`, ...).
    #[serde(default)]
    pub source: Option<String>,
    /// Restrict to a minimum severity (`info`, `low`, `medium`, `high`,
    /// `critical`).
    #[serde(default)]
    pub min_severity: Option<String>,
    /// Maximum number of findings.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for ListFindingsParams {
    fn default() -> Self {
        Self {
            source: None,
            min_severity: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `get_finding` — one finding by id.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetFindingParams {
    /// The finding id.
    pub id: String,
}

// ---------------------------------------------------------------------------
// Debug lane
// ---------------------------------------------------------------------------

/// `debug_fetch_evidence` — captured signals for a debug session (passive/DAP).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DebugFetchEvidenceParams {
    /// The debug session id (as returned by `debug_start_session`).
    pub session_id: String,
    /// Maximum number of evidence events.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for DebugFetchEvidenceParams {
    fn default() -> Self {
        Self {
            session_id: String::new(),
            // Match the `#[serde(default)]` so `::default()` never yields LIMIT 0.
            limit: DEFAULT_LIMIT,
        }
    }
}

// ---------------------------------------------------------------------------
// Inventory lane (read)
// ---------------------------------------------------------------------------

/// `inventory_list_sessions` — recorded `logbook agent <cli>` sessions.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct InventoryListSessionsParams {
    /// Restrict to a single agent (`claude`, `cursor`, ...).
    #[serde(default)]
    pub agent: Option<String>,
    /// Maximum number of sessions.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for InventoryListSessionsParams {
    fn default() -> Self {
        Self {
            agent: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `inventory_findings` — risk/shadow findings, optionally filtered by kind.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct InventoryFindingsParams {
    /// Restrict to a finding kind (`unsanctioned_agent`, `shadow_mcp`,
    /// `mcp_secret`, ...).
    #[serde(default)]
    pub kind: Option<String>,
    /// Maximum number of findings.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for InventoryFindingsParams {
    fn default() -> Self {
        Self {
            kind: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

// ---------------------------------------------------------------------------
// Session read-back lane (Phase 2 — "agent can query past sessions")
// ---------------------------------------------------------------------------

/// `session_list` — recent recorded `logbook agent <cli>` sessions (the
/// `agent_sessions` index), newest-first, optionally filtered by agent.
///
/// Distinct from `inventory_list_sessions` (which is the inventory-lane view of
/// the same table): the session read-back tools form a small, cohesive surface
/// (`list`/`get`/`diff`/`search`) for the *agent-querying-its-own-history* use
/// case, and `session_list` additionally annotates each row with its
/// `action_count` and `has_transcript`, mirroring the UI master list.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SessionListParams {
    /// Restrict to a single agent (`claude`, `cursor`, ...). When omitted, all
    /// agents are listed.
    #[serde(default)]
    pub agent: Option<String>,
    /// Maximum number of sessions to return (newest-first).
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for SessionListParams {
    fn default() -> Self {
        Self {
            agent: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// `session_get` — one recorded session in full: the `agent_sessions` row, its
/// `session_transcripts` pointer, its `agent_actions` (with redacted diffs), and
/// the ordered events on the session's trace.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SessionGetParams {
    /// The session id (as listed by `session_list` / `inventory_list_sessions`).
    pub session_id: String,
    /// Maximum number of trace events to include (oldest-first). Defaults to
    /// [`DEFAULT_LIMIT`] when omitted.
    #[serde(default = "default_limit")]
    pub event_limit: u32,
}

impl Default for SessionGetParams {
    fn default() -> Self {
        // Like the other limit-bearing params: a hand-written `Default` so
        // `::default()` uses `DEFAULT_LIMIT`, never the `u32` zero (LIMIT 0).
        Self {
            session_id: String::new(),
            event_limit: DEFAULT_LIMIT,
        }
    }
}

/// `session_diff` — the redacted per-file diffs (`agent_actions`) of one session.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct SessionDiffParams {
    /// The session id whose file diffs to return.
    pub session_id: String,
}

/// `session_search` — full-text search (FTS5 MATCH) over the events and commands
/// captured under a single session.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SessionSearchParams {
    /// The session id to scope the search to.
    pub session_id: String,
    /// FTS5 MATCH query (e.g. `connection refused`, `error AND timeout`).
    pub query: String,
    /// Maximum number of matching events to return.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

impl Default for SessionSearchParams {
    fn default() -> Self {
        Self {
            session_id: String::new(),
            query: String::new(),
            limit: DEFAULT_LIMIT,
        }
    }
}

// ---------------------------------------------------------------------------
// Write-tool params (stubs in v1 — bodies live behind the permission gate)
// ---------------------------------------------------------------------------

/// `browser_navigate` — navigate the browser to a URL (gated; egress allowlist
/// enforced by the collector adapter).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BrowserNavigateParams {
    /// Target URL. Must be within `[permissions].allowed_domains`.
    pub url: String,
    /// Optional session id to reuse.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `browser_replay` — replay a recorded browser session (gated).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BrowserReplayParams {
    /// The recording / session id to replay.
    pub session_id: String,
}

/// `security_scan` — run a configured scanner on demand (gated).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SecurityScanParams {
    /// Which scanner to run (`semgrep`, `trivy`, `cargo-audit`).
    pub scanner: String,
    /// Path to scan (defaults to the workspace root).
    #[serde(default)]
    pub path: Option<String>,
}

/// `debug_set_logpoint` — set a DAP logpoint (alpha, gated).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DebugSetLogpointParams {
    /// Source file the logpoint attaches to.
    pub file: String,
    /// One-based line number.
    pub line: u32,
    /// Log expression to evaluate (no source write occurs).
    pub expression: String,
}

/// `export_otel` — export a trace to an OTel-shaped payload (gated).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExportOtelParams {
    /// The trace id (hex) to export.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Shared output envelope
// ---------------------------------------------------------------------------

/// A uniform structured output envelope for list-style tools: a count plus the
/// items. rmcp serializes this as the tool result's structured content.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ListResult {
    /// Number of items returned.
    pub count: usize,
    /// The items (events / findings / inventory rows as JSON objects).
    pub items: Vec<serde_json::Value>,
}

impl ListResult {
    /// Build a [`ListResult`] from a vec of JSON values.
    #[must_use]
    pub fn new(items: Vec<serde_json::Value>) -> Self {
        Self {
            count: items.len(),
            items,
        }
    }
}
