//! Plain data types for discovered inventory items (plan §2, §7b).
//!
//! These mirror the SQLite inventory tables (`endpoints`, `agent_installs`,
//! `mcp_servers`, `agent_sessions`, `agent_actions`, `inventory_findings`) and
//! serialize directly into the JSON report. Construction is side-effect-free;
//! persistence lives in [`crate::store_ext`].

use logbook_core::Severity;
use serde::{Deserialize, Serialize};

/// The local machine this inventory describes (v1: always exactly one).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Stable id for this endpoint (a hostname-derived fingerprint).
    pub id: String,
    /// Hostname.
    pub hostname: String,
    /// Operating system (`macos`, `linux`, ...).
    pub os: String,
    /// CPU architecture (`aarch64`, `x86_64`, ...).
    pub arch: String,
}

/// A coding-agent CLI discovered on `PATH`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstall {
    /// Stable id (derived from endpoint + name; path is intentionally excluded
    /// so an upgrade re-scan upserts the same row).
    pub id: String,
    /// Canonical agent name (`claude`, `cursor`, `codex`, `gemini`, `aider`, ...).
    pub name: String,
    /// Resolved version string, if the binary reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Resolved absolute binary path on `PATH`.
    pub path: String,
    /// Whether this install is on the sanctioned allowlist (`false` = shadow).
    pub sanctioned: bool,
}

/// The transport an MCP server uses, inferred from its config shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    /// Spawned local process over stdio (`command` + `args`).
    Stdio,
    /// Server-sent events over HTTP.
    Sse,
    /// Streamable HTTP.
    Http,
    /// WebSocket.
    Ws,
    /// Could not be determined.
    #[default]
    Unknown,
}

impl McpTransport {
    /// Stable lowercase wire string for the `transport` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            McpTransport::Stdio => "stdio",
            McpTransport::Sse => "sse",
            McpTransport::Http => "http",
            McpTransport::Ws => "ws",
            McpTransport::Unknown => "unknown",
        }
    }
}

/// An MCP server discovered in a known config location or a local project file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServer {
    /// Stable id (derived from source config + name).
    pub id: String,
    /// Server name (the config key).
    pub name: String,
    /// Which config file declared it (absolute path, human-readable).
    pub source_config: String,
    /// The launch command (`command`) or remote URL, for stdio/remote servers.
    /// Already redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Inferred transport.
    pub transport: McpTransport,
    /// Whether this server is on the sanctioned allowlist (`false` = shadow).
    pub sanctioned: bool,
    /// Whether the config carried a secret (which has been redacted before this
    /// struct was produced).
    pub has_secret: bool,
}

/// A best-effort observation of a running agent-related process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningProcess {
    /// Process id.
    pub pid: i32,
    /// The agent name this process was matched to (`claude`, `codex`, ...).
    pub agent: String,
    /// The (redacted) command line.
    pub command: String,
}

/// Presence of an external tool logbook can reuse (schrute, security-suite).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPresence {
    /// Tool name (`schrute`, `security-suite`, `semgrep`, ...).
    pub name: String,
    /// Whether it was found.
    pub present: bool,
    /// Where it was found (path / config), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A `session_transcripts` row (plan §1.3): pointers + metadata for a captured
/// agent session's redacted transcript. The bulk bytes already live on disk
/// (the `*.terminal.log` / `*.txt` tiers); this row points at them under the
/// session's shared `trace_id` so replay can stream the file or render the
/// structured per-line events (already in `events`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTranscriptRecord {
    /// Session id (== `agent_sessions.id`, the primary key here).
    pub session_id: String,
    /// The shared correlation trace id (hex) across all session artifacts.
    pub trace_id: String,
    /// Path to the redacted `*.terminal.log` transcript, if that tier was
    /// written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_log_path: Option<String>,
    /// Path to the ANSI-stripped `*.txt` cleaned text, if that tier was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_path: Option<String>,
    /// Number of structured line-events emitted (one per completed cleaned line).
    pub line_count: Option<i64>,
    /// Byte length of the redacted transcript persisted to the `.terminal.log`
    /// tier.
    pub byte_size: Option<i64>,
    /// Most-sensitive class present (defaults to `transcript`).
    pub max_sensitivity: String,
}

/// A risk / shadow finding (advisory, local-only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryFinding {
    /// Stable id.
    pub id: String,
    /// Finding kind (`unsanctioned_agent`, `shadow_mcp`, `mcp_secret`, ...).
    pub kind: String,
    /// Severity.
    pub severity: Severity,
    /// The subject (agent name, MCP server name, path) the finding is about.
    pub subject: String,
    /// Human-readable, already-redacted message.
    pub message: String,
}

/// The `kind` strings used for [`InventoryFinding::kind`]. Centralized so the
/// store layer, report, and tests agree.
pub mod finding_kind {
    /// An agent CLI was found on `PATH` that is not on the sanctioned allowlist.
    pub const UNSANCTIONED_AGENT: &str = "unsanctioned_agent";
    /// An MCP server was configured that is not on the sanctioned allowlist.
    pub const SHADOW_MCP: &str = "shadow_mcp";
    /// An MCP config carried an inline secret (redacted; advisory).
    pub const MCP_SECRET: &str = "mcp_secret";
}
