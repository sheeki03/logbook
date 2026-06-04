//! Endpoint Inventory Lite read models and queries (plan §7b).
//!
//! The inventory tables (`endpoints`, `agent_installs`, `mcp_servers`,
//! `agent_sessions`, `inventory_findings`) are populated by `logbook-inventory`
//! and live in the same SQLite database as the event spine. This module owns the
//! *read* side the UI needs: typed row structs and the SQL that loads them via
//! the store's generic [`Store::read`] connection accessor.
//!
//! Secrets are redacted at write time (plan §9), so anything read here is
//! already safe to ship to the browser. The `has_secret` flag on
//! [`McpServer`] is an advisory boolean — the secret value itself is never
//! stored.

use rusqlite::Connection;
use serde::Serialize;

use logbook_store::error::Result as StoreResult;
use logbook_store::Store;

/// The local endpoint (machine) the store has observed. v1 records exactly one.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Endpoint {
    /// Stable endpoint id (host fingerprint).
    pub id: String,
    /// Hostname.
    pub hostname: String,
    /// Operating system, if recorded.
    pub os: Option<String>,
    /// CPU architecture, if recorded.
    pub arch: Option<String>,
    /// First-seen timestamp (microseconds).
    pub first_seen: i64,
    /// Last-seen timestamp (microseconds).
    pub last_seen: i64,
}

/// A coding-agent CLI discovered on the endpoint.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct AgentInstall {
    /// Row id.
    pub id: String,
    /// Owning endpoint id.
    pub endpoint_id: String,
    /// Agent name (`claude`, `cursor`, `codex`, …).
    pub name: String,
    /// Resolved version, if detected.
    pub version: Option<String>,
    /// Resolved binary path on `PATH`.
    pub path: Option<String>,
    /// Whether the install is sanctioned (`false` = shadow/untracked).
    pub sanctioned: bool,
    /// Discovery timestamp (microseconds).
    pub discovered_at: i64,
}

/// An MCP server declared in a known config location.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct McpServer {
    /// Row id.
    pub id: String,
    /// Owning endpoint id.
    pub endpoint_id: String,
    /// Server name.
    pub name: String,
    /// Which config file declared it.
    pub source_config: Option<String>,
    /// Launch command, if stdio transport.
    pub command: Option<String>,
    /// Transport (`stdio`, `sse`, `http`, `ws`).
    pub transport: Option<String>,
    /// Whether the server is sanctioned (`false` = shadow/untracked).
    pub sanctioned: bool,
    /// Whether the config carried a (redacted) secret — advisory only.
    pub has_secret: bool,
    /// Discovery timestamp (microseconds).
    pub discovered_at: i64,
}

/// An `logbook agent <cli>` session.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct AgentSession {
    /// Session id.
    pub id: String,
    /// Owning endpoint id, if known.
    pub endpoint_id: Option<String>,
    /// Agent name.
    pub agent: String,
    /// The wrapped command line.
    pub command: String,
    /// Correlating trace id, if any.
    pub trace_id: Option<String>,
    /// Start timestamp (microseconds).
    pub started_at: i64,
    /// End timestamp (microseconds), if finished.
    pub ended_at: Option<i64>,
    /// Process exit code, if finished.
    pub exit_code: Option<i64>,
}

/// A risk / shadow finding (advisory, local-only).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct InventoryFinding {
    /// Row id.
    pub id: String,
    /// Owning endpoint id, if known.
    pub endpoint_id: Option<String>,
    /// Finding kind (`unsanctioned_agent`, `shadow_mcp`, `mcp_secret`, …).
    pub kind: String,
    /// Severity (`info`..`critical`), if assigned.
    pub severity: Option<String>,
    /// The agent/MCP/path the finding is about.
    pub subject: Option<String>,
    /// Human-readable description.
    pub message: Option<String>,
    /// Creation timestamp (microseconds).
    pub created_at: i64,
}

/// The full inventory snapshot returned by `/api/inventory` — all five tabs in
/// one payload so the UI can switch tabs without refetching.
#[derive(Clone, Debug, Serialize, PartialEq, Default)]
pub struct InventorySnapshot {
    /// Known endpoints.
    pub endpoints: Vec<Endpoint>,
    /// Discovered agent installs.
    pub agents: Vec<AgentInstall>,
    /// Configured MCP servers.
    pub mcp_servers: Vec<McpServer>,
    /// Recorded agent sessions.
    pub sessions: Vec<AgentSession>,
    /// Risk / shadow findings.
    pub findings: Vec<InventoryFinding>,
}

/// Load the complete inventory snapshot from the store in one read.
///
/// # Errors
/// Returns a store error if any query fails.
pub fn load_snapshot(store: &Store) -> StoreResult<InventorySnapshot> {
    store.read(|conn| {
        Ok(InventorySnapshot {
            endpoints: query_endpoints(conn)?,
            agents: query_agents(conn)?,
            mcp_servers: query_mcp_servers(conn)?,
            sessions: query_sessions(conn)?,
            findings: query_findings(conn)?,
        })
    })
}

fn query_endpoints(conn: &Connection) -> StoreResult<Vec<Endpoint>> {
    let mut stmt = conn.prepare(
        "SELECT id, hostname, os, arch, first_seen, last_seen \
         FROM endpoints ORDER BY last_seen DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Endpoint {
            id: r.get(0)?,
            hostname: r.get(1)?,
            os: r.get(2)?,
            arch: r.get(3)?,
            first_seen: r.get(4)?,
            last_seen: r.get(5)?,
        })
    })?;
    collect(rows)
}

fn query_agents(conn: &Connection) -> StoreResult<Vec<AgentInstall>> {
    let mut stmt = conn.prepare(
        "SELECT id, endpoint_id, name, version, path, sanctioned, discovered_at \
         FROM agent_installs ORDER BY name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(AgentInstall {
            id: r.get(0)?,
            endpoint_id: r.get(1)?,
            name: r.get(2)?,
            version: r.get(3)?,
            path: r.get(4)?,
            sanctioned: r.get::<_, i64>(5)? != 0,
            discovered_at: r.get(6)?,
        })
    })?;
    collect(rows)
}

fn query_mcp_servers(conn: &Connection) -> StoreResult<Vec<McpServer>> {
    let mut stmt = conn.prepare(
        "SELECT id, endpoint_id, name, source_config, command, transport, \
                sanctioned, has_secret, discovered_at \
         FROM mcp_servers ORDER BY name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(McpServer {
            id: r.get(0)?,
            endpoint_id: r.get(1)?,
            name: r.get(2)?,
            source_config: r.get(3)?,
            command: r.get(4)?,
            transport: r.get(5)?,
            sanctioned: r.get::<_, i64>(6)? != 0,
            has_secret: r.get::<_, i64>(7)? != 0,
            discovered_at: r.get(8)?,
        })
    })?;
    collect(rows)
}

fn query_sessions(conn: &Connection) -> StoreResult<Vec<AgentSession>> {
    let mut stmt = conn.prepare(
        "SELECT id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code \
         FROM agent_sessions ORDER BY started_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(AgentSession {
            id: r.get(0)?,
            endpoint_id: r.get(1)?,
            agent: r.get(2)?,
            command: r.get(3)?,
            trace_id: r.get(4)?,
            started_at: r.get(5)?,
            ended_at: r.get(6)?,
            exit_code: r.get(7)?,
        })
    })?;
    collect(rows)
}

fn query_findings(conn: &Connection) -> StoreResult<Vec<InventoryFinding>> {
    let mut stmt = conn.prepare(
        "SELECT id, endpoint_id, kind, severity, subject, message, created_at \
         FROM inventory_findings ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(InventoryFinding {
            id: r.get(0)?,
            endpoint_id: r.get(1)?,
            kind: r.get(2)?,
            severity: r.get(3)?,
            subject: r.get(4)?,
            message: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;
    collect(rows)
}

/// Collect a rusqlite mapped-rows iterator into a `Vec`, surfacing the first
/// row error as a store error.
fn collect<T>(
    rows: impl Iterator<Item = rusqlite::Result<T>>,
) -> StoreResult<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}
