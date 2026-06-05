//! Multi-endpoint inventory roll-up (plan "Phase 4 — Complete Tier & Fleet" →
//! Hub: "the multi-endpoint roll-up of the existing inventory").
//!
//! The local inventory (`logbook-inventory`) records, per endpoint, the
//! discovered agent installs, configured MCP servers, and `logbook agent`
//! sessions into the shared store tables (`endpoints`, `agent_installs`,
//! `mcp_servers`, `agent_sessions`), each keyed by `endpoint_id`. When many
//! endpoints forward into one hub store, this read **aggregates across all
//! endpoint ids**: a fleet-wide count plus a per-endpoint breakdown, so an
//! operator sees "across the fleet: N agents, M MCP servers, K sessions, on E
//! endpoints" and can drill into any one endpoint.
//!
//! This is a **read-only** aggregation over already-persisted, already-redacted
//! inventory rows — it discovers nothing and mutates nothing.

use logbook_store::Store;
use serde::Serialize;

use crate::error::Result;

/// One endpoint's slice of the fleet inventory roll-up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EndpointRollup {
    /// The endpoint id (`endpoints.id`).
    pub endpoint_id: String,
    /// Hostname, if the `endpoints` row is present (an endpoint can have
    /// forwarded sessions before its `endpoints` row, so this is optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Operating system, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Number of discovered agent installs on this endpoint.
    pub agents: u64,
    /// Number of configured MCP servers on this endpoint.
    pub mcp_servers: u64,
    /// Number of recorded `logbook agent` sessions on this endpoint.
    pub sessions: u64,
}

/// The fleet-wide inventory roll-up: totals plus a per-endpoint breakdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FleetRollup {
    /// A short schema marker so a consumer can tell roll-up payloads apart.
    pub kind: &'static str,
    /// Number of distinct endpoints seen across the inventory tables.
    pub endpoints: u64,
    /// Fleet-wide total agent installs (summed across endpoints).
    pub total_agents: u64,
    /// Fleet-wide total MCP servers.
    pub total_mcp_servers: u64,
    /// Fleet-wide total recorded sessions.
    pub total_sessions: u64,
    /// Per-endpoint breakdown, ordered by `endpoint_id`.
    pub per_endpoint: Vec<EndpointRollup>,
}

/// Build the multi-endpoint inventory [`FleetRollup`] from the store.
///
/// Counts agent installs, MCP servers, and sessions **grouped by `endpoint_id`**
/// across the inventory tables, unions in every endpoint that appears in the
/// `endpoints` table (so a discovered-but-empty endpoint still shows, with
/// zeros), and joins each endpoint's `hostname`/`os` where the `endpoints` row
/// exists. The totals are the column sums; `endpoints` is the count of distinct
/// endpoint ids observed.
///
/// Read-only; safe to run concurrently with writes.
///
/// # Errors
/// Returns a [`HubError::Store`](crate::HubError::Store) if a read fails.
pub fn fleet_rollup(store: &Store) -> Result<FleetRollup> {
    let per_endpoint = store.read(|conn| {
        // Per-table counts grouped by endpoint, unioned with the endpoints table
        // so an endpoint with zero of a given kind still appears. A LEFT JOIN
        // from the union of all endpoint ids onto each per-table aggregate keeps
        // the read in one SQLite pass.
        //
        // `endpoint_ids` = every endpoint id that appears anywhere (endpoints
        // row OR any owned inventory/session row). Then left-join the grouped
        // counts and the endpoints metadata.
        let sql = "
            WITH endpoint_ids AS (
                SELECT id AS endpoint_id FROM endpoints
                UNION SELECT endpoint_id FROM agent_installs
                UNION SELECT endpoint_id FROM mcp_servers
                UNION SELECT endpoint_id FROM agent_sessions
            ),
            ai AS (
                SELECT endpoint_id, COUNT(*) AS n FROM agent_installs GROUP BY endpoint_id
            ),
            ms AS (
                SELECT endpoint_id, COUNT(*) AS n FROM mcp_servers GROUP BY endpoint_id
            ),
            se AS (
                SELECT endpoint_id, COUNT(*) AS n FROM agent_sessions GROUP BY endpoint_id
            )
            SELECT
                e.endpoint_id,
                ep.hostname,
                ep.os,
                COALESCE(ai.n, 0) AS agents,
                COALESCE(ms.n, 0) AS mcp_servers,
                COALESCE(se.n, 0) AS sessions
            FROM endpoint_ids e
            LEFT JOIN endpoints ep ON ep.id = e.endpoint_id
            LEFT JOIN ai ON ai.endpoint_id = e.endpoint_id
            LEFT JOIN ms ON ms.endpoint_id = e.endpoint_id
            LEFT JOIN se ON se.endpoint_id = e.endpoint_id
            ORDER BY e.endpoint_id ASC
        ";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(EndpointRollup {
                    endpoint_id: r.get(0)?,
                    hostname: r.get(1)?,
                    os: r.get(2)?,
                    agents: r.get::<_, i64>(3)? as u64,
                    mcp_servers: r.get::<_, i64>(4)? as u64,
                    sessions: r.get::<_, i64>(5)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })?;

    let mut total_agents = 0u64;
    let mut total_mcp_servers = 0u64;
    let mut total_sessions = 0u64;
    for e in &per_endpoint {
        total_agents += e.agents;
        total_mcp_servers += e.mcp_servers;
        total_sessions += e.sessions;
    }

    Ok(FleetRollup {
        kind: "logbook.hub.fleet_rollup.v1",
        endpoints: per_endpoint.len() as u64,
        total_agents,
        total_mcp_servers,
        total_sessions,
        per_endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_inventory::model::{AgentInstall, Endpoint, McpServer, McpTransport};
    use logbook_inventory::store_ext::{
        upsert_agent_installs, upsert_endpoint, upsert_mcp_servers,
    };
    use logbook_inventory::wrapper::AgentSessionRecord;

    fn endpoint(id: &str, host: &str) -> Endpoint {
        Endpoint {
            id: id.into(),
            hostname: host.into(),
            os: "linux".into(),
            arch: "x86_64".into(),
        }
    }

    fn agent(id: &str, name: &str) -> AgentInstall {
        AgentInstall {
            id: id.into(),
            name: name.into(),
            version: None,
            path: format!("/usr/bin/{name}"),
            sanctioned: true,
        }
    }

    fn mcp(id: &str, name: &str) -> McpServer {
        McpServer {
            id: id.into(),
            name: name.into(),
            source_config: "/tmp/.mcp.json".into(),
            command: Some("x".into()),
            transport: McpTransport::Stdio,
            sanctioned: true,
            has_secret: false,
        }
    }

    fn session(id: &str, endpoint_id: &str) -> AgentSessionRecord {
        AgentSessionRecord {
            session_id: id.into(),
            endpoint_id: Some(endpoint_id.into()),
            agent: "claude".into(),
            command: "claude --help".into(),
            trace_id: logbook_core::TraceId::new().to_hex(),
            started_at: 1,
            ended_at: Some(2),
            exit_code: Some(0),
        }
    }

    #[test]
    fn rollup_aggregates_two_endpoints() {
        let store = Store::open_in_memory().unwrap();

        // Endpoint A: 2 agents, 1 MCP, 1 session.
        upsert_endpoint(&store, &endpoint("endpoint-a", "alpha")).unwrap();
        upsert_agent_installs(
            &store,
            "endpoint-a",
            &[agent("a-claude", "claude"), agent("a-codex", "codex")],
        )
        .unwrap();
        upsert_mcp_servers(&store, "endpoint-a", &[mcp("a-fs", "filesystem")]).unwrap();
        logbook_inventory::store_ext::insert_agent_session(&store, &session("sess-a1", "endpoint-a"))
            .unwrap();

        // Endpoint B: 1 agent, 2 MCP, 2 sessions.
        upsert_endpoint(&store, &endpoint("endpoint-b", "bravo")).unwrap();
        upsert_agent_installs(&store, "endpoint-b", &[agent("b-aider", "aider")]).unwrap();
        upsert_mcp_servers(
            &store,
            "endpoint-b",
            &[mcp("b-fs", "filesystem"), mcp("b-gh", "github")],
        )
        .unwrap();
        logbook_inventory::store_ext::insert_agent_session(&store, &session("sess-b1", "endpoint-b"))
            .unwrap();
        logbook_inventory::store_ext::insert_agent_session(&store, &session("sess-b2", "endpoint-b"))
            .unwrap();

        let roll = fleet_rollup(&store).unwrap();
        assert_eq!(roll.endpoints, 2, "two distinct endpoints");
        assert_eq!(roll.total_agents, 3, "2 + 1 agents across the fleet");
        assert_eq!(roll.total_mcp_servers, 3, "1 + 2 MCP servers");
        assert_eq!(roll.total_sessions, 3, "1 + 2 sessions");

        // Per-endpoint breakdown, ordered by id.
        assert_eq!(roll.per_endpoint.len(), 2);
        let a = &roll.per_endpoint[0];
        assert_eq!(a.endpoint_id, "endpoint-a");
        assert_eq!(a.hostname.as_deref(), Some("alpha"));
        assert_eq!(a.agents, 2);
        assert_eq!(a.mcp_servers, 1);
        assert_eq!(a.sessions, 1);
        let b = &roll.per_endpoint[1];
        assert_eq!(b.endpoint_id, "endpoint-b");
        assert_eq!(b.agents, 1);
        assert_eq!(b.mcp_servers, 2);
        assert_eq!(b.sessions, 2);
    }

    #[test]
    fn rollup_includes_endpoint_with_only_sessions() {
        // An endpoint whose only inventory is a forwarded session (no agents or
        // MCP servers discovered) must still appear in the roll-up with its
        // session counted. The `endpoints` row is required: `agent_sessions.endpoint_id`
        // is a foreign key (foreign_keys=ON), so a session can never reference a
        // missing endpoint.
        let store = Store::open_in_memory().unwrap();
        upsert_endpoint(&store, &endpoint("endpoint-ghost", "ghost")).unwrap();
        logbook_inventory::store_ext::insert_agent_session(
            &store,
            &session("sess-x", "endpoint-ghost"),
        )
        .unwrap();

        let roll = fleet_rollup(&store).unwrap();
        assert_eq!(roll.endpoints, 1);
        assert_eq!(roll.per_endpoint[0].endpoint_id, "endpoint-ghost");
        assert_eq!(roll.per_endpoint[0].hostname.as_deref(), Some("ghost"));
        assert_eq!(roll.per_endpoint[0].sessions, 1);
        assert_eq!(roll.per_endpoint[0].agents, 0);
        assert_eq!(roll.per_endpoint[0].mcp_servers, 0);
        assert_eq!(roll.total_sessions, 1);
    }

    #[test]
    fn rollup_empty_store_is_zero() {
        let store = Store::open_in_memory().unwrap();
        let roll = fleet_rollup(&store).unwrap();
        assert_eq!(roll.endpoints, 0);
        assert_eq!(roll.total_agents, 0);
        assert!(roll.per_endpoint.is_empty());
    }
}
