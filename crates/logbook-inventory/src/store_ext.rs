//! Persistence helpers for the inventory tables (plan §2).
//!
//! These run raw SQL against the inventory tables via the `Store`'s arbitrary
//! read/write escape hatches (`Store::write` / `Store::read`). The tables
//! (`endpoints`, `agent_installs`, `mcp_servers`, `agent_sessions`,
//! `agent_actions`, `inventory_findings`) are created by the store's V1
//! migration; we only INSERT/UPSERT and SELECT here.
//!
//! Everything written here is already redacted upstream (plan §9).

use logbook_store::Store;
use rusqlite::params;

use crate::error::Result;
use crate::model::{AgentInstall, Endpoint, InventoryFinding, McpServer, SessionTranscriptRecord};
use crate::wrapper::{AgentAction, AgentSessionRecord};

/// Current wall-clock microseconds (matches the store's INTEGER-µs convention).
fn now_micros() -> i64 {
    logbook_core::MicrosTimestamp::now().as_micros()
}

/// Upsert the endpoint row (idempotent on `id`; refreshes `last_seen`).
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn upsert_endpoint(store: &Store, ep: &Endpoint) -> Result<()> {
    let ep = ep.clone();
    let now = now_micros();
    store.write(move |conn| {
        conn.execute(
            "INSERT INTO endpoints (id, hostname, os, arch, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                os       = excluded.os,
                arch     = excluded.arch,
                last_seen = excluded.last_seen",
            params![ep.id, ep.hostname, ep.os, ep.arch, now],
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Upsert all agent installs for an endpoint.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn upsert_agent_installs(
    store: &Store,
    endpoint_id: &str,
    installs: &[AgentInstall],
) -> Result<()> {
    let endpoint_id = endpoint_id.to_string();
    let installs = installs.to_vec();
    let now = now_micros();
    store.write(move |conn| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO agent_installs
                   (id, endpoint_id, name, version, path, sanctioned, discovered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                   version = excluded.version,
                   path = excluded.path,
                   sanctioned = excluded.sanctioned,
                   discovered_at = excluded.discovered_at",
            )?;
            for a in &installs {
                stmt.execute(params![
                    a.id,
                    endpoint_id,
                    a.name,
                    a.version,
                    a.path,
                    i64::from(a.sanctioned),
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })?;
    Ok(())
}

/// Upsert all MCP servers for an endpoint.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn upsert_mcp_servers(store: &Store, endpoint_id: &str, servers: &[McpServer]) -> Result<()> {
    let endpoint_id = endpoint_id.to_string();
    let servers = servers.to_vec();
    let now = now_micros();
    store.write(move |conn| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO mcp_servers
                   (id, endpoint_id, name, source_config, command, transport, sanctioned, has_secret, discovered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                   source_config = excluded.source_config,
                   command = excluded.command,
                   transport = excluded.transport,
                   sanctioned = excluded.sanctioned,
                   has_secret = excluded.has_secret,
                   discovered_at = excluded.discovered_at",
            )?;
            for s in &servers {
                stmt.execute(params![
                    s.id,
                    endpoint_id,
                    s.name,
                    s.source_config,
                    s.command,
                    s.transport.as_str(),
                    i64::from(s.sanctioned),
                    i64::from(s.has_secret),
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })?;
    Ok(())
}

/// Insert risk/shadow findings (one row each). Findings are append-only with a
/// fresh id per scan, so repeated scans accumulate a history; callers that want
/// a clean slate can clear first via [`clear_inventory_findings`].
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn insert_inventory_findings(
    store: &Store,
    endpoint_id: &str,
    findings: &[InventoryFinding],
) -> Result<()> {
    let endpoint_id = endpoint_id.to_string();
    let findings = findings.to_vec();
    let now = now_micros();
    store.write(move |conn| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO inventory_findings
                   (id, endpoint_id, kind, severity, subject, message, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for f in &findings {
                stmt.execute(params![
                    f.id,
                    endpoint_id,
                    f.kind,
                    f.severity.as_str(),
                    f.subject,
                    f.message,
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })?;
    Ok(())
}

/// Insert an `agent_sessions` row.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn insert_agent_session(store: &Store, rec: &AgentSessionRecord) -> Result<()> {
    let rec = rec.clone();
    store.write(move |conn| {
        conn.execute(
            "INSERT OR REPLACE INTO agent_sessions
               (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rec.session_id,
                rec.endpoint_id,
                rec.agent,
                rec.command,
                rec.trace_id,
                rec.started_at,
                rec.ended_at,
                rec.exit_code,
            ],
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Insert the `agent_actions` (session-accurate file diffs) observed during a
/// session, including the Phase-1 V2 columns: the redacted `diff` body, its
/// pre-truncation `diff_bytes`, the `post_hash`, `revert_safe`, and
/// `max_sensitivity` (plan §1.2). Everything written here is already redacted
/// upstream by the wrapper.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn insert_agent_actions(
    store: &Store,
    session_id: &str,
    actions: &[AgentAction],
) -> Result<()> {
    let session_id = session_id.to_string();
    let actions = actions.to_vec();
    store.write(move |conn| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO agent_actions
                   (id, session_id, kind, path, detail, observed_at,
                    diff, diff_bytes, post_hash, revert_safe, max_sensitivity)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for a in &actions {
                stmt.execute(params![
                    a.id,
                    session_id,
                    a.kind,
                    a.path,
                    a.detail,
                    a.observed_at,
                    a.diff,
                    // SQLite stores INTEGER as i64; widen the byte count safely.
                    a.diff_bytes.map(|n| n as i64),
                    a.post_hash,
                    i64::from(a.revert_safe),
                    a.max_sensitivity,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })?;
    Ok(())
}

/// One recorded `agent_actions` row, projected for detection: the affected
/// `path` (nullable in the schema), the redacted `diff` body (NULL when diffs
/// were off or the file exceeded the baseline caps), and the owning session's
/// `trace_id` (joined from `agent_sessions`, since `agent_actions` carries no
/// trace column of its own; also nullable).
///
/// `logbook detect` / `logbook guard` fold these into the rule input as synthetic
/// `Kind::Agent` diff events so the `secret_in_diff` rule sees the per-file diffs
/// — the diffs that `logbook agent` stores here rather than in the `events`
/// table.
pub type AgentActionDiff = (Option<String>, Option<String>, Option<String>);

/// Load a session's recorded `agent_actions` (oldest-first), each joined to its
/// session's `trace_id`, for detection. Mirrors the read pattern in the UI's
/// `query_actions` (`SELECT … FROM agent_actions WHERE session_id = ?1 ORDER BY
/// observed_at ASC`) but pulls the columns the synthetic diff event needs: the
/// `path`, the redacted `diff`, and the owning session's `trace_id` (a LEFT JOIN
/// so an action survives even if the session header is missing a trace).
///
/// Everything returned is already redacted upstream by the wrapper — the `diff`
/// is the redacted start→end content diff (plan §9), so callers only ever see the
/// redaction *marker* a scrubbed secret leaves, never a raw value.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the read fails.
pub fn agent_actions_for_session(
    store: &Store,
    session_id: &str,
) -> Result<Vec<AgentActionDiff>> {
    let session_id = session_id.to_string();
    let rows = store.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT a.path, a.diff, s.trace_id \
             FROM agent_actions a \
             LEFT JOIN agent_sessions s ON s.id = a.session_id \
             WHERE a.session_id = ?1 \
             ORDER BY a.observed_at ASC",
        )?;
        let mapped = stmt
            .query_map(params![session_id], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(mapped)
    })?;
    Ok(rows)
}

/// Load the most recent `agent_actions` across **all** sessions (newest-first,
/// capped by `limit`), each joined to its session's `trace_id`, for the
/// no-session `logbook detect` "what looks risky lately?" pass. Same projection
/// and join as [`agent_actions_for_session`]; only the scope (all sessions, a
/// recency cap) differs.
///
/// Like [`agent_actions_for_session`], everything returned is already redacted
/// upstream by the wrapper.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the read fails.
pub fn recent_agent_action_diffs(store: &Store, limit: u32) -> Result<Vec<AgentActionDiff>> {
    let rows = store.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT a.path, a.diff, s.trace_id \
             FROM agent_actions a \
             LEFT JOIN agent_sessions s ON s.id = a.session_id \
             ORDER BY a.observed_at DESC \
             LIMIT ?1",
        )?;
        let mapped = stmt
            .query_map(params![limit], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(mapped)
    })?;
    Ok(rows)
}

/// Insert (or replace) the `session_transcripts` row for a session (plan §1.3):
/// pointers + metadata for the captured agent session's redacted transcript (the
/// bulk bytes already live on disk). Keyed on `session_id`, so re-running the
/// wrapper for the same session replaces the row. Written by the wrapper from
/// [`logbook_capture::CaptureOutcome::transcript`].
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn insert_session_transcript(store: &Store, rec: &SessionTranscriptRecord) -> Result<()> {
    let rec = rec.clone();
    let now = now_micros();
    store.write(move |conn| {
        conn.execute(
            "INSERT OR REPLACE INTO session_transcripts
               (session_id, trace_id, terminal_log_path, text_path,
                line_count, byte_size, max_sensitivity, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rec.session_id,
                rec.trace_id,
                rec.terminal_log_path,
                rec.text_path,
                rec.line_count,
                rec.byte_size,
                rec.max_sensitivity,
                now,
            ],
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Delete all inventory findings for an endpoint (used to refresh on re-scan).
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the write fails.
pub fn clear_inventory_findings(store: &Store, endpoint_id: &str) -> Result<()> {
    let endpoint_id = endpoint_id.to_string();
    store.write(move |conn| {
        conn.execute(
            "DELETE FROM inventory_findings WHERE endpoint_id = ?1",
            params![endpoint_id],
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Count rows in an inventory table (for tests / quick reporting).
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the read fails.
pub fn count_rows(store: &Store, table: InventoryTable) -> Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM {}", table.name());
    let n = store.read(move |conn| Ok(conn.query_row(&sql, [], |r| r.get::<_, i64>(0))?))?;
    Ok(n)
}

/// Load the persisted findings for an endpoint (newest first).
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the read fails.
pub fn load_inventory_findings(store: &Store, endpoint_id: &str) -> Result<Vec<InventoryFinding>> {
    let endpoint_id = endpoint_id.to_string();
    let rows = store.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, kind, severity, subject, message
             FROM inventory_findings
             WHERE endpoint_id = ?1
             ORDER BY created_at DESC, id",
        )?;
        let mapped = stmt
            .query_map(params![endpoint_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(mapped)
    })?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, sev, subject, message)| InventoryFinding {
            id,
            kind,
            // Unrecognized / NULL severities lossily default to `Info`, matching
            // the prior local `parse_severity` behavior.
            severity: sev
                .as_deref()
                .and_then(logbook_core::Severity::from_wire)
                .unwrap_or(logbook_core::Severity::Info),
            subject: subject.unwrap_or_default(),
            message: message.unwrap_or_default(),
        })
        .collect())
}

/// The inventory tables, for the typed `count_rows` helper.
#[derive(Clone, Copy, Debug)]
pub enum InventoryTable {
    /// `endpoints`
    Endpoints,
    /// `agent_installs`
    AgentInstalls,
    /// `mcp_servers`
    McpServers,
    /// `agent_sessions`
    AgentSessions,
    /// `agent_actions`
    AgentActions,
    /// `session_transcripts`
    SessionTranscripts,
    /// `inventory_findings`
    InventoryFindings,
}

impl InventoryTable {
    /// The SQL table name. (A closed enum, so interpolating this into SQL is
    /// safe — never user input.)
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            InventoryTable::Endpoints => "endpoints",
            InventoryTable::AgentInstalls => "agent_installs",
            InventoryTable::McpServers => "mcp_servers",
            InventoryTable::AgentSessions => "agent_sessions",
            InventoryTable::AgentActions => "agent_actions",
            InventoryTable::SessionTranscripts => "session_transcripts",
            InventoryTable::InventoryFindings => "inventory_findings",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{finding_kind, McpTransport};
    use logbook_core::Severity;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
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
    fn upsert_endpoint_is_idempotent() {
        let s = mem();
        upsert_endpoint(&s, &ep()).unwrap();
        upsert_endpoint(&s, &ep()).unwrap();
        assert_eq!(count_rows(&s, InventoryTable::Endpoints).unwrap(), 1);
    }

    #[test]
    fn agent_install_upsert_replaces() {
        let s = mem();
        upsert_endpoint(&s, &ep()).unwrap();
        let mut a = AgentInstall {
            id: "agent-endpoint-test-claude".into(),
            name: "claude".into(),
            version: None,
            path: "/usr/bin/claude".into(),
            sanctioned: true,
        };
        upsert_agent_installs(&s, "endpoint-test", std::slice::from_ref(&a)).unwrap();
        a.version = Some("1.2.3".into());
        a.path = "/opt/claude".into();
        upsert_agent_installs(&s, "endpoint-test", std::slice::from_ref(&a)).unwrap();
        assert_eq!(count_rows(&s, InventoryTable::AgentInstalls).unwrap(), 1);
    }

    #[test]
    fn mcp_server_roundtrips_with_has_secret() {
        let s = mem();
        upsert_endpoint(&s, &ep()).unwrap();
        let server = McpServer {
            id: "mcp-x".into(),
            name: "evil".into(),
            source_config: "/tmp/.mcp.json".into(),
            command: Some("x".into()),
            transport: McpTransport::Stdio,
            sanctioned: false,
            has_secret: true,
        };
        upsert_mcp_servers(&s, "endpoint-test", std::slice::from_ref(&server)).unwrap();
        assert_eq!(count_rows(&s, InventoryTable::McpServers).unwrap(), 1);
        // Verify has_secret stored as 1.
        let flag = s
            .read(|conn| {
                Ok(
                    conn.query_row("SELECT has_secret FROM mcp_servers", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(flag, 1);
    }

    #[test]
    fn findings_insert_clear_and_load() {
        let s = mem();
        upsert_endpoint(&s, &ep()).unwrap();
        let finding = InventoryFinding {
            id: "f1".into(),
            kind: finding_kind::SHADOW_MCP.into(),
            severity: Severity::Medium,
            subject: "evil".into(),
            message: "shadow MCP server".into(),
        };
        insert_inventory_findings(&s, "endpoint-test", std::slice::from_ref(&finding)).unwrap();
        let loaded = load_inventory_findings(&s, "endpoint-test").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kind, finding_kind::SHADOW_MCP);
        assert_eq!(loaded[0].severity, Severity::Medium);

        clear_inventory_findings(&s, "endpoint-test").unwrap();
        assert!(load_inventory_findings(&s, "endpoint-test")
            .unwrap()
            .is_empty());
    }
}
