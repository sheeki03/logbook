//! Session replay read models and queries (Orbit plan §1.4).
//!
//! Phase 1 turns `logbook agent -- <cli>` into a fully replayable session. The
//! capture pipeline + the inventory wrapper write three correlated artifacts
//! under one `session_id`/`trace_id`:
//!
//! - an `agent_sessions` row (the session header — agent, command, exit code);
//! - a `session_transcripts` row (pointers to the redacted transcript files on
//!   disk + line/byte counts — added in migration V2);
//! - `agent_actions` rows (session-accurate, **redacted** per-file diffs with
//!   `diff_bytes` / `post_hash` / `revert_safe` — V2 columns);
//! - ordered per-line `events` under the shared trace.
//!
//! This module owns the *read* side the Sessions view needs: a newest-first
//! master list ([`list_sessions`]) and a per-session detail
//! ([`load_session`]) that joins all four. Both go through the store's generic
//! [`Store::read`] escape hatch (same pattern as
//! [`crate::inventory::load_snapshot`]).
//!
//! Everything read here is already redacted at write time (the persisted diff is
//! the redacted start→end content diff; the secrets floor scrubbed the
//! transcript before it hit disk; plan §9), so it is safe to ship to the
//! browser. The transcript paths are pointers only — the bulk bytes are streamed
//! from disk, never duplicated into the DB.

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use logbook_core::Event;
use logbook_store::error::Result as StoreResult;
use logbook_store::Store;

/// One row in the Sessions master list: the `agent_sessions` header plus two
/// derived columns — the count of recorded `agent_actions` and whether a
/// `session_transcripts` row exists.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SessionSummary {
    /// Session id (== `agent_sessions.id`).
    pub session_id: String,
    /// Agent name (`claude`, `codex`, …).
    pub agent: String,
    /// The wrapped command line.
    pub command: String,
    /// Start timestamp (microseconds since UNIX epoch).
    pub started_at: i64,
    /// End timestamp (microseconds), if the session finished.
    pub ended_at: Option<i64>,
    /// Process exit code, if the session finished.
    pub exit_code: Option<i64>,
    /// Number of recorded file-diff actions in this session.
    pub action_count: i64,
    /// Whether a transcript (terminal log + cleaned text) was captured.
    pub has_transcript: bool,
}

/// Transcript pointers + metadata for a session (the `session_transcripts` row).
/// The files live on disk; these are pointers, not bulk bytes.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SessionTranscript {
    /// Path to the redacted terminal log (`*.terminal.log`), if recorded.
    pub terminal_log_path: Option<String>,
    /// Path to the ANSI-stripped cleaned text (`*.txt`), if recorded.
    pub text_path: Option<String>,
    /// Number of transcript lines, if recorded.
    pub line_count: Option<i64>,
    /// On-disk transcript size in bytes, if recorded.
    pub byte_size: Option<i64>,
}

/// One recorded action (file diff) within a session — the V2 `agent_actions`
/// columns the replay UI renders (truncated + revert-safe badges).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SessionAction {
    /// Action kind (`file_modified` | `file_added` | `file_deleted` | …).
    pub kind: String,
    /// Affected path, if any.
    pub path: Option<String>,
    /// The redacted, size-capped per-file diff. `None` when diffs were off or
    /// the file exceeded the baseline caps (diff omitted).
    pub diff: Option<String>,
    /// Original (pre-truncation) diff byte length. `diff_bytes > len(diff)`
    /// flags a truncated body (the UI renders a "truncated" badge).
    pub diff_bytes: Option<i64>,
    /// Post-state content hash of the file after the change (used by a future
    /// `logbook revert`).
    pub post_hash: Option<String>,
    /// Whether this action can be safely reverted (clean tree at start, or an
    /// opt-in encrypted preimage was stored).
    pub revert_safe: bool,
}

/// The full per-session replay payload returned by `GET /api/sessions/:id`: the
/// session header, the optional transcript pointers, the recorded diffs, and the
/// ordered event stream under the shared trace.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SessionDetail {
    /// The session header (same shape as the master-list row).
    pub session: SessionSummary,
    /// Transcript pointers + metadata, if a transcript was captured.
    pub transcript: Option<SessionTranscript>,
    /// Recorded file-diff actions, in observation order.
    pub actions: Vec<SessionAction>,
    /// The ordered (oldest-first) event stream for this session's trace — the
    /// per-line transcript events, commands, tool/LLM events, etc. Empty when
    /// the session has no `trace_id` (so there is nothing to correlate).
    pub events: Vec<Event>,
}

/// List all recorded sessions, newest-first, with their action count and a
/// has-transcript flag.
///
/// The action count is a correlated subquery rather than a `GROUP BY` join so a
/// session with zero actions still appears (a `LEFT JOIN … COUNT` would too, but
/// the subquery keeps the row shape flat and avoids a `GROUP BY` over every
/// `agent_sessions` column).
///
/// # Errors
/// Returns a store error if the read fails.
pub fn list_sessions(store: &Store) -> StoreResult<Vec<SessionSummary>> {
    store.read(query_session_summaries)
}

/// Load one session's full replay detail by id, or `None` if no such session.
///
/// Reads the `agent_sessions` header, the `session_transcripts` row (if any),
/// the `agent_actions` (with diffs), and — when the session carries a
/// `trace_id` — the ordered trace via [`Store::trace`]. All in one read so the
/// detail is internally consistent.
///
/// # Errors
/// Returns a store error if any read fails.
pub fn load_session(store: &Store, session_id: &str) -> StoreResult<Option<SessionDetail>> {
    let session_id = session_id.to_string();
    store.read(move |conn| {
        let Some(session) = query_session_header(conn, &session_id)? else {
            return Ok(None);
        };
        let transcript = query_transcript(conn, &session_id)?;
        let actions = query_actions(conn, &session_id)?;
        // The ordered event stream is keyed by trace, not session: the per-line
        // transcript/command/tool events all share the session's trace_id. A
        // session with no trace_id has no correlated events.
        let events = match query_session_trace_id(conn, &session_id)? {
            Some(trace_id) => logbook_store::get_trace(conn, &trace_id)?,
            None => Vec::new(),
        };
        Ok(Some(SessionDetail {
            session,
            transcript,
            actions,
            events,
        }))
    })
}

/// Map an `agent_sessions` row (with the derived `action_count` /
/// `has_transcript`) into a [`SessionSummary`]. Shared by the list and detail
/// queries so the header shape never drifts.
fn map_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionSummary> {
    Ok(SessionSummary {
        session_id: row.get(0)?,
        agent: row.get(1)?,
        command: row.get(2)?,
        started_at: row.get(3)?,
        ended_at: row.get(4)?,
        exit_code: row.get(5)?,
        action_count: row.get(6)?,
        has_transcript: row.get::<_, i64>(7)? != 0,
    })
}

/// The shared SELECT list for a session header + its two derived columns. The
/// trailing `{filter}` lets the list query order all rows while the detail query
/// pins a single id.
const SESSION_SELECT: &str = "SELECT s.id, s.agent, s.command, s.started_at, s.ended_at, s.exit_code, \
            (SELECT COUNT(*) FROM agent_actions a WHERE a.session_id = s.id) AS action_count, \
            EXISTS (SELECT 1 FROM session_transcripts t WHERE t.session_id = s.id) AS has_transcript \
     FROM agent_sessions s";

fn query_session_summaries(conn: &Connection) -> StoreResult<Vec<SessionSummary>> {
    let sql = format!("{SESSION_SELECT} ORDER BY s.started_at DESC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_summary)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn query_session_header(
    conn: &Connection,
    session_id: &str,
) -> StoreResult<Option<SessionSummary>> {
    let sql = format!("{SESSION_SELECT} WHERE s.id = ?1");
    let mut stmt = conn.prepare(&sql)?;
    let row = stmt
        .query_row([session_id], map_summary)
        .optional()?;
    Ok(row)
}

fn query_transcript(
    conn: &Connection,
    session_id: &str,
) -> StoreResult<Option<SessionTranscript>> {
    let mut stmt = conn.prepare(
        "SELECT terminal_log_path, text_path, line_count, byte_size \
         FROM session_transcripts WHERE session_id = ?1",
    )?;
    let row = stmt
        .query_row([session_id], |r| {
            Ok(SessionTranscript {
                terminal_log_path: r.get(0)?,
                text_path: r.get(1)?,
                line_count: r.get(2)?,
                byte_size: r.get(3)?,
            })
        })
        .optional()?;
    Ok(row)
}

fn query_actions(conn: &Connection, session_id: &str) -> StoreResult<Vec<SessionAction>> {
    // `revert_safe` is NOT NULL DEFAULT 0 (V2); the diff/diff_bytes/post_hash
    // columns are nullable and read NULL on pre-V2 rows.
    let mut stmt = conn.prepare(
        "SELECT kind, path, diff, diff_bytes, post_hash, revert_safe \
         FROM agent_actions WHERE session_id = ?1 ORDER BY observed_at ASC",
    )?;
    let rows = stmt.query_map([session_id], |r| {
        Ok(SessionAction {
            kind: r.get(0)?,
            path: r.get(1)?,
            diff: r.get(2)?,
            diff_bytes: r.get(3)?,
            post_hash: r.get(4)?,
            revert_safe: r.get::<_, i64>(5)? != 0,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn query_session_trace_id(
    conn: &Connection,
    session_id: &str,
) -> StoreResult<Option<String>> {
    let mut stmt = conn.prepare("SELECT trace_id FROM agent_sessions WHERE id = ?1")?;
    // The column itself is nullable, so flatten Option<Option<String>>.
    let trace_id = stmt
        .query_row([session_id], |r| r.get::<_, Option<String>>(0))
        .optional()?
        .flatten();
    Ok(trace_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    use logbook_core::{Category, Event, Kind, SessionId, Status, TraceId};

    /// Open an in-memory store (migrations run, so V2 columns/tables exist).
    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    /// Plant a session header + (optionally) a transcript + actions + trace
    /// events, exercising the V2 columns the way the inventory writer will.
    fn seed_session(store: &Store, trace: TraceId) {
        let trace_hex = trace.to_hex();
        store
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                     VALUES ('sess-1', NULL, 'claude', 'claude -- build', ?1, 100, 200, 0)",
                    [&trace_hex],
                )?;
                conn.execute_batch(
                    "INSERT INTO session_transcripts \
                       (session_id, trace_id, terminal_log_path, text_path, line_count, byte_size, max_sensitivity, created_at) \
                       VALUES ('sess-1', 'trace-x', '/o/s.terminal.log', '/o/s.txt', 12, 2048, 'transcript', 150);
                     INSERT INTO agent_actions \
                       (id, session_id, kind, path, detail, observed_at, diff, diff_bytes, post_hash, revert_safe, max_sensitivity) \
                       VALUES ('act-1', 'sess-1', 'file_modified', 'f.txt', NULL, 160, '@@ -1 +1 @@\n-a\n+b', 200, 'deadbeef', 1, 'file_diffs'),
                              ('act-2', 'sess-1', 'file_added', 'big.bin', NULL, 170, NULL, NULL, NULL, 0, 'file_diffs');",
                )?;
                Ok(())
            })
            .unwrap();

        // An ordered transcript line-event under the shared trace.
        let mut ev = Event::new(trace, Kind::Log, Category::Agent, "line")
            .with_name("hello from agent")
            .with_status(Status::Ok)
            .with_session(SessionId::new("sess-1"));
        ev.timestamp = logbook_core::MicrosTimestamp(155);
        store.insert(&ev).unwrap();
    }

    #[test]
    fn list_sessions_is_newest_first_with_counts() {
        let store = store();
        let trace = TraceId::new();
        seed_session(&store, trace);
        // A second, older, session with no actions and no transcript.
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                     VALUES ('sess-0', NULL, 'codex', 'codex -- x', NULL, 50, 60, 1)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

        let list = list_sessions(&store).unwrap();
        assert_eq!(list.len(), 2);
        // Newest first: sess-1 (started_at=100) leads sess-0 (50).
        assert_eq!(list[0].session_id, "sess-1");
        assert_eq!(list[0].action_count, 2);
        assert!(list[0].has_transcript);
        assert_eq!(list[0].exit_code, Some(0));
        // The empty session still appears, with zero actions / no transcript.
        assert_eq!(list[1].session_id, "sess-0");
        assert_eq!(list[1].action_count, 0);
        assert!(!list[1].has_transcript);
        assert_eq!(list[1].exit_code, Some(1));
    }

    #[test]
    fn load_session_joins_transcript_actions_and_trace() {
        let store = store();
        let trace = TraceId::new();
        seed_session(&store, trace);

        let detail = load_session(&store, "sess-1").unwrap().expect("session exists");
        assert_eq!(detail.session.session_id, "sess-1");
        assert_eq!(detail.session.agent, "claude");
        assert_eq!(detail.session.action_count, 2);

        // Transcript pointers surfaced.
        let t = detail.transcript.expect("transcript row present");
        assert_eq!(t.terminal_log_path.as_deref(), Some("/o/s.terminal.log"));
        assert_eq!(t.line_count, Some(12));
        assert_eq!(t.byte_size, Some(2048));

        // Actions in observation order; first has a redacted diff, second omitted.
        assert_eq!(detail.actions.len(), 2);
        assert_eq!(detail.actions[0].kind, "file_modified");
        assert_eq!(detail.actions[0].diff.as_deref(), Some("@@ -1 +1 @@\n-a\n+b"));
        assert_eq!(detail.actions[0].diff_bytes, Some(200));
        assert!(detail.actions[0].revert_safe, "clean-tree action is revert-safe");
        assert!(detail.actions[1].diff.is_none(), "omitted diff reads NULL");
        assert!(!detail.actions[1].revert_safe);

        // The ordered trace stream carries the planted line-event.
        assert_eq!(detail.events.len(), 1);
        assert_eq!(detail.events[0].name, "hello from agent");
    }

    #[test]
    fn load_session_missing_is_none() {
        let store = store();
        assert!(load_session(&store, "nope").unwrap().is_none());
    }

    #[test]
    fn load_session_without_trace_has_empty_events() {
        let store = store();
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                     VALUES ('sess-nt', NULL, 'aider', 'aider', NULL, 10, 20, 0)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let detail = load_session(&store, "sess-nt").unwrap().unwrap();
        assert!(detail.transcript.is_none());
        assert!(detail.actions.is_empty());
        assert!(detail.events.is_empty(), "no trace_id => no correlated events");
    }
}
