//! The `debug_sessions` lifecycle, persisted in `logbook-store` (plan §6, §2).
//!
//! A debug session is a short-lived, **non-invasive** investigation: it
//! correlates already-captured signals (Tier 1, passive) and — when explicitly
//! put in DAP mode — sets logpoints on a running process (Tier 2, alpha). The
//! lifecycle row lives in the store's `debug_sessions` table:
//!
//! ```text
//! id  trace_id  status(active|fetched|ended)  mode(passive|dap)  target  started_at  ended_at
//! ```
//!
//! This crate owns the CRUD for that table. Because `logbook-store` exposes a
//! generic single-writer [`Store::write`](logbook_store::Store::write) and a
//! read-pool [`Store::read`](logbook_store::Store::read), the SQL lives here
//! rather than in the store crate — no store edits are required.

use logbook_core::{MicrosTimestamp, SessionId, TraceId};
use logbook_store::{Store, StoreError};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::error::{DebugError, Result};

/// Lifecycle state of a debug session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugStatus {
    /// The session is open: evidence can be queried and (in DAP mode) logpoints
    /// remain attached.
    Active,
    /// The agent has fetched evidence at least once; the session is still open.
    Fetched,
    /// The session has been ended; all logpoints/tracing have been detached.
    Ended,
}

impl DebugStatus {
    /// Stable lowercase wire string (matches the `status` column).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DebugStatus::Active => "active",
            DebugStatus::Fetched => "fetched",
            DebugStatus::Ended => "ended",
        }
    }

    /// Parse from the stored column value. Infallible: an unrecognized value
    /// maps to [`DebugStatus::Active`] (the safe default for an open session),
    /// so this is deliberately *not* a fallible [`std::str::FromStr`].
    #[must_use]
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "fetched" => DebugStatus::Fetched,
            "ended" => DebugStatus::Ended,
            _ => DebugStatus::Active,
        }
    }
}

/// Evidence tier the session is operating in (plan §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugMode {
    /// Tier 1 — passive: query already-captured logs/console/network from the
    /// store. The default; never touches the target process or its source.
    Passive,
    /// Tier 2 — DAP logpoints (**alpha**): attach to a running process's debug
    /// adapter and log expressions at `file:line` without stopping and without
    /// editing source.
    Dap,
}

impl DebugMode {
    /// Stable lowercase wire string (matches the `mode` column).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DebugMode::Passive => "passive",
            DebugMode::Dap => "dap",
        }
    }

    /// Parse from the stored column value. Infallible: an unrecognized value
    /// maps to [`DebugMode::Passive`] (the safe, non-invasive default), so this
    /// is deliberately *not* a fallible [`std::str::FromStr`].
    #[must_use]
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "dap" => DebugMode::Dap,
            _ => DebugMode::Passive,
        }
    }
}

/// A row of the `debug_sessions` table.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DebugSessionRecord {
    /// The session id (primary key).
    pub id: SessionId,
    /// Correlated trace id, if the session pins one (hex, 32 chars).
    pub trace_id: Option<String>,
    /// Lifecycle state.
    pub status: DebugStatus,
    /// Evidence tier.
    pub mode: DebugMode,
    /// Human-meaningful target description (e.g. a process name, a `file:line`,
    /// or an adapter address). Free-form, advisory.
    pub target: Option<String>,
    /// Start time (microseconds since the UNIX epoch).
    pub started_at: i64,
    /// End time (microseconds), set when the session is ended.
    pub ended_at: Option<i64>,
}

impl DebugSessionRecord {
    /// Whether this session has been ended.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.status == DebugStatus::Ended
    }
}

/// Persist a brand-new `active` debug session row.
///
/// # Errors
/// Returns a [`DebugError::Store`] if the write fails.
pub(crate) fn insert_session(store: &Store, record: &DebugSessionRecord) -> Result<()> {
    let id = record.id.as_str().to_string();
    let trace_id = record.trace_id.clone();
    let status = record.status.as_str().to_string();
    let mode = record.mode.as_str().to_string();
    let target = record.target.clone();
    let started_at = record.started_at;
    let ended_at = record.ended_at;

    store.write(move |conn| {
        conn.execute(
            "INSERT INTO debug_sessions \
             (id, trace_id, status, mode, target, started_at, ended_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, trace_id, status, mode, target, started_at, ended_at],
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Load a session row by id.
///
/// # Errors
/// Returns a [`DebugError::Store`] if the read fails.
pub(crate) fn get_session(store: &Store, id: &SessionId) -> Result<Option<DebugSessionRecord>> {
    let id = id.as_str().to_string();
    let row = store.read(move |conn| {
        conn.query_row(
            "SELECT id, trace_id, status, mode, target, started_at, ended_at \
             FROM debug_sessions WHERE id = ?1",
            rusqlite::params![id],
            row_to_record,
        )
        .optional()
        .map_err(StoreError::from)
    })?;
    Ok(row)
}

/// List all sessions, newest-started first.
///
/// # Errors
/// Returns a [`DebugError::Store`] if the read fails.
pub fn list_sessions(store: &Store) -> Result<Vec<DebugSessionRecord>> {
    let rows = store.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, trace_id, status, mode, target, started_at, ended_at \
             FROM debug_sessions ORDER BY started_at DESC, id DESC",
        )?;
        let mapped = stmt.query_map([], row_to_record)?;
        let mut out = Vec::new();
        for r in mapped {
            out.push(r?);
        }
        Ok(out)
    })?;
    Ok(rows)
}

/// Update a session's status (and, when ending, stamp `ended_at`).
///
/// # Errors
/// Returns a [`DebugError::Store`] if the write fails.
pub(crate) fn set_status(
    store: &Store,
    id: &SessionId,
    status: DebugStatus,
    ended_at: Option<i64>,
) -> Result<()> {
    let id = id.as_str().to_string();
    let status_str = status.as_str().to_string();
    store.write(move |conn| {
        conn.execute(
            "UPDATE debug_sessions SET status = ?2, ended_at = COALESCE(?3, ended_at) \
             WHERE id = ?1",
            rusqlite::params![id, status_str, ended_at],
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Map a `debug_sessions` row to a [`DebugSessionRecord`].
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DebugSessionRecord> {
    let id: String = row.get(0)?;
    let trace_id: Option<String> = row.get(1)?;
    let status: String = row.get(2)?;
    let mode: String = row.get(3)?;
    let target: Option<String> = row.get(4)?;
    let started_at: i64 = row.get(5)?;
    let ended_at: Option<i64> = row.get(6)?;
    Ok(DebugSessionRecord {
        id: SessionId::new(id),
        trace_id,
        status: DebugStatus::from_db_str(&status),
        mode: DebugMode::from_db_str(&mode),
        target,
        started_at,
        ended_at,
    })
}

/// Build a fresh `active` session record, minting an id and (if none supplied) a
/// trace id to correlate any DAP-emitted evidence.
#[must_use]
pub(crate) fn new_record(
    mode: DebugMode,
    trace: TraceId,
    target: Option<String>,
) -> DebugSessionRecord {
    DebugSessionRecord {
        id: SessionId::generate(),
        trace_id: Some(trace.to_hex()),
        status: DebugStatus::Active,
        mode,
        target,
        started_at: MicrosTimestamp::now().as_micros(),
        ended_at: None,
    }
}

/// Resolve a session by id, erroring if it is missing.
pub(crate) fn require_session(store: &Store, id: &SessionId) -> Result<DebugSessionRecord> {
    get_session(store, id)?.ok_or_else(|| DebugError::UnknownSession(id.as_str().to_string()))
}
