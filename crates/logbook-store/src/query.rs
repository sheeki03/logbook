//! The read/query API over the `events` table.
//!
//! A [`Query`] is a declarative filter (time range, category, trace id, session
//! id, FTS match) that compiles to a single parameterized SQL statement.
//! [`query_events`] runs on a read-only connection borrowed from the read pool
//! for file-backed stores, and on the single writer connection for `:memory:`
//! stores (each `:memory:` open is a distinct database, so the read pool can't
//! be shared — see [`crate::Store::read`]).

use rusqlite::{Connection, ToSql};

use logbook_core::{Category, Event};

use crate::error::Result;
use crate::schema::event_from_body;

/// A declarative event query. Unset fields are not constrained. Combine freely;
/// all set constraints are ANDed together.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Inclusive lower bound on `timestamp` (microseconds).
    pub since_micros: Option<i64>,
    /// Inclusive upper bound on `timestamp` (microseconds).
    pub until_micros: Option<i64>,
    /// Restrict to a single category lane.
    pub category: Option<Category>,
    /// Restrict to a single W3C trace id (hex).
    pub trace_id: Option<String>,
    /// Restrict to a single session id.
    pub session_id: Option<String>,
    /// Full-text query string (FTS5 MATCH syntax). When set, results are joined
    /// against `events_fts`.
    pub text: Option<String>,
    /// Maximum number of rows to return. `None` = no limit.
    pub limit: Option<u32>,
    /// Sort newest-first when true (default), oldest-first when false.
    pub newest_first: bool,
}

impl Query {
    /// An unconstrained query (newest-first).
    #[must_use]
    pub fn new() -> Self {
        Self {
            newest_first: true,
            ..Default::default()
        }
    }

    /// Constrain to a time range `[since, until]` (microseconds).
    #[must_use]
    pub fn time_range(mut self, since: i64, until: i64) -> Self {
        self.since_micros = Some(since);
        self.until_micros = Some(until);
        self
    }

    /// Constrain to a category.
    #[must_use]
    pub fn category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self
    }

    /// Constrain to a trace id.
    #[must_use]
    pub fn trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Constrain to a session id.
    #[must_use]
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Add a full-text search constraint (FTS5 MATCH syntax).
    #[must_use]
    pub fn search(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Cap the number of returned rows.
    #[must_use]
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Return oldest-first instead of newest-first.
    #[must_use]
    pub fn oldest_first(mut self) -> Self {
        self.newest_first = false;
        self
    }
}

/// Execute `query` against `conn`, returning the matching events ordered by
/// timestamp (direction per [`Query::newest_first`]).
pub fn query_events(conn: &Connection, query: &Query) -> Result<Vec<Event>> {
    let mut sql = String::from("SELECT e.body FROM events e");
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    let mut wheres: Vec<String> = Vec::new();

    // FTS join (must come before WHERE building so the alias exists).
    if let Some(text) = &query.text {
        sql.push_str(" JOIN events_fts f ON f.rowid = e.rowid");
        wheres.push("events_fts MATCH ?".to_string());
        params.push(Box::new(text.clone()));
    }

    if let Some(since) = query.since_micros {
        wheres.push("e.timestamp >= ?".to_string());
        params.push(Box::new(since));
    }
    if let Some(until) = query.until_micros {
        wheres.push("e.timestamp <= ?".to_string());
        params.push(Box::new(until));
    }
    if let Some(cat) = query.category {
        wheres.push("e.category = ?".to_string());
        params.push(Box::new(cat.as_str().to_string()));
    }
    if let Some(trace) = &query.trace_id {
        wheres.push("e.trace_id = ?".to_string());
        params.push(Box::new(trace.clone()));
    }
    if let Some(session) = &query.session_id {
        wheres.push("e.session_id = ?".to_string());
        params.push(Box::new(session.clone()));
    }

    if !wheres.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wheres.join(" AND "));
    }

    sql.push_str(if query.newest_first {
        " ORDER BY e.timestamp DESC, e.rowid DESC"
    } else {
        " ORDER BY e.timestamp ASC, e.rowid ASC"
    });

    if let Some(limit) = query.limit {
        sql.push_str(" LIMIT ?");
        params.push(Box::new(limit));
    }

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        let body: String = row.get(0)?;
        Ok(body)
    })?;

    let mut out = Vec::new();
    for body in rows {
        out.push(event_from_body(&body?)?);
    }
    Ok(out)
}

/// Convenience: fetch a whole trace (all events sharing `trace_id`), oldest
/// first (the natural reading order for a timeline).
pub fn get_trace(conn: &Connection, trace_id: &str) -> Result<Vec<Event>> {
    query_events(conn, &Query::new().trace(trace_id).oldest_first())
}

/// Count all events (used by tests and retention).
pub fn count_events(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?)
}
