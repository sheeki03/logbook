//! Connection configuration, migrations, and `Event` <-> row mapping.

use rusqlite::Connection;

use logbook_core::Event;

use crate::error::Result;

// Embed the SQL migrations under `src/migrations` at compile time. Files are
// named `V{n}__{name}.sql` per refinery's convention.
mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("src/migrations");
}

/// Apply pragmas appropriate for the logbook store to a freshly opened
/// connection: WAL journaling (concurrent readers + one writer), `NORMAL`
/// synchronous (durable enough for a local observability store, much faster
/// than `FULL`), foreign-key enforcement, and a busy timeout so readers wait
/// for the writer instead of erroring with `SQLITE_BUSY`.
pub fn configure_connection(conn: &Connection) -> Result<()> {
    // `journal_mode` returns the new mode as a row, so use a query pragma.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// Run all pending migrations on `conn`. Idempotent: refinery records applied
/// migrations in its own table and skips them on subsequent runs.
pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    embedded::migrations::runner().run(conn)?;
    Ok(())
}

/// The denormalized scalar columns we project out of an [`Event`] for indexing,
/// alongside the full JSON body.
pub(crate) struct EventRow {
    pub id: String,
    pub trace_id: String,
    pub parent_id: Option<String>,
    pub timestamp: i64,
    pub duration_ms: Option<f64>,
    pub kind: String,
    pub type_: String,
    pub category: String,
    pub operation: String,
    pub name: String,
    pub status: String,
    pub error: Option<String>,
    pub session_id: Option<String>,
    pub body: String,
}

/// Project an [`Event`] into its row form (serializing the body to canonical
/// JSON). The body is the source of truth on read-back; the scalar columns are
/// only used for filtering and indexing.
pub(crate) fn event_to_row(event: &Event) -> Result<EventRow> {
    let body = serde_json::to_string(event)?;
    // `kind` / `status` store their bare lowercase wire token (e.g. `log`,
    // `ok`); read it straight off the core enum instead of round-tripping
    // through a transient serde_json `Value` on every insert.
    Ok(EventRow {
        id: event.id.as_str().to_string(),
        trace_id: event.trace_id.to_hex(),
        parent_id: event.parent_id.map(|p| p.to_hex()),
        timestamp: event.timestamp.as_micros(),
        duration_ms: event.duration_ms,
        kind: event.kind.as_str().to_string(),
        type_: event.type_.clone(),
        category: event.category.as_str().to_string(),
        operation: event.operation.clone(),
        name: event.name.clone(),
        status: event.status.as_str().to_string(),
        error: event.error.clone(),
        session_id: event.session_id.as_ref().map(|s| s.as_str().to_string()),
        body,
    })
}

/// Reconstruct an [`Event`] from a stored body string. The scalar columns are
/// ignored on read because the body is the canonical, lossless representation.
pub(crate) fn event_from_body(body: &str) -> Result<Event> {
    Ok(serde_json::from_str(body)?)
}
