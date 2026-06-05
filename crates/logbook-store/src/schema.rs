//! Connection configuration, migrations, and `Event` <-> row mapping.

use rusqlite::Connection;

use logbook_core::{Category, Event, Kind, SensitivityClass};

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
    /// Zero-based turn index projected from the event's
    /// [`AgentBlock::turn`](logbook_core::AgentBlock::turn) (V3 `events.turn`).
    /// `None` when the event carries no agent block or that block has no turn.
    /// Drives fast per-session turn grouping/filtering; the JSON `body` remains
    /// the source of truth on read — this column is a denormalized projection
    /// only.
    pub turn: Option<i64>,
    /// The most-sensitive [`SensitivityClass`] present in this event, as its
    /// snake_case wire string (V2 `events.max_sensitivity`). Drives the
    /// per-class retention prune; `None` means unclassified (retained under the
    /// global default, omitted from the export payload projection). The JSON
    /// `body` remains the source of truth on read — this column is a
    /// denormalized projection only.
    pub max_sensitivity: Option<String>,
    pub body: String,
}

/// Compute a **conservative** dominant [`SensitivityClass`] for an event — the
/// most-sensitive class its content could plausibly belong to — for the V2
/// `max_sensitivity` retention column. The JSON `body` stays the source of
/// truth; this is only a coarse projection for `Store::prune` (Phase 3) and the
/// export projection, so it errs toward the *more* sensitive class when unsure.
///
/// Resolution is block-first (the typed domain block is the strongest signal),
/// falling back to `category`/`kind`:
/// - a `tool` block → [`SensitivityClass::ToolResults`] when the event carries
///   an output payload, else [`SensitivityClass::ToolArgs`] (both force-redacted
///   payload classes; results are the larger leak surface);
/// - an `llm` block → [`SensitivityClass::Prompts`] when an input/output payload
///   is present (prompt-bearing), else [`SensitivityClass::ModelMetadata`]
///   (provider/model/token/cost only);
/// - otherwise by lane: `Browser` → [`SensitivityClass::BrowserData`]; an
///   agent/PTY log line → [`SensitivityClass::Transcript`].
///
/// Returns `None` for events with no class-bearing content (e.g. security /
/// inventory findings), which then store `max_sensitivity = NULL`.
fn max_sensitivity_for(event: &Event) -> Option<SensitivityClass> {
    // (1) Typed blocks are the strongest, most-specific signal.
    if event.blocks.tool.is_some() {
        return Some(if event.output.is_some() {
            SensitivityClass::ToolResults
        } else {
            SensitivityClass::ToolArgs
        });
    }
    if event.blocks.llm.is_some() {
        return Some(if event.input.is_some() || event.output.is_some() {
            SensitivityClass::Prompts
        } else {
            SensitivityClass::ModelMetadata
        });
    }

    // (2) Fall back to the lane / kind.
    match event.category {
        Category::Browser => Some(SensitivityClass::BrowserData),
        // PTY transcript lines + agent steps are the Universal-tier transcript.
        Category::AppLog | Category::Agent => Some(SensitivityClass::Transcript),
        // Security / inventory / test rows carry no capture-policy payload class.
        Category::CodeTest | Category::Security | Category::Inventory => match event.kind {
            // A bare browser/log line slipping through a non-browser lane is
            // still transcript-class content.
            Kind::Browser | Kind::Log => Some(SensitivityClass::Transcript),
            _ => None,
        },
    }
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
        // V3: denormalized projection of AgentBlock.turn for fast grouping.
        // `None` when there is no agent block or no turn. The column is INTEGER
        // (i64); turn indices are small so a saturating try_from is exact here,
        // and the JSON body keeps the true u64 on read either way.
        turn: event
            .blocks
            .agent
            .as_ref()
            .and_then(|a| a.turn)
            .map(|t| i64::try_from(t).unwrap_or(i64::MAX)),
        max_sensitivity: max_sensitivity_for(event).map(|c| c.as_str().to_string()),
        body,
    })
}

/// Reconstruct an [`Event`] from a stored body string. The scalar columns are
/// ignored on read because the body is the canonical, lossless representation.
pub(crate) fn event_from_body(body: &str) -> Result<Event> {
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{
        AgentBlock, Category, Event, Kind, LlmBlock, ToolBlock, TraceId,
    };
    use refinery::Target;
    use rusqlite::Connection;
    use std::path::Path;

    /// Whether `table` has a column named `column` (via PRAGMA table_info).
    fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        names.iter().any(|n| n == column)
    }

    /// Whether a table exists in the schema.
    fn has_table(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// Open a connection, configure it, and apply migrations only up to V1 —
    /// leaving the DB in the exact pre-Orbit (V1) shape. Refinery records V1 in
    /// its history table, so a later full run applies *only* V2 (the genuine
    /// V1→V2 upgrade path, not a fresh build).
    fn open_at_v1(path: &Path) -> Connection {
        let mut conn = Connection::open(path).unwrap();
        configure_connection(&conn).unwrap();
        embedded::migrations::runner()
            .set_target(Target::Version(1))
            .run(&mut conn)
            .unwrap();
        conn
    }

    /// Open a connection and apply migrations only up to V2 — leaving the DB in
    /// the exact pre-V3 shape (V2 columns/tables present, but no `events.turn`).
    /// Refinery records V1+V2 in its history, so a later full run applies *only*
    /// V3 (the genuine V2→V3 upgrade path, not a fresh build).
    fn open_at_v2(path: &Path) -> Connection {
        let mut conn = Connection::open(path).unwrap();
        configure_connection(&conn).unwrap();
        embedded::migrations::runner()
            .set_target(Target::Version(2))
            .run(&mut conn)
            .unwrap();
        conn
    }

    /// Open a connection and apply migrations only up to V3 — leaving the DB in
    /// the exact pre-V4 shape (the `audit_log` table absent). Refinery records
    /// V1+V2+V3, so a later full run applies *only* V4 (the genuine V3→V4 upgrade
    /// path, not a fresh build).
    fn open_at_v3(path: &Path) -> Connection {
        let mut conn = Connection::open(path).unwrap();
        configure_connection(&conn).unwrap();
        embedded::migrations::runner()
            .set_target(Target::Version(3))
            .run(&mut conn)
            .unwrap();
        conn
    }

    #[test]
    fn v2_migration_is_incremental_and_idempotent_on_a_v1_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("logbook.db");

        // (1) Build a V1-shaped DB and assert the V2 columns/table are ABSENT.
        let conn = open_at_v1(&db);
        assert!(
            has_column(&conn, "events", "trace_id"),
            "sanity: V1 events table exists"
        );
        assert!(
            !has_column(&conn, "events", "max_sensitivity"),
            "max_sensitivity must not exist at V1"
        );
        assert!(
            !has_column(&conn, "agent_actions", "diff"),
            "agent_actions.diff must not exist at V1"
        );
        assert!(
            !has_table(&conn, "session_transcripts"),
            "session_transcripts must not exist at V1"
        );

        // Insert an event row through the V1 column set (14 cols, no
        // max_sensitivity) so we have a pre-existing "old" row to read back.
        conn.execute(
            "INSERT INTO events \
             (id, trace_id, parent_id, timestamp, duration_ms, kind, type, \
              category, operation, name, status, error, session_id, body) \
             VALUES ('old-1','aa','', 100, NULL, 'log', 'stdout', 'app_log', \
              'log', 'old line', 'unset', NULL, NULL, '{}')",
            [],
        )
        .unwrap();
        // Insert a V1 agent_session + agent_action so the CASCADE FK on the new
        // session_transcripts table has a parent and the old action reads back.
        conn.execute(
            "INSERT INTO agent_sessions (id, agent, command, started_at) \
             VALUES ('sess-1', 'claude', 'sh', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_actions (id, session_id, kind, observed_at) \
             VALUES ('act-1', 'sess-1', 'file_modified', 2)",
            [],
        )
        .unwrap();
        drop(conn);

        // (2) Reopen at the latest target → refinery applies ONLY V2 on top.
        let mut conn = Connection::open(&db).unwrap();
        configure_connection(&conn).unwrap();
        run_migrations(&mut conn).unwrap();

        // V2 columns + table now exist.
        assert!(has_column(&conn, "events", "max_sensitivity"));
        for col in ["diff", "diff_bytes", "post_hash", "revert_safe", "max_sensitivity"] {
            assert!(
                has_column(&conn, "agent_actions", col),
                "agent_actions.{col} must exist after V2"
            );
        }
        assert!(has_table(&conn, "session_transcripts"));
        // The new index exists.
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type='index' AND name='idx_events_max_sensitivity'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx, 1, "idx_events_max_sensitivity must exist after V2");

        // (3) The pre-existing rows read NULL for the new nullable columns.
        let ev_ms: Option<String> = conn
            .query_row(
                "SELECT max_sensitivity FROM events WHERE id='old-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ev_ms, None, "old events row must read max_sensitivity=NULL");
        let (act_diff, act_ms, revert_safe): (Option<String>, Option<String>, i64) = conn
            .query_row(
                "SELECT diff, max_sensitivity, revert_safe FROM agent_actions WHERE id='act-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(act_diff, None, "old action diff must read NULL");
        assert_eq!(act_ms, None, "old action max_sensitivity must read NULL");
        assert_eq!(revert_safe, 0, "revert_safe must default to 0 for old rows");

        // (4) Running migrations again is a no-op (refinery skips applied).
        run_migrations(&mut conn).unwrap();
        assert!(has_column(&conn, "events", "max_sensitivity"));
        assert!(has_table(&conn, "session_transcripts"));

        // The session_transcripts FK + 'transcript' default work end-to-end.
        conn.execute(
            "INSERT INTO session_transcripts (session_id, trace_id, created_at) \
             VALUES ('sess-1', 'aa', 3)",
            [],
        )
        .unwrap();
        let default_ms: String = conn
            .query_row(
                "SELECT max_sensitivity FROM session_transcripts WHERE session_id='sess-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(default_ms, "transcript", "DEFAULT 'transcript' applies");
    }

    #[test]
    fn event_to_row_populates_max_sensitivity() {
        let trace = TraceId::new();

        // A PTY transcript line (Kind::Log / Category::AppLog) → transcript.
        let log = Event::new(trace, Kind::Log, Category::AppLog, "stdout");
        assert_eq!(
            event_to_row(&log).unwrap().max_sensitivity.as_deref(),
            Some("transcript")
        );

        // An agent step → transcript (Universal tier).
        let agent = Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_agent(AgentBlock::default());
        assert_eq!(
            event_to_row(&agent).unwrap().max_sensitivity.as_deref(),
            Some("transcript")
        );

        // A tool call with an output payload → the most-sensitive results class.
        let mut tool = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_tool(ToolBlock::default());
        tool.output = Some(serde_json::json!({"ok": true}));
        assert_eq!(
            event_to_row(&tool).unwrap().max_sensitivity.as_deref(),
            Some("tool_results")
        );

        // A tool call without output → tool_args.
        let tool_args = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_tool(ToolBlock::default());
        assert_eq!(
            event_to_row(&tool_args).unwrap().max_sensitivity.as_deref(),
            Some("tool_args")
        );

        // An LLM call carrying a prompt payload → prompts.
        let mut llm = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_llm(LlmBlock::default());
        llm.input = Some(serde_json::json!("hello"));
        assert_eq!(
            event_to_row(&llm).unwrap().max_sensitivity.as_deref(),
            Some("prompts")
        );

        // A metadata-only LLM event (no input/output) → model_metadata.
        let meta = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_llm(LlmBlock {
                model: Some("claude".into()),
                ..Default::default()
            });
        assert_eq!(
            event_to_row(&meta).unwrap().max_sensitivity.as_deref(),
            Some("model_metadata")
        );

        // A browser event → browser_data.
        let browser = Event::new(trace, Kind::Browser, Category::Browser, "console");
        assert_eq!(
            event_to_row(&browser).unwrap().max_sensitivity.as_deref(),
            Some("browser_data")
        );

        // A security finding carries no capture-policy payload class → NULL.
        let finding = Event::new(trace, Kind::Finding, Category::Security, "advisory");
        assert_eq!(event_to_row(&finding).unwrap().max_sensitivity, None);
    }

    #[test]
    fn fresh_db_runs_all_migrations() {
        // A from-scratch open applies V1+V2+V3+V4 in one go; the full surface is
        // present (V2 capture-policy columns/table + the V3 `events.turn` + the
        // V4 `audit_log` table).
        let dir = tempfile::tempdir().unwrap();
        let mut conn = Connection::open(dir.path().join("fresh.db")).unwrap();
        configure_connection(&conn).unwrap();
        run_migrations(&mut conn).unwrap();
        assert!(has_column(&conn, "events", "max_sensitivity"));
        assert!(has_column(&conn, "agent_actions", "revert_safe"));
        assert!(has_table(&conn, "session_transcripts"));
        assert!(has_column(&conn, "events", "turn"), "V3 events.turn present");
        assert!(has_table(&conn, "audit_log"), "V4 audit_log present");
    }

    #[test]
    fn v4_migration_is_incremental_and_idempotent_on_a_v3_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("logbook.db");

        // (1) Build a V3-shaped DB and assert the V4 `audit_log` table is ABSENT.
        let conn = open_at_v3(&db);
        assert!(
            has_column(&conn, "events", "turn"),
            "sanity: V3 surface is present"
        );
        assert!(
            !has_table(&conn, "audit_log"),
            "audit_log must not exist at V3"
        );
        drop(conn);

        // (2) Reopen at the latest target → refinery applies ONLY V4 on top.
        let mut conn = Connection::open(&db).unwrap();
        configure_connection(&conn).unwrap();
        run_migrations(&mut conn).unwrap();

        // V4 table + its event_id index now exist.
        assert!(has_table(&conn, "audit_log"));
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type='index' AND name='idx_audit_log_event_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx, 1, "idx_audit_log_event_id must exist after V4");

        // (3) The AUTOINCREMENT seq is monotonic and bound params round-trip.
        conn.execute(
            "INSERT INTO audit_log (event_id, prev_hash, row_hash, created_at) \
             VALUES ('ev-1', 'p', 'h1', 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log (event_id, prev_hash, row_hash, created_at) \
             VALUES ('ev-2', 'h1', 'h2', 20)",
            [],
        )
        .unwrap();
        let (s1, s2): (i64, i64) = (
            conn.query_row(
                "SELECT seq FROM audit_log WHERE event_id='ev-1'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            conn.query_row(
                "SELECT seq FROM audit_log WHERE event_id='ev-2'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        );
        assert!(s2 > s1, "seq is strictly increasing");

        // (4) Running migrations again is a no-op (refinery skips applied).
        run_migrations(&mut conn).unwrap();
        assert!(has_table(&conn, "audit_log"));
    }

    #[test]
    fn v3_migration_is_incremental_and_idempotent_on_a_v2_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("logbook.db");

        // (1) Build a V2-shaped DB and assert the V3 `turn` column is ABSENT.
        let conn = open_at_v2(&db);
        assert!(
            has_column(&conn, "events", "max_sensitivity"),
            "sanity: V2 surface is present"
        );
        assert!(
            !has_column(&conn, "events", "turn"),
            "events.turn must not exist at V2"
        );

        // Insert an event through the V2 column set (15 cols, no `turn`) so we
        // have a pre-existing "old" row to read back after the V3 upgrade.
        conn.execute(
            "INSERT INTO events \
             (id, trace_id, parent_id, timestamp, duration_ms, kind, type, \
              category, operation, name, status, error, session_id, \
              max_sensitivity, body) \
             VALUES ('old-1','aa','', 100, NULL, 'log', 'stdout', 'app_log', \
              'log', 'old line', 'unset', NULL, NULL, NULL, '{}')",
            [],
        )
        .unwrap();
        drop(conn);

        // (2) Reopen at the latest target → refinery applies ONLY V3 on top.
        let mut conn = Connection::open(&db).unwrap();
        configure_connection(&conn).unwrap();
        run_migrations(&mut conn).unwrap();

        // V3 column + its index now exist.
        assert!(has_column(&conn, "events", "turn"));
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type='index' AND name='idx_events_turn'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx, 1, "idx_events_turn must exist after V3");

        // (3) The pre-existing row reads NULL for the new nullable `turn` column.
        let old_turn: Option<i64> = conn
            .query_row("SELECT turn FROM events WHERE id='old-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(old_turn, None, "old events row must read turn=NULL");

        // (4) Running migrations again is a no-op (refinery skips applied).
        run_migrations(&mut conn).unwrap();
        assert!(has_column(&conn, "events", "turn"));

        // (5) New inserts can carry a non-NULL turn through the V3 column.
        conn.execute(
            "INSERT INTO events \
             (id, trace_id, parent_id, timestamp, duration_ms, kind, type, \
              category, operation, name, status, error, session_id, turn, \
              max_sensitivity, body) \
             VALUES ('new-1','bb','', 200, NULL, 'agent', 'step', 'agent', \
              'step', 'turn 5', 'unset', NULL, 'sess-1', 5, 'transcript', '{}')",
            [],
        )
        .unwrap();
        let new_turn: Option<i64> = conn
            .query_row("SELECT turn FROM events WHERE id='new-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(new_turn, Some(5));
    }

    #[test]
    fn event_to_row_projects_agent_turn() {
        let trace = TraceId::new();

        // An agent block with a turn → `turn` column carries it.
        let with_turn = Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_agent(AgentBlock {
                turn: Some(7),
                ..Default::default()
            });
        assert_eq!(event_to_row(&with_turn).unwrap().turn, Some(7));

        // An agent block without a turn → NULL.
        let no_turn = Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_agent(AgentBlock::default());
        assert_eq!(event_to_row(&no_turn).unwrap().turn, None);

        // A non-agent event → NULL (no agent block to project from).
        let log = Event::new(trace, Kind::Log, Category::AppLog, "stdout");
        assert_eq!(event_to_row(&log).unwrap().turn, None);
    }
}
