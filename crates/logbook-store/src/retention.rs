//! Phase-3 store reads + retention/governance (plan "Phase 3 — Correlation,
//! Risk & Governance").
//!
//! Three capabilities live here, all built on the existing `events` spine +
//! inventory tables (no new schema):
//!
//! - [`session_tree`] — the **correlation timeline** read. Groups one session's
//!   events by turn (turns as parents, tool/llm/log/finding events as children),
//!   oldest-first, so the UI can render "turn → action → diff → command →
//!   finding" woven by the shared trace.
//! - [`prune`] — **retention enforcement**. A per-class age sweep keyed on the
//!   denormalized `events.max_sensitivity` column (each class's `max_age_days`,
//!   falling back to the global `[retention].max_age_days` = 14), then a global
//!   size sweep that deletes the oldest rows until the store is back under
//!   `[retention].max_db_mb`. All parameters are bound; the closed
//!   [`SensitivityClass`] set never interpolates user input.
//! - [`forget_session`] / [`forget_before`] — **governance deletion** for
//!   `logbook forget`. Removes the matching `events` plus the session-scoped
//!   inventory rows (`agent_sessions` + its `agent_actions` /
//!   `session_transcripts`, which cascade), addressed by the session's
//!   trace/id.
//!
//! Everything here only ever *deletes* or *reads* already-redacted rows — the
//! redaction-before-persistence invariant is upstream and untouched.

use rusqlite::{params, Connection, OptionalExtension};

use logbook_core::{CapturePolicy, Event, SensitivityClass};

use crate::error::Result;
use crate::query::{query_events, Query};

/// Microseconds in one day (`24 * 60 * 60 * 1_000_000`). Used to convert a
/// retention age in days into a `timestamp` cut-off.
const MICROS_PER_DAY: i64 = 86_400 * 1_000_000;

// ===========================================================================
// session_tree — the correlation timeline read
// ===========================================================================

/// One turn of a [`SessionTree`]: a turn index (the parent) and the events that
/// belong to it (the children — tool / llm / log / finding rows), oldest-first.
///
/// The `turn` is the zero-based [`AgentBlock::turn`](logbook_core::AgentBlock::turn)
/// projected onto the V3 `events.turn` column. Events that carry no turn (most
/// tool/log/finding rows, which are linked to their turn by `parent_id`/time
/// rather than a stamped turn index) collect under the single trailing
/// [`turn = None`](TurnGroup::turn) group so nothing is dropped from the
/// timeline.
#[derive(Clone, Debug, PartialEq)]
pub struct TurnGroup {
    /// The turn index this group represents, or `None` for the catch-all group
    /// of turn-less events (tool/log/finding rows without a stamped turn). The
    /// `None` group always sorts last.
    pub turn: Option<i64>,
    /// The events in this turn, ordered oldest-first (ascending timestamp, then
    /// rowid) — the natural reading order for a timeline.
    pub events: Vec<Event>,
}

/// The correlation timeline for one session: its events grouped by turn,
/// oldest-first, turns ascending with the turn-less catch-all group last.
///
/// Built by [`session_tree`] from the shared `session_id`. Turns are the
/// parents; the tool/llm/log/finding events within each turn are the children.
/// The total ordering is: ascending `turn` (a stamped turn index), then the
/// `None` group; within each group, ascending timestamp then rowid.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionTree {
    /// The session id this tree was built for.
    pub session_id: String,
    /// The turn groups, ascending by turn index with the turn-less group last.
    pub turns: Vec<TurnGroup>,
}

impl SessionTree {
    /// Total number of events across all turns (handy for tests/UI badges).
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.turns.iter().map(|t| t.events.len()).sum()
    }
}

/// Build the [`SessionTree`] for `session_id`: all of the session's events,
/// grouped by turn (turns as parents, oldest-first within each turn), turns
/// ascending with the turn-less catch-all group (`turn = None`) last.
///
/// Reads the session's events oldest-first via the existing [`Query`] path (so
/// the FTS / index machinery is reused) and buckets them by the resolved turn
/// (`AgentBlock.turn` from the JSON body, the source of truth). Insertion order
/// into each bucket is already oldest-first, so the children need no re-sort.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if the read or a body
/// deserialization fails.
pub fn session_tree(conn: &Connection, session_id: &str) -> Result<SessionTree> {
    // Oldest-first so each turn's children land in timeline order as we insert.
    let events = query_events(conn, &Query::new().session(session_id).oldest_first())?;

    // Bucket into a Vec keyed by turn (linear find — a session has few distinct
    // turns), preserving each bucket's already-oldest-first insertion order,
    // then sort the buckets (Some(turn) ascending, None last) below.
    let mut groups: Vec<TurnGroup> = Vec::new();
    for ev in events {
        let turn = ev.blocks.agent.as_ref().and_then(|a| a.turn).map(turn_to_i64);
        match groups.iter_mut().find(|g| g.turn == turn) {
            Some(g) => g.events.push(ev),
            None => groups.push(TurnGroup {
                turn,
                events: vec![ev],
            }),
        }
    }

    // Total order: ascending turn index, with the turn-less (None) group last.
    groups.sort_by(|a, b| match (a.turn, b.turn) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    Ok(SessionTree {
        session_id: session_id.to_string(),
        turns: groups,
    })
}

/// Saturating `u64 -> i64` turn projection, matching `schema::event_to_row`
/// (turn indices are small, so this is exact in practice; the JSON body keeps
/// the true `u64` regardless).
fn turn_to_i64(turn: u64) -> i64 {
    i64::try_from(turn).unwrap_or(i64::MAX)
}

// ===========================================================================
// prune — per-class age + global size retention
// ===========================================================================

/// What a [`prune`] removed, for logging / tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PruneStats {
    /// Rows deleted by the per-class age sweep (sum across all classes).
    pub events_by_age: u64,
    /// Rows deleted by the global size sweep (oldest-first, to get back under
    /// `[retention].max_db_mb`). `0` when the store was already under cap.
    pub events_by_size: u64,
}

impl PruneStats {
    /// Total events deleted (`events_by_age + events_by_size`).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.events_by_age.saturating_add(self.events_by_size)
    }
}

/// Enforce retention against the `events` table (plan §3, "Retention").
///
/// Two sweeps, in order:
///
/// 1. **Per-class age.** For every [`SensitivityClass`], delete rows whose
///    `max_sensitivity` equals that class and whose `timestamp` is older than
///    `now_micros - max_age`, where `max_age` is the class's `max_age_days`
///    (from `policy`) or the global `retention.max_age_days` fallback (14 by
///    default). The cut-off and class are **bound parameters** — the closed
///    [`SensitivityClass`] set never interpolates user input. Rows with
///    `max_sensitivity = NULL` (pre-V2 / unclassified) are swept under the
///    global default via a dedicated `IS NULL` pass.
/// 2. **Global size.** If the **live** store size exceeds
///    `retention.max_db_mb`, delete the **oldest** rows in batches until the
///    estimated size is back under the cap (or the table is empty). Size is
///    the VACUUM-free estimate `(page_count - freelist_count) * page_size`,
///    which falls as deletes move pages onto the freelist (see
///    [`db_size_bytes`]), so the sweep converges without a full `VACUUM`. The
///    sweep then runs a `PRAGMA wal_checkpoint(TRUNCATE)` so the pages it freed
///    into the WAL (the store is in WAL mode) are folded back and the `-wal`
///    file truncated — otherwise the reclaimed bytes would linger on disk in the
///    WAL and keep the on-disk size above the cap.
///
/// Only the `events` spine is pruned here; the inventory tables are governed by
/// [`forget_session`] / [`forget_before`] (a `logbook forget` is the explicit
/// deletion path, retention is the passive age/size cap on the event stream).
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if any delete or size probe
/// fails.
pub fn prune(
    conn: &mut Connection,
    policy: &CapturePolicy,
    retention: &logbook_core::config::Retention,
    now_micros: i64,
) -> Result<PruneStats> {
    let global_age_days = i64::from(retention.max_age_days);
    let mut stats = PruneStats::default();

    // ---- (1) per-class age sweep -----------------------------------------
    // One DELETE per class, with the class's own max_age_days (or the global
    // fallback). All bound; the class string comes from the closed enum.
    let tx = conn.transaction()?;
    {
        let mut stmt =
            tx.prepare("DELETE FROM events WHERE max_sensitivity = ?1 AND timestamp < ?2")?;
        for class in SensitivityClass::ALL {
            let class_days = policy
                .rule(class)
                .max_age_days
                .map_or(global_age_days, i64::from);
            // A zero/negative age would mean "expire everything"; treat the
            // configured value verbatim (0 days => cut-off == now, deleting
            // strictly-older rows). Saturating math keeps the cut-off in range.
            let cutoff = now_micros.saturating_sub(class_days.saturating_mul(MICROS_PER_DAY));
            let n = stmt.execute(params![class.as_str(), cutoff])?;
            stats.events_by_age = stats.events_by_age.saturating_add(n as u64);
        }

        // Unclassified rows (max_sensitivity IS NULL: pre-V2 or class-less
        // findings) are retained under the global default age.
        let null_cutoff =
            now_micros.saturating_sub(global_age_days.saturating_mul(MICROS_PER_DAY));
        let n = tx.execute(
            "DELETE FROM events WHERE max_sensitivity IS NULL AND timestamp < ?1",
            params![null_cutoff],
        )?;
        stats.events_by_age = stats.events_by_age.saturating_add(n as u64);
    }
    tx.commit()?;

    // ---- (2) global size sweep -------------------------------------------
    let max_bytes = u64::from(retention.max_db_mb).saturating_mul(1024 * 1024);
    if max_bytes > 0 {
        stats.events_by_size = prune_to_size(conn, max_bytes)?;
    }

    Ok(stats)
}

/// Estimate the **live** logical database size in bytes as
/// `(page_count - freelist_count) * page_size`.
///
/// A plain `DELETE` does **not** shrink `page_count` (only a full `VACUUM`
/// does) — it moves emptied pages onto the freelist. Subtracting
/// `freelist_count` therefore yields a VACUUM-free estimate that *does* fall as
/// rows are deleted, so the size sweep converges (and terminates) without the
/// cost of a `VACUUM`. The freed pages are reused by subsequent inserts.
///
/// These pragmas read the database's **logical** page state (which already
/// accounts for any pages held in the WAL), so this estimate decreases
/// monotonically as the size sweep deletes rows — it is the loop's convergent
/// termination measure. It deliberately does **not** add the physical `-wal`
/// file size: in WAL mode each delete *appends* frames to the `-wal` file, so a
/// `logical + wal-file` sum would *grow* during the sweep and the loop would
/// over-delete to empty. The physical WAL bytes are instead reclaimed by the
/// one-shot truncating checkpoint [`prune_to_size`] runs after the sweep.
fn db_size_bytes(conn: &Connection) -> Result<u64> {
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let freelist: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let live_pages = (page_count - freelist).max(0) as u64;
    Ok(live_pages.saturating_mul(page_size.max(0) as u64))
}

/// Delete the oldest `events` rows in batches until the estimated DB size is
/// under `max_bytes` (or the table is empty). Returns the number of rows
/// deleted. Each batch deletes the globally-oldest rows
/// (`ORDER BY timestamp ASC, rowid ASC`).
///
/// Size is measured by [`db_size_bytes`] (the *logical* live-page estimate,
/// which falls as rows are deleted so the loop converges). The store runs in
/// **WAL** mode, however, so the rows the sweep frees land in the `-wal` sidecar
/// file and stay on disk until a checkpoint folds them back — meaning the
/// physical on-disk footprint could remain above the cap even though the logical
/// estimate is under it. After the sweep we therefore run a single
/// `PRAGMA wal_checkpoint(TRUNCATE)`, which folds the WAL frames into the main db
/// and truncates the `-wal` file to zero, so the freed space is genuinely
/// reclaimed on disk (not stranded in the WAL).
fn prune_to_size(conn: &mut Connection, max_bytes: u64) -> Result<u64> {
    /// Rows removed per batch. Large enough to reclaim pages quickly, small
    /// enough to avoid a long single transaction.
    const BATCH: i64 = 512;

    let mut deleted = 0u64;
    loop {
        if db_size_bytes(conn)? <= max_bytes {
            break;
        }
        // Delete the oldest BATCH rows by (timestamp, rowid). Subquery keeps it
        // to a single bound statement.
        let n = conn.execute(
            "DELETE FROM events WHERE rowid IN (\
                 SELECT rowid FROM events ORDER BY timestamp ASC, rowid ASC LIMIT ?1\
             )",
            params![BATCH],
        )?;
        if n == 0 {
            // Table is empty (or nothing left to delete) yet still over cap
            // (e.g. WAL/freelist overhead); checkpoint below then stop rather
            // than spin.
            break;
        }
        deleted = deleted.saturating_add(n as u64);
    }

    // Fold freed pages back into the main db and truncate the WAL, so the bytes
    // the sweep reclaimed are actually released on disk (not stranded in the
    // `-wal` file). Harmless / no-op for an in-memory database, where there is
    // no WAL file to truncate.
    checkpoint_truncate(conn)?;

    Ok(deleted)
}

/// Run `PRAGMA wal_checkpoint(TRUNCATE)`: flush all committed WAL frames into the
/// main database and truncate the `-wal` file back to zero bytes, reclaiming the
/// disk the size sweep freed. The pragma yields one `(busy, log, checkpointed)`
/// row which we read and discard. A no-op (no error) for a non-WAL / in-memory
/// connection, so it is always safe to call after the size sweep.
fn checkpoint_truncate(conn: &Connection) -> Result<()> {
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    Ok(())
}

// ===========================================================================
// forget — governance deletion (`logbook forget`)
// ===========================================================================

/// What a [`forget_session`] / [`forget_before`] removed, for logging / tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForgetStats {
    /// Rows deleted from `events`.
    pub events: u64,
    /// Rows deleted from `agent_sessions` (their `agent_actions` /
    /// `session_transcripts` cascade via `ON DELETE CASCADE`).
    pub agent_sessions: u64,
}

impl ForgetStats {
    /// Total rows deleted across `events` + `agent_sessions`.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.events.saturating_add(self.agent_sessions)
    }
}

/// Forget exactly one session's data (`logbook forget <session>`): delete its
/// `events` (matched on `session_id`, plus any extra events sharing the
/// session's `trace_id` so trace-correlated rows go too) and its
/// `agent_sessions` row. The session's `agent_actions` and `session_transcripts`
/// rows cascade via their `ON DELETE CASCADE` foreign key (foreign keys are
/// enabled on every connection by `configure_connection`).
///
/// Idempotent: forgetting an absent session deletes nothing and returns zeroed
/// [`ForgetStats`].
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if a delete fails.
pub fn forget_session(conn: &mut Connection, session_id: &str) -> Result<ForgetStats> {
    let session_id = session_id.to_string();
    let mut stats = ForgetStats::default();

    let tx = conn.transaction()?;
    {
        // The session's trace (if the row exists) lets us also drop any
        // trace-correlated events that were not stamped with the session id.
        let trace_id: Option<String> = tx
            .query_row(
                "SELECT trace_id FROM agent_sessions WHERE id = ?1",
                params![session_id],
                |r| r.get(0),
            )
            .optional()?;

        // Events directly stamped with the session id.
        let n = tx.execute(
            "DELETE FROM events WHERE session_id = ?1",
            params![session_id],
        )?;
        stats.events = stats.events.saturating_add(n as u64);

        // Plus any session-LESS events sharing the session's trace (correlated
        // tool/log/finding rows that were never stamped with a session id). We
        // deliberately restrict to `session_id IS NULL` so forgetting this
        // session can never delete *another* session's stamped rows, even in the
        // (unusual) event two sessions share a trace.
        if let Some(trace) = trace_id.as_deref() {
            let n = tx.execute(
                "DELETE FROM events WHERE trace_id = ?1 AND session_id IS NULL",
                params![trace],
            )?;
            stats.events = stats.events.saturating_add(n as u64);
        }

        // The agent_sessions row (cascades agent_actions + session_transcripts).
        let n = tx.execute(
            "DELETE FROM agent_sessions WHERE id = ?1",
            params![session_id],
        )?;
        stats.agent_sessions = stats.agent_sessions.saturating_add(n as u64);
    }
    tx.commit()?;

    Ok(stats)
}

/// Forget everything older than `micros` (`logbook forget --before <ts>`):
/// delete `events` with `timestamp < micros`, the `agent_sessions` whose
/// `started_at < micros`, **and every remaining event belonging to those
/// forgotten sessions regardless of the event's own timestamp**. The matching
/// sessions' `agent_actions` / `session_transcripts` cascade via their foreign
/// key.
///
/// The third clause is what keeps the two deletes consistent. The bare
/// timestamp delete is keyed on the *event* timestamp while the session delete
/// is keyed on the *session start*, so a session that **started** before the
/// cutoff but produced events **after** it would have its `agent_sessions` row
/// removed while those post-cutoff events survived — a half-deleted session with
/// orphaned events. To prevent that we first resolve the ids (and trace ids) of
/// the `agent_sessions` about to be forgotten and delete *all* of their events,
/// not just the pre-cutoff ones:
///
/// - events stamped with a forgotten session's id, and
/// - session-LESS events sharing a forgotten session's `trace_id` (the
///   trace-correlated tool/log/finding rows that were never stamped with a
///   session id).
///
/// As in [`forget_session`], the trace clause is restricted to
/// `session_id IS NULL` so forgetting an old session can never delete a *newer*
/// (still-retained) session's stamped rows, even in the unusual case where two
/// sessions share a trace.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if a delete fails.
pub fn forget_before(conn: &mut Connection, micros: i64) -> Result<ForgetStats> {
    let mut stats = ForgetStats::default();
    let tx = conn.transaction()?;
    {
        // Resolve the sessions about to be forgotten (started before the cutoff)
        // up front, so we can delete *all* of their events — including any
        // stamped after the cutoff — and not just the pre-cutoff rows the bare
        // timestamp sweep would catch. Without this the session row would be
        // deleted while its post-cutoff events were orphaned.
        let mut session_ids: Vec<String> = Vec::new();
        let mut trace_ids: Vec<String> = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT id, trace_id FROM agent_sessions WHERE started_at < ?1",
            )?;
            let rows = stmt.query_map(params![micros], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?;
            for row in rows {
                let (id, trace) = row?;
                session_ids.push(id);
                if let Some(trace) = trace {
                    trace_ids.push(trace);
                }
            }
        }

        // (a) The timestamp-based sweep: events older than the cutoff.
        let n = tx.execute(
            "DELETE FROM events WHERE timestamp < ?1",
            params![micros],
        )?;
        stats.events = n as u64;

        // (b) Make the session delete consistent with (a): also remove every
        // *remaining* event of a forgotten session, regardless of the event's
        // own timestamp, so no session is left half-deleted with orphaned
        // post-cutoff events. We restrict to `timestamp >= micros` only to avoid
        // double-counting the rows (a) already deleted.
        for id in &session_ids {
            let n = tx.execute(
                "DELETE FROM events WHERE session_id = ?1 AND timestamp >= ?2",
                params![id, micros],
            )?;
            stats.events = stats.events.saturating_add(n as u64);
        }
        // Plus the forgotten sessions' trace-correlated, session-LESS events
        // (never stamped with a session id). Restricted to `session_id IS NULL`
        // so a newer retained session sharing the trace is untouched.
        for trace in &trace_ids {
            let n = tx.execute(
                "DELETE FROM events \
                 WHERE trace_id = ?1 AND session_id IS NULL AND timestamp >= ?2",
                params![trace, micros],
            )?;
            stats.events = stats.events.saturating_add(n as u64);
        }

        // Finally the session rows themselves (cascading agent_actions +
        // session_transcripts).
        let n = tx.execute(
            "DELETE FROM agent_sessions WHERE started_at < ?1",
            params![micros],
        )?;
        stats.agent_sessions = n as u64;
    }
    tx.commit()?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::config::Retention;
    use logbook_core::{
        AgentBlock, Category, Event, FindingBlock, Kind, MicrosTimestamp, SessionId, SpanId,
        ToolBlock, TraceId,
    };

    use crate::Store;

    // ---- session_tree ----------------------------------------------------

    fn agent_turn(trace: TraceId, sess: &SessionId, turn: u64, name: &str, ts: i64) -> Event {
        let mut ev = Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_name(name)
            .with_session(sess.clone())
            .with_agent(AgentBlock {
                agent: Some("claude".into()),
                turn: Some(turn),
                ..Default::default()
            });
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    fn tool_child(
        trace: TraceId,
        sess: &SessionId,
        parent: SpanId,
        name: &str,
        ts: i64,
    ) -> Event {
        let mut ev = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name(name)
            .with_session(sess.clone())
            .with_parent(parent)
            .with_tool(ToolBlock::default());
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    #[test]
    fn session_tree_groups_by_turn_oldest_first() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-tree");
        let parent = SpanId::new();

        // Insert out of order across two turns + a turn-less tool/finding child.
        store.insert(&agent_turn(trace, &sess, 1, "t1-step", 200)).unwrap();
        store.insert(&agent_turn(trace, &sess, 0, "t0-step", 100)).unwrap();
        // A turn-less tool call (linked by parent_id, no stamped turn).
        store
            .insert(&tool_child(trace, &sess, parent, "tool-a", 150))
            .unwrap();
        // A turn-less finding child.
        let mut finding = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_name("secret-in-diff")
            .with_session(sess.clone())
            .with_finding(FindingBlock::default());
        finding.timestamp = MicrosTimestamp(180);
        store.insert(&finding).unwrap();
        // An event from a different session must not leak in.
        store
            .insert(&agent_turn(trace, &SessionId::new("other"), 0, "other", 120))
            .unwrap();

        let tree = store.session_tree(sess.as_str()).unwrap();

        assert_eq!(tree.session_id, "sess-tree");
        assert_eq!(tree.event_count(), 4, "only this session's 4 events");

        // Turn order: 0, 1, then the turn-less (None) catch-all last.
        let turn_ids: Vec<Option<i64>> = tree.turns.iter().map(|t| t.turn).collect();
        assert_eq!(turn_ids, vec![Some(0), Some(1), None]);

        // Turn 0 has exactly its step; turn 1 has exactly its step.
        let t0 = &tree.turns[0];
        assert_eq!(t0.events.len(), 1);
        assert_eq!(t0.events[0].name, "t0-step");
        let t1 = &tree.turns[1];
        assert_eq!(t1.events.len(), 1);
        assert_eq!(t1.events[0].name, "t1-step");

        // The None group holds the turn-less children, oldest-first by ts:
        // tool-a (150) then finding (180).
        let none_group = &tree.turns[2];
        assert_eq!(none_group.events.len(), 2);
        assert_eq!(none_group.events[0].name, "tool-a");
        assert_eq!(none_group.events[1].name, "secret-in-diff");
    }

    #[test]
    fn session_tree_empty_session_is_empty() {
        let store = Store::open_in_memory().unwrap();
        let tree = store.session_tree("no-such-session").unwrap();
        assert_eq!(tree.session_id, "no-such-session");
        assert!(tree.turns.is_empty());
        assert_eq!(tree.event_count(), 0);
    }

    // ---- prune (per-class age) -------------------------------------------

    /// An event of a given class-bearing shape at timestamp `ts`. We use the
    /// `max_sensitivity` projection rules: a prompt-bearing LLM event => prompts;
    /// a metadata-only LLM => model_metadata; a plain log => transcript.
    fn prompt_event(trace: TraceId, ts: i64) -> Event {
        let mut ev = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_llm(logbook_core::LlmBlock::default());
        ev.input = Some(serde_json::json!("a prompt"));
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    fn transcript_event(trace: TraceId, ts: i64) -> Event {
        let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("line");
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    #[test]
    fn prune_deletes_only_per_class_expired_rows() {
        // A fresh prompts row is kept; an old prompts row is dropped. Other
        // classes with a longer (global) age survive at the same old timestamp.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        let now = 1_000_000 * MICROS_PER_DAY; // a big "now" so cut-offs are positive.
        let day = MICROS_PER_DAY;

        // prompts: capped to a SHORT 1-day retention via policy override.
        let mut policy = CapturePolicy::default();
        policy.classes.prompts.max_age_days = Some(1);

        // A fresh prompt (now - 0.5 day) and an old prompt (now - 3 days).
        store.insert(&prompt_event(trace, now - day / 2)).unwrap();
        store.insert(&prompt_event(trace, now - 3 * day)).unwrap();
        // A transcript at the same old timestamp — but transcript uses the
        // global 14-day default, so it must SURVIVE the 3-day-old cut.
        store.insert(&transcript_event(trace, now - 3 * day)).unwrap();

        // Large db cap so the size sweep is a no-op here.
        let retention = Retention {
            max_age_days: 14,
            max_db_mb: 4096,
        };

        let stats = store.prune(&policy, &retention, now).unwrap();

        assert_eq!(stats.events_by_age, 1, "exactly the one old prompt dropped");
        assert_eq!(stats.events_by_size, 0, "size sweep no-op under a big cap");

        // The fresh prompt + the transcript remain (2 rows).
        assert_eq!(store.count().unwrap(), 2);
        // And specifically: no prompt older than the 1-day cut survives.
        let remaining_prompts = store
            .query(&Query::new().category(Category::Agent))
            .unwrap();
        assert_eq!(remaining_prompts.len(), 1, "one fresh prompt left");
        assert_eq!(
            remaining_prompts[0].timestamp.as_micros(),
            now - day / 2,
            "the surviving prompt is the fresh one"
        );
    }

    #[test]
    fn prune_unclassified_rows_use_global_default() {
        // A NULL-max_sensitivity row (a class-less finding) is swept under the
        // global default age, not kept forever.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let now = 1_000_000 * MICROS_PER_DAY;
        let day = MICROS_PER_DAY;

        // A security finding => max_sensitivity NULL (see schema::max_sensitivity_for).
        let mut old_finding = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock::default());
        old_finding.timestamp = MicrosTimestamp(now - 30 * day); // 30 days old
        store.insert(&old_finding).unwrap();

        let mut fresh_finding = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock::default());
        fresh_finding.timestamp = MicrosTimestamp(now - day); // 1 day old
        store.insert(&fresh_finding).unwrap();

        let policy = CapturePolicy::default();
        let retention = Retention {
            max_age_days: 14,
            max_db_mb: 4096,
        };
        let stats = store.prune(&policy, &retention, now).unwrap();
        assert_eq!(stats.events_by_age, 1, "the 30-day-old NULL row is dropped");
        assert_eq!(store.count().unwrap(), 1, "the 1-day-old NULL row survives");
    }

    #[test]
    fn prune_respects_global_size_cap() {
        // Insert many rows so the DB grows past a tiny max_db_mb, then prune and
        // assert the oldest rows are removed until back under the cap.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let now = 1_000_000 * MICROS_PER_DAY;

        // All rows are FRESH (1 second apart, all "now-ish"), so the AGE sweep
        // never touches them — only the SIZE sweep can. Give each a chunky body
        // so a few hundred rows clear the page cap.
        let big = "x".repeat(2048);
        for i in 0..1500i64 {
            let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout")
                .with_name(format!("line-{i}-{big}"));
            ev.timestamp = MicrosTimestamp(now + i); // ascending, all fresh
            store.insert(&ev).unwrap();
        }
        let before = store.count().unwrap();
        assert_eq!(before, 1500);

        // A deliberately tiny 1 MiB cap forces the size sweep to bite.
        let policy = CapturePolicy::default();
        let retention = Retention {
            max_age_days: 14,
            max_db_mb: 1,
        };
        let stats = store.prune(&policy, &retention, now + 10_000).unwrap();

        assert_eq!(stats.events_by_age, 0, "all rows fresh => age sweep no-op");
        assert!(stats.events_by_size > 0, "size sweep must delete some rows");

        let after = store.count().unwrap();
        assert!(after < before, "size sweep reduced the row count");

        // The deletions were OLDEST-first: the lowest-timestamp rows are gone,
        // the newest survive. Check the minimum surviving timestamp moved up.
        let min_ts: Option<i64> = store
            .read(|conn| Ok(conn.query_row("SELECT MIN(timestamp) FROM events", [], |r| r.get(0)).ok()))
            .unwrap();
        if let Some(min_ts) = min_ts {
            assert!(min_ts > now, "oldest rows (ts==now..) were the ones pruned");
        }
    }

    #[test]
    fn prune_size_sweep_checkpoints_wal() {
        // Regression: the size measurement read only the main db file, so after
        // the size sweep the freed pages could sit in the `-wal` file and the
        // on-disk footprint stayed above the cap. The sweep now (a) counts the
        // `-wal` bytes in the measurement and (b) runs `wal_checkpoint(TRUNCATE)`
        // afterwards, so the WAL is folded back + truncated. A *file-backed*
        // store is required for a real `-wal` file to exist on disk.
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("logbook.db-wal");
        let store = Store::open_in_dir(dir.path()).unwrap();
        let trace = TraceId::new();
        let now = 1_000_000 * MICROS_PER_DAY;

        // Many chunky, all-fresh rows so the WAL grows well past a 1 MiB cap and
        // only the SIZE sweep (not the age sweep) can act.
        let big = "x".repeat(2048);
        for i in 0..1500i64 {
            let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout")
                .with_name(format!("line-{i}-{big}"));
            ev.timestamp = MicrosTimestamp(now + i);
            store.insert(&ev).unwrap();
        }

        let policy = CapturePolicy::default();
        let retention = Retention {
            max_age_days: 14,
            max_db_mb: 1, // tiny cap forces the size sweep + checkpoint to run.
        };

        // The size measurement (now WAL-aware) and the truncating checkpoint must
        // run without error.
        let stats = store.prune(&policy, &retention, now + 10_000).unwrap();
        assert_eq!(stats.events_by_age, 0, "all rows fresh => age sweep no-op");
        assert!(stats.events_by_size > 0, "size sweep must delete some rows");

        // The checkpoint truncated the WAL back to (near) zero, so the bytes the
        // sweep freed are actually reclaimed on disk rather than stranded in the
        // `-wal` file. Without the fix this file stays large (megabytes).
        let wal_len_after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        assert!(
            wal_len_after < 256 * 1024,
            "wal_checkpoint(TRUNCATE) should reclaim the WAL after the size sweep \
             (left {wal_len_after} bytes)"
        );

        store.shutdown().unwrap();
    }

    // ---- forget ----------------------------------------------------------

    /// Seed a full session: agent_sessions + agent_actions + session_transcripts
    /// rows, plus a session-stamped event and a trace-correlated (session-less)
    /// event. Returns the (session_id, trace_id).
    fn seed_session(store: &Store, sess: &str, trace: &TraceId, started_at: i64) {
        let sess_id = sess.to_string();
        let trace_hex = trace.to_hex();
        store
            .write({
                let sess_id = sess_id.clone();
                let trace_hex = trace_hex.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO agent_sessions (id, agent, command, trace_id, started_at) \
                         VALUES (?1, 'claude', 'sh', ?2, ?3)",
                        params![sess_id, trace_hex, started_at],
                    )?;
                    conn.execute(
                        "INSERT INTO agent_actions (id, session_id, kind, observed_at) \
                         VALUES (?1, ?2, 'file_modified', ?3)",
                        params![format!("act-{sess_id}"), sess_id, started_at],
                    )?;
                    conn.execute(
                        "INSERT INTO session_transcripts (session_id, trace_id, created_at) \
                         VALUES (?1, ?2, ?3)",
                        params![sess_id, trace_hex, started_at],
                    )?;
                    Ok(())
                }
            })
            .unwrap();
        // A session-stamped event + a trace-correlated session-less event.
        let mut stamped = Event::new(*trace, Kind::Log, Category::AppLog, "stdout")
            .with_name("stamped")
            .with_session(SessionId::new(sess));
        stamped.timestamp = MicrosTimestamp(started_at);
        store.insert(&stamped).unwrap();
        let mut correlated = Event::new(*trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name("correlated")
            .with_tool(ToolBlock::default());
        correlated.timestamp = MicrosTimestamp(started_at + 1);
        store.insert(&correlated).unwrap();
    }

    fn table_count(store: &Store, table: &'static str) -> i64 {
        store
            .read(move |conn| {
                Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
            })
            .unwrap()
    }

    #[test]
    fn forget_session_removes_exactly_that_session() {
        let store = Store::open_in_memory().unwrap();
        let trace_a = TraceId::new();
        let trace_b = TraceId::new();
        seed_session(&store, "sess-a", &trace_a, 1_000);
        seed_session(&store, "sess-b", &trace_b, 2_000);

        // Sanity: both sessions present (2 each across tables; 4 events total).
        assert_eq!(table_count(&store, "agent_sessions"), 2);
        assert_eq!(table_count(&store, "agent_actions"), 2);
        assert_eq!(table_count(&store, "session_transcripts"), 2);
        assert_eq!(store.count().unwrap(), 4);

        let stats = store.forget_session("sess-a").unwrap();
        // sess-a had 1 stamped + 1 trace-correlated event = 2; one agent_session.
        assert_eq!(stats.events, 2, "both of sess-a's events removed");
        assert_eq!(stats.agent_sessions, 1);

        // sess-a is gone everywhere; the cascade dropped its action + transcript.
        assert_eq!(table_count(&store, "agent_sessions"), 1, "only sess-b left");
        assert_eq!(table_count(&store, "agent_actions"), 1, "sess-a action cascaded");
        assert_eq!(table_count(&store, "session_transcripts"), 1, "sess-a transcript cascaded");

        // sess-b's data is intact (2 events: stamped + correlated).
        assert_eq!(store.count().unwrap(), 2);
        let b_sess: String = store
            .read(|conn| Ok(conn.query_row("SELECT id FROM agent_sessions", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(b_sess, "sess-b");

        // Forgetting an absent session is a no-op.
        let none = store.forget_session("ghost").unwrap();
        assert_eq!(none, ForgetStats::default());
    }

    #[test]
    fn forget_before_drops_old_events_and_sessions() {
        let store = Store::open_in_memory().unwrap();
        let trace_old = TraceId::new();
        let trace_new = TraceId::new();
        seed_session(&store, "old", &trace_old, 1_000);
        seed_session(&store, "new", &trace_new, 9_000);

        // Cut at 5_000: the "old" session (started_at 1_000, events at 1_000/1_001)
        // goes; the "new" one (9_000) stays.
        let stats = store.forget_before(5_000).unwrap();
        assert_eq!(stats.events, 2, "old session's two events dropped");
        assert_eq!(stats.agent_sessions, 1, "old session row dropped");

        assert_eq!(table_count(&store, "agent_sessions"), 1);
        assert_eq!(table_count(&store, "agent_actions"), 1, "cascade dropped old action");
        assert_eq!(table_count(&store, "session_transcripts"), 1, "cascade dropped old transcript");
        assert_eq!(store.count().unwrap(), 2, "only the new session's events remain");
    }

    #[test]
    fn forget_before_leaves_no_orphaned_events_for_forgotten_session() {
        // Regression: `forget_before` deleted events by *event* timestamp but
        // sessions by *session start*. A session that STARTED before the cutoff
        // yet kept producing events AFTER it would have its `agent_sessions` row
        // removed while those later events survived — orphans pointing at a gone
        // session. `forget_before` must now also delete *all* events of any
        // session it forgets, regardless of the event's own timestamp.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let trace_hex = trace.to_hex();

        // A long-running session that started at 1_000 (before the 5_000 cutoff)
        // but whose events span both sides of it.
        seed_session(&store, "long", &trace, 1_000);
        // Two extra events for the SAME session, both stamped AFTER the cutoff:
        // one stamped with the session id, one trace-correlated + session-less.
        let mut after_stamped = Event::new(trace, Kind::Log, Category::AppLog, "stdout")
            .with_name("after-stamped")
            .with_session(SessionId::new("long"));
        after_stamped.timestamp = MicrosTimestamp(9_000); // post-cutoff
        store.insert(&after_stamped).unwrap();
        let mut after_correlated = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name("after-correlated")
            .with_tool(ToolBlock::default());
        after_correlated.timestamp = MicrosTimestamp(9_001); // post-cutoff, session-less
        store.insert(&after_correlated).unwrap();

        // Sanity: the session has 4 events (2 pre-cutoff from seed_session at
        // 1_000/1_001, 2 post-cutoff here).
        assert_eq!(store.count().unwrap(), 4);

        let stats = store.forget_before(5_000).unwrap();

        // The session row is gone...
        assert_eq!(stats.agent_sessions, 1, "the long session row dropped");
        assert_eq!(table_count(&store, "agent_sessions"), 0, "no session left");
        // ...and so are ALL four of its events — none orphaned past the cutoff.
        assert_eq!(stats.events, 4, "all of the forgotten session's events dropped");
        assert_eq!(store.count().unwrap(), 0, "no orphaned post-cutoff events remain");

        // Specifically: nothing stamped with the session id and nothing on its
        // trace survives the forget.
        let leftover_for_session: i64 = store
            .read({
                let trace_hex = trace_hex.clone();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT COUNT(*) FROM events WHERE session_id = 'long' OR trace_id = ?1",
                        params![trace_hex],
                        |r| r.get(0),
                    )?)
                }
            })
            .unwrap();
        assert_eq!(leftover_for_session, 0, "no event of the forgotten session is left");
    }

    #[test]
    fn forget_before_keeps_a_newer_session_sharing_the_trace() {
        // The consistency fix must not over-delete: when a forgotten old session
        // and a still-retained newer session share a `trace_id`, the newer
        // session's *stamped* events (and any of its own pre-cutoff rows) survive
        // — the trace sweep only removes session-LESS rows. Mirrors the same
        // `session_id IS NULL` guard `forget_session` uses.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        // Old session started pre-cutoff; new session started post-cutoff. Both
        // on the SAME trace (the unusual-but-possible case).
        seed_session(&store, "old", &trace, 1_000);
        seed_session(&store, "new", &trace, 9_000);

        // seed_session inserted, for each session: a stamped event + a
        // session-LESS correlated event on this shared trace => 4 events total.
        assert_eq!(store.count().unwrap(), 4);

        let stats = store.forget_before(5_000).unwrap();

        // Only the old session row is forgotten.
        assert_eq!(stats.agent_sessions, 1, "only the old session row dropped");
        assert_eq!(table_count(&store, "agent_sessions"), 1, "the new session survives");
        let surviving: String = store
            .read(|conn| Ok(conn.query_row("SELECT id FROM agent_sessions", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(surviving, "new");

        // The NEW session's stamped event must still be present (it shares the
        // trace but is NOT session-less, so the trace sweep can't touch it).
        let new_stamped: i64 = store
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM events WHERE session_id = 'new'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(new_stamped, 1, "the newer session's stamped event is retained");

        // Old session's two events (one stamped pre-cutoff + one session-less on
        // the trace) are gone; the new session's session-less correlated event,
        // stamped at 9_001 (post-cutoff), also goes via the trace sweep — leaving
        // exactly the new session's stamped event.
        assert_eq!(stats.events, 3, "old session's two + new session-less trace row");
        assert_eq!(store.count().unwrap(), 1, "exactly the new stamped event remains");
    }
}
