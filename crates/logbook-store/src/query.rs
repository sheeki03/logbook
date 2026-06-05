//! The read/query API over the `events` table.
//!
//! A [`Query`] is a declarative filter (time range, category, trace id, session
//! id, parent span id, turn, FTS match) that compiles to a single parameterized
//! SQL statement. [`query_events`] runs on a read-only connection borrowed from
//! the read pool for file-backed stores, and on the single writer connection for
//! `:memory:` stores (each `:memory:` open is a distinct database, so the read
//! pool can't be shared — see [`crate::Store::read`]).
//!
//! [`token_cost_rollup`] is a read helper that aggregates the [`LlmBlock`] fields
//! of LLM events in a time window into per-model/agent [`CostRow`] totals (read
//! from each event's JSON `body`, the source of truth).
//!
//! [`LlmBlock`]: logbook_core::LlmBlock

use std::collections::BTreeMap;

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
    /// Restrict to a single parent span id (hex), matched against the
    /// denormalized `events.parent_id` column. Used to fetch the children of a
    /// turn/tool span (e.g. tool calls linked to their turn).
    pub parent_id: Option<String>,
    /// Restrict to a single turn index, matched against the V3 `events.turn`
    /// column (projected from `AgentBlock.turn`). Pair with [`Query::session`]
    /// to scope a turn to one session.
    pub turn: Option<i64>,
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

    /// Constrain to a parent span id (hex). Matches the denormalized
    /// `events.parent_id` column, so it returns the direct children of that
    /// span (e.g. the tool calls under a turn span).
    #[must_use]
    pub fn parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Constrain to a turn index (V3 `events.turn`, projected from
    /// `AgentBlock.turn`). Combine with [`Query::session`] to scope a turn to a
    /// single session.
    #[must_use]
    pub fn turn(mut self, turn: i64) -> Self {
        self.turn = Some(turn);
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
    if let Some(parent) = &query.parent_id {
        wheres.push("e.parent_id = ?".to_string());
        params.push(Box::new(parent.clone()));
    }
    if let Some(turn) = query.turn {
        wheres.push("e.turn = ?".to_string());
        params.push(Box::new(turn));
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

/// One row of the token/cost rollup: an aggregate over the [`LlmBlock`] fields of
/// every LLM-bearing event in a time window, grouped by `(model, agent)`.
///
/// [`LlmBlock`]: logbook_core::LlmBlock
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CostRow {
    /// The model identifier (`LlmBlock.model`), or `None` for events whose LLM
    /// block did not report a model. Part of the grouping key.
    pub model: Option<String>,
    /// The originating agent (`AgentBlock.agent`) when the same event also
    /// carries an agent block, else `None`. Part of the grouping key so a
    /// rollup can attribute spend per agent as well as per model. In practice an
    /// event carries at most one typed block (see `Event::validate`), so this is
    /// usually `None`; it is wired so a future producer that stamps the agent
    /// onto an LLM event (e.g. via attributes promotion) rolls up correctly.
    pub agent: Option<String>,
    /// Summed prompt/input tokens across the group (`LlmBlock.input_tokens`).
    pub input_tokens: u64,
    /// Summed completion/output tokens across the group
    /// (`LlmBlock.output_tokens`).
    pub output_tokens: u64,
    /// Summed total tokens across the group (`LlmBlock.total_tokens`). Note this
    /// sums the provider-reported `total_tokens` field directly; it is **not**
    /// derived as `input + output` (a provider may report only a subset), so
    /// callers wanting a derived total should compute `input_tokens +
    /// output_tokens` themselves.
    pub total_tokens: u64,
    /// Summed cost in USD across the group (`LlmBlock.cost_usd`). `0.0` when no
    /// event in the group reported a cost. Always finite: non-finite addends
    /// (NaN/±inf) are skipped and the running total is clamped to
    /// `[f64::MIN, f64::MAX]`, so a pathological input can never poison the total
    /// with `inf`/`NaN`. Normal-magnitude sums are exact.
    pub cost_usd: f64,
    /// Number of LLM events in the group.
    pub count: u64,
}

/// Token/cost rollup over LLM events in the half-open-ish window
/// `[since_micros, until_micros]` (both bounds inclusive, matching
/// [`Query::time_range`]). `None` for a bound leaves it unconstrained.
///
/// **Grouping:** one [`CostRow`] per distinct `(model, agent)` pair, where
/// `model` is `LlmBlock.model` and `agent` is `AgentBlock.agent` if the same
/// event also carries an agent block (otherwise `None`). Within each group the
/// helper sums `input_tokens`, `output_tokens`, `total_tokens`, `cost_usd`, and
/// the event `count`.
///
/// **Source of truth:** the values are read from each event's JSON `body` (the
/// canonical, lossless representation) — specifically `blocks.llm` — not from
/// any denormalized column, so the rollup reflects exactly what was persisted in
/// the `LlmBlock`. Only rows that carry an `llm` block contribute; every other
/// event is skipped.
///
/// Rows are returned in a stable order (ascending by `model` then `agent`, with
/// `None` sorting first) so output is deterministic for tests and display.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if the read or a body
/// deserialization fails.
pub fn token_cost_rollup(
    conn: &Connection,
    since_micros: Option<i64>,
    until_micros: Option<i64>,
) -> Result<Vec<CostRow>> {
    // Restrict to LLM-kind rows up front (the denormalized `kind` column is an
    // index-friendly pre-filter); the body is still the source of truth for the
    // summed LlmBlock fields. A row could in principle be kind!=llm yet carry an
    // llm block, but producers set kind=llm for llm blocks, and we re-check the
    // block presence below regardless.
    let mut sql = String::from("SELECT e.body FROM events e WHERE e.kind = 'llm'");
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    if let Some(since) = since_micros {
        sql.push_str(" AND e.timestamp >= ?");
        params.push(Box::new(since));
    }
    if let Some(until) = until_micros {
        sql.push_str(" AND e.timestamp <= ?");
        params.push(Box::new(until));
    }

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))?;

    // Group by (model, agent). BTreeMap keeps the output deterministically
    // ordered (None < Some, then lexicographic) without a separate sort.
    let mut groups: BTreeMap<(Option<String>, Option<String>), CostRow> = BTreeMap::new();
    for body in rows {
        let event = event_from_body(&body?)?;
        let Some(llm) = event.blocks.llm.as_ref() else {
            // kind=llm but no llm block (shouldn't happen for well-formed
            // producers); nothing to roll up.
            continue;
        };
        let agent = event
            .blocks
            .agent
            .as_ref()
            .and_then(|a| a.agent.clone());
        let key = (llm.model.clone(), agent.clone());
        let entry = groups.entry(key).or_insert_with(|| CostRow {
            model: llm.model.clone(),
            agent,
            ..Default::default()
        });
        entry.input_tokens = entry.input_tokens.saturating_add(llm.input_tokens.unwrap_or(0));
        entry.output_tokens = entry
            .output_tokens
            .saturating_add(llm.output_tokens.unwrap_or(0));
        entry.total_tokens = entry.total_tokens.saturating_add(llm.total_tokens.unwrap_or(0));
        // Cost is defensive like the token sums above (which use `saturating_add`):
        // a single pathological `cost_usd` (NaN/±inf, or a finite value large
        // enough that the running total overflows) must not poison the whole
        // group's total with a non-finite value. Skip non-finite addends and clamp
        // the running total back into `[f64::MIN, f64::MAX]`, so the result is
        // always finite. Normal-magnitude sums never hit the clamp and stay exact.
        let addend = llm.cost_usd.unwrap_or(0.0);
        if addend.is_finite() {
            entry.cost_usd = (entry.cost_usd + addend).clamp(f64::MIN, f64::MAX);
        }
        entry.count += 1;
    }

    Ok(groups.into_values().collect())
}

#[cfg(test)]
mod tests {
    use logbook_core::{
        AgentBlock, Category, Event, Kind, LlmBlock, MicrosTimestamp, SessionId, SpanId,
        TraceId,
    };

    use crate::{query_events, token_cost_rollup, CostRow, Query, Store};

    fn agent_step(trace: TraceId, session: &SessionId, turn: u64, name: &str) -> Event {
        Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_name(name)
            .with_session(session.clone())
            .with_agent(AgentBlock {
                agent: Some("claude".into()),
                turn: Some(turn),
                ..Default::default()
            })
    }

    /// An LLM event with the given model + token/cost numbers, timestamped so the
    /// rollup window can include/exclude it.
    fn llm_event(trace: TraceId, model: &str, ts: i64, llm: LlmBlock) -> Event {
        let mut ev = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_llm(LlmBlock {
                model: Some(model.into()),
                ..llm
            });
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    #[test]
    fn turn_round_trips_and_filters() {
        // A turn stamped onto AgentBlock.turn projects to the V3 `events.turn`
        // column and is filterable via Query::turn (scoped by session).
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-turn");
        store.insert(&agent_step(trace, &sess, 0, "t0")).unwrap();
        store.insert(&agent_step(trace, &sess, 1, "t1-a")).unwrap();
        store.insert(&agent_step(trace, &sess, 1, "t1-b")).unwrap();
        store.insert(&agent_step(trace, &sess, 2, "t2")).unwrap();

        // Filter to turn 1 within the session → exactly the two turn-1 steps.
        let turn1 = store
            .query(&Query::new().session(sess.as_str()).turn(1))
            .unwrap();
        assert_eq!(turn1.len(), 2, "two events in turn 1");
        for ev in &turn1 {
            assert_eq!(ev.blocks.agent.as_ref().and_then(|a| a.turn), Some(1));
        }

        // A turn that does not exist → empty.
        let turn9 = store
            .query(&Query::new().session(sess.as_str()).turn(9))
            .unwrap();
        assert!(turn9.is_empty());

        // The body still carries the turn losslessly (body is source of truth).
        let t2 = store
            .query(&Query::new().session(sess.as_str()).turn(2))
            .unwrap();
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0].name, "t2");
    }

    #[test]
    fn parent_id_filter_returns_children_of_a_span() {
        // Query::parent matches the denormalized events.parent_id column, so it
        // returns the direct children of a turn/tool span.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let parent = SpanId::new();
        let parent_hex = parent.to_hex();

        let child_a = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name("child-a")
            .with_parent(parent);
        let child_b = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name("child-b")
            .with_parent(parent);
        // An unrelated event with no parent.
        let orphan = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("orphan");

        store.insert(&child_a).unwrap();
        store.insert(&child_b).unwrap();
        store.insert(&orphan).unwrap();

        let children = store.query(&Query::new().parent(parent_hex.clone())).unwrap();
        assert_eq!(children.len(), 2, "exactly the two children of the parent span");
        for ev in &children {
            assert_eq!(ev.parent_id.map(|p| p.to_hex()).as_deref(), Some(parent_hex.as_str()));
        }
    }

    #[test]
    fn fts_search_still_works_alongside_new_columns() {
        // Regression: the V3 `turn` column / new Query fields don't disturb the
        // existing FTS `text()` path.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-fts");
        store
            .insert(&agent_step(trace, &sess, 0, "connection refused on port 8080"))
            .unwrap();
        store
            .insert(&agent_step(trace, &sess, 1, "everything is fine"))
            .unwrap();

        let hits = store.query(&Query::new().search("refused")).unwrap();
        assert_eq!(hits.len(), 1, "FTS still finds the 'refused' line");
        assert!(hits[0].name.contains("refused"));

        // FTS combines with the new turn filter (ANDed).
        let none = store
            .query(&Query::new().search("refused").turn(1))
            .unwrap();
        assert!(none.is_empty(), "the 'refused' line is turn 0, not turn 1");
    }

    #[test]
    fn token_cost_rollup_groups_by_model_and_sums() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        // Two sonnet calls + one opus call, all in window.
        store
            .insert(&llm_event(
                trace,
                "claude-3-5-sonnet",
                1_000,
                LlmBlock {
                    input_tokens: Some(100),
                    output_tokens: Some(20),
                    total_tokens: Some(120),
                    cost_usd: Some(0.01),
                    ..Default::default()
                },
            ))
            .unwrap();
        store
            .insert(&llm_event(
                trace,
                "claude-3-5-sonnet",
                2_000,
                LlmBlock {
                    input_tokens: Some(50),
                    output_tokens: Some(10),
                    total_tokens: Some(60),
                    cost_usd: Some(0.005),
                    ..Default::default()
                },
            ))
            .unwrap();
        store
            .insert(&llm_event(
                trace,
                "claude-3-opus",
                3_000,
                LlmBlock {
                    input_tokens: Some(200),
                    output_tokens: Some(40),
                    total_tokens: Some(240),
                    cost_usd: Some(0.10),
                    ..Default::default()
                },
            ))
            .unwrap();
        // A non-LLM event must be ignored entirely.
        store
            .insert(&Event::new(trace, Kind::Log, Category::AppLog, "stdout"))
            .unwrap();

        let rollup = store
            .read(|conn| token_cost_rollup(conn, None, None))
            .unwrap();
        // Two groups, ordered by model ascending (BTreeMap key order):
        // "claude-3-5-sonnet" ('5' = 0x35) sorts before "claude-3-opus" ('o' = 0x6F).
        assert_eq!(rollup.len(), 2, "one row per distinct model");

        let opus = rollup
            .iter()
            .find(|r| r.model.as_deref() == Some("claude-3-opus"))
            .expect("opus row");
        assert_eq!(opus.count, 1);
        assert_eq!(opus.input_tokens, 200);
        assert_eq!(opus.output_tokens, 40);
        assert_eq!(opus.total_tokens, 240);
        assert!((opus.cost_usd - 0.10).abs() < 1e-9);

        let sonnet = rollup
            .iter()
            .find(|r| r.model.as_deref() == Some("claude-3-5-sonnet"))
            .expect("sonnet row");
        assert_eq!(sonnet.count, 2, "two sonnet calls summed");
        assert_eq!(sonnet.input_tokens, 150);
        assert_eq!(sonnet.output_tokens, 30);
        assert_eq!(sonnet.total_tokens, 180);
        assert!((sonnet.cost_usd - 0.015).abs() < 1e-9);

        // Deterministic order: ascending by model — sonnet ('5') before opus ('o').
        assert_eq!(rollup[0].model.as_deref(), Some("claude-3-5-sonnet"));
        assert_eq!(rollup[1].model.as_deref(), Some("claude-3-opus"));
    }

    #[test]
    fn token_cost_rollup_honors_time_window() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        store
            .insert(&llm_event(
                trace,
                "m",
                1_000,
                LlmBlock { cost_usd: Some(1.0), ..Default::default() },
            ))
            .unwrap();
        store
            .insert(&llm_event(
                trace,
                "m",
                5_000,
                LlmBlock { cost_usd: Some(2.0), ..Default::default() },
            ))
            .unwrap();

        // Window [2_000, 9_000] excludes the first (ts=1_000), includes the second.
        let rollup = store
            .read(|conn| token_cost_rollup(conn, Some(2_000), Some(9_000)))
            .unwrap();
        assert_eq!(rollup.len(), 1);
        assert_eq!(rollup[0].count, 1);
        assert!((rollup[0].cost_usd - 2.0).abs() < 1e-9);

        // Inclusive lower bound: window starting exactly at 1_000 includes it.
        let both = store
            .read(|conn| token_cost_rollup(conn, Some(1_000), None))
            .unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].count, 2);
        assert!((both[0].cost_usd - 3.0).abs() < 1e-9);
    }

    #[test]
    fn token_cost_rollup_handles_missing_fields_and_empty() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        // Empty store → empty rollup.
        let empty = store.read(|conn| token_cost_rollup(conn, None, None)).unwrap();
        assert_eq!(empty, Vec::<CostRow>::new());

        // An LLM event with a model but no token/cost numbers → counted, zeros.
        store
            .insert(&llm_event(trace, "bare", 1_000, LlmBlock::default()))
            .unwrap();
        // An LLM event with no model at all → grouped under model=None.
        let mut no_model = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_llm(LlmBlock { input_tokens: Some(5), ..Default::default() });
        no_model.timestamp = MicrosTimestamp(2_000);
        store.insert(&no_model).unwrap();

        let rollup = store.read(|conn| token_cost_rollup(conn, None, None)).unwrap();
        assert_eq!(rollup.len(), 2, "model=None and model=Some('bare')");
        // None sorts first in the BTreeMap key.
        assert_eq!(rollup[0].model, None);
        assert_eq!(rollup[0].input_tokens, 5);
        assert_eq!(rollup[0].cost_usd, 0.0);
        assert_eq!(rollup[1].model.as_deref(), Some("bare"));
        assert_eq!(rollup[1].count, 1);
        assert_eq!(rollup[1].input_tokens, 0);
    }

    #[test]
    fn token_cost_rollup_bounds_pathological_cost() {
        // Regression: the per-group cost accumulator must be defensive like the
        // token sums (which saturate). A pathological `cost_usd` — here several
        // `f64::MAX` values in the same group whose naive sum overflows to +inf —
        // must yield a *finite, bounded* total, never inf/NaN. (Non-finite inputs
        // like NaN/inf serialize to JSON `null` and round-trip back to `None`, so
        // the realistic poisoning vector is finite-but-huge values summing past
        // f64::MAX; the fix also skips any non-finite addend defensively.)
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        // Three f64::MAX costs in one group: f64::MAX + f64::MAX overflows to +inf
        // under a naive `+=`. The fix clamps the running total to f64::MAX.
        for ts in [1_000_i64, 2_000, 3_000] {
            store
                .insert(&llm_event(
                    trace,
                    "huge",
                    ts,
                    LlmBlock { cost_usd: Some(f64::MAX), ..Default::default() },
                ))
                .unwrap();
        }
        // A second group mixes one huge cost with one normal cost; the total must
        // also stay finite (and is dominated by the huge addend).
        store
            .insert(&llm_event(
                trace,
                "mixed",
                4_000,
                LlmBlock { cost_usd: Some(f64::MAX), ..Default::default() },
            ))
            .unwrap();
        store
            .insert(&llm_event(
                trace,
                "mixed",
                5_000,
                LlmBlock { cost_usd: Some(0.25), ..Default::default() },
            ))
            .unwrap();

        let rollup = store.read(|conn| token_cost_rollup(conn, None, None)).unwrap();

        let huge = rollup
            .iter()
            .find(|r| r.model.as_deref() == Some("huge"))
            .expect("huge row");
        assert_eq!(huge.count, 3);
        assert!(
            huge.cost_usd.is_finite(),
            "overflowing cost total must stay finite, got {}",
            huge.cost_usd
        );
        // Clamped to the bound rather than spilling to +inf.
        assert_eq!(huge.cost_usd, f64::MAX);

        let mixed = rollup
            .iter()
            .find(|r| r.model.as_deref() == Some("mixed"))
            .expect("mixed row");
        assert_eq!(mixed.count, 2);
        assert!(
            mixed.cost_usd.is_finite(),
            "mixed cost total must stay finite, got {}",
            mixed.cost_usd
        );
        // f64::MAX + 0.25 rounds to f64::MAX in f64; either way it stays bounded.
        assert_eq!(mixed.cost_usd, f64::MAX);
    }

    #[test]
    fn query_compiles_with_all_filters_combined() {
        // Sanity: every set constraint ANDs into one statement without SQL error,
        // including the new parent_id + turn alongside the existing ones.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-all");
        let parent = SpanId::new();
        let ev = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name("matchable haystack")
            .with_session(sess.clone())
            .with_parent(parent);
        store.insert(&ev).unwrap();

        let q = Query::new()
            .time_range(0, i64::MAX)
            .category(Category::Agent)
            .trace(trace.to_hex())
            .session(sess.as_str())
            .parent(parent.to_hex())
            .turn(0) // tool event has no agent turn → excludes it
            .search("haystack")
            .limit(10);
        // turn(0) excludes the tool row (its events.turn is NULL), so this is
        // empty — but importantly it compiles and runs.
        let got = store.read(move |conn| query_events(conn, &q)).unwrap();
        assert!(got.is_empty(), "turn=0 filter excludes the turn-less tool row");

        // Drop the turn filter → the row matches the rest of the predicate.
        let q2 = Query::new()
            .category(Category::Agent)
            .session(sess.as_str())
            .parent(parent.to_hex())
            .search("haystack");
        let got2 = store.read(move |conn| query_events(conn, &q2)).unwrap();
        assert_eq!(got2.len(), 1);
        assert_eq!(got2[0].name, "matchable haystack");
    }
}
