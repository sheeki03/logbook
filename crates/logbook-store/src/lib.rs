//! `logbook-store` — the persistence layer (plan §2).
//!
//! A [`Store`] wraps a SQLite database (rusqlite, with SQLite compiled in via
//! the `bundled` feature) migrated by [`refinery`]. It runs in **WAL** mode
//! behind a **single-writer thread** (all mutations serialized over an mpsc
//! channel) plus a **read pool** (concurrent read-only connections). A
//! [`jsonl`] fallback writer/reader mirrors events to `events.jsonl` for
//! durability when SQLite is unavailable.
//!
//! Secret redaction happens upstream in `logbook-core`; by the time an
//! [`Event`](logbook_core::Event) reaches the store it is already safe to
//! persist.
//!
//! # Example
//! ```
//! use logbook_store::{Store, Query};
//! use logbook_core::{Event, Kind, Category, TraceId};
//!
//! # fn main() -> logbook_store::Result<()> {
//! let store = Store::open_in_memory()?;
//! let trace = TraceId::new();
//! store.insert(&Event::new(trace, Kind::Log, Category::AppLog, "stdout"))?;
//!
//! let found = store.query(&Query::new().trace(trace.to_hex()))?;
//! assert_eq!(found.len(), 1);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod error;
pub mod jsonl;
pub mod query;
pub mod retention;
pub mod schema;
mod writer;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::Connection;

use logbook_core::{CapturePolicy, Event};

pub use audit::{
    append_audit, canonical_json, hub_receive, verify_chain, AuditBreak, AuditVerification,
    BreakReason, GENESIS_HASH,
};
pub use error::{Result, StoreError};
pub use jsonl::{read_jsonl, read_jsonl_opt, JsonlWriter, JSONL_FILENAME};
pub use query::{
    count_events, get_trace, query_events, token_cost_rollup, CostRow, Query,
};
pub use retention::{ForgetStats, PruneStats, SessionTree, TurnGroup};

use writer::StoreInner;

/// The conventional SQLite filename within an out-dir.
pub const DB_FILENAME: &str = "logbook.db";

/// A handle to the logbook event store. Cheap to clone (`Arc` inside); all
/// clones share the same single-writer thread and read pool.
#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

impl Store {
    /// Open (creating if needed) a file-backed store at `path`, running pragmas
    /// and migrations.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the file/dir cannot be created or migrations
    /// fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let inner = StoreInner::open(path.as_ref().to_path_buf())?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Open the store inside an out-dir (`<out_dir>/logbook.db`).
    ///
    /// # Errors
    /// See [`Store::open`].
    pub fn open_in_dir(out_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open(out_dir.as_ref().join(DB_FILENAME))
    }

    /// Open a private in-memory store (handy for tests). Reads are routed
    /// through the writer connection because each `:memory:` open is a distinct
    /// database.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if migrations fail.
    pub fn open_in_memory() -> Result<Self> {
        let inner = StoreInner::open(PathBuf::from(":memory:"))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The database path (`:memory:` for in-memory stores).
    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Insert (or replace, keyed on [`Event::id`]) a single event. Blocks until
    /// the single-writer thread has committed it.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the write fails or the writer is gone.
    pub fn insert(&self, event: &Event) -> Result<()> {
        self.inner.insert(event)
    }

    /// Insert (or replace) a batch of events in one transaction.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the write fails or the writer is gone.
    pub fn insert_batch(&self, events: Vec<Event>) -> Result<()> {
        self.inner.insert_batch(events)
    }

    /// Run a [`Query`] and return the matching events.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the read fails.
    pub fn query(&self, query: &Query) -> Result<Vec<Event>> {
        let query = query.clone();
        self.inner.read(move |conn| query_events(conn, &query))
    }

    /// Fetch a whole trace (all events sharing `trace_id`), oldest first.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the read fails.
    pub fn trace(&self, trace_id: &str) -> Result<Vec<Event>> {
        let trace_id = trace_id.to_string();
        self.inner.read(move |conn| get_trace(conn, &trace_id))
    }

    /// Total number of stored events.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the read fails.
    pub fn count(&self) -> Result<i64> {
        self.inner.read(count_events)
    }

    /// Run an arbitrary read against a read-pool connection (or the writer
    /// connection, for `:memory:` stores). Useful for the inventory / findings
    /// query helpers that other crates will add.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the read closure fails.
    pub fn read<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.inner.read(f)
    }

    /// Run an arbitrary mutation against the single write connection.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the closure fails or the writer is gone.
    pub fn write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Connection) -> Result<()> + Send + 'static,
    {
        self.inner.exec(f)
    }

    /// Run a mutating closure against the single write connection and return its
    /// value (e.g. a delete count). Like [`Store::write`] but threads a typed
    /// value back from the writer thread, for prune/forget-style helpers that
    /// report stats.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the closure fails or the writer is gone.
    pub fn write_returning<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.inner.write_with(f)
    }

    /// Build the correlation timeline ([`SessionTree`]) for a session: its
    /// events grouped by turn (turns as parents, oldest-first within each turn),
    /// turns ascending with the turn-less group last (plan §3, "Correlation
    /// timeline"). Reads only; safe to run concurrently.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the read fails.
    pub fn session_tree(&self, session_id: &str) -> Result<SessionTree> {
        let session_id = session_id.to_string();
        self.inner
            .read(move |conn| retention::session_tree(conn, &session_id))
    }

    /// Append one tamper-evidence audit-log row for `event`, extending the
    /// hash chain (plan "Phase 4 — Complete Tier & Fleet" → hash-chain audit),
    /// and return the new `row_hash`. The row links to the current chain tail
    /// (genesis = [`GENESIS_HASH`]) via
    /// `row_hash = hex(sha256(prev_hash || canonical_json(event)))` over the
    /// event's canonical, **already-redacted** JSON.
    ///
    /// This attests that a stored, redacted row was not altered/removed *after*
    /// it was recorded; it does **not** prove raw secrets were never captured
    /// before redaction (redaction runs upstream at capture). See
    /// [`audit`](crate::audit) for the full integrity model.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if canonicalization or the insert fails, or the
    /// writer is gone.
    pub fn append_audit(&self, event: &Event) -> Result<String> {
        let event = event.clone();
        self.inner
            .write_with(move |conn| crate::audit::append_audit(conn, &event))
    }

    /// Recompute the hash chain from the current stored event bodies in `seq`
    /// order and report the first break ([`AuditVerification`]). Mutating or
    /// deleting an audited event's stored body makes verification fail at that
    /// row (plan "P4 tests": "mutating an audited row breaks chain
    /// verification"). Reads only; an empty chain verifies cleanly.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the read or a body deserialization fails.
    pub fn verify_chain(&self) -> Result<AuditVerification> {
        self.inner.read(crate::audit::verify_chain)
    }

    /// Idempotently receive a batch of forwarded `events` by id (the fleet
    /// receiver's upsert-by-id path, plan "Phase 4 — Complete Tier & Fleet" →
    /// Hub). Inserts each event with `INSERT OR IGNORE` on the `events.id`
    /// primary key — re-receiving an already-present id is a no-op that
    /// preserves the local copy — and returns how many rows were **newly**
    /// inserted. Forwarded events are already-redacted on their origin plane.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if a row fails to serialize, the insert
    /// transaction fails (the whole batch rolls back), or the writer is gone.
    pub fn hub_receive(&self, events: &[Event]) -> Result<usize> {
        let events = events.to_vec();
        self.inner
            .write_with(move |conn| crate::audit::hub_receive(conn, &events))
    }

    /// Enforce retention against the `events` table (plan §3): a per-class age
    /// sweep keyed on `events.max_sensitivity` (each class's `max_age_days`,
    /// falling back to the global `retention.max_age_days`), then a global size
    /// sweep that deletes the oldest rows until the store is back under
    /// `retention.max_db_mb`. Returns the [`PruneStats`] describing what was
    /// removed.
    ///
    /// Run at `ui`/`agent` startup. Only the `events` spine is pruned here;
    /// inventory rows are governed by [`Store::forget_session`] /
    /// [`Store::forget_before`].
    ///
    /// # Errors
    /// Returns a [`StoreError`] if a delete or size probe fails or the writer is
    /// gone.
    pub fn prune(
        &self,
        policy: &CapturePolicy,
        retention: &logbook_core::config::Retention,
        now_micros: i64,
    ) -> Result<PruneStats> {
        // The closure must be `'static`; clone the small policy/retention in.
        // (Bind to distinct names so they don't shadow the `retention` module.)
        let policy = policy.clone();
        let retention_cfg = retention.clone();
        self.inner.write_with(move |conn| {
            crate::retention::prune(conn, &policy, &retention_cfg, now_micros)
        })
    }

    /// Forget exactly one session's data (`logbook forget <session>`): delete its
    /// `events` (matched on `session_id` plus the session's `trace_id`) and its
    /// `agent_sessions` row; the session's `agent_actions` / `session_transcripts`
    /// cascade. Returns the [`ForgetStats`]. Idempotent for an absent session.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if a delete fails or the writer is gone.
    pub fn forget_session(&self, session_id: &str) -> Result<ForgetStats> {
        let session_id = session_id.to_string();
        self.inner
            .write_with(move |conn| retention::forget_session(conn, &session_id))
    }

    /// Forget everything older than `micros` (`logbook forget --before <ts>`):
    /// delete `events` with `timestamp < micros` and `agent_sessions` whose
    /// `started_at < micros` (their inventory rows cascade). Returns the
    /// [`ForgetStats`].
    ///
    /// # Errors
    /// Returns a [`StoreError`] if a delete fails or the writer is gone.
    pub fn forget_before(&self, micros: i64) -> Result<ForgetStats> {
        self.inner
            .write_with(move |conn| retention::forget_before(conn, micros))
    }

    /// Flush and shut down the single-writer thread. Called automatically on
    /// drop of the last handle, but can be invoked explicitly to surface
    /// errors.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the writer thread reported a problem.
    pub fn shutdown(&self) -> Result<()> {
        self.inner.shutdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{Category, ConsoleBlock, Event, FindingBlock, Kind, Severity, SessionId, Status, TraceId};

    fn log_event(trace: TraceId, name: &str) -> Event {
        Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name(name)
    }

    #[test]
    fn open_in_memory_runs_migrations() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn insert_and_query_by_trace() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        store.insert(&log_event(trace, "one")).unwrap();
        store.insert(&log_event(trace, "two")).unwrap();
        // A different trace, should not match.
        store.insert(&log_event(TraceId::new(), "other")).unwrap();

        let found = store.query(&Query::new().trace(trace.to_hex())).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(store.count().unwrap(), 3);
    }

    #[test]
    fn query_by_category_and_time_range() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let mut sec = Event::new(trace, Kind::Finding, Category::Security, "advisory");
        sec.timestamp = logbook_core::MicrosTimestamp(1_000);
        let mut log = log_event(trace, "log");
        log.timestamp = logbook_core::MicrosTimestamp(2_000);
        store.insert(&sec).unwrap();
        store.insert(&log).unwrap();

        let security = store.query(&Query::new().category(Category::Security)).unwrap();
        assert_eq!(security.len(), 1);
        assert_eq!(security[0].category, Category::Security);

        let in_range = store
            .query(&Query::new().time_range(1_500, 3_000))
            .unwrap();
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].name, "log");
    }

    #[test]
    fn query_by_session() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-42");
        let ev = log_event(trace, "in-session").with_session(sess.clone());
        store.insert(&ev).unwrap();
        store.insert(&log_event(trace, "no-session")).unwrap();

        let found = store.query(&Query::new().session(sess.as_str())).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "in-session");
    }

    #[test]
    fn fts_search_matches_name_and_body() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        store
            .insert(&log_event(trace, "connection refused on port 8080"))
            .unwrap();
        store.insert(&log_event(trace, "everything is fine")).unwrap();

        let hits = store.query(&Query::new().search("refused")).unwrap();
        assert_eq!(hits.len(), 1, "FTS should find the 'refused' line");
        assert!(hits[0].name.contains("refused"));

        let none = store.query(&Query::new().search("nonexistentterm")).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn upsert_on_id_replaces_not_duplicates() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let mut ev = log_event(trace, "v1");
        store.insert(&ev).unwrap();
        // Same id, new content.
        ev.name = "v2".to_string();
        ev.status = Status::Ok;
        store.insert(&ev).unwrap();

        assert_eq!(store.count().unwrap(), 1, "same id must upsert, not duplicate");
        let got = store.trace(&trace.to_hex()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "v2");
        assert_eq!(got[0].status, Status::Ok);
    }

    #[test]
    fn batch_insert_in_transaction() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let batch: Vec<Event> = (0..50).map(|i| log_event(trace, &format!("line {i}"))).collect();
        store.insert_batch(batch).unwrap();
        assert_eq!(store.count().unwrap(), 50);
    }

    #[test]
    fn batch_insert_rolls_back_entirely_on_mid_batch_failure() {
        // The whole point of `insert_batch` is atomicity: if any row in the
        // batch fails, none of them should land. Install a tripwire trigger
        // that aborts the insert of a sentinel-named row, then submit a batch
        // whose middle event trips it, and assert the table is left empty.
        let store = Store::open_in_memory().unwrap();
        store
            .write(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER tripwire BEFORE INSERT ON events \
                     WHEN new.name = 'TRIPWIRE' \
                     BEGIN SELECT RAISE(ABORT, 'tripwire'); END;",
                )?;
                Ok(())
            })
            .unwrap();

        let trace = TraceId::new();
        let mut batch: Vec<Event> = (0..5).map(|i| log_event(trace, &format!("ok {i}"))).collect();
        // Make a middle row trip the trigger so the failure is genuinely
        // mid-batch (rows before it have already been written in the tx).
        batch[2] = log_event(trace, "TRIPWIRE");

        let result = store.insert_batch(batch);
        assert!(result.is_err(), "a mid-batch failure must surface as Err");
        assert_eq!(
            store.count().unwrap(),
            0,
            "the whole batch must roll back, leaving zero rows"
        );

        // The store must still be usable after the rolled-back batch.
        store.write(|conn| {
            conn.execute_batch("DROP TRIGGER tripwire")?;
            Ok(())
        })
        .unwrap();
        store.insert(&log_event(trace, "after")).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn batch_insert_empty_is_ok() {
        let store = Store::open_in_memory().unwrap();
        store.insert_batch(Vec::new()).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn trace_returns_oldest_first() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let mut a = log_event(trace, "first");
        a.timestamp = logbook_core::MicrosTimestamp(10);
        let mut b = log_event(trace, "second");
        b.timestamp = logbook_core::MicrosTimestamp(20);
        // Insert out of order.
        store.insert(&b).unwrap();
        store.insert(&a).unwrap();

        let trace_events = store.trace(&trace.to_hex()).unwrap();
        assert_eq!(trace_events.len(), 2);
        assert_eq!(trace_events[0].name, "first", "oldest first");
        assert_eq!(trace_events[1].name, "second");
    }

    #[test]
    fn roundtrip_preserves_domain_blocks() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let ev = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_error("vulnerable dep")
            .with_finding(FindingBlock {
                source: Some("cargo-audit".into()),
                severity: Some(Severity::High),
                rule_id: Some("RUSTSEC-2024-0002".into()),
                ..Default::default()
            })
            .with_console(ConsoleBlock {
                level: Some("error".into()),
                message: Some("boom".into()),
                ..Default::default()
            });
        store.insert(&ev).unwrap();
        let back = store.trace(&trace.to_hex()).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], ev, "stored body should round-trip losslessly");
    }

    #[test]
    fn file_backed_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let trace = TraceId::new();
        {
            let store = Store::open_in_dir(dir.path()).unwrap();
            store.insert(&log_event(trace, "persisted")).unwrap();
            store.shutdown().unwrap();
        }
        // Reopen and confirm the row survived (WAL checkpoint on close).
        let store2 = Store::open_in_dir(dir.path()).unwrap();
        assert_eq!(store2.count().unwrap(), 1);
        let got = store2.trace(&trace.to_hex()).unwrap();
        assert_eq!(got[0].name, "persisted");
    }

    #[test]
    fn file_backed_concurrent_reads_during_writes() {
        // Exercises the read pool alongside the single writer.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let trace = TraceId::new();
        for i in 0..100 {
            store.insert(&log_event(trace, &format!("n{i}"))).unwrap();
        }
        // Spawn several reader threads.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = store.clone();
            let t = trace.to_hex();
            handles.push(std::thread::spawn(move || {
                let n = s.query(&Query::new().trace(t).limit(1000)).unwrap().len();
                assert_eq!(n, 100);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    // ---- JSONL fallback tests ----

    #[test]
    fn jsonl_write_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let trace = TraceId::new();
        let events = vec![
            log_event(trace, "alpha"),
            log_event(trace, "beta").with_status(Status::Ok),
        ];
        {
            let mut w = JsonlWriter::in_dir(dir.path()).unwrap();
            for e in &events {
                w.append(e).unwrap();
            }
        }
        let read = read_jsonl(dir.path().join(JSONL_FILENAME)).unwrap();
        assert_eq!(read, events, "JSONL fallback should round-trip");
    }

    #[test]
    fn jsonl_skips_blank_and_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let trace = TraceId::new();
        let good = log_event(trace, "good");
        let good_line = serde_json::to_string(&good).unwrap();
        // Hand-build a file with a blank line and a malformed line around a good one.
        std::fs::write(
            &path,
            format!("\n{{ not valid json\n{good_line}\n\n"),
        )
        .unwrap();
        let read = read_jsonl(&path).unwrap();
        assert_eq!(read.len(), 1, "only the valid line should be read");
        assert_eq!(read[0].name, "good");
    }

    #[test]
    fn jsonl_missing_file_is_empty_with_opt() {
        let dir = tempfile::tempdir().unwrap();
        let read = read_jsonl_opt(dir.path().join("does-not-exist.jsonl")).unwrap();
        assert!(read.is_empty());
    }

    #[test]
    fn jsonl_append_batch_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let trace = TraceId::new();
        let batch: Vec<Event> = (0..10).map(|i| log_event(trace, &format!("b{i}"))).collect();
        {
            let mut w = JsonlWriter::in_dir(dir.path()).unwrap();
            w.append_batch(&batch).unwrap();
        }
        let read = read_jsonl(dir.path().join(JSONL_FILENAME)).unwrap();
        assert_eq!(read.len(), 10);
        assert_eq!(read, batch);
    }
}
