//! `logbook-debug` — non-invasive debug mode (plan §6).
//!
//! Debugging an agent-built program by **guessing** is the failure mode this
//! crate exists to kill. Instead of editing source to add prints, a debug
//! session gives the agent **real runtime evidence** in two tiers, neither of
//! which mutates the program's source:
//!
//! 1. **Tier 1 — passive (default, reliable).** Query already-captured
//!    logs / console / network from the [`Store`] by time window and
//!    `session_id`. Nothing is attached to the running process; this just reads
//!    back what the capture pipeline and collector already wrote.
//!    See [`evidence`].
//! 2. **Tier 2 — DAP logpoints (alpha).** Connect to a *running* process's
//!    debug adapter and set a **logpoint** — log an expression at `file:line`
//!    **without stopping** and **without editing source** — then ingest the
//!    emitted values as [`Event`](logbook_core::Event)s. See [`dap`].
//!
//! Source-instrumentation (writing markers into files) is **explicitly not
//! implemented** here; the plan defers it as an approval-gated fallback.
//!
//! ## Session API
//! The lifecycle is owned by [`DebugSession`], persisted in the store's
//! `debug_sessions` table (plan §2):
//!
//! - [`DebugSession::start_session`] — open a session (`passive` or `dap`).
//! - [`DebugSession::request_repro`] — record the human-reproduction marker and
//!   stamp the window start so a later fetch can scope to "since repro".
//! - [`DebugSession::fetch_evidence`] — run a Tier-1 passive query and bucket
//!   the result; flips the session to `fetched`.
//! - [`DebugSession::end_session`] — detach **all** logpoints / tracing and mark
//!   the session `ended`. After this, `git status --porcelain` is unchanged:
//!   the session never wrote to any source file.
//!
//! ## Non-invasiveness guarantee
//! No method in this crate writes to a source file. Tier 1 only reads the
//! store. Tier 2 sets DAP logpoints (a runtime-only construct) and clears them
//! on [`DebugSession::end_session`]. This is asserted directly by the
//! `git status` test in `tests/`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dap;
pub mod error;
pub mod evidence;
pub mod session;

use std::sync::Arc;

use logbook_core::{Event, MicrosTimestamp, Redactor, SessionId, TraceId};
use logbook_store::Store;

pub use dap::{ChannelSink, DapClient, EventSink, Logpoint};
pub use error::{DebugError, Result};
pub use evidence::{collect as collect_evidence, Evidence, EvidenceFilter};
pub use session::{
    list_sessions, DebugMode, DebugSessionRecord, DebugStatus,
};

use session::{insert_session, new_record, require_session, set_status};

/// A live, non-invasive debug session.
///
/// Holds a [`Store`] handle plus the in-memory state for the session (its id,
/// correlated trace, mode, an optional repro-window start, and any attached DAP
/// client). Lifecycle transitions are mirrored into the `debug_sessions` table.
pub struct DebugSession {
    store: Store,
    record: DebugSessionRecord,
    trace: TraceId,
    redactor: Arc<Redactor>,
    /// The DAP client, present only once logpoints have been attached in
    /// `dap` mode.
    dap: Option<Arc<DapClient>>,
    /// Microsecond timestamp recorded by [`DebugSession::request_repro`]; used
    /// as the default lower bound for a subsequent evidence fetch.
    repro_since: Option<i64>,
}

impl DebugSession {
    /// Start a new debug session against `store` in the given [`DebugMode`].
    ///
    /// A fresh correlated [`TraceId`] is minted (so any DAP-ingested evidence
    /// can be found by trace as well as by session). `target` is a free-form
    /// description (process name, `file:line`, adapter address) for the UI. The
    /// row is persisted as `active`.
    ///
    /// Redaction is **on by default** ([`Redactor::new`] seeded with the
    /// process environment's secret-looking variables); logged DAP values are
    /// scrubbed before they touch the store.
    ///
    /// # Errors
    /// Returns [`DebugError::Store`] if the session row cannot be written.
    pub fn start_session(
        store: &Store,
        mode: DebugMode,
        target: Option<String>,
    ) -> Result<Self> {
        Self::start_session_with_redactor(
            store,
            mode,
            target,
            Arc::new(Redactor::new().with_process_env()),
        )
    }

    /// Like [`DebugSession::start_session`] but with a caller-supplied
    /// [`Redactor`] (e.g. one built from `logbook.toml`'s `[redaction]`
    /// section, or [`Redactor::disabled`] for `--no-redact`).
    ///
    /// # Errors
    /// Returns [`DebugError::Store`] if the session row cannot be written.
    pub fn start_session_with_redactor(
        store: &Store,
        mode: DebugMode,
        target: Option<String>,
        redactor: Arc<Redactor>,
    ) -> Result<Self> {
        let trace = TraceId::new();
        let record = new_record(mode, trace, target);
        insert_session(store, &record)?;
        tracing::info!(
            session = %record.id,
            mode = mode.as_str(),
            "debug session started"
        );
        Ok(Self {
            store: store.clone(),
            record,
            trace,
            redactor,
            dap: None,
            repro_since: None,
        })
    }

    /// The session id.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.record.id
    }

    /// The correlated trace id for this session.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace
    }

    /// The session mode.
    #[must_use]
    pub fn mode(&self) -> DebugMode {
        self.record.mode
    }

    /// The persisted record (status reflects the last committed transition).
    #[must_use]
    pub fn record(&self) -> &DebugSessionRecord {
        &self.record
    }

    /// Record that the human is about to reproduce the problem.
    ///
    /// Stamps a window-start timestamp (used as the default lower bound for the
    /// next [`DebugSession::fetch_evidence`]) and emits a marker
    /// [`Event`](logbook_core::Event) on the session's trace so the repro point
    /// shows up on the timeline. Non-invasive: writes only to the event store.
    ///
    /// # Errors
    /// Returns [`DebugError::UnknownSession`] if the session is gone, or
    /// [`DebugError::Store`] on a write failure.
    pub fn request_repro(&mut self, note: Option<&str>) -> Result<()> {
        // Confirm the session still exists / isn't ended.
        let current = require_session(&self.store, &self.record.id)?;
        if current.is_ended() {
            return Err(DebugError::WrongState {
                id: self.record.id.as_str().to_string(),
                actual: DebugStatus::Ended.as_str().to_string(),
                expected: "active or fetched".to_string(),
            });
        }
        let now = MicrosTimestamp::now().as_micros();
        self.repro_since = Some(now);

        let mut marker = Event::new(
            self.trace,
            logbook_core::Kind::Span,
            logbook_core::Category::AppLog,
            "debug.repro_requested",
        )
        .with_op("repro")
        .with_name("reproduction requested")
        .with_session(self.record.id.clone());
        if let Some(n) = note {
            marker = marker.with_attr("note", self.redactor.redact(n).into_owned());
        }
        self.store.insert(&marker)?;
        Ok(())
    }

    /// Fetch Tier-1 passive evidence for this session.
    ///
    /// If `filter` constrains nothing, it is widened to "this session, since the
    /// last [`DebugSession::request_repro`] (if any)". The session is flipped to
    /// `fetched`. **Reads only** — no process or source is touched.
    ///
    /// # Errors
    /// Returns [`DebugError::Store`] on a read/write failure.
    pub fn fetch_evidence(&mut self, filter: Option<EvidenceFilter>) -> Result<Evidence> {
        let mut filter = filter.unwrap_or_default();
        // Default scope: this session, since repro.
        if filter.session_id.is_none() && filter.trace_id.is_none() {
            filter.session_id = Some(self.record.id.as_str().to_string());
        }
        if filter.since_micros.is_none() {
            filter.since_micros = self.repro_since;
            // Pair an open lower bound with "now" so the window is well-formed.
            if filter.since_micros.is_some() && filter.until_micros.is_none() {
                filter.until_micros = Some(MicrosTimestamp::now().as_micros());
            }
        }

        let evidence = evidence::collect(&self.store, &filter)?;

        // Transition to `fetched` (only from active; idempotent otherwise).
        if self.record.status == DebugStatus::Active {
            set_status(&self.store, &self.record.id, DebugStatus::Fetched, None)?;
            self.record.status = DebugStatus::Fetched;
        }
        Ok(evidence)
    }

    /// Attach a DAP client (alpha). The session must have been started in
    /// [`DebugMode::Dap`]. Output ingested by the client is written to the store
    /// on this session's trace via a store-backed [`EventSink`].
    ///
    /// Returns a shared handle to the client so the caller can drive the
    /// handshake and set logpoints; the same handle is retained internally so
    /// [`DebugSession::end_session`] can detach.
    ///
    /// # Errors
    /// Returns [`DebugError::NotDapMode`] if the session is not in DAP mode.
    pub fn attach_dap(&mut self, client: DapClient) -> Result<Arc<DapClient>> {
        if self.record.mode != DebugMode::Dap {
            return Err(DebugError::NotDapMode(self.record.id.as_str().to_string()));
        }
        let client = Arc::new(client);
        self.dap = Some(Arc::clone(&client));
        Ok(client)
    }

    /// Build a store-backed [`EventSink`] for this session: ingested DAP output
    /// is persisted as events on the store. Hand this to
    /// [`DapClient::from_transport`] / [`DapClient::connect_tcp`].
    #[must_use]
    pub fn store_sink(&self) -> Arc<dyn EventSink> {
        Arc::new(StoreSink {
            store: self.store.clone(),
        })
    }

    /// The redactor this session uses (clone of the `Arc`).
    #[must_use]
    pub fn redactor(&self) -> Arc<Redactor> {
        Arc::clone(&self.redactor)
    }

    /// End the session: **detach all logpoints / tracing** and mark it `ended`.
    ///
    /// If a DAP client is attached, this calls [`DapClient::disconnect`] (which
    /// clears every installed logpoint and disconnects). It is the explicit
    /// guarantee point that the session leaves the program — and its source —
    /// exactly as it found them.
    ///
    /// # Errors
    /// Returns [`DebugError::Store`] if the status update fails.
    pub async fn end_session(&mut self) -> Result<()> {
        if let Some(dap) = self.dap.take() {
            dap.disconnect().await;
        }
        let now = MicrosTimestamp::now().as_micros();
        set_status(&self.store, &self.record.id, DebugStatus::Ended, Some(now))?;
        self.record.status = DebugStatus::Ended;
        self.record.ended_at = Some(now);
        tracing::info!(session = %self.record.id, "debug session ended; logpoints detached");
        Ok(())
    }
}

/// A store-backed [`EventSink`]: persists each ingested DAP-output event.
struct StoreSink {
    store: Store,
}

impl EventSink for StoreSink {
    fn emit(&self, event: Event) {
        if let Err(e) = self.store.insert(&event) {
            tracing::warn!(error = %e, "dap: failed to persist ingested logpoint event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_persists_active_session_row() {
        let store = Store::open_in_memory().unwrap();
        let sess = DebugSession::start_session(&store, DebugMode::Passive, Some("svc".into()))
            .unwrap();
        let id = sess.id().clone();

        let rows = list_sessions(&store).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].status, DebugStatus::Active);
        assert_eq!(rows[0].mode, DebugMode::Passive);
        assert_eq!(rows[0].target.as_deref(), Some("svc"));
        assert!(rows[0].ended_at.is_none());
    }

    #[test]
    fn fetch_evidence_buckets_session_events_and_marks_fetched() {
        let store = Store::open_in_memory().unwrap();
        let mut sess =
            DebugSession::start_session(&store, DebugMode::Passive, None).unwrap();
        let sid = sess.id().clone();
        let trace = sess.trace_id();

        // Plant some captured evidence tagged with this session.
        store
            .insert(
                &Event::new(trace, logbook_core::Kind::Log, logbook_core::Category::AppLog, "stdout")
                    .with_name("listening on 8080")
                    .with_session(sid.clone()),
            )
            .unwrap();
        store
            .insert(
                &Event::new(trace, logbook_core::Kind::Log, logbook_core::Category::AppLog, "stderr")
                    .with_name("boom")
                    .with_error("panic")
                    .with_session(sid.clone()),
            )
            .unwrap();

        let ev = sess.fetch_evidence(None).unwrap();
        assert_eq!(ev.logs.len(), 1);
        assert_eq!(ev.errors.len(), 1);
        assert_eq!(sess.record().status, DebugStatus::Fetched);

        // Persisted status reflects the transition.
        let rows = list_sessions(&store).unwrap();
        assert_eq!(rows[0].status, DebugStatus::Fetched);
    }

    #[tokio::test]
    async fn end_session_marks_ended_without_dap() {
        let store = Store::open_in_memory().unwrap();
        let mut sess =
            DebugSession::start_session(&store, DebugMode::Passive, None).unwrap();
        sess.end_session().await.unwrap();
        assert_eq!(sess.record().status, DebugStatus::Ended);
        assert!(sess.record().ended_at.is_some());

        let rows = list_sessions(&store).unwrap();
        assert_eq!(rows[0].status, DebugStatus::Ended);
        assert!(rows[0].ended_at.is_some());
    }

    #[test]
    fn request_repro_emits_marker_and_sets_window() {
        let store = Store::open_in_memory().unwrap();
        let mut sess =
            DebugSession::start_session(&store, DebugMode::Passive, None).unwrap();
        sess.request_repro(Some("click submit")).unwrap();
        assert!(sess.repro_since.is_some());

        // The marker is on the session's trace.
        let trace = sess.trace_id();
        let events = store.trace(&trace.to_hex()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].type_, "debug.repro_requested");
    }

    #[tokio::test]
    async fn attach_dap_rejected_in_passive_mode() {
        // We can't easily build a DapClient without a transport here, so just
        // assert the mode gate via a fresh passive session and the error type
        // path: build a dummy client over an in-memory duplex. (Constructing a
        // DapClient spawns its read task, so this needs a tokio runtime.)
        let store = Store::open_in_memory().unwrap();
        let mut sess =
            DebugSession::start_session(&store, DebugMode::Passive, None).unwrap();
        let (a, _b) = tokio::io::duplex(64);
        let (sink, _rx) = ChannelSink::new();
        let client = DapClient::from_transport(
            Box::new(a),
            sess.trace_id(),
            sess.id().clone(),
            Arc::new(sink),
            Arc::new(Redactor::disabled()),
        );
        let err = sess.attach_dap(client).unwrap_err();
        assert!(matches!(err, DebugError::NotDapMode(_)));
    }
}
