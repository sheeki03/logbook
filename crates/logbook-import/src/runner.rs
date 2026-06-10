//! The import seam: drive a [`SessionSource`] → adapter → [`ImportBatch`].
//!
//! This is intentionally minimal. It expresses the *shape* of an import without
//! baking in adapter dispatch, because the adapter needs a `HarnessContext`
//! (which is not `Clone` and whose redaction policy the CLI owns). So the
//! event-building step is injected as a `build_events` closure: Wave 2 supplies
//! one wired to the Cursor harness adapter and a freshly-minted `HarnessContext`
//! per session, while this crate stays free of any redaction-policy or
//! persistence concerns.
//!
//! The flow is: [`SessionSource::read`] the session's raw records → run
//! `build_events` (the adapter) → package the redacted [`Event`]s and the
//! [`ImportSessionHeader`] into an [`ImportBatch`]. A read failure becomes an
//! `Err(ReadError)`; the caller (the CLI) turns that into a [`Diag`] and skips
//! the session. **Nothing here persists** — the CLI is the sole persister.

use logbook_core::Event;

use crate::{Diag, DiscoveredSession, ImportBatch, ImportSessionHeader, ReadError, SessionSource, SessionRecords};

/// Read one `session` from `source` and build its [`ImportBatch`].
///
/// `build_events` is the adapter seam: it receives the raw [`SessionRecords`]
/// and returns the redacted [`Event`]s plus the deterministic
/// [`ImportSessionHeader`] for the session. Wave 2 passes a closure that mints a
/// fresh `HarnessContext` and runs the per-tool harness adapter; Wave 1 callers
/// (and tests) can pass any closure that honours the determinism contract.
///
/// # Errors
/// Returns the [`ReadError`] from [`SessionSource::read`] when the source store
/// cannot be read (lock, corruption, permission, unsupported). The caller should
/// emit a [`Diag`] and continue with the next session.
pub fn import_session(
    source: &dyn SessionSource,
    session: &DiscoveredSession,
    build_events: &dyn Fn(&SessionRecords) -> (Vec<Event>, ImportSessionHeader),
) -> Result<ImportBatch, ReadError> {
    let records = source.read(session)?;
    let (events, header) = build_events(&records);
    Ok(ImportBatch {
        header,
        events,
        // The runner itself adds no diagnostics; read-level problems are carried
        // by the `Err` path, and adapter-level shape drift is tolerated (empty
        // events) inside `build_events`. The CLI may append its own.
        diagnostics: Vec::<Diag>::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataRoots, SessionLocator};
    use logbook_core::{Category, Kind, MicrosTimestamp, TraceId};
    use std::path::PathBuf;

    /// A test source that returns canned records (no real IO).
    struct CannedSource;

    impl SessionSource for CannedSource {
        fn tool(&self) -> &str {
            "canned"
        }
        fn discover(&self, _roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
            (Vec::new(), Vec::new())
        }
        fn read(&self, session: &DiscoveredSession) -> Result<SessionRecords, ReadError> {
            Ok(SessionRecords {
                native_id: session.native_id.clone(),
                records: vec![serde_json::json!({"role": "user", "text": "hi"})],
                session_meta: serde_json::json!({}),
            })
        }
    }

    fn probe_session() -> DiscoveredSession {
        DiscoveredSession {
            tool: "canned".into(),
            native_id: "n1".into(),
            import_id: "fp:n1".into(),
            origin: PathBuf::from("/tmp/store"),
            locator: SessionLocator::Key("n1".into()),
            title: None,
            last_active: None,
            mtime: MicrosTimestamp(42),
            approx_messages: Some(1),
            workspace: None,
        }
    }

    #[test]
    fn import_session_runs_build_events_and_packages_batch() {
        let source = CannedSource;
        let session = probe_session();
        let trace = TraceId::from_bytes([7u8; 16]);
        let build = move |recs: &SessionRecords| {
            // Trivially derive one event per record (Wave 2 uses the adapter).
            let events: Vec<Event> = recs
                .records
                .iter()
                .map(|_| Event::new(trace, Kind::Agent, Category::AppLog, "user"))
                .collect();
            let header = ImportSessionHeader {
                session_id: "sid".into(),
                trace_id: trace.to_hex(),
                agent: "canned".into(),
                command: "import:canned".into(),
                started_at: 42,
                ended_at: Some(42),
            };
            (events, header)
        };

        let batch = import_session(&source, &session, &build).unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.header.session_id, "sid");
        assert_eq!(batch.header.agent, "canned");
        assert!(batch.diagnostics.is_empty());
    }

    /// A source whose read always fails, to prove the error path surfaces.
    struct FailingSource;
    impl SessionSource for FailingSource {
        fn tool(&self) -> &str {
            "failing"
        }
        fn discover(&self, _roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
            (Vec::new(), Vec::new())
        }
        fn read(&self, _session: &DiscoveredSession) -> Result<SessionRecords, ReadError> {
            Err(ReadError::Unsupported {
                tool: "failing".into(),
            })
        }
    }

    #[test]
    fn import_session_propagates_read_error() {
        let build =
            |_: &SessionRecords| -> (Vec<Event>, ImportSessionHeader) { unreachable!() };
        let err = import_session(&FailingSource, &probe_session(), &build).unwrap_err();
        assert!(matches!(err, ReadError::Unsupported { .. }));
    }
}
