//! Tier 1 (passive) evidence collection (plan §6).
//!
//! The passive tier is the **default** and the only fully reliable tier: it
//! never touches the target process or its source. It simply re-reads what the
//! capture pipeline, collector, and security scanners have **already** written
//! to the store, scoped to a time window and (optionally) a `session_id`, and
//! buckets it into a shape an agent can reason about: logs, console messages,
//! network requests, errors, and findings.

use logbook_core::{Category, Event, Kind, Status};
use logbook_store::{Query, Store};
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A filter describing *which* already-captured signals to pull for an
/// investigation. All fields are optional; unset fields widen the query.
#[derive(Clone, Debug, Default)]
pub struct EvidenceFilter {
    /// Inclusive lower bound on event timestamp (microseconds since epoch).
    pub since_micros: Option<i64>,
    /// Inclusive upper bound on event timestamp (microseconds since epoch).
    pub until_micros: Option<i64>,
    /// Restrict to events tagged with this session id (e.g. the debug session,
    /// or a captured run/agent session).
    pub session_id: Option<String>,
    /// Restrict to a single correlated trace id (hex).
    pub trace_id: Option<String>,
    /// Optional full-text search (FTS5 MATCH syntax) — handy for honing on an
    /// error message the human just reproduced.
    pub text: Option<String>,
    /// Cap on the number of rows pulled (defaults to [`EvidenceFilter::DEFAULT_LIMIT`]).
    pub limit: Option<u32>,
}

impl EvidenceFilter {
    /// Default cap on rows pulled for a single evidence fetch.
    pub const DEFAULT_LIMIT: u32 = 2000;

    /// An empty filter (no constraints).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Constrain to a `[since, until]` time window (microseconds).
    #[must_use]
    pub fn window(mut self, since: i64, until: i64) -> Self {
        self.since_micros = Some(since);
        self.until_micros = Some(until);
        self
    }

    /// Constrain to a session id.
    #[must_use]
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Constrain to a trace id.
    #[must_use]
    pub fn trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Add a full-text search constraint.
    #[must_use]
    pub fn search(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Override the row cap.
    #[must_use]
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Compile this filter into a store [`Query`] (oldest-first, so the bucketed
    /// evidence reads in timeline order).
    fn to_query(&self) -> Query {
        let mut q = Query::new().oldest_first();
        if let (Some(since), Some(until)) = (self.since_micros, self.until_micros) {
            q = q.time_range(since, until);
        }
        if let Some(s) = &self.session_id {
            q = q.session(s.clone());
        }
        if let Some(t) = &self.trace_id {
            q = q.trace(t.clone());
        }
        if let Some(text) = &self.text {
            q = q.search(text.clone());
        }
        q.limit(self.limit.unwrap_or(Self::DEFAULT_LIMIT))
    }
}

/// A bundle of passive evidence, bucketed by lane for agent consumption.
///
/// Buckets are not mutually exclusive in spirit but are here: each source
/// event lands in exactly one bucket (errors are pulled out first, then by
/// kind/category), so the totals add up to [`Evidence::total`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Application / process log lines (`category=app_log`, `kind=log`).
    pub logs: Vec<Event>,
    /// Browser/console messages (`category=browser`, `kind=browser`/console).
    pub console: Vec<Event>,
    /// Network requests/responses (`kind=network` or browser network).
    pub network: Vec<Event>,
    /// Security / inventory findings (`kind=finding`).
    pub findings: Vec<Event>,
    /// Anything with `status=error` (across lanes), surfaced for quick triage.
    pub errors: Vec<Event>,
    /// Events that did not fit the buckets above.
    pub other: Vec<Event>,
}

impl Evidence {
    /// Total number of events across all buckets.
    #[must_use]
    pub fn total(&self) -> usize {
        self.logs.len()
            + self.console.len()
            + self.network.len()
            + self.findings.len()
            + self.errors.len()
            + self.other.len()
    }

    /// Whether any evidence was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Bucket a flat, ordered list of events into an [`Evidence`] bundle. Errors
    /// are extracted first so a failing log line is always visible under
    /// `errors` rather than buried among ordinary logs.
    #[must_use]
    pub fn from_events(events: Vec<Event>) -> Self {
        let mut ev = Evidence::default();
        for e in events {
            if e.status == Status::Error || e.error.is_some() {
                ev.errors.push(e);
            } else if is_network(&e) {
                // Network first: a browser network event carries category=browser
                // but belongs in the network bucket, not console.
                ev.network.push(e);
            } else if e.kind == Kind::Browser || e.category == Category::Browser {
                ev.console.push(e);
            } else if e.kind == Kind::Finding
                || e.category == Category::Security
                || e.category == Category::Inventory
            {
                ev.findings.push(e);
            } else if e.kind == Kind::Log || e.category == Category::AppLog {
                ev.logs.push(e);
            } else {
                ev.other.push(e);
            }
        }
        ev
    }
}

/// Whether an event carries network details (used to disambiguate browser
/// console vs browser network events, which share `category=browser`).
fn is_network(e: &Event) -> bool {
    e.kind == Kind::Network || e.blocks.network.is_some()
}

/// Run a Tier-1 passive query against the store and bucket the result.
///
/// This is the heart of `debug_fetch_evidence`: no process is touched, no
/// source is edited — it reads back already-captured signals.
///
/// # Errors
/// Returns a [`crate::DebugError::Store`] if the read fails.
pub fn collect(store: &Store, filter: &EvidenceFilter) -> Result<Evidence> {
    let events = store.query(&filter.to_query())?;
    Ok(Evidence::from_events(events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{ConsoleBlock, FindingBlock, NetworkBlock, Severity, TraceId};

    fn log(trace: TraceId, name: &str) -> Event {
        Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name(name)
    }

    #[test]
    fn buckets_by_kind_and_category() {
        let t = TraceId::new();
        let events = vec![
            log(t, "build ok"),
            Event::new(t, Kind::Browser, Category::Browser, "console").with_console(ConsoleBlock {
                level: Some("warn".into()),
                message: Some("deprecated".into()),
                ..Default::default()
            }),
            Event::new(t, Kind::Network, Category::Browser, "fetch").with_network(NetworkBlock {
                method: Some("GET".into()),
                url: Some("https://x.test".into()),
                status_code: Some(200),
                ..Default::default()
            }),
            Event::new(t, Kind::Finding, Category::Security, "advisory").with_finding(
                FindingBlock {
                    source: Some("semgrep".into()),
                    severity: Some(Severity::High),
                    ..Default::default()
                },
            ),
        ];
        let ev = Evidence::from_events(events);
        assert_eq!(ev.logs.len(), 1);
        assert_eq!(ev.console.len(), 1);
        assert_eq!(ev.network.len(), 1);
        assert_eq!(ev.findings.len(), 1);
        assert_eq!(ev.errors.len(), 0);
        assert_eq!(ev.total(), 4);
    }

    #[test]
    fn errors_extracted_first() {
        let t = TraceId::new();
        let mut boom = log(t, "panic at the disco");
        boom = boom.with_error("thread panicked");
        let ev = Evidence::from_events(vec![log(t, "fine"), boom]);
        assert_eq!(ev.logs.len(), 1);
        assert_eq!(ev.errors.len(), 1);
        assert!(ev.errors[0].error.is_some());
    }
}
