//! JSON API handlers (plan §1, §Phase 3): `/api/events`, `/api/timeline`,
//! `/api/inventory`, `/api/findings`, `/api/sessions[/:id[/tree]]`.
//!
//! All are read-only queries over [`logbook_store`]. Events are returned in an
//! `{ "events": [...] }` envelope (matching the front-end `EventPage` type);
//! `/api/events` is newest-first (a feed), `/api/timeline` is oldest-first
//! (reading order). The inventory endpoint returns the full five-tab snapshot.
//! `/api/findings` is the Phase-3 Risk feed (security findings, newest-first,
//! optionally filtered to a minimum severity); `/api/sessions/:id/tree` is the
//! Phase-3 correlation timeline (a session's events grouped by turn).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use logbook_core::{Category, Event, Severity};
use logbook_store::Query as StoreQuery;

use crate::inventory::{self, InventorySnapshot};
use crate::sessions::{self, SessionDetail, SessionSummary, SessionTreeView};
use crate::state::AppState;

/// Default row cap for event queries when the client does not specify one.
const DEFAULT_LIMIT: u32 = 500;
/// Hard upper bound to keep a single response bounded.
const MAX_LIMIT: u32 = 5000;

/// Query-string filters accepted by `/api/events` and `/api/timeline`.
#[derive(Debug, Default, Deserialize)]
pub struct EventParams {
    /// Restrict to a single category lane (`agent`, `browser`, …).
    pub category: Option<String>,
    /// Restrict to a single trace id (hex).
    pub trace_id: Option<String>,
    /// Restrict to a single session id.
    pub session_id: Option<String>,
    /// Full-text query (FTS5 MATCH syntax).
    pub q: Option<String>,
    /// Row cap (clamped to [`MAX_LIMIT`]).
    pub limit: Option<u32>,
}

/// The `{ "events": [...] }` response envelope.
#[derive(Debug, Serialize)]
pub struct EventPage {
    /// The matched events.
    pub events: Vec<Event>,
}

/// Parse a wire category string into the core [`Category`] enum.
fn parse_category(s: &str) -> Option<Category> {
    match s {
        "agent" => Some(Category::Agent),
        "browser" => Some(Category::Browser),
        "app_log" => Some(Category::AppLog),
        "code_test" => Some(Category::CodeTest),
        "security" => Some(Category::Security),
        "inventory" => Some(Category::Inventory),
        _ => None,
    }
}

/// Build a [`StoreQuery`] from request params, applying the given ordering.
///
/// An unrecognized `category` token is a client error: rather than silently
/// dropping the filter and returning every category (which would mislead a user
/// who believes they are viewing one lane), it is rejected with a 400, matching
/// the strictness of the MCP tool layer's `parse_category`.
fn build_query(params: &EventParams, newest_first: bool) -> Result<StoreQuery, ApiError> {
    let mut q = StoreQuery::new();
    q.newest_first = newest_first;
    if let Some(raw) = params.category.as_deref() {
        let cat = parse_category(raw)
            .ok_or_else(|| ApiError::bad_request(format!("unknown category: {raw}")))?;
        q = q.category(cat);
    }
    if let Some(trace) = &params.trace_id {
        q = q.trace(trace.clone());
    }
    if let Some(session) = &params.session_id {
        q = q.session(session.clone());
    }
    if let Some(text) = &params.q {
        if !text.trim().is_empty() {
            q = q.search(text.clone());
        }
    }
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    Ok(q.limit(limit))
}

/// `GET /api/events` — flat event feed, newest-first, optionally filtered.
pub async fn events(
    State(state): State<AppState>,
    Query(params): Query<EventParams>,
) -> Result<Json<EventPage>, ApiError> {
    let query = build_query(&params, true)?;
    let events = state.store.query(&query)?;
    Ok(Json(EventPage { events }))
}

/// `GET /api/timeline` — events across all categories, oldest-first for reading.
pub async fn timeline(
    State(state): State<AppState>,
    Query(params): Query<EventParams>,
) -> Result<Json<EventPage>, ApiError> {
    let query = build_query(&params, false)?;
    let events = state.store.query(&query)?;
    Ok(Json(EventPage { events }))
}

/// `GET /api/inventory` — the full Endpoint Inventory Lite snapshot.
pub async fn inventory(
    State(state): State<AppState>,
) -> Result<Json<InventorySnapshot>, ApiError> {
    let snapshot = inventory::load_snapshot(&state.store)?;
    Ok(Json(snapshot))
}

/// Query-string filters accepted by `/api/findings`.
#[derive(Debug, Default, Deserialize)]
pub struct FindingParams {
    /// Minimum severity (`info`..`critical`). Findings *below* this rank are
    /// dropped. An unrecognized token is a 400 (mirrors the strictness of the
    /// MCP `list_findings` tool, which also parses via [`Severity::from_wire`]).
    pub severity: Option<String>,
    /// Row cap (clamped to [`MAX_LIMIT`]).
    pub limit: Option<u32>,
}

/// The `{ "findings": [...] }` response envelope for the Risk feed.
#[derive(Debug, Serialize)]
pub struct FindingPage {
    /// The matched finding events, newest-first.
    pub findings: Vec<Event>,
}

/// `GET /api/findings` — security findings (Phase 3 Risk feed), newest-first,
/// optionally filtered to a minimum severity.
///
/// Findings are the [`Category::Security`] events the detect engine emits
/// (`Kind::Finding` carrying a [`FindingBlock`](logbook_core::FindingBlock)).
/// They are read through the same [`StoreQuery`] path as `/api/events` (so the
/// indexes are reused), then post-filtered by severity in Rust: severity lives
/// in the JSON `FindingBlock`, not a column, and ranking here via the core
/// [`Severity`] `Ord` keeps the SQL simple and the ordering stable (newest
/// first). Everything read is already redacted at write time, so it is safe to
/// ship to the browser.
pub async fn findings(
    State(state): State<AppState>,
    Query(params): Query<FindingParams>,
) -> Result<Json<FindingPage>, ApiError> {
    // Parse the floor once, via the canonical core enum; an unknown token is a
    // client error rather than a silently-ignored filter.
    let min_severity: Option<Severity> = match params.severity.as_deref() {
        Some(s) => Some(
            Severity::from_wire(s)
                .ok_or_else(|| ApiError::bad_request(format!("unknown severity: {s}")))?,
        ),
        None => None,
    };
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let query = StoreQuery::new().category(Category::Security).limit(limit);
    let events = state.store.query(&query)?;

    // Min-severity post-filter, comparing against the core ordering (Info < Low
    // < … < Critical). A finding with no severity is conservatively dropped when
    // a floor is set (it cannot be shown to clear the bar).
    let findings = match min_severity {
        None => events,
        Some(min) => events
            .into_iter()
            .filter(|e| {
                e.blocks
                    .finding
                    .as_ref()
                    .and_then(|f| f.severity)
                    .is_some_and(|sev| sev >= min)
            })
            .collect(),
    };
    Ok(Json(FindingPage { findings }))
}

/// The `{ "sessions": [...] }` response envelope for the master list.
#[derive(Debug, Serialize)]
pub struct SessionPage {
    /// The recorded sessions, newest-first.
    pub sessions: Vec<SessionSummary>,
}

/// `GET /api/sessions` — newest-first master list of recorded agent sessions
/// (Orbit plan §1.4), each with its action count and a has-transcript flag.
pub async fn sessions(State(state): State<AppState>) -> Result<Json<SessionPage>, ApiError> {
    let sessions = sessions::list_sessions(&state.store)?;
    Ok(Json(SessionPage { sessions }))
}

/// `GET /api/sessions/:id` — the full replay detail for one session: header,
/// transcript pointers, recorded diffs, and the ordered event stream. A missing
/// session is a `404` (via [`ApiError::not_found`]).
pub async fn session(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<SessionDetail>, ApiError> {
    match sessions::load_session(&state.store, &id)? {
        Some(detail) => Ok(Json(detail)),
        None => Err(ApiError::not_found(format!("no session: {id}"))),
    }
}

/// `GET /api/sessions/:id/tree` — the Phase-3 **correlation timeline** for one
/// session: its events grouped by turn (turns ascending, the turn-less catch-all
/// group last; children oldest-first within each turn). This is the "agent
/// action → diff → command → runtime log → finding" view woven by the shared
/// `session_id`.
///
/// Built via [`Store::session_tree`](logbook_store::Store::session_tree). An
/// unknown session id is **not** a 404 here: `session_tree` returns an empty
/// tree for a session with no events, which is the correct correlation view
/// (nothing to correlate), so the endpoint returns `200` with empty `turns`.
pub async fn session_tree(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<SessionTreeView>, ApiError> {
    let tree = state.store.session_tree(&id)?;
    Ok(Json(SessionTreeView::from(tree)))
}

/// API error wrapper.
///
/// - An internal failure (e.g. a store error, surfaced via `?`) becomes a 500
///   with a short opaque JSON body; the detailed error is logged server-side
///   rather than leaked to the client.
/// - A [`bad_request`](ApiError::bad_request) becomes a 400 whose message *is*
///   echoed to the client, since it describes invalid client input (e.g. an
///   unknown `category` filter) and carries no sensitive internal detail.
#[derive(Debug)]
pub enum ApiError {
    /// Invalid client input → `400 Bad Request`; the message is returned.
    BadRequest(String),
    /// No such resource → `404 Not Found`; the message is returned (it names the
    /// missing id and carries no sensitive detail).
    NotFound(String),
    /// Server-side failure → `500 Internal Server Error`; message is logged only.
    Internal(anyhow::Error),
}

impl ApiError {
    /// Construct a `400 Bad Request` carrying a client-facing message.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    /// Construct a `404 Not Found` carrying a client-facing message.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message })))
                    .into_response()
            }
            ApiError::NotFound(message) => {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": message })))
                    .into_response()
            }
            ApiError::Internal(err) => {
                tracing::error!(error = %err, "ui api error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "internal error" })),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_category_round_trips_all_lanes() {
        for cat in [
            Category::Agent,
            Category::Browser,
            Category::AppLog,
            Category::CodeTest,
            Category::Security,
            Category::Inventory,
        ] {
            assert_eq!(parse_category(cat.as_str()), Some(cat));
        }
        assert_eq!(parse_category("nope"), None);
    }

    #[test]
    fn build_query_clamps_limit_and_sets_order() {
        let params = EventParams {
            limit: Some(99_999),
            ..Default::default()
        };
        let q = build_query(&params, false).expect("no category filter");
        assert_eq!(q.limit, Some(MAX_LIMIT));
        assert!(!q.newest_first);
    }

    #[test]
    fn build_query_default_limit_when_unset() {
        let q = build_query(&EventParams::default(), true).expect("no category filter");
        assert_eq!(q.limit, Some(DEFAULT_LIMIT));
        assert!(q.newest_first);
    }

    #[test]
    fn build_query_ignores_blank_search() {
        let params = EventParams {
            q: Some("   ".to_string()),
            ..Default::default()
        };
        let q = build_query(&params, true).expect("no category filter");
        assert!(q.text.is_none(), "blank FTS query must be dropped");
    }

    #[test]
    fn build_query_applies_filters() {
        let params = EventParams {
            category: Some("security".to_string()),
            trace_id: Some("abc".to_string()),
            session_id: Some("sess-1".to_string()),
            q: Some("boom".to_string()),
            limit: Some(10),
        };
        let q = build_query(&params, true).expect("security is a valid category");
        assert_eq!(q.category, Some(Category::Security));
        assert_eq!(q.trace_id.as_deref(), Some("abc"));
        assert_eq!(q.session_id.as_deref(), Some("sess-1"));
        assert_eq!(q.text.as_deref(), Some("boom"));
        assert_eq!(q.limit, Some(10));
    }

    #[test]
    fn build_query_rejects_unknown_category() {
        let params = EventParams {
            category: Some("securty".to_string()), // typo
            ..Default::default()
        };
        // An unknown category is a 400, not a silently-dropped filter.
        let err = build_query(&params, true).expect_err("unknown category must error");
        match err {
            ApiError::BadRequest(msg) => assert!(
                msg.contains("securty"),
                "message should name the bad token, got {msg}"
            ),
            ApiError::NotFound(m) => panic!("expected BadRequest, got NotFound: {m}"),
            ApiError::Internal(e) => panic!("expected BadRequest, got Internal: {e}"),
        }
    }
}
