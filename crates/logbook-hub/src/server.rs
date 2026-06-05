//! The hub axum server: the fleet **receiver** + the **governance plane** (plan
//! "Phase 4 — Complete Tier & Fleet" → Hub).
//!
//! Bound to `127.0.0.1` (loopback only, like the collector — plan §9), bearer-
//! gated by a [`HubToken`], exposing:
//!
//! | Route | Method | Auth | Purpose |
//! |---|---|---|---|
//! | `/health` | GET | public | liveness, no secret |
//! | `/hub/ingest` | POST | bearer | receive a forwarded event batch from an endpoint |
//! | `/hub/verify` | GET | bearer | run the hash-chain tamper check ([`verify_chain`]) |
//! | `/hub/events` | GET | bearer | RBAC read (Viewer → export projection, Auditor → full) |
//! | `/hub/inventory` | GET | bearer | multi-endpoint inventory roll-up |
//! | `/hub/prune` | POST | bearer | endpoint-triggered retention sweep ([`Store::prune`]) |
//!
//! ## Receive + audit (the headline path)
//!
//! `POST /hub/ingest` takes `{endpoint_id, events:[…]}` (a batch of
//! already-redacted events forwarded from a local plane) and, in order:
//! 1. persists them via [`Store::hub_receive`] — `INSERT OR IGNORE` by id, so a
//!    re-sent batch is **idempotent** and never overwrites the local copy;
//! 2. appends **each newly-received event** to the tamper-evident hash chain via
//!    [`append_audit`], so the stored archive is integrity-protected.
//!
//! Only events that were *newly* inserted (not idempotent duplicates) are
//! appended to the chain — re-receiving a batch must not grow the chain or
//! double-audit a row.
//!
//! ## Redaction-before-persistence
//!
//! The hub is a **receiver of already-redacted records**: redaction is the
//! origin plane's job and happens at capture, before forwarding. The hub never
//! sees a raw provider payload (that is exclusively the LLM proxy's concern) and
//! persists what it receives as-is. The RBAC Viewer projection is an additional
//! *export-sensitivity* gate on reads, not a substitute for capture-time
//! redaction.
//!
//! ## Server-side retention
//!
//! A periodic background sweep runs [`Store::prune`] at a configurable interval,
//! and `POST /hub/prune` triggers the same sweep on demand (plan: "server-side
//! retention (`Store::prune`) … a periodic/endpoint-triggered sweep").

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_http::cors::{AllowOrigin, CorsLayer};

use logbook_core::{CapturePolicy, Event, MicrosTimestamp};
use logbook_store::Store;

use crate::error::HubError;
use crate::rbac::{project_for_role, Role};
use crate::rollup::fleet_rollup;
use crate::token::{HubToken, TokenMode};

/// Maximum number of ports to try when the preferred one is busy (collector
/// parity).
pub const MAX_PORT_ATTEMPTS: u16 = 64;

/// Default server-side retention sweep interval.
const DEFAULT_PRUNE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Loopback host the hub binds to. Never a public interface (plan §9).
fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Configuration for a hub instance (passed to [`run_hub`]).
#[derive(Clone, Debug)]
pub struct HubConfig {
    /// Bind host. Defaults to `127.0.0.1`; non-loopback hosts are rejected.
    pub host: IpAddr,
    /// Preferred starting port. `0` lets the OS choose (and disables
    /// auto-increment).
    pub port: u16,
    /// Output directory (created if missing; reserved for future state files).
    pub out_dir: PathBuf,
    /// Origin allowed by CORS (scoped, never `*`).
    pub dev_origin: String,
    /// How the hub bearer token is sourced.
    pub token_mode: TokenMode,
    /// The capture policy. Governs the RBAC export projection (which classes a
    /// Viewer may see) and the per-class retention sweep. Defaults to the
    /// recorder-on [`CapturePolicy::default`] (only `model_metadata` exports).
    pub capture_policy: CapturePolicy,
    /// Retention bounds for the server-side prune sweep.
    pub retention: logbook_core::config::Retention,
    /// Interval for the periodic background prune sweep. `None` disables the
    /// periodic sweep (the `/hub/prune` route still works on demand).
    pub prune_interval: Option<Duration>,
}

impl HubConfig {
    /// A config rooted at `out_dir` with loopback host, a generated token, the
    /// given dev origin, recorder-on policy + default retention, and the default
    /// periodic prune interval.
    #[must_use]
    pub fn new(out_dir: impl Into<PathBuf>, dev_origin: impl Into<String>) -> Self {
        Self {
            host: loopback(),
            port: 0,
            out_dir: out_dir.into(),
            dev_origin: dev_origin.into(),
            token_mode: TokenMode::Generated,
            capture_policy: CapturePolicy::default(),
            retention: logbook_core::config::Retention::default(),
            prune_interval: Some(DEFAULT_PRUNE_INTERVAL),
        }
    }

    /// Set the preferred port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the token mode.
    #[must_use]
    pub fn with_token_mode(mut self, mode: TokenMode) -> Self {
        self.token_mode = mode;
        self
    }

    /// Set the capture policy (RBAC projection + retention classes).
    #[must_use]
    pub fn with_capture_policy(mut self, policy: CapturePolicy) -> Self {
        self.capture_policy = policy;
        self
    }

    /// Set the retention bounds for the prune sweep.
    #[must_use]
    pub fn with_retention(mut self, retention: logbook_core::config::Retention) -> Self {
        self.retention = retention;
        self
    }

    /// Set (or clear, with `None`) the periodic prune interval.
    #[must_use]
    pub fn with_prune_interval(mut self, interval: Option<Duration>) -> Self {
        self.prune_interval = interval;
        self
    }
}

/// Shared state handed to the axum handlers.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    token: HubToken,
    policy: Arc<CapturePolicy>,
    /// Retention bounds for the endpoint-triggered `/hub/prune` sweep (the same
    /// value the periodic loop uses, so a manual sweep matches the periodic one).
    retention: Arc<logbook_core::config::Retention>,
    started_at: String,
}

/// A running hub handle: the bound address, the resolved token, and a shutdown
/// trigger. Dropping the handle does **not** stop the server; call
/// [`RunningHub::shutdown`] or await [`RunningHub::join`].
pub struct RunningHub {
    addr: SocketAddr,
    token: HubToken,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningHub {
    /// The socket address the server is bound to.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The bound port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The resolved hub bearer token (`None` when `token_mode = off`).
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_str()
    }

    /// Signal the server to stop and await the server task.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.handle).await;
    }

    /// Await the server task to completion (e.g. after a termination signal).
    pub async fn join(mut self) {
        let _ = (&mut self.handle).await;
    }
}

/// Start the hub: reject non-loopback binds, resolve the token, bind a port,
/// spawn the axum server and the periodic retention sweep. Returns once the
/// socket is bound.
///
/// This is the hub entry point (plan "P4 tests" / "Report the hub entry").
///
/// # Errors
/// Returns [`HubError`] on a non-loopback host, token resolution failure, bind
/// failure, or out-dir creation failure.
pub async fn run_hub(config: HubConfig, store: Store) -> crate::Result<RunningHub> {
    if !config.host.is_loopback() {
        return Err(HubError::NonLoopbackBind(config.host));
    }

    std::fs::create_dir_all(&config.out_dir).map_err(|source| HubError::OutDir {
        path: config.out_dir.clone(),
        source,
    })?;

    let token = HubToken::resolve(config.token_mode)?;

    let listener = bind_with_auto_increment(config.host, config.port).await?;
    let addr = listener.local_addr().map_err(|source| HubError::Bind {
        port: config.port,
        source,
    })?;

    let store = Arc::new(store);
    let policy = Arc::new(config.capture_policy.clone());
    let retention = Arc::new(config.retention.clone());

    let state = AppState {
        store: store.clone(),
        token: token.clone(),
        policy: policy.clone(),
        retention: retention.clone(),
        started_at: now_epoch_micros_tag(),
    };

    let app = build_router(state, &config.dev_origin)?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Periodic server-side retention sweep (plan: "server-side retention
    // (Store::prune)"). The background loop holds a shutdown receiver so it ends
    // with the server; the `/hub/prune` route triggers the same sweep on demand.
    let prune_task = config.prune_interval.map(|interval| {
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        let store = store.clone();
        let policy = policy.clone();
        let retention = config.retention.clone();
        let task = tokio::spawn(prune_loop(store, policy, retention, interval, kill_rx));
        (kill_tx, task)
    });

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            tokio::select! {
                _ = shutdown_rx => {}
                _ = terminate_signal() => {}
            }
        };
        let server = axum::serve(listener, app).with_graceful_shutdown(shutdown);
        if let Err(e) = server.await {
            tracing::error!(error = %e, "hub server error");
        }
        // Stop the prune loop when the server ends.
        if let Some((kill_tx, task)) = prune_task {
            let _ = kill_tx.send(());
            let _ = task.await;
        }
    });

    Ok(RunningHub {
        addr,
        token,
        shutdown_tx: Some(shutdown_tx),
        handle,
    })
}

/// The periodic retention sweep: every `interval`, run [`Store::prune`] against
/// the configured policy + retention, until the kill channel fires.
async fn prune_loop(
    store: Arc<Store>,
    policy: Arc<CapturePolicy>,
    retention: logbook_core::config::Retention,
    interval: Duration,
    mut kill_rx: oneshot::Receiver<()>,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick so startup doesn't prune before any data.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Errors are logged inside `run_prune_once`; a failed periodic
                // sweep must not kill the loop.
                let _ = run_prune_once(&store, &policy, &retention);
            }
            _ = &mut kill_rx => break,
        }
    }
}

/// Run one prune sweep, logging the outcome. Shared by the periodic loop and the
/// `/hub/prune` route.
fn run_prune_once(
    store: &Store,
    policy: &CapturePolicy,
    retention: &logbook_core::config::Retention,
) -> logbook_store::Result<logbook_store::PruneStats> {
    let now = MicrosTimestamp::now().as_micros();
    match store.prune(policy, retention, now) {
        Ok(stats) => {
            tracing::debug!(?stats, "hub retention sweep complete");
            Ok(stats)
        }
        Err(e) => {
            tracing::error!(error = %e, "hub retention sweep failed");
            Err(e)
        }
    }
}

/// Bind a loopback `TcpListener`, auto-incrementing the port on `AddrInUse`
/// (collector parity). `start_port == 0` lets the OS choose (no retry loop).
///
/// # Errors
/// Returns [`HubError::Bind`] if no port in the range could be bound.
pub async fn bind_with_auto_increment(
    host: IpAddr,
    start_port: u16,
) -> crate::Result<TcpListener> {
    if start_port == 0 {
        let addr = SocketAddr::new(host, 0);
        return TcpListener::bind(addr)
            .await
            .map_err(|source| HubError::Bind { port: 0, source });
    }
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..MAX_PORT_ATTEMPTS {
        let port = start_port.saturating_add(attempt);
        let addr = SocketAddr::new(host, port);
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(HubError::Bind { port, source: e }),
        }
    }
    Err(HubError::Bind {
        port: start_port,
        source: last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrInUse, "all ports in range busy")
        }),
    })
}

/// Resolve when the process receives SIGINT or SIGTERM (Unix); Ctrl-C elsewhere.
async fn terminate_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Build the axum router with the scoped CORS layer (collector parity).
fn build_router(state: AppState, dev_origin: &str) -> crate::Result<Router> {
    let origin: axum::http::HeaderValue = dev_origin
        .parse()
        .map_err(|_| HubError::BadOrigin(dev_origin.to_string()))?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([origin]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            ROLE_HEADER,
        ]);

    Ok(Router::new()
        .route("/health", get(health))
        .route("/hub/ingest", post(hub_ingest))
        .route("/hub/verify", get(hub_verify))
        .route("/hub/events", get(hub_events))
        .route("/hub/inventory", get(hub_inventory))
        .route("/hub/prune", post(hub_prune))
        .layer(cors)
        .with_state(state))
}

/// The header an endpoint/operator uses to assert a role on a read
/// (`X-Logbook-Role: viewer|auditor`). Absent/unknown ⇒ the least-privileged
/// [`Role::Viewer`].
const ROLE_HEADER: axum::http::HeaderName =
    axum::http::HeaderName::from_static("x-logbook-role");

type Response = axum::response::Response;

/// `GET /health` — public, no secret.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "logbook-hub",
        "startedAt": state.started_at,
    }))
}

/// The `/hub/ingest` request body: a batch of already-redacted events forwarded
/// from one endpoint.
#[derive(Debug, Deserialize)]
struct IngestBody {
    /// The forwarding endpoint's id (informational/correlation; events carry
    /// their own ids + trace/session, so this is recorded for tracing but is not
    /// required to persist).
    #[serde(default)]
    endpoint_id: Option<String>,
    /// The forwarded events.
    #[serde(default)]
    events: Vec<Event>,
}

/// `POST /hub/ingest` — receive a forwarded batch from an endpoint. Bearer-gated.
///
/// Persists via [`Store::hub_receive`] (idempotent `INSERT OR IGNORE` by id) and
/// appends **each newly-received event** to the hash chain via [`append_audit`].
/// Re-receiving the same ids is a no-op for both (no duplicate rows, no extra
/// chain links). Responds `200` with `{received, audited}` counts.
async fn hub_ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<IngestBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let Json(payload) = match body {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON").into_response(),
    };

    if let Some(ep) = payload.endpoint_id.as_deref() {
        tracing::debug!(endpoint_id = ep, n = payload.events.len(), "hub_ingest batch");
    }

    if payload.events.is_empty() {
        return Json(json!({ "received": 0, "audited": 0 })).into_response();
    }

    // Persist (idempotent) AND audit the newly-inserted rows in one write so the
    // chain reflects exactly what landed. To know WHICH ids are genuinely new
    // (so we audit each exactly once and never re-audit an idempotent duplicate),
    // probe presence per id BEFORE the insert, inside the same writer closure.
    // A within-batch duplicate id is collapsed too (the second copy is already
    // "seen"), so the chain link count matches the row count `hub_receive`
    // reports.
    let events = payload.events.clone();
    let result = state.store.write_returning(move |conn| {
        let mut newly: Vec<Event> = Vec::with_capacity(events.len());
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        {
            let mut exists = conn.prepare_cached("SELECT 1 FROM events WHERE id = ?1")?;
            for ev in &events {
                let id = ev.id.as_str();
                // Skip an id already present in the store or already queued from
                // an earlier copy in this same batch.
                if !seen.insert(id.to_string()) {
                    continue;
                }
                let present: Option<i64> = exists
                    .query_row(rusqlite::params![id], |r| r.get(0))
                    .ok();
                if present.is_none() {
                    newly.push(ev.clone());
                }
            }
        }
        // Idempotent receive (INSERT OR IGNORE by id) — the authoritative count of
        // rows that did not already exist.
        let received = logbook_store::audit::hub_receive(conn, &events)?;
        // Append only the genuinely-new rows to the tamper-evident chain.
        let mut audited = 0usize;
        for ev in &newly {
            logbook_store::audit::append_audit(conn, ev)?;
            audited += 1;
        }
        Ok((received, audited))
    });

    match result {
        Ok((received, audited)) => {
            Json(json!({ "received": received, "audited": audited })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "hub_ingest persist/audit failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `GET /hub/verify` — run the hash-chain tamper check ([`verify_chain`]).
/// Bearer-gated. Responds `200` with the [`AuditVerification`] as JSON
/// (`{ok, checked, first_break}`).
async fn hub_verify(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    match state.store.verify_chain() {
        Ok(v) => Json(json!({
            "ok": v.ok,
            "checked": v.checked,
            "first_break": v.first_break.map(break_to_json),
        }))
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "verify_chain failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `GET /hub/events` — an RBAC-gated event read. Bearer-gated, then the
/// `X-Logbook-Role` header selects the visibility:
/// - `auditor` ⇒ the full already-redacted rows;
/// - `viewer` (default / unknown) ⇒ the per-class export projection (no payload
///   classes).
///
/// Supports an optional `?trace=<hex>` filter (a single trace's events) and a
/// `?limit=` cap; otherwise returns the most recent events.
async fn hub_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<EventsQuery>,
) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let role = role_from_headers(&headers);

    let events = if let Some(trace) = params.trace.as_deref() {
        state.store.trace(trace)
    } else {
        let mut q = logbook_store::Query::new();
        if let Some(limit) = params.limit {
            q = q.limit(limit);
        }
        state.store.query(&q)
    };

    match events {
        Ok(events) => {
            let projected = project_for_role(role, &state.policy, events);
            Json(json!({
                "role": role.as_str(),
                "count": projected.len(),
                "events": projected,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "hub_events read failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `GET /hub/inventory` — the multi-endpoint inventory roll-up
/// ([`fleet_rollup`]). Bearer-gated. The roll-up is structural inventory metadata
/// (endpoint/agent/MCP/session counts), not payload, so it is the same for any
/// role.
async fn hub_inventory(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    match fleet_rollup(&state.store) {
        Ok(roll) => Json(roll).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "fleet_rollup failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `POST /hub/prune` — trigger the server-side retention sweep on demand
/// ([`Store::prune`]). Bearer-gated. Responds `200` with the prune stats.
async fn hub_prune(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    // Use the hub's configured retention (the same value the periodic loop
    // owns), so an endpoint-triggered sweep matches the periodic one.
    match run_prune_once(&state.store, &state.policy, &state.retention) {
        Ok(stats) => Json(json!({
            "ok": true,
            "events_by_age": stats.events_by_age,
            "events_by_size": stats.events_by_size,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "hub_prune failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// The `/hub/events` query string.
#[derive(Debug, Deserialize)]
struct EventsQuery {
    /// Optional 32-hex trace id filter.
    #[serde(default)]
    trace: Option<String>,
    /// Optional result cap.
    #[serde(default)]
    limit: Option<u32>,
}

/// Read the asserted [`Role`] from `X-Logbook-Role` (absent/unknown ⇒
/// least-privileged [`Role::Viewer`]).
fn role_from_headers(headers: &HeaderMap) -> Role {
    headers
        .get(ROLE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(Role::parse)
        .unwrap_or_default()
}

/// Render an [`AuditBreak`](logbook_store::AuditBreak) as JSON for `/hub/verify`.
fn break_to_json(brk: logbook_store::AuditBreak) -> Value {
    use logbook_store::BreakReason;
    let reason = match brk.reason {
        BreakReason::PrevHashMismatch {
            stored_prev,
            expected_prev,
        } => json!({
            "kind": "prev_hash_mismatch",
            "stored_prev": stored_prev,
            "expected_prev": expected_prev,
        }),
        BreakReason::MissingEvent { event_id } => json!({
            "kind": "missing_event",
            "event_id": event_id,
        }),
        BreakReason::RowHashMismatch { stored, recomputed } => json!({
            "kind": "row_hash_mismatch",
            "stored": stored,
            "recomputed": recomputed,
        }),
    };
    json!({ "seq": brk.seq, "event_id": brk.event_id, "reason": reason })
}

/// Bearer check (collector parity). With `token_mode = off` the token is `None`
/// and every request is allowed (dev/test only).
fn authorize(expected: &HubToken, headers: &HeaderMap) -> bool {
    let Some(want) = expected.as_str() else {
        return true; // token disabled (dev/test only)
    };
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(got) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return false;
    };
    constant_time_eq(got.trim().as_bytes(), want.as_bytes())
}

/// Length-checked constant-time byte comparison (avoids early-exit timing leak).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Epoch-microseconds string tagged with `us` (collector parity; opaque
/// instant).
fn now_epoch_micros_tag() -> String {
    format!("{}us", MicrosTimestamp::now().as_micros())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn authorize_requires_matching_bearer() {
        let token = HubToken::from_secret("s3cr3t-hub-token");
        let mut headers = HeaderMap::new();
        assert!(!authorize(&token, &headers), "missing header must fail");
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(!authorize(&token, &headers), "wrong token must fail");
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cr3t-hub-token"),
        );
        assert!(authorize(&token, &headers), "correct token must pass");
    }

    #[test]
    fn authorize_allows_when_token_disabled() {
        let token = HubToken::disabled();
        assert!(authorize(&token, &HeaderMap::new()), "off mode allows all");
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn role_header_defaults_to_viewer() {
        let mut headers = HeaderMap::new();
        assert_eq!(role_from_headers(&headers), Role::Viewer);
        headers.insert(ROLE_HEADER, HeaderValue::from_static("auditor"));
        assert_eq!(role_from_headers(&headers), Role::Auditor);
        headers.insert(ROLE_HEADER, HeaderValue::from_static("nonsense"));
        assert_eq!(role_from_headers(&headers), Role::Viewer, "unknown ⇒ viewer");
    }
}
