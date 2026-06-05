//! The axum collector: `GET /health` (public) + `POST /ingest` (bearer-gated)
//! bound to `127.0.0.1`, with port auto-increment, a parent-PID watchdog, and
//! the v3.2 token-file split (`collector.json` = no secret, `collector.token` =
//! token only, perms `0600`).
//!
//! Ported from OpenLogs `collector.ts` (`[OpenLogs]`) and extended with the
//! per-run ingest token (`[new]`, review #v3.1/#v3.2). Browser events arriving
//! on `/ingest` are redacted via [`logbook_core::Redactor`] and persisted as
//! `Event{category:browser}` through [`logbook_store::Store`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_http::cors::{AllowOrigin, CorsLayer};

use logbook_core::text::truncate_with_ellipsis;
use logbook_core::{
    CapturePolicy, Category, ConsoleBlock, Event, Kind, MicrosTimestamp, Redactor, SensitivityClass,
    SessionId, Status, TraceId,
};
use logbook_harness::{ClaudeCodeAdapter, HarnessAdapter, HarnessContext};
use logbook_store::Store;

use crate::error::CollectorError;
use crate::token::{IngestToken, TokenMode};

/// Conventional filenames inside the out-dir.
pub const COLLECTOR_JSON: &str = "collector.json";
/// File holding only the bearer token, written `0600`.
pub const COLLECTOR_TOKEN: &str = "collector.token";

/// Maximum number of ports to try when the preferred one is busy. Matches the
/// OpenLogs collector (`maxAttempts = 64`).
pub const MAX_PORT_ATTEMPTS: u16 = 64;

/// How often the watchdog checks whether the launching process is still alive.
const WATCHDOG_INTERVAL: Duration = Duration::from_millis(500);

/// Loopback host the collector binds to. Never a public interface (plan §9).
fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Configuration for a collector instance.
#[derive(Clone, Debug)]
pub struct CollectorConfig {
    /// Bind host. Defaults to `127.0.0.1`; non-loopback hosts are rejected.
    pub host: IpAddr,
    /// Preferred starting port. `0` lets the OS choose (and disables
    /// auto-increment, since the OS already picks a free port).
    pub port: u16,
    /// Output directory where `collector.json` / `collector.token` and browser
    /// logs are written.
    pub out_dir: PathBuf,
    /// Origin allowed by CORS (e.g. `http://localhost:5173`). Scoped, never `*`
    /// (plan §4).
    pub dev_origin: String,
    /// How the ingest token is sourced.
    pub token_mode: TokenMode,
    /// Whether redaction is enabled (default true; plan §9).
    pub redact: bool,
    /// The capture policy gating per-class persistence. Consulted at the
    /// persistence boundary for the `browser_data` class on `/ingest` and for
    /// the `prompts`/`tool_*`/`model_metadata` classes on `/v1/hooks` /
    /// `/v1/traces` (plan §"Capture policy", collector rows). Defaults to the
    /// recorder-on [`CapturePolicy::default`], so existing behavior is unchanged
    /// (every class on).
    pub capture_policy: CapturePolicy,
    /// Parent PID to watch; when it dies the collector shuts down. `None`
    /// disables the watchdog (useful in tests).
    pub parent_pid: Option<i32>,
}

impl CollectorConfig {
    /// A config rooted at `out_dir` with loopback host, a generated token, the
    /// given dev origin, redaction on, and the current parent watched.
    #[must_use]
    pub fn new(out_dir: impl Into<PathBuf>, dev_origin: impl Into<String>) -> Self {
        Self {
            host: loopback(),
            port: 0,
            out_dir: out_dir.into(),
            dev_origin: dev_origin.into(),
            token_mode: TokenMode::Generated,
            redact: true,
            capture_policy: CapturePolicy::default(),
            parent_pid: crate::watchdog::parent_pid(),
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

    /// Disable redaction (callers should warn — `--no-redact`).
    #[must_use]
    pub fn without_redaction(mut self) -> Self {
        self.redact = false;
        self
    }

    /// Set the capture policy (per-class persistence gate). The recorder-on
    /// [`CapturePolicy::default`] is used otherwise.
    #[must_use]
    pub fn with_capture_policy(mut self, policy: CapturePolicy) -> Self {
        self.capture_policy = policy;
        self
    }

    /// Override (or clear) the watched parent PID.
    #[must_use]
    pub fn with_parent_pid(mut self, pid: Option<i32>) -> Self {
        self.parent_pid = pid;
        self
    }
}

/// The metadata written to `collector.json`. **No secret** lives here — the
/// token is in `collector.token` (review #v3.2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorRecord {
    /// Bind host as a string (e.g. `127.0.0.1`).
    pub host: String,
    /// Bound port.
    pub port: u16,
    /// Output directory.
    #[serde(rename = "outDir")]
    pub out_dir: String,
    /// Collector process id.
    pub pid: u32,
    /// Start timestamp: epoch microseconds (UTC) rendered as a string with a
    /// `us` suffix, e.g. `"1700000000000000us"` (**NOT** RFC3339). Kept as a
    /// tagged integer string so the file stays dependency-light; downstream
    /// code treats it as an opaque instant.
    #[serde(rename = "startedAt")]
    pub started_at: String,
}

/// Shared state handed to the axum handlers.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    redactor: Arc<Redactor>,
    /// The resolved capture policy (per-class persistence gate). Consulted for
    /// the `browser_data` gate on `/ingest` and threaded into the per-request
    /// [`HarnessContext`] for `/v1/hooks` + `/v1/traces`.
    policy: Arc<CapturePolicy>,
    /// Whether the **general** redactor is enabled (i.e. not `--no-redact`).
    /// Threaded into each request's [`HarnessContext`]; the mandatory secrets
    /// floor always applies regardless.
    redact: bool,
    token: IngestToken,
    record: Arc<CollectorRecord>,
}

impl AppState {
    /// Build a fresh [`HarnessContext`] for one request: a general redactor
    /// gated by [`Self::redact`] (disabled under `--no-redact`) over the
    /// resolved capture policy. The context constructs + always applies the
    /// mandatory secrets floor internally, so a secret can never reach an
    /// `Event` even when the general layer is off. Built per request because
    /// [`HarnessContext`] is not `Clone` ([`Redactor`] is not `Clone`).
    fn harness_context(&self) -> HarnessContext {
        let general = if self.redact {
            Redactor::new()
        } else {
            Redactor::disabled()
        };
        HarnessContext::new(general, (*self.policy).clone(), self.redact)
    }
}

/// A running collector handle: the bound address, the resolved token, and a
/// shutdown trigger. Dropping the handle does **not** stop the server; call
/// [`RunningCollector::shutdown`] or await [`RunningCollector::join`].
pub struct RunningCollector {
    addr: SocketAddr,
    token: IngestToken,
    out_dir: PathBuf,
    pid: u32,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningCollector {
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

    /// The resolved ingest token (`None` when `token_mode = off`).
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_str()
    }

    /// Signal the server to stop and remove `collector.json` / `collector.token`
    /// if (and only if) they still belong to this process. Awaits the server
    /// task.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.handle).await;
        cleanup_files(&self.out_dir, self.pid);
    }

    /// Await the server task to completion (e.g. after the watchdog fires).
    pub async fn join(mut self) {
        let _ = (&mut self.handle).await;
        cleanup_files(&self.out_dir, self.pid);
    }
}

/// Bind a loopback `TcpListener`, auto-incrementing the port on `AddrInUse` up
/// to [`MAX_PORT_ATTEMPTS`] (ported from OpenLogs `listenOnAvailablePort`).
///
/// When `start_port == 0` the OS chooses a free port and no retry loop runs.
///
/// # Errors
/// Returns [`CollectorError::Bind`] if no port in the range could be bound.
pub async fn bind_with_auto_increment(
    host: IpAddr,
    start_port: u16,
) -> Result<TcpListener, CollectorError> {
    if start_port == 0 {
        let addr = SocketAddr::new(host, 0);
        return TcpListener::bind(addr)
            .await
            .map_err(|source| CollectorError::Bind {
                port: 0,
                source,
            });
    }

    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..MAX_PORT_ATTEMPTS {
        let port = start_port.saturating_add(attempt);
        let addr = SocketAddr::new(host, port);
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(e) if is_addr_in_use(&e) => {
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                return Err(CollectorError::Bind { port, source: e });
            }
        }
    }
    Err(CollectorError::Bind {
        port: start_port,
        source: last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrInUse, "all ports in range busy")
        }),
    })
}

fn is_addr_in_use(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrInUse
}

/// Start the collector: reject non-loopback binds, resolve the token, bind a
/// port, write `collector.json` (no secret) + `collector.token` (`0600`), and
/// spawn the axum server plus the parent-PID watchdog. Returns once the socket
/// is bound and the files are written.
///
/// # Errors
/// Returns [`CollectorError`] on a non-loopback host, token resolution failure,
/// bind failure, or a failure writing the collector files.
pub async fn start(
    config: CollectorConfig,
    store: Store,
) -> Result<RunningCollector, CollectorError> {
    if !config.host.is_loopback() {
        return Err(CollectorError::NonLoopbackBind(config.host));
    }

    std::fs::create_dir_all(&config.out_dir).map_err(|source| CollectorError::OutDir {
        path: config.out_dir.clone(),
        source,
    })?;

    let token = IngestToken::resolve(config.token_mode)?;

    let listener = bind_with_auto_increment(config.host, config.port).await?;
    let addr = listener
        .local_addr()
        .map_err(|source| CollectorError::Bind {
            port: config.port,
            source,
        })?;

    let pid = std::process::id();
    let record = CollectorRecord {
        host: config.host.to_string(),
        port: addr.port(),
        out_dir: config.out_dir.to_string_lossy().into_owned(),
        pid,
        started_at: now_epoch_micros_tag(),
    };

    // v3.2 split: collector.json carries NO secret; collector.token holds the
    // token only, 0600.
    write_collector_json(&config.out_dir, &record)?;
    write_collector_token(&config.out_dir, &token)?;

    let redactor = if config.redact {
        Redactor::new().with_process_env()
    } else {
        // Secrets floor (plan §9: "`--no-redact` can never expose a secret").
        // `--no-redact` disables only the general/`deny`-pattern layer; the
        // mandatory floor still scrubs cloud keys, JWT, bearer, PEM, … plus the
        // process env's secret-looking values from every persisted `/ingest`
        // event. Mirrors logbook-capture `pty.rs` and logbook-inventory `cli.rs`.
        Redactor::secrets_floor_with_process_env()
    };

    let state = AppState {
        store: Arc::new(store),
        redactor: Arc::new(redactor),
        policy: Arc::new(config.capture_policy.clone()),
        redact: config.redact,
        token: token.clone(),
        record: Arc::new(record),
    };

    let app = build_router(state, &config.dev_origin)?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Parent-PID watchdog: trip the shutdown channel if the launching process
    // dies, so collectors never linger and squat the port (OpenLogs parity).
    let watchdog = config.parent_pid.map(|ppid| {
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(crate::watchdog::watch(ppid, WATCHDOG_INTERVAL, kill_tx));
        kill_rx
    });

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            // Either an explicit shutdown signal, the watchdog firing, or a
            // termination signal (SIGINT/SIGTERM) ends the server.
            tokio::select! {
                _ = shutdown_rx => {}
                _ = async {
                    match watchdog {
                        Some(rx) => { let _ = rx.await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
                _ = terminate_signal() => {}
            }
        };
        let server = axum::serve(listener, app).with_graceful_shutdown(shutdown);
        if let Err(e) = server.await {
            tracing::error!(error = %e, "collector server error");
        }
    });

    Ok(RunningCollector {
        addr,
        token,
        out_dir: config.out_dir,
        pid,
        shutdown_tx: Some(shutdown_tx),
        handle,
    })
}

/// Resolve when the process receives SIGINT or SIGTERM (Unix). On non-Unix it
/// resolves only on Ctrl-C.
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

/// Build the axum router with the scoped CORS layer.
fn build_router(state: AppState, dev_origin: &str) -> Result<Router, CollectorError> {
    let origin: HeaderValue = dev_origin
        .parse()
        .map_err(|_| CollectorError::BadOrigin(dev_origin.to_string()))?;

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([origin]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ]);

    Ok(Router::new()
        .route("/health", get(health))
        .route("/ingest", post(ingest))
        .route("/v1/hooks", post(ingest_hooks))
        .route("/v1/traces", post(ingest_traces))
        .layer(cors)
        .with_state(state))
}

/// `GET /health` — public, no secret. Mirrors OpenLogs `{ ok, ...record }`.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let r = &*state.record;
    Json(json!({
        "ok": true,
        "host": r.host,
        "port": r.port,
        "outDir": r.out_dir,
        "pid": r.pid,
        "startedAt": r.started_at,
    }))
}

/// `POST /ingest` — requires `Authorization: Bearer <token>` unless the token
/// mode is `off`. Accepts `{events:[]}` or a bare array. Normalizes each
/// browser event into `Event{category:browser}`, redacts, and persists.
async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // Auth first: never look at the body for an unauthorized request.
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    let payload = match body {
        Ok(Json(v)) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON").into_response(),
    };

    // `browser_data` capture-policy gate (plan: "a *new* collector-side gate;
    // today `/ingest` is not class-gated"). When the class is off, drop the
    // batch — accept the request (204) but persist nothing, so a paused capture
    // toggle silences passive browser ingest without erroring the client.
    if !state.policy.should_capture(SensitivityClass::BrowserData) {
        return StatusCode::NO_CONTENT.into_response();
    }

    let raw_events = extract_events(payload);

    // One trace ties this ingest batch together (browser lane).
    let trace = TraceId::new();
    let events: Vec<Event> = raw_events
        .into_iter()
        .map(|e| normalize_browser_event(&e, trace, &state.redactor))
        .collect();

    if !events.is_empty() {
        if let Err(e) = state.store.insert_batch(events) {
            tracing::error!(error = %e, "failed to persist ingested events");
            return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

/// `POST /v1/hooks` — ingest a harness **hook** record (Claude Code
/// `PreToolUse`/`PostToolUse`/`UserPromptSubmit`/`Stop`, or a session-log line),
/// normalize it via the [`logbook_harness`] adapters, and persist the resulting
/// redacted events. Bearer-gated exactly like `/ingest`.
///
/// The body is a single hook record object (or a `{records:[...]}` / bare array
/// of them). A top-level `trace` (32-hex) and `session` field may be supplied to
/// tie the events to an existing session; otherwise a fresh trace is minted.
/// Unrecognized records normalize to zero events (the adapter is tolerant),
/// yielding `204` with nothing persisted.
///
/// **Redaction-before-persistence** (plan §9): every prompt / tool arg / tool
/// result is scrubbed by the adapter's [`HarnessContext`] before it becomes an
/// event — the handler never builds an event holding a raw secret.
async fn ingest_hooks(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let payload = match body {
        Ok(Json(v)) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON").into_response(),
    };

    // Capture-policy gate (mirrors the `/ingest` browser_data gate). Hook records
    // normalize into `prompts` / `tool_args` / `tool_results` / `model_metadata`
    // events — all structured-tier classes. When the master switch is paused or
    // the structured tier is off, *none* of these classes is captured, so persist
    // nothing: accept the request (204) but drop the batch, so a master-pause /
    // structured-tier-off silences hook ingest just like it silences `/ingest`.
    // (Per-class redaction/omission inside the adapter is unchanged; this is the
    // missing producer-level master gate.)
    if !structured_capture_open(&state.policy) {
        return StatusCode::NO_CONTENT.into_response();
    }

    // Optional trace/session correlation from the body (a fresh trace otherwise).
    let trace = payload
        .get("trace")
        .or_else(|| payload.get("trace_id"))
        .and_then(Value::as_str)
        .and_then(parse_trace_hex)
        .unwrap_or_else(TraceId::new);
    let session = payload
        .get("session")
        .or_else(|| payload.get("session_id"))
        .and_then(Value::as_str)
        .map(SessionId::new);

    let records = extract_records(&payload);
    if records.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    // Build a per-request harness context (redactor + policy) mirroring the
    // server's resolved posture; the adapter routes every payload through it.
    let ctx = state.harness_context();
    let adapter = ClaudeCodeAdapter::new(trace, ctx, harness_version_of(&payload));

    let mut events: Vec<Event> = Vec::new();
    for rec in &records {
        for mut ev in adapter.parse_record(rec) {
            if let Some(s) = &session {
                ev = ev.with_session(s.clone());
            }
            events.push(ev);
        }
    }

    if !events.is_empty() {
        if let Err(e) = state.store.insert_batch(events) {
            tracing::error!(error = %e, "failed to persist hook events");
            return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /v1/traces` — a **minimal OTLP-JSON** spans receiver: map each span in
/// the standard `resourceSpans[].scopeSpans[].spans[]` envelope to an [`Event`]
/// and persist it. Bearer-gated like `/ingest`.
///
/// This is intentionally small (the inverse of `logbook-export`'s OTLP shape):
/// it reads `traceId`/`spanId`/`parentSpanId` (hex), `name`, `startTimeUnixNano`,
/// `status.code`, and string `attributes`, producing a `Kind::Span` /
/// `Category::Agent` event. Span `name` + string attribute **values** are routed
/// through the harness context (`tool_args` class) so any secret is redacted
/// before persistence. Unparseable / empty envelopes yield `204` with nothing
/// stored.
async fn ingest_traces(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !authorize(&state.token, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let payload = match body {
        Ok(Json(v)) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON").into_response(),
    };

    // Capture-policy gate (mirrors the `/ingest` browser_data gate). OTLP spans
    // are persisted with their name + string attributes routed through the
    // `tool_args` class, so gate on it: when the master switch is paused or the
    // structured tier is off, `tool_args` is not captured and we persist nothing
    // (accept with 204, drop the batch). Without this gate a master-pause /
    // structured-tier-off would not stop `/v1/traces`.
    if !state.policy.should_capture(SensitivityClass::ToolArgs) {
        return StatusCode::NO_CONTENT.into_response();
    }

    let ctx = state.harness_context();
    let events = otlp_spans_to_events(&payload, &ctx);

    if !events.is_empty() {
        if let Err(e) = state.store.insert_batch(events) {
            tracing::error!(error = %e, "failed to persist OTLP spans");
            return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

type Response = axum::response::Response;

/// Constant-time-ish bearer check. With `token_mode = off` the token is `None`
/// and every request is allowed (dev/test only).
fn authorize(expected: &IngestToken, headers: &HeaderMap) -> bool {
    let Some(want) = expected.as_str() else {
        return true; // token disabled (dev/test only)
    };
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(got) = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")) else {
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

/// A single browser event as posted by the injected snippet (or schrute). All
/// fields optional; shapes that don't match are coerced best-effort.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct BrowserEvent {
    /// Event kind (`console`, `error`, `network`, ...). Defaults to `console`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Console level (`log`, `info`, `warn`, `error`, `debug`).
    #[serde(default)]
    pub level: Option<String>,
    /// Rendered message.
    #[serde(default)]
    pub message: Option<String>,
    /// Console-style args, joined into the message when present.
    #[serde(default)]
    pub args: Option<Vec<Value>>,
    /// Originating URL / file.
    #[serde(default)]
    pub url: Option<String>,
    /// Stack trace.
    #[serde(default)]
    pub stack: Option<String>,
    /// Logical source label (drives the per-source log files in OpenLogs).
    #[serde(default)]
    pub source: Option<String>,
    /// Client-supplied timestamp (ISO string); informational only.
    #[serde(default)]
    pub ts: Option<String>,
    /// Free-form metadata.
    #[serde(default)]
    pub meta: Option<Value>,
}

/// Pull the event list out of either `{events:[...]}` or a bare `[...]`.
/// Anything else yields an empty list (OpenLogs parity).
fn extract_events(payload: Value) -> Vec<BrowserEvent> {
    let array = match payload {
        Value::Object(mut map) => match map.remove("events") {
            Some(Value::Array(items)) => items,
            _ => return Vec::new(),
        },
        Value::Array(items) => items,
        _ => return Vec::new(),
    };
    array
        .into_iter()
        .filter_map(|v| serde_json::from_value::<BrowserEvent>(v).ok())
        .collect()
}

/// Normalize a browser event into an `Event{category:browser}`, redacting all
/// free text **before** it is persisted (plan §9). The message is built from
/// `message` + stringified `args` (OpenLogs `normalizeBrowserEvent`).
fn normalize_browser_event(event: &BrowserEvent, trace: TraceId, redactor: &Redactor) -> Event {
    let level = event
        .level
        .as_deref()
        .unwrap_or("info")
        .to_ascii_lowercase();
    // Redact + length-cap `kind` before it becomes the persisted event `type`
    // (plan §9): like message/url/stack/meta, it is client-supplied free text
    // and must not leak secrets or smuggle an oversized blob into the store.
    let kind = truncate_with_ellipsis(&redactor.redact(event.kind.as_deref().unwrap_or("console")), 64);

    let mut message = event.message.clone().unwrap_or_default();
    if let Some(args) = &event.args {
        let joined = args
            .iter()
            .map(stringify_value)
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            if message.is_empty() {
                message = joined;
            } else {
                message.push(' ');
                message.push_str(&joined);
            }
        }
    }
    let message = message.trim().to_string();
    let message = if message.is_empty() {
        "(empty)".to_string()
    } else {
        redactor.redact(&message).into_owned()
    };

    let url = event
        .url
        .as_ref()
        .map(|u| redactor.redact(u).into_owned());
    let stack = event
        .stack
        .as_ref()
        .map(|s| redactor.redact(s).into_owned());
    let source = event
        .source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("browser")
        .to_string();

    // Error-level console events mark the span errored.
    let is_error = level == "error" || kind == "error";
    let status = if is_error { Status::Error } else { Status::Ok };

    let mut ev = Event::new(trace, Kind::Browser, Category::Browser, kind)
        .with_op("console")
        .with_name(truncate_with_ellipsis(&message, 120))
        .with_status(status)
        .with_attr("source", source.clone())
        .with_console(ConsoleBlock {
            level: Some(level),
            message: Some(message.clone()),
            url: url.clone(),
            stack: stack.clone(),
        });

    if is_error {
        ev.error = Some(message);
    }
    if let Some(meta) = &event.meta {
        let mut meta = meta.clone();
        redactor.redact_json(&mut meta);
        ev = ev.with_attr("meta", meta);
    }
    if let Some(ts) = &event.ts {
        ev = ev.with_attr("client_ts", ts.clone());
    }
    ev
}

/// Stringify a JSON arg the way the OpenLogs collector does (strings verbatim,
/// scalars via `to_string`, everything else via compact JSON).
fn stringify_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

// ---- /v1/hooks helpers ---------------------------------------------------

/// Parse a 32-hex-char trace id into a [`TraceId`], returning `None` on a bad
/// length or non-hex input (the caller mints a fresh trace instead).
fn parse_trace_hex(hex: &str) -> Option<TraceId> {
    let hex = hex.trim();
    if hex.len() != TraceId::HEX_LEN {
        return None;
    }
    let mut bytes = [0u8; TraceId::LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        let s = hex.get(i * 2..i * 2 + 2)?;
        *b = u8::from_str_radix(s, 16).ok()?;
    }
    if bytes == [0u8; TraceId::LEN] {
        return None;
    }
    Some(TraceId::from_bytes(bytes))
}

/// Pull the hook record(s) out of a `/v1/hooks` body: a single record object,
/// a `{records:[...]}` wrapper, or a bare array. The record(s) returned are the
/// raw harness JSON the adapter understands. A wrapper object's correlation
/// fields (`trace`/`session`) are read by the caller, not here.
fn extract_records(payload: &Value) -> Vec<Value> {
    match payload {
        Value::Array(items) => items.clone(),
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get("records") {
                items.clone()
            } else if map.contains_key("record") {
                vec![map.get("record").cloned().unwrap_or(Value::Null)]
            } else {
                // A bare hook record object (the common case).
                vec![payload.clone()]
            }
        }
        _ => Vec::new(),
    }
}

/// The harness version to stamp on hook events: an explicit `harness_version`
/// body field, else `"unknown"`.
fn harness_version_of(payload: &Value) -> String {
    payload
        .get("harness_version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

/// Whether *any* structured-tier content class a hook record can emit is
/// captured under `policy`. A hook normalizes into `prompts` / `tool_args` /
/// `tool_results` / `model_metadata` events; all four are gated by the master
/// switch (`enabled`) and the `structured` tier. When the master switch is
/// paused or the structured tier is off, none is captured and `/v1/hooks`
/// persists nothing (the producer-level gate that mirrors the `/ingest`
/// `browser_data` gate). Returning `true` here does **not** relax per-class
/// redaction/omission inside the adapter.
fn structured_capture_open(policy: &CapturePolicy) -> bool {
    policy.should_capture(SensitivityClass::Prompts)
        || policy.should_capture(SensitivityClass::ToolArgs)
        || policy.should_capture(SensitivityClass::ToolResults)
        || policy.should_capture(SensitivityClass::ModelMetadata)
}

// ---- /v1/traces (minimal OTLP-JSON) --------------------------------------

/// Map a minimal OTLP-JSON spans envelope to [`Event`]s. Walks
/// `resourceSpans[].scopeSpans[].spans[]` (the standard OTLP/JSON shape), and
/// for each span produces a `Kind::Span` / `Category::Agent` event. The span
/// `name` and string attribute **values** are redacted via `ctx` (tool_args
/// class) before they land on the event; numbers/bools are kept as-is.
fn otlp_spans_to_events(payload: &Value, ctx: &HarnessContext) -> Vec<Event> {
    let mut out = Vec::new();
    let Some(resource_spans) = payload.get("resourceSpans").and_then(Value::as_array) else {
        return out;
    };
    for rs in resource_spans {
        let Some(scope_spans) = rs.get("scopeSpans").and_then(Value::as_array) else {
            continue;
        };
        for ss in scope_spans {
            let Some(spans) = ss.get("spans").and_then(Value::as_array) else {
                continue;
            };
            for span in spans {
                if let Some(ev) = otlp_span_to_event(span, ctx) {
                    out.push(ev);
                }
            }
        }
    }
    out
}

/// Convert one OTLP span object into an [`Event`]. Returns `None` only if the
/// span carries no usable `traceId`.
fn otlp_span_to_event(span: &Value, ctx: &HarnessContext) -> Option<Event> {
    let trace = span
        .get("traceId")
        .and_then(Value::as_str)
        .and_then(parse_trace_hex)?;

    let raw_name = span.get("name").and_then(Value::as_str).unwrap_or("span");
    // Redact the span name (it can embed args/urls); tool_args class + floor.
    let (name, _trunc) = ctx.redact_text(SensitivityClass::ToolArgs, raw_name);

    let mut ev = Event::new(trace, Kind::Span, Category::Agent, "otlp.span")
        .with_op("span")
        .with_name(truncate_with_ellipsis(&name, 120))
        .with_attr("source", "otlp");

    // Parent span id (16-hex) → SpanId for the turn/step tree.
    if let Some(parent) = span
        .get("parentSpanId")
        .and_then(Value::as_str)
        .and_then(parse_span_hex)
    {
        ev = ev.with_parent(parent);
    }

    // Start time: OTLP uses nanoseconds since the epoch; the store is micros.
    if let Some(nanos) = span
        .get("startTimeUnixNano")
        .and_then(otlp_u64)
    {
        ev.timestamp = MicrosTimestamp((nanos / 1_000) as i64);
    }

    // Status: OTLP StatusCode 2 = ERROR, 1 = OK, 0 = UNSET.
    let status_code = span
        .get("status")
        .and_then(|s| s.get("code"))
        .and_then(otlp_u64)
        .unwrap_or(0);
    if status_code == 2 {
        let raw_msg = span
            .get("status")
            .and_then(|s| s.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("span errored");
        let (msg, _t) = ctx.redact_text(SensitivityClass::ToolArgs, raw_msg);
        ev = ev.with_error(msg);
    } else if status_code == 1 {
        ev = ev.with_status(Status::Ok);
    }

    // String attributes (OTLP KeyValue list) → redacted event attributes.
    if let Some(attrs) = span.get("attributes").and_then(Value::as_array) {
        for kv in attrs {
            let Some(key) = kv.get("key").and_then(Value::as_str) else {
                continue;
            };
            let Some(val) = kv.get("value") else { continue };
            if let Some(s) = val.get("stringValue").and_then(Value::as_str) {
                let (red, _t) = ctx.redact_text(SensitivityClass::ToolArgs, s);
                ev = ev.with_attr(key.to_string(), red);
            } else if let Some(i) = val.get("intValue").and_then(otlp_u64) {
                ev = ev.with_attr(key.to_string(), i);
            } else if let Some(b) = val.get("boolValue").and_then(Value::as_bool) {
                ev = ev.with_attr(key.to_string(), b);
            }
        }
    }

    ev.debug_assert_valid();
    Some(ev)
}

/// Parse a 16-hex-char span id into a [`SpanId`] (OTLP `parentSpanId`).
fn parse_span_hex(hex: &str) -> Option<logbook_core::SpanId> {
    let hex = hex.trim();
    if hex.len() != logbook_core::SpanId::HEX_LEN {
        return None;
    }
    let mut bytes = [0u8; logbook_core::SpanId::LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        let s = hex.get(i * 2..i * 2 + 2)?;
        *b = u8::from_str_radix(s, 16).ok()?;
    }
    if bytes == [0u8; logbook_core::SpanId::LEN] {
        return None;
    }
    Some(logbook_core::SpanId::from_bytes(bytes))
}

/// OTLP/JSON encodes 64-bit integers as either a JSON number or a decimal
/// string. Accept both.
fn otlp_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// Write `collector.json` (pretty, trailing newline; **no secret**).
///
/// # Errors
/// Returns [`CollectorError::WriteRecord`] on I/O or serialization failure.
pub fn write_collector_json(out_dir: &Path, record: &CollectorRecord) -> Result<(), CollectorError> {
    let path = out_dir.join(COLLECTOR_JSON);
    let body = serde_json::to_string_pretty(record)
        .map_err(|e| CollectorError::WriteRecord(e.to_string()))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| CollectorError::WriteRecord(e.to_string()))?;
    Ok(())
}

/// Write `collector.token` containing only the token, with perms `0600` on
/// Unix (review #v3.2). No-op (no file) when the token is disabled.
///
/// # Errors
/// Returns [`CollectorError::WriteToken`] on I/O failure.
pub fn write_collector_token(out_dir: &Path, token: &IngestToken) -> Result<(), CollectorError> {
    let Some(secret) = token.as_str() else {
        return Ok(());
    };
    let path = out_dir.join(COLLECTOR_TOKEN);
    write_secret_file(&path, secret).map_err(|e| CollectorError::WriteToken(e.to_string()))
}

/// Write a secret to `path` ensuring it is created `0600` on Unix (the perms
/// are set atomically via `OpenOptions::mode` so the secret is never briefly
/// world-readable).
fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    // Remove any stale file first so we always create fresh with our mode.
    let _ = std::fs::remove_file(path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }
    Ok(())
}

/// Load and parse `collector.json` from `out_dir`, if present.
///
/// # Errors
/// Returns [`CollectorError::WriteRecord`] if the file exists but cannot be
/// parsed. A missing file yields `Ok(None)`.
pub fn load_collector_record(out_dir: &Path) -> Result<Option<CollectorRecord>, CollectorError> {
    let path = out_dir.join(COLLECTOR_JSON);
    match std::fs::read_to_string(&path) {
        Ok(body) => serde_json::from_str(&body)
            .map(Some)
            .map_err(|e| CollectorError::WriteRecord(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CollectorError::WriteRecord(e.to_string())),
    }
}

/// Remove `collector.json` / `collector.token` **only if** the record's pid
/// matches `pid` (so a relaunched collector that adopted the out-dir is not
/// clobbered by a late-dying predecessor — OpenLogs parity).
pub fn cleanup_files(out_dir: &Path, pid: u32) {
    match load_collector_record(out_dir) {
        Ok(Some(record)) if record.pid == pid => {
            let _ = std::fs::remove_file(out_dir.join(COLLECTOR_JSON));
            let _ = std::fs::remove_file(out_dir.join(COLLECTOR_TOKEN));
        }
        _ => {}
    }
}

/// Render the current time as epoch microseconds (UTC) tagged with a `us`
/// suffix, e.g. `"1700000000000000us"`. This is intentionally **not** RFC3339:
/// a full date string is overkill for `collector.json`/`/health`, which only
/// need an opaque, dependency-light start instant.
fn now_epoch_micros_tag() -> String {
    let micros = logbook_core::MicrosTimestamp::now().as_micros();
    // Epoch-microseconds string; downstream code treats it as an opaque instant.
    format!("{micros}us")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_events_handles_both_shapes() {
        let wrapped = json!({"events": [{"message": "a"}, {"message": "b"}]});
        assert_eq!(extract_events(wrapped).len(), 2);

        let bare = json!([{"message": "x"}]);
        assert_eq!(extract_events(bare).len(), 1);

        let neither = json!({"foo": 1});
        assert_eq!(extract_events(neither).len(), 0);

        let scalar = json!(42);
        assert_eq!(extract_events(scalar).len(), 0);
    }

    #[test]
    fn normalize_joins_args_and_redacts() {
        let r = Redactor::new();
        let trace = TraceId::new();
        let ev = BrowserEvent {
            message: Some("token".into()),
            args: Some(vec![json!("AKIAIOSFODNN7EXAMPLE"), json!(7)]),
            level: Some("WARN".into()),
            ..Default::default()
        };
        let out = normalize_browser_event(&ev, trace, &r);
        assert_eq!(out.category, Category::Browser);
        assert_eq!(out.kind, Kind::Browser);
        let console = out.blocks.console.as_ref().unwrap();
        let msg = console.message.as_ref().unwrap();
        assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {msg}");
        assert!(msg.contains('7'));
        assert_eq!(console.level.as_deref(), Some("warn"));
    }

    #[test]
    fn error_level_marks_status_error() {
        let r = Redactor::new();
        let ev = BrowserEvent {
            message: Some("boom".into()),
            level: Some("error".into()),
            ..Default::default()
        };
        let out = normalize_browser_event(&ev, TraceId::new(), &r);
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.error.as_deref(), Some("boom"));
    }

    #[test]
    fn no_redact_still_applies_secrets_floor() {
        // Regression (plan §9: "`--no-redact` can never expose a secret"). When
        // `config.redact == false` the `/ingest` redactor is the mandatory
        // secrets floor, NOT a passthrough, so an ingested AWS-style key is still
        // scrubbed from the persisted event while benign text survives. This is
        // the exact redactor `start` now builds for the `redact = false` branch.
        let floor = Redactor::secrets_floor_with_process_env();
        assert!(
            floor.is_secrets_floor(),
            "redact=false must build the mandatory secrets floor, not a passthrough"
        );

        let trace = TraceId::new();
        let ev = BrowserEvent {
            message: Some("creds AKIAIOSFODNN7EXAMPLE benignword".into()),
            url: Some("https://logs.example/AKIAIOSFODNN7EXAMPLE/path".into()),
            ..Default::default()
        };
        let out = normalize_browser_event(&ev, trace, &floor);

        let console = out.blocks.console.as_ref().unwrap();
        let msg = console.message.as_ref().unwrap();
        assert!(
            !msg.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret persisted under --no-redact: {msg}"
        );
        assert!(
            msg.contains("REDACTED:CLOUD_KEY:"),
            "expected secrets-floor placeholder: {msg}"
        );
        assert!(msg.contains("benignword"), "over-redacted benign text: {msg}");

        // The same floor scrubs the URL field, not just the message.
        let url = console.url.as_ref().unwrap();
        assert!(
            !url.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret persisted in url under --no-redact: {url}"
        );
        assert!(url.contains("REDACTED:CLOUD_KEY:"), "url not scrubbed: {url}");
    }

    #[test]
    fn empty_message_becomes_placeholder() {
        let r = Redactor::new();
        let ev = BrowserEvent::default();
        let out = normalize_browser_event(&ev, TraceId::new(), &r);
        assert_eq!(out.blocks.console.unwrap().message.as_deref(), Some("(empty)"));
    }

    #[test]
    fn authorize_requires_matching_bearer() {
        let token = IngestToken::from_secret("s3cr3t-token-value");
        let mut headers = HeaderMap::new();
        assert!(!authorize(&token, &headers), "missing header must fail");

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(!authorize(&token, &headers), "wrong token must fail");

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cr3t-token-value"),
        );
        assert!(authorize(&token, &headers), "correct token must pass");
    }

    #[test]
    fn authorize_allows_when_token_disabled() {
        let token = IngestToken::disabled();
        let headers = HeaderMap::new();
        assert!(authorize(&token, &headers), "off mode allows all");
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn record_json_has_no_secret_field() {
        let record = CollectorRecord {
            host: "127.0.0.1".into(),
            port: 7070,
            out_dir: "/tmp/x".into(),
            pid: 1234,
            started_at: "0us".into(),
        };
        let v = serde_json::to_value(&record).unwrap();
        assert!(v.get("token").is_none(), "collector.json must not carry a token");
        assert!(v.get("secret").is_none());
        assert_eq!(v["outDir"], json!("/tmp/x"));
        assert_eq!(v["port"], json!(7070));
    }
}
