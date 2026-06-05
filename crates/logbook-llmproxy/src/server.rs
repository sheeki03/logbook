//! The axum loopback, token-gated proxy server.
//!
//! An agent points `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at this server. Every
//! request is:
//! 1. **authorized** against the proxy token on the dedicated
//!    [`PROXY_TOKEN_HEADER`] (raw value, constant-time compare) — kept separate
//!    from `Authorization` so the provider's own credential passes through;
//! 2. **routed** to a [`Provider`] by URL prefix (`/anthropic/...` /
//!    `/openai/...`) or, when single-provider, the lone configured one;
//! 3. **forwarded** to the real provider via the injected [`Upstream`] (which
//!    buffers the whole response, draining any SSE stream);
//! 4. **recorded** as one redacted [`Kind::Llm`](logbook_core::Kind) event
//!    ([`crate::record`]) — prompts/results force-redacted + gated, SSE
//!    reassembled before redaction, metadata always kept; and
//! 5. **relayed** back to the client unchanged (the client still gets the real
//!    bytes; only the *stored* copy is redacted).
//!
//! The proxy **refuses to start** unless the resolved capture policy enables the
//! Complete tier ([`LlmProxyError::CompleteTierDisabled`]). Binds `127.0.0.1`
//! only.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use logbook_core::{MicrosTimestamp, Redactor};
use logbook_harness::HarnessContext;
use logbook_store::Store;

use crate::error::LlmProxyError;
use crate::record::{record_llm_event, RecordInputs};
use crate::upstream::{ReqwestUpstream, Upstream, UpstreamRequest};
use crate::LlmProxyConfig;

/// Maximum number of ports to try when the preferred one is busy (parity with
/// the collector).
pub const MAX_PORT_ATTEMPTS: u16 = 64;

/// The dedicated header the agent → proxy hop authenticates on. Its value is the
/// **raw** proxy token (no `Bearer` prefix). This is decoupled from
/// `Authorization` on purpose: the real provider credential rides `Authorization`
/// (OpenAI) or `x-api-key` (Anthropic), so the proxy must read its own token from
/// a separate header and never consume — or forward — the provider's.
///
/// This is a **shared contract with the CLI**, which sets this exact header when
/// it points an agent at the proxy.
pub const PROXY_TOKEN_HEADER: &str = "x-logbook-proxy-token";

/// Loopback host the proxy binds to. Never a public interface.
#[must_use]
pub fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Shared handler state.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    upstream: Arc<dyn Upstream>,
    config: Arc<LlmProxyConfig>,
    /// Whether the **general** redactor is enabled (`[redaction].enabled &&
    /// !--no-redact`). The mandatory secrets floor always applies regardless.
    redact: bool,
    token: Option<String>,
}

impl AppState {
    /// Build a fresh per-request [`HarnessContext`] (the redaction-before-
    /// persistence surface). Built per request because [`Redactor`] is not
    /// `Clone`. The general layer is gated by [`Self::redact`]; the floor is
    /// always constructed inside the context.
    fn harness_context(&self) -> HarnessContext {
        let general = if self.redact {
            Redactor::new()
        } else {
            Redactor::disabled()
        };
        HarnessContext::new(general, self.config.capture_policy.clone(), self.redact)
    }
}

/// A running proxy handle: bound address, token, and a shutdown trigger.
#[derive(Debug)]
pub struct RunningProxy {
    addr: SocketAddr,
    token: Option<String>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningProxy {
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

    /// The resolved bearer token (`None` only when explicitly disabled for
    /// dev/test).
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Signal the server to stop and await the task.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.handle).await;
    }

    /// Await the server task to completion.
    pub async fn join(mut self) {
        let _ = (&mut self.handle).await;
    }
}

/// Start the proxy with the production [`ReqwestUpstream`].
///
/// This is the public run entry the CLI calls. It enforces the Complete-tier
/// gate, builds the reqwest upstream, binds a loopback port, and spawns the
/// server. Returns once the socket is bound.
///
/// # Errors
/// Returns [`LlmProxyError::CompleteTierDisabled`] if the resolved policy does
/// not enable the Complete tier; otherwise a bind/token/client error.
pub async fn run_llm_proxy(
    config: LlmProxyConfig,
    store: Store,
) -> Result<RunningProxy, LlmProxyError> {
    let upstream = Arc::new(ReqwestUpstream::new()?);
    start_with_upstream(config, store, upstream).await
}

/// Start the proxy with an **injected** [`Upstream`] — the seam tests use to run
/// the whole forward → reassemble → redact → persist path against a mock with no
/// real network (plan "Phase 4 tests").
///
/// Performs the same Complete-tier gate + loopback bind as [`run_llm_proxy`].
///
/// # Errors
/// Returns [`LlmProxyError`] on the tier gate, a non-loopback host, or a bind
/// failure.
pub async fn start_with_upstream(
    config: LlmProxyConfig,
    store: Store,
    upstream: Arc<dyn Upstream>,
) -> Result<RunningProxy, LlmProxyError> {
    // GATE (critical): the proxy is the only component that sees raw provider
    // payloads, so it refuses to start unless the Complete tier is explicitly on.
    if !config.capture_policy.tiers.complete {
        return Err(LlmProxyError::CompleteTierDisabled);
    }
    if !config.host.is_loopback() {
        return Err(LlmProxyError::NonLoopbackBind(config.host));
    }

    let token = config.resolve_token()?;

    let listener = bind_with_auto_increment(config.host, config.port).await?;
    let addr = listener
        .local_addr()
        .map_err(|source| LlmProxyError::Bind {
            port: config.port,
            source,
        })?;

    let state = AppState {
        store: Arc::new(store),
        upstream,
        redact: config.redact,
        token: token.clone(),
        config: Arc::new(config),
    };

    let app = build_router(state);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let shutdown = async move {
            tokio::select! {
                _ = shutdown_rx => {}
                _ = terminate_signal() => {}
            }
        };
        let server = axum::serve(listener, app).with_graceful_shutdown(shutdown);
        if let Err(e) = server.await {
            tracing::error!(error = %e, "llm proxy server error");
        }
    });

    Ok(RunningProxy {
        addr,
        token,
        shutdown_tx: Some(shutdown_tx),
        handle,
    })
}

/// Build the router: a single catch-all that proxies every method/path, plus a
/// public `/health`.
fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health))
        .fallback(proxy)
        .with_state(state)
}

/// `GET /health` — public, secret-free liveness probe.
async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "ok": true }))
}

/// Bind a loopback `TcpListener`, auto-incrementing the port on `AddrInUse`
/// (ported from the collector's `bind_with_auto_increment`).
///
/// # Errors
/// Returns [`LlmProxyError::Bind`] if no port in the range could be bound.
pub async fn bind_with_auto_increment(
    host: IpAddr,
    start_port: u16,
) -> Result<TcpListener, LlmProxyError> {
    if start_port == 0 {
        let addr = SocketAddr::new(host, 0);
        return TcpListener::bind(addr)
            .await
            .map_err(|source| LlmProxyError::Bind { port: 0, source });
    }
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..MAX_PORT_ATTEMPTS {
        let port = start_port.saturating_add(attempt);
        match TcpListener::bind(SocketAddr::new(host, port)).await {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(LlmProxyError::Bind { port, source: e }),
        }
    }
    Err(LlmProxyError::Bind {
        port: start_port,
        source: last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrInUse, "all ports in range busy")
        }),
    })
}

/// Resolve when the process receives SIGINT/SIGTERM (Unix) or Ctrl-C elsewhere.
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

/// The catch-all proxy handler.
async fn proxy(
    State(state): State<AppState>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Auth first — never forward or read the body of an unauthorized request.
    if !authorize(state.token.as_deref(), &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    let path = uri.path();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.to_string());

    // Route to a provider + strip the provider prefix from the forwarded path.
    let (provider, upstream_path) = match state.config.route(&path_and_query) {
        Some(routed) => routed,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                "no upstream provider for this path; prefix with /anthropic or /openai, or configure a single provider",
            )
                .into_response();
        }
    };
    let base_url = state.config.upstream_base(provider);

    // Normalize the request (lowercased header names; strip our own dedicated
    // proxy-token header so it never leaks upstream — the provider credential
    // rides `Authorization`/`x-api-key`, which are forwarded verbatim).
    let req = UpstreamRequest {
        method: method.as_str().to_string(),
        path_and_query: upstream_path,
        headers: forward_request_headers(&headers),
        body: body.to_vec(),
    };

    // Forward upstream (buffers the whole response, draining any SSE stream).
    let start = std::time::Instant::now();
    let upstream_resp = match state.upstream.send(base_url, &req).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, provider = provider.as_str(), "upstream forward failed");
            return (StatusCode::BAD_GATEWAY, "upstream error").into_response();
        }
    };
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    // RECORD: one redacted Kind::Llm event. Prompt/result bodies are force-
    // redacted + gated inside; SSE was already reassembled into the buffered
    // body; metadata is always kept. Persist failures must not break the proxy
    // response to the client.
    let ctx = state.harness_context();
    let price = state.config.price_for(provider, &req);
    let event = record_llm_event(
        &ctx,
        RecordInputs {
            provider,
            request: &req,
            response: &upstream_resp,
            price,
            timestamp: MicrosTimestamp::now(),
            duration_ms: Some(duration_ms),
        },
    );
    if let Err(e) = state.store.insert(&event) {
        tracing::error!(error = %e, "failed to persist llm proxy event");
    }
    // Best-effort: extend the tamper-evident audit chain over the (already
    // redacted) stored event. A chain-append failure is logged, not fatal.
    if state.config.audit {
        if let Err(e) = state.store.append_audit(&event) {
            tracing::warn!(error = %e, "failed to append llm proxy event to audit chain");
        }
    }

    // RELAY the real upstream bytes back to the client unchanged. The client gets
    // the genuine response; only the stored copy was redacted.
    relay_response(&upstream_resp)
}

/// Build the upstream response to relay back to the client, copying status +
/// safe headers (dropping hop-by-hop / length headers axum will recompute).
fn relay_response(resp: &crate::upstream::UpstreamResponse) -> Response {
    let mut builder = Response::builder().status(resp.status);
    for (name, value) in &resp.headers {
        if RESPONSE_SKIP_HEADERS.contains(&name.as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(axum::body::Body::from(resp.body.clone()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Response headers the proxy recomputes / must not copy verbatim.
const RESPONSE_SKIP_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "trailer",
    "upgrade",
];

/// Lowercase-name header map to forward upstream, dropping **only** the proxy's
/// own dedicated [`PROXY_TOKEN_HEADER`] so the proxy token never reaches the
/// provider. The real provider credential rides a separate header —
/// `Authorization` (OpenAI's bearer key) or `x-api-key` (Anthropic) — and is
/// **forwarded verbatim**, so the upstream request still carries its credential.
fn forward_request_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        let lname = name.as_str().to_ascii_lowercase();
        if lname == PROXY_TOKEN_HEADER {
            // This authenticated the agent → proxy hop; it is not a provider
            // credential, so it must never be forwarded upstream.
            continue;
        }
        if let Ok(v) = value.to_str() {
            out.insert(lname, v.to_string());
        }
    }
    out
}

/// Authorize a request against the proxy token, read from the dedicated
/// [`PROXY_TOKEN_HEADER`] as a **raw** value (no `Bearer` prefix). This is kept
/// separate from `Authorization` so the provider's own credential on that header
/// (OpenAI) passes through untouched. When `expected` is `None` the token is
/// disabled (dev/test only) and every request is allowed.
fn authorize(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(want) = expected else {
        return true;
    };
    let Some(value) = headers.get(PROXY_TOKEN_HEADER) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    constant_time_eq(value.trim().as_bytes(), want.as_bytes())
}

/// Length-checked constant-time byte comparison (no early-exit timing leak).
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    /// Build a header map carrying the proxy token on the dedicated
    /// [`PROXY_TOKEN_HEADER`] (raw value, no `Bearer` prefix).
    fn proxy_token(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static(PROXY_TOKEN_HEADER),
            HeaderValue::from_str(token).unwrap(),
        );
        h
    }

    #[test]
    fn authorize_requires_matching_proxy_token() {
        assert!(authorize(Some("secret"), &proxy_token("secret")));
        assert!(!authorize(Some("secret"), &proxy_token("wrong")));
        assert!(!authorize(Some("secret"), &HeaderMap::new()));
    }

    #[test]
    fn authorize_ignores_authorization_header() {
        // The provider credential on `Authorization` must NOT satisfy the proxy
        // token check — the two headers are decoupled.
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(!authorize(Some("secret"), &h));
    }

    #[test]
    fn authorize_allows_when_token_disabled() {
        assert!(authorize(None, &HeaderMap::new()));
    }

    #[test]
    fn forward_headers_strip_proxy_token_keep_provider_credentials() {
        let mut h = HeaderMap::new();
        // The dedicated proxy-token header must be stripped...
        h.insert(
            HeaderName::from_static(PROXY_TOKEN_HEADER),
            HeaderValue::from_static("proxy-tok"),
        );
        // ...while BOTH provider credential headers pass through verbatim:
        // OpenAI's key on `Authorization` and Anthropic's on `x-api-key`.
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-openai"),
        );
        h.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("sk-anthropic"),
        );
        let fwd = forward_request_headers(&h);
        assert!(
            !fwd.contains_key(PROXY_TOKEN_HEADER),
            "proxy token must not be forwarded"
        );
        assert_eq!(
            fwd.get("authorization").map(String::as_str),
            Some("Bearer sk-openai"),
            "OpenAI provider key on Authorization must survive"
        );
        assert_eq!(fwd.get("x-api-key").map(String::as_str), Some("sk-anthropic"));
    }
}
