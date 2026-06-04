//! Router assembly and the bound-server lifecycle (plan §1, §4).
//!
//! The UI server is a *separate* axum app from the collector. It exposes:
//! - the embedded static bundle (`GET /*path`, SPA fallback) — [`crate::embed`];
//! - read-only JSON APIs `/api/events`, `/api/timeline`, `/api/inventory` —
//!   [`crate::api`];
//! - a live-tail SSE endpoint `/api/stream` — [`crate::sse`].
//!
//! Binding follows the OpenLogs collector contract: `127.0.0.1` only, with port
//! auto-increment (up to [`MAX_PORT_ATTEMPTS`]) when the preferred port is busy,
//! and an optional parent-PID watchdog so the server never lingers and squats a
//! port after its launching process dies (which would block future runs across
//! e.g. git worktrees).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use logbook_store::Store;

use crate::api;
use crate::bus::EventBus;
use crate::embed::static_handler;
use crate::sse;
use crate::state::AppState;

/// Default UI port. Chosen to avoid common dev-server ports (3000/5173/8080)
/// and the collector's range.
pub const DEFAULT_PORT: u16 = 7878;

/// How many sequential ports to try before giving up (matches OpenLogs).
pub const MAX_PORT_ATTEMPTS: u16 = 64;

/// Configuration for the UI server.
#[derive(Clone, Debug)]
pub struct UiConfig {
    /// Loopback bind address. Defaults to `127.0.0.1`.
    pub host: IpAddr,
    /// Preferred port; auto-increments on conflict.
    pub port: u16,
    /// When set, the server exits if this PID is no longer alive (watchdog).
    pub parent_pid: Option<u32>,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            parent_pid: None,
        }
    }
}

/// Build the UI [`Router`] over the given state. Exposed for tests and for
/// callers that want to mount it inside a larger server.
pub fn app(state: AppState) -> Router {
    // The UI is served same-origin in production (embedded) and via the Vite
    // dev proxy in development, so permissive CORS is only relevant to the
    // read-only JSON APIs on loopback. Keep it to GETs.
    let cors = CorsLayer::new()
        .allow_methods([axum::http::Method::GET])
        .allow_origin(Any);

    Router::new()
        .route("/api/events", get(api::events))
        .route("/api/timeline", get(api::timeline))
        .route("/api/inventory", get(api::inventory))
        .route("/api/stream", get(sse::stream))
        // Static + SPA fallback for everything else.
        .fallback(static_handler)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// A bound, not-yet-serving UI server: holds the listener so the caller can read
/// the actual [`Self::addr`] (important when the port auto-incremented) before
/// awaiting [`Self::serve`].
pub struct UiServer {
    listener: TcpListener,
    router: Router,
    parent_pid: Option<u32>,
    addr: SocketAddr,
}

impl UiServer {
    /// The address the server is actually bound to.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The bound port (after any auto-increment).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Serve until the process is told to stop (Ctrl-C / SIGTERM) or, if a
    /// parent PID was configured, until that parent dies.
    ///
    /// # Errors
    /// Returns any error from the underlying axum/hyper server.
    pub async fn serve(self) -> std::io::Result<()> {
        let UiServer {
            listener,
            router,
            parent_pid,
            addr,
        } = self;
        tracing::info!(%addr, "logbook UI listening");
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal(parent_pid))
            .await
    }
}

/// Bind the UI server, trying [`MAX_PORT_ATTEMPTS`] sequential ports from
/// `config.port`. Returns a [`UiServer`] whose [`UiServer::addr`] reflects the
/// port actually claimed.
///
/// # Errors
/// Returns the last bind error if every attempted port is unavailable.
pub async fn bind(config: &UiConfig, state: AppState) -> std::io::Result<UiServer> {
    let router = app(state);
    let mut last_err: Option<std::io::Error> = None;

    for offset in 0..MAX_PORT_ATTEMPTS {
        let port = config.port.saturating_add(offset);
        let addr = SocketAddr::new(config.host, port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                let bound = listener.local_addr().unwrap_or(addr);
                return Ok(UiServer {
                    listener,
                    router,
                    parent_pid: config.parent_pid,
                    addr: bound,
                });
            }
            Err(err) if is_addr_in_use(&err) => {
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no available port for logbook UI",
        )
    }))
}

/// Convenience: bind (with auto-increment) and serve in one call.
///
/// # Errors
/// Returns a bind or serve error.
pub async fn serve(config: &UiConfig, store: Store, bus: EventBus) -> std::io::Result<()> {
    let server = bind(config, AppState::new(store, bus)).await?;
    server.serve().await
}

/// Whether a bind error indicates the address/port is already in use.
fn is_addr_in_use(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::AddrInUse)
}

/// Resolve when it is time to shut down: either an OS interrupt (Ctrl-C /
/// SIGTERM), or — if a parent PID is configured — when that parent is gone.
async fn shutdown_signal(parent_pid: Option<u32>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sig) = signal(SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    let watchdog = async {
        match parent_pid {
            Some(pid) => loop {
                if !is_process_alive(pid) {
                    tracing::info!(pid, "parent process gone; shutting down UI");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            },
            // No parent watchdog configured: never resolve on this branch.
            None => std::future::pending::<()>().await,
        }
    };

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
        () = watchdog => {}
    }
}

/// Best-effort liveness check for `pid`, via the safe `rustix` wrapper around
/// `kill(pid, 0)`. `Ok(())` means the process exists; an `EPERM` error means it
/// exists but we may not signal it (still alive); anything else (e.g. `ESRCH`)
/// means it is gone. Keeping this in `rustix` avoids an `unsafe` FFI block so
/// the crate can stay `#![forbid(unsafe_code)]`.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    use rustix::process::{test_kill_process, Pid};
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    match Pid::from_raw(raw) {
        Some(p) => !matches!(test_kill_process(p), Err(rustix::io::Errno::SRCH)),
        None => false,
    }
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    // No portable liveness check here; assume alive so we rely on OS signals.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_store::Store;

    fn test_state() -> AppState {
        AppState::new(Store::open_in_memory().unwrap(), EventBus::new())
    }

    #[tokio::test]
    async fn bind_picks_a_port_and_auto_increments() {
        let state = test_state();
        // Bind once on an arbitrary high port.
        let cfg = UiConfig {
            port: 0, // 0 => OS assigns a free port for the first listener
            ..Default::default()
        };
        let server = bind(&cfg, state.clone()).await.unwrap();
        assert!(server.port() > 0);

        // Now occupy a specific port and confirm a second bind on the same
        // preferred port rolls forward instead of failing.
        let occupied = bind(
            &UiConfig {
                port: 0,
                ..Default::default()
            },
            state.clone(),
        )
        .await
        .unwrap();
        let busy_port = occupied.port();
        let rolled = bind(
            &UiConfig {
                port: busy_port,
                ..Default::default()
            },
            state,
        )
        .await
        .unwrap();
        assert_ne!(
            rolled.port(),
            busy_port,
            "second bind on a busy port should auto-increment"
        );
    }

    #[test]
    fn is_addr_in_use_detects_kind() {
        let err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "x");
        assert!(is_addr_in_use(&err));
        let other = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "x");
        assert!(!is_addr_in_use(&other));
    }

    #[test]
    fn current_process_is_alive() {
        let me = std::process::id();
        assert!(is_process_alive(me));
    }
}
