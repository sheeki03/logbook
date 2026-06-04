//! `logbook-collector` — axum collector + browser-capture adapters (plan §4).
//!
//! ## Collector (`[OpenLogs]` + `[new]`)
//! An axum server bound to `127.0.0.1`:
//! - **`GET /health`** — public, no secrets;
//! - **`POST /ingest`** — requires a per-run bearer token
//!   (`Authorization: Bearer <token>`); `401` if missing/wrong.
//!
//! Token sourcing (review #v3.1/#v3.2): `LOGBOOK_INGEST_TOKEN` if set, else a
//! token minted at startup. The **v3.2 split** is enforced:
//! - `collector.json` = `{host, port, outDir, pid, startedAt}` with **no
//!   secret**;
//! - `collector.token` = the token only, written `0600`.
//!
//! CORS is scoped to the dev origin (never `*`). `/ingest` accepts
//! `{events:[]}` or a bare array; each browser event is normalized into
//! `Event{category:browser}` via [`logbook_core`] (redacted at capture) and
//! persisted via [`logbook_store`]. The port auto-increments on `EADDRINUSE`
//! (≤ 64), and a parent-PID watchdog shuts the collector down if the launching
//! process dies, removing `collector.json` / `collector.token` only when the
//! recorded pid still matches.
//!
//! ## Browser capture
//! In v1 the [`BrowserCapture`] trait has a single impl, [`InjectedJsAdapter`]:
//! - [`InjectedJsAdapter`] — produces a JS shim (hooks `console.*`,
//!   `window.onerror`, `fetch`, `XHR`, `PerformanceObserver`; batches
//!   `POST /ingest` with the bearer token). The token is injected **at
//!   runtime** — via a Vite dev-middleware helper or an `logbook`-printed
//!   snippet; the browser never reads `collector.token`.
//! - [`SchruteAdapter`] — an MCP stdio client to schrute for a **verified
//!   subset** (record / replay / network). It does **not** implement
//!   [`BrowserCapture`]; it exposes its own async MCP surface. schrute's
//!   security gates are `PENDING`, so logbook enforces its **own**
//!   [`EgressAllowlist`] before any navigation/replay target is issued.

#![warn(missing_docs)]
// `unsafe` is confined to the `watchdog` module's libc calls (getppid/kill),
// which annotate it locally with `#![deny(unsafe_code)]`-style discipline via
// SAFETY comments. Every other module is unsafe-free.

pub mod browser;
pub mod collector;
pub mod egress;
pub mod error;
pub mod injected;
pub mod schrute_mcp;
pub mod token;
pub mod watchdog;

pub use browser::{BrowserCapture, CaptureKind};
pub use collector::{
    bind_with_auto_increment, cleanup_files, load_collector_record, start, CollectorConfig,
    CollectorRecord, RunningCollector, BrowserEvent, COLLECTOR_JSON, COLLECTOR_TOKEN,
    MAX_PORT_ATTEMPTS,
};
pub use egress::{EgressAllowlist, EgressDenied};
pub use error::CollectorError;
pub use injected::InjectedJsAdapter;
pub use schrute_mcp::{McpTransport, SchruteAdapter, SchruteError, SchruteOp, StdioTransport};
pub use token::{IngestToken, TokenMode, ENV_VAR as INGEST_TOKEN_ENV};
