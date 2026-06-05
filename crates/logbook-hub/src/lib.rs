//! `logbook-hub` — the fleet **receiver** + **governance plane** (plan
//! "Phase 4 — Complete Tier & Fleet" → Hub).
//!
//! The local plane (`logbook run`/`agent`, the collector) stays the source of
//! truth; the hub is an **opt-in central receiver** many endpoints forward into.
//! It reuses `logbook-core` + `logbook-store` and the collector's loopback +
//! bearer-token server model, and adds five governance capabilities:
//!
//! 1. **Fleet receiver** — an axum server on `127.0.0.1`, bearer-gated by a
//!    [`HubToken`]. `POST /hub/ingest` takes `{endpoint_id, events:[…]}` (a batch
//!    of already-redacted events from one endpoint) and persists them via
//!    [`Store::hub_receive`](logbook_store::Store::hub_receive) (idempotent
//!    `INSERT OR IGNORE` by id) **and** appends each newly-received event to the
//!    tamper-evident hash chain via
//!    [`append_audit`](logbook_store::append_audit).
//! 2. **RBAC** — a [`Role`] of `Viewer` or `Auditor`. A `Viewer` read returns the
//!    per-class **export projection** (reusing `logbook-inventory`'s
//!    sanitization), so a viewer never sees a payload class; an `Auditor` sees
//!    the full already-redacted rows.
//! 3. **Server-side retention** — a periodic + endpoint-triggered sweep via
//!    [`Store::prune`](logbook_store::Store::prune).
//! 4. **Tamper check** — `GET /hub/verify` runs
//!    [`verify_chain`](logbook_store::verify_chain) over the stored event bodies
//!    and reports the first chain break.
//! 5. **Multi-endpoint inventory roll-up** — [`fleet_rollup`] aggregates the
//!    discovered agents / MCP servers / sessions across endpoint ids.
//!
//! # What the hash chain proves (and what it does NOT)
//!
//! The chain is **tamper-evidence over stored, already-redacted rows** — it shows
//! a row was not altered or deleted *after* it was recorded. It does **not** prove
//! raw secrets were never captured before redaction: redaction runs upstream at
//! capture, before anything reaches a store or is forwarded to the hub. The hub
//! never sees a raw provider payload (that is exclusively the LLM proxy's
//! concern). The `secrets` marker records only that redaction *occurred*, never
//! the value (plan "Top risks & mitigations" #2).
//!
//! # Entry point
//!
//! [`run_hub`] starts the server (loopback-only, bearer-gated) and the periodic
//! retention sweep, returning a [`RunningHub`] handle.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod rbac;
pub mod rollup;
pub mod server;
pub mod token;

pub use error::{HubError, Result};
pub use rbac::{project_for_role, Role};
pub use rollup::{fleet_rollup, EndpointRollup, FleetRollup};
pub use server::{
    bind_with_auto_increment, run_hub, HubConfig, RunningHub, MAX_PORT_ATTEMPTS,
};
pub use token::{HubToken, TokenMode, HUB_TOKEN_ENV};
