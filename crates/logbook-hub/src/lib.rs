//! `logbook-hub` — optional central receiver. **v1.5; stub in v1.**
//!
//! Planned responsibilities (plan §10):
//! - Shares `core` + `store`; an opt-in forwarder (bearer + project id,
//!   idempotent upsert on `id`) pushes from the local plane. Local stays the
//!   source of truth.
//! - Hub adds the receiver, RBAC, retention, audit, and a dashboard (reuses the
//!   UI). Fleet inventory (multi-endpoint roll-up of §7b) lives here.
//!
//! Intentionally empty in v1 — kept as a compiling stub.

#![forbid(unsafe_code)]
