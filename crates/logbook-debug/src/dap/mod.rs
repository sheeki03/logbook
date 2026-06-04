//! Tier 2 (**alpha**) — a minimal Debug Adapter Protocol client for logpoints.
//!
//! See [`client::DapClient`] for the connection + handshake + logpoint flow,
//! [`logpoint::Logpoint`] for the logpoint descriptor, and [`protocol`] for the
//! `Content-Length` wire framing and message types.
//!
//! The whole point of this tier is **non-invasive** runtime evidence: a
//! logpoint logs an expression at `file:line` *without stopping execution* and
//! *without editing source*. The reliable default remains the Tier-1 passive
//! query (see [`crate::evidence`]).

pub mod client;
pub mod logpoint;
pub mod protocol;

pub use client::{ChannelSink, DapClient, EventSink, Transport, DEFAULT_REQUEST_TIMEOUT};
pub use logpoint::Logpoint;
