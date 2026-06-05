//! `logbook-core` — the event model, identifiers, secret redaction, and error
//! types shared across the logbook workspace (plan §2, §9).
//!
//! This crate is deliberately dependency-light and side-effect-free (no I/O, no
//! async): it defines the [`Event`] spine that every other crate produces and
//! consumes, the W3C-trace-context-width [`TraceId`] / [`SpanId`] generators,
//! the session/run/event newtypes, and the [`Redactor`] that scrubs secrets at
//! capture **before** anything is persisted.
//!
//! # Quick tour
//! ```
//! use logbook_core::{Event, Kind, Category, Status, TraceId, Redactor};
//!
//! // Mint a correlated trace and an event on it.
//! let trace = TraceId::new();
//! let ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout")
//!     .with_name("build started")
//!     .with_status(Status::Ok);
//! assert_eq!(ev.trace_id, trace);
//!
//! // Redaction is on by default.
//! let r = Redactor::new();
//! let safe = r.redact("token AKIAIOSFODNN7EXAMPLE");
//! assert!(!safe.contains("AKIAIOSFODNN7EXAMPLE"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capture_policy;
pub mod config;
pub mod correlation;
pub mod error;
pub mod event;
pub mod ids;
pub mod redact;
pub mod session;
pub mod text;
pub mod time;

// Flat re-exports for the common surface so downstream crates can
// `use logbook_core::{Event, TraceId, Redactor, ...}`.
pub use capture_policy::{
    CapturePolicy, CaptureState, CaptureStateClasses, ClassRule, ClassRules, CliOverlay,
    RedactionMode, SensitivityClass, Tiers, CAPTURE_STATE_FILENAME,
};
pub use config::{LogbookConfig, CONFIG_FILENAME, INVENTORY_WATCH_WRITE};
pub use correlation::{parse_trace, trace_from_env, SESSION_ENV, TRACE_ENV, TRACE_HEADER};
pub use error::{CoreError, Result};
pub use event::{
    AgentBlock, Blocks, Category, ConsoleBlock, Event, FindingBlock, Kind, LlmBlock,
    MicrosTimestamp, NetworkBlock, Severity, Status, ToolBlock,
};
pub use ids::{SpanId, TraceId};
pub use redact::{Redactor, SecretKind};
pub use session::{EventId, RunId, SessionId};
pub use text::{ceil_char_boundary, floor_char_boundary, truncate_with_ellipsis};
pub use time::{civil_from_days, format_rfc3339_millis};
