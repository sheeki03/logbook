//! Per-tool [`SessionSource`](crate::SessionSource) implementations.
//!
//! Each module owns the (drift-prone) on-disk storage knowledge for a single
//! tool and nothing else: it discovers sessions cheaply (stat + bounded
//! structural counts, no payload bodies) and reads one session's raw records into
//! the neutral [`SessionRecords`](crate::SessionRecords) the harness adapter
//! consumes. Sources never persist, redact, or build [`Event`](logbook_core::Event)s
//! — they move only opaque [`serde_json::Value`]s.

pub mod continue_;
pub mod cursor;
pub mod gemini;

pub use continue_::ContinueSource;
pub use cursor::CursorSource;
pub use gemini::GeminiSource;
