//! Core error type shared across logbook crates.

use thiserror::Error;

/// Errors originating in `logbook-core` (event model, ids, redaction).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A hex id string was not the expected width or contained non-hex bytes.
    #[error("invalid id: expected {expected} lowercase hex chars, got {got:?}")]
    InvalidId {
        /// Expected number of hex characters (32 for trace, 16 for span).
        expected: usize,
        /// The offending input.
        got: String,
    },

    /// The OS entropy source failed while generating an id.
    #[error("failed to obtain randomness for id generation: {0}")]
    Entropy(String),

    /// A redaction pattern supplied by the user failed to compile.
    #[error("invalid redaction pattern {pattern:?}: {source}")]
    BadPattern {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying regex error.
        #[source]
        source: regex::Error,
    },

    /// (De)serialization of an event or block failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A severity token did not match a known [`Severity`](crate::Severity)
    /// wire value.
    #[error("unknown severity: {0:?}")]
    BadSeverity(String),

    /// An [`Event`](crate::Event) failed a cross-field invariant check (see
    /// [`Event::validate`](crate::Event::validate)).
    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

/// Convenience alias for results in this crate.
pub type Result<T, E = CoreError> = std::result::Result<T, E>;
