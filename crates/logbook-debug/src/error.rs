//! Error type for `logbook-debug`.

use thiserror::Error;

/// Errors originating in the debug crate (session lifecycle, passive evidence
/// queries, and the alpha DAP logpoint client).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DebugError {
    /// A store read/write failed while managing the `debug_sessions` lifecycle
    /// or querying captured evidence.
    #[error("store error: {0}")]
    Store(#[from] logbook_store::StoreError),

    /// The referenced debug session does not exist (or was already ended).
    #[error("unknown debug session: {0}")]
    UnknownSession(String),

    /// An operation was attempted on a session in the wrong lifecycle state.
    #[error("debug session {id} is {actual}, not {expected}")]
    WrongState {
        /// The session id.
        id: String,
        /// The state the session was actually in.
        actual: String,
        /// The state the operation required.
        expected: String,
    },

    /// A DAP logpoint operation was requested but the session is not in DAP
    /// (alpha) mode — or DAP support is not enabled for this session.
    #[error("debug session {0} is not in DAP mode; logpoints require mode=dap")]
    NotDapMode(String),

    /// An I/O error talking to the debug adapter (connect, read, write).
    #[error("dap io error: {0}")]
    DapIo(#[from] std::io::Error),

    /// The debug adapter sent a malformed or unexpected message.
    #[error("dap protocol error: {0}")]
    DapProtocol(String),

    /// A DAP request returned `success: false`.
    #[error("dap request {command:?} failed: {message}")]
    DapRequestFailed {
        /// The command that failed (e.g. `setBreakpoints`).
        command: String,
        /// The adapter-supplied failure message.
        message: String,
    },

    /// Timed out waiting for a DAP response or event.
    #[error("dap timeout after {0:?}")]
    DapTimeout(std::time::Duration),

    /// (De)serialization of a DAP message or evidence payload failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// An id supplied by the caller was not valid (e.g. a malformed trace id).
    #[error("core error: {0}")]
    Core(#[from] logbook_core::CoreError),
}

/// Convenience alias for results in this crate.
pub type Result<T, E = DebugError> = std::result::Result<T, E>;
