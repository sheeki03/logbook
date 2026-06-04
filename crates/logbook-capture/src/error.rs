//! Error type for the capture pipeline.

use thiserror::Error;

/// Errors originating in `logbook-capture`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// The capture pipeline only runs on POSIX terminals (macOS / Linux).
    #[error("logbook capture currently requires a POSIX terminal (macOS/Linux)")]
    UnsupportedPlatform,

    /// No command was supplied to run.
    #[error("no command supplied to run")]
    EmptyCommand,

    /// `tail` could not find a matching log file (carries the friendly message).
    #[error("{0}")]
    NotFound(String),

    /// Opening or driving the PTY failed.
    #[error("pty error: {0}")]
    Pty(String),

    /// The wrapped command could not be spawned.
    #[error("failed to spawn command {command:?}: {source}")]
    Spawn {
        /// The command that failed to spawn.
        command: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The OS process table could not be read for descendant discovery.
    #[error("could not read process table: {0}")]
    ProcTable(String),

    /// Sending a signal to a process failed (other than "no such process").
    #[error("failed to send signal {signal} to pid {pid}: {source}")]
    Signal {
        /// Target PID.
        pid: i32,
        /// Signal number.
        signal: i32,
        /// The underlying `nix` errno.
        #[source]
        source: nix::errno::Errno,
    },

    /// A filesystem operation failed (log files, run index, capture temp).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The event store rejected a write.
    #[error("store error: {0}")]
    Store(#[from] logbook_store::StoreError),

    /// A core error bubbled up (id parsing, redaction pattern, ...).
    #[error("core error: {0}")]
    Core(#[from] logbook_core::CoreError),
}

/// Convenience alias for results in this crate.
pub type Result<T, E = CaptureError> = std::result::Result<T, E>;
