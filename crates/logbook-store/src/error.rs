//! Store error type.

use thiserror::Error;

/// Errors originating in `logbook-store`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A SQLite operation failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A schema migration failed.
    #[error("migration error: {0}")]
    Migration(#[from] refinery::Error),

    /// (De)serialization of an event body failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A filesystem operation (JSONL fallback, db dir creation) failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The single-writer task channel was closed (writer dropped / panicked).
    #[error("store writer channel closed")]
    WriterGone,

    /// A blocking read task panicked or was cancelled.
    #[error("store read task failed: {0}")]
    ReadTask(String),

    /// An error bubbled up from `logbook-core` (e.g. id parsing).
    #[error(transparent)]
    Core(#[from] logbook_core::CoreError),
}

/// Convenience alias for results in this crate.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;
