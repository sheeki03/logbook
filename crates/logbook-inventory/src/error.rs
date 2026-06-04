//! Error type for `logbook-inventory`.

use thiserror::Error;

/// Errors originating in the inventory crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InventoryError {
    /// A filesystem operation failed (reading a config, walking a tree, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The event/inventory store reported an error.
    #[error("store error: {0}")]
    Store(#[from] logbook_store::StoreError),

    /// A core operation (id parse, redaction pattern) failed.
    #[error("core error: {0}")]
    Core(#[from] logbook_core::CoreError),

    /// JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A continuous `inventory watch` was requested but writes are not enabled.
    ///
    /// `inventory watch` is the only continuous, opt-in surface; per plan §7b /
    /// §9.1 it requires `enabled_writes` to include `inventory_watch`. `scan` and
    /// `report` are always allowed (read-only, user-triggered).
    #[error(
        "`inventory watch` requires permission: add \"inventory_watch\" to \
         [permissions].enabled_writes in logbook.toml (scan/report do not need it)"
    )]
    WatchNotEnabled,

    /// The `logbook agent <cli>` wrapper could not launch the agent binary.
    #[error("could not run agent command {command:?}: {source}")]
    AgentSpawn {
        /// The command line that failed.
        command: String,
        /// The underlying spawn error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience alias for results in this crate.
pub type Result<T, E = InventoryError> = std::result::Result<T, E>;
