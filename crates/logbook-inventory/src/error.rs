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

    /// The PTY capture pipeline (transcript + line-events) failed while running
    /// the wrapped agent.
    #[error("capture pipeline failed for {command:?}: {source}")]
    Capture {
        /// The command line that failed.
        command: String,
        /// The underlying capture error.
        #[source]
        source: logbook_capture::CaptureError,
    },

    /// `--reversible` (encrypted dirty-tree preimages) was requested but is not
    /// yet available. The clean-tree path is always revertable via git itself;
    /// only the dirty-tree opt-in is pending key management.
    #[error(
        "reversible dirty-tree capture is not yet available \
         (encrypted-preimage key management pending)"
    )]
    ReversibleUnavailable,

    /// A `logbook revert <session>` named a session that has no recorded
    /// `agent_sessions` row (typo, already forgotten, or never captured here).
    #[error("no recorded session with id {0:?} to revert")]
    SessionNotFound(String),

    /// A governance verb (`logbook forget <session>`) was handed a session id
    /// that is not a well-formed id (empty, contains a path separator or a `..`
    /// component, is absolute, or is not the 32-hex-char shape
    /// [`logbook_core::SessionId::generate`] mints). Refused before any
    /// filesystem deletion so a crafted id (e.g. `../../etc`) can never reach a
    /// `remove_dir_all` outside the out-dir.
    #[error(
        "invalid session id {0:?}: a session id must be a 32-character hex string \
         (no path separators, no `..`, not absolute)"
    )]
    InvalidSessionId(String),

    /// `git` could not be run (or exited non-zero) while reverting a file. The
    /// command line and git's stderr are surfaced so the user can see exactly
    /// which restore failed. Revert is conservative: a single git failure aborts
    /// that file's restore and is reported as a refusal, never a partial write.
    #[error("git {operation} failed for {path:?}: {detail}")]
    GitRevert {
        /// The git operation attempted (e.g. `checkout HEAD --`).
        operation: String,
        /// The repo-relative path being restored.
        path: String,
        /// git's stderr (or the spawn error), already trimmed.
        detail: String,
    },

    /// A capture flag was passed that has no mechanism wired here yet. As of
    /// Phase 2 the structured tier has landed (`--capture-prompts` / `--tier
    /// structured` are accepted), so only `--tier complete` (the Phase-4
    /// raw-provider-traffic tier) and an unrecognized `--tier` value are
    /// rejected — rather than silently no-op'd so the user is not misled.
    #[error(
        "{flag} is not available: the complete tier (full provider traffic) is \
         opt-in by mechanism and ships in Phase 4"
    )]
    UnsupportedFlag {
        /// The rejected flag (e.g. `--tier complete`).
        flag: String,
    },
}

/// Convenience alias for results in this crate.
pub type Result<T, E = InventoryError> = std::result::Result<T, E>;
