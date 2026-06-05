//! Error type for the hub crate.

use std::net::IpAddr;

use thiserror::Error;

/// Errors raised while starting or running the hub (plan "Phase 4 — Complete
/// Tier & Fleet" → Hub).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HubError {
    /// The configured bind host is not a loopback address. Like the collector,
    /// the hub only ever binds `127.0.0.1`/`::1` (plan §9, local-only).
    #[error("refusing to bind non-loopback host {0}")]
    NonLoopbackBind(IpAddr),

    /// No port in the auto-increment range could be bound.
    #[error("failed to bind a port starting at {port}: {source}")]
    Bind {
        /// The preferred port that was attempted first.
        port: u16,
        /// The underlying I/O error from the last attempt.
        #[source]
        source: std::io::Error,
    },

    /// The out-dir could not be created.
    #[error("failed to create out-dir {path}: {source}")]
    OutDir {
        /// The out-dir path.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A hub bearer token was required (`token_mode = env`) but unset or empty.
    #[error("token_mode=env but {var} is unset or empty")]
    MissingEnvToken {
        /// The environment variable that was consulted.
        var: &'static str,
    },

    /// Entropy was unavailable while generating a token.
    #[error("failed to generate hub token: {0}")]
    TokenGeneration(String),

    /// The CORS dev origin could not be parsed into a header value.
    #[error("invalid CORS dev origin: {0}")]
    BadOrigin(String),

    /// The event/inventory store reported an error.
    #[error("store error: {0}")]
    Store(#[from] logbook_store::StoreError),
}

/// Result alias for the hub crate.
pub type Result<T> = std::result::Result<T, HubError>;
