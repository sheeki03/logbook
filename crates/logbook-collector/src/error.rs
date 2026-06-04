//! Error type for the collector crate.

use std::net::IpAddr;
use std::path::PathBuf;

use thiserror::Error;

/// Errors raised while starting or running the collector.
#[derive(Debug, Error)]
pub enum CollectorError {
    /// The configured bind host is not a loopback address. The collector only
    /// ever binds `127.0.0.1`/`::1` (plan §9).
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
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `LOGBOOK_INGEST_TOKEN` was required (`token_mode = env`) but unset or
    /// empty.
    #[error("token_mode=env but LOGBOOK_INGEST_TOKEN is unset or empty")]
    MissingEnvToken,

    /// Entropy was unavailable while generating a token.
    #[error("failed to generate ingest token: {0}")]
    TokenGeneration(String),

    /// The CORS dev origin could not be parsed into a header value.
    #[error("invalid CORS dev origin: {0}")]
    BadOrigin(String),

    /// Writing `collector.json` failed.
    #[error("failed to write collector.json: {0}")]
    WriteRecord(String),

    /// Writing `collector.token` failed.
    #[error("failed to write collector.token: {0}")]
    WriteToken(String),
}
