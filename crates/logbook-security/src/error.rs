//! Error type for `logbook-security`.
//!
//! Note the deliberate distinction between **hard errors** (modelled here) and
//! **soft degradation**. A *missing scanner binary* is **not** an error: it is
//! recorded as a [`crate::ScanNote`] on the [`crate::ScanReport`] and the scan
//! continues (plan §7a, §9.1 — "missing binary = soft-degrade, not error").
//! Hard errors are reserved for things the caller genuinely cannot recover
//! from: malformed SARIF/JSON we were explicitly asked to import, an I/O
//! failure reading a report file, or a store write failure.

use thiserror::Error;

/// Errors originating in `logbook-security`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecurityError {
    /// A scanner / report file could not be read.
    #[error("failed to read {path}: {source}")]
    ReadFile {
        /// The path we tried to read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A scanner subprocess could not be spawned for a reason *other* than the
    /// binary being absent (e.g. a permissions problem). A missing binary is
    /// soft-degraded instead and never reaches this variant.
    #[error("failed to spawn {tool} ({program:?}): {source}")]
    Spawn {
        /// The logical scanner name (`semgrep`, `trivy`, `cargo-audit`).
        tool: String,
        /// The program path we attempted to execute.
        program: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A document we were asked to import as SARIF / scanner JSON did not parse.
    #[error("failed to parse {format} document: {source}")]
    Parse {
        /// The format we were trying to parse (`sarif`, `semgrep`, `trivy`,
        /// `cargo-audit`).
        format: String,
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// The imported document parsed as JSON but did not have the structure we
    /// expect for the named format.
    #[error("{format} document is not in the expected shape: {detail}")]
    Shape {
        /// The format we were trying to interpret.
        format: String,
        /// What was wrong.
        detail: String,
    },

    /// Persisting findings / events to the store failed.
    #[error("store error: {0}")]
    Store(#[from] logbook_store::StoreError),

    /// An error bubbled up from `logbook-core`.
    #[error(transparent)]
    Core(#[from] logbook_core::CoreError),
}

/// Convenience alias for results in this crate.
pub type Result<T, E = SecurityError> = std::result::Result<T, E>;
