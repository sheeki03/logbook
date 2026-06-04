//! Export error type.

/// Errors that can arise while mapping an [`Event`](logbook_core::Event) to a
/// target span schema.
///
/// In v1 (schema + golden tests, no network export) the mapping is
/// infallible in practice — every `Event` maps to a span — so this is mostly a
/// forward-looking surface for v1.5 network export. It exists so adapter
/// signatures can stay fallible without a breaking change later.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// A value could not be serialized to JSON.
    #[error("failed to serialize span to JSON: {0}")]
    Serialize(#[from] serde_json::Error),

    /// The event was missing a field required by the target schema.
    #[error("event is missing field required by {target}: {field}")]
    MissingField {
        /// The export target (e.g. `langfuse`).
        target: &'static str,
        /// The missing field name.
        field: &'static str,
    },
}

/// Convenience result alias for export operations.
pub type Result<T> = std::result::Result<T, ExportError>;
