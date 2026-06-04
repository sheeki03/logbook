//! The [`SpanExportAdapter`] trait (plan §8).

use logbook_core::Event;
use serde_json::Value;

use crate::error::Result;
use crate::otel::{to_canonical, CanonicalSpan};

/// A span-export adapter maps the unified logbook [`Event`] model onto a
/// specific tracing schema's JSON shape.
///
/// The contract is intentionally schema-only for v1: an adapter is a pure
/// function from events to JSON, with **no network side effects** (network
/// export is a v1.5 concern). Each adapter first lowers an `Event` to the
/// shared [`CanonicalSpan`] (via [`to_canonical`]) and then re-keys it, so all
/// adapters agree on the underlying semantics.
///
/// Implementors only need to provide [`SpanExportAdapter::span_to_json`]; the
/// `event_*` methods are provided.
pub trait SpanExportAdapter {
    /// A short, stable identifier for the target schema (e.g. `"otel"`,
    /// `"openinference"`, `"langfuse"`, `"mlflow"`). Used in error messages and
    /// golden-fixture filenames.
    fn target(&self) -> &'static str;

    /// Re-key a single [`CanonicalSpan`] into this adapter's JSON shape.
    ///
    /// # Errors
    /// Returns [`ExportError`](crate::ExportError) if a field required by the
    /// target schema is absent or a value cannot be serialized.
    fn span_to_json(&self, span: &CanonicalSpan) -> Result<Value>;

    /// Convenience: lower an [`Event`] to canonical form and re-key it.
    ///
    /// # Errors
    /// Propagates any error from [`SpanExportAdapter::span_to_json`].
    fn event_to_json(&self, event: &Event) -> Result<Value> {
        let span = to_canonical(event);
        self.span_to_json(&span)
    }

    /// Convenience: map a batch of events, preserving order.
    ///
    /// # Errors
    /// Returns on the first event that fails to map.
    fn events_to_json(&self, events: &[Event]) -> Result<Vec<Value>> {
        events.iter().map(|e| self.event_to_json(e)).collect()
    }
}
