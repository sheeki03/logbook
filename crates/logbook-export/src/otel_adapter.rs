//! The canonical OpenTelemetry adapter — a thin [`SpanExportAdapter`] over the
//! OTLP/JSON projection in [`crate::otel`].

use serde_json::Value;

use crate::adapter::SpanExportAdapter;
use crate::error::Result;
use crate::otel::{span_to_otlp_json, CanonicalSpan};

/// Emits the canonical OTLP/JSON span shape (the form found inside
/// `resourceSpans[].scopeSpans[].spans[]`).
#[derive(Clone, Copy, Debug, Default)]
pub struct OtelAdapter;

impl SpanExportAdapter for OtelAdapter {
    fn target(&self) -> &'static str {
        "otel"
    }

    fn span_to_json(&self, span: &CanonicalSpan) -> Result<Value> {
        Ok(span_to_otlp_json(span))
    }
}
