//! `logbook-export` — span export (plan §8).
//!
//! Maps the unified logbook [`Event`](logbook_core::Event) model onto tracing
//! schemas. The design is a **canonical hub + re-keyers**:
//!
//! 1. Every `Event` is lowered to a single [`CanonicalSpan`] (an in-memory OTLP
//!    span whose attributes follow OpenTelemetry semantic conventions —
//!    notably the GenAI `gen_ai.*` conventions). This is the *one* place the
//!    event model is interpreted.
//! 2. Each [`SpanExportAdapter`] then **re-keys** that canonical span into its
//!    target schema's JSON shape: [`OtelAdapter`] (OTLP/JSON),
//!    [`OpenInferenceAdapter`], [`LangfuseAdapter`], [`MlflowAdapter`].
//!
//! **v1 scope is schema + golden tests only** — there is no network export
//! (that is v1.5). And per plan §8 we take only the *tracing schema* of
//! Langfuse / Phoenix / MLflow: **no** prompt management, evals, datasets,
//! annotations, replay, or cost dashboards.
//!
//! # Example
//! ```
//! use logbook_core::{Event, Kind, Category, TraceId, LlmBlock};
//! use logbook_export::{SpanExportAdapter, OpenInferenceAdapter};
//!
//! let ev = Event::new(TraceId::new(), Kind::Llm, Category::Agent, "chat.completion")
//!     .with_llm(LlmBlock { model: Some("gpt-4o".into()), ..Default::default() });
//!
//! let span = OpenInferenceAdapter.event_to_json(&ev).unwrap();
//! assert_eq!(span["attributes"]["openinference.span.kind"], "LLM");
//! assert_eq!(span["attributes"]["llm.model_name"], "gpt-4o");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapter;
pub mod error;
pub mod langfuse;
pub mod mlflow;
pub mod openinference;
pub mod otel;
pub mod otel_adapter;

pub use adapter::SpanExportAdapter;
pub use error::{ExportError, Result};
pub use langfuse::LangfuseAdapter;
pub use mlflow::MlflowAdapter;
pub use openinference::OpenInferenceAdapter;
pub use otel::{
    span_to_otlp_json, spans_to_otlp_document, to_canonical, CanonicalSpan, OtelStatusCode,
};
pub use otel_adapter::OtelAdapter;
