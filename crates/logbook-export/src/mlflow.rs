//! MLflow Tracing re-keyer (plan §8).
//!
//! [MLflow Tracing] models a trace as a list of spans. We re-key each canonical
//! span into one MLflow span:
//!
//! - `name`
//! - `context` `{trace_id, span_id}`, `parent_id`
//! - `start_time_ns` / `end_time_ns` (integer nanoseconds)
//! - `status_code` (`OK`/`ERROR`/`UNSET`) + `status_message`
//! - `span_type` — `LLM` / `TOOL` / `AGENT` / `SECURITY` / `CHAIN` / `UNKNOWN`
//! - `attributes` — remaining canonical attributes, plus the `mlflow.*`
//!   reserved keys (`mlflow.spanType`, `mlflow.spanInputs`, `mlflow.spanOutputs`).
//!   Span I/O lives ONLY in `mlflow.span{Inputs,Outputs}` — not duplicated as
//!   top-level `inputs`/`outputs` (MLflow expects one form, not both)
//!
//! Tracing schema only — no MLflow models, runs, experiments, or model
//! registry (plan §8 "Do NOT take").
//!
//! [MLflow Tracing]: https://mlflow.org/docs/latest/llms/tracing/index.html

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::adapter::SpanExportAdapter;
use crate::error::Result;
use crate::otel::{parse_or_string, str_attr, CanonicalSpan};

/// Re-keys canonical spans into MLflow spans.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlflowAdapter;

impl SpanExportAdapter for MlflowAdapter {
    fn target(&self) -> &'static str {
        "mlflow"
    }

    fn span_to_json(&self, span: &CanonicalSpan) -> Result<Value> {
        let a = &span.attributes;
        let span_type = span_type(span);

        let mut obj = Map::new();
        obj.insert("name".into(), json!(span.name));
        obj.insert(
            "context".into(),
            json!({ "trace_id": span.trace_id, "span_id": span.span_id }),
        );
        // MLflow uses JSON null for a root span's parent.
        obj.insert(
            "parent_id".into(),
            span.parent_span_id
                .as_ref()
                .map_or(Value::Null, |p| json!(p)),
        );
        obj.insert("start_time_ns".into(), json!(clamp_i64(span.start_unix_nano)));
        obj.insert("end_time_ns".into(), json!(clamp_i64(span.end_unix_nano)));
        obj.insert("status_code".into(), json!(span.status_code.as_bare_str()));
        obj.insert(
            "status_message".into(),
            span.status_message
                .as_ref()
                .map_or(Value::String(String::new()), |m| json!(m)),
        );
        obj.insert("span_type".into(), json!(span_type));

        // Span I/O is surfaced ONLY via the reserved mlflow.span{Inputs,Outputs}
        // attributes (the form MLflow uses for OTel / third-party ingestion) —
        // not duplicated as top-level inputs/outputs (MLflow expects one form).
        let inputs = str_attr(a, "logbook.input").map(parse_or_string);
        let outputs = str_attr(a, "logbook.output").map(parse_or_string);

        // Attributes block, including the reserved mlflow.* keys.
        let mut attrs = build_attributes(a);
        attrs.insert("mlflow.spanType".into(), json!(span_type));
        if let Some(inp) = inputs {
            attrs.insert("mlflow.spanInputs".into(), inp);
        }
        if let Some(out) = outputs {
            attrs.insert("mlflow.spanOutputs".into(), out);
        }
        obj.insert("attributes".into(), Value::Object(attrs));

        Ok(Value::Object(obj))
    }
}

/// MLflow span type from the canonical kind.
fn span_type(span: &CanonicalSpan) -> &'static str {
    match str_attr(&span.attributes, "logbook.kind") {
        Some("llm") => "LLM",
        Some("tool") => "TOOL",
        Some("agent") => "AGENT",
        // Browser/network requests map to TOOL (MLflow's closest built-in for an
        // external call); security findings get a custom SECURITY span type
        // (MLflow allows custom string types) rather than the sequence-oriented CHAIN.
        Some("network") | Some("browser") => "TOOL",
        Some("finding") => "SECURITY",
        _ => "UNKNOWN",
    }
}

/// Build the MLflow `attributes` map from the canonical attributes, excluding
/// the input/output payloads (surfaced via the reserved
/// `mlflow.span{Inputs,Outputs}` attribute keys).
fn build_attributes(a: &BTreeMap<String, Value>) -> Map<String, Value> {
    const EXCLUDED: &[&str] = &["logbook.input", "logbook.output"];
    let mut m = Map::new();
    for (k, v) in a {
        if EXCLUDED.contains(&k.as_str()) {
            continue;
        }
        m.insert(k.clone(), v.clone());
    }
    m
}

/// Clamp a `u128` nanosecond value into the `i64` range MLflow uses.
fn clamp_i64(v: u128) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}
