//! Langfuse re-keyer (plan §8).
//!
//! [Langfuse] models a trace as a tree of **observations**. We re-key each
//! canonical span into one observation:
//!
//! - `type` — `GENERATION` (LLM calls) | `EVENT` (zero-duration logs/findings)
//!   | `SPAN` (everything else)
//! - `id` / `traceId` / `parentObservationId`
//! - `name`, `startTime` / `endTime` (ISO-8601 UTC)
//! - `model`, `modelParameters`, `usage` `{input, output, total, unit}`
//! - `input` / `output`, `level` (`DEFAULT`/`WARNING`/`ERROR`), `statusMessage`
//! - `metadata` — the remaining canonical attributes
//!
//! We intentionally implement **only the tracing schema** — no prompt
//! management, evals, datasets, scores, or annotations (plan §8 "Do NOT take").
//!
//! [Langfuse]: https://langfuse.com

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::adapter::SpanExportAdapter;
use crate::error::Result;
use crate::otel::{parse_or_string, str_attr, CanonicalSpan};

/// Re-keys canonical spans into Langfuse observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct LangfuseAdapter;

impl SpanExportAdapter for LangfuseAdapter {
    fn target(&self) -> &'static str {
        "langfuse"
    }

    fn span_to_json(&self, span: &CanonicalSpan) -> Result<Value> {
        let a = &span.attributes;
        let mut obj = Map::new();

        let obs_type = observation_type(span);
        obj.insert("type".into(), json!(obs_type));
        obj.insert("id".into(), json!(span.span_id));
        obj.insert("traceId".into(), json!(span.trace_id));
        if let Some(parent) = &span.parent_span_id {
            obj.insert("parentObservationId".into(), json!(parent));
        }
        obj.insert("name".into(), json!(span.name));
        obj.insert("startTime".into(), json!(iso8601(span.start_unix_nano)));
        obj.insert("endTime".into(), json!(iso8601(span.end_unix_nano)));

        // Generation-specific fields.
        if obs_type == "GENERATION" {
            if let Some(m) = str_attr(a, "gen_ai.request.model") {
                obj.insert("model".into(), json!(m));
            }
            if let Some(t) = a.get("gen_ai.request.temperature") {
                obj.insert("modelParameters".into(), json!({ "temperature": t }));
            }
            let usage = usage_obj(a);
            if !usage.is_empty() {
                obj.insert("usage".into(), Value::Object(usage));
            }
        }

        // Input / output (parsed back to JSON when they are JSON strings).
        if let Some(input) = str_attr(a, "logbook.input") {
            obj.insert("input".into(), parse_or_string(input));
        }
        if let Some(output) = str_attr(a, "logbook.output") {
            obj.insert("output".into(), parse_or_string(output));
        }

        // Level + status message.
        obj.insert("level".into(), json!(level(span)));
        if let Some(msg) = &span.status_message {
            obj.insert("statusMessage".into(), json!(msg));
        }

        // Everything else → metadata (deterministic order via BTreeMap).
        let metadata = metadata(a);
        if !metadata.is_empty() {
            obj.insert("metadata".into(), Value::Object(metadata));
        }

        Ok(Value::Object(obj))
    }
}

/// Langfuse observation type from the canonical kind.
fn observation_type(span: &CanonicalSpan) -> &'static str {
    match str_attr(&span.attributes, "logbook.kind") {
        Some("llm") => "GENERATION",
        // A point-in-time signal (no duration) is an EVENT; a log line or a
        // finding is naturally event-shaped.
        Some("log") | Some("finding") => "EVENT",
        _ => "SPAN",
    }
}

/// Build the Langfuse `usage` object from GenAI token attributes.
fn usage_obj(a: &BTreeMap<String, Value>) -> Map<String, Value> {
    let mut usage = Map::new();
    if let Some(v) = a.get("gen_ai.usage.input_tokens") {
        usage.insert("input".into(), v.clone());
    }
    if let Some(v) = a.get("gen_ai.usage.output_tokens") {
        usage.insert("output".into(), v.clone());
    }
    if let Some(v) = a.get("gen_ai.usage.total_tokens") {
        usage.insert("total".into(), v.clone());
    }
    if !usage.is_empty() {
        usage.insert("unit".into(), json!("TOKENS"));
    }
    usage
}

/// Langfuse log level from span status.
fn level(span: &CanonicalSpan) -> &'static str {
    use crate::otel::OtelStatusCode::Error;
    if span.status_code == Error {
        "ERROR"
    } else if matches!(
        str_attr(&span.attributes, "log.level"),
        Some("warn") | Some("warning")
    ) {
        "WARNING"
    } else {
        "DEFAULT"
    }
}

/// Build the `metadata` object: every canonical attribute except those already
/// promoted to dedicated Langfuse fields.
fn metadata(a: &BTreeMap<String, Value>) -> Map<String, Value> {
    const PROMOTED: &[&str] = &[
        "gen_ai.request.model",
        "gen_ai.response.model",
        "gen_ai.request.temperature",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.total_tokens",
        "logbook.input",
        "logbook.output",
    ];
    let mut m = Map::new();
    for (k, v) in a {
        if PROMOTED.contains(&k.as_str()) {
            continue;
        }
        m.insert(k.clone(), v.clone());
    }
    m
}

/// Format nanoseconds-since-epoch as an ISO-8601 UTC timestamp with
/// millisecond precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
///
/// Delegates to the shared, dependency-free
/// [`logbook_core::format_rfc3339_millis`] (the single home for the
/// civil-from-days date math previously copied into this crate) after reducing
/// the nanosecond instant to whole milliseconds.
fn iso8601(unix_nano: u128) -> String {
    let millis = i64::try_from(unix_nano / 1_000_000).unwrap_or(i64::MAX);
    logbook_core::format_rfc3339_millis(millis)
}
