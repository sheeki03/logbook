//! OpenInference re-keyer (plan §8).
//!
//! [OpenInference] is the span convention used by Arize Phoenix. It is itself
//! OTel-span-shaped, so we keep the OTLP envelope (trace/span ids, timings,
//! status) and re-key the **attributes** onto OpenInference's namespaces:
//!
//! - `openinference.span.kind` — `LLM` / `TOOL` / `AGENT` / `CHAIN` / ...
//! - `llm.model_name`, `llm.provider`, `llm.token_count.{prompt,completion,total}`
//! - `tool.name`
//! - `input.value` / `input.mime_type`, `output.value` / `output.mime_type`
//!
//! [OpenInference]: https://github.com/Arize-ai/openinference

use serde_json::{json, Map, Value};

use crate::adapter::SpanExportAdapter;
use crate::error::Result;
use crate::otel::{span_kind_otlp, str_attr, CanonicalSpan};

/// Re-keys canonical spans into the OpenInference convention.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenInferenceAdapter;

impl SpanExportAdapter for OpenInferenceAdapter {
    fn target(&self) -> &'static str {
        "openinference"
    }

    fn span_to_json(&self, span: &CanonicalSpan) -> Result<Value> {
        let a = &span.attributes;
        let mut attrs = Map::new();

        // The defining OpenInference attribute.
        attrs.insert(
            "openinference.span.kind".into(),
            json!(span_kind(span)),
        );

        // LLM attributes.
        if let Some(m) = str_attr(a, "gen_ai.request.model") {
            attrs.insert("llm.model_name".into(), json!(m));
        }
        if let Some(p) = str_attr(a, "gen_ai.system") {
            attrs.insert("llm.provider".into(), json!(p));
        }
        if let Some(t) = a.get("gen_ai.request.temperature") {
            // OpenInference carries invocation params as a JSON string.
            attrs.insert(
                "llm.invocation_parameters".into(),
                json!(json!({ "temperature": t }).to_string()),
            );
        }
        if let Some(v) = a.get("gen_ai.usage.input_tokens") {
            attrs.insert("llm.token_count.prompt".into(), v.clone());
        }
        if let Some(v) = a.get("gen_ai.usage.output_tokens") {
            attrs.insert("llm.token_count.completion".into(), v.clone());
        }
        if let Some(v) = a.get("gen_ai.usage.total_tokens") {
            attrs.insert("llm.token_count.total".into(), v.clone());
        }

        // Tool attributes.
        if let Some(n) = str_attr(a, "gen_ai.tool.name") {
            attrs.insert("tool.name".into(), json!(n));
        }
        if let Some(args) = str_attr(a, "gen_ai.tool.arguments") {
            attrs.insert("tool.parameters".into(), json!(args));
        }

        // Input / output values (OpenInference treats these as first-class).
        if let Some(input) = str_attr(a, "logbook.input") {
            attrs.insert("input.value".into(), json!(input));
            attrs.insert("input.mime_type".into(), json!(mime_for(input)));
        }
        if let Some(output) = str_attr(a, "logbook.output") {
            attrs.insert("output.value".into(), json!(output));
            attrs.insert("output.mime_type".into(), json!(mime_for(output)));
        }

        // Carry the logbook category through for filtering in Phoenix.
        if let Some(cat) = str_attr(a, "logbook.category") {
            attrs.insert("logbook.category".into(), json!(cat));
        }

        let mut obj = Map::new();
        obj.insert("trace_id".into(), json!(span.trace_id));
        obj.insert("span_id".into(), json!(span.span_id));
        if let Some(parent) = &span.parent_span_id {
            obj.insert("parent_id".into(), json!(parent));
        }
        obj.insert("name".into(), json!(span.name));
        obj.insert("span_kind".into(), json!(span_kind_otlp(&span.kind)));
        obj.insert("start_time_unix_nano".into(), json!(span.start_unix_nano.to_string()));
        obj.insert("end_time_unix_nano".into(), json!(span.end_unix_nano.to_string()));
        obj.insert("status_code".into(), json!(span.status_code.as_bare_str()));
        if let Some(msg) = &span.status_message {
            obj.insert("status_message".into(), json!(msg));
        }
        obj.insert("attributes".into(), Value::Object(attrs));

        Ok(Value::Object(obj))
    }
}

/// The OpenInference span kind, derived from the canonical `logbook.kind`
/// attribute (which mirrors [`logbook_core::Kind`]).
fn span_kind(span: &CanonicalSpan) -> &'static str {
    match str_attr(&span.attributes, "logbook.kind") {
        Some("llm") => "LLM",
        Some("tool") => "TOOL",
        Some("agent") => "AGENT",
        Some("network") | Some("browser") => "CHAIN",
        Some("finding") => "CHAIN",
        _ => "CHAIN",
    }
}

/// Best-effort MIME type for an input/output payload string: `application/json`
/// when it parses as JSON, else `text/plain`.
fn mime_for(s: &str) -> &'static str {
    let t = s.trim_start();
    if (t.starts_with('{') || t.starts_with('[')) && serde_json::from_str::<Value>(s).is_ok() {
        "application/json"
    } else {
        "text/plain"
    }
}
