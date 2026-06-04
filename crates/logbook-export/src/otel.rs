//! The canonical OpenTelemetry layer (plan §8).
//!
//! Every [`Event`](logbook_core::Event) is first lowered to a single
//! [`CanonicalSpan`] — an in-memory representation of one OTLP span whose
//! attributes follow OpenTelemetry semantic conventions (notably the **GenAI**
//! conventions, `gen_ai.*`). This canonical span is the *one* place the unified
//! event model is interpreted; the OpenInference / Langfuse / MLflow adapters
//! are then pure **re-keyers** over it, never touching `Event` directly. That
//! keeps the three target schemas consistent with each other by construction.
//!
//! We borrow type-safe primitives from the [`opentelemetry`] API crate
//! ([`SpanKind`], status code, [`TraceId`]/[`SpanId`] for validity), but emit
//! the OTLP/JSON wire shape ourselves: the API crate deliberately ships no
//! OTLP-JSON serializer (that lives in `opentelemetry-otlp` behind
//! protobuf/tonic, which is a v1.5 network-export concern, not v1).

use std::collections::BTreeMap;

use logbook_core::{Category, Event, Kind, Status};
use opentelemetry::trace::{SpanId as OtelSpanId, SpanKind, TraceId as OtelTraceId};
use serde_json::{json, Map, Value};

/// OTLP status codes (OTLP/JSON uses the screaming-snake names).
///
/// Mirrors [`opentelemetry::trace::Status`] but as a small copyable enum we can
/// map straight onto the wire string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtelStatusCode {
    /// Not set by the application.
    Unset,
    /// Explicitly marked OK.
    Ok,
    /// Explicitly marked an error.
    Error,
}

impl OtelStatusCode {
    /// The OTLP/JSON `status.code` wire string.
    #[must_use]
    pub const fn as_otlp_str(self) -> &'static str {
        match self {
            OtelStatusCode::Unset => "STATUS_CODE_UNSET",
            OtelStatusCode::Ok => "STATUS_CODE_OK",
            OtelStatusCode::Error => "STATUS_CODE_ERROR",
        }
    }

    /// The bare status token (`UNSET` / `OK` / `ERROR`) used by the
    /// OpenInference and MLflow re-keyers (the unprefixed sibling of
    /// [`as_otlp_str`](Self::as_otlp_str)).
    #[must_use]
    pub const fn as_bare_str(self) -> &'static str {
        match self {
            OtelStatusCode::Unset => "UNSET",
            OtelStatusCode::Ok => "OK",
            OtelStatusCode::Error => "ERROR",
        }
    }
}

/// The canonical, schema-neutral representation of one span.
///
/// Field names track OTel concepts. Attributes are kept in a [`BTreeMap`] so
/// the emitted JSON is **deterministically ordered** — essential for stable
/// golden fixtures.
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalSpan {
    /// 128-bit trace id (32 lowercase hex chars).
    pub trace_id: String,
    /// 64-bit span id (16 lowercase hex chars), derived from the event id.
    pub span_id: String,
    /// Parent span id, if any (16 lowercase hex chars).
    pub parent_span_id: Option<String>,
    /// Span display name (OTel `name`).
    pub name: String,
    /// OTel span kind.
    pub kind: SpanKind,
    /// Start time, nanoseconds since the UNIX epoch (OTLP uses nanos).
    pub start_unix_nano: u128,
    /// End time, nanoseconds since the UNIX epoch (== start when no duration).
    pub end_unix_nano: u128,
    /// Status code.
    pub status_code: OtelStatusCode,
    /// Status message (the redacted error text, when errored).
    pub status_message: Option<String>,
    /// Semantic-convention attributes (`gen_ai.*`, `tool.*`, custom `logbook.*`).
    pub attributes: BTreeMap<String, Value>,
}

/// The conventional OpenTelemetry scope/instrumentation name logbook emits
/// under. Stable so golden fixtures can assert on it.
pub const SCOPE_NAME: &str = "logbook";

/// Build the canonical OTel span for an [`Event`].
#[must_use]
pub fn to_canonical(ev: &Event) -> CanonicalSpan {
    let span_id = derive_span_id(ev);
    let start_nano = micros_to_nanos(ev.timestamp.as_micros());
    let end_nano = start_nano + duration_ms_to_nanos(ev.duration_ms);

    let mut attributes = BTreeMap::new();
    // Stable classification attributes shared by every span.
    attributes.insert("logbook.kind".into(), json!(ev.kind.as_str()));
    attributes.insert("logbook.category".into(), json!(ev.category.as_str()));
    attributes.insert("logbook.type".into(), json!(ev.type_));
    attributes.insert("logbook.operation".into(), json!(ev.operation));

    if let Some(session) = &ev.session_id {
        attributes.insert("session.id".into(), json!(session.as_str()));
    }

    // Free-form event attributes pass through verbatim (already redacted).
    for (k, v) in &ev.attributes {
        attributes.insert(k.clone(), v.clone());
    }

    // Typed domain blocks → semantic-convention attributes.
    map_blocks(ev, &mut attributes);

    // Span input/output are carried as canonical attributes so each adapter can
    // re-key them to its own input/output field (OpenInference `input.value`,
    // Langfuse `input`, MLflow `inputs`). Stored as compact JSON strings.
    if let Some(input) = &ev.input {
        attributes.insert("logbook.input".into(), json!(stringify(input)));
    }
    if let Some(output) = &ev.output {
        attributes.insert("logbook.output".into(), json!(stringify(output)));
    }

    CanonicalSpan {
        trace_id: normalize_trace_id(&ev.trace_id.to_hex()),
        span_id,
        parent_span_id: ev.parent_id.as_ref().map(|p| normalize_span_id(&p.to_hex())),
        name: ev.name.clone(),
        kind: span_kind(ev),
        start_unix_nano: start_nano,
        end_unix_nano: end_nano,
        status_code: status_code(ev.status),
        status_message: if ev.status == Status::Error { ev.error.clone() } else { None },
        attributes,
    }
}

/// Lower the typed blocks of an event into OTel-convention attributes.
fn map_blocks(ev: &Event, attrs: &mut BTreeMap<String, Value>) {
    if let Some(llm) = &ev.blocks.llm {
        // GenAI semantic conventions (`gen_ai.*`).
        if let Some(p) = &llm.provider {
            attrs.insert("gen_ai.system".into(), json!(p));
        }
        if let Some(m) = &llm.model {
            attrs.insert("gen_ai.request.model".into(), json!(m));
            attrs.insert("gen_ai.response.model".into(), json!(m));
        }
        if let Some(t) = llm.temperature {
            attrs.insert("gen_ai.request.temperature".into(), json!(t));
        }
        if let Some(it) = llm.input_tokens {
            attrs.insert("gen_ai.usage.input_tokens".into(), json!(it));
        }
        if let Some(ot) = llm.output_tokens {
            attrs.insert("gen_ai.usage.output_tokens".into(), json!(ot));
        }
        if let Some(tt) = llm.total_tokens {
            attrs.insert("gen_ai.usage.total_tokens".into(), json!(tt));
        }
        if let Some(c) = llm.cost_usd {
            // Non-standard but widely understood; kept under our namespace.
            attrs.insert("logbook.llm.cost_usd".into(), json!(c));
        }
    }

    if let Some(tool) = &ev.blocks.tool {
        if let Some(n) = &tool.tool_name {
            // OTel GenAI tool convention.
            attrs.insert("gen_ai.tool.name".into(), json!(n));
        }
        if let Some(w) = tool.is_write {
            attrs.insert("logbook.tool.is_write".into(), json!(w));
        }
        if let Some(args) = &tool.arguments {
            attrs.insert("gen_ai.tool.arguments".into(), json!(stringify(args)));
        }
    }

    if let Some(agent) = &ev.blocks.agent {
        if let Some(a) = &agent.agent {
            attrs.insert("logbook.agent.name".into(), json!(a));
        }
        if let Some(s) = agent.step {
            attrs.insert("logbook.agent.step".into(), json!(s));
        }
        if let Some(r) = &agent.role {
            attrs.insert("gen_ai.operation.role".into(), json!(r));
        }
    }

    if let Some(console) = &ev.blocks.console {
        if let Some(l) = &console.level {
            attrs.insert("log.level".into(), json!(l));
        }
        if let Some(m) = &console.message {
            attrs.insert("log.message".into(), json!(m));
        }
        if let Some(u) = &console.url {
            attrs.insert("url.full".into(), json!(u));
        }
        if let Some(st) = &console.stack {
            attrs.insert("exception.stacktrace".into(), json!(st));
        }
    }

    if let Some(net) = &ev.blocks.network {
        if let Some(m) = &net.method {
            attrs.insert("http.request.method".into(), json!(m));
        }
        if let Some(u) = &net.url {
            attrs.insert("url.full".into(), json!(u));
        }
        if let Some(s) = net.status_code {
            attrs.insert("http.response.status_code".into(), json!(s));
        }
        if let Some(b) = net.request_bytes {
            attrs.insert("http.request.body.size".into(), json!(b));
        }
        if let Some(b) = net.response_bytes {
            attrs.insert("http.response.body.size".into(), json!(b));
        }
    }

    if let Some(f) = &ev.blocks.finding {
        if let Some(s) = &f.source {
            attrs.insert("logbook.finding.source".into(), json!(s));
        }
        if let Some(r) = &f.rule_id {
            attrs.insert("logbook.finding.rule_id".into(), json!(r));
        }
        if let Some(sev) = f.severity {
            attrs.insert("logbook.finding.severity".into(), json!(sev.as_str()));
        }
        if let Some(file) = &f.file {
            attrs.insert("code.filepath".into(), json!(file));
        }
        if let Some(line) = f.line {
            attrs.insert("code.lineno".into(), json!(line));
        }
        if let Some(m) = &f.message {
            attrs.insert("logbook.finding.message".into(), json!(m));
        }
    }
}

/// OTel span kind for an event. LLM/tool/agent spans are `Internal` per the
/// GenAI conventions (they model in-process work, not RPC client/server);
/// network/browser-network spans are `Client`.
fn span_kind(ev: &Event) -> SpanKind {
    match ev.kind {
        Kind::Network => SpanKind::Client,
        Kind::Browser => {
            if ev.blocks.network.is_some() {
                SpanKind::Client
            } else {
                SpanKind::Internal
            }
        }
        _ => match ev.category {
            Category::Browser if ev.blocks.network.is_some() => SpanKind::Client,
            _ => SpanKind::Internal,
        },
    }
}

/// Map the event's terminal status to an OTLP status code.
fn status_code(status: Status) -> OtelStatusCode {
    match status {
        Status::Unset => OtelStatusCode::Unset,
        Status::Ok => OtelStatusCode::Ok,
        Status::Error => OtelStatusCode::Error,
    }
}

/// The OTel `SpanKind` as the OTLP/JSON wire string.
#[must_use]
pub fn span_kind_otlp(kind: &SpanKind) -> &'static str {
    match kind {
        SpanKind::Internal => "SPAN_KIND_INTERNAL",
        SpanKind::Server => "SPAN_KIND_SERVER",
        SpanKind::Client => "SPAN_KIND_CLIENT",
        SpanKind::Producer => "SPAN_KIND_PRODUCER",
        SpanKind::Consumer => "SPAN_KIND_CONSUMER",
    }
}

/// Derive a deterministic 64-bit span id from the event id.
///
/// Event ids are 32-hex-char (trace width). A span id is 16 hex chars, so we
/// take the **first 16** when the id is already hex of the expected width, and
/// otherwise fold the bytes via the OTel [`SpanId`] type to guarantee a valid,
/// non-empty 16-char hex value.
fn derive_span_id(ev: &Event) -> String {
    let raw = ev.id.as_str();
    if raw.len() == 32 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return raw[..16].to_ascii_lowercase();
    }
    // Fold arbitrary id bytes into 8 bytes (FNV-1a) and render via OTel SpanId.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in raw.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if hash == 0 {
        hash = 1; // all-zero span id is invalid per the spec
    }
    let span = OtelSpanId::from_bytes(hash.to_be_bytes());
    format!("{span:016x}")
}

/// Render an OTel `TraceId` from a hex string, lowercased and normalized.
fn normalize_trace_id(hex: &str) -> String {
    if let Ok(bytes) = hex_to_array16(hex) {
        let id = OtelTraceId::from_bytes(bytes);
        return format!("{id:032x}");
    }
    hex.to_ascii_lowercase()
}

/// Render an OTel `SpanId` from a hex string, lowercased and normalized.
fn normalize_span_id(hex: &str) -> String {
    if let Ok(bytes) = hex_to_array8(hex) {
        let id = OtelSpanId::from_bytes(bytes);
        return format!("{id:016x}");
    }
    hex.to_ascii_lowercase()
}

fn hex_to_array16(s: &str) -> Result<[u8; 16], ()> {
    let mut out = [0u8; 16];
    decode_hex(s, &mut out)?;
    Ok(out)
}

fn hex_to_array8(s: &str) -> Result<[u8; 8], ()> {
    let mut out = [0u8; 8];
    decode_hex(s, &mut out)?;
    Ok(out)
}

fn decode_hex(s: &str, out: &mut [u8]) -> Result<(), ()> {
    if s.len() != out.len() * 2 {
        return Err(());
    }
    let b = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(b[i * 2])?;
        let lo = hex_nibble(b[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

/// Microseconds → nanoseconds (OTLP timestamps are nanos). Negative (pre-epoch)
/// values clamp to 0.
fn micros_to_nanos(micros: i64) -> u128 {
    u128::try_from(micros).unwrap_or(0) * 1_000
}

/// Convert a millisecond duration into nanoseconds, clamping NaN/negative to 0.
fn duration_ms_to_nanos(ms: Option<f64>) -> u128 {
    match ms {
        Some(v) if v.is_finite() && v > 0.0 => (v * 1_000_000.0) as u128,
        _ => 0,
    }
}

/// Compact-stringify a JSON value (used for input/output/argument payloads that
/// the OTel attribute model represents as strings).
pub(crate) fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Borrow a string-valued canonical attribute by key.
///
/// Shared by the re-keyers (OpenInference / Langfuse / MLflow), which all pull
/// string attributes off the same [`CanonicalSpan::attributes`] map.
pub(crate) fn str_attr<'a>(attrs: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    attrs.get(key).and_then(Value::as_str)
}

/// Parse a string as JSON if it is valid JSON, else keep it as a JSON string.
///
/// Used by adapters to round-trip the compact-JSON `logbook.input`/
/// `logbook.output` payloads back into structured values where the target
/// schema wants them inline.
pub(crate) fn parse_or_string(s: &str) -> Value {
    serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.to_owned()))
}

/// Render the canonical span as an OTLP/JSON span object (the form found inside
/// `resourceSpans[].scopeSpans[].spans[]`).
#[must_use]
pub fn span_to_otlp_json(span: &CanonicalSpan) -> Value {
    let mut obj = Map::new();
    obj.insert("traceId".into(), json!(span.trace_id));
    obj.insert("spanId".into(), json!(span.span_id));
    if let Some(parent) = &span.parent_span_id {
        obj.insert("parentSpanId".into(), json!(parent));
    }
    obj.insert("name".into(), json!(span.name));
    obj.insert("kind".into(), json!(span_kind_otlp(&span.kind)));
    // OTLP/JSON renders nanos as decimal strings.
    obj.insert("startTimeUnixNano".into(), json!(span.start_unix_nano.to_string()));
    obj.insert("endTimeUnixNano".into(), json!(span.end_unix_nano.to_string()));
    obj.insert("attributes".into(), attrs_to_otlp(&span.attributes));

    let mut status = Map::new();
    status.insert("code".into(), json!(span.status_code.as_otlp_str()));
    if let Some(msg) = &span.status_message {
        status.insert("message".into(), json!(msg));
    }
    obj.insert("status".into(), Value::Object(status));

    Value::Object(obj)
}

/// Wrap one or more canonical spans into a full OTLP/JSON `TracesData` document
/// (single resource, single scope).
#[must_use]
pub fn spans_to_otlp_document(spans: &[CanonicalSpan]) -> Value {
    let span_json: Vec<Value> = spans.iter().map(span_to_otlp_json).collect();
    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    kv("service.name", json!("logbook"))
                ]
            },
            "scopeSpans": [{
                "scope": { "name": SCOPE_NAME },
                "spans": span_json
            }]
        }]
    })
}

/// Render an attribute map as the OTLP/JSON `KeyValue[]` array (deterministic
/// order, since the source is a `BTreeMap`).
fn attrs_to_otlp(attrs: &BTreeMap<String, Value>) -> Value {
    Value::Array(attrs.iter().map(|(k, v)| kv(k, v.clone())).collect())
}

/// Build one OTLP/JSON `KeyValue` with a typed `AnyValue`.
fn kv(key: &str, value: Value) -> Value {
    json!({ "key": key, "value": any_value(&value) })
}

/// Wrap a JSON value as an OTLP/JSON `AnyValue` (typed union).
fn any_value(v: &Value) -> Value {
    match v {
        Value::String(s) => json!({ "stringValue": s }),
        Value::Bool(b) => json!({ "boolValue": b }),
        Value::Number(n) => {
            // OTLP `intValue` is a signed 64-bit field (proto `int64`), so only
            // values that fit `i64` are emitted as `intValue`. A `u64` above
            // `i64::MAX` (e.g. a very large `http.response.body.size`) cannot be
            // represented faithfully there, so it intentionally falls back to
            // `doubleValue` rather than overflowing the signed wire type. See
            // the `large_u64_attribute_encodes_as_double` regression test.
            if let Some(i) = n.as_i64() {
                json!({ "intValue": i.to_string() })
            } else {
                json!({ "doubleValue": n.as_f64().unwrap_or(0.0) })
            }
        }
        Value::Array(arr) => {
            json!({ "arrayValue": { "values": arr.iter().map(any_value).collect::<Vec<_>>() } })
        }
        Value::Object(_) => json!({ "stringValue": stringify(v) }),
        Value::Null => json!({ "stringValue": "" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_integer_attribute_encodes_as_int_string() {
        // Values within i64 range are emitted as OTLP `intValue` (a decimal
        // string per OTLP/JSON), which is what the golden fixtures rely on.
        let v = any_value(&json!(2048u64));
        assert_eq!(v, json!({ "intValue": "2048" }));

        let max_i64 = any_value(&json!(i64::MAX as u64));
        assert_eq!(max_i64, json!({ "intValue": i64::MAX.to_string() }));
    }

    #[test]
    fn large_u64_attribute_encodes_as_double() {
        // A u64 above i64::MAX (e.g. an enormous http.response.body.size) does
        // not fit OTLP's signed `intValue`, so it intentionally falls back to
        // `doubleValue`. Pin that contract so the type/precision choice for an
        // out-of-i64-range numeric attribute cannot silently regress.
        let big = (i64::MAX as u64) + 1; // 9_223_372_036_854_775_808
        let v = any_value(&json!(big));
        assert_eq!(v, json!({ "doubleValue": big as f64 }));

        let max_u64 = any_value(&json!(u64::MAX));
        assert_eq!(max_u64, json!({ "doubleValue": u64::MAX as f64 }));
    }
}
