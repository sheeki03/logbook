//! Turn a forwarded request + (reassembled) response into **one redacted**
//! [`Kind::Llm`](logbook_core::Kind) [`Event`].
//!
//! This is where the Complete-tier privacy contract is enforced (plan "Phase 4"
//! + "Privacy defaults"):
//!
//! - **Redaction before persistence is sacred.** Prompt (request) and response
//!   bodies are captured *only* when the `prompts` / `tool_results` classes are
//!   on, and are **always force-redacted** through [`HarnessContext`] (the
//!   general redactor + the mandatory secrets floor + the per-class byte cap)
//!   before they ever touch an [`Event`]. The proxy is the one component that
//!   sees raw provider payloads, so it must scrub them here.
//! - **SSE is reassembled, then redacted, then persisted — never raw chunks.**
//!   A streaming response arrives already-buffered (see [`crate::upstream`]); we
//!   reassemble its text + usage from the `data:` events into one string and one
//!   metadata set, then redact that, then store it.
//! - **Metadata may be recorded even when payload capture is off.** Model, token
//!   counts, cost, finish-reason, and the stream flag are the `model_metadata`
//!   class (exported by default, no payload) and are always recorded; only the
//!   prompt/response *bodies* are gated by their content classes.
//!
//! Nothing in this module logs or persists a raw payload.

use std::borrow::Cow;
use std::io::Read;

use logbook_core::{Category, Event, Kind, LlmBlock, MicrosTimestamp, SensitivityClass, Status};
use logbook_harness::HarnessContext;

use crate::upstream::{UpstreamRequest, UpstreamResponse};
use crate::{ModelPrice, Provider};

/// Inputs to [`record_llm_event`]: the provider, the forwarded request, the
/// reassembled response, and the optional per-1M-token price for cost
/// derivation.
pub struct RecordInputs<'a> {
    /// Which provider this call went to (sets `LlmBlock.provider`).
    pub provider: Provider,
    /// The forwarded request (its body is the prompt — redacted + gated here).
    pub request: &'a UpstreamRequest,
    /// The reassembled upstream response (its body is the completion — redacted
    /// + gated here).
    pub response: &'a UpstreamResponse,
    /// Per-model USD price (per 1M tokens), if known, for `cost_usd` derivation.
    pub price: Option<ModelPrice>,
    /// Event timestamp (microseconds). Passed in so the caller controls the clock
    /// (and so the event time matches when the call was observed).
    pub timestamp: MicrosTimestamp,
    /// Span duration in milliseconds (wall time of the upstream round-trip), if
    /// measured.
    pub duration_ms: Option<f64>,
}

/// Decode an upstream response body for **recording only**, honoring its
/// `Content-Encoding`.
///
/// # Why this exists (the bug it fixes)
/// Real providers (Anthropic, OpenAI) compress responses — almost always
/// `content-encoding: gzip`, sometimes `br`/`deflate`. Our upstream client
/// forwards the client's `accept-encoding` and returns the body **still
/// compressed** (reqwest's auto-decompress features are intentionally off so the
/// [relay][crate::server] stays byte-exact). If the recording path consumed those
/// raw bytes, the stored `output` would be gzip garbage (`0x1f 0x8b …`) and the
/// SSE reassembly + token/usage extraction would find no `data:`/JSON and yield
/// nothing. So before *recording* we decode here; the relay still sends the
/// original compressed bytes untouched.
///
/// Borrows the original bytes (zero-copy) for an empty body or an
/// `identity`/absent/unknown encoding; allocates only when it actually decodes.
/// Decoding **never panics**: on any decode error (or unrecognized encoding) it
/// falls back to the raw bytes so the event still records *something*.
///
/// `Content-Encoding` may list multiple, comma-separated encodings applied in
/// order (e.g. `gzip, br`); the *last* listed is the outermost / first to peel.
/// We handle the common single-value case robustly and, for a list, attempt that
/// last-applied encoding (a single decode pass), else fall back to raw — we do
/// not chase arbitrarily nested stacks, which providers do not send.
fn decoded_body(resp: &UpstreamResponse) -> Cow<'_, [u8]> {
    let raw = resp.body.as_slice();
    if raw.is_empty() {
        return Cow::Borrowed(raw);
    }
    // Header names are already lowercased (see `UpstreamResponse`); the *value*
    // (and any list members) still need lowercasing + trimming.
    let Some(encoding) = resp.headers.get("content-encoding") else {
        return Cow::Borrowed(raw);
    };
    // For a comma-listed value, the last entry is the outermost encoding (the
    // last one applied), so that's the one to peel here.
    let token = encoding
        .rsplit(',')
        .next()
        .unwrap_or(encoding)
        .trim()
        .to_ascii_lowercase();

    let decoded = match token.as_str() {
        // No-ops: record the bytes as-is.
        "" | "identity" => return Cow::Borrowed(raw),
        // gzip: MultiGzDecoder tolerates concatenated members (a streamed gzip
        // response can be several gzip frames), a robust superset of GzDecoder.
        "gzip" | "x-gzip" => decode_with(flate2::read::MultiGzDecoder::new(raw)),
        // `deflate` on the wire is usually zlib-wrapped; fall back to raw deflate.
        "deflate" | "zlib" => decode_with(flate2::read::ZlibDecoder::new(raw))
            .or_else(|| decode_with(flate2::read::DeflateDecoder::new(raw))),
        "br" => decode_brotli(raw),
        // Unknown/unsupported single token (e.g. `zstd`): don't guess.
        _ => None,
    };

    match decoded {
        Some(bytes) => Cow::Owned(bytes),
        // Any decode failure (truncated/corrupt body, wrong declared encoding,
        // unsupported token) records the raw bytes rather than panicking or
        // dropping the event.
        None => Cow::Borrowed(raw),
    }
}

/// Run a `Read`-based decoder to completion, returning `None` on any I/O/decode
/// error so the caller can fall back to the raw bytes.
fn decode_with<R: Read>(mut decoder: R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok().map(|_| out)
}

/// Brotli-decode `raw`, returning `None` on any decode error.
fn decode_brotli(raw: &[u8]) -> Option<Vec<u8>> {
    // `brotli::Decompressor` is a `Read` adapter over the compressed source; the
    // 4096 is just the internal scratch buffer size, not a length cap.
    decode_with(brotli::Decompressor::new(raw, 4096))
}

/// Parsed, provider-agnostic completion metadata extracted from a response.
#[derive(Clone, Debug, Default, PartialEq)]
struct CompletionMeta {
    model: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    finish_reason: Option<String>,
    /// The reassembled completion text (for streaming responses) — used as the
    /// recorded response body when no full JSON body is available. Already plain
    /// text; still force-redacted before persistence.
    reassembled_text: Option<String>,
}

/// Build the single redacted [`Kind::Llm`] event for one proxied call.
///
/// The event always carries the `model_metadata` (provider/model/tokens/cost/
/// finish-reason/stream). The **prompt** body is attached (redacted) only when
/// [`HarnessContext::captures`]`(Prompts)`; the **response** body is attached
/// (redacted) only when `captures(ToolResults)`. When a content class is off,
/// the event is metadata-only for that side (plan: "prompts-off => metadata-only").
#[must_use]
pub fn record_llm_event(ctx: &HarnessContext, inputs: RecordInputs<'_>) -> Event {
    let RecordInputs {
        provider,
        request,
        response,
        price,
        timestamp,
        duration_ms,
    } = inputs;

    // The recorded `stream` flag reflects whether streaming was *in play* — either
    // the client asked for it or the upstream replied with an event stream.
    let streamed = response.is_event_stream() || request.wants_stream();
    // Decode the response body ONCE for recording, honoring `Content-Encoding`
    // (gzip/deflate/br). Real providers reply compressed, and our upstream returns
    // those bytes still compressed so the RELAY stays byte-exact — so everything
    // the recording path reads from the body (SSE reassembly, JSON usage parsing,
    // the stored `output` text) must run over the DECODED bytes, not `response.body`.
    let body = decoded_body(response);
    // The parser choice, however, is driven by the RESPONSE shape only: a client
    // can ask for `stream:true` and still receive a buffered JSON body (the
    // provider ignored the flag, or it's a 4xx/5xx JSON error body). Keying the
    // reassembly off `request.wants_stream()` would run `reassemble_sse` on that
    // JSON, find no `data:` lines, and silently drop tokens/finish-reason/cost.
    let meta = extract_completion_meta(response, &body);

    // Model: prefer the response's reported model, fall back to the request's.
    let model = meta
        .model
        .clone()
        .or_else(|| request_model(request));

    let cost_usd = derive_cost(price, meta.input_tokens, meta.output_tokens);

    let llm = LlmBlock {
        provider: Some(provider.as_str().to_string()),
        model,
        input_tokens: meta.input_tokens,
        output_tokens: meta.output_tokens,
        total_tokens: sum_tokens(meta.input_tokens, meta.output_tokens),
        temperature: request_temperature(request),
        cost_usd,
        finish_reason: meta.finish_reason.clone(),
        stream: Some(streamed),
    };

    // Status mirrors the upstream HTTP outcome so a failed provider call is
    // recorded as an error span (the body, if any, is still redacted).
    let status = if (200..300).contains(&response.status) {
        Status::Ok
    } else {
        Status::Error
    };

    let mut event = Event::new(
        request_trace(request),
        Kind::Llm,
        Category::Agent,
        operation_for(provider),
    )
    .with_name(format!("{} chat.completion", provider.as_str()))
    .with_status(status)
    .with_llm(llm);

    // Use the caller-supplied observation time so the event timestamp reflects
    // when the call was seen (and so audit `created_at` is reproducible from it).
    event.timestamp = timestamp;

    if let Some(ms) = duration_ms {
        event = event.with_duration_ms(ms);
    }

    // A non-2xx call records the status code as the (redaction-safe) error tag.
    if status == Status::Error {
        event = event.with_error(format!("upstream status {}", response.status));
    }

    // The stream flag is also stamped as an attribute so the metadata-only export
    // projection carries it without needing the LlmBlock.
    event
        .attributes
        .insert("stream".to_string(), serde_json::Value::Bool(streamed));
    event.attributes.insert(
        "upstream_status".to_string(),
        serde_json::Value::from(response.status),
    );

    // ---- Prompt body (request) — gated by the `prompts` class, force-redacted.
    if ctx.captures(SensitivityClass::Prompts) {
        if !request.body.is_empty() {
            let raw = String::from_utf8_lossy(&request.body);
            let (redacted, truncated) = ctx.redact_text(SensitivityClass::Prompts, &raw);
            event.input = Some(serde_json::Value::String(redacted));
            if truncated {
                event.attributes.insert(
                    "prompt_truncated".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        }
    } else {
        // Explicitly mark the omission so a reader knows the body was dropped by
        // policy (not merely absent) — metadata-only for the prompt side.
        event.attributes.insert(
            "prompt_captured".to_string(),
            serde_json::Value::Bool(false),
        );
    }

    // ---- Response body — gated by the `tool_results` class, force-redacted.
    // For a streaming response the reassembled text is the body; for a buffered
    // response the raw (JSON) body is. Either way it is one complete string that
    // is redacted here BEFORE being attached — never a raw chunk.
    if ctx.captures(SensitivityClass::ToolResults) {
        if let Some(body_text) = response_body_text(&body, &meta) {
            let (redacted, truncated) =
                ctx.redact_text(SensitivityClass::ToolResults, &body_text);
            event.output = Some(serde_json::Value::String(redacted));
            if truncated {
                event.attributes.insert(
                    "response_truncated".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        }
    } else {
        event.attributes.insert(
            "response_captured".to_string(),
            serde_json::Value::Bool(false),
        );
    }

    event
}

/// The text to record as the response body: the reassembled completion text for
/// a streamed response, otherwise the (decoded) buffered body as text. `body` is
/// the already-`Content-Encoding`-decoded response bytes (see [`decoded_body`]),
/// so the recorded `output` is readable text, not gzip garbage. Returns `None`
/// for an empty body. **Always** redacted by the caller before use.
fn response_body_text(body: &[u8], meta: &CompletionMeta) -> Option<String> {
    if let Some(text) = &meta.reassembled_text {
        if !text.is_empty() {
            return Some(text.clone());
        }
    }
    if body.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(body).into_owned())
}

/// The provider-relative operation verb for the event.
fn operation_for(provider: Provider) -> &'static str {
    match provider {
        Provider::Anthropic => "messages",
        Provider::OpenAi => "chat.completions",
    }
}

/// Use the request's trace id when the client forwarded one as a header
/// (`x-logbook-trace`), otherwise mint a fresh trace so the call is still
/// correlated as its own unit.
// `TraceId::new()` mints a fresh RANDOM id, not the all-zero `Default`, so
// clippy's `unwrap_or_default` suggestion would be semantically wrong here.
#[allow(clippy::unwrap_or_default)]
fn request_trace(request: &UpstreamRequest) -> logbook_core::TraceId {
    request
        .headers
        .get("x-logbook-trace")
        .and_then(|h| parse_trace_hex(h))
        .unwrap_or_else(logbook_core::TraceId::new)
}

/// Parse a 32-hex-char W3C trace id, if well-formed (rejecting the all-zero id).
fn parse_trace_hex(s: &str) -> Option<logbook_core::TraceId> {
    use std::str::FromStr;
    let trace = logbook_core::TraceId::from_str(s.trim()).ok()?;
    if trace.to_hex() == "0".repeat(32) {
        return None;
    }
    Some(trace)
}

/// The model named in the request body (both providers put it at top-level
/// `"model"`).
fn request_model(request: &UpstreamRequest) -> Option<String> {
    request
        .body_json()?
        .get("model")?
        .as_str()
        .map(str::to_string)
}

/// The sampling temperature in the request body, if present.
fn request_temperature(request: &UpstreamRequest) -> Option<f64> {
    request.body_json()?.get("temperature")?.as_f64()
}

/// Sum input + output tokens when at least one is known (so a partial count
/// still yields a `total`); `None` only when both are absent.
///
/// Uses a **saturating** add: a hostile or buggy provider could report token
/// counts near `u64::MAX`, and an unchecked `+` would panic in debug / silently
/// wrap in release. Saturating clamps to `u64::MAX` instead — recording the call
/// must never crash on adversarial metadata.
fn sum_tokens(input: Option<u64>, output: Option<u64>) -> Option<u64> {
    match (input, output) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
    }
}

/// Derive USD cost from a per-1M-token price and token counts. `None` when the
/// price is unknown or no tokens were reported (cost is "derivable" only with
/// both).
fn derive_cost(price: Option<ModelPrice>, input: Option<u64>, output: Option<u64>) -> Option<f64> {
    let price = price?;
    if input.is_none() && output.is_none() {
        return None;
    }
    let i = input.unwrap_or(0) as f64;
    let o = output.unwrap_or(0) as f64;
    Some((i * price.input_per_mtok + o * price.output_per_mtok) / 1_000_000.0)
}

/// Extract provider-agnostic completion metadata from a response.
///
/// `body` is the already-`Content-Encoding`-decoded response body (see
/// [`decoded_body`]) — a gzipped stream is the WHOLE SSE stream compressed, so it
/// must be decoded BEFORE we reassemble, otherwise `reassemble_sse` sees binary
/// and finds no `data:` lines. We parse `body`, not `response.body`.
///
/// The parser is chosen from the **response shape**, never the request: SSE is
/// reassembled only when the upstream actually replied with an event stream
/// (`response.is_event_stream()`); otherwise the buffered JSON body is parsed.
/// This matters because a client can send `stream:true` yet receive a buffered
/// JSON body — the provider ignored the flag, or it's a 4xx/5xx JSON error body.
/// Reassembling SSE over that JSON would find no `data:` lines and return a
/// default (empty) meta, silently dropping the tokens/finish-reason/cost that
/// are sitting right there in the body.
fn extract_completion_meta(response: &UpstreamResponse, body: &[u8]) -> CompletionMeta {
    if response.is_event_stream() {
        reassemble_sse(body)
    } else if let Some(json) = body_json(body) {
        meta_from_json(&json)
    } else {
        CompletionMeta::default()
    }
}

/// Best-effort parse of a (decoded) buffered JSON response body. Mirrors
/// [`UpstreamResponse::body_json`] but over the decoded bytes.
fn body_json(body: &[u8]) -> Option<serde_json::Value> {
    if body.is_empty() {
        return None;
    }
    serde_json::from_slice(body).ok()
}

/// Pull model / usage / finish-reason out of a buffered JSON completion body,
/// tolerating both the OpenAI (`usage.prompt_tokens`/`completion_tokens`,
/// `choices[0].finish_reason`) and Anthropic (`usage.input_tokens`/
/// `output_tokens`, `stop_reason`) shapes.
fn meta_from_json(json: &serde_json::Value) -> CompletionMeta {
    let mut meta = CompletionMeta {
        model: json.get("model").and_then(|v| v.as_str()).map(str::to_string),
        ..CompletionMeta::default()
    };

    if let Some(usage) = json.get("usage") {
        // OpenAI names first, then Anthropic names.
        meta.input_tokens = u64_field(usage, "prompt_tokens").or_else(|| u64_field(usage, "input_tokens"));
        meta.output_tokens =
            u64_field(usage, "completion_tokens").or_else(|| u64_field(usage, "output_tokens"));
    }

    // finish_reason: OpenAI `choices[0].finish_reason`, else Anthropic `stop_reason`.
    meta.finish_reason = json
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c0| c0.get("finish_reason"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            json.get("stop_reason")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });

    meta
}

/// Read a `u64` field from a JSON object, tolerating it being absent or a
/// non-integer.
fn u64_field(obj: &serde_json::Value, key: &str) -> Option<u64> {
    obj.get(key).and_then(serde_json::Value::as_u64)
}

/// Reassemble a buffered SSE byte stream into one [`CompletionMeta`]: concatenate
/// the incremental text deltas (so the recorded "body" is the full completion
/// text, never individual chunks) and carry forward the last-seen model / usage /
/// finish-reason across `data:` events.
///
/// This tolerates both provider streaming shapes:
/// - **OpenAI**: `data: {choices:[{delta:{content:"…"}}], ...}` with the final
///   `usage` on a late event (when `stream_options.include_usage` is set) and
///   `choices[0].finish_reason`. A terminal `data: [DONE]` sentinel is ignored.
/// - **Anthropic**: `event: content_block_delta` / `data: {delta:{text:"…"}}`,
///   `message_start.message.usage.input_tokens`, `message_delta.usage.output_tokens`,
///   and `message_delta.delta.stop_reason`.
fn reassemble_sse(body: &[u8]) -> CompletionMeta {
    let text = String::from_utf8_lossy(body);
    let mut meta = CompletionMeta::default();
    let mut buf = String::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(json) = serde_json::from_str::<serde_json::Value>(data) else {
            // A non-JSON data line is not text we can trust to reassemble; skip
            // it rather than guess (and never persist it raw).
            continue;
        };

        // Model (first event that names it wins; Anthropic puts it under
        // message_start.message.model, OpenAI at top-level model).
        if meta.model.is_none() {
            if let Some(m) = json.get("model").and_then(|v| v.as_str()) {
                meta.model = Some(m.to_string());
            } else if let Some(m) = json
                .get("message")
                .and_then(|msg| msg.get("model"))
                .and_then(|v| v.as_str())
            {
                meta.model = Some(m.to_string());
            }
        }

        // Incremental text: OpenAI choices[0].delta.content, Anthropic delta.text.
        if let Some(c) = json
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c0| c0.get("delta"))
            .and_then(|d| d.get("content"))
            .and_then(|v| v.as_str())
        {
            buf.push_str(c);
        } else if let Some(t) = json
            .get("delta")
            .and_then(|d| d.get("text"))
            .and_then(|v| v.as_str())
        {
            buf.push_str(t);
        }

        // Usage can appear on message_start (input) and message_delta (output)
        // for Anthropic, or a trailing usage event for OpenAI.
        if let Some(usage) = json
            .get("usage")
            .or_else(|| json.get("message").and_then(|m| m.get("usage")))
        {
            if let Some(i) = u64_field(usage, "prompt_tokens").or_else(|| u64_field(usage, "input_tokens")) {
                meta.input_tokens = Some(i);
            }
            if let Some(o) =
                u64_field(usage, "completion_tokens").or_else(|| u64_field(usage, "output_tokens"))
            {
                meta.output_tokens = Some(o);
            }
        }

        // finish/stop reason (last one wins).
        if let Some(fr) = json
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c0| c0.get("finish_reason"))
            .and_then(|v| v.as_str())
        {
            meta.finish_reason = Some(fr.to_string());
        } else if let Some(sr) = json
            .get("delta")
            .and_then(|d| d.get("stop_reason"))
            .and_then(|v| v.as_str())
            .or_else(|| json.get("stop_reason").and_then(|v| v.as_str()))
        {
            meta.finish_reason = Some(sr.to_string());
        }
    }

    if !buf.is_empty() {
        meta.reassembled_text = Some(buf);
    }
    meta
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use logbook_core::CapturePolicy;

    fn ctx_with(policy: CapturePolicy) -> HarnessContext {
        HarnessContext::new(logbook_core::Redactor::new(), policy, true)
    }

    fn req(body: &[u8]) -> UpstreamRequest {
        UpstreamRequest {
            method: "POST".into(),
            path_and_query: "/v1/messages".into(),
            headers: BTreeMap::new(),
            body: body.to_vec(),
        }
    }

    fn json_resp(status: u16, body: &[u8]) -> UpstreamResponse {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), "application/json".into());
        UpstreamResponse {
            status,
            headers,
            body: body.to_vec(),
        }
    }

    fn sse_resp(body: &str) -> UpstreamResponse {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), "text/event-stream".into());
        UpstreamResponse {
            status: 200,
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    /// gzip-compress `bytes` the way a real provider would (so the test exercises
    /// the actual decode path, not a hand-rolled stub).
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    /// A response with a gzip-compressed body + `content-encoding: gzip`, of the
    /// given content-type (so we can build both a gzipped JSON body and a gzipped
    /// SSE stream — exactly what Anthropic/OpenAI return on the wire).
    fn gzip_resp(status: u16, content_type: &str, plain_body: &[u8]) -> UpstreamResponse {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), content_type.into());
        headers.insert("content-encoding".into(), "gzip".into());
        UpstreamResponse {
            status,
            headers,
            body: gzip(plain_body),
        }
    }

    #[test]
    fn meta_from_openai_json() {
        let body = br#"{"model":"gpt-4o","usage":{"prompt_tokens":12,"completion_tokens":7},"choices":[{"finish_reason":"stop"}]}"#;
        let meta = meta_from_json(&serde_json::from_slice(body).unwrap());
        assert_eq!(meta.model.as_deref(), Some("gpt-4o"));
        assert_eq!(meta.input_tokens, Some(12));
        assert_eq!(meta.output_tokens, Some(7));
        assert_eq!(meta.finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn meta_from_anthropic_json() {
        let body = br#"{"model":"claude-3","usage":{"input_tokens":20,"output_tokens":9},"stop_reason":"end_turn"}"#;
        let meta = meta_from_json(&serde_json::from_slice(body).unwrap());
        assert_eq!(meta.model.as_deref(), Some("claude-3"));
        assert_eq!(meta.input_tokens, Some(20));
        assert_eq!(meta.output_tokens, Some(9));
        assert_eq!(meta.finish_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn reassemble_openai_sse_concatenates_text_and_usage() {
        let stream = "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n\
                      data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n\
                      data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n\
                      data: [DONE]\n\n";
        let meta = reassemble_sse(stream.as_bytes());
        assert_eq!(meta.reassembled_text.as_deref(), Some("Hello"));
        assert_eq!(meta.model.as_deref(), Some("gpt-4o"));
        assert_eq!(meta.input_tokens, Some(3));
        assert_eq!(meta.output_tokens, Some(2));
        assert_eq!(meta.finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn reassemble_anthropic_sse() {
        let stream = "event: message_start\n\
                      data: {\"message\":{\"model\":\"claude-3\",\"usage\":{\"input_tokens\":15}}}\n\n\
                      event: content_block_delta\n\
                      data: {\"delta\":{\"text\":\"Hi \"}}\n\n\
                      event: content_block_delta\n\
                      data: {\"delta\":{\"text\":\"there\"}}\n\n\
                      event: message_delta\n\
                      data: {\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n";
        let meta = reassemble_sse(stream.as_bytes());
        assert_eq!(meta.reassembled_text.as_deref(), Some("Hi there"));
        assert_eq!(meta.model.as_deref(), Some("claude-3"));
        assert_eq!(meta.input_tokens, Some(15));
        assert_eq!(meta.output_tokens, Some(5));
        assert_eq!(meta.finish_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn derive_cost_uses_price_table() {
        let price = ModelPrice {
            input_per_mtok: 3.0,
            output_per_mtok: 15.0,
        };
        // 1M input @3 + 1M output @15 = 18.0
        let c = derive_cost(Some(price), Some(1_000_000), Some(1_000_000)).unwrap();
        assert!((c - 18.0).abs() < 1e-9, "got {c}");
        // No price ⇒ no cost.
        assert_eq!(derive_cost(None, Some(10), Some(10)), None);
        // Price but no tokens ⇒ no cost.
        assert_eq!(derive_cost(Some(price), None, None), None);
    }

    #[test]
    fn sum_tokens_saturates_on_overflow() {
        // Both absent ⇒ None.
        assert_eq!(sum_tokens(None, None), None);
        // A partial count still yields a total.
        assert_eq!(sum_tokens(Some(7), None), Some(7));
        assert_eq!(sum_tokens(None, Some(4)), Some(4));
        assert_eq!(sum_tokens(Some(7), Some(4)), Some(11));
        // Overflow saturates to u64::MAX instead of panicking (debug) / wrapping
        // (release) on a hostile provider reporting near-MAX token counts.
        assert_eq!(sum_tokens(Some(u64::MAX), Some(1)), Some(u64::MAX));
        assert_eq!(sum_tokens(Some(u64::MAX), Some(u64::MAX)), Some(u64::MAX));
    }

    #[test]
    fn record_does_not_panic_on_overflowing_token_counts() {
        // A hostile provider returns u64::MAX for both token fields. Recording the
        // event must not panic (the unchecked `+` would have, in debug) — the
        // total saturates and the event is built normally.
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"gpt-4o"}"#);
        let body = format!(
            r#"{{"model":"gpt-4o","usage":{{"prompt_tokens":{max},"completion_tokens":{max}}},"choices":[{{"finish_reason":"stop"}}]}}"#,
            max = u64::MAX
        );
        let response = json_resp(200, body.as_bytes());
        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::OpenAi,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );

        let llm = ev.blocks.llm.as_ref().unwrap();
        assert_eq!(llm.input_tokens, Some(u64::MAX));
        assert_eq!(llm.output_tokens, Some(u64::MAX));
        // The sum saturated rather than overflowed.
        assert_eq!(llm.total_tokens, Some(u64::MAX));
    }

    #[test]
    fn records_redacted_prompt_when_class_on() {
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"claude-3","messages":[{"role":"user","content":"deploy with AKIAIOSFODNN7EXAMPLE"}]}"#);
        let response = json_resp(
            200,
            br#"{"model":"claude-3","usage":{"input_tokens":5,"output_tokens":3},"stop_reason":"end_turn"}"#,
        );
        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::Anthropic,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1_000),
                duration_ms: Some(12.0),
            },
        );

        assert_eq!(ev.kind, Kind::Llm);
        let llm = ev.blocks.llm.as_ref().unwrap();
        assert_eq!(llm.provider.as_deref(), Some("anthropic"));
        assert_eq!(llm.model.as_deref(), Some("claude-3"));
        assert_eq!(llm.input_tokens, Some(5));
        assert_eq!(llm.output_tokens, Some(3));
        assert_eq!(llm.stream, Some(false));

        // The prompt is present AND redacted (the secret is gone).
        let prompt = ev.input.as_ref().unwrap().as_str().unwrap();
        assert!(!prompt.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into prompt: {prompt}");
        assert!(prompt.contains("REDACTED:CLOUD_KEY:"), "no redaction marker: {prompt}");
    }

    #[test]
    fn prompts_off_is_metadata_only() {
        // prompts class capture off ⇒ no prompt body, but metadata still recorded.
        let mut policy = CapturePolicy::default();
        policy.classes.prompts.capture = false;
        policy.classes.tool_results.capture = false;
        let ctx = ctx_with(policy);

        let request = req(br#"{"model":"gpt-4o","messages":[{"role":"user","content":"secret stuff"}]}"#);
        let response = json_resp(
            200,
            br#"{"model":"gpt-4o","usage":{"prompt_tokens":8,"completion_tokens":4},"choices":[{"finish_reason":"stop"}]}"#,
        );
        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::OpenAi,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );

        // No prompt / response bodies.
        assert!(ev.input.is_none(), "prompt body must be omitted when prompts off");
        assert!(ev.output.is_none(), "response body must be omitted when tool_results off");
        // But metadata is intact.
        let llm = ev.blocks.llm.as_ref().unwrap();
        assert_eq!(llm.model.as_deref(), Some("gpt-4o"));
        assert_eq!(llm.input_tokens, Some(8));
        assert_eq!(llm.output_tokens, Some(4));
        // Omission markers present.
        assert_eq!(ev.attributes.get("prompt_captured"), Some(&serde_json::Value::Bool(false)));
        assert_eq!(ev.attributes.get("response_captured"), Some(&serde_json::Value::Bool(false)));
    }

    #[test]
    fn streamed_response_is_reassembled_then_redacted() {
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"gpt-4o","stream":true,"messages":[]}"#);
        // A streamed completion whose text content contains a secret split across
        // chunks-worth of deltas; after reassembly + redaction it must be gone.
        let stream = "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"key=AKIA\"}}]}\n\n\
                      data: {\"choices\":[{\"delta\":{\"content\":\"IOSFODNN7EXAMPLE done\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":6}}\n\n\
                      data: [DONE]\n\n";
        let response = sse_resp(stream);
        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::OpenAi,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );

        let llm = ev.blocks.llm.as_ref().unwrap();
        assert_eq!(llm.stream, Some(true), "stream flag set");
        assert_eq!(llm.output_tokens, Some(6));
        // The reassembled body is redacted: the secret that spanned two deltas is
        // scrubbed (proving reassembly happened BEFORE redaction).
        let out = ev.output.as_ref().unwrap().as_str().unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret survived reassembly: {out}");
        assert!(out.contains("done"), "completion text lost: {out}");
        assert!(out.contains("REDACTED:CLOUD_KEY:"), "no redaction marker: {out}");
    }

    #[test]
    fn stream_requested_but_json_body_still_records_meta() {
        // Regression: the client asked for `stream:true`, but the upstream replied
        // with a buffered (non-SSE) JSON body — the provider ignored the flag, or
        // it's an error body. The parser must key off the RESPONSE shape (JSON),
        // NOT the request flag; otherwise `reassemble_sse` runs over the JSON,
        // finds no `data:` lines, and silently drops tokens / finish-reason / cost.
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"gpt-4o","stream":true,"messages":[]}"#);
        // NON-SSE: content-type application/json, a normal buffered completion body.
        let response = json_resp(
            200,
            br#"{"model":"gpt-4o","usage":{"prompt_tokens":11,"completion_tokens":5},"choices":[{"finish_reason":"stop"}]}"#,
        );
        let price = ModelPrice {
            input_per_mtok: 3.0,
            output_per_mtok: 15.0,
        };
        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::OpenAi,
                request: &request,
                response: &response,
                price: Some(price),
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );

        let llm = ev.blocks.llm.as_ref().unwrap();
        // The metadata from the JSON body is recorded (NOT dropped to defaults).
        assert_eq!(llm.input_tokens, Some(11), "input tokens dropped on stream-flag false-positive");
        assert_eq!(llm.output_tokens, Some(5), "output tokens dropped on stream-flag false-positive");
        assert_eq!(llm.total_tokens, Some(16));
        assert_eq!(llm.finish_reason.as_deref(), Some("stop"), "finish_reason dropped");
        assert_eq!(llm.model.as_deref(), Some("gpt-4o"));
        // Cost is derivable now that tokens survived: 11*3/1e6 + 5*15/1e6.
        let cost = llm.cost_usd.expect("cost should be derived from recovered tokens");
        let expected = (11.0 * 3.0 + 5.0 * 15.0) / 1_000_000.0;
        assert!((cost - expected).abs() < 1e-12, "got {cost}, want {expected}");
        // The recorded `stream` flag still reflects that streaming was requested —
        // the request flag drives the FLAG, just not the parser choice.
        assert_eq!(llm.stream, Some(true), "stream flag should still reflect the request");
        assert_eq!(ev.attributes.get("stream"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn non_2xx_upstream_is_recorded_as_error() {
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"gpt-4o"}"#);
        let response = json_resp(429, br#"{"error":{"message":"rate limited"}}"#);
        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::OpenAi,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );
        assert_eq!(ev.status, Status::Error);
        assert_eq!(ev.error.as_deref(), Some("upstream status 429"));
        assert_eq!(ev.attributes.get("upstream_status"), Some(&serde_json::Value::from(429u16)));
    }

    #[test]
    fn gzip_json_response_is_decoded_for_recording() {
        // Regression for the dogfooding bug: a real provider returns the JSON
        // completion body gzip-compressed (`content-encoding: gzip`). Before the
        // fix, the recording path consumed the raw gzip bytes — the stored
        // `output` started with the gzip magic (0x1f 0x8b) and token usage parsed
        // to nothing. After the fix, the body is decoded first, so the recorded
        // text is readable JSON and tokens/finish-reason are populated.
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"claude-3","messages":[]}"#);
        let plain = br#"{"model":"claude-3","usage":{"input_tokens":17,"output_tokens":8},"stop_reason":"end_turn"}"#;
        let response = gzip_resp(200, "application/json", plain);

        // Sanity: the body on the wire really is gzip (magic bytes), not plaintext.
        assert_eq!(&response.body[..2], &[0x1f, 0x8b], "test body should be gzip");

        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::Anthropic,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );

        // Token usage + finish-reason parsed out of the DECODED JSON.
        let llm = ev.blocks.llm.as_ref().unwrap();
        assert_eq!(llm.input_tokens, Some(17), "input tokens lost (body not decoded?)");
        assert_eq!(llm.output_tokens, Some(8), "output tokens lost (body not decoded?)");
        assert_eq!(llm.total_tokens, Some(25));
        assert_eq!(llm.finish_reason.as_deref(), Some("end_turn"));
        assert_eq!(llm.model.as_deref(), Some("claude-3"));

        // The recorded `output` is the readable decoded text, NOT gzip bytes.
        let out = ev.output.as_ref().unwrap().as_str().unwrap();
        assert!(!out.starts_with('\u{1f}'), "output still looks like gzip: {out:?}");
        assert!(out.contains("end_turn"), "decoded JSON not recorded: {out}");
        assert!(out.contains("\"output_tokens\":8"), "decoded JSON not recorded: {out}");
    }

    #[test]
    fn gzip_sse_stream_is_decoded_then_reassembled() {
        // A streamed (text/event-stream) response that is ALSO gzip-compressed:
        // the WHOLE stream is gzipped, so it must be decoded before SSE reassembly
        // can find any `data:` lines. Asserts the completion text reassembled and
        // usage/finish-reason came through from the decoded stream.
        let ctx = ctx_with(CapturePolicy::default());
        let request = req(br#"{"model":"gpt-4o","stream":true,"messages":[]}"#);
        let stream = "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n\
                      data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\n\n\
                      data: [DONE]\n\n";
        let response = gzip_resp(200, "text/event-stream", stream.as_bytes());

        let ev = record_llm_event(
            &ctx,
            RecordInputs {
                provider: Provider::OpenAi,
                request: &request,
                response: &response,
                price: None,
                timestamp: MicrosTimestamp(1),
                duration_ms: None,
            },
        );

        let llm = ev.blocks.llm.as_ref().unwrap();
        assert_eq!(llm.stream, Some(true));
        assert_eq!(llm.input_tokens, Some(4), "usage lost (gzipped stream not decoded?)");
        assert_eq!(llm.output_tokens, Some(2));
        assert_eq!(llm.finish_reason.as_deref(), Some("stop"));
        // The reassembled completion text is recorded (decoded → reassembled).
        let out = ev.output.as_ref().unwrap().as_str().unwrap();
        assert_eq!(out, "Hello", "reassembled completion text wrong: {out}");
    }

    #[test]
    fn decoded_body_passes_through_identity_and_unencoded() {
        // No content-encoding ⇒ bytes unchanged (and borrowed, not copied).
        let plain = json_resp(200, br#"{"ok":true}"#);
        assert_eq!(decoded_body(&plain).as_ref(), &br#"{"ok":true}"#[..]);
        assert!(matches!(decoded_body(&plain), Cow::Borrowed(_)));

        // Explicit `identity` ⇒ also a no-op passthrough.
        let mut identity = json_resp(200, b"hello");
        identity.headers.insert("content-encoding".into(), "identity".into());
        assert_eq!(decoded_body(&identity).as_ref(), &b"hello"[..]);

        // Unknown encoding (e.g. zstd, which we don't decode) ⇒ raw bytes, no panic.
        let mut zstd = json_resp(200, b"\x00\x01\x02");
        zstd.headers.insert("content-encoding".into(), "zstd".into());
        assert_eq!(decoded_body(&zstd).as_ref(), &b"\x00\x01\x02"[..]);
    }

    #[test]
    fn decoded_body_falls_back_to_raw_on_corrupt_gzip() {
        // content-encoding says gzip but the body is not valid gzip: decoding must
        // not panic; it falls back to the raw bytes so the event still records.
        let mut bad = json_resp(200, b"not actually gzip");
        bad.headers.insert("content-encoding".into(), "gzip".into());
        assert_eq!(decoded_body(&bad).as_ref(), &b"not actually gzip"[..]);
    }

    #[test]
    fn decoded_body_uses_last_listed_encoding() {
        // A comma-listed `content-encoding` (e.g. `identity, gzip`) means gzip was
        // applied last / outermost, so that's what we peel. A single decode pass
        // over a gzip body recovers the plaintext.
        let mut resp = gzip_resp(200, "application/json", b"payload");
        resp.headers.insert("content-encoding".into(), "identity, gzip".into());
        assert_eq!(decoded_body(&resp).as_ref(), &b"payload"[..]);
    }
}
