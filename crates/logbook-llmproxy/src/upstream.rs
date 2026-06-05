//! The upstream-provider seam: a small [`Upstream`] trait the proxy forwards
//! through, plus the real [`ReqwestUpstream`] (reqwest over rustls) and the
//! request/response value types.
//!
//! # Why a trait
//! The proxy is the **only** component that sees raw provider payloads, so its
//! tests must exercise the full forward → reassemble → redact → persist path
//! **without** touching the network (plan "Phase 4 tests": "Tests with a MOCK
//! upstream … NO real network"). Modelling the upstream as an injectable trait
//! (mirroring the codebase's `HarnessAdapter` / `McpTransport` decorator seams)
//! lets a test pass a canned-response stub while production passes
//! [`ReqwestUpstream`]. The proxy logic above it is identical either way.
//!
//! # Buffering is deliberate
//! [`UpstreamResponse::body`] is the **fully-buffered** response bytes — for a
//! streaming (SSE) response the real client drains the whole event stream into
//! this buffer before returning. That is what makes "reassemble the full stream,
//! THEN redact, THEN persist — never persist raw chunks" structurally true: by
//! the time a response leaves the [`Upstream`], it is one complete byte string,
//! and the recording path ([`crate::record`]) redacts that whole string before
//! anything is persisted.

use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::error::LlmProxyError;

/// One forwarded request, normalized to the bytes + metadata the proxy needs to
/// (a) replay it upstream and (b) record a redacted [`Kind::Llm`](logbook_core::Kind)
/// event. The body is the raw client bytes; it is **never** persisted as-is —
/// the recording path redacts it first.
#[derive(Clone, Debug)]
pub struct UpstreamRequest {
    /// HTTP method (usually `POST`).
    pub method: String,
    /// The provider-relative path + query (e.g. `/v1/messages`), appended to the
    /// provider's configured upstream base URL.
    pub path_and_query: String,
    /// Request headers to forward (the proxy strips its own bearer and hop-by-hop
    /// headers before this point). Header **names are lowercased**.
    pub headers: BTreeMap<String, String>,
    /// The raw request body bytes (a JSON chat/messages payload for the providers
    /// we model). Redacted before any persistence.
    pub body: Vec<u8>,
}

impl UpstreamRequest {
    /// Best-effort parse of the request body as JSON (the providers we model send
    /// JSON). Returns `None` for a non-JSON or empty body.
    #[must_use]
    pub fn body_json(&self) -> Option<serde_json::Value> {
        if self.body.is_empty() {
            return None;
        }
        serde_json::from_slice(&self.body).ok()
    }

    /// Whether the client asked for a streaming response. Both providers we model
    /// signal this with a top-level `"stream": true` in the JSON body.
    #[must_use]
    pub fn wants_stream(&self) -> bool {
        self.body_json()
            .as_ref()
            .and_then(|v| v.get("stream"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }
}

/// The fully-buffered upstream response. For a streaming response the event
/// stream has already been drained into [`Self::body`] (see the module note), so
/// the proxy holds one complete byte string and never persists individual SSE
/// chunks.
#[derive(Clone, Debug)]
pub struct UpstreamResponse {
    /// HTTP status code returned by the provider.
    pub status: u16,
    /// Response headers (names lowercased). The `content-type` here is how the
    /// recorder decides whether the body is an SSE stream to reassemble.
    pub headers: BTreeMap<String, String>,
    /// The complete response body bytes (SSE stream already reassembled for a
    /// streaming response). Redacted before any persistence; the raw bytes are
    /// returned to the client but never stored.
    pub body: Vec<u8>,
}

impl UpstreamResponse {
    /// The `content-type` header value, if present (lowercased name lookup).
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(String::as_str)
    }

    /// Whether the response is a Server-Sent-Events stream (`text/event-stream`).
    /// The recorder reassembles these before redacting.
    #[must_use]
    pub fn is_event_stream(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
            .unwrap_or(false)
    }

    /// Best-effort parse of a non-streaming JSON response body.
    #[must_use]
    pub fn body_json(&self) -> Option<serde_json::Value> {
        if self.body.is_empty() {
            return None;
        }
        serde_json::from_slice(&self.body).ok()
    }
}

/// The forwarding seam. An implementation takes a normalized [`UpstreamRequest`]
/// plus the resolved provider base URL and returns the **fully-buffered**
/// [`UpstreamResponse`].
///
/// Production uses [`ReqwestUpstream`]; tests inject a stub so the whole proxy
/// can be exercised with no real network (plan "Phase 4 tests").
#[async_trait]
pub trait Upstream: Send + Sync {
    /// Forward `req` to `base_url` (the provider's real API root) and return the
    /// complete response. Implementations must drain a streaming body into
    /// [`UpstreamResponse::body`] before returning.
    ///
    /// # Errors
    /// Returns [`LlmProxyError`] on a transport/build failure (a non-2xx
    /// provider status is **not** an error — it is returned as the response so
    /// the proxy can relay it to the client and still record the call).
    async fn send(
        &self,
        base_url: &str,
        req: &UpstreamRequest,
    ) -> Result<UpstreamResponse, LlmProxyError>;
}

/// The production [`Upstream`]: a `reqwest` client (rustls TLS) that replays the
/// request against the provider and buffers the whole response (including a
/// drained SSE stream) before returning.
#[derive(Clone)]
pub struct ReqwestUpstream {
    client: reqwest::Client,
}

impl ReqwestUpstream {
    /// Build a reqwest-backed upstream.
    ///
    /// # Errors
    /// Returns [`LlmProxyError::Client`] if the client cannot be constructed.
    pub fn new() -> Result<Self, LlmProxyError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| LlmProxyError::Client(e.to_string()))?;
        Ok(Self { client })
    }
}

/// Headers the proxy must never forward upstream (hop-by-hop or proxy-injected).
/// Lowercased for case-insensitive matching against [`UpstreamRequest::headers`].
const STRIP_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

#[async_trait]
impl Upstream for ReqwestUpstream {
    async fn send(
        &self,
        base_url: &str,
        req: &UpstreamRequest,
    ) -> Result<UpstreamResponse, LlmProxyError> {
        let url = join_url(base_url, &req.path_and_query);
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .unwrap_or(reqwest::Method::POST);

        let mut builder = self.client.request(method, url);
        for (name, value) in &req.headers {
            if STRIP_REQUEST_HEADERS.contains(&name.as_str()) {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder = builder.body(req.body.clone());

        let resp = builder
            .send()
            .await
            .map_err(|e| LlmProxyError::Client(e.to_string()))?;

        let status = resp.status().as_u16();
        let mut headers = BTreeMap::new();
        for (name, value) in resp.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_ascii_lowercase(), v.to_string());
            }
        }

        // Drain the WHOLE body — for a streaming response this collects every SSE
        // chunk into one buffer, so the caller holds a complete byte string and
        // never sees (or persists) individual chunks.
        let body = resp
            .bytes()
            .await
            .map_err(|e| LlmProxyError::Client(e.to_string()))?
            .to_vec();

        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

/// Join a provider base URL with a request path, avoiding a doubled `/`.
fn join_url(base: &str, path_and_query: &str) -> String {
    let base = base.trim_end_matches('/');
    if path_and_query.is_empty() {
        return base.to_string();
    }
    if path_and_query.starts_with('/') {
        format!("{base}{path_and_query}")
    } else {
        format!("{base}/{path_and_query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_avoids_double_slash() {
        assert_eq!(
            join_url("https://api.anthropic.com/", "/v1/messages"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            join_url("https://api.anthropic.com", "v1/messages"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(join_url("https://x/", ""), "https://x");
    }

    #[test]
    fn wants_stream_reads_body_flag() {
        let streaming = UpstreamRequest {
            method: "POST".into(),
            path_and_query: "/v1/messages".into(),
            headers: BTreeMap::new(),
            body: br#"{"model":"claude","stream":true}"#.to_vec(),
        };
        assert!(streaming.wants_stream());

        let plain = UpstreamRequest {
            body: br#"{"model":"claude"}"#.to_vec(),
            ..streaming.clone()
        };
        assert!(!plain.wants_stream());
    }

    #[test]
    fn is_event_stream_keys_off_content_type() {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), "text/event-stream; charset=utf-8".into());
        let resp = UpstreamResponse {
            status: 200,
            headers,
            body: Vec::new(),
        };
        assert!(resp.is_event_stream());

        let mut json_headers = BTreeMap::new();
        json_headers.insert("content-type".into(), "application/json".into());
        let json = UpstreamResponse {
            status: 200,
            headers: json_headers,
            body: Vec::new(),
        };
        assert!(!json.is_event_stream());
    }
}
