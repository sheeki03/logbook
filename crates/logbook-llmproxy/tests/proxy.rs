//! Integration tests for the LLM proxy (plan "Phase 4 tests").
//!
//! All tests use a **mock [`Upstream`]** — a canned-response stub that records
//! the request it was handed — so the full forward → reassemble → redact →
//! persist path runs with **no real network** (the plan's "injected client
//! trait" option). The proxy server itself is bound on loopback and driven with
//! `reqwest`.
//!
//! Coverage:
//! - a forwarded request is recorded as a **redacted** `Kind::Llm` event (a
//!   planted secret in the prompt is scrubbed; metadata is present);
//! - the proxy **refuses to start** without the Complete tier;
//! - a **streamed (SSE) response is reassembled + redacted** before persistence
//!   (a secret split across deltas is gone from the stored body);
//! - `prompts` off ⇒ **metadata-only** (no prompt/response bodies, metadata
//!   intact);
//! - the proxy is **bearer-gated** (401 without the token) and the mock never
//!   sees an unauthorized request;
//! - the real upstream bytes are **relayed unchanged** to the client.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use logbook_core::{CapturePolicy, Kind};
use logbook_llmproxy::{
    start_with_upstream, LlmProxyConfig, LlmProxyError, Provider, RunningProxy, TokenMode,
    Upstream, UpstreamRequest, UpstreamResponse,
};
use logbook_store::{Query, Store};

/// A mock upstream: returns a fixed response and records the last request it
/// received (so a test can assert what was forwarded). Never touches the network.
struct MockUpstream {
    response: UpstreamResponse,
    last_request: Mutex<Option<UpstreamRequest>>,
    last_base_url: Mutex<Option<String>>,
}

impl MockUpstream {
    fn new(response: UpstreamResponse) -> Arc<Self> {
        Arc::new(Self {
            response,
            last_request: Mutex::new(None),
            last_base_url: Mutex::new(None),
        })
    }

    fn taken_request(&self) -> Option<UpstreamRequest> {
        self.last_request.lock().unwrap().clone()
    }

    fn taken_base_url(&self) -> Option<String> {
        self.last_base_url.lock().unwrap().clone()
    }
}

#[async_trait]
impl Upstream for MockUpstream {
    async fn send(
        &self,
        base_url: &str,
        req: &UpstreamRequest,
    ) -> Result<UpstreamResponse, LlmProxyError> {
        *self.last_request.lock().unwrap() = Some(req.clone());
        *self.last_base_url.lock().unwrap() = Some(base_url.to_string());
        Ok(self.response.clone())
    }
}

fn json_response(status: u16, body: &[u8]) -> UpstreamResponse {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    UpstreamResponse {
        status,
        headers,
        body: body.to_vec(),
    }
}

fn sse_response(body: &str) -> UpstreamResponse {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());
    UpstreamResponse {
        status: 200,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

/// A complete-tier config for a single Anthropic upstream with a fixed token.
fn complete_config() -> LlmProxyConfig {
    LlmProxyConfig::single(Provider::Anthropic, "https://upstream.example")
        .with_port(0)
        .with_token_mode(TokenMode::Fixed("test-token".into()))
        .with_complete_tier()
}

/// A complete-tier config for a single OpenAI upstream with a fixed token.
fn openai_complete_config() -> LlmProxyConfig {
    LlmProxyConfig::single(Provider::OpenAi, "https://openai.example")
        .with_port(0)
        .with_token_mode(TokenMode::Fixed("test-token".into()))
        .with_complete_tier()
}

/// Start the proxy with a mock upstream, returning the running handle + store.
async fn start_proxy(
    config: LlmProxyConfig,
    upstream: Arc<dyn Upstream>,
) -> (RunningProxy, Store) {
    let store = Store::open_in_memory().unwrap();
    let proxy = start_with_upstream(config, store.clone(), upstream)
        .await
        .expect("proxy should start with the complete tier on");
    (proxy, store)
}

#[tokio::test]
async fn refuses_to_start_without_complete_tier() {
    // Default policy has complete=false ⇒ the proxy must refuse to start.
    let config = LlmProxyConfig::single(Provider::Anthropic, "https://upstream.example")
        .with_port(0)
        .with_token_mode(TokenMode::Fixed("t".into()));
    assert!(!config.capture_policy.tiers.complete);

    let store = Store::open_in_memory().unwrap();
    let upstream = MockUpstream::new(json_response(200, b"{}"));
    let err = start_with_upstream(config, store, upstream)
        .await
        .expect_err("must refuse without the complete tier");
    assert!(
        matches!(err, LlmProxyError::CompleteTierDisabled),
        "expected CompleteTierDisabled, got {err:?}"
    );
}

#[tokio::test]
async fn forwarded_request_is_recorded_as_redacted_llm_event() {
    let upstream = MockUpstream::new(json_response(
        200,
        br#"{"model":"claude-3-sonnet","usage":{"input_tokens":11,"output_tokens":4},"stop_reason":"end_turn"}"#,
    ));
    let (proxy, store) = start_proxy(complete_config(), upstream.clone()).await;

    let url = format!("http://127.0.0.1:{}/v1/messages", proxy.port());
    // The prompt body carries a planted secret that MUST be redacted in the store.
    let resp = reqwest::Client::new()
        .post(&url)
        .header("x-logbook-proxy-token", "test-token")
        .header("x-api-key", "sk-provider-key")
        .json(&serde_json::json!({
            "model": "claude-3-sonnet",
            "messages": [{"role": "user", "content": "deploy with AKIAIOSFODNN7EXAMPLE"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "client gets the relayed upstream status");

    // The mock saw the forwarded request at the right base URL, with the proxy
    // token header stripped but the Anthropic provider key preserved.
    let fwd = upstream.taken_request().expect("upstream received the request");
    assert_eq!(upstream.taken_base_url().as_deref(), Some("https://upstream.example"));
    assert_eq!(fwd.path_and_query, "/v1/messages");
    assert!(!fwd.headers.contains_key("x-logbook-proxy-token"), "proxy token must not be forwarded");
    assert_eq!(fwd.headers.get("x-api-key").map(String::as_str), Some("sk-provider-key"));

    // Exactly one Kind::Llm event was persisted, with full metadata...
    let events = store.query(&Query::new()).unwrap();
    assert_eq!(events.len(), 1, "one llm event recorded");
    let ev = &events[0];
    assert_eq!(ev.kind, Kind::Llm);
    let llm = ev.blocks.llm.as_ref().unwrap();
    assert_eq!(llm.provider.as_deref(), Some("anthropic"));
    assert_eq!(llm.model.as_deref(), Some("claude-3-sonnet"));
    assert_eq!(llm.input_tokens, Some(11));
    assert_eq!(llm.output_tokens, Some(4));
    assert_eq!(llm.finish_reason.as_deref(), Some("end_turn"));
    assert_eq!(llm.stream, Some(false));

    // ...and the recorded prompt is REDACTED (secret gone, marker present).
    let prompt = ev.input.as_ref().expect("prompt captured").as_str().unwrap();
    assert!(!prompt.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into store: {prompt}");
    assert!(prompt.contains("REDACTED:CLOUD_KEY:"), "no redaction marker: {prompt}");

    proxy.shutdown().await;
}

#[tokio::test]
async fn openai_round_trip_forwards_provider_authorization_and_strips_proxy_token() {
    // Regression for the OpenAI-lane auth bug: the OpenAI provider key rides
    // `Authorization`, while the proxy authenticates on its own dedicated header.
    // The forwarded request MUST keep the provider's `Authorization` (so the key
    // reaches OpenAI and the call doesn't 401) and MUST drop the proxy token.
    let upstream = MockUpstream::new(json_response(
        200,
        br#"{"model":"gpt-4o","usage":{"prompt_tokens":6,"completion_tokens":3},"choices":[{"finish_reason":"stop"}]}"#,
    ));
    let (proxy, store) = start_proxy(openai_complete_config(), upstream.clone()).await;

    let url = format!("http://127.0.0.1:{}/v1/chat/completions", proxy.port());
    let resp = reqwest::Client::new()
        .post(&url)
        // The proxy token on its dedicated header authenticates the agent → proxy
        // hop; the OpenAI key rides `Authorization` like a normal OpenAI request.
        .header("x-logbook-proxy-token", "test-token")
        .bearer_auth("sk-openai-secret-key")
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "client gets the relayed upstream status");

    // The mock upstream asserts the forwarded request carries the provider key on
    // `Authorization` (verbatim) and does NOT carry the proxy token.
    let fwd = upstream.taken_request().expect("upstream received the request");
    assert_eq!(upstream.taken_base_url().as_deref(), Some("https://openai.example"));
    assert_eq!(fwd.path_and_query, "/v1/chat/completions");
    assert_eq!(
        fwd.headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret-key"),
        "OpenAI provider key on Authorization must survive to the upstream"
    );
    assert!(
        !fwd.headers.contains_key("x-logbook-proxy-token"),
        "proxy token must never be forwarded upstream"
    );

    // And the call is recorded as a normal OpenAI event.
    let events = store.query(&Query::new()).unwrap();
    assert_eq!(events.len(), 1, "one llm event recorded");
    let llm = events[0].blocks.llm.as_ref().unwrap();
    assert_eq!(llm.provider.as_deref(), Some("openai"));
    assert_eq!(llm.model.as_deref(), Some("gpt-4o"));

    proxy.shutdown().await;
}

#[tokio::test]
async fn streamed_response_is_reassembled_and_redacted_before_persistence() {
    // A streamed completion whose text spans two deltas and contains a secret
    // straddling the chunk boundary. Correct behavior: reassemble the full
    // stream, THEN redact — so the secret is gone from the stored body, proving
    // raw chunks were never persisted.
    let stream = "data: {\"model\":\"claude-3\",\"choices\":[{\"delta\":{\"content\":\"token AKIA\"}}]}\n\n\
                  data: {\"choices\":[{\"delta\":{\"content\":\"IOSFODNN7EXAMPLE end\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":7}}\n\n\
                  data: [DONE]\n\n";
    let upstream = MockUpstream::new(sse_response(stream));
    let (proxy, store) = start_proxy(complete_config(), upstream).await;

    let url = format!("http://127.0.0.1:{}/v1/messages", proxy.port());
    let resp = reqwest::Client::new()
        .post(&url)
        .header("x-logbook-proxy-token", "test-token")
        .json(&serde_json::json!({"model": "claude-3", "stream": true, "messages": []}))
        .send()
        .await
        .unwrap();
    // The client receives the raw SSE bytes unchanged (relayed verbatim).
    let relayed = resp.text().await.unwrap();
    // The secret is SPLIT across the two SSE deltas ("token AKIA" |
    // "IOSFODNN7EXAMPLE end"), so the contiguous secret never appears on the wire;
    // both raw halves reach the client unredacted (only the PERSISTED, reassembled
    // body is redacted — see below). This proves verbatim relay.
    assert!(relayed.contains("token AKIA"), "raw delta 1 must reach the client: {relayed}");
    assert!(relayed.contains("IOSFODNN7EXAMPLE end"), "raw delta 2 must reach the client: {relayed}");

    let events = store.query(&Query::new()).unwrap();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    let llm = ev.blocks.llm.as_ref().unwrap();
    assert_eq!(llm.stream, Some(true), "stream flag recorded");
    assert_eq!(llm.output_tokens, Some(7), "usage reassembled from the stream");

    // The STORED body is reassembled + redacted: the secret that straddled the
    // delta boundary is scrubbed, and benign text survived.
    let stored = ev.output.as_ref().expect("response captured").as_str().unwrap();
    assert!(!stored.contains("AKIAIOSFODNN7EXAMPLE"), "secret survived in store: {stored}");
    assert!(stored.contains("end"), "reassembled text lost: {stored}");
    assert!(stored.contains("REDACTED:CLOUD_KEY:"), "no redaction marker: {stored}");

    proxy.shutdown().await;
}

#[tokio::test]
async fn prompts_off_records_metadata_only() {
    // Turn prompt + response body capture OFF (keeping the complete tier on).
    let mut policy = CapturePolicy::default();
    policy.tiers.complete = true;
    policy.classes.prompts.capture = false;
    policy.classes.tool_results.capture = false;
    let config = LlmProxyConfig::single(Provider::OpenAi, "https://upstream.example")
        .with_port(0)
        .with_token_mode(TokenMode::Fixed("test-token".into()))
        .with_capture_policy(policy);

    let upstream = MockUpstream::new(json_response(
        200,
        br#"{"model":"gpt-4o","usage":{"prompt_tokens":9,"completion_tokens":2},"choices":[{"finish_reason":"stop"}]}"#,
    ));
    let (proxy, store) = start_proxy(config, upstream).await;

    let url = format!("http://127.0.0.1:{}/v1/chat/completions", proxy.port());
    let resp = reqwest::Client::new()
        .post(&url)
        .header("x-logbook-proxy-token", "test-token")
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "this prompt must NOT be stored"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let events = store.query(&Query::new()).unwrap();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    // No bodies stored...
    assert!(ev.input.is_none(), "prompt must be omitted when prompts off");
    assert!(ev.output.is_none(), "response body must be omitted when tool_results off");
    // ...but metadata fully present.
    let llm = ev.blocks.llm.as_ref().unwrap();
    assert_eq!(llm.provider.as_deref(), Some("openai"));
    assert_eq!(llm.model.as_deref(), Some("gpt-4o"));
    assert_eq!(llm.input_tokens, Some(9));
    assert_eq!(llm.output_tokens, Some(2));

    // Belt-and-suspenders: the omitted prompt text appears NOWHERE in the row.
    let row = serde_json::to_string(ev).unwrap();
    assert!(!row.contains("this prompt must NOT be stored"), "prompt leaked despite prompts-off: {row}");

    proxy.shutdown().await;
}

#[tokio::test]
async fn unauthorized_request_is_rejected_and_not_forwarded() {
    let upstream = MockUpstream::new(json_response(200, b"{}"));
    let (proxy, store) = start_proxy(complete_config(), upstream.clone()).await;

    let url = format!("http://127.0.0.1:{}/v1/messages", proxy.port());

    // No proxy-token header ⇒ 401.
    let unauth = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"model": "claude-3"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);

    // Wrong proxy token ⇒ 401.
    let wrong = reqwest::Client::new()
        .post(&url)
        .header("x-logbook-proxy-token", "nope")
        .json(&serde_json::json!({"model": "claude-3"}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);

    // A provider credential on `Authorization` alone must NOT authorize the proxy
    // hop — the proxy token lives on its own dedicated header.
    let auth_only = reqwest::Client::new()
        .post(&url)
        .bearer_auth("test-token")
        .json(&serde_json::json!({"model": "claude-3"}))
        .send()
        .await
        .unwrap();
    assert_eq!(auth_only.status(), 401);

    // The upstream was never called and nothing was persisted.
    assert!(upstream.taken_request().is_none(), "unauthorized request must not be forwarded");
    assert_eq!(store.count().unwrap(), 0, "unauthorized request must not persist");

    proxy.shutdown().await;
}

#[tokio::test]
async fn health_is_public() {
    let upstream = MockUpstream::new(json_response(200, b"{}"));
    let (proxy, _store) = start_proxy(complete_config(), upstream).await;
    let url = format!("http://127.0.0.1:{}/health", proxy.port());
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], serde_json::json!(true));
    proxy.shutdown().await;
}
