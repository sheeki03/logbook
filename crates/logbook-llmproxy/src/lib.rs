//! `logbook-llmproxy` — the **Complete tier** LLM API proxy (plan "Phase 4 —
//! Complete Tier & Fleet").
//!
//! An **opt-in, loopback-only, bearer-gated** HTTP server an agent points
//! `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at. It forwards each request to the
//! real provider and records the call as a redacted [`Kind::Llm`] event carrying
//! a full [`LlmBlock`] (provider, model, input/output tokens, cost when
//! derivable, finish-reason, stream flag).
//!
//! ```no_run
//! use logbook_llmproxy::{run_llm_proxy, LlmProxyConfig, Provider};
//! use logbook_store::Store;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let store = Store::open_in_memory()?;
//! // The Complete tier MUST be enabled or `run_llm_proxy` refuses to start.
//! let mut config = LlmProxyConfig::single(Provider::Anthropic, "https://api.anthropic.com");
//! config.capture_policy.tiers.complete = true;
//! let proxy = run_llm_proxy(config, store).await?;
//! // point ANTHROPIC_BASE_URL at proxy.addr() ...
//! proxy.shutdown().await;
//! # Ok(()) }
//! ```
//!
//! # The privacy contract (sacred)
//! The proxy is the **only** component in logbook that sees raw provider
//! payloads, so it carries the strictest version of the redaction-before-
//! persistence rule:
//!
//! - It **refuses to start** unless the resolved [`CapturePolicy`] has the
//!   **Complete tier** enabled ([`LlmProxyError::CompleteTierDisabled`]).
//! - Prompt (request) and response bodies are captured **only** when the
//!   `prompts` / `tool_results` classes are on, and are **always force-redacted**
//!   through [`HarnessContext`](logbook_harness::HarnessContext) — the general
//!   redactor, the mandatory secrets floor, and a per-class byte cap — before
//!   they ever touch an [`Event`].
//! - **Streaming (SSE) responses are reassembled in full, THEN redacted, THEN
//!   persisted** — individual chunks are never logged or stored (the buffering
//!   happens in [`upstream`], the reassembly + redaction in [`record`]).
//! - Metadata (model / token counts / cost / finish-reason / stream) may be
//!   recorded even when prompt/result capture is off (`prompts`-off ⇒
//!   metadata-only).
//! - The real upstream bytes are relayed back to the client unchanged; only the
//!   *stored* copy is redacted.
//!
//! # Testability
//! Forwarding goes through the injectable [`Upstream`] trait, so the whole
//! forward → reassemble → redact → persist path is exercised in tests against a
//! mock with **no real network** (see [`start_with_upstream`] and the crate's
//! integration tests).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod record;
pub mod server;
pub mod upstream;

use std::net::IpAddr;

use logbook_core::CapturePolicy;

pub use error::LlmProxyError;
pub use server::{
    bind_with_auto_increment, loopback, run_llm_proxy, start_with_upstream, RunningProxy,
    PROXY_TOKEN_HEADER,
};
pub use upstream::{ReqwestUpstream, Upstream, UpstreamRequest, UpstreamResponse};

/// The environment variable consulted for the proxy bearer token when
/// [`TokenMode::Generated`] / [`TokenMode::Env`] is used.
pub const ENV_TOKEN_VAR: &str = "LOGBOOK_LLMPROXY_TOKEN";

/// A provider the proxy can forward to. Each maps to its own upstream base URL,
/// its own request/response shape (handled in [`record`]), and its own URL
/// routing prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic Messages API (`/v1/messages`; `x-api-key`).
    Anthropic,
    /// OpenAI (bearer key). Both the **Chat Completions** (`/v1/chat/completions`)
    /// and **Responses** (`/v1/responses`) wire shapes route here; the recorder
    /// picks the parser per request (see [`WireApi`]).
    OpenAi,
}

/// Which OpenAI *wire shape* a forwarded call uses, i.e. which parser the
/// recording path applies to the request/response. Anthropic has a single shape
/// (Messages) so this only differentiates the two OpenAI surfaces, but the lane
/// is resolved uniformly for every provider.
///
/// - [`WireApi::Chat`] — the **Chat Completions** shape
///   (`POST /v1/chat/completions`; response `choices[].message.content`;
///   `usage.prompt_tokens`/`completion_tokens`).
/// - [`WireApi::Responses`] — the **Responses** shape (`POST /v1/responses`;
///   request `input` + `instructions`; response `output[]` items with
///   `output_text` parts; `usage.input_tokens`/`output_tokens`; `status` /
///   `incomplete_details`). Codex and newer clients use this.
/// - [`WireApi::Auto`] (the default) — pick the parser per request: by the
///   request **path** first (`/v1/responses` ⇒ Responses; `/v1/chat/completions`
///   ⇒ Chat), then a response **shape sniff** when the path is unrecognized.
///
/// The relay is byte-exact regardless; this only selects how the **recorded**
/// copy is parsed for model / tokens / finish / output text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WireApi {
    /// Auto-detect the lane per request (path first, then response shape).
    #[default]
    Auto,
    /// Force the Chat Completions parser.
    Chat,
    /// Force the Responses-API parser.
    Responses,
}

impl Provider {
    /// Stable lowercase wire string (used as `LlmBlock.provider` and the routing
    /// prefix `/<as_str>/...`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAi => "openai",
        }
    }

    /// The conventional public upstream base URL for the provider (used by
    /// [`LlmProxyConfig::single`] / [`LlmProxyConfig::dual`] as a default; always
    /// overridable per provider).
    #[must_use]
    pub const fn default_base_url(self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com",
            Provider::OpenAi => "https://api.openai.com",
        }
    }
}

/// Per-model price, in **USD per 1,000,000 tokens**, for `cost_usd` derivation.
/// Cost is recorded only when a matching price is configured *and* the response
/// reported token counts (plan: "cost if derivable").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModelPrice {
    /// USD per 1M input (prompt) tokens.
    pub input_per_mtok: f64,
    /// USD per 1M output (completion) tokens.
    pub output_per_mtok: f64,
}

/// How the proxy bearer token is sourced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TokenMode {
    /// Use this exact secret.
    Fixed(String),
    /// Use `LOGBOOK_LLMPROXY_TOKEN` if set & non-empty, else mint a fresh
    /// 256-bit token at startup (the default).
    #[default]
    Generated,
    /// Require `LOGBOOK_LLMPROXY_TOKEN`; an unset/empty value is a hard error.
    Env,
    /// No token — **dev/test only**; every request is allowed.
    Off,
}

/// One configured provider upstream: its base URL plus an optional per-model
/// price table for cost derivation.
#[derive(Clone, Debug, Default)]
pub struct UpstreamConfig {
    /// The provider's real API root (e.g. `https://api.anthropic.com`). The
    /// request path is appended to this.
    pub base_url: String,
    /// Per-model USD price (per 1M tokens), keyed by the model id reported in the
    /// request/response. Empty ⇒ no cost derivation for this provider.
    pub prices: std::collections::BTreeMap<String, ModelPrice>,
}

impl UpstreamConfig {
    /// An upstream with the given base URL and no price table.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            prices: std::collections::BTreeMap::new(),
        }
    }

    /// Add a per-model price (builder-style).
    #[must_use]
    pub fn with_price(mut self, model: impl Into<String>, price: ModelPrice) -> Self {
        self.prices.insert(model.into(), price);
        self
    }
}

/// Configuration for the LLM proxy (the public config struct surfaced alongside
/// the [`run_llm_proxy`] run entry).
///
/// Construct via [`Self::single`] (one provider) or [`Self::dual`] (both, routed
/// by `/anthropic` / `/openai` URL prefix), then flip
/// `capture_policy.tiers.complete = true` (required) and adjust the bind / token
/// / redaction knobs.
#[derive(Clone, Debug)]
pub struct LlmProxyConfig {
    /// Bind host. Defaults to `127.0.0.1`; non-loopback hosts are rejected at
    /// start.
    pub host: IpAddr,
    /// Preferred starting port. `0` lets the OS choose (and disables
    /// auto-increment).
    pub port: u16,
    /// The Anthropic upstream, if this proxy serves Anthropic traffic.
    pub anthropic: Option<UpstreamConfig>,
    /// The OpenAI upstream, if this proxy serves OpenAI traffic.
    pub openai: Option<UpstreamConfig>,
    /// How the bearer token is sourced.
    pub token_mode: TokenMode,
    /// Whether the **general** redactor is enabled (default true). The mandatory
    /// secrets floor always applies regardless (`--no-redact` cannot expose a
    /// secret).
    pub redact: bool,
    /// Whether to additionally extend the tamper-evident audit hash chain over
    /// each recorded (already-redacted) event. Off by default.
    pub audit: bool,
    /// The resolved capture policy. **Must** have `tiers.complete = true` or the
    /// proxy refuses to start. Prompt/result body capture is further gated by the
    /// `prompts` / `tool_results` classes here.
    pub capture_policy: CapturePolicy,
    /// Which OpenAI wire shape the **recording** path parses. Defaults to
    /// [`WireApi::Auto`] (detect per request by path, then response shape);
    /// [`WireApi::Chat`] / [`WireApi::Responses`] force the lane (the
    /// `--wire-api` CLI flag). The relay is byte-exact regardless.
    pub wire_api: WireApi,
}

impl LlmProxyConfig {
    /// A single-provider config (no URL prefix needed; every request routes to
    /// this provider) with the given upstream base URL.
    ///
    /// **Note:** the returned config does **not** enable the Complete tier — the
    /// caller must set `capture_policy.tiers.complete = true` before
    /// [`run_llm_proxy`] will start (the gate is deliberate).
    #[must_use]
    pub fn single(provider: Provider, base_url: impl Into<String>) -> Self {
        let upstream = Some(UpstreamConfig::new(base_url));
        let (anthropic, openai) = match provider {
            Provider::Anthropic => (upstream, None),
            Provider::OpenAi => (None, upstream),
        };
        Self {
            host: server::loopback(),
            port: 0,
            anthropic,
            openai,
            token_mode: TokenMode::default(),
            redact: true,
            audit: false,
            capture_policy: CapturePolicy::default(),
            wire_api: WireApi::default(),
        }
    }

    /// A dual-provider config: Anthropic traffic on the `/anthropic/...` prefix,
    /// OpenAI on `/openai/...`, each with its given base URL.
    #[must_use]
    pub fn dual(anthropic_base: impl Into<String>, openai_base: impl Into<String>) -> Self {
        Self {
            host: server::loopback(),
            port: 0,
            anthropic: Some(UpstreamConfig::new(anthropic_base)),
            openai: Some(UpstreamConfig::new(openai_base)),
            token_mode: TokenMode::default(),
            redact: true,
            audit: false,
            capture_policy: CapturePolicy::default(),
            wire_api: WireApi::default(),
        }
    }

    /// Set the preferred port (builder-style).
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the token mode (builder-style).
    #[must_use]
    pub fn with_token_mode(mut self, mode: TokenMode) -> Self {
        self.token_mode = mode;
        self
    }

    /// Enable the Complete tier on the embedded policy (builder-style
    /// convenience; the gate still requires this to be on).
    #[must_use]
    pub fn with_complete_tier(mut self) -> Self {
        self.capture_policy.tiers.complete = true;
        self
    }

    /// Set the capture policy (builder-style).
    #[must_use]
    pub fn with_capture_policy(mut self, policy: CapturePolicy) -> Self {
        self.capture_policy = policy;
        self
    }

    /// Force the recording-path wire shape (builder-style). Defaults to
    /// [`WireApi::Auto`] (per-request detection); use [`WireApi::Chat`] /
    /// [`WireApi::Responses`] to pin the lane (the `--wire-api` CLI flag).
    #[must_use]
    pub fn with_wire_api(mut self, wire_api: WireApi) -> Self {
        self.wire_api = wire_api;
        self
    }

    /// Disable the general redactor (`--no-redact`). The secrets floor still
    /// applies. Callers should warn.
    #[must_use]
    pub fn without_redaction(mut self) -> Self {
        self.redact = false;
        self
    }

    /// Enable extending the audit hash chain over each recorded event.
    #[must_use]
    pub fn with_audit(mut self) -> Self {
        self.audit = true;
        self
    }

    /// The number of providers this proxy serves.
    fn provider_count(&self) -> usize {
        usize::from(self.anthropic.is_some()) + usize::from(self.openai.is_some())
    }

    /// Route a request path to a provider and the **upstream-relative** path.
    ///
    /// - With a single configured provider, every path routes to it unchanged.
    /// - With both providers, the path must be prefixed `/<provider>/...`
    ///   (`/anthropic/v1/messages` → `(Anthropic, "/v1/messages")`); an unknown
    ///   prefix returns `None` (the handler answers `502`).
    pub(crate) fn route(&self, path_and_query: &str) -> Option<(Provider, String)> {
        // Explicit provider prefix always wins, even in single-provider mode.
        for provider in [Provider::Anthropic, Provider::OpenAi] {
            let prefix = format!("/{}", provider.as_str());
            if let Some(rest) = strip_provider_prefix(path_and_query, &prefix) {
                if self.upstream(provider).is_some() {
                    return Some((provider, rest));
                }
                return None;
            }
        }
        // No prefix: only valid when exactly one provider is configured.
        if self.provider_count() == 1 {
            let provider = if self.anthropic.is_some() {
                Provider::Anthropic
            } else {
                Provider::OpenAi
            };
            return Some((provider, path_and_query.to_string()));
        }
        None
    }

    /// The configured upstream for a provider, if any.
    fn upstream(&self, provider: Provider) -> Option<&UpstreamConfig> {
        match provider {
            Provider::Anthropic => self.anthropic.as_ref(),
            Provider::OpenAi => self.openai.as_ref(),
        }
    }

    /// The upstream base URL for a provider (empty string if somehow unset —
    /// routing guarantees the provider is configured before this is called).
    pub(crate) fn upstream_base(&self, provider: Provider) -> &str {
        self.upstream(provider)
            .map(|u| u.base_url.as_str())
            .unwrap_or("")
    }

    /// The per-model price for a request, if the provider has one for the model
    /// named in the request body.
    pub(crate) fn price_for(&self, provider: Provider, req: &UpstreamRequest) -> Option<ModelPrice> {
        let model = req
            .body_json()?
            .get("model")?
            .as_str()?
            .to_string();
        self.upstream(provider)?.prices.get(&model).copied()
    }

    /// Resolve the bearer token from [`Self::token_mode`].
    ///
    /// # Errors
    /// Returns [`LlmProxyError::Token`] for `Env` mode with an unset/empty
    /// variable, or if entropy is unavailable when generating.
    pub(crate) fn resolve_token(&self) -> Result<Option<String>, LlmProxyError> {
        match &self.token_mode {
            TokenMode::Off => Ok(None),
            TokenMode::Fixed(s) => Ok(Some(s.clone())),
            TokenMode::Env => {
                let v = std::env::var(ENV_TOKEN_VAR).unwrap_or_default();
                if v.trim().is_empty() {
                    Err(LlmProxyError::Token(format!(
                        "token_mode=env but {ENV_TOKEN_VAR} is unset or empty"
                    )))
                } else {
                    Ok(Some(v))
                }
            }
            TokenMode::Generated => {
                if let Ok(v) = std::env::var(ENV_TOKEN_VAR) {
                    if !v.trim().is_empty() {
                        return Ok(Some(v));
                    }
                }
                Ok(Some(generate_token()?))
            }
        }
    }
}

/// Strip a `/<provider>` prefix from a path, returning the remainder (with a
/// leading `/`). Matches `/anthropic`, `/anthropic/...`, but not `/anthropicx`.
fn strip_provider_prefix(path: &str, prefix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some("/".to_string())
    } else if rest.starts_with('/') {
        Some(rest.to_string())
    } else {
        // e.g. prefix `/openai` against `/openaix/...` — not a real match.
        None
    }
}

/// Mint a 256-bit token rendered as 64 lowercase hex chars (two W3C-width trace
/// ids of OS entropy), reusing the vetted `logbook_core` generator.
fn generate_token() -> Result<String, LlmProxyError> {
    let a = logbook_core::TraceId::try_new().map_err(|e| LlmProxyError::Token(e.to_string()))?;
    let b = logbook_core::TraceId::try_new().map_err(|e| LlmProxyError::Token(e.to_string()))?;
    Ok(format!("{}{}", a.to_hex(), b.to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_provider_routes_without_prefix() {
        let cfg = LlmProxyConfig::single(Provider::Anthropic, "https://api.anthropic.com");
        let (p, path) = cfg.route("/v1/messages").unwrap();
        assert_eq!(p, Provider::Anthropic);
        assert_eq!(path, "/v1/messages");
        assert_eq!(cfg.upstream_base(Provider::Anthropic), "https://api.anthropic.com");
    }

    #[test]
    fn single_provider_still_honors_explicit_prefix() {
        let cfg = LlmProxyConfig::single(Provider::OpenAi, "https://api.openai.com");
        let (p, path) = cfg.route("/openai/v1/chat/completions").unwrap();
        assert_eq!(p, Provider::OpenAi);
        assert_eq!(path, "/v1/chat/completions");
        // A prefix for an UNconfigured provider is rejected.
        assert!(cfg.route("/anthropic/v1/messages").is_none());
    }

    #[test]
    fn dual_provider_routes_by_prefix() {
        let cfg = LlmProxyConfig::dual("https://a.example", "https://o.example");
        let (pa, path_a) = cfg.route("/anthropic/v1/messages").unwrap();
        assert_eq!(pa, Provider::Anthropic);
        assert_eq!(path_a, "/v1/messages");
        assert_eq!(cfg.upstream_base(Provider::Anthropic), "https://a.example");

        let (po, pq) = cfg.route("/openai/v1/chat/completions?stream=true").unwrap();
        assert_eq!(po, Provider::OpenAi);
        assert_eq!(pq, "/v1/chat/completions?stream=true");

        // No prefix is ambiguous with two providers ⇒ unrouted.
        assert!(cfg.route("/v1/messages").is_none());
    }

    #[test]
    fn strip_provider_prefix_is_boundary_safe() {
        assert_eq!(strip_provider_prefix("/openai/x", "/openai").as_deref(), Some("/x"));
        assert_eq!(strip_provider_prefix("/openai", "/openai").as_deref(), Some("/"));
        // Must not match a longer path segment.
        assert_eq!(strip_provider_prefix("/openaix/y", "/openai"), None);
    }

    #[test]
    fn price_for_reads_model_from_body() {
        let mut cfg = LlmProxyConfig::single(Provider::Anthropic, "https://a.example");
        cfg.anthropic = Some(
            UpstreamConfig::new("https://a.example").with_price(
                "claude-3",
                ModelPrice { input_per_mtok: 3.0, output_per_mtok: 15.0 },
            ),
        );
        let req = UpstreamRequest {
            method: "POST".into(),
            path_and_query: "/v1/messages".into(),
            headers: Default::default(),
            body: br#"{"model":"claude-3"}"#.to_vec(),
        };
        let price = cfg.price_for(Provider::Anthropic, &req).unwrap();
        assert_eq!(price.input_per_mtok, 3.0);
        // An unknown model ⇒ no price.
        let req2 = UpstreamRequest {
            body: br#"{"model":"unknown"}"#.to_vec(),
            ..req
        };
        assert!(cfg.price_for(Provider::Anthropic, &req2).is_none());
    }

    #[test]
    fn provider_as_str_is_stable() {
        assert_eq!(Provider::Anthropic.as_str(), "anthropic");
        assert_eq!(Provider::OpenAi.as_str(), "openai");
    }

    #[test]
    fn wire_api_defaults_to_auto_and_is_overridable() {
        // The config defaults to auto-detection...
        let cfg = LlmProxyConfig::single(Provider::OpenAi, "https://api.openai.com");
        assert_eq!(cfg.wire_api, WireApi::Auto);
        assert_eq!(WireApi::default(), WireApi::Auto);
        // ...and the builder pins the lane.
        let forced = cfg.with_wire_api(WireApi::Responses);
        assert_eq!(forced.wire_api, WireApi::Responses);
    }

    #[test]
    fn fixed_token_resolves_verbatim() {
        let cfg = LlmProxyConfig::single(Provider::Anthropic, "https://a.example")
            .with_token_mode(TokenMode::Fixed("the-token".into()));
        assert_eq!(cfg.resolve_token().unwrap(), Some("the-token".to_string()));
    }

    #[test]
    fn off_token_is_none() {
        let cfg = LlmProxyConfig::single(Provider::Anthropic, "https://a.example")
            .with_token_mode(TokenMode::Off);
        assert_eq!(cfg.resolve_token().unwrap(), None);
    }
}
