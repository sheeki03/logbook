//! Error type for the LLM proxy crate.

use std::net::IpAddr;

use thiserror::Error;

/// Errors raised while starting or running the [`run_llm_proxy`](crate::run_llm_proxy)
/// server.
#[derive(Debug, Error)]
pub enum LlmProxyError {
    /// The resolved [`CapturePolicy`](logbook_core::CapturePolicy) does not have
    /// the **complete** tier enabled. The proxy is the one component that sees
    /// raw provider payloads, so it **refuses to start** unless the operator has
    /// explicitly turned on the Complete tier (plan "Phase 4": "refuses to start
    /// unless `complete` enabled"). This is a hard gate, distinct from the
    /// per-class prompt/result capture toggles.
    #[error("refusing to start the LLM proxy: the resolved capture policy does not enable the 'complete' tier (tiers.complete=false). The Complete tier captures raw provider traffic and must be explicitly enabled.")]
    CompleteTierDisabled,

    /// The configured bind host is not a loopback address. The proxy only ever
    /// binds `127.0.0.1`/`::1` — an agent points `ANTHROPIC_BASE_URL` /
    /// `OPENAI_BASE_URL` at it locally; it is never a public listener.
    #[error("refusing to bind non-loopback host {0}: the LLM proxy is loopback-only")]
    NonLoopbackBind(IpAddr),

    /// No port in the auto-increment range could be bound.
    #[error("failed to bind a port starting at {port}: {source}")]
    Bind {
        /// The preferred port that was attempted first.
        port: u16,
        /// The underlying I/O error from the last attempt.
        #[source]
        source: std::io::Error,
    },

    /// The bearer token could not be resolved (e.g. entropy unavailable when
    /// generating one).
    #[error("failed to resolve the proxy bearer token: {0}")]
    Token(String),

    /// A configured upstream base URL could not be parsed.
    #[error("invalid upstream base URL for provider {provider}: {url}")]
    BadUpstreamUrl {
        /// The provider whose upstream URL was rejected.
        provider: &'static str,
        /// The offending URL string.
        url: String,
    },

    /// Building the upstream HTTP client failed.
    #[error("failed to build the upstream HTTP client: {0}")]
    Client(String),
}
