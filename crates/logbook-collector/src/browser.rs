//! The [`BrowserCapture`] trait shared by the browser-capture adapters
//! (plan §4).
//!
//! In v1 only [`crate::injected::InjectedJsAdapter`] implements
//! [`BrowserCapture`] (it produces an injected-JS shim that posts to
//! `/ingest`). [`crate::schrute_mcp::SchruteAdapter`] — an MCP client to
//! schrute for a verified record/replay/network subset, with logbook's own
//! egress allowlist enforced locally — does **not** implement the trait; it
//! exposes its own async MCP surface instead, so `CaptureKind::SchruteMcp` is
//! reserved but not yet produced.

/// How a [`BrowserCapture`] adapter sources its events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureKind {
    /// Events arrive over `POST /ingest` from a page-injected JS shim.
    Injected,
    /// Events are pulled from schrute over an MCP stdio connection. Reserved
    /// for a future adapter: [`crate::schrute_mcp::SchruteAdapter`] does not
    /// implement [`BrowserCapture`] in v1, so this variant is not yet produced.
    SchruteMcp,
}

/// A source of browser observations that lands events on the logbook timeline.
///
/// The trait is intentionally small in v1: it identifies the adapter and how it
/// captures. Concrete adapters expose their own richer, async surface (snippet
/// generation for [`crate::injected::InjectedJsAdapter`]; MCP calls for
/// [`crate::schrute_mcp::SchruteAdapter`], which does not implement this trait)
/// because their lifecycles differ enough that a single `capture()` method
/// would be a leaky abstraction in v1.
pub trait BrowserCapture {
    /// A short, stable adapter name (used in logs / the UI).
    fn name(&self) -> &str;

    /// How this adapter captures.
    fn capture_kind(&self) -> CaptureKind;
}
