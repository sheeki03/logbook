//! [`LoggingMcpTransport`] — a logging decorator over any [`McpTransport`]
//! (plan "Phase 2", MCP proxy row).
//!
//! Wraps an existing transport and, on **every `tools/call` request**, emits one
//! [`Kind::Tool`] [`Event`] capturing the call: the (redacted) `arguments` under
//! the `tool_args` class, and the (redacted) result under `tool_results`, both
//! routed through a [`HarnessContext`] so **no raw payload is ever persisted**
//! (plan §9: redaction-before-persistence is sacred). The event is persisted via
//! the supplied [`Store`] under a caller-provided trace/session.
//!
//! The decorator is transport-agnostic: it forwards *all* frames verbatim to the
//! inner transport (`initialize`, `tools/list`, notifications, …) and only
//! *additionally* records `tools/call` exchanges. It never alters the JSON-RPC
//! bytes the inner transport sees or returns, so it is safe to slot in front of
//! [`SchruteAdapter`]'s transport **or** a passthrough [`StdioTransport`] to a
//! real MCP server (see [`crate::mcp_proxy`]) without changing protocol
//! behavior.
//!
//! ## Egress allowlist stays in front
//! Logging does not relax any gate. When the wrapped flow is schrute via
//! [`SchruteAdapter`], that adapter still runs [`crate::EgressAllowlist`] before
//! it ever issues a navigation/replay call — the logging layer sits *below* the
//! adapter (it only sees frames the adapter already decided to send), so a
//! refused target is never logged because the call is never made. A caller
//! wiring the decorator directly (the passthrough proxy) supplies its own
//! allowlist check before `request()` for any target-bearing tool.
//!
//! ## What is logged, exactly
//! For a `tools/call` request `{method:"tools/call", params:{name, arguments}}`
//! and its response:
//! - `Kind::Tool` / `Category::Agent`, `name = <tool name>`;
//! - [`ToolBlock`] `tool_name`, `is_write` (heuristic on the tool name),
//!   redacted `arguments` (`tool_args`), redacted `result_summary`
//!   (`tool_results`);
//! - the redacted full result text in [`Event::output`] (`tool_results`);
//! - `status = Error` when the response carries a JSON-RPC `error` or the tool
//!   result sets `isError: true`.
//!
//! When a class is *capture-off* in the policy, that payload is omitted (the
//! event is still emitted as a turn anchor) — mirroring the harness adapters.

use std::sync::Arc;

use serde_json::Value;

use logbook_core::{
    text::truncate_with_ellipsis, Category, Event, Kind, SessionId, Status, ToolBlock, TraceId,
};
use logbook_harness::{class, HarnessContext};
use logbook_store::Store;

use crate::schrute_mcp::{McpTransport, SchruteError};

/// Tool names that indicate a mutating ("write") operation, used to populate
/// [`ToolBlock::is_write`]. Mirrors the harness adapters' heuristic so the proxy
/// and the hook/session-log adapters agree on what counts as a write.
const WRITE_TOOLS: &[&str] = &[
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "create",
    "delete",
    "rename",
    "move",
    "bash",
    "applypatch",
    "str_replace",
    "str_replace_editor",
];

/// Whether a tool name looks like a mutating operation (case-insensitive).
fn is_write_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WRITE_TOOLS.iter().any(|w| lower == *w)
}

/// A logging decorator over an [`McpTransport`].
///
/// Construct with [`LoggingMcpTransport::new`], supplying the inner transport,
/// the [`Store`] to persist into, the [`HarnessContext`] (redactor + capture
/// policy), and the `trace`/`session` every emitted tool event is tagged with.
/// Then use it anywhere an `McpTransport` is expected — e.g. hand it to
/// [`SchruteAdapter::new`](crate::SchruteAdapter), or drive it directly in a
/// passthrough proxy.
pub struct LoggingMcpTransport<T: McpTransport> {
    inner: T,
    store: Arc<Store>,
    ctx: Arc<HarnessContext>,
    trace: TraceId,
    session: SessionId,
    /// Harness label stamped on emitted events (e.g. `mcp-proxy`). Defaults to
    /// [`Self::DEFAULT_HARNESS`].
    harness: String,
    /// Count of `tools/call` events emitted (diagnostics / tests).
    logged: u64,
}

impl<T: McpTransport> LoggingMcpTransport<T> {
    /// Default harness label stamped on emitted tool events.
    pub const DEFAULT_HARNESS: &'static str = "mcp-proxy";

    /// Wrap `inner`, persisting redacted `tools/call` events into `store` under
    /// `trace`/`session`, routing every payload through `ctx`.
    #[must_use]
    pub fn new(
        inner: T,
        store: Arc<Store>,
        ctx: Arc<HarnessContext>,
        trace: TraceId,
        session: SessionId,
    ) -> Self {
        Self {
            inner,
            store,
            ctx,
            trace,
            session,
            harness: Self::DEFAULT_HARNESS.to_string(),
            logged: 0,
        }
    }

    /// Override the harness label stamped on emitted events.
    #[must_use]
    pub fn with_harness(mut self, harness: impl Into<String>) -> Self {
        self.harness = harness.into();
        self
    }

    /// The trace every emitted tool event is tagged with.
    #[must_use]
    pub fn trace(&self) -> TraceId {
        self.trace
    }

    /// The session every emitted tool event is tagged with.
    #[must_use]
    pub fn session(&self) -> &SessionId {
        &self.session
    }

    /// Number of `tools/call` events this transport has emitted.
    #[must_use]
    pub fn logged_count(&self) -> u64 {
        self.logged
    }

    /// Borrow the inner transport (e.g. for diagnostics).
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Build the redacted [`Kind::Tool`] event for one `tools/call` exchange.
    /// Returns `None` when the request is not a `tools/call` (nothing to log).
    ///
    /// **Redaction-before-persistence**: arguments and result text are scrubbed
    /// via [`HarnessContext`] before they touch the event; the returned event is
    /// safe to persist.
    fn tool_event(&self, request: &Value, response: &Value) -> Option<Event> {
        if request.get("method").and_then(Value::as_str) != Some("tools/call") {
            return None;
        }
        let params = request.get("params");
        let tool_name = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("tool");
        let arguments = params.and_then(|p| p.get("arguments"));

        // The response is either a JSON-RPC error or a `result` (an MCP tool
        // result that may itself carry `isError` + a `content` array).
        let rpc_error = response.get("error");
        let result = response.get("result");
        let is_error = rpc_error.is_some()
            || result
                .and_then(|r| r.get("isError"))
                .and_then(Value::as_bool)
                .unwrap_or(false);

        // Extract a single result text for redaction (tool result content array,
        // or the JSON-RPC error message, or a compact JSON fallback).
        let result_text = rpc_error
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| result.and_then(collect_result_text));

        let mut tool = ToolBlock {
            tool_name: Some(tool_name.to_string()),
            is_write: Some(is_write_tool(tool_name)),
            ..Default::default()
        };

        // Redacted arguments (tool_args), only when that class is captured.
        if let Some(args) = arguments {
            if self.ctx.captures(class::TOOL_ARGS) {
                tool.arguments = Some(self.ctx.redact_json(class::TOOL_ARGS, args));
            }
        }
        // Redacted result summary (tool_results), only when captured.
        if let Some(text) = &result_text {
            if self.ctx.captures(class::TOOL_RESULTS) {
                tool.result_summary = Some(self.ctx.redact_summary(text));
            }
        }

        let mut ev = Event::new(self.trace, Kind::Tool, Category::Agent, "tool.call")
            .with_op("tool")
            .with_name(truncate_with_ellipsis(tool_name, 120))
            .with_session(self.session.clone())
            .with_status(if is_error { Status::Error } else { Status::Ok })
            .with_attr("harness", self.harness.clone())
            .with_attr("source", "mcp")
            .with_tool(tool);

        // Surface the request id for correlation when present.
        if let Some(id) = request.get("id") {
            ev = ev.with_attr("mcp_request_id", id.clone());
        }

        // Redacted full result body in `output` (tool_results), when captured.
        if let Some(text) = &result_text {
            if self.ctx.captures(class::TOOL_RESULTS) {
                let (red, truncated) = self.ctx.redact_text(class::TOOL_RESULTS, text);
                if is_error {
                    ev.error = Some(red.clone());
                }
                ev.output = Some(Value::String(red));
                if truncated {
                    ev = ev.with_attr("output_truncated", true);
                }
            }
        }
        // If the call errored but the result body was not captured, still record
        // a redacted marker so the event stays coherent (status Error ⇒ error
        // message must be set; see Event::validate).
        if is_error && ev.error.is_none() {
            ev.error = Some("tool call failed".to_string());
        }

        Some(ev)
    }

    /// Emit (persist) the tool event for a `tools/call` exchange, best-effort. A
    /// store failure is logged but never propagated — logging must not break the
    /// proxied call.
    fn log_call(&mut self, request: &Value, response: &Value) {
        let Some(ev) = self.tool_event(request, response) else {
            return;
        };
        ev.debug_assert_valid();
        match self.store.insert(&ev) {
            Ok(()) => {
                self.logged += 1;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to persist proxied tool event");
            }
        }
    }
}

impl<T: McpTransport> McpTransport for LoggingMcpTransport<T> {
    fn request(&mut self, request: Value) -> Result<Value, SchruteError> {
        // Forward verbatim; only log a successful exchange (transport errors
        // surface unchanged — there is no response to attribute to a tool event).
        let response = self.inner.request(request.clone())?;
        self.log_call(&request, &response);
        Ok(response)
    }

    /// Forward a one-way notification verbatim to the inner transport.
    ///
    /// The decorator only *additionally records* `tools/call` requests; it never
    /// alters the JSON-RPC frames the inner transport sees. Notifications carry
    /// no `id` and no response, so there is nothing to log — but the frame **must
    /// still reach** the inner transport. Without this delegation, `notify` would
    /// fall through to the [`McpTransport`] trait default no-op and the
    /// proxy-in-the-middle would silently drop every agent notification
    /// (`notifications/initialized`, …), which the real MCP server needs to see.
    fn notify(&mut self, notification: Value) -> Result<(), SchruteError> {
        self.inner.notify(notification)
    }
}

/// Collect a single text blob from an MCP tool `result` for redaction:
/// concatenate any `{type:"text", text:…}` content blocks; otherwise fall back
/// to a compact JSON rendering of `structuredContent` or the whole result.
fn collect_result_text(result: &Value) -> Option<String> {
    if let Some(content) = result.get("content").and_then(Value::as_array) {
        let mut parts = Vec::new();
        for item in content {
            if item.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(t) = item.get("text").and_then(Value::as_str) {
                    parts.push(t.to_string());
                }
            }
        }
        if !parts.is_empty() {
            return Some(parts.join("\n"));
        }
    }
    if let Some(sc) = result.get("structuredContent") {
        return serde_json::to_string(sc).ok();
    }
    // Last resort: a compact JSON of the whole result (still redacted downstream).
    serde_json::to_string(result).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use logbook_core::CapturePolicy;
    use logbook_store::{Query, Store};
    use serde_json::json;

    /// A scripted mock transport (mirrors the one in `schrute_mcp` tests):
    /// returns queued responses in order, records the requests it received.
    /// `notify` is **overridden** to record forwarded notifications so the
    /// decorator's delegation is observable (the trait-default no-op would hide
    /// a dropped notification).
    struct MockTransport {
        responses: VecDeque<Value>,
        seen: Vec<Value>,
        notifications: Vec<Value>,
    }

    impl MockTransport {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: responses.into(),
                seen: Vec::new(),
                notifications: Vec::new(),
            }
        }
    }

    impl McpTransport for MockTransport {
        fn request(&mut self, request: Value) -> Result<Value, SchruteError> {
            self.seen.push(request);
            self.responses
                .pop_front()
                .ok_or_else(|| SchruteError::Transport("no scripted response".into()))
        }
        fn notify(&mut self, notification: Value) -> Result<(), SchruteError> {
            self.notifications.push(notification);
            Ok(())
        }
    }

    fn trace() -> TraceId {
        TraceId::from_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ])
    }

    fn store() -> Arc<Store> {
        // In-memory store (no temp dir needed); single-writer.
        Arc::new(Store::open_in_memory().expect("open in-memory store"))
    }

    fn tools_call(id: i64, name: &str, args: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        })
    }

    fn ok(id: i64, result: Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"result":result})
    }

    #[test]
    fn tools_call_emits_one_redacted_tool_event() {
        let store = store();
        let ctx = Arc::new(HarnessContext::with_defaults());
        // Inner returns a tool result whose text carries a planted secret.
        let inner = MockTransport::new(vec![ok(
            7,
            json!({
                "content": [{"type":"text","text":"wrote file, key was AKIAIOSFODNN7EXAMPLE"}]
            }),
        )]);
        let mut t = LoggingMcpTransport::new(
            inner,
            store.clone(),
            ctx,
            trace(),
            SessionId::new("sess-1"),
        );

        let req = tools_call(
            7,
            "Edit",
            json!({"file_path": "/app/main.rs", "token": "AKIAIOSFODNN7EXAMPLE"}),
        );
        let resp = t.request(req).unwrap();
        // The response is forwarded verbatim.
        assert!(resp["result"]["content"][0]["text"].is_string());
        assert_eq!(t.logged_count(), 1);

        // Exactly one Tool event was persisted, fully redacted.
        let events = store
            .query(&Query::new().category(Category::Agent).limit(100))
            .unwrap();
        assert_eq!(events.len(), 1, "one tools/call ⇒ one tool event");
        let ev = &events[0];
        assert_eq!(ev.kind, Kind::Tool);
        let tb = ev.blocks.tool.as_ref().expect("tool block");
        assert_eq!(tb.tool_name.as_deref(), Some("Edit"));
        assert_eq!(tb.is_write, Some(true), "Edit is a write tool");

        // Arguments redacted, non-secret arg preserved.
        let args_s = serde_json::to_string(tb.arguments.as_ref().unwrap()).unwrap();
        assert!(
            !args_s.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked in args: {args_s}"
        );
        assert!(args_s.contains("/app/main.rs"), "non-secret arg lost: {args_s}");

        // Result body redacted in output.
        let out = ev.output.as_ref().unwrap().as_str().unwrap();
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked in result: {out}"
        );
        assert!(out.contains("REDACTED:CLOUD_KEY:"), "no redaction placeholder: {out}");
        // The redacted summary is also set and secret-free.
        assert!(!tb
            .result_summary
            .as_ref()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"));
        // Tagged with the supplied trace + session.
        assert_eq!(ev.trace_id, trace());
        assert_eq!(ev.session_id.as_ref().map(SessionId::as_str), Some("sess-1"));
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn non_tool_call_frames_are_forwarded_but_not_logged() {
        let store = store();
        let ctx = Arc::new(HarnessContext::with_defaults());
        let inner = MockTransport::new(vec![
            ok(1, json!({"protocolVersion": "2025-06-18"})), // initialize
            ok(2, json!({"tools": [{"name": "Read"}]})),     // tools/list
        ]);
        let mut t =
            LoggingMcpTransport::new(inner, store.clone(), ctx, trace(), SessionId::new("s"));

        let _ = t
            .request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}))
            .unwrap();
        let _ = t
            .request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .unwrap();

        assert_eq!(t.logged_count(), 0, "only tools/call is logged");
        assert_eq!(store.count().unwrap(), 0, "no events persisted for non-calls");
    }

    #[test]
    fn notify_is_delegated_to_inner_transport() {
        // Regression: the decorator must forward one-way notifications to the
        // inner transport. Before the fix `notify` fell through to the
        // McpTransport trait DEFAULT no-op, so the proxy-in-the-middle silently
        // dropped every agent notification (notifications/initialized, …) and the
        // real MCP server never saw them (and could hang). A notification carries
        // no response and is never logged, but it MUST reach the inner transport.
        let store = store();
        let ctx = Arc::new(HarnessContext::with_defaults());
        // No scripted responses needed — notifications take the request-free path.
        let inner = MockTransport::new(vec![]);
        let mut t =
            LoggingMcpTransport::new(inner, store.clone(), ctx, trace(), SessionId::new("s"));

        t.notify(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .expect("notify delegates without error");

        // The inner transport received exactly the forwarded notification.
        let inner = t.inner();
        assert_eq!(
            inner.notifications.len(),
            1,
            "notification must be delegated to the inner transport, not dropped"
        );
        assert_eq!(
            inner.notifications[0]["method"],
            json!("notifications/initialized")
        );
        // Notifications are never logged and never touch the request path.
        assert!(inner.seen.is_empty(), "notify must not issue a request");
        assert_eq!(t.logged_count(), 0, "notifications are not tool events");
        assert_eq!(store.count().unwrap(), 0, "nothing persisted for a notification");
    }

    #[test]
    fn rpc_error_response_marks_event_errored() {
        let store = store();
        let ctx = Arc::new(HarnessContext::with_defaults());
        let inner = MockTransport::new(vec![json!({
            "jsonrpc": "2.0",
            "id": 3,
            "error": {"code": -32000, "message": "tool blew up on AKIAIOSFODNN7EXAMPLE"}
        })]);
        let mut t =
            LoggingMcpTransport::new(inner, store.clone(), ctx, trace(), SessionId::new("s"));

        let _ = t
            .request(tools_call(3, "Bash", json!({"command": "false"})))
            .unwrap();

        let events = store.query(&Query::new().limit(10)).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.status, Status::Error);
        let err = ev.error.as_ref().unwrap();
        assert!(!err.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in error: {err}");
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn tool_args_off_omits_arguments_but_still_emits_event() {
        let store = store();
        // tool_args capture off; tool_results stays on.
        let mut policy = CapturePolicy::default();
        policy.classes.tool_args.capture = false;
        let ctx = Arc::new(HarnessContext::new(
            logbook_core::Redactor::new(),
            policy,
            true,
        ));
        let inner = MockTransport::new(vec![ok(
            5,
            json!({"content": [{"type":"text","text":"done"}]}),
        )]);
        let mut t =
            LoggingMcpTransport::new(inner, store.clone(), ctx, trace(), SessionId::new("s"));

        let _ = t
            .request(tools_call(5, "Read", json!({"file_path": "/x", "secret": "AKIAIOSFODNN7EXAMPLE"})))
            .unwrap();

        let events = store.query(&Query::new().limit(10)).unwrap();
        assert_eq!(events.len(), 1, "event still emitted as turn anchor");
        let tb = events[0].blocks.tool.as_ref().unwrap();
        assert!(tb.arguments.is_none(), "tool_args off ⇒ no arguments persisted");
        // Result still captured (tool_results on).
        assert!(events[0].output.is_some());
    }

    #[test]
    fn transport_error_propagates_and_logs_nothing() {
        let store = store();
        let ctx = Arc::new(HarnessContext::with_defaults());
        // No scripted response ⇒ the mock returns a Transport error.
        let inner = MockTransport::new(vec![]);
        let mut t =
            LoggingMcpTransport::new(inner, store.clone(), ctx, trace(), SessionId::new("s"));
        let err = t.request(tools_call(1, "Read", json!({}))).unwrap_err();
        assert!(matches!(err, SchruteError::Transport(_)), "got: {err:?}");
        assert_eq!(store.count().unwrap(), 0, "no event on transport failure");
        assert_eq!(t.logged_count(), 0);
    }
}
