//! `logbook` as an **MCP proxy in the middle** (plan "Phase 2", MCP proxy row:
//! "logbook can also run as a proxy in the middle (stdio passthrough) between an
//! agent and its real MCP servers").
//!
//! An agent is pointed at `logbook` instead of its real MCP server; `logbook`
//! spawns the real server ([`StdioTransport`]), forwards the agent's JSON-RPC
//! frames through a [`LoggingMcpTransport`] (which **persists a redacted
//! `Kind::Tool` event per `tools/call`**), and relays the server's responses
//! back to the agent — transparently. The agent sees the real server; logbook
//! sees (and records) every tool call in between.
//!
//! ```text
//!   agent stdin ──▶ proxy ──▶ LoggingMcpTransport ──▶ StdioTransport ──▶ real MCP server
//!   agent stdout ◀── proxy ◀──────────── response ◀──────────────────────┘
//!                                  │
//!                                  └─▶ redacted Kind::Tool Event ──▶ Store
//! ```
//!
//! Framing is line-delimited JSON (one JSON-RPC message per line), matching
//! [`StdioTransport`]. A **request** (frame with an `id`) is sent via
//! [`McpTransport::request`] and its response written back to the agent; a
//! **notification** (no `id`) is forwarded one-way via [`McpTransport::notify`]
//! with nothing written back. Malformed / blank lines are skipped (tolerant).
//!
//! ## Redaction + gates
//! All `tools/call` payloads are redacted by the [`HarnessContext`] inside
//! [`LoggingMcpTransport`] **before** persistence (plan §9). The proxy itself is
//! a passthrough; if a caller needs an egress allowlist on target-bearing tools
//! it can pre-check frames before calling [`pump`], but the default proxy trusts
//! the agent↔real-server contract (the real server enforces its own policy) and
//! focuses on *recording*.

use std::io::{BufRead, Write};
use std::sync::Arc;

use serde_json::Value;

use logbook_core::{SessionId, TraceId};
use logbook_harness::HarnessContext;
use logbook_store::Store;

use crate::logging_mcp::LoggingMcpTransport;
use crate::schrute_mcp::{McpTransport, SchruteError, StdioTransport};

/// Outcome of a finished proxy pump: how many frames were relayed and how many
/// `tools/call` events were recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyOutcome {
    /// Number of request frames (with an `id`) forwarded and answered.
    pub requests: u64,
    /// Number of notification frames (no `id`) forwarded one-way.
    pub notifications: u64,
    /// Number of `tools/call` events persisted by the logging transport.
    pub tool_events: u64,
}

/// Pump JSON-RPC frames from `agent_in` through `transport`, writing each
/// response to `agent_out`. Returns when `agent_in` reaches EOF.
///
/// This is the transport-agnostic core (the runnable [`run_mcp_proxy`] wires a
/// real [`StdioTransport`] behind a [`LoggingMcpTransport`] and calls this).
/// Driving it against a mock transport makes the relay logic unit-testable
/// without spawning a child process.
///
/// Behavior per line:
/// - **blank / non-JSON** → skipped;
/// - **request** (`id` present) → `transport.request(frame)`, the response is
///   serialized + newline-terminated to `agent_out` and flushed. A transport
///   error is turned into a JSON-RPC error response carrying the same `id` so
///   the agent is not left hanging;
/// - **notification** (no `id`) → `transport.notify(frame)`, nothing written
///   back.
///
/// # Errors
/// Returns [`SchruteError::Transport`] only on a fatal I/O error reading
/// `agent_in` or writing `agent_out`; per-frame transport errors are relayed to
/// the agent as JSON-RPC error responses and do **not** stop the pump.
pub fn pump<R, W, T>(
    mut agent_in: R,
    mut agent_out: W,
    transport: &mut T,
) -> Result<ProxyOutcome, SchruteError>
where
    R: BufRead,
    W: Write,
    T: McpTransport,
{
    let mut outcome = ProxyOutcome::default();
    let mut line = String::new();
    loop {
        line.clear();
        let n = agent_in
            .read_line(&mut line)
            .map_err(|e| SchruteError::Transport(format!("proxy read: {e}")))?;
        if n == 0 {
            break; // agent closed stdin
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let frame: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue, // skip non-JSON noise on the agent's stdin
        };

        // A frame with an `id` is a request expecting a response; without an
        // `id` it is a one-way notification.
        if frame.get("id").is_some() {
            let id = frame.get("id").cloned();
            let response = match transport.request(frame) {
                Ok(resp) => resp,
                Err(e) => json_rpc_error(id, &e),
            };
            write_frame(&mut agent_out, &response)?;
            outcome.requests += 1;
        } else {
            // Best-effort one-way forward; a failure to forward a notification
            // is logged but does not break the session.
            if let Err(e) = transport.notify(frame) {
                tracing::warn!(error = %e, "failed to forward MCP notification");
            }
            outcome.notifications += 1;
        }
    }
    Ok(outcome)
}

/// Serialize `frame` as one line (+ `\n`) to `out` and flush.
fn write_frame<W: Write>(out: &mut W, frame: &Value) -> Result<(), SchruteError> {
    let line = serde_json::to_string(frame).map_err(|e| SchruteError::Malformed(e.to_string()))?;
    out.write_all(line.as_bytes())
        .and_then(|_| out.write_all(b"\n"))
        .and_then(|_| out.flush())
        .map_err(|e| SchruteError::Transport(format!("proxy write: {e}")))
}

/// Build a JSON-RPC error response carrying `id` from a transport [`SchruteError`]
/// so a forwarding failure is surfaced to the agent rather than hanging it.
fn json_rpc_error(id: Option<Value>, err: &SchruteError) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": -32000, "message": format!("logbook proxy: {err}") }
    })
}

/// Configuration for the runnable stdio MCP proxy.
pub struct McpProxyConfig {
    /// The real MCP server program to spawn (e.g. `node`).
    pub program: String,
    /// Arguments to the server program (e.g. `["dist/index.js", "serve"]`).
    pub args: Vec<String>,
    /// Working directory for the spawned server.
    pub cwd: Option<std::path::PathBuf>,
    /// Trace every recorded tool event is tagged with (ties the proxied session
    /// to the rest of the timeline).
    pub trace: TraceId,
    /// Session every recorded tool event is tagged with.
    pub session: SessionId,
    /// Harness label stamped on recorded events (default
    /// [`LoggingMcpTransport::DEFAULT_HARNESS`]).
    pub harness: Option<String>,
}

impl McpProxyConfig {
    /// A config spawning `program args` with a fresh trace + session and default
    /// labels.
    #[must_use]
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            cwd: None,
            trace: TraceId::new(),
            session: SessionId::generate(),
            harness: None,
        }
    }

    /// Set the working directory for the spawned server.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Use a specific trace id (e.g. the active `logbook` session trace).
    #[must_use]
    pub fn with_trace(mut self, trace: TraceId) -> Self {
        self.trace = trace;
        self
    }

    /// Use a specific session id.
    #[must_use]
    pub fn with_session(mut self, session: SessionId) -> Self {
        self.session = session;
        self
    }
}

/// Run the stdio MCP proxy to completion: spawn the real server, wrap it in a
/// [`LoggingMcpTransport`] (recording redacted `tools/call` events into `store`),
/// and relay frames between the agent's `agent_in`/`agent_out` and the server
/// until the agent closes its input.
///
/// `ctx` supplies the redactor + capture policy; **every recorded tool payload
/// is redacted before persistence** (plan §9). The blocking I/O loop is driven
/// on the calling thread (run it under `spawn_blocking` from async code, like
/// the schrute client).
///
/// Despite the `async` signature (so it slots into an async entrypoint and can
/// be `await`ed alongside other tasks), the body is synchronous blocking I/O —
/// it does not yield. Wrap the call in `tokio::task::spawn_blocking` if you need
/// the executor free.
///
/// # Errors
/// Returns [`SchruteError`] if the server cannot be spawned, or on a fatal I/O
/// error on the agent pipes. Per-call transport errors are relayed to the agent
/// as JSON-RPC errors and do not abort the proxy.
pub async fn run_mcp_proxy<R, W>(
    config: McpProxyConfig,
    store: Arc<Store>,
    ctx: HarnessContext,
    agent_in: R,
    agent_out: W,
) -> Result<ProxyOutcome, SchruteError>
where
    R: BufRead,
    W: Write,
{
    // Destructure up front so the borrow of `args` does not overlap the moves of
    // the trace/session/harness fields.
    let McpProxyConfig {
        program,
        args,
        cwd,
        trace,
        session,
        harness,
    } = config;

    let server = {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        StdioTransport::spawn(&program, &arg_refs, cwd.as_deref())?
    };

    let mut transport = LoggingMcpTransport::new(server, store, Arc::new(ctx), trace, session);
    if let Some(harness) = harness {
        transport = transport.with_harness(harness);
    }

    let mut outcome = pump(agent_in, agent_out, &mut transport)?;
    outcome.tool_events = transport.logged_count();
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;

    use logbook_core::{Category, Kind, Status};
    use logbook_store::{Query, Store};
    use serde_json::json;

    /// A scripted mock transport that records the frames it received (requests
    /// and notifications) and returns queued responses for requests.
    struct MockTransport {
        responses: VecDeque<Value>,
        requests: Vec<Value>,
        notifications: Vec<Value>,
    }

    impl MockTransport {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: responses.into(),
                requests: Vec::new(),
                notifications: Vec::new(),
            }
        }
    }

    impl McpTransport for MockTransport {
        fn request(&mut self, request: Value) -> Result<Value, SchruteError> {
            self.requests.push(request);
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
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
            0xb7, 0xb8,
        ])
    }

    #[test]
    fn pump_relays_requests_and_forwards_notifications() {
        // Agent sends: initialize (req), initialized (notification), tools/call (req).
        let agent_input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"Read","arguments":{"file_path":"/x"}}}"#,
            "\n",
        );
        let mut out: Vec<u8> = Vec::new();
        let mut transport = MockTransport::new(vec![
            json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}),
            json!({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}),
        ]);

        let outcome = pump(Cursor::new(agent_input), &mut out, &mut transport).unwrap();
        assert_eq!(outcome.requests, 2, "two id-bearing requests");
        assert_eq!(outcome.notifications, 1, "one notification");

        // The mock saw both requests and the one notification.
        assert_eq!(transport.requests.len(), 2);
        assert_eq!(transport.notifications.len(), 1);
        assert_eq!(
            transport.notifications[0]["method"],
            json!("notifications/initialized")
        );

        // Two response lines were written back to the agent (one per request).
        let written = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = written.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "one response per request, none for the notification");
        let r1: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(r1["id"], json!(1));
        let r2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r2["id"], json!(2));
    }

    #[test]
    fn pump_through_logging_transport_records_redacted_tool_event() {
        // The real wiring: pump → LoggingMcpTransport → mock server. A tools/call
        // produces exactly one redacted, persisted tool event.
        let store = Arc::new(Store::open_in_memory().unwrap());
        let ctx = Arc::new(HarnessContext::with_defaults());
        let inner = MockTransport::new(vec![json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content":[{"type":"text","text":"wrote, key AKIAIOSFODNN7EXAMPLE"}]}
        })]);
        let mut logging = LoggingMcpTransport::new(
            inner,
            store.clone(),
            ctx,
            trace(),
            SessionId::new("proxy-sess"),
        );

        let agent_input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"deploy","key":"AKIAIOSFODNN7EXAMPLE"}}}"#,
            "\n",
        );
        let mut out: Vec<u8> = Vec::new();
        let outcome = pump(Cursor::new(agent_input), &mut out, &mut logging).unwrap();
        assert_eq!(outcome.requests, 1);
        assert_eq!(logging.logged_count(), 1);

        // The agent got the verbatim response back.
        let resp: Value = serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"), "passthrough must not alter the server response");

        // But the PERSISTED event is redacted.
        let events = store.query(&Query::new().category(Category::Agent).limit(10)).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.kind, Kind::Tool);
        assert_eq!(ev.status, Status::Ok);
        let out_text = ev.output.as_ref().unwrap().as_str().unwrap();
        assert!(!out_text.contains("AKIAIOSFODNN7EXAMPLE"), "secret persisted: {out_text}");
        let args_s = serde_json::to_string(ev.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap()).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "secret in args: {args_s}");
        assert!(args_s.contains("deploy"), "non-secret arg lost: {args_s}");
    }

    #[test]
    fn pump_relays_transport_error_as_jsonrpc_error_and_continues() {
        // A request whose forward fails (empty scripted queue → Transport error)
        // must NOT hang the agent: the proxy synthesizes a JSON-RPC error
        // carrying the same id and the pump runs to EOF. The mock returns queued
        // responses positionally, so the first request answers from the queue and
        // the second (queue now empty) errors — proving the pump continues past a
        // transport failure.
        let agent_input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"X"}}"#,
            "\n",
        );
        let mut out: Vec<u8> = Vec::new();
        // One scripted response: request 1 succeeds, request 2 errors (empty).
        let mut transport = MockTransport::new(vec![json!({
            "jsonrpc": "2.0", "id": 1, "result": {"tools": []}
        })]);
        let outcome = pump(Cursor::new(agent_input), &mut out, &mut transport).unwrap();
        assert_eq!(outcome.requests, 2, "pump continued past the error");

        let written = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = written.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "one response line per request");
        // First request answered normally.
        let ok: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(ok["id"], json!(1));
        // Second request: a synthesized JSON-RPC error echoing the request id.
        let err: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(err["id"], json!(2), "error response must echo the request id");
        assert!(err["error"]["message"].as_str().unwrap().contains("logbook proxy"));
    }

    #[test]
    fn pump_skips_blank_and_non_json_lines() {
        let agent_input = "\n   \nnot json at all\n{bad\n";
        let mut out: Vec<u8> = Vec::new();
        let mut transport = MockTransport::new(vec![]);
        let outcome = pump(Cursor::new(agent_input), &mut out, &mut transport).unwrap();
        assert_eq!(outcome.requests, 0);
        assert_eq!(outcome.notifications, 0);
        assert!(out.is_empty(), "nothing should be written for junk input");
    }
}
