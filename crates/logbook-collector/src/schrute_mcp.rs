//! `SchruteAdapter` — an MCP stdio client to schrute (plan §4, §13).
//!
//! schrute exposes a Model Context Protocol server over stdio
//! (`node dist/index.js serve --no-daemon`, per its `.mcp.json`). This adapter
//! speaks that protocol (JSON-RPC 2.0: `initialize` → `tools/list` →
//! `tools/call`) to drive a **verified subset**: record → replay → network
//! capture, session reuse.
//!
//! ## Gates are PENDING — logbook enforces its own egress allowlist
//! schrute's security gates (SSRF blocking, domain allowlist, redirect
//! behavior) are `PENDING VERIFICATION` (`agent-browser-parity.md:3`). We do
//! **not** assume them: every navigation/replay target is checked against
//! [`crate::egress::EgressAllowlist`] **before** schrute is asked to fetch it.
//! A target that is not allow-listed (or resolves to a private/loopback host)
//! is refused locally and the MCP call is never issued.
//!
//! The transport is abstracted behind [`McpTransport`] so the protocol logic is
//! unit-testable against a mock without spawning a real schrute process.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use logbook_core::text::truncate_with_ellipsis;
use logbook_core::{Category, ConsoleBlock, Event, Kind, NetworkBlock, Redactor, SessionId, Status, TraceId};

use crate::egress::{EgressAllowlist, EgressDenied};

/// The MCP protocol version logbook negotiates with schrute.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// The verified subset of schrute MCP operations logbook uses in v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchruteOp {
    /// Record a browser action into a replayable skill.
    Record,
    /// Replay a previously recorded skill.
    Replay,
    /// Capture network requests.
    Network,
}

impl SchruteOp {
    /// The schrute MCP tool name for this op. schrute prefixes its tools with
    /// `schrute_` (see its `mcp-handlers.ts`).
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            SchruteOp::Record => "schrute_record",
            SchruteOp::Replay => "schrute_replay",
            SchruteOp::Network => "schrute_network",
        }
    }

    /// Whether this op navigates/fetches a target URL (and so must clear the
    /// egress allowlist first).
    #[must_use]
    pub const fn needs_egress_check(self) -> bool {
        // Record and replay both drive navigation; a bare network read of the
        // current page does not navigate, but we still verify any URL passed.
        matches!(self, SchruteOp::Record | SchruteOp::Replay | SchruteOp::Network)
    }
}

/// Errors from the schrute adapter.
#[derive(Debug, thiserror::Error)]
pub enum SchruteError {
    /// A target URL was refused by logbook's egress allowlist.
    #[error("egress denied: {0}")]
    Egress(#[from] EgressDenied),

    /// The MCP transport failed (spawn / read / write).
    #[error("mcp transport error: {0}")]
    Transport(String),

    /// schrute returned a JSON-RPC error.
    #[error("schrute rpc error {code}: {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },

    /// A response could not be parsed / was missing a field.
    #[error("malformed mcp response: {0}")]
    Malformed(String),

    /// No matching response arrived within the per-request deadline (schrute
    /// stalled or replied only with mismatched/notification frames).
    #[error("schrute transport timeout after {0:?}")]
    Timeout(std::time::Duration),
}

/// A line-delimited JSON-RPC transport to an MCP server. Production uses a child
/// process over stdio; tests use a scripted mock.
pub trait McpTransport: Send {
    /// Send one JSON-RPC request and await the matching response value.
    ///
    /// # Errors
    /// Implementations return [`SchruteError::Transport`] on I/O failure.
    fn request(&mut self, request: Value) -> Result<Value, SchruteError>;

    /// Send a one-way JSON-RPC **notification** (a frame with no `id`, e.g.
    /// `notifications/initialized`) for which **no response is awaited**.
    ///
    /// Used by the passthrough proxy ([`crate::mcp_proxy`]) to forward an
    /// agent's notification frames to a real server without blocking on a reply.
    /// The default implementation is a best-effort **no-op** (a notification is
    /// fire-and-forget; a transport with no real downstream — a mock or the
    /// schrute adapter, which never forwards client notifications — simply drops
    /// it). [`StdioTransport`] overrides this to write the frame to the child's
    /// stdin.
    ///
    /// # Errors
    /// Implementations return [`SchruteError::Transport`] on I/O failure.
    fn notify(&mut self, _notification: Value) -> Result<(), SchruteError> {
        Ok(())
    }
}

/// An MCP client to schrute over a [`McpTransport`], enforcing logbook's
/// egress allowlist.
pub struct SchruteAdapter<T: McpTransport> {
    transport: T,
    allowlist: EgressAllowlist,
    redactor: Redactor,
    next_id: i64,
    initialized: bool,
    session: SessionId,
}

impl<T: McpTransport> SchruteAdapter<T> {
    /// New adapter over `transport`, enforcing `allowlist`, redacting captured
    /// text before it becomes events.
    #[must_use]
    pub fn new(transport: T, allowlist: EgressAllowlist) -> Self {
        Self {
            transport,
            allowlist,
            redactor: Redactor::new(),
            next_id: 1,
            initialized: false,
            session: SessionId::generate(),
        }
    }

    /// Use a specific redactor (e.g. one seeded with the process env).
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// The logical session id this adapter tags its events with.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session
    }

    /// Borrow the egress allowlist (e.g. for diagnostics).
    #[must_use]
    pub fn allowlist(&self) -> &EgressAllowlist {
        &self.allowlist
    }

    fn alloc_id(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Perform the MCP `initialize` handshake (idempotent).
    ///
    /// # Errors
    /// Returns [`SchruteError`] on transport or RPC failure.
    pub fn initialize(&mut self) -> Result<Value, SchruteError> {
        if self.initialized {
            return Ok(Value::Null);
        }
        let id = self.alloc_id();
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "logbook-collector", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        let resp = self.transport.request(req)?;
        let result = extract_result(&resp)?;
        self.initialized = true;
        Ok(result)
    }

    /// List the tools schrute advertises (`tools/list`).
    ///
    /// # Errors
    /// Returns [`SchruteError`] on transport or RPC failure.
    pub fn list_tools(&mut self) -> Result<Vec<String>, SchruteError> {
        self.initialize()?;
        let id = self.alloc_id();
        let req = json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}});
        let resp = self.transport.request(req)?;
        let result = extract_result(&resp)?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| SchruteError::Malformed("tools/list missing `tools` array".into()))?;
        Ok(tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_string))
            .collect())
    }

    /// Call a verified-subset op. Any `url` argument is checked against the
    /// egress allowlist **before** the MCP call is issued (schrute gates are
    /// not trusted). Returns the captured events normalized onto `trace`.
    ///
    /// # Errors
    /// Returns [`SchruteError::Egress`] if a target is refused, or other
    /// [`SchruteError`] variants on RPC/transport failure.
    pub fn call(
        &mut self,
        op: SchruteOp,
        mut arguments: BTreeMap<String, Value>,
        trace: TraceId,
    ) -> Result<Vec<Event>, SchruteError> {
        // Egress check: enforce logbook's allowlist on any target URL.
        if op.needs_egress_check() {
            if let Some(url) = arguments.get("url").and_then(Value::as_str) {
                // Refuses (and never issues the call) if not allow-listed.
                self.allowlist.check(url)?;
            }
        }

        self.initialize()?;
        let id = self.alloc_id();
        let args_value = Value::Object(arguments.clone().into_iter().collect());
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": op.tool_name(), "arguments": args_value }
        });
        // Avoid an unused-mut warning if no url key was present.
        arguments.clear();

        let resp = self.transport.request(req)?;
        let result = extract_result(&resp)?;
        Ok(self.events_from_tool_result(op, &result, trace))
    }

    /// Convert an MCP `tools/call` result into logbook events. MCP tool results
    /// carry a `content` array (text / structured); we also look for a
    /// `structuredContent`/`network` payload for network captures.
    fn events_from_tool_result(&self, op: SchruteOp, result: &Value, trace: TraceId) -> Vec<Event> {
        let mut out = Vec::new();

        // Network captures: schrute returns request records we map to
        // NetworkBlock events.
        if op == SchruteOp::Network {
            if let Some(records) = find_network_records(result) {
                for rec in records {
                    out.push(self.network_event(&rec, trace));
                }
            }
        }

        // Text content -> a console-style browser event (e.g. record/replay
        // status text).
        if let Some(text) = collect_text_content(result) {
            if !text.trim().is_empty() {
                let redacted = self.redactor.redact(&text).into_owned();
                let is_error = result
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let mut ev = Event::new(trace, Kind::Browser, Category::Browser, "schrute")
                    .with_op(op_operation(op))
                    .with_name(short_name(&redacted))
                    .with_status(if is_error { Status::Error } else { Status::Ok })
                    .with_session(self.session.clone())
                    .with_attr("source", "schrute")
                    .with_attr("schrute_tool", op.tool_name())
                    .with_console(ConsoleBlock {
                        level: Some(if is_error { "error".into() } else { "info".into() }),
                        message: Some(redacted.clone()),
                        url: None,
                        stack: None,
                    });
                if is_error {
                    ev.error = Some(redacted);
                }
                out.push(ev);
            }
        }

        out
    }

    /// Build a network `Event` from a single schrute network record.
    fn network_event(&self, rec: &Value, trace: TraceId) -> Event {
        let method = rec.get("method").and_then(Value::as_str).map(str::to_string);
        let url = rec
            .get("url")
            .and_then(Value::as_str)
            .map(|u| self.redactor.redact(u).into_owned());
        let status = rec
            .get("status")
            .or_else(|| rec.get("statusCode"))
            .and_then(Value::as_u64)
            .map(|s| s as u16);
        let name = format!(
            "{} {}",
            method.as_deref().unwrap_or("GET"),
            url.as_deref().unwrap_or("")
        );
        let errored = status.map(|s| s >= 400).unwrap_or(false);
        let mut ev = Event::new(trace, Kind::Network, Category::Browser, "network")
            .with_op("request")
            .with_name(name.trim().to_string())
            .with_status(if errored { Status::Error } else { Status::Ok })
            .with_session(self.session.clone())
            .with_attr("source", "schrute")
            .with_network(NetworkBlock {
                method,
                url,
                status_code: status,
                request_bytes: rec.get("requestBytes").and_then(Value::as_u64),
                response_bytes: rec.get("responseBytes").and_then(Value::as_u64),
            });
        if errored {
            ev = ev.with_error(format!("HTTP {}", status.unwrap_or(0)));
        }
        ev
    }
}

/// Human-readable operation verb for an op.
fn op_operation(op: SchruteOp) -> &'static str {
    match op {
        SchruteOp::Record => "record",
        SchruteOp::Replay => "replay",
        SchruteOp::Network => "network",
    }
}

/// Truncate a message to a short display name (UTF-8-safe, ellipsis on overflow).
fn short_name(s: &str) -> String {
    truncate_with_ellipsis(s.trim(), 120)
}

/// Pull the `result` out of a JSON-RPC response, surfacing `error` as
/// [`SchruteError::Rpc`].
fn extract_result(resp: &Value) -> Result<Value, SchruteError> {
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        return Err(SchruteError::Rpc { code, message });
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| SchruteError::Malformed("response missing `result`".into()))
}

/// Collect any text from an MCP `content` array (`[{type:"text", text:"..."}]`).
fn collect_text_content(result: &Value) -> Option<String> {
    let content = result.get("content")?.as_array()?;
    let mut parts = Vec::new();
    for item in content {
        if item.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(text) = item.get("text").and_then(Value::as_str) {
                parts.push(text.to_string());
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Find an array of network records in a tool result, tolerating a few shapes
/// schrute might use (`structuredContent.requests`, `requests`, `network`).
fn find_network_records(result: &Value) -> Option<Vec<Value>> {
    for path in [
        result.get("structuredContent").and_then(|s| s.get("requests")),
        result.get("requests"),
        result.get("network"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(arr) = path.as_array() {
            return Some(arr.clone());
        }
    }
    None
}

/// Default deadline for a single `request()` exchange. Mirrors the sibling DAP
/// client's `DEFAULT_REQUEST_TIMEOUT` so a stalled subprocess can't hang a
/// blocking worker indefinitely.
pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A blocking line-delimited JSON-RPC transport over a child process's
/// stdin/stdout. This is the production transport: it spawns schrute
/// (`node dist/index.js serve --no-daemon`, per its `.mcp.json`) and exchanges
/// newline-delimited JSON messages.
///
/// Kept blocking (synchronous) to match [`McpTransport`]; the adapter is driven
/// from a blocking context or `spawn_blocking`. A dedicated reader thread owns
/// the child's stdout and forwards each line over a channel, so `request()` can
/// bound its wait with a per-request deadline ([`Self::with_timeout`], default
/// [`DEFAULT_REQUEST_TIMEOUT`]) instead of blocking forever on `read_line` when
/// schrute (an untrusted subprocess) stalls or never closes stdout.
/// Notification frames (no `id`) from the server are skipped while waiting for
/// the matching response id; a frame carrying a *mismatched* id is logged and
/// discarded rather than silently spun on.
pub struct StdioTransport {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    /// Lines read from the child's stdout (or the read error that ended the
    /// stream), produced by `reader`.
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
    /// The reader thread; joined in `Drop` only if it has already finished so
    /// teardown never blocks on a wedged pipe.
    reader: Option<std::thread::JoinHandle<()>>,
    /// Per-request deadline applied in `request()`.
    request_timeout: std::time::Duration,
}

impl StdioTransport {
    /// Spawn `program` with `args` in `cwd`, wiring its stdio for MCP.
    ///
    /// # Errors
    /// Returns [`SchruteError::Transport`] if the process cannot be spawned or
    /// its stdio handles cannot be captured.
    pub fn spawn(
        program: &str,
        args: &[&str],
        cwd: Option<&std::path::Path>,
    ) -> Result<Self, SchruteError> {
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| SchruteError::Transport(format!("spawn {program}: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| SchruteError::Transport("child stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SchruteError::Transport("child stdout unavailable".into()))?;

        // A single long-lived reader thread owns the BufReader and forwards each
        // line over an unbounded channel. This lets `request()` enforce a
        // deadline via `recv_timeout` without ever blocking forever on
        // `read_line`, and avoids the fd-level non-blocking/poll vs. buffered-
        // bytes pitfalls of timing out a `BufReader` directly.
        let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<String>>();
        let reader = std::thread::Builder::new()
            .name("schrute-mcp-stdio-reader".into())
            .spawn(move || {
                use std::io::BufRead;
                let mut stdout = std::io::BufReader::new(stdout);
                loop {
                    let mut buf = String::new();
                    match stdout.read_line(&mut buf) {
                        Ok(0) => break, // EOF: child closed stdout
                        Ok(_) => {
                            if tx.send(Ok(buf)).is_err() {
                                break; // transport dropped; stop reading
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e));
                            break;
                        }
                    }
                }
            })
            .map_err(|e| SchruteError::Transport(format!("reader thread: {e}")))?;

        Ok(Self {
            child,
            stdin,
            lines: rx,
            reader: Some(reader),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Override the per-request deadline (default [`DEFAULT_REQUEST_TIMEOUT`]).
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        // Best-effort: terminate the schrute child, then reap it so we never
        // leave a zombie. Killing the child closes the pipe, which unblocks the
        // reader thread's `read_line`.
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Only join if the reader has already finished — never block teardown on
        // a wedged pipe (e.g. a grandchild that inherited stdout keeps it open).
        if let Some(handle) = self.reader.take() {
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}

impl McpTransport for StdioTransport {
    fn request(&mut self, request: Value) -> Result<Value, SchruteError> {
        use std::io::Write;
        use std::sync::mpsc::RecvTimeoutError;
        use std::time::Instant;

        let want_id = request.get("id").cloned();
        let line = serde_json::to_string(&request)
            .map_err(|e| SchruteError::Malformed(e.to_string()))?;
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| SchruteError::Transport(format!("write: {e}")))?;

        // Read (with an overall deadline) until we see the response whose id
        // matches our request id. A stalled child can no longer hang the worker:
        // once the deadline elapses we return `SchruteError::Timeout`.
        let deadline = Instant::now() + self.request_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SchruteError::Timeout(self.request_timeout));
            }
            let buf = match self.lines.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                Ok(Err(e)) => return Err(SchruteError::Transport(format!("read: {e}"))),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(SchruteError::Timeout(self.request_timeout))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(SchruteError::Transport("schrute closed stdout".into()))
                }
            };
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue, // skip non-JSON log noise on stdout
            };
            // Skip notifications / mismatched ids until ours arrives. A
            // mismatched id is surfaced (not silently dropped) so protocol
            // desync is observable.
            match (&want_id, value.get("id")) {
                (Some(a), Some(b)) if a == b => return Ok(value),
                (_, None) => continue,
                (_, Some(got)) => {
                    tracing::warn!(
                        wanted_id = ?want_id,
                        got_id = ?got,
                        "discarding schrute response with mismatched id"
                    );
                    continue;
                }
            }
        }
    }

    fn notify(&mut self, notification: Value) -> Result<(), SchruteError> {
        use std::io::Write;
        // Fire-and-forget: write the frame and flush; never wait for a reply (a
        // notification has no `id`). Used by the passthrough proxy to forward an
        // agent's notifications to the real server.
        let line = serde_json::to_string(&notification)
            .map_err(|e| SchruteError::Malformed(e.to_string()))?;
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| SchruteError::Transport(format!("notify write: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A scripted mock transport: returns queued responses in order and records
    /// the requests it received.
    struct MockTransport {
        responses: VecDeque<Value>,
        seen: Vec<Value>,
    }

    impl MockTransport {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: responses.into(),
                seen: Vec::new(),
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
    }

    fn ok(id: i64, result: Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"result":result})
    }

    #[test]
    fn egress_denied_target_never_calls_schrute() {
        // deny-all allowlist; replaying a public URL must be refused locally and
        // never reach the transport.
        let transport = MockTransport::new(vec![ok(1, json!({}))]); // only the (unused) init
        let mut adapter = SchruteAdapter::new(transport, EgressAllowlist::deny_all());

        let mut args = BTreeMap::new();
        args.insert("url".to_string(), json!("https://example.com/login"));
        let err = adapter
            .call(SchruteOp::Replay, args, TraceId::new())
            .unwrap_err();
        assert!(matches!(err, SchruteError::Egress(_)), "got: {err:?}");
        // No request should have been issued because the egress check precedes
        // initialize().
        assert!(adapter.transport.seen.is_empty(), "schrute was contacted despite egress denial");
    }

    #[test]
    fn private_host_blocked_even_if_domain_allowlisted() {
        let transport = MockTransport::new(vec![]);
        let allow = EgressAllowlist::from_domains(["localhost"]);
        let mut adapter = SchruteAdapter::new(transport, allow);
        let mut args = BTreeMap::new();
        args.insert("url".to_string(), json!("http://localhost:3000/"));
        let err = adapter.call(SchruteOp::Replay, args, TraceId::new()).unwrap_err();
        assert!(matches!(err, SchruteError::Egress(EgressDenied::PrivateHost(_))));
    }

    #[test]
    fn allowed_target_initializes_then_calls() {
        // init -> tools/call. Allowlist permits example.com (public).
        let transport = MockTransport::new(vec![
            ok(1, json!({"protocolVersion": MCP_PROTOCOL_VERSION})), // initialize
            ok(2, json!({"content": [{"type":"text","text":"recorded ok"}]})), // tools/call
        ]);
        let mut adapter = SchruteAdapter::new(transport, EgressAllowlist::from_domains(["example.com"]));
        let mut args = BTreeMap::new();
        args.insert("url".to_string(), json!("https://example.com/page"));
        args.insert("action_name".to_string(), json!("login"));
        let events = adapter.call(SchruteOp::Record, args, TraceId::new()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category, Category::Browser);
        assert_eq!(events[0].blocks.console.as_ref().unwrap().message.as_deref(), Some("recorded ok"));
        // Two requests: initialize, then tools/call.
        assert_eq!(adapter.transport.seen.len(), 2);
        assert_eq!(adapter.transport.seen[0]["method"], json!("initialize"));
        assert_eq!(adapter.transport.seen[1]["method"], json!("tools/call"));
        assert_eq!(adapter.transport.seen[1]["params"]["name"], json!("schrute_record"));
    }

    #[test]
    fn network_records_become_network_events_and_redact() {
        let transport = MockTransport::new(vec![
            ok(1, json!({})), // initialize
            ok(2, json!({
                "structuredContent": {
                    "requests": [
                        {"method":"GET","url":"https://example.com/api?token=AKIAIOSFODNN7EXAMPLE","status":200,"responseBytes":12},
                        {"method":"POST","url":"https://example.com/fail","status":500}
                    ]
                }
            })),
        ]);
        let mut adapter = SchruteAdapter::new(transport, EgressAllowlist::from_domains(["example.com"]));
        // Network read without navigating: no `url` arg, so egress check passes.
        let events = adapter.call(SchruteOp::Network, BTreeMap::new(), TraceId::new()).unwrap();
        assert_eq!(events.len(), 2);
        let first = &events[0];
        assert_eq!(first.kind, Kind::Network);
        let net = first.blocks.network.as_ref().unwrap();
        assert_eq!(net.status_code, Some(200));
        // The AWS key in the URL must be redacted.
        assert!(!net.url.as_deref().unwrap().contains("AKIAIOSFODNN7EXAMPLE"), "leaked secret in url: {net:?}");
        // The 500 is an error.
        assert_eq!(events[1].status, Status::Error);
    }

    #[test]
    fn rpc_error_surfaces() {
        let transport = MockTransport::new(vec![
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}),
        ]);
        let mut adapter = SchruteAdapter::new(transport, EgressAllowlist::deny_all());
        let err = adapter.initialize().unwrap_err();
        match err {
            SchruteError::Rpc { code, .. } => assert_eq!(code, -32601),
            other => panic!("expected rpc error, got {other:?}"),
        }
    }

    #[test]
    fn tool_names_match_schrute_prefix() {
        assert_eq!(SchruteOp::Record.tool_name(), "schrute_record");
        assert_eq!(SchruteOp::Replay.tool_name(), "schrute_replay");
        assert_eq!(SchruteOp::Network.tool_name(), "schrute_network");
    }

    #[test]
    fn list_tools_parses_names() {
        let transport = MockTransport::new(vec![
            ok(1, json!({})), // initialize
            ok(2, json!({"tools":[{"name":"schrute_record"},{"name":"schrute_replay"}]})),
        ]);
        let mut adapter = SchruteAdapter::new(transport, EgressAllowlist::deny_all());
        let tools = adapter.list_tools().unwrap();
        assert_eq!(tools, vec!["schrute_record", "schrute_replay"]);
    }

    // The read-timeout regression tests drive the real `StdioTransport` against
    // tiny `sh` helper processes (Unix-only; the production transport spawns a
    // node subprocess and the codebase's unsafe/process discipline is Unix).

    /// A child that drains stdin and never writes a response must NOT hang
    /// `request()` forever; the per-request deadline returns `Timeout`.
    #[cfg(unix)]
    #[test]
    fn request_times_out_when_child_never_responds() {
        use std::time::{Duration, Instant};
        // `cat >/dev/null` keeps stdout open but never emits a line.
        let mut transport = StdioTransport::spawn("sh", &["-c", "cat >/dev/null"], None)
            .expect("spawn helper")
            .with_timeout(Duration::from_millis(200));
        let start = Instant::now();
        let err = transport
            .request(json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
            .unwrap_err();
        assert!(
            matches!(err, SchruteError::Timeout(_)),
            "expected Timeout, got: {err:?}"
        );
        // It returned at roughly the deadline, not after blocking indefinitely.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "request did not return promptly at the deadline"
        );
    }

    /// A child that only ever replies with a mismatched id must not spin
    /// forever: the mismatched frame is discarded and the request still hits
    /// its deadline and returns `Timeout`.
    #[cfg(unix)]
    #[test]
    fn request_discards_mismatched_id_then_times_out() {
        use std::time::Duration;
        // Emit one response carrying id 999 (never our id), then sleep so stdout
        // stays open with no further frames.
        let script = r#"read line; printf '{"jsonrpc":"2.0","id":999,"result":{}}\n'; sleep 5"#;
        let mut transport = StdioTransport::spawn("sh", &["-c", script], None)
            .expect("spawn helper")
            .with_timeout(Duration::from_millis(300));
        let err = transport
            .request(json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
            .unwrap_err();
        assert!(
            matches!(err, SchruteError::Timeout(_)),
            "mismatched id must be discarded and the request must time out, got: {err:?}"
        );
    }

    /// Sanity: a child that echoes a correctly-id'd response resolves normally
    /// through the real `StdioTransport` (the reader-thread happy path).
    #[cfg(unix)]
    #[test]
    fn request_resolves_matching_id_over_stdio() {
        use std::time::Duration;
        // Read one request line, then reply with our id (1).
        let script = r#"read line; printf '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'"#;
        let mut transport = StdioTransport::spawn("sh", &["-c", script], None)
            .expect("spawn helper")
            .with_timeout(Duration::from_secs(5));
        let resp = transport
            .request(json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
            .expect("matching response should resolve");
        assert_eq!(resp["result"]["ok"], json!(true));
    }
}
