//! A minimal async Debug Adapter Protocol client (plan §6, Tier 2 **alpha**).
//!
//! The client connects to a **running process's** debug adapter, performs the
//! `initialize` handshake, installs **logpoints** (`setBreakpoints` with
//! `logMessage`), and ingests the resulting `output` events as logbook
//! [`Event`](logbook_core::Event)s — all **without stopping** execution and
//! **without editing source**. On [`DapClient::disconnect`] it detaches every
//! logpoint (sends `setBreakpoints` with an empty list per file, then
//! `disconnect`).
//!
//! ## Scope (honest, per plan)
//! This is the *alpha* tier. It speaks only the slice of DAP needed for
//! logpoints: `initialize`, `setBreakpoints`, `configurationDone`, `disconnect`,
//! plus consuming `output`/`initialized`/`terminated` events. It does **not**
//! launch/attach programs, manage threads, evaluate in stack frames, or cover
//! the wider protocol — the reliable Tier-1 passive path remains the default.
//!
//! ## Transport
//! [`DapClient`] is generic over any [`AsyncRead`] + [`AsyncWrite`] transport,
//! so it drives a real adapter over TCP ([`DapClient::connect_tcp`]) or over a
//! spawned adapter's stdio, and is exercised in tests over a loopback socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use logbook_core::{Redactor, SessionId, TraceId};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::dap::logpoint::{output_event_to_event, set_breakpoints_arguments, Logpoint};
use crate::dap::protocol::{self, Inbound, Request, Response};
use crate::error::{DebugError, Result};

/// Default timeout for a single DAP request/response exchange.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Where ingested logpoint-output [`Event`](logbook_core::Event)s are sent.
///
/// Implementors persist or forward the event. The crate ships a store-backed
/// sink in [`crate::session`]; tests use a channel-backed one.
pub trait EventSink: Send + Sync + 'static {
    /// Handle one ingested event. Errors are logged by the caller; a failing
    /// sink must not tear down the read loop.
    fn emit(&self, event: logbook_core::Event);
}

/// An [`EventSink`] backed by an `mpsc` channel (used by tests and callers that
/// want to drain events themselves).
pub struct ChannelSink {
    tx: mpsc::UnboundedSender<logbook_core::Event>,
}

impl ChannelSink {
    /// Create a sink and its receiver.
    #[must_use]
    pub fn new() -> (Self, mpsc::UnboundedReceiver<logbook_core::Event>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl EventSink for ChannelSink {
    fn emit(&self, event: logbook_core::Event) {
        // Best-effort: if the receiver is gone, drop the event.
        let _ = self.tx.send(event);
    }
}

/// Shared state for matching responses to outstanding requests.
type Pending = Arc<Mutex<HashMap<i64, oneshot::Sender<Response>>>>;

/// A connected DAP client.
///
/// Cheap to hold; owns the write half of the transport, a background read task,
/// and the bookkeeping needed to correlate responses and detach logpoints.
pub struct DapClient {
    /// Write half of the transport, behind a mutex (requests are serialized).
    writer: Arc<Mutex<WriteHalf<Box<dyn Transport>>>>,
    /// Monotonic request sequence.
    seq: AtomicI64,
    /// Outstanding requests awaiting a response.
    pending: Pending,
    /// The read task handle (aborted on drop / disconnect).
    reader: Option<JoinHandle<()>>,
    /// Files we've installed logpoints on, so `disconnect` can clear each.
    instrumented_files: Mutex<Vec<String>>,
    /// Per-request timeout.
    timeout: Duration,
    /// Whether `disconnect` has run (idempotency).
    disconnected: std::sync::atomic::AtomicBool,
}

/// Marker trait for a duplex transport the client can own as a trait object.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

impl DapClient {
    /// Connect to a debug adapter listening on a TCP address (the common
    /// "debug server" deployment, e.g. `debugpy --listen`, `dlv dap`,
    /// `node --inspect`-style DAP servers behind an adapter).
    ///
    /// `trace` correlates ingested output; `session` tags it; `sink` receives
    /// the [`Event`](logbook_core::Event)s; `redactor` scrubs logged text
    /// before it is persisted.
    ///
    /// # Errors
    /// Returns [`DebugError::DapIo`] if the connection fails.
    pub async fn connect_tcp(
        addr: impl tokio::net::ToSocketAddrs,
        trace: TraceId,
        session: SessionId,
        sink: Arc<dyn EventSink>,
        redactor: Arc<Redactor>,
    ) -> Result<Self> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        Ok(Self::from_transport(
            Box::new(stream),
            trace,
            session,
            sink,
            redactor,
        ))
    }

    /// Build a client over an arbitrary already-connected transport (TCP, the
    /// stdio of a spawned adapter, or an in-memory duplex in tests).
    #[must_use]
    pub fn from_transport(
        transport: Box<dyn Transport>,
        trace: TraceId,
        session: SessionId,
        sink: Arc<dyn EventSink>,
        redactor: Arc<Redactor>,
    ) -> Self {
        let (read_half, write_half) = tokio::io::split(transport);
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));

        let reader = tokio::spawn(read_loop(
            read_half,
            Arc::clone(&pending),
            trace,
            session,
            sink,
            redactor,
        ));

        Self {
            writer: Arc::new(Mutex::new(write_half)),
            seq: AtomicI64::new(1),
            pending,
            reader: Some(reader),
            instrumented_files: Mutex::new(Vec::new()),
            timeout: DEFAULT_REQUEST_TIMEOUT,
            disconnected: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Override the per-request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Next request sequence number.
    fn next_seq(&self) -> i64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a request and await its response (matched by `request_seq`),
    /// enforcing the per-request timeout and surfacing adapter-side failures.
    ///
    /// # Errors
    /// - [`DebugError::DapIo`] on a write failure.
    /// - [`DebugError::DapTimeout`] if no response arrives in time.
    /// - [`DebugError::DapRequestFailed`] if the adapter replies `success:false`.
    pub async fn request(&self, command: &str, arguments: Option<Value>) -> Result<Response> {
        let seq = self.next_seq();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(seq, tx);

        let framed = protocol::encode(&Request::new(seq, command, arguments))?;
        {
            let mut w = self.writer.lock().await;
            w.write_all(&framed).await?;
            w.flush().await?;
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => {
                if resp.success {
                    Ok(resp)
                } else {
                    Err(DebugError::DapRequestFailed {
                        command: command.to_string(),
                        message: resp.message.unwrap_or_else(|| "<no message>".to_string()),
                    })
                }
            }
            Ok(Err(_canceled)) => Err(DebugError::DapProtocol(format!(
                "response channel closed for {command}"
            ))),
            Err(_elapsed) => {
                // Drop the pending entry so a late response is ignored.
                self.pending.lock().await.remove(&seq);
                Err(DebugError::DapTimeout(self.timeout))
            }
        }
    }

    /// Perform the DAP `initialize` handshake. Returns the adapter capabilities
    /// body. Many adapters then send an `initialized` event; logpoints can be
    /// configured once initialize has returned.
    ///
    /// # Errors
    /// See [`DapClient::request`].
    pub async fn initialize(&self, client_id: &str) -> Result<Option<Value>> {
        let args = serde_json::json!({
            "clientID": client_id,
            "clientName": "logbook-debug",
            "adapterID": "logbook",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "pathFormat": "path",
            "supportsRunInTerminalRequest": false,
        });
        let resp = self.request("initialize", Some(args)).await?;
        Ok(resp.body)
    }

    /// Tell the adapter configuration is complete (sent after the initial
    /// `setBreakpoints` for adapters that emit `initialized`). Failures are
    /// non-fatal for logpoints, so callers may ignore the error.
    ///
    /// # Errors
    /// See [`DapClient::request`].
    pub async fn configuration_done(&self) -> Result<()> {
        self.request("configurationDone", None).await.map(|_| ())
    }

    /// Install `logpoints` on the running process. Logpoints are grouped by file
    /// and one `setBreakpoints` request is sent per file (DAP requires all
    /// breakpoints in a call to share the same `source`). **No source is
    /// written and the adapter does not stop** — logpoints only log.
    ///
    /// The instrumented files are remembered so [`DapClient::disconnect`] can
    /// clear each one.
    ///
    /// # Errors
    /// See [`DapClient::request`]; the first failing file aborts.
    pub async fn set_logpoints(&self, logpoints: &[Logpoint]) -> Result<()> {
        // Stable, de-duplicated file order.
        let mut files: Vec<String> = logpoints.iter().map(|lp| lp.file.clone()).collect();
        files.sort();
        files.dedup();

        for file in &files {
            let args = set_breakpoints_arguments(file, logpoints);
            self.request("setBreakpoints", Some(args)).await?;
        }

        let mut tracked = self.instrumented_files.lock().await;
        for f in files {
            if !tracked.contains(&f) {
                tracked.push(f);
            }
        }
        Ok(())
    }

    /// Detach all logpoints and disconnect from the adapter.
    ///
    /// Clears breakpoints on every instrumented file (`setBreakpoints` with an
    /// empty list) and then sends `disconnect`. Idempotent and best-effort:
    /// individual step failures are swallowed so detach always completes — the
    /// guarantee that matters is that **no logpoints remain and no source was
    /// touched**.
    pub async fn disconnect(&self) {
        if self.disconnected.swap(true, Ordering::SeqCst) {
            return;
        }
        let files = {
            let tracked = self.instrumented_files.lock().await;
            tracked.clone()
        };
        for file in files {
            let args = serde_json::json!({
                "source": { "path": file },
                "breakpoints": [],
                "sourceModified": false,
            });
            // Best-effort clear.
            let _ = self.request("setBreakpoints", Some(args)).await;
        }
        let _ = self
            .request(
                "disconnect",
                Some(serde_json::json!({ "restart": false, "terminateDebuggee": false })),
            )
            .await;
        // Stop the read loop.
        if let Some(handle) = self.reader_handle() {
            handle.abort();
        }
    }

    /// Take the reader join handle for aborting (used by `disconnect`/`Drop`).
    fn reader_handle(&self) -> Option<tokio::task::AbortHandle> {
        self.reader.as_ref().map(JoinHandle::abort_handle)
    }
}

impl std::fmt::Debug for DapClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DapClient")
            .field("seq", &self.seq.load(Ordering::Relaxed))
            .field("timeout", &self.timeout)
            .field(
                "disconnected",
                &self.disconnected.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for DapClient {
    fn drop(&mut self) {
        // If the caller never called `disconnect`, at least stop the read task
        // so it doesn't outlive the client. (We can't run async detach here;
        // callers should `disconnect().await` for a clean teardown.)
        if let Some(handle) = self.reader.take() {
            handle.abort();
        }
    }
}

/// The background read loop: frame messages off the transport, route responses
/// to their pending request, and ingest `output` events via the sink. Exits on
/// EOF, a hard transport error, or abort.
async fn read_loop(
    mut reader: ReadHalf<Box<dyn Transport>>,
    pending: Pending,
    trace: TraceId,
    session: SessionId,
    sink: Arc<dyn EventSink>,
    redactor: Arc<Redactor>,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];

    loop {
        // Try to parse as many complete messages as the buffer holds.
        loop {
            match try_take_message(&buf) {
                Ok(Some((consumed, body))) => {
                    buf.drain(..consumed);
                    dispatch(&body, &pending, trace, &session, &sink, &redactor).await;
                }
                Ok(None) => break, // need more bytes
                Err(e) => {
                    tracing::warn!(error = %e, "dap: dropping unparseable message buffer");
                    buf.clear();
                    break;
                }
            }
        }

        match reader.read(&mut chunk).await {
            Ok(0) => break, // EOF
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                tracing::debug!(error = %e, "dap: read loop ending");
                break;
            }
        }
    }
}

/// If `buf` starts with a complete framed message, return `(bytes_consumed,
/// body)`. Returns `Ok(None)` when more bytes are needed.
fn try_take_message(buf: &[u8]) -> Result<Option<(usize, Vec<u8>)>> {
    // Find the header/body separator (CRLFCRLF).
    let Some(sep) = find_subsequence(buf, b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&buf[..sep])
        .map_err(|_| DebugError::DapProtocol("non-utf8 DAP header".to_string()))?;
    let content_len = protocol::parse_content_length(headers)?;
    let body_start = sep + 4;
    let body_end = body_start + content_len;
    if buf.len() < body_end {
        return Ok(None); // body not fully arrived
    }
    let body = buf[body_start..body_end].to_vec();
    Ok(Some((body_end, body)))
}

/// Route one decoded message body.
async fn dispatch(
    body: &[u8],
    pending: &Pending,
    trace: TraceId,
    session: &SessionId,
    sink: &Arc<dyn EventSink>,
    redactor: &Redactor,
) {
    match Inbound::from_json(body) {
        Ok(Inbound::Response(resp)) => {
            if let Some(tx) = pending.lock().await.remove(&resp.request_seq) {
                let _ = tx.send(resp);
            }
        }
        Ok(Inbound::Event(evt)) => {
            // Logpoint hits surface as `output` events.
            if evt.event == "output" {
                if let Some(b) = &evt.body {
                    let event = output_event_to_event(trace, session, b, redactor);
                    sink.emit(event);
                }
            }
            // `initialized` / `terminated` / others are not needed for the
            // alpha logpoint path; ignore.
        }
        Ok(Inbound::Request(_)) => {
            // Reverse requests (e.g. runInTerminal) are unsupported in alpha.
        }
        Err(e) => tracing::warn!(error = %e, "dap: failed to decode message"),
    }
}

/// Find the first index of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_crlf_separator() {
        assert_eq!(find_subsequence(b"ab\r\n\r\ncd", b"\r\n\r\n"), Some(2));
        assert_eq!(find_subsequence(b"no separator here", b"\r\n\r\n"), None);
    }

    #[test]
    fn try_take_message_waits_for_full_body() {
        // Header present but body short.
        let partial = b"Content-Length: 10\r\n\r\n{\"a\":1}";
        assert!(matches!(try_take_message(partial), Ok(None)));

        // Complete message followed by the start of another.
        let body = br#"{"type":"event","event":"x"}"#;
        let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        framed.extend_from_slice(body);
        framed.extend_from_slice(b"Content-Length: 5\r\n\r\nABC"); // trailing partial
        let (consumed, taken) = try_take_message(&framed).unwrap().unwrap();
        assert_eq!(taken, body);
        // Consumed exactly the first message.
        assert_eq!(consumed, framed.len() - "Content-Length: 5\r\n\r\nABC".len());
    }
}
