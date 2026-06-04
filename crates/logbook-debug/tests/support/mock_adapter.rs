//! A hermetic mock Debug Adapter Protocol server for integration tests.
//!
//! Speaks just enough DAP over a loopback TCP socket to exercise the alpha
//! logpoint flow without requiring a real language debugger to be installed:
//! it frames `Content-Length` messages, answers `initialize` /
//! `setBreakpoints` / `configurationDone` / `disconnect` with `success:true`,
//! and (after the first `setBreakpoints` that installs a logpoint) emits a
//! couple of `output` events to simulate logpoint hits.
//!
//! Crucially, the mock adapter **never reads or writes any file on disk** — it
//! only echoes protocol — which is exactly the property the `git status` test
//! relies on for the *client* side too.
//!
//! NOTE: this file is `#[path]`-included by integration tests, so not every
//! item is used by every test; suppress dead-code noise.
#![allow(dead_code)]

use std::sync::atomic::{AtomicI64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Spawn a mock adapter on an ephemeral loopback port. Returns the bound
/// `SocketAddr`; the server task serves exactly one connection then returns.
pub async fn spawn() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _peer)) = listener.accept().await {
            serve(stream).await;
        }
    });
    addr
}

/// Serve one DAP client connection until it disconnects or EOFs.
async fn serve(mut stream: TcpStream) {
    let seq = AtomicI64::new(1);
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut emitted_logpoint_output = false;

    loop {
        // Parse complete framed messages currently in the buffer.
        while let Some((consumed, body)) = take_message(&buf) {
            buf.drain(..consumed);
            let value: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if value.get("type").and_then(|t| t.as_str()) != Some("request") {
                continue;
            }
            let req_seq = value.get("seq").and_then(|s| s.as_i64()).unwrap_or(0);
            let command = value
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();

            // Acknowledge the request.
            let body = match command.as_str() {
                "initialize" => Some(serde_json::json!({
                    "supportsConfigurationDoneRequest": true,
                    "supportsLogPoints": true,
                })),
                "setBreakpoints" => {
                    // Report each requested breakpoint as verified.
                    let bps = value
                        .get("arguments")
                        .and_then(|a| a.get("breakpoints"))
                        .and_then(|b| b.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|b| {
                                    serde_json::json!({
                                        "verified": true,
                                        "line": b.get("line").cloned().unwrap_or(serde_json::Value::Null),
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    Some(serde_json::json!({ "breakpoints": bps }))
                }
                _ => None,
            };
            send_response(&mut stream, &seq, req_seq, &command, true, body).await;

            // After installing the first logpoint, emit simulated hits.
            if command == "setBreakpoints" && !emitted_logpoint_output {
                let installed = value
                    .get("arguments")
                    .and_then(|a| a.get("breakpoints"))
                    .and_then(|b| b.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                if installed {
                    emitted_logpoint_output = true;
                    send_output(&mut stream, &seq, "x=41", 7).await;
                    send_output(&mut stream, &seq, "x=42", 7).await;
                }
            }

            if command == "disconnect" {
                let _ = stream.flush().await;
                return;
            }
        }

        match stream.read(&mut chunk).await {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
    }
}

async fn send_response(
    stream: &mut TcpStream,
    seq: &AtomicI64,
    request_seq: i64,
    command: &str,
    success: bool,
    body: Option<serde_json::Value>,
) {
    let mut msg = serde_json::json!({
        "seq": seq.fetch_add(1, Ordering::Relaxed),
        "type": "response",
        "request_seq": request_seq,
        "success": success,
        "command": command,
    });
    if let Some(b) = body {
        msg["body"] = b;
    }
    write_framed(stream, &msg).await;
}

async fn send_output(stream: &mut TcpStream, seq: &AtomicI64, text: &str, line: i64) {
    let msg = serde_json::json!({
        "seq": seq.fetch_add(1, Ordering::Relaxed),
        "type": "event",
        "event": "output",
        "body": {
            "category": "stdout",
            "output": text,
            "line": line,
            "source": { "path": "/virtual/main" }
        }
    });
    write_framed(stream, &msg).await;
}

async fn write_framed(stream: &mut TcpStream, msg: &serde_json::Value) {
    let body = serde_json::to_vec(msg).unwrap();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.flush().await;
}

/// Pull one complete framed message off the front of `buf`, if present.
fn take_message(buf: &[u8]) -> Option<(usize, Vec<u8>)> {
    let sep = find(buf, b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&buf[..sep]).ok()?;
    let mut content_len = None;
    for line in headers.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_len = value.trim().parse::<usize>().ok();
            }
        }
    }
    let content_len = content_len?;
    let body_start = sep + 4;
    let body_end = body_start + content_len;
    if buf.len() < body_end {
        return None;
    }
    Some((body_end, buf[body_start..body_end].to_vec()))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
