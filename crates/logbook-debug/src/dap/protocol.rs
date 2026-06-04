//! Debug Adapter Protocol (DAP) wire types and `Content-Length` framing.
//!
//! DAP base protocol (the same envelope VS Code and every DAP adapter speak):
//! each message is a UTF-8 JSON object prefixed by an HTTP-style header
//!
//! ```text
//! Content-Length: <byte-length-of-body>\r\n
//! \r\n
//! <json-body>
//! ```
//!
//! There are three message types, discriminated by the `type` field:
//! `request`, `response`, and `event`. We model only the slice needed to set a
//! **logpoint** and ingest its output — not the full protocol surface (this is
//! the alpha tier, plan §6).
//!
//! References: the DAP specification (`microsoft/debug-adapter-protocol`),
//! `Content-Length` framing and the `request`/`response`/`event` shapes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{DebugError, Result};

/// Maximum body we will buffer for a single DAP message (1 MiB). A larger
/// declared `Content-Length` is treated as a protocol error rather than an
/// invitation to allocate unboundedly.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// An outgoing DAP **request**.
#[derive(Clone, Debug, Serialize)]
pub struct Request {
    /// Sequence number (monotonic, client-assigned, starts at 1).
    pub seq: i64,
    /// Always `"request"`.
    #[serde(rename = "type")]
    pub type_: &'static str,
    /// The command name (e.g. `initialize`, `setBreakpoints`, `disconnect`).
    pub command: String,
    /// Command arguments, omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

impl Request {
    /// Build a request with the given seq, command, and optional arguments.
    #[must_use]
    pub fn new(seq: i64, command: impl Into<String>, arguments: Option<Value>) -> Self {
        Self {
            seq,
            type_: "request",
            command: command.into(),
            arguments,
        }
    }
}

/// An incoming DAP **response** to a request.
#[derive(Clone, Debug, Deserialize)]
pub struct Response {
    /// This response's own sequence number.
    #[serde(default)]
    pub seq: i64,
    /// The `seq` of the request this responds to.
    pub request_seq: i64,
    /// Whether the request succeeded.
    pub success: bool,
    /// The command that was requested.
    #[serde(default)]
    pub command: String,
    /// Failure message when `success == false`.
    #[serde(default)]
    pub message: Option<String>,
    /// Command-specific result body.
    #[serde(default)]
    pub body: Option<Value>,
}

/// An incoming DAP **event** (unsolicited, adapter-initiated).
#[derive(Clone, Debug, Deserialize)]
pub struct Event {
    /// This event's sequence number.
    #[serde(default)]
    pub seq: i64,
    /// The event name (e.g. `initialized`, `output`, `terminated`).
    pub event: String,
    /// Event-specific body.
    #[serde(default)]
    pub body: Option<Value>,
}

/// Any inbound protocol message, discriminated on the `type` field.
#[derive(Clone, Debug)]
pub enum Inbound {
    /// A response to one of our requests.
    Response(Response),
    /// An adapter-initiated event.
    Event(Event),
    /// A request *from* the adapter (reverse request, e.g. `runInTerminal`). We
    /// don't service these in the alpha client, but we surface them so the read
    /// loop doesn't choke on them.
    Request(Request),
}

impl Inbound {
    /// Parse a decoded JSON body into a typed inbound message.
    ///
    /// # Errors
    /// Returns [`DebugError::DapProtocol`] if the `type` field is missing or
    /// unrecognized, or [`DebugError::Serde`] if the body doesn't match the
    /// expected shape.
    pub fn from_json(body: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(body)?;
        let ty = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| DebugError::DapProtocol("message missing `type` field".to_string()))?;
        match ty {
            "response" => Ok(Inbound::Response(serde_json::from_value(value)?)),
            "event" => Ok(Inbound::Event(serde_json::from_value(value)?)),
            "request" => {
                // Reverse requests carry no `seq` guarantees we rely on; map
                // through a lenient shape.
                let seq = value.get("seq").and_then(Value::as_i64).unwrap_or(0);
                let command = value
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let arguments = value.get("arguments").cloned();
                Ok(Inbound::Request(Request {
                    seq,
                    type_: "request",
                    command,
                    arguments,
                }))
            }
            other => Err(DebugError::DapProtocol(format!(
                "unknown message type {other:?}"
            ))),
        }
    }
}

/// Serialize an outgoing request into a fully framed DAP message
/// (`Content-Length` header + CRLFCRLF + JSON body).
///
/// # Errors
/// Returns [`DebugError::Serde`] if the request cannot be serialized.
pub fn encode(request: &Request) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(request)?;
    let mut framed = Vec::with_capacity(body.len() + 32);
    framed.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

/// Parse the `Content-Length` value out of a header block (the bytes before the
/// blank line). Header names are matched case-insensitively per the spec.
///
/// # Errors
/// Returns [`DebugError::DapProtocol`] if the header is absent, unparseable, or
/// exceeds [`MAX_BODY_BYTES`].
pub fn parse_content_length(headers: &str) -> Result<usize> {
    for line in headers.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                let n: usize = value.trim().parse().map_err(|_| {
                    DebugError::DapProtocol(format!("invalid Content-Length: {value:?}"))
                })?;
                if n > MAX_BODY_BYTES {
                    return Err(DebugError::DapProtocol(format!(
                        "Content-Length {n} exceeds maximum {MAX_BODY_BYTES}"
                    )));
                }
                return Ok(n);
            }
        }
    }
    Err(DebugError::DapProtocol(
        "missing Content-Length header".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_frames_with_content_length() {
        let req = Request::new(1, "initialize", Some(serde_json::json!({"adapterID": "x"})));
        let framed = encode(&req).unwrap();
        let s = String::from_utf8(framed).unwrap();
        assert!(s.starts_with("Content-Length: "));
        // header / body separated by a blank line
        let (header, body) = s.split_once("\r\n\r\n").unwrap();
        let declared = parse_content_length(header).unwrap();
        assert_eq!(declared, body.len());
        assert!(body.contains("\"command\":\"initialize\""));
        assert!(body.contains("\"type\":\"request\""));
    }

    #[test]
    fn parse_content_length_is_case_insensitive() {
        assert_eq!(parse_content_length("content-LENGTH: 42").unwrap(), 42);
        assert_eq!(
            parse_content_length("X-Foo: bar\r\nContent-Length: 7").unwrap(),
            7
        );
    }

    #[test]
    fn parse_content_length_rejects_missing_and_huge() {
        assert!(parse_content_length("X-Foo: bar").is_err());
        let huge = format!("Content-Length: {}", MAX_BODY_BYTES + 1);
        assert!(parse_content_length(&huge).is_err());
    }

    #[test]
    fn inbound_discriminates_on_type() {
        let resp = br#"{"type":"response","request_seq":1,"success":true,"command":"initialize"}"#;
        assert!(matches!(Inbound::from_json(resp).unwrap(), Inbound::Response(_)));

        let evt = br#"{"type":"event","event":"output","body":{"output":"hi"}}"#;
        match Inbound::from_json(evt).unwrap() {
            Inbound::Event(e) => assert_eq!(e.event, "output"),
            _ => panic!("expected event"),
        }

        let bad = br#"{"foo":"bar"}"#;
        assert!(Inbound::from_json(bad).is_err());
    }

    #[test]
    fn response_failure_carries_message() {
        let resp = br#"{"type":"response","request_seq":2,"success":false,"command":"setBreakpoints","message":"no such file"}"#;
        match Inbound::from_json(resp).unwrap() {
            Inbound::Response(r) => {
                assert!(!r.success);
                assert_eq!(r.message.as_deref(), Some("no such file"));
            }
            _ => panic!("expected response"),
        }
    }
}
