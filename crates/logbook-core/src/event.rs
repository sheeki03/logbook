//! The unified [`Event`] model and its enums / domain blocks (plan §2).
//!
//! Every observation in logbook — a log line, an LLM call, a browser console
//! message, a security finding, an inventory record — is one `Event`. The shape
//! is deliberately export-friendly (OTel / OpenInference-shaped): W3C-width ids,
//! a microsecond timestamp, a `kind`/`type`/`category`/`operation`/`name`
//! quadruple for classification, a free-form `attributes` bag, and optional
//! typed domain blocks.

use serde::{Deserialize, Serialize};

use crate::ids::{SpanId, TraceId};
use crate::session::{EventId, SessionId};

/// Coarse span classification, OpenInference-flavored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A structured log line (the PTY/console tier).
    Log,
    /// An LLM / chat-completion call.
    Llm,
    /// A tool / function call made by an agent.
    Tool,
    /// A high-level agent step or turn.
    Agent,
    /// A browser-originated event (console, network, error).
    Browser,
    /// A network request/response not tied to a browser.
    Network,
    /// A security or inventory finding.
    Finding,
    /// A test / check result.
    Test,
    /// A generic span with no more specific kind.
    Span,
    /// Anything not yet modelled.
    Other,
}

/// The high-level lane an event belongs to. Drives UI tabs and store indexes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Coding-agent activity (`logbook agent <cli>` sessions, agent steps).
    Agent,
    /// Browser state (console, network, DOM) from injected-JS or schrute.
    Browser,
    /// Application / process logs captured via the PTY pipeline.
    AppLog,
    /// Code test / check results.
    CodeTest,
    /// Security findings (Semgrep / Trivy / cargo-audit / SARIF import).
    Security,
    /// Endpoint-inventory records (installed agents, MCP servers, risk).
    Inventory,
}

impl Category {
    /// Stable lowercase wire string (matches the serde representation and the
    /// value stored in the SQLite `category` column).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Agent => "agent",
            Category::Browser => "browser",
            Category::AppLog => "app_log",
            Category::CodeTest => "code_test",
            Category::Security => "security",
            Category::Inventory => "inventory",
        }
    }
}

/// Terminal disposition of a span.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Span has not yet completed.
    #[default]
    Unset,
    /// Completed successfully.
    Ok,
    /// Completed with an error (see [`Event::error`]).
    Error,
}

/// Severity used by [`FindingBlock`] (security + inventory findings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational, no action required.
    Info,
    /// Low impact.
    Low,
    /// Medium impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact.
    Critical,
}

impl Severity {
    /// Every severity, ascending (least to most severe).
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Stable lowercase wire string (matches the serde representation and the
    /// value stored in the SQLite `findings.severity` column). This is the
    /// single source of truth previously hand-copied as `sev_str` /
    /// `severity_str` / `severity_label` across the workspace.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity from its lowercase wire token, returning `None` for an
    /// unrecognized value (callers that want a lossy default can use
    /// `from_wire(s).unwrap_or(Severity::Info)`). Matching is case-insensitive.
    #[must_use]
    pub fn from_wire(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Numeric rank `0..=4` (`Info` = 0 … `Critical` = 4), matching the derived
    /// [`Ord`]. Useful for `min_severity` filtering; prefer comparing
    /// `Severity` values via `Ord` directly where possible.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = crate::error::CoreError;

    /// Parse from the lowercase wire token (case-insensitive). Errors with
    /// [`CoreError::BadSeverity`](crate::error::CoreError::BadSeverity) on an
    /// unrecognized value.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::from_wire(s)
            .ok_or_else(|| crate::error::CoreError::BadSeverity(s.to_string()))
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Kind {
    /// Stable lowercase wire string (matches the serde `snake_case`
    /// representation and the value stored in the SQLite `kind` column).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Log => "log",
            Kind::Llm => "llm",
            Kind::Tool => "tool",
            Kind::Agent => "agent",
            Kind::Browser => "browser",
            Kind::Network => "network",
            Kind::Finding => "finding",
            Kind::Test => "test",
            Kind::Span => "span",
            Kind::Other => "other",
        }
    }
}

impl Status {
    /// Stable lowercase wire string (matches the serde `snake_case`
    /// representation and the value stored in the SQLite `status` column).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Unset => "unset",
            Status::Ok => "ok",
            Status::Error => "error",
        }
    }
}

/// LLM / chat-completion details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LlmBlock {
    /// Provider (e.g. `anthropic`, `openai`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Model identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Prompt / input tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Completion / output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// Total tokens, if reported directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Reported / estimated cost in USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

/// Tool / function-call details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolBlock {
    /// Tool / function name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Whether the call is considered a "write" (mutating) tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_write: Option<bool>,
    /// Arguments passed to the tool (already redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
}

/// Agent step / turn details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentBlock {
    /// Agent CLI / product (e.g. `claude`, `cursor`, `codex`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Zero-based step index within the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u64>,
    /// Free-form role (`user`, `assistant`, `system`, `tool`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Browser/process console details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConsoleBlock {
    /// Console level (`log`, `info`, `warn`, `error`, `debug`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Rendered message (already redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Originating URL / file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Stack trace, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
}

/// Network request/response details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkBlock {
    /// HTTP method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Request URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Response status code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Request body size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    /// Response body size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
}

/// Security / inventory finding details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingBlock {
    /// Tool / scanner that produced the finding (e.g. `semgrep`, `trivy`,
    /// `inventory`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Stable rule / check identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Severity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Affected file path, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// One-based line number, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The optional typed domain blocks an [`Event`] may carry. All are flattened
/// into the parent during (de)serialization so the JSON stays flat and
/// export-friendly, and each is omitted entirely when absent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Blocks {
    /// LLM call details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmBlock>,
    /// Tool call details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolBlock>,
    /// Agent step details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentBlock>,
    /// Console details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console: Option<ConsoleBlock>,
    /// Network details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkBlock>,
    /// Finding details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<FindingBlock>,
}

impl Blocks {
    /// Whether every block is absent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.llm.is_none()
            && self.tool.is_none()
            && self.agent.is_none()
            && self.console.is_none()
            && self.network.is_none()
            && self.finding.is_none()
    }
}

/// A microsecond UNIX timestamp wrapper for clarity (the store column is
/// `INTEGER` microseconds). Stored/serialized as a bare integer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MicrosTimestamp(pub i64);

impl MicrosTimestamp {
    /// The current wall-clock time in microseconds since the UNIX epoch.
    #[must_use]
    pub fn now() -> Self {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self(i64::try_from(dur.as_micros()).unwrap_or(i64::MAX))
    }

    /// The raw microsecond value.
    #[must_use]
    pub const fn as_micros(self) -> i64 {
        self.0
    }
}

/// The unified event record.
///
/// Construct via [`Event::new`] (which mints `id` + `timestamp`) and then set
/// fields with the builder-style `with_*` methods, or fill the struct directly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Stable unique id (SQLite primary key; idempotent-upsert key for the hub).
    pub id: EventId,
    /// W3C trace id (128-bit) tying correlated events together.
    pub trace_id: TraceId,
    /// Parent span id (64-bit), if this event is a child span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<SpanId>,
    /// Event time, microseconds since the UNIX epoch.
    pub timestamp: MicrosTimestamp,
    /// Span duration in milliseconds, if the span has completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// Coarse classification.
    pub kind: Kind,
    /// Fine-grained type string (free-form, e.g. `chat.completion`, `stderr`,
    /// `cargo_audit.advisory`). Serialized as `type`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The lane this event belongs to.
    pub category: Category,
    /// Operation name (verb-ish, e.g. `request`, `navigate`, `scan`).
    pub operation: String,
    /// Human-friendly display name.
    pub name: String,
    /// Terminal disposition.
    #[serde(default)]
    pub status: Status,
    /// Error message when `status == Error` (already redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Free-form attribute bag (already redacted).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    /// Span input payload (already redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    /// Span output payload (already redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Logical session this event belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Typed domain blocks, flattened into the parent JSON object.
    #[serde(flatten)]
    pub blocks: Blocks,
}

impl Event {
    /// Create a new event with a fresh id and `now()` timestamp, in the given
    /// `kind`/`category`, with the supplied `type`. `operation` and `name`
    /// default to the type string and can be overridden with [`Event::with_op`]
    /// / [`Event::with_name`].
    #[must_use]
    pub fn new(
        trace_id: TraceId,
        kind: Kind,
        category: Category,
        type_: impl Into<String>,
    ) -> Self {
        let type_ = type_.into();
        Self {
            id: EventId::generate(),
            trace_id,
            parent_id: None,
            timestamp: MicrosTimestamp::now(),
            duration_ms: None,
            kind,
            operation: type_.clone(),
            name: type_.clone(),
            type_,
            category,
            status: Status::Unset,
            error: None,
            attributes: serde_json::Map::new(),
            input: None,
            output: None,
            session_id: None,
            blocks: Blocks::default(),
        }
    }

    /// Set the parent span id.
    #[must_use]
    pub fn with_parent(mut self, parent: SpanId) -> Self {
        self.parent_id = Some(parent);
        self
    }

    /// Set the operation name.
    #[must_use]
    pub fn with_op(mut self, op: impl Into<String>) -> Self {
        self.operation = op.into();
        self
    }

    /// Set the display name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the status.
    #[must_use]
    pub fn with_status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    /// Mark the event errored with the given (pre-redacted) message.
    #[must_use]
    pub fn with_error(mut self, message: impl Into<String>) -> Self {
        self.status = Status::Error;
        self.error = Some(message.into());
        self
    }

    /// Attach to a session.
    #[must_use]
    pub fn with_session(mut self, session: SessionId) -> Self {
        self.session_id = Some(session);
        self
    }

    /// Set the duration in milliseconds.
    #[must_use]
    pub fn with_duration_ms(mut self, ms: f64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Insert/overwrite a single attribute.
    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Attach a finding block.
    ///
    /// Note: this sets only `blocks.finding`; it does **not** adjust
    /// `kind`/`category`. Producers are responsible for choosing a coherent
    /// `Kind`/`Category` (typically [`Kind::Finding`] + [`Category::Security`]
    /// or [`Category::Inventory`]); see [`Event::validate`] for the invariants.
    #[must_use]
    pub fn with_finding(mut self, finding: FindingBlock) -> Self {
        self.blocks.finding = Some(finding);
        self
    }

    /// Attach an LLM block.
    #[must_use]
    pub fn with_llm(mut self, llm: LlmBlock) -> Self {
        self.blocks.llm = Some(llm);
        self
    }

    /// Attach a console block.
    #[must_use]
    pub fn with_console(mut self, console: ConsoleBlock) -> Self {
        self.blocks.console = Some(console);
        self
    }

    /// Attach a network block.
    #[must_use]
    pub fn with_network(mut self, network: NetworkBlock) -> Self {
        self.blocks.network = Some(network);
        self
    }

    /// Attach a tool block.
    #[must_use]
    pub fn with_tool(mut self, tool: ToolBlock) -> Self {
        self.blocks.tool = Some(tool);
        self
    }

    /// Attach an agent block.
    #[must_use]
    pub fn with_agent(mut self, agent: AgentBlock) -> Self {
        self.blocks.agent = Some(agent);
        self
    }

    /// Check the key cross-field invariants the rest of the system relies on.
    ///
    /// The flat `Event`-with-optional-`Blocks` shape is **intentional** (plan
    /// §2): it keeps the JSON wire form flat and export-friendly (OTel /
    /// OpenInference), and a full `enum Payload` redesign is deliberately out of
    /// scope. Because every field is `pub`, illegal combinations are
    /// *representable*; this lightweight guard makes them *detectable* at the
    /// boundaries that care (e.g. just before persisting), without changing the
    /// type.
    ///
    /// Invariants enforced:
    /// 1. **status/error coherence** — `error` is set iff `status == Error`. An
    ///    `error: Some` with a non-`Error` status drops its message on OTel
    ///    export while reading as an error to the timeline, so the two must
    ///    agree.
    /// 2. **at most one typed block** — a coherent event carries at most one of
    ///    the six domain blocks; consumers never expect (say) an `llm` and a
    ///    `finding` block on the same event.
    /// 3. **finding ⇒ Kind::Finding** — if a [`FindingBlock`] is present the
    ///    `kind` must be [`Kind::Finding`].
    ///
    /// # Errors
    /// Returns [`CoreError::InvalidEvent`](crate::error::CoreError::InvalidEvent)
    /// describing the first violated invariant.
    pub fn validate(&self) -> crate::error::Result<()> {
        match (self.status, self.error.is_some()) {
            (Status::Error, false) => {
                return Err(crate::error::CoreError::InvalidEvent(
                    "status is Error but no error message is set".to_string(),
                ));
            }
            (s, true) if s != Status::Error => {
                return Err(crate::error::CoreError::InvalidEvent(format!(
                    "error message is set but status is {} (expected error)",
                    s.as_str()
                )));
            }
            _ => {}
        }

        let block_count = [
            self.blocks.llm.is_some(),
            self.blocks.tool.is_some(),
            self.blocks.agent.is_some(),
            self.blocks.console.is_some(),
            self.blocks.network.is_some(),
            self.blocks.finding.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if block_count > 1 {
            return Err(crate::error::CoreError::InvalidEvent(format!(
                "event carries {block_count} typed blocks; expected at most one"
            )));
        }

        if self.blocks.finding.is_some() && self.kind != Kind::Finding {
            return Err(crate::error::CoreError::InvalidEvent(format!(
                "finding block requires kind=finding, got kind={}",
                self.kind.as_str()
            )));
        }

        Ok(())
    }

    /// Debug-only invariant check: in debug builds this panics if
    /// [`Event::validate`] fails; in release builds it is a no-op. Intended for
    /// cheap producer-side sanity at construction sites that always build
    /// coherent events.
    #[inline]
    pub fn debug_assert_valid(&self) {
        debug_assert!(
            self.validate().is_ok(),
            "Event failed validate(): {:?}",
            self.validate().err()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_event_has_id_and_timestamp() {
        let ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout");
        assert_eq!(ev.id.as_str().len(), 32);
        assert!(ev.timestamp.as_micros() > 0);
        assert_eq!(ev.type_, "stdout");
        // operation/name default to the type.
        assert_eq!(ev.operation, "stdout");
        assert_eq!(ev.name, "stdout");
        assert_eq!(ev.status, Status::Unset);
        assert!(ev.blocks.is_empty());
    }

    #[test]
    fn category_wire_strings_are_stable() {
        assert_eq!(Category::AppLog.as_str(), "app_log");
        assert_eq!(Category::CodeTest.as_str(), "code_test");
        assert_eq!(
            serde_json::to_value(Category::Security).unwrap(),
            serde_json::json!("security")
        );
        assert_eq!(
            serde_json::to_value(Category::Inventory).unwrap(),
            serde_json::json!("inventory")
        );
    }

    #[test]
    fn type_field_serializes_as_type() {
        let ev = Event::new(TraceId::new(), Kind::Llm, Category::Agent, "chat.completion");
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], serde_json::json!("chat.completion"));
        assert!(json.get("type_").is_none(), "must not leak the raw field name");
    }

    #[test]
    fn blocks_flatten_into_parent() {
        let ev = Event::new(TraceId::new(), Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("cargo-audit".into()),
                rule_id: Some("RUSTSEC-2024-0001".into()),
                severity: Some(Severity::High),
                ..Default::default()
            });
        let json = serde_json::to_value(&ev).unwrap();
        // `finding` should be a flattened object on the parent.
        assert_eq!(json["finding"]["source"], serde_json::json!("cargo-audit"));
        assert_eq!(json["finding"]["severity"], serde_json::json!("high"));
    }

    #[test]
    fn event_roundtrips_through_json() {
        let ev = Event::new(TraceId::new(), Kind::Network, Category::Browser, "fetch")
            .with_op("request")
            .with_name("GET /api")
            .with_status(Status::Ok)
            .with_duration_ms(12.5)
            .with_session(SessionId::new("sess-xyz"))
            .with_attr("retries", 2)
            .with_network(NetworkBlock {
                method: Some("GET".into()),
                url: Some("https://example.test/api".into()),
                status_code: Some(200),
                ..Default::default()
            });
        let json = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_string_api_is_canonical() {
        // as_str matches the serde lowercase representation.
        for s in Severity::ALL {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.as_str())
            );
            // Round-trip through the wire token.
            assert_eq!(Severity::from_wire(s.as_str()), Some(s));
            assert_eq!(s.to_string(), s.as_str());
        }
        // Case-insensitive parse, unknown -> None / Err.
        assert_eq!(Severity::from_wire("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_wire("nope"), None);
        assert!("nope".parse::<Severity>().is_err());
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
    }

    #[test]
    fn severity_rank_matches_ord() {
        // rank() agrees with the derived Ord (0..=4 ascending).
        let mut prev = None;
        for s in Severity::ALL {
            if let Some(p) = prev {
                assert!(s.rank() > p);
            }
            prev = Some(s.rank());
        }
        assert_eq!(Severity::Info.rank(), 0);
        assert_eq!(Severity::Critical.rank(), 4);
        // The min_severity filter `sev.rank() >= min.rank()` equals `sev >= min`.
        let min = Severity::Medium;
        for s in Severity::ALL {
            assert_eq!(s.rank() >= min.rank(), s >= min);
        }
    }

    #[test]
    fn kind_and_status_as_str_match_serde() {
        let kinds = [
            Kind::Log, Kind::Llm, Kind::Tool, Kind::Agent, Kind::Browser,
            Kind::Network, Kind::Finding, Kind::Test, Kind::Span, Kind::Other,
        ];
        for k in kinds {
            assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(k.as_str()));
        }
        for s in [Status::Unset, Status::Ok, Status::Error] {
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(s.as_str()));
        }
    }

    #[test]
    fn validate_accepts_coherent_events() {
        // Plain log, no blocks, Unset/no-error: valid.
        let ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout");
        assert!(ev.validate().is_ok());
        ev.debug_assert_valid();

        // Error + message: valid.
        let ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stderr")
            .with_error("boom");
        assert!(ev.validate().is_ok());

        // Finding block on a Kind::Finding event: valid.
        let ev = Event::new(TraceId::new(), Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock { severity: Some(Severity::High), ..Default::default() });
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn validate_rejects_status_error_mismatch() {
        // error set but status not Error.
        let mut ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout");
        ev.error = Some("oops".to_string());
        ev.status = Status::Ok;
        assert!(ev.validate().is_err());

        // status Error but no message.
        let mut ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout");
        ev.status = Status::Error;
        assert!(ev.validate().is_err());
    }

    #[test]
    fn validate_rejects_multiple_blocks_and_finding_kind_mismatch() {
        // Two blocks at once.
        let ev = Event::new(TraceId::new(), Kind::Llm, Category::Agent, "chat")
            .with_llm(LlmBlock::default())
            .with_finding(FindingBlock::default());
        assert!(ev.validate().is_err());

        // Finding block but wrong kind.
        let ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "line")
            .with_finding(FindingBlock::default());
        assert!(ev.validate().is_err());
    }

    #[test]
    fn empty_attributes_omitted_from_json() {
        let ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout");
        let json = serde_json::to_value(&ev).unwrap();
        assert!(json.get("attributes").is_none(), "empty attrs should be omitted");
        assert!(json.get("parent_id").is_none(), "none parent should be omitted");
    }
}
