//! Codex **structured event-stream** adapter (plan "Phase 2", Codex row —
//! `codex exec --json`). The structured-capture counterpart to the Claude Code
//! hooks tier.
//!
//! `codex exec --json` emits **one JSON object per stdout line**, a typed event
//! stream (verified live + against developers.openai.com/codex/noninteractive).
//! Unlike [`CodexAdapter`](crate::codex::CodexAdapter) (which best-effort-parses
//! a *rollout JSONL file* one record at a time), this adapter consumes the
//! **whole stream** because correlation needs state across lines: the session
//! `thread_id` (minted at `thread.started`), the current model, and the running
//! turn index that wires every tool/LLM/agent event to its turn span.
//!
//! ## Event stream → logbook [`Event`]s
//! | Stream object | Event |
//! |---|---|
//! | `thread.started` | (no event) — mints the session [`TraceId`] + stashes `thread_id` |
//! | `turn.started` | (no event) — opens a turn (advances the turn index) |
//! | `turn.completed` (`usage`) | [`Kind::Llm`] / [`Category::Agent`] — provider/model + input/output tokens; `cached_input_tokens`/`reasoning_output_tokens` as attrs |
//! | `turn.failed` (`error`) | [`Kind::Agent`] error-status event |
//! | `item.completed` `command_execution` | [`Kind::Tool`] (`shell`) — the command + `aggregated_output`, `exit_code`/`status` attrs |
//! | `item.completed` `file_change` | [`Kind::Tool`] (`file_change`) — redactable summary of `changes` + `status` |
//! | `item.completed` `mcp_tool_call` | [`Kind::Tool`] (the MCP tool name + args/result) |
//! | `item.completed` `web_search` | [`Kind::Tool`] (`web_search`) — the query |
//! | `item.completed` `agent_message` | [`Kind::Agent`] — the assistant message `text` in `output` |
//! | `item.completed` `reasoning` | [`Kind::Agent`] — the reasoning `text` in `output` |
//! | `item.completed` `error` / top-level `error` | [`Kind::Agent`] error-status event |
//!
//! Every emitted event shares the session [`TraceId`], is `.with_session(thread_id)`,
//! is parented to its turn span ([`crate::turn_span_id`]), and is stamped with
//! `harness="codex"` + the `thread_id` (`codex_thread_id` attribute) for
//! correlation. The adapter is **tolerant**: an unknown event `type`, an unknown
//! item `type`, or a malformed object is skipped (never panics, never drops the
//! rest of the stream).
//!
//! ## Redaction is sacred (plan §9)
//! As with every adapter, no payload (command, aggregated output, file-change
//! summary, MCP args/result, search query, message/reasoning text, error text)
//! reaches an [`Event`] before it is routed through the adapter's
//! [`HarnessContext`] — force-redacted (secrets floor always on) + class-capped.
//! The persistence boundary (the `logbook codex` command) only resolves the
//! [`CapturePolicy`](logbook_core::CapturePolicy) and hands it here; the adapter
//! builds already-redacted, ready-to-persist events.

use serde_json::Value;

use logbook_core::{
    truncate_with_ellipsis, AgentBlock, Category, Event, Kind, LlmBlock, SessionId, Status,
    ToolBlock, TraceId,
};

use crate::context::HarnessContext;
use crate::{class, turn_span_id};

/// The Codex `exec --json` structured-stream adapter.
///
/// Holds the session [`TraceId`] (minted at `thread.started`), the
/// [`HarnessContext`] every payload is routed through, the scrubbed
/// `harness_version`, and the interior-mutable correlation state (`thread_id`,
/// current model, running turn index) that survives across stream lines.
#[derive(Debug)]
pub struct CodexJsonAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
    /// Correlation state mutated as the stream is walked.
    state: StreamState,
}

/// Mutable per-stream correlation state. Codex streams events one line at a
/// time; a tool/LLM line carries no turn index of its own, so we track it here.
#[derive(Debug, Default)]
struct StreamState {
    /// The codex `thread_id` from `thread.started` (the session correlation id).
    thread_id: Option<String>,
    /// The current model, if a later event surfaces one (Codex's stream rarely
    /// carries it; kept `None` unless seen so the LLM block reports honestly).
    model: Option<String>,
    /// The running turn index. `thread.started` resets it to 0; each
    /// `turn.started` advances it. Tool/LLM/agent events parent to this turn.
    turn: u64,
    /// Whether at least one `turn.started` has been seen (so the first turn is
    /// index 0, not 1, even though we increment on each `turn.started`).
    turn_open: bool,
}

/// Codex/shell tool names considered mutating (mirrors
/// [`CodexAdapter`](crate::codex::CodexAdapter)). `shell` and `file_change` are
/// the structured-stream item kinds that mutate.
const WRITE_TOOLS: &[&str] = &[
    "shell", "bash", "exec", "apply_patch", "applypatch", "write", "edit", "create_file", "patch",
    "str_replace", "file_change",
];

impl CodexJsonAdapter {
    /// Stable harness name.
    pub const NAME: &'static str = "codex";
    /// `agent` label.
    pub const AGENT: &'static str = "codex";

    /// Build the adapter for a session `trace` with a redaction + policy
    /// [`HarnessContext`] and the `harness_version` stamped on each event.
    ///
    /// `harness_version` is attacker-controlled (it arrives from the harness),
    /// so it is scrubbed through the secrets floor + a length cap before being
    /// stamped on every event (redaction-before-persistence applies to metadata
    /// too).
    #[must_use]
    pub fn new(trace: TraceId, ctx: HarnessContext, harness_version: impl Into<String>) -> Self {
        let harness_version =
            ctx.scrub_metadata(&harness_version.into(), crate::HARNESS_VERSION_MAX);
        Self {
            trace,
            ctx,
            harness_version,
            state: StreamState::default(),
        }
    }

    /// Convenience: default recorder-on policy + enabled redactor.
    #[must_use]
    pub fn with_defaults(trace: TraceId, harness_version: impl Into<String>) -> Self {
        Self::new(trace, HarnessContext::with_defaults(), harness_version)
    }

    /// Parse a whole `codex exec --json` event stream (one parsed JSON object per
    /// element) into logbook [`Event`]s, in stream order.
    ///
    /// This is the **whole-stream** entry point: it threads the correlation state
    /// (`thread_id`, model, turn index) across lines so every emitted event shares
    /// the session trace, is tagged with the codex `thread_id`, and parents to its
    /// turn span. Unknown event/item `type`s and malformed objects are skipped.
    #[must_use]
    pub fn parse_stream(&mut self, events: &[Value]) -> Vec<Event> {
        let mut out = Vec::new();
        for raw in events {
            out.extend(self.parse_line(raw));
        }
        out
    }

    /// Parse one stream object, mutating correlation state and returning zero or
    /// more events. Tolerant: an unrecognized `type` yields an empty `Vec`.
    fn parse_line(&mut self, raw: &Value) -> Vec<Event> {
        let Some(ty) = raw.get("type").and_then(Value::as_str) else {
            return Vec::new();
        };
        match ty {
            "thread.started" => {
                // Session start: stash the thread_id for correlation + reset the
                // turn counter. No event of its own.
                if let Some(id) = raw.get("thread_id").and_then(Value::as_str) {
                    self.state.thread_id = Some(id.to_string());
                }
                self.state.turn = 0;
                self.state.turn_open = false;
                Vec::new()
            }
            "turn.started" => {
                // Advance the turn index (the first turn is 0; subsequent turns
                // increment). No event of its own — the turn span is anchored by
                // the events that parent to it.
                if self.state.turn_open {
                    self.state.turn += 1;
                } else {
                    self.state.turn_open = true;
                }
                Vec::new()
            }
            "turn.completed" => {
                let usage = raw.get("usage");
                vec![self.turn_completed_event(usage)]
            }
            "turn.failed" => {
                let msg = raw
                    .get("error")
                    .map(codex_error_text)
                    .unwrap_or_else(|| "codex turn failed".to_string());
                vec![self.error_event("agent.turn_failed", "turn failed", &msg)]
            }
            "item.completed" => {
                // The `item` is the structured payload; its kind is in `type`
                // (NOT `item_type`).
                match raw.get("item") {
                    Some(item) => self.item_event(item),
                    None => Vec::new(),
                }
            }
            // `item.started` carries no completed payload (the matching
            // `item.completed` does); recognized but intentionally empty.
            "item.started" => Vec::new(),
            "error" => {
                let msg = raw
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("codex error")
                    .to_string();
                vec![self.error_event("agent.error", "error", &msg)]
            }
            _ => Vec::new(),
        }
    }

    /// The current session id for `.with_session` (the codex `thread_id`), if a
    /// `thread.started` has been seen.
    fn session(&self) -> Option<SessionId> {
        self.state.thread_id.as_ref().map(SessionId::new)
    }

    /// Base event scaffold: a fresh event on the session trace, stamped with
    /// `harness`, `harness_version`, the codex `thread_id` (`codex_thread_id`),
    /// and attached to the session, plus the running `turn` attribute.
    fn base(&self, kind: Kind, type_: &str) -> Event {
        let mut ev = Event::new(self.trace, kind, Category::Agent, type_)
            .with_attr("harness", Self::NAME)
            .with_attr("harness_version", self.harness_version.clone())
            .with_attr("turn", self.state.turn);
        if let Some(id) = &self.state.thread_id {
            ev = ev.with_attr("codex_thread_id", id.clone());
        }
        if let Some(s) = self.session() {
            ev = ev.with_session(s);
        }
        ev
    }

    fn is_write_tool(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        WRITE_TOOLS.iter().any(|w| lower == *w)
    }

    // ---- turn.completed → Kind::Llm -------------------------------------

    /// Build a [`Kind::Llm`] completion event from a `turn.completed`'s `usage`.
    /// Token counts come from the standard codex usage keys; the two extra counts
    /// (`cached_input_tokens`, `reasoning_output_tokens`) are stashed as
    /// attributes since [`LlmBlock`] has no field for them.
    fn turn_completed_event(&self, usage: Option<&Value>) -> Event {
        let parent = turn_span_id(self.trace, self.state.turn);
        let get = |k: &str| usage.and_then(|u| u.get(k)).and_then(Value::as_u64);
        let input_tokens = get("input_tokens");
        let output_tokens = get("output_tokens");
        let cached = get("cached_input_tokens");
        let reasoning = get("reasoning_output_tokens");

        let llm = if self.ctx.captures(class::MODEL_METADATA) {
            LlmBlock {
                provider: Some("openai".to_string()),
                model: self.state.model.clone(),
                input_tokens,
                output_tokens,
                ..Default::default()
            }
        } else {
            LlmBlock::default()
        };

        let mut ev = self
            .base(Kind::Llm, "llm.completion")
            .with_parent(parent)
            .with_op("completion")
            .with_name(self.state.model.as_deref().unwrap_or("assistant").to_string())
            .with_status(Status::Ok)
            .with_llm(llm);
        // The two extra usage counts only when the metadata class is captured
        // (they ARE model metadata; gate them like the block).
        if self.ctx.captures(class::MODEL_METADATA) {
            if let Some(c) = cached {
                ev = ev.with_attr("cached_input_tokens", c);
            }
            if let Some(r) = reasoning {
                ev = ev.with_attr("reasoning_output_tokens", r);
            }
        }
        ev
    }

    // ---- item.completed → typed event -----------------------------------

    /// Dispatch one completed `item` on its `type` (the field is `type`, not
    /// `item_type`). Unknown item types are skipped (tolerant).
    fn item_event(&self, item: &Value) -> Vec<Event> {
        let Some(item_ty) = item.get("type").and_then(Value::as_str) else {
            return Vec::new();
        };
        let item_id = item.get("id").and_then(Value::as_str);
        match item_ty {
            "command_execution" => vec![self.command_execution_event(item, item_id)],
            "file_change" => vec![self.file_change_event(item, item_id)],
            "mcp_tool_call" => vec![self.mcp_tool_call_event(item, item_id)],
            "web_search" => vec![self.web_search_event(item, item_id)],
            "agent_message" => self.agent_message_event(item, item_id, "agent.message", "agent message"),
            "reasoning" => self.agent_message_event(item, item_id, "agent.reasoning", "reasoning"),
            "error" => {
                let msg = item
                    .get("message")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("text").and_then(Value::as_str))
                    .unwrap_or("codex item error")
                    .to_string();
                vec![self.error_event("agent.error", "error", &msg)]
            }
            _ => Vec::new(),
        }
    }

    /// A shared [`Kind::Tool`] builder: redacts `arguments` (as tool_args) and
    /// `result` (as tool_results) through the context, parents to the turn span,
    /// and stamps the item id. Mirrors the existing adapters' tool path so the
    /// redaction/capping/summary behaviour is identical.
    fn tool_event(
        &self,
        type_: &str,
        tool_name: &str,
        arguments: Option<Value>,
        result: Option<&str>,
        item_id: Option<&str>,
    ) -> Event {
        let parent = turn_span_id(self.trace, self.state.turn);
        let mut tool = ToolBlock {
            tool_name: Some(tool_name.to_string()),
            is_write: Some(Self::is_write_tool(tool_name)),
            ..Default::default()
        };

        let mut args_truncated = false;
        if let Some(args) = arguments {
            if self.ctx.captures(class::TOOL_ARGS) {
                // Force-redact + 64 KiB cap (an over-cap blob becomes a bounded
                // string), exactly like the Claude/Codex adapters.
                let (red_args, truncated) = self.ctx.redact_tool_args(&args);
                tool.arguments = Some(red_args);
                args_truncated = truncated;
            }
        }

        // Redact the result body ONCE; the summary is derived from that same
        // already-redacted+capped string (no second redaction pass).
        let redacted_result = result.and_then(|res| {
            if self.ctx.captures(class::TOOL_RESULTS) {
                Some(self.ctx.redact_text(class::TOOL_RESULTS, res))
            } else {
                None
            }
        });
        if let Some((red, _trunc)) = redacted_result.as_ref() {
            tool.result_summary = Some(truncate_with_ellipsis(red, crate::RESULT_SUMMARY_MAX));
        }

        let mut ev = self
            .base(Kind::Tool, type_)
            .with_parent(parent)
            .with_op("tool")
            .with_name(tool_name.to_string())
            .with_status(Status::Ok)
            .with_tool(tool);
        if args_truncated {
            ev = ev.with_attr("arguments_truncated", true);
        }
        if let Some(id) = item_id {
            ev = ev.with_attr("tool_call_id", id.to_string());
        }
        if let Some((red, truncated)) = redacted_result {
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        ev
    }

    /// `command_execution` → a `shell` tool call carrying the command (as
    /// arguments) + its `aggregated_output` (as result), with `exit_code`/`status`
    /// attributes.
    fn command_execution_event(&self, item: &Value, item_id: Option<&str>) -> Event {
        let command = item.get("command").and_then(Value::as_str).unwrap_or("");
        let output = item
            .get("aggregated_output")
            .and_then(Value::as_str)
            .or_else(|| item.get("output").and_then(Value::as_str));
        // Carry the command as a structured `{command: ...}` arg so it redacts +
        // caps through the tool_args path (and reads consistently with the other
        // shell-tool events).
        let args = Some(Value::String(command.to_string()));
        let mut ev = self.tool_event(
            "tool.call",
            "shell",
            args,
            output,
            item_id,
        );
        if let Some(code) = item.get("exit_code").and_then(Value::as_i64) {
            ev = ev.with_attr("exit_code", code);
            if code != 0 {
                ev.status = Status::Error;
                // A failed command: set a (redaction-safe) error marker so the
                // event reads as errored on the timeline. The output already
                // holds the redacted detail.
                ev.error = Some(format!("command exited with code {code}"));
            }
        }
        if let Some(status) = item.get("status").and_then(Value::as_str) {
            ev = ev.with_attr("command_status", status.to_string());
        }
        ev
    }

    /// `file_change` → a `file_change` tool call carrying a redactable summary of
    /// the `changes` (as arguments) + the `status`.
    fn file_change_event(&self, item: &Value, item_id: Option<&str>) -> Event {
        // `changes` describes the edits/patch; pass it through as structured
        // tool_args so it is force-redacted + capped. Codex shapes it as an array
        // or object; keep it as-is for the redactor to walk.
        let changes = item.get("changes").cloned();
        let mut ev = self.tool_event("tool.call", "file_change", changes, None, item_id);
        if let Some(status) = item.get("status").and_then(Value::as_str) {
            ev = ev.with_attr("file_change_status", status.to_string());
        }
        ev
    }

    /// `mcp_tool_call` → a tool call keyed by the MCP tool name, carrying the
    /// args + result (both redacted). The tool name is taken from `tool`/`name`
    /// (often qualified `server.tool`); falls back to `mcp_tool_call`.
    fn mcp_tool_call_event(&self, item: &Value, item_id: Option<&str>) -> Event {
        let tool_name = item
            .get("tool")
            .or_else(|| item.get("name"))
            .or_else(|| item.get("tool_name"))
            .and_then(Value::as_str)
            .unwrap_or("mcp_tool_call");
        let args = item
            .get("arguments")
            .or_else(|| item.get("args"))
            .or_else(|| item.get("input"))
            .cloned();
        let result = item
            .get("result")
            .or_else(|| item.get("output"))
            .map(codex_stringify);
        let mut ev = self.tool_event(
            "tool.call",
            tool_name,
            args,
            result.as_deref(),
            item_id,
        );
        // Tag the lane so the UI can distinguish an MCP tool call from a shell one.
        ev = ev.with_attr("tool_kind", "mcp");
        if let Some(server) = item.get("server").and_then(Value::as_str) {
            ev = ev.with_attr("mcp_server", server.to_string());
        }
        ev
    }

    /// `web_search` → a `web_search` tool call carrying the query (as arguments).
    fn web_search_event(&self, item: &Value, item_id: Option<&str>) -> Event {
        let query = item
            .get("query")
            .and_then(Value::as_str)
            .or_else(|| item.get("q").and_then(Value::as_str))
            .unwrap_or("");
        let args = Some(Value::String(query.to_string()));
        self.tool_event("tool.call", "web_search", args, None, item_id)
    }

    /// `agent_message` / `reasoning` → a [`Kind::Agent`] event carrying the
    /// (redacted) `text` as the body in `output`. Reasoning uses the same path
    /// with a distinct type/name.
    ///
    /// The text is redacted under the `prompts` class (assistant-authored model
    /// content shares the prompt-sensitivity posture); when that class is off the
    /// event is still emitted (metadata anchor) but carries no body.
    fn agent_message_event(
        &self,
        item: &Value,
        item_id: Option<&str>,
        type_: &str,
        name: &str,
    ) -> Vec<Event> {
        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
        if text.is_empty() {
            return Vec::new();
        }
        let parent = turn_span_id(self.trace, self.state.turn);
        let mut ev = self
            .base(Kind::Agent, type_)
            .with_parent(parent)
            .with_op("message")
            .with_name(name.to_string())
            .with_status(Status::Ok)
            .with_agent(AgentBlock {
                agent: Some(Self::AGENT.to_string()),
                role: Some("assistant".to_string()),
                turn: Some(self.state.turn),
                ..Default::default()
            });
        if self.ctx.captures(class::PROMPTS) {
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, text);
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        if let Some(id) = item_id {
            ev = ev.with_attr("item_id", id.to_string());
        }
        vec![ev]
    }

    /// Build a [`Kind::Agent`] error-status event from an error message
    /// (`turn.failed`, top-level `error`, or an `error` item). The message is
    /// scrubbed through the secrets floor + prompt cap before it lands on
    /// `Event::error` (it is harness-authored, attacker-influenced text).
    fn error_event(&self, type_: &str, name: &str, message: &str) -> Event {
        let parent = turn_span_id(self.trace, self.state.turn);
        // Route the error text through the prompts class so it is force-redacted
        // (secrets floor) + capped before landing on the event.
        let (red, _truncated) = self.ctx.redact_text(class::PROMPTS, message);
        self.base(Kind::Agent, type_)
            .with_parent(parent)
            .with_op("error")
            .with_name(name.to_string())
            .with_error(red)
            .with_agent(AgentBlock {
                agent: Some(Self::AGENT.to_string()),
                role: Some("assistant".to_string()),
                turn: Some(self.state.turn),
                ..Default::default()
            })
    }
}

/// Free-function whole-stream entry point requested by the plan: parse a slice of
/// parsed `codex exec --json` objects into logbook [`Event`]s with default
/// recorder-on capture + redaction. For a custom [`HarnessContext`] (e.g.
/// `--no-redact` or a narrowed [`CapturePolicy`](logbook_core::CapturePolicy)),
/// construct a [`CodexJsonAdapter`] and call [`CodexJsonAdapter::parse_stream`].
///
/// A fresh session [`TraceId`] is minted here; the codex `thread_id` from
/// `thread.started` is attached to every event (via `.with_session` + the
/// `codex_thread_id` attribute) for cross-correlation.
#[must_use]
pub fn parse_codex_json_stream(events: &[Value]) -> Vec<Event> {
    let mut adapter = CodexJsonAdapter::with_defaults(TraceId::new(), "unknown");
    adapter.parse_stream(events)
}

/// Render a codex error object/string into a single message string.
fn codex_error_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Object(map) => map
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| serde_json::to_string(value).unwrap_or_default()),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Stringify a codex value (string, array, or object) for redaction — used for
/// MCP results which may be a string, a content-block array, or an object.
fn codex_stringify(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .map(|b| {
                b.get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| serde_json::to_string(b).unwrap_or_default())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> TraceId {
        TraceId::from_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ])
    }

    fn adapter() -> CodexJsonAdapter {
        CodexJsonAdapter::with_defaults(trace(), "codex-0.40")
    }

    /// The real event lines from `codex exec --json` (a `thread.started`, a
    /// `turn.started`, a `turn.completed` with usage, an `item.completed`
    /// `command_execution`, a `file_change`, and an `agent_message`) normalize to
    /// the right Events: a `Kind::Tool` for the command (with command + output),
    /// a `Kind::Llm` with input/output tokens for `turn.completed`, a `Kind::Agent`
    /// for the message — all sharing one trace_id + the codex thread_id attribute.
    #[test]
    fn golden_codex_json_stream_normalizes_all_shapes() {
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "th_abc123" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "item_0",
                    "type": "command_execution",
                    "command": "ls -la",
                    "status": "completed",
                    "aggregated_output": "total 0\n",
                    "exit_code": 0
                }
            }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "item_1",
                    "type": "file_change",
                    "status": "completed",
                    "changes": [{ "path": "fizzbuzz.py", "kind": "add" }]
                }
            }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "item_2",
                    "type": "agent_message",
                    "text": "Created fizzbuzz.py for you."
                }
            }),
            serde_json::json!({
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 1200,
                    "cached_input_tokens": 1024,
                    "output_tokens": 88,
                    "reasoning_output_tokens": 40
                }
            }),
        ];
        let evs = a.parse_stream(&stream);
        // thread.started + turn.started emit nothing; 4 events: command, file
        // change, agent message, turn.completed.
        assert_eq!(evs.len(), 4, "got {} events", evs.len());

        // All share the session trace + the codex thread_id + session id.
        for ev in &evs {
            assert_eq!(ev.trace_id, trace());
            assert_eq!(
                ev.attributes.get("codex_thread_id").and_then(Value::as_str),
                Some("th_abc123"),
                "every event tagged with the codex thread_id"
            );
            assert_eq!(ev.session_id.as_ref().map(|s| s.as_str()), Some("th_abc123"));
            assert_eq!(ev.attributes.get("harness").and_then(Value::as_str), Some("codex"));
            assert!(ev.validate().is_ok(), "event invalid: {:?}", ev.validate().err());
        }

        // (1) command_execution → Kind::Tool, shell, command in args, output in body.
        let cmd = &evs[0];
        assert_eq!(cmd.kind, Kind::Tool);
        let t = cmd.blocks.tool.as_ref().unwrap();
        assert_eq!(t.tool_name.as_deref(), Some("shell"));
        assert_eq!(t.is_write, Some(true), "shell is a write tool");
        let args_s = serde_json::to_string(t.arguments.as_ref().unwrap()).unwrap();
        assert!(args_s.contains("ls -la"), "command not in args: {args_s}");
        assert!(cmd.output.as_ref().unwrap().as_str().unwrap().contains("total 0"));
        assert_eq!(cmd.attributes.get("exit_code").and_then(Value::as_i64), Some(0));
        assert_eq!(
            cmd.attributes.get("command_status").and_then(Value::as_str),
            Some("completed")
        );
        // Parents to turn 0 span (first turn).
        assert_eq!(cmd.parent_id, Some(turn_span_id(trace(), 0)));

        // (2) file_change → Kind::Tool, file_change tool, status attr.
        let fc = &evs[1];
        assert_eq!(fc.kind, Kind::Tool);
        assert_eq!(fc.blocks.tool.as_ref().unwrap().tool_name.as_deref(), Some("file_change"));
        assert_eq!(
            fc.attributes.get("file_change_status").and_then(Value::as_str),
            Some("completed")
        );
        let fc_args = serde_json::to_string(fc.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap()).unwrap();
        assert!(fc_args.contains("fizzbuzz.py"), "changes not carried: {fc_args}");

        // (3) agent_message → Kind::Agent, text in output.
        let msg = &evs[2];
        assert_eq!(msg.kind, Kind::Agent);
        assert_eq!(msg.blocks.agent.as_ref().unwrap().role.as_deref(), Some("assistant"));
        assert_eq!(
            msg.output.as_ref().unwrap().as_str().unwrap(),
            "Created fizzbuzz.py for you."
        );

        // (4) turn.completed → Kind::Llm with the token counts; extras as attrs.
        let llm = &evs[3];
        assert_eq!(llm.kind, Kind::Llm);
        let l = llm.blocks.llm.as_ref().unwrap();
        assert_eq!(l.provider.as_deref(), Some("openai"));
        assert_eq!(l.input_tokens, Some(1200));
        assert_eq!(l.output_tokens, Some(88));
        assert_eq!(
            llm.attributes.get("cached_input_tokens").and_then(Value::as_u64),
            Some(1024)
        );
        assert_eq!(
            llm.attributes.get("reasoning_output_tokens").and_then(Value::as_u64),
            Some(40)
        );
        assert_eq!(llm.parent_id, Some(turn_span_id(trace(), 0)));
    }

    #[test]
    fn command_execution_redacts_secret_in_command_and_output() {
        // A planted secret in the command arg AND in the aggregated output must be
        // scrubbed from both the redacted args and the redacted body/summary.
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "th_x" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "c1",
                    "type": "command_execution",
                    "command": "deploy --key AKIAIOSFODNN7EXAMPLE",
                    "status": "completed",
                    "aggregated_output": "using AKIAIOSFODNN7EXAMPLE ok",
                    "exit_code": 0
                }
            }),
        ];
        let evs = a.parse_stream(&stream);
        assert_eq!(evs.len(), 1);
        let tool = &evs[0];
        let args_s = serde_json::to_string(tool.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap()).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in args: {args_s}");
        let out = tool.output.as_ref().unwrap().as_str().unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in output: {out}");
        assert!(out.contains("REDACTED:CLOUD_KEY:"), "result not redacted: {out}");
        let summary = tool.blocks.tool.as_ref().unwrap().result_summary.as_ref().unwrap();
        assert!(!summary.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in summary: {summary}");
    }

    #[test]
    fn failed_command_marks_event_errored() {
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "c1",
                    "type": "command_execution",
                    "command": "false",
                    "status": "failed",
                    "aggregated_output": "",
                    "exit_code": 1
                }
            }),
        ];
        let evs = a.parse_stream(&stream);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].status, Status::Error);
        assert!(evs[0].error.is_some());
        assert!(evs[0].validate().is_ok());
    }

    #[test]
    fn mcp_and_web_search_items_map_to_tools() {
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "m1",
                    "type": "mcp_tool_call",
                    "tool": "github.create_issue",
                    "server": "github",
                    "arguments": { "title": "bug", "token": "AKIAIOSFODNN7EXAMPLE" },
                    "result": "issue #1 created"
                }
            }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "w1", "type": "web_search", "query": "rust serde flatten" }
            }),
        ];
        let evs = a.parse_stream(&stream);
        assert_eq!(evs.len(), 2);
        // MCP tool call.
        let mcp = &evs[0];
        assert_eq!(mcp.kind, Kind::Tool);
        assert_eq!(mcp.blocks.tool.as_ref().unwrap().tool_name.as_deref(), Some("github.create_issue"));
        assert_eq!(mcp.attributes.get("tool_kind").and_then(Value::as_str), Some("mcp"));
        assert_eq!(mcp.attributes.get("mcp_server").and_then(Value::as_str), Some("github"));
        let mcp_args = serde_json::to_string(mcp.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap()).unwrap();
        assert!(!mcp_args.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in mcp args: {mcp_args}");
        assert!(mcp.output.as_ref().unwrap().as_str().unwrap().contains("issue #1"));
        // Web search.
        let ws = &evs[1];
        assert_eq!(ws.kind, Kind::Tool);
        assert_eq!(ws.blocks.tool.as_ref().unwrap().tool_name.as_deref(), Some("web_search"));
        let ws_args = serde_json::to_string(ws.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap()).unwrap();
        assert!(ws_args.contains("rust serde flatten"), "query not carried: {ws_args}");
    }

    #[test]
    fn turn_index_advances_across_multiple_turns() {
        // Two turns: events in the second turn must parent to turn-span 1.
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({ "type": "turn.completed", "usage": { "input_tokens": 1, "output_tokens": 1 } }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "c", "type": "command_execution", "command": "echo hi", "status": "completed", "aggregated_output": "hi", "exit_code": 0 }
            }),
            serde_json::json!({ "type": "turn.completed", "usage": { "input_tokens": 2, "output_tokens": 2 } }),
        ];
        let evs = a.parse_stream(&stream);
        // turn0 llm, turn1 command, turn1 llm.
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].parent_id, Some(turn_span_id(trace(), 0)), "first turn.completed → turn 0");
        assert_eq!(evs[1].parent_id, Some(turn_span_id(trace(), 1)), "second turn command → turn 1");
        assert_eq!(evs[2].parent_id, Some(turn_span_id(trace(), 1)), "second turn.completed → turn 1");
        // turn attribute reflects the index.
        assert_eq!(evs[0].attributes.get("turn").and_then(Value::as_u64), Some(0));
        assert_eq!(evs[1].attributes.get("turn").and_then(Value::as_u64), Some(1));
    }

    #[test]
    fn unknown_event_and_item_types_are_skipped() {
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            // Unknown top-level event type.
            serde_json::json!({ "type": "thread.metadata", "foo": 1 }),
            // item.completed with an unknown item type.
            serde_json::json!({ "type": "item.completed", "item": { "id": "x", "type": "todo_list", "items": [] } }),
            // item.started carries nothing.
            serde_json::json!({ "type": "item.started", "item": { "id": "y", "type": "command_execution" } }),
            // Malformed objects (no type / not an object-ish shape).
            serde_json::json!({ "nope": true }),
            serde_json::json!("a bare string"),
        ];
        let evs = a.parse_stream(&stream);
        assert!(evs.is_empty(), "unknown/malformed lines must be skipped, got {}", evs.len());
    }

    #[test]
    fn error_events_map_to_errored_agent_events() {
        let mut a = adapter();
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({ "type": "turn.failed", "error": { "message": "model overloaded" } }),
            serde_json::json!({ "type": "error", "message": "stream aborted with key AKIAIOSFODNN7EXAMPLE" }),
        ];
        let evs = a.parse_stream(&stream);
        assert_eq!(evs.len(), 2);
        for ev in &evs {
            assert_eq!(ev.kind, Kind::Agent);
            assert_eq!(ev.status, Status::Error);
            assert!(ev.error.is_some());
            assert!(ev.validate().is_ok());
        }
        assert!(evs[0].error.as_ref().unwrap().contains("model overloaded"));
        // The secret in the top-level error message is scrubbed on the error field.
        assert!(
            !evs[1].error.as_ref().unwrap().contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked in error: {:?}",
            evs[1].error
        );
    }

    #[test]
    fn prompts_off_drops_message_body_but_keeps_event() {
        // With `prompts` capture off, an agent_message event is still emitted (turn
        // anchor) but carries no output body — metadata only.
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.prompts.capture = false;
                p
            },
            true,
        );
        let mut a = CodexJsonAdapter::new(trace(), ctx, "codex-1");
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "m", "type": "agent_message", "text": "secret plan AKIAIOSFODNN7EXAMPLE" }
            }),
        ];
        let evs = a.parse_stream(&stream);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, Kind::Agent);
        assert!(evs[0].output.is_none(), "prompts off ⇒ no message body persisted");
    }

    #[test]
    fn free_function_entry_point_mints_trace_and_tags_thread() {
        // The plan's `parse_codex_json_stream` free fn: mints a fresh trace, tags
        // every event with the codex thread_id, and redacts by default.
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "th_free" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "c", "type": "command_execution", "command": "echo AKIAIOSFODNN7EXAMPLE", "status": "completed", "aggregated_output": "ok", "exit_code": 0 }
            }),
        ];
        let evs = parse_codex_json_stream(&stream);
        assert_eq!(evs.len(), 1);
        assert!(!evs[0].trace_id.is_zero(), "a fresh trace must be minted");
        assert_eq!(
            evs[0].attributes.get("codex_thread_id").and_then(Value::as_str),
            Some("th_free")
        );
        let args_s = serde_json::to_string(evs[0].blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap()).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "default redaction must scrub the secret: {args_s}");
    }

    #[test]
    fn hostile_harness_version_is_scrubbed_and_capped() {
        let hostile = format!("c {} AKIAIOSFODNN7EXAMPLE", "p".repeat(300));
        let mut a = CodexJsonAdapter::with_defaults(trace(), hostile);
        let evs = a.parse_stream(&[
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({ "type": "turn.completed", "usage": { "input_tokens": 1, "output_tokens": 1 } }),
        ]);
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in harness_version: {v}");
        assert!(v.len() <= 64 + 3, "harness_version not capped: {} bytes", v.len());
    }
}
