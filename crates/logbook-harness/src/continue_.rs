//! Continue adapter (plan "Phase 1", Continue row) — the retroactive-import
//! counterpart to the live Codex/Claude adapters, mirroring [`CursorAdapter`].
//!
//! The module is named `continue_` because `continue` is a Rust keyword; the
//! public type is [`ContinueAdapter`] and its name is `"continue"`.
//!
//! The Continue extension keeps each conversation in a standalone JSON file
//! (`~/.continue/sessions/*.json`) shaped
//! `{ sessionId, title, workspaceDirectory, history:[…] }`. The IO-side
//! [`ContinueSource`](../../logbook_import/sources/continue_/struct.ContinueSource.html)
//! reads that file and passes the **native `history[]` array straight through**
//! as the `records` slice, so this adapter consumes those native history items
//! directly. This module documents that shape as the source↔adapter contract.
//!
//! ## The Continue history item (source↔adapter contract)
//!
//! Each element of the `records` slice [`parse_records`](ContinueAdapter::parse_records)
//! consumes is a native Continue history item:
//!
//! ```json
//! {
//!   "message": {
//!     "role":      "user" | "assistant",       // required; anything else ⇒ skip
//!     "content":   "…" | [{ "type":"text", "text":"…" }, …],  // string OR parts
//!     "toolCalls": [ { "function": { "name": "…", "arguments": "…" } }, … ]
//!   },
//!   "toolCallStates": [ { "status":"done", "output": <any>,
//!                         "tool": { "function": { "name": "…" } } }, … ],
//!   "reasoning":     { "text": "…" },            // optional; assistant reasoning
//!   "contextItems":  [ … ]                       // optional; context (unused)
//! }
//! ```
//!
//! Continue stores **no per-message timestamp**, so every event uses the
//! deterministic `base_ts + index` fallback and is stamped
//! `imported_timestamp="approx"`. The adapter derives `coord = {sessionId}:{index}`
//! (supplied via the constructor) and threads the turn counter itself (advancing
//! on each `user` message).
//!
//! ## History item → logbook [`Event`]s
//! | History item | Event(s) |
//! |---|---|
//! | `role:"user"` | [`Kind::Agent`] + [`AgentBlock`] (`role:"user"`, `turn`), redacted body in `input` (`prompts` class); span = `turn_span_id(trace,turn)` |
//! | `role:"assistant"` (content) | [`Kind::Agent`] assistant message, redacted body in `output` (`prompts` class) |
//! | `reasoning.text` | [`Kind::Agent`] reasoning event, redacted reasoning in `output` (`prompts` class) |
//! | each `toolCalls[i]` + matching `toolCallStates` | [`Kind::Tool`] (`is_write` from a per-tool list), redacted `arguments` + result, parented to the turn span |
//!
//! Every emitted event sets a **deterministic** `ev.id`
//! ([`import_event_id`](crate::import_event_id)`(trace, coord, role)`) and a
//! deterministic `ev.timestamp` (`base_ts + index`, always `approx` since
//! Continue is undated), stamps `harness="continue"`, the scrubbed
//! `harness_version`, `turn`, and a `continue_session_id` attribute. The adapter
//! is **tolerant**: a history item missing its `message`/`role`, or carrying no
//! body, reasoning, or tool payload, yields no event — it never panics, never
//! drops the rest.
//!
//! ## Redaction is sacred (plan §9)
//! As with every adapter, no payload (prompt, assistant text, reasoning, tool
//! args/result) reaches an [`Event`] before it is routed through the adapter's
//! [`HarnessContext`] — force-redacted (secrets floor always on) + class-capped.
//! The source moves only opaque [`serde_json::Value`]s; this adapter is the sole
//! component that redacts and builds events.

use serde_json::Value;

use logbook_core::{
    truncate_with_ellipsis, AgentBlock, Category, Event, Kind, MicrosTimestamp, SessionId, Status,
    ToolBlock, TraceId,
};

use crate::context::HarnessContext;
use crate::{class, import_event_id, turn_span_id};

/// Continue tool names treated as mutating ("write") operations. A name not on
/// this list is read-only. Mirrors the Cursor adapter's small edit-centric list,
/// extended with Continue's built-in edit/terminal tools.
const WRITE_TOOLS: &[&str] = &[
    "edit_file",
    "edit",
    "edit_existing_file",
    "create_new_file",
    "write",
    "write_file",
    "create_file",
    "delete_file",
    "apply_patch",
    "applypatch",
    "search_replace",
    "str_replace",
    "run_terminal_command",
    "run_terminal_cmd",
    "runterminalcommand",
    "terminal",
    "shell",
    "bash",
];

/// The Continue retroactive-import adapter.
///
/// Holds the session [`TraceId`] every event shares, the [`HarnessContext`] each
/// payload is routed through, the scrubbed `harness_version`, the deterministic
/// timestamp base (`base_ts`, the source file's `mtime`), and the native
/// `continue_session_id` stamped on each event for correlation.
#[derive(Debug)]
pub struct ContinueAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
    /// Deterministic timestamp base (the source file's `mtime`, in micros).
    /// Continue is undated, so every history item gets `base_ts + record_index`
    /// and is stamped `imported_timestamp="approx"` (never `now()`).
    base_ts: i64,
    /// The Continue native session id (the file's `sessionId`), stamped on every
    /// event as `continue_session_id` and used as the `coord` prefix.
    continue_session_id: String,
    /// Running turn counter, advanced on each user message.
    turn: u64,
    /// Whether a user message has been seen yet (so the first turn is 0).
    turn_open: bool,
}

impl ContinueAdapter {
    /// The stable harness name (matches the source's `tool()` and the `tool`
    /// stamped on each `DiscoveredSession`).
    pub const NAME: &'static str = "continue";
    /// The `agent` label stamped on agent/tool blocks.
    pub const AGENT: &'static str = "continue";

    /// Build the adapter for a session `trace`.
    ///
    /// - `ctx` — the redaction + capture-policy context every payload is routed
    ///   through (the CLI owns its resolution).
    /// - `harness_version` — attacker-controlled metadata (the Continue version,
    ///   if known); scrubbed through the secrets floor + a length cap before
    ///   being stamped on every event.
    /// - `continue_session_id` — the native `sessionId`, stamped as
    ///   `continue_session_id` and used as the `coord` prefix.
    /// - `base_ts` — the deterministic timestamp base (the source file's `mtime`
    ///   in micros); Continue records no per-message timestamp.
    #[must_use]
    pub fn new(
        trace: TraceId,
        ctx: HarnessContext,
        harness_version: impl Into<String>,
        continue_session_id: impl Into<String>,
        base_ts: i64,
    ) -> Self {
        let harness_version =
            ctx.scrub_metadata(&harness_version.into(), crate::HARNESS_VERSION_MAX);
        Self {
            trace,
            ctx,
            harness_version,
            base_ts,
            continue_session_id: continue_session_id.into(),
            turn: 0,
            turn_open: false,
        }
    }

    /// Convenience: default recorder-on policy + enabled redactor, a zero
    /// timestamp base, and an empty session id. Intended for tests / ad-hoc use;
    /// the CLI uses [`ContinueAdapter::new`] with a real context + base.
    #[must_use]
    pub fn with_defaults(trace: TraceId) -> Self {
        Self::new(trace, HarnessContext::with_defaults(), "unknown", "", 0)
    }

    /// Parse a whole Continue `history[]` stream into logbook [`Event`]s, in
    /// record order.
    ///
    /// `records` is the native history slice the source produces (see the module
    /// docs for its shape); `_meta` is the session-level metadata Value
    /// (title/workspace/session id) — currently unused here because the session
    /// id arrives via the constructor and every other field is present
    /// per-item, but accepted so the seam matches the other adapters.
    ///
    /// Each user message advances the turn counter. Unknown/empty items are
    /// skipped.
    #[must_use]
    pub fn parse_records(&mut self, records: &[Value], _meta: &Value) -> Vec<Event> {
        let mut out = Vec::new();
        for (index, raw) in records.iter().enumerate() {
            out.extend(self.parse_item(raw, index));
        }
        out
    }

    /// Parse one history item at position `index`, returning zero or more events.
    fn parse_item(&mut self, raw: &Value, index: usize) -> Vec<Event> {
        // The message envelope is mandatory; an item without one (or without a
        // role) is an unknown shape ⇒ skip (tolerant).
        let Some(message) = raw.get("message") else {
            return Vec::new();
        };
        let Some(role) = message.get("role").and_then(Value::as_str) else {
            return Vec::new();
        };
        let coord = format!("{}:{index}", self.continue_session_id);

        let mut out = Vec::new();
        match role {
            "user" => {
                self.note_user_turn();
                let turn = self.turn;
                if let Some(ev) = self.user_event(message, &coord, turn, index) {
                    out.push(ev);
                }
            }
            "assistant" => {
                let turn = self.turn;
                if let Some(ev) = self.assistant_message_event(message, &coord, turn, index) {
                    out.push(ev);
                }
                if let Some(ev) = self.reasoning_event(raw, &coord, turn, index) {
                    out.push(ev);
                }
                out.extend(self.tool_events(message, raw, &coord, turn, index));
            }
            // Any other role is an unknown item shape: skip.
            _ => {}
        }
        out
    }

    /// Advance the turn counter for a user message (first user → 0).
    fn note_user_turn(&mut self) {
        if self.turn_open {
            self.turn += 1;
        } else {
            self.turn_open = true;
        }
    }

    /// The deterministic timestamp for the item at `index`. Continue is undated,
    /// so this is always `base_ts + index` and always `approx`. (The signature
    /// returns `(ts, is_approx)` to mirror the dated adapters.)
    fn timestamp_for(&self, index: usize) -> (MicrosTimestamp, bool) {
        (
            MicrosTimestamp(self.base_ts.saturating_add(index as i64)),
            true,
        )
    }

    /// Base event scaffold: a fresh event on the session trace stamped with the
    /// **deterministic** id (`import_event_id(trace, coord, role)`) and timestamp,
    /// plus `harness`, `harness_version`, `turn`, the `continue_session_id`, and
    /// the session attachment. `imported_timestamp="approx"` is always stamped
    /// (Continue is undated).
    fn base(&self, kind: Kind, type_: &str, coord: &str, role: &str, turn: u64, index: usize) -> Event {
        let (timestamp, approx) = self.timestamp_for(index);
        let mut ev = Event::new(self.trace, kind, Category::Agent, type_)
            .with_attr("harness", Self::NAME)
            .with_attr("harness_version", self.harness_version.clone())
            .with_attr("turn", turn)
            .with_session(SessionId::new(&self.continue_session_id));
        // Deterministic id + timestamp are MANDATORY on the import path: never
        // leave the random `Event::new` id / `now()` timestamp.
        ev.id = import_event_id(self.trace, coord, role);
        ev.timestamp = timestamp;
        if !self.continue_session_id.is_empty() {
            ev = ev.with_attr("continue_session_id", self.continue_session_id.clone());
        }
        if approx {
            ev = ev.with_attr("imported_timestamp", "approx");
        }
        ev
    }

    /// Whether a tool name looks like a mutating operation.
    fn is_write_tool(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        WRITE_TOOLS.iter().any(|w| lower == *w)
    }

    // ---- user prompt -----------------------------------------------------

    /// Build a [`Kind::Agent`] user-prompt event with the redacted body in
    /// `input`. The event's own span id is the turn span. Returns `None` when the
    /// message carries no content.
    fn user_event(&self, message: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let text = message_content(message);
        if text.is_empty() {
            return None;
        }
        let mut ev = self
            .base(Kind::Agent, "agent.user_prompt", coord, "user", turn, index)
            .with_op("prompt")
            .with_name("user prompt")
            .with_status(Status::Ok)
            .with_agent(AgentBlock {
                agent: Some(Self::AGENT.to_string()),
                role: Some("user".to_string()),
                turn: Some(turn),
                ..Default::default()
            });
        if self.ctx.captures(class::PROMPTS) {
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, &text);
            ev.input = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("input_truncated", true);
            }
        }
        Some(ev)
    }

    // ---- assistant message ----------------------------------------------

    /// Build a [`Kind::Agent`] assistant-message event with the redacted body in
    /// `output`, parented to the turn span. Returns `None` when the assistant
    /// message carries no content (a tool-only or reasoning-only assistant item
    /// still yields its own events via the other builders).
    fn assistant_message_event(
        &self,
        message: &Value,
        coord: &str,
        turn: u64,
        index: usize,
    ) -> Option<Event> {
        let text = message_content(message);
        if text.is_empty() {
            return None;
        }
        let parent = turn_span_id(self.trace, turn);
        let mut ev = self
            .base(Kind::Agent, "agent.message", coord, "assistant", turn, index)
            .with_parent(parent)
            .with_op("message")
            .with_name("assistant message")
            .with_status(Status::Ok)
            .with_agent(AgentBlock {
                agent: Some(Self::AGENT.to_string()),
                role: Some("assistant".to_string()),
                turn: Some(turn),
                ..Default::default()
            });
        if self.ctx.captures(class::PROMPTS) {
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, &text);
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        Some(ev)
    }

    // ---- assistant / reasoning ------------------------------------------

    /// Build a [`Kind::Agent`] reasoning event from a history item's
    /// `reasoning.text`, parented to the turn span. Reasoning is prompt-sensitive,
    /// so the redacted text lands in `output` under the `prompts` class. Returns
    /// `None` when the item carries no (non-empty) reasoning text.
    fn reasoning_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let text = raw
            .get("reasoning")
            .and_then(|r| r.get("text"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if text.is_empty() {
            return None;
        }
        let parent = turn_span_id(self.trace, turn);
        let mut ev = self
            .base(Kind::Agent, "agent.reasoning", coord, "reasoning", turn, index)
            .with_parent(parent)
            .with_op("reasoning")
            .with_name("assistant reasoning")
            .with_status(Status::Ok)
            .with_agent(AgentBlock {
                agent: Some(Self::AGENT.to_string()),
                role: Some("assistant".to_string()),
                turn: Some(turn),
                ..Default::default()
            });
        if self.ctx.captures(class::PROMPTS) {
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, text);
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        Some(ev)
    }

    // ---- tools -----------------------------------------------------------

    /// Build one [`Kind::Tool`] event per `message.toolCalls[i]`, parented to the
    /// turn span. Each tool's result is looked up in the item's `toolCallStates`
    /// (the entry whose `status=="done"`), matched by tool-call id when present
    /// else positionally. Args + result are redacted before they land on the
    /// event. Returns an empty `Vec` when the message has no tool calls.
    fn tool_events(
        &self,
        message: &Value,
        raw: &Value,
        coord: &str,
        turn: u64,
        index: usize,
    ) -> Vec<Event> {
        let Some(calls) = message.get("toolCalls").and_then(Value::as_array) else {
            return Vec::new();
        };
        let states = raw
            .get("toolCallStates")
            .and_then(Value::as_array)
            .map(Vec::as_slice);
        let parent = turn_span_id(self.trace, turn);

        let mut out = Vec::new();
        for (call_idx, call) in calls.iter().enumerate() {
            let tool_name = tool_call_name(call);
            let arguments = tool_call_arguments(call);
            let result = matching_tool_result(call, states, call_idx);

            let mut tool = ToolBlock {
                tool_name: Some(tool_name.clone()),
                is_write: Some(Self::is_write_tool(&tool_name)),
                ..Default::default()
            };

            let mut args_truncated = false;
            if let Some(args) = arguments {
                if self.ctx.captures(class::TOOL_ARGS) {
                    let (red_args, truncated) = self.ctx.redact_tool_args(&args);
                    tool.arguments = Some(red_args);
                    args_truncated = truncated;
                }
            }

            // Redact the result body ONCE; the summary derives from that same
            // already-redacted+capped string (no second redaction pass).
            let redacted_result = result.and_then(|res| {
                if self.ctx.captures(class::TOOL_RESULTS) {
                    Some(self.ctx.redact_text(class::TOOL_RESULTS, &res))
                } else {
                    None
                }
            });
            if let Some((red, _trunc)) = redacted_result.as_ref() {
                tool.result_summary = Some(truncate_with_ellipsis(red, crate::RESULT_SUMMARY_MAX));
            }

            // The tool event uses the role "tool:{call_idx}" in its deterministic
            // id so multiple tool calls on the same history item never collide and
            // stay stable across re-imports.
            let role = format!("tool:{call_idx}");
            let mut ev = self
                .base(Kind::Tool, "tool.call", coord, &role, turn, index)
                .with_parent(parent)
                .with_op("tool")
                .with_name(tool_name)
                .with_status(Status::Ok)
                .with_tool(tool);
            if args_truncated {
                ev = ev.with_attr("arguments_truncated", true);
            }
            if let Some((red, truncated)) = redacted_result {
                ev.output = Some(Value::String(red));
                if truncated {
                    ev = ev.with_attr("output_truncated", true);
                }
            }
            out.push(ev);
        }
        out
    }
}

/// Extract a Continue `message.content` as a plain string. Continue stores
/// `content` as either a string or an array of `{type:"text", text:"…"}` parts;
/// the array form concatenates the text of the `text`-typed parts (matching the
/// reference extractor).
fn message_content(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Extract a tool name from a Continue `toolCalls[i]` entry. Continue shapes a
/// tool call as `{ id, type:"function", function:{ name, arguments } }`; fall
/// back to common flat spellings and a generic `tool` label.
fn tool_call_name(call: &Value) -> String {
    call.get("function")
        .and_then(|f| f.get("name"))
        .and_then(Value::as_str)
        .or_else(|| call.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| "tool".to_string())
}

/// Extract structured tool arguments from a Continue `toolCalls[i]` entry.
/// Continue stores `function.arguments` as a JSON **string**; parse it to a
/// structured value when possible (so the redactor walks it field-by-field),
/// else carry the raw string. Falls back to a flat `arguments`/`args` key.
fn tool_call_arguments(call: &Value) -> Option<Value> {
    let raw = call
        .get("function")
        .and_then(|f| f.get("arguments"))
        .or_else(|| call.get("arguments"))
        .or_else(|| call.get("args"))?;
    match raw {
        Value::String(s) => Some(
            serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.clone())),
        ),
        other => Some(other.clone()),
    }
}

/// Find the result string for a tool call among the item's `toolCallStates`.
///
/// Matches the state whose `status=="done"` to the call by tool-call id
/// (`state.toolCallId == call.id`) when both are present, else positionally
/// (`call_idx`). Returns the stringified `output` of the matched state, or
/// `None` when there is no done state with output.
fn matching_tool_result(call: &Value, states: Option<&[Value]>, call_idx: usize) -> Option<String> {
    let states = states?;
    let call_id = call.get("id").and_then(Value::as_str);

    // Prefer an id match among the done states.
    if let Some(id) = call_id {
        if let Some(state) = states.iter().find(|s| {
            s.get("status").and_then(Value::as_str) == Some("done")
                && tool_call_state_id(s) == Some(id)
        }) {
            return state.get("output").map(stringify_result);
        }
    }

    // Else fall back to the done state at the same position.
    let done: Vec<&Value> = states
        .iter()
        .filter(|s| s.get("status").and_then(Value::as_str) == Some("done"))
        .collect();
    done.get(call_idx)
        .and_then(|s| s.get("output"))
        .map(stringify_result)
}

/// The tool-call id a `toolCallStates` entry refers to, from its common
/// spellings (`toolCallId`, or nested `toolCall.id`).
fn tool_call_state_id(state: &Value) -> Option<&str> {
    state
        .get("toolCallId")
        .and_then(Value::as_str)
        .or_else(|| state.get("toolCall").and_then(|t| t.get("id")).and_then(Value::as_str))
}

/// Stringify a Continue tool-call `output` for redaction + the result summary.
/// Continue's `output` is commonly an array of `{content}` / `{text}` context
/// items; handle string, array, and object forms, falling back to a compact
/// serialization.
fn stringify_result(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .map(|item| {
                item.get("content")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("text").and_then(Value::as_str))
                    .map(str::to_string)
                    .unwrap_or_else(|| serde_json::to_string(item).unwrap_or_default())
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
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x03,
        ])
    }

    fn adapter() -> ContinueAdapter {
        ContinueAdapter::new(
            trace(),
            HarnessContext::with_defaults(),
            "continue-0.9",
            "sess-c1",
            1_700_000_000_000_000,
        )
    }

    /// The golden fixture: a user item (planted secret, **array** content form),
    /// an assistant item carrying content + reasoning + a tool call whose result
    /// is in `toolCallStates`. Asserts exact kinds, redaction, `is_write`,
    /// parents, the **no-timestamp `base_ts+index` + approx** path, and the exact
    /// deterministic id the import contract requires.
    #[test]
    fn golden_continue_stream_normalizes_all_shapes() {
        let mut a = adapter();
        let records = vec![
            serde_json::json!({
                "message": {
                    "role": "user",
                    // Array content form (Continue stores either string or parts).
                    "content": [
                        { "type": "text", "text": "deploy with AKIAIOSFODNN7EXAMPLE" },
                        { "type": "text", "text": "thanks" }
                    ]
                }
            }),
            serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": "Editing the file now.",
                    "toolCalls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "edit_file",
                                "arguments": "{\"path\":\"/app/main.rs\",\"new\":\"key=AKIAIOSFODNN7EXAMPLE\"}"
                            }
                        }
                    ]
                },
                "reasoning": { "text": "I will edit using AKIAIOSFODNN7EXAMPLE." },
                "toolCallStates": [
                    {
                        "status": "done",
                        "toolCallId": "call-1",
                        "tool": { "function": { "name": "edit_file" } },
                        "output": "applied 1 edit using AKIAIOSFODNN7EXAMPLE"
                    }
                ]
            }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        // user prompt, assistant message, reasoning, tool = 4 events.
        assert_eq!(evs.len(), 4, "got {} events: {evs:#?}", evs.len());

        // Common invariants: trace, session id, harness tag, deterministic id,
        // and (Continue) the approx-timestamp marker on EVERY event.
        for ev in &evs {
            assert_eq!(ev.trace_id, trace());
            assert_eq!(ev.session_id.as_ref().map(|s| s.as_str()), Some("sess-c1"));
            assert_eq!(
                ev.attributes.get("harness").and_then(Value::as_str),
                Some("continue")
            );
            assert_eq!(ev.id.as_str().len(), 32, "deterministic 32-hex id");
            assert_eq!(
                ev.attributes.get("imported_timestamp").and_then(Value::as_str),
                Some("approx"),
                "Continue is undated ⇒ every event is approx"
            );
            assert!(ev.validate().is_ok(), "invalid: {:?}", ev.validate().err());
        }

        // (1) user prompt → Kind::Agent, redacted in input (array content joined),
        // EXACT id, base_ts+index timestamp (index 0).
        let user = &evs[0];
        assert_eq!(user.kind, Kind::Agent);
        assert_eq!(user.blocks.agent.as_ref().unwrap().role.as_deref(), Some("user"));
        let input = user.input.as_ref().unwrap().as_str().unwrap();
        assert!(!input.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {input}");
        assert!(input.contains("REDACTED:CLOUD_KEY:"), "no placeholder: {input}");
        assert!(input.contains("thanks"), "second content part lost: {input}");
        assert_eq!(user.id, import_event_id(trace(), "sess-c1:0", "user"));
        assert_eq!(user.timestamp, MicrosTimestamp(1_700_000_000_000_000));

        // (2) assistant message → Kind::Agent assistant, redacted output, parents
        // to turn-0 span, base_ts+index (index 1).
        let msg = &evs[1];
        assert_eq!(msg.kind, Kind::Agent);
        assert_eq!(msg.type_, "agent.message");
        assert_eq!(msg.output.as_ref().unwrap().as_str().unwrap(), "Editing the file now.");
        assert_eq!(msg.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(msg.id, import_event_id(trace(), "sess-c1:1", "assistant"));
        assert_eq!(msg.timestamp, MicrosTimestamp(1_700_000_000_000_001));

        // (3) reasoning → Kind::Agent reasoning, redacted, distinct id.
        let reasoning = &evs[2];
        assert_eq!(reasoning.type_, "agent.reasoning");
        let rtext = reasoning.output.as_ref().unwrap().as_str().unwrap();
        assert!(!rtext.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in reasoning: {rtext}");
        assert_eq!(reasoning.id, import_event_id(trace(), "sess-c1:1", "reasoning"));

        // (4) tool call → Kind::Tool, is_write, redacted args + result, parents to
        // turn 0, role "tool:0".
        let tool = &evs[3];
        assert_eq!(tool.kind, Kind::Tool);
        let tb = tool.blocks.tool.as_ref().unwrap();
        assert_eq!(tb.tool_name.as_deref(), Some("edit_file"));
        assert_eq!(tb.is_write, Some(true), "edit_file is a write tool");
        let args_s = serde_json::to_string(tb.arguments.as_ref().unwrap()).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in args: {args_s}");
        assert!(args_s.contains("/app/main.rs"), "non-secret arg lost: {args_s}");
        let out = tool.output.as_ref().unwrap().as_str().unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in result: {out}");
        let summary = tb.result_summary.as_ref().unwrap();
        assert!(!summary.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in summary: {summary}");
        assert_eq!(tool.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(tool.id, import_event_id(trace(), "sess-c1:1", "tool:0"));
    }

    #[test]
    fn string_content_form_is_handled() {
        // The string content form (vs the array form in the golden) is handled.
        let mut a = adapter();
        let records = vec![serde_json::json!({
            "message": { "role": "user", "content": "just a plain string" }
        })];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].input.as_ref().unwrap().as_str().unwrap(), "just a plain string");
    }

    #[test]
    fn unknown_item_shape_is_skipped() {
        let mut a = adapter();
        let records = vec![
            // No message envelope.
            serde_json::json!({ "reasoning": { "text": "orphan" } }),
            // No role.
            serde_json::json!({ "message": { "content": "x" } }),
            // Unknown role.
            serde_json::json!({ "message": { "role": "system", "content": "sys" } }),
            // User with empty content ⇒ nothing to emit.
            serde_json::json!({ "message": { "role": "user", "content": "" } }),
            // Assistant with no content, reasoning, or tools ⇒ nothing.
            serde_json::json!({ "message": { "role": "assistant" } }),
            // Not even an object.
            serde_json::json!("a bare string"),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert!(evs.is_empty(), "unknown/empty items must be skipped, got {}", evs.len());
    }

    #[test]
    fn turn_advances_on_user_messages() {
        let mut a = adapter();
        let records = vec![
            serde_json::json!({ "message": { "role": "user", "content": "first" } }),
            serde_json::json!({ "message": { "role": "assistant", "content": "a0" } }),
            serde_json::json!({ "message": { "role": "user", "content": "second" } }),
            serde_json::json!({ "message": { "role": "assistant", "content": "a1" } }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 4);
        assert_eq!(evs[0].attributes.get("turn").and_then(Value::as_u64), Some(0));
        assert_eq!(evs[1].parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(evs[2].attributes.get("turn").and_then(Value::as_u64), Some(1));
        assert_eq!(evs[3].parent_id, Some(turn_span_id(trace(), 1)));
    }

    #[test]
    fn multiple_tool_calls_get_distinct_ids_and_positional_results() {
        // Two tool calls on one assistant item, results matched positionally
        // among the done states. Distinct deterministic ids (tool:0 / tool:1).
        let mut a = adapter();
        let records = vec![serde_json::json!({
            "message": {
                "role": "assistant",
                "toolCalls": [
                    { "function": { "name": "read_file", "arguments": "{\"path\":\"a.txt\"}" } },
                    { "function": { "name": "edit_file", "arguments": "{\"path\":\"b.txt\"}" } }
                ]
            },
            "toolCallStates": [
                { "status": "done", "output": "contents of a" },
                { "status": "done", "output": "edited b" }
            ]
        })];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 2, "two tool events");
        assert_eq!(evs[0].blocks.tool.as_ref().unwrap().tool_name.as_deref(), Some("read_file"));
        assert_eq!(evs[0].blocks.tool.as_ref().unwrap().is_write, Some(false));
        assert_eq!(evs[0].output.as_ref().unwrap().as_str().unwrap(), "contents of a");
        assert_eq!(evs[0].id, import_event_id(trace(), "sess-c1:0", "tool:0"));
        assert_eq!(evs[1].blocks.tool.as_ref().unwrap().tool_name.as_deref(), Some("edit_file"));
        assert_eq!(evs[1].blocks.tool.as_ref().unwrap().is_write, Some(true));
        assert_eq!(evs[1].output.as_ref().unwrap().as_str().unwrap(), "edited b");
        assert_eq!(evs[1].id, import_event_id(trace(), "sess-c1:0", "tool:1"));
    }

    #[test]
    fn pending_tool_state_yields_no_result() {
        // A toolCallState that is not "done" must not contribute a result.
        let mut a = adapter();
        let records = vec![serde_json::json!({
            "message": {
                "role": "assistant",
                "toolCalls": [ { "id": "c1", "function": { "name": "read_file", "arguments": "{}" } } ]
            },
            "toolCallStates": [ { "status": "generating", "toolCallId": "c1" } ]
        })];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 1);
        assert!(evs[0].output.is_none(), "non-done state ⇒ no result body");
        assert!(evs[0].blocks.tool.as_ref().unwrap().result_summary.is_none());
    }

    #[test]
    fn prompts_off_drops_bodies_but_keeps_events() {
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.prompts.capture = false;
                p
            },
            true,
        );
        let mut a = ContinueAdapter::new(trace(), ctx, "v", "s", 1000);
        let records = vec![
            serde_json::json!({ "message": { "role": "user", "content": "secret AKIAIOSFODNN7EXAMPLE" } }),
            serde_json::json!({ "message": { "role": "assistant", "content": "secret reply" }, "reasoning": { "text": "secret think" } }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        // user prompt + assistant message + reasoning = 3 events.
        assert_eq!(evs.len(), 3);
        assert!(evs[0].input.is_none(), "prompts off ⇒ no user body");
        assert!(evs[1].output.is_none(), "prompts off ⇒ no assistant body");
        assert!(evs[2].output.is_none(), "prompts off ⇒ no reasoning body");
    }

    #[test]
    fn deterministic_across_reparse() {
        let records = vec![
            serde_json::json!({ "message": { "role": "user", "content": "hi" } }),
            serde_json::json!({ "message": { "role": "assistant", "content": "yo" } }),
        ];
        let mut a1 = adapter();
        let mut a2 = adapter();
        let e1 = a1.parse_records(&records, &serde_json::json!({}));
        let e2 = a2.parse_records(&records, &serde_json::json!({}));
        assert_eq!(e1, e2, "re-parse must be byte-identical");
    }

    #[test]
    fn hostile_harness_version_is_scrubbed_and_capped() {
        let hostile = format!("c {} AKIAIOSFODNN7EXAMPLE", "p".repeat(300));
        let mut a = ContinueAdapter::new(trace(), HarnessContext::with_defaults(), hostile, "s", 0);
        let evs = a.parse_records(
            &[serde_json::json!({ "message": { "role": "user", "content": "hi" } })],
            &serde_json::json!({}),
        );
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in harness_version: {v}");
        assert!(v.len() <= 64 + 3, "harness_version not capped: {} bytes", v.len());
    }
}
