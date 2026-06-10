//! Cursor adapter (plan "Phase 0", Cursor row) — the retroactive-import
//! counterpart to the live Codex/Claude adapters.
//!
//! Cursor keeps its conversations in four different on-disk layouts (old
//! `aiService.prompts`/`generations` paired arrays, workspace
//! `composer.composerData`, chat-mode `…aichat.chatdata`, and global
//! `composerData:{id}` / separate `bubbleId:{composer}:{bubble}` rows). The
//! IO-side [`CursorSource`](../../logbook_import/sources/cursor/struct.CursorSource.html)
//! flattens **all four** into one uniform **bubble-record** shape so this
//! adapter stays simple and format-agnostic; this module documents that shape
//! as the source↔adapter contract.
//!
//! ## The uniform bubble record (source↔adapter contract)
//!
//! Each element of the `records` slice [`parse_records`](CursorAdapter::parse_records)
//! consumes is a JSON object of the form:
//!
//! ```json
//! {
//!   "role":         "user" | "assistant",   // required; anything else ⇒ skip
//!   "text":         "…",                     // message body (may be absent/empty)
//!   "model":        "claude-3.5-sonnet",     // optional; assistant model name
//!   "tool_results": <any JSON>,              // optional; tool call/result payload
//!   "code_context": <any JSON>,              // optional; selected-code context
//!   "coord":        "bubbleId:cmp:bub",      // REQUIRED stable per-bubble key
//!   "turn":         3,                         // REQUIRED 0-based turn index
//!   "ts":           1700000000000000          // optional native micros timestamp
//! }
//! ```
//!
//! - `coord` is the bubble's intrinsic stable key (the `bubbleId:{cmp}:{bub}`
//!   row key for separate storage, `composerId:{i}` for inline, `aiService:{i}`
//!   for the old paired arrays). It feeds [`import_event_id`](crate::import_event_id)
//!   so a re-import reproduces byte-identical event ids.
//! - `turn` is assigned by the **source** (it owns conversation order): the
//!   adapter does not re-thread turns from `role`, it trusts the field. (The
//!   adapter still exposes a running counter for the rare record that omits it.)
//! - `ts`, when present, is the native micros timestamp; when absent the adapter
//!   stamps a deterministic `base_ts + index` and marks `imported_timestamp =
//!   "approx"` (see below).
//!
//! ## Bubble → logbook [`Event`]s
//! | Bubble | Event(s) |
//! |---|---|
//! | `role:"user"` | [`Kind::Agent`] + [`AgentBlock`] (`role:"user"`, `turn`), redacted body in `input` (`prompts` class); span = `turn_span_id(trace,turn)` |
//! | `role:"assistant"` (text) | [`Kind::Agent`] assistant message, redacted body in `output` (`prompts` class) |
//! | `role:"assistant"` (`model`) | [`Kind::Llm`] + [`LlmBlock`] (`model`, `model_metadata` class) |
//! | any bubble with `tool_results` | [`Kind::Tool`] (`is_write` from a per-tool list), redacted args + result, parented to the turn span |
//!
//! Every emitted event sets a **deterministic** `ev.id`
//! ([`import_event_id`](crate::import_event_id)`(trace, coord, role)`) and a
//! deterministic `ev.timestamp` (native `ts`, else `base_ts + index`), stamps
//! `harness="cursor"`, the scrubbed `harness_version`, `turn`, and a
//! `cursor_session_id` attribute. The adapter is **tolerant**: a bubble of an
//! unknown shape (missing/empty `role`, or carrying no body, model, or
//! tool payload) yields no event — it never panics, never drops the rest.
//!
//! ## Redaction is sacred (plan §9)
//! As with every adapter, no payload (prompt, assistant text, tool args/result,
//! model name) reaches an [`Event`] before it is routed through the adapter's
//! [`HarnessContext`] — force-redacted (secrets floor always on) + class-capped.
//! The source moves only opaque [`serde_json::Value`]s; this adapter is the sole
//! component that redacts and builds events.

use serde_json::Value;

use logbook_core::{
    truncate_with_ellipsis, AgentBlock, Category, Event, Kind, LlmBlock, MicrosTimestamp,
    SessionId, Status, ToolBlock, TraceId,
};

use crate::context::HarnessContext;
use crate::{class, import_event_id, turn_span_id};

/// Cursor tool names treated as mutating ("write") operations. Cursor's tool
/// surface is small and edit-centric; a name not on this list is read-only.
const WRITE_TOOLS: &[&str] = &[
    "edit_file",
    "edit",
    "write",
    "write_file",
    "create_file",
    "delete_file",
    "apply_patch",
    "applypatch",
    "search_replace",
    "str_replace",
    "run_terminal_cmd",
    "run_terminal_command",
    "terminal",
    "shell",
    "bash",
];

/// The Cursor retroactive-import adapter.
///
/// Holds the session [`TraceId`] every event shares, the [`HarnessContext`] each
/// payload is routed through, the scrubbed `harness_version`, the deterministic
/// timestamp base (`base_ts`) for undated bubbles, and the stable
/// `cursor_session_id` stamped on each event for correlation.
#[derive(Debug)]
pub struct CursorAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
    /// Deterministic timestamp base (the source store's `mtime`, in micros).
    /// Undated bubbles get `base_ts + record_index` so a re-import reproduces the
    /// same timestamps (never `now()`).
    base_ts: i64,
    /// The Cursor native session key (composer id / chat key), stamped on every
    /// event as `cursor_session_id` for correlation.
    cursor_session_id: String,
    /// Running turn counter for a record that omits an explicit `turn`. Advanced
    /// on each user bubble. The source normally provides `turn`, so this is only a
    /// fallback.
    fallback_turn: u64,
    /// Whether a user bubble has been seen yet (so the first fallback turn is 0).
    turn_open: bool,
}

impl CursorAdapter {
    /// The stable harness name (matches the source's `tool()` and the `tool`
    /// stamped on each `DiscoveredSession`).
    pub const NAME: &'static str = "cursor";
    /// The `agent` label stamped on agent/tool blocks.
    pub const AGENT: &'static str = "cursor";

    /// Build the adapter for a session `trace`.
    ///
    /// - `ctx` — the redaction + capture-policy context every payload is routed
    ///   through (the CLI owns its resolution).
    /// - `harness_version` — attacker-controlled metadata (the Cursor version, if
    ///   known); scrubbed through the secrets floor + a length cap before being
    ///   stamped on every event.
    /// - `cursor_session_id` — the native session key (composer id / chat key),
    ///   stamped as `cursor_session_id` for correlation.
    /// - `base_ts` — the deterministic timestamp base (the source store's `mtime`
    ///   in micros) for bubbles that carry no native `ts`.
    #[must_use]
    pub fn new(
        trace: TraceId,
        ctx: HarnessContext,
        harness_version: impl Into<String>,
        cursor_session_id: impl Into<String>,
        base_ts: i64,
    ) -> Self {
        let harness_version =
            ctx.scrub_metadata(&harness_version.into(), crate::HARNESS_VERSION_MAX);
        Self {
            trace,
            ctx,
            harness_version,
            base_ts,
            cursor_session_id: cursor_session_id.into(),
            fallback_turn: 0,
            turn_open: false,
        }
    }

    /// Convenience: default recorder-on policy + enabled redactor, a zero
    /// timestamp base, and an empty session id. Intended for tests / ad-hoc use;
    /// the CLI uses [`CursorAdapter::new`] with a real context + base.
    #[must_use]
    pub fn with_defaults(trace: TraceId) -> Self {
        Self::new(trace, HarnessContext::with_defaults(), "unknown", "", 0)
    }

    /// Parse a whole flattened Cursor bubble stream into logbook [`Event`]s, in
    /// record order.
    ///
    /// `records` is the uniform bubble-record slice the source produces (see the
    /// module docs for its shape); `_meta` is the session-level metadata Value
    /// (title/workspace/model) — currently unused here because every event field
    /// it would feed is already present per-bubble, but accepted so the seam
    /// matches the other adapters and future per-session enrichment needs no
    /// signature change.
    ///
    /// Each user bubble advances the fallback turn counter (used only when a
    /// record omits `turn`). Unknown/empty bubbles are skipped.
    #[must_use]
    pub fn parse_records(&mut self, records: &[Value], _meta: &Value) -> Vec<Event> {
        let mut out = Vec::new();
        for (index, raw) in records.iter().enumerate() {
            out.extend(self.parse_bubble(raw, index));
        }
        out
    }

    /// Parse one bubble at position `index`, returning zero or more events.
    fn parse_bubble(&mut self, raw: &Value, index: usize) -> Vec<Event> {
        let Some(role) = raw.get("role").and_then(Value::as_str) else {
            return Vec::new();
        };
        // The bubble's intrinsic stable key; without it we cannot mint a
        // deterministic id, so skip (tolerant) rather than fall back to entropy.
        let Some(coord) = raw.get("coord").and_then(Value::as_str) else {
            return Vec::new();
        };

        // Turn: trust the source's explicit `turn`; otherwise derive a running
        // index that advances on each user bubble (matching the live adapters).
        let turn = match raw.get("turn").and_then(Value::as_u64) {
            Some(t) => {
                // Keep the fallback counter loosely in sync so a later
                // turn-less record continues sensibly.
                if role == "user" {
                    self.note_user_turn();
                }
                t
            }
            None => {
                if role == "user" {
                    self.note_user_turn();
                }
                self.fallback_turn
            }
        };

        let mut out = Vec::new();
        match role {
            "user" => {
                if let Some(ev) = self.user_event(raw, coord, turn, index) {
                    out.push(ev);
                }
                // A user bubble may also carry a tool result (rare, but Cursor's
                // separate storage attaches `toolResults` to either side).
                if let Some(ev) = self.tool_event(raw, coord, turn, index) {
                    out.push(ev);
                }
            }
            "assistant" => {
                if let Some(ev) = self.assistant_message_event(raw, coord, turn, index) {
                    out.push(ev);
                }
                if let Some(ev) = self.llm_event(raw, coord, turn, index) {
                    out.push(ev);
                }
                if let Some(ev) = self.tool_event(raw, coord, turn, index) {
                    out.push(ev);
                }
            }
            // Any other role is an unknown bubble shape: skip.
            _ => {}
        }
        out
    }

    /// Advance the fallback turn counter for a user bubble (first user → 0).
    fn note_user_turn(&mut self) {
        if self.turn_open {
            self.fallback_turn += 1;
        } else {
            self.turn_open = true;
        }
    }

    /// The deterministic timestamp for the bubble at `index`: the native `ts`
    /// when present, else `base_ts + index`. Returns `(timestamp, is_approx)`.
    fn timestamp_for(&self, raw: &Value, index: usize) -> (MicrosTimestamp, bool) {
        match raw.get("ts").and_then(Value::as_i64) {
            Some(ts) => (MicrosTimestamp(ts), false),
            None => (
                MicrosTimestamp(self.base_ts.saturating_add(index as i64)),
                true,
            ),
        }
    }

    /// Base event scaffold: a fresh event on the session trace stamped with the
    /// **deterministic** id (`import_event_id(trace, coord, role)`) and timestamp,
    /// plus `harness`, `harness_version`, `turn`, the `cursor_session_id`, and the
    /// session attachment. `imported_timestamp="approx"` is stamped when the
    /// timestamp was synthesised from `base_ts + index`.
    #[allow(clippy::too_many_arguments)]
    fn base(
        &self,
        kind: Kind,
        type_: &str,
        coord: &str,
        role: &str,
        turn: u64,
        raw: &Value,
        index: usize,
    ) -> Event {
        let (timestamp, approx) = self.timestamp_for(raw, index);
        let mut ev = Event::new(self.trace, kind, Category::Agent, type_)
            .with_attr("harness", Self::NAME)
            .with_attr("harness_version", self.harness_version.clone())
            .with_attr("turn", turn)
            .with_session(SessionId::new(&self.cursor_session_id));
        // Deterministic id + timestamp are MANDATORY on the import path: never
        // leave the random `Event::new` id / `now()` timestamp.
        ev.id = import_event_id(self.trace, coord, role);
        ev.timestamp = timestamp;
        if !self.cursor_session_id.is_empty() {
            ev = ev.with_attr("cursor_session_id", self.cursor_session_id.clone());
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
    /// `input`. The event's own span id is the turn span, so tool/LLM events on
    /// the same turn parent to it. Returns `None` when the bubble carries no text
    /// (e.g. a context-only user bubble) — a body-less prompt is not emitted.
    fn user_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let text = raw.get("text").and_then(Value::as_str).unwrap_or("");
        if text.is_empty() {
            return None;
        }
        let mut ev = self
            .base(Kind::Agent, "agent.user_prompt", coord, "user", turn, raw, index)
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
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, text);
            ev.input = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("input_truncated", true);
            }
        }
        // A planted code_context (selected code) is also prompt-sensitive; carry a
        // redacted, capped form as an attribute so the intent survives without a
        // raw leak. Skipped when the prompts class is off.
        if self.ctx.captures(class::PROMPTS) {
            if let Some(ctx_val) = raw.get("code_context") {
                if !ctx_val.is_null() {
                    let red = self.ctx.redact_json(class::PROMPTS, ctx_val);
                    ev = ev.with_attr("code_context", red);
                }
            }
        }
        Some(ev)
    }

    // ---- assistant message ----------------------------------------------

    /// Build a [`Kind::Agent`] assistant-message event with the redacted body in
    /// `output`. Returns `None` when the assistant bubble carries no text (a
    /// model-only or tool-only assistant bubble still yields its own LLM/tool
    /// event via the other builders).
    fn assistant_message_event(
        &self,
        raw: &Value,
        coord: &str,
        turn: u64,
        index: usize,
    ) -> Option<Event> {
        let text = raw.get("text").and_then(Value::as_str).unwrap_or("");
        if text.is_empty() {
            return None;
        }
        let parent = turn_span_id(self.trace, turn);
        let mut ev = self
            .base(Kind::Agent, "agent.message", coord, "assistant", turn, raw, index)
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
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, text);
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        Some(ev)
    }

    // ---- assistant / llm -------------------------------------------------

    /// Build a [`Kind::Llm`] event carrying the model attribution, parented to the
    /// turn span. Returns `None` when the bubble names no model (Cursor only
    /// records a model for conversations with a stored `modelConfig`).
    fn llm_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let model = raw.get("model").and_then(Value::as_str);
        // No model ⇒ no LLM attribution to record (an empty LlmBlock would be a
        // bare, content-free row).
        let model = model.filter(|m| !m.is_empty())?;
        let parent = turn_span_id(self.trace, turn);

        // Model metadata is the one default-exported class; capture-gate it but it
        // needs no redaction (it carries no payload body). The model NAME is still
        // routed through the secrets-floor scrubber defensively.
        let llm = if self.ctx.captures(class::MODEL_METADATA) {
            let scrubbed = self
                .ctx
                .scrub_metadata(model, crate::HARNESS_VERSION_MAX);
            LlmBlock {
                model: Some(scrubbed),
                ..Default::default()
            }
        } else {
            LlmBlock::default()
        };

        let name = if self.ctx.captures(class::MODEL_METADATA) {
            self.ctx.scrub_metadata(model, crate::HARNESS_VERSION_MAX)
        } else {
            "assistant".to_string()
        };

        // The LLM event uses the role "llm" in its deterministic id so it never
        // collides with the assistant *message* event on the same coord.
        let ev = self
            .base(Kind::Llm, "llm.completion", coord, "llm", turn, raw, index)
            .with_parent(parent)
            .with_op("completion")
            .with_name(name)
            .with_status(Status::Ok)
            .with_llm(llm);
        Some(ev)
    }

    // ---- tool ------------------------------------------------------------

    /// Build a [`Kind::Tool`] event from a bubble's `tool_results`, parented to
    /// the turn span. Args + result are redacted before they land on the event.
    /// Returns `None` when the bubble carries no `tool_results`.
    fn tool_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let tool_results = raw.get("tool_results")?;
        if tool_results.is_null() {
            return None;
        }
        let parent = turn_span_id(self.trace, turn);

        // Cursor's tool payloads are loosely shaped; pull a name + structured args
        // + a stringified result defensively from common key spellings.
        let tool_name = tool_name_of(tool_results);
        let arguments = tool_args_of(tool_results);
        let result = tool_result_of(tool_results);

        let mut tool = ToolBlock {
            tool_name: Some(tool_name.clone()),
            is_write: Some(Self::is_write_tool(&tool_name)),
            ..Default::default()
        };

        let mut args_truncated = false;
        if let Some(args) = arguments {
            if self.ctx.captures(class::TOOL_ARGS) {
                // Force-redact + byte-cap (an over-cap blob becomes a bounded
                // string), exactly like the live adapters.
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

        // The tool event uses the role "tool:{n}" in its deterministic id (n =
        // the bubble's record index) so it never collides with the message/LLM
        // events on the same coord, and stays stable across re-imports.
        let role = format!("tool:{index}");
        let mut ev = self
            .base(Kind::Tool, "tool.call", coord, &role, turn, raw, index)
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
        Some(ev)
    }
}

/// Extract a tool name from a Cursor `tool_results` payload, falling back to a
/// generic `tool` label. Cursor shapes this as an object (with `name`/`tool`/…),
/// an array of such objects, or an opaque value.
fn tool_name_of(value: &Value) -> String {
    let from_obj = |obj: &Value| {
        obj.get("name")
            .or_else(|| obj.get("tool"))
            .or_else(|| obj.get("toolName"))
            .or_else(|| obj.get("tool_name"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    match value {
        Value::Object(_) => from_obj(value).unwrap_or_else(|| "tool".to_string()),
        Value::Array(arr) => arr
            .iter()
            .find_map(from_obj)
            .unwrap_or_else(|| "tool".to_string()),
        _ => "tool".to_string(),
    }
}

/// Extract structured tool arguments from a `tool_results` payload, if any. Falls
/// back to handing the whole payload to the redactor (it is structurally walked).
fn tool_args_of(value: &Value) -> Option<Value> {
    let from_obj = |obj: &Value| {
        obj.get("args")
            .or_else(|| obj.get("arguments"))
            .or_else(|| obj.get("input"))
            .or_else(|| obj.get("params"))
            .cloned()
    };
    match value {
        Value::Object(_) => from_obj(value).or_else(|| Some(value.clone())),
        Value::Array(arr) => arr.iter().find_map(from_obj).or_else(|| Some(value.clone())),
        Value::Null => None,
        other => Some(other.clone()),
    }
}

/// Extract a stringified tool result from a `tool_results` payload, for redaction
/// and the result summary. Handles the common `result`/`output`/`content` key
/// spellings and falls back to a compact serialization.
fn tool_result_of(value: &Value) -> Option<String> {
    let from_obj = |obj: &Value| {
        obj.get("result")
            .or_else(|| obj.get("output"))
            .or_else(|| obj.get("content"))
            .map(cursor_stringify)
    };
    match value {
        Value::Object(_) => from_obj(value).or_else(|| Some(cursor_stringify(value))),
        Value::Array(arr) => arr
            .iter()
            .find_map(from_obj)
            .or_else(|| Some(cursor_stringify(value))),
        Value::Null => None,
        other => Some(cursor_stringify(other)),
    }
}

/// Stringify a Cursor value (string, array of content blocks, or object) for
/// redaction — mirrors the codex/claude `stringify_result` helpers.
fn cursor_stringify(value: &Value) -> String {
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
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0x01,
        ])
    }

    fn adapter() -> CursorAdapter {
        // A fixed non-zero base so undated bubbles get deterministic timestamps.
        CursorAdapter::new(
            trace(),
            HarnessContext::with_defaults(),
            "cursor-1.5",
            "cmp_session_42",
            1_700_000_000_000_000,
        )
    }

    /// The golden fixture: a user bubble (with a planted secret), an assistant
    /// bubble (text + model), and a tool-result bubble (an `edit_file` write).
    /// Asserts exact kinds, redaction, `is_write`, parents, and the exact
    /// deterministic id + timestamp the import contract requires.
    #[test]
    fn golden_cursor_stream_normalizes_all_shapes() {
        let mut a = adapter();
        let records = vec![
            serde_json::json!({
                "role": "user",
                "text": "deploy with AKIAIOSFODNN7EXAMPLE please",
                "coord": "bubbleId:cmp:b0",
                "turn": 0,
                "ts": 1_700_000_111_000_000_i64
            }),
            serde_json::json!({
                "role": "assistant",
                "text": "Editing the file now.",
                "model": "claude-3.5-sonnet",
                "coord": "bubbleId:cmp:b1",
                "turn": 0
            }),
            serde_json::json!({
                "role": "assistant",
                "coord": "bubbleId:cmp:b2",
                "turn": 0,
                "tool_results": {
                    "name": "edit_file",
                    "args": { "path": "/app/main.rs", "new": "key=AKIAIOSFODNN7EXAMPLE" },
                    "result": "applied 1 edit using AKIAIOSFODNN7EXAMPLE"
                }
            }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        // user prompt, assistant message, assistant llm, tool call = 4 events.
        assert_eq!(evs.len(), 4, "got {} events: {evs:#?}", evs.len());

        // Common invariants: trace, session id, harness tag, deterministic id,
        // valid.
        for ev in &evs {
            assert_eq!(ev.trace_id, trace());
            assert_eq!(
                ev.session_id.as_ref().map(|s| s.as_str()),
                Some("cmp_session_42")
            );
            assert_eq!(
                ev.attributes.get("harness").and_then(Value::as_str),
                Some("cursor")
            );
            assert_eq!(ev.id.as_str().len(), 32, "deterministic 32-hex id");
            assert!(ev.validate().is_ok(), "invalid: {:?}", ev.validate().err());
        }

        // (1) user prompt → Kind::Agent, redacted in input, EXACT id + timestamp.
        let user = &evs[0];
        assert_eq!(user.kind, Kind::Agent);
        assert_eq!(user.blocks.agent.as_ref().unwrap().role.as_deref(), Some("user"));
        let input = user.input.as_ref().unwrap().as_str().unwrap();
        assert!(!input.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {input}");
        assert!(input.contains("REDACTED:CLOUD_KEY:"), "no placeholder: {input}");
        // EXACT deterministic id + timestamp (the determinism contract).
        assert_eq!(user.id, import_event_id(trace(), "bubbleId:cmp:b0", "user"));
        assert_eq!(user.timestamp, MicrosTimestamp(1_700_000_111_000_000));
        // A dated bubble is NOT marked approx.
        assert!(user.attributes.get("imported_timestamp").is_none());

        // (2) assistant message → Kind::Agent assistant, redacted output, parents
        // to turn-0 span.
        let msg = &evs[1];
        assert_eq!(msg.kind, Kind::Agent);
        assert_eq!(msg.blocks.agent.as_ref().unwrap().role.as_deref(), Some("assistant"));
        assert_eq!(msg.output.as_ref().unwrap().as_str().unwrap(), "Editing the file now.");
        assert_eq!(msg.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(msg.id, import_event_id(trace(), "bubbleId:cmp:b1", "assistant"));
        // Undated ⇒ deterministic base_ts + index (index 1) + approx marker.
        assert_eq!(msg.timestamp, MicrosTimestamp(1_700_000_000_000_001));
        assert_eq!(
            msg.attributes.get("imported_timestamp").and_then(Value::as_str),
            Some("approx")
        );

        // (3) assistant llm → Kind::Llm, model attribution, distinct id (role "llm").
        let llm = &evs[2];
        assert_eq!(llm.kind, Kind::Llm);
        assert_eq!(llm.blocks.llm.as_ref().unwrap().model.as_deref(), Some("claude-3.5-sonnet"));
        assert_eq!(llm.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(llm.id, import_event_id(trace(), "bubbleId:cmp:b1", "llm"));
        // The message + llm share a coord but have distinct ids (role disambiguates).
        assert_ne!(llm.id, msg.id);

        // (4) tool call → Kind::Tool, is_write, redacted args + result, parents to
        // turn 0.
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
        // tool id uses role "tool:{index}" (index 2 here).
        assert_eq!(tool.id, import_event_id(trace(), "bubbleId:cmp:b2", "tool:2"));
    }

    #[test]
    fn unknown_bubble_shape_is_skipped() {
        let mut a = adapter();
        let records = vec![
            // No role.
            serde_json::json!({ "text": "orphan", "coord": "x", "turn": 0 }),
            // Unknown role.
            serde_json::json!({ "role": "system", "text": "sys", "coord": "y", "turn": 0 }),
            // No coord (cannot mint a deterministic id) ⇒ skip.
            serde_json::json!({ "role": "user", "text": "no coord", "turn": 0 }),
            // User with empty text + no tool payload ⇒ nothing to emit.
            serde_json::json!({ "role": "user", "text": "", "coord": "z", "turn": 0 }),
            // Assistant with no text, no model, no tool ⇒ nothing to emit.
            serde_json::json!({ "role": "assistant", "coord": "w", "turn": 0 }),
            // Not even an object.
            serde_json::json!("a bare string"),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert!(evs.is_empty(), "unknown/empty bubbles must be skipped, got {}", evs.len());
    }

    #[test]
    fn fallback_turn_advances_on_user_bubbles_when_turn_absent() {
        // With no explicit `turn`, the adapter threads a running index that
        // advances on each user bubble; tool/assistant events parent to the
        // current turn span.
        let mut a = adapter();
        let records = vec![
            serde_json::json!({ "role": "user", "text": "first", "coord": "c0" }),
            serde_json::json!({ "role": "assistant", "text": "a0", "coord": "c1" }),
            serde_json::json!({ "role": "user", "text": "second", "coord": "c2" }),
            serde_json::json!({ "role": "assistant", "text": "a1", "coord": "c3" }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 4);
        // turn 0: first user + its assistant message.
        assert_eq!(evs[0].attributes.get("turn").and_then(Value::as_u64), Some(0));
        assert_eq!(evs[1].parent_id, Some(turn_span_id(trace(), 0)));
        // turn 1: second user + its assistant message.
        assert_eq!(evs[2].attributes.get("turn").and_then(Value::as_u64), Some(1));
        assert_eq!(evs[3].parent_id, Some(turn_span_id(trace(), 1)));
    }

    #[test]
    fn prompts_off_drops_bodies_but_keeps_events() {
        // With `prompts` capture off, the user/assistant events are still emitted
        // (turn anchors) but carry no body — metadata only.
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.prompts.capture = false;
                p
            },
            true,
        );
        let mut a = CursorAdapter::new(trace(), ctx, "v", "sess", 1000);
        let records = vec![
            serde_json::json!({ "role": "user", "text": "secret AKIAIOSFODNN7EXAMPLE", "coord": "c0", "turn": 0 }),
            serde_json::json!({ "role": "assistant", "text": "secret reply", "coord": "c1", "turn": 0 }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 2);
        assert!(evs[0].input.is_none(), "prompts off ⇒ no user body");
        assert!(evs[1].output.is_none(), "prompts off ⇒ no assistant body");
    }

    #[test]
    fn deterministic_across_reparse() {
        // Re-running the adapter over the same records reproduces byte-identical
        // events (ids + timestamps included) — the core determinism invariant the
        // CLI's double-import test depends on.
        let records = vec![
            serde_json::json!({ "role": "user", "text": "hi", "coord": "c0", "turn": 0 }),
            serde_json::json!({ "role": "assistant", "text": "yo", "model": "m", "coord": "c1", "turn": 0 }),
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
        let mut a = CursorAdapter::new(trace(), HarnessContext::with_defaults(), hostile, "s", 0);
        let evs = a.parse_records(
            &[serde_json::json!({ "role": "user", "text": "hi", "coord": "c", "turn": 0 })],
            &serde_json::json!({}),
        );
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in harness_version: {v}");
        assert!(v.len() <= 64 + 3, "harness_version not capped: {} bytes", v.len());
    }
}
