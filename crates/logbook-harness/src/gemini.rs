//! Gemini CLI adapter (plan "Phase 1", Gemini row) — the retroactive-import
//! counterpart to the live Codex/Claude adapters, mirroring [`CursorAdapter`].
//!
//! The Gemini CLI keeps each conversation in a single JSON file
//! (`~/.gemini/tmp/{project_hash}/chats/session-*.json`) shaped
//! `{ sessionId, projectHash, startTime, lastUpdated, messages:[…] }`. The
//! IO-side [`GeminiSource`](../../logbook_import/sources/gemini/struct.GeminiSource.html)
//! reads that file and passes the **native `messages[]` array straight through**
//! as the `records` slice (Gemini's on-disk message shape is already close to
//! what we want), so this adapter consumes those native records directly. This
//! module documents that shape as the source↔adapter contract.
//!
//! ## The Gemini message record (source↔adapter contract)
//!
//! Each element of the `records` slice [`parse_records`](GeminiAdapter::parse_records)
//! consumes is a native Gemini message object:
//!
//! ```json
//! {
//!   "type":      "user" | "gemini",          // required; anything else ⇒ skip
//!   "content":   "…",                          // message body (may be absent/empty)
//!   "timestamp": 1700000000000,                // optional native millis timestamp
//!   "model":     "gemini-2.0-flash",          // optional; assistant model name
//!   "thoughts":  "…" | [{ "text": "…" }, …],  // optional; assistant reasoning
//!   "tokens":    { "input": 12, "output": 34 } // optional; token usage object
//! }
//! ```
//!
//! Unlike Cursor's flattened bubble record, the source does **not** synthesise a
//! `coord`/`turn`/`role`; the adapter derives them from the message `type` and
//! the record index (`coord = {sessionId}:{index}`, supplied via
//! `session_meta`), and threads the turn counter itself (advancing on each
//! `user` message, exactly like the live adapters).
//!
//! ## Message → logbook [`Event`]s
//! | Message | Event(s) |
//! |---|---|
//! | `type:"user"` | [`Kind::Agent`] + [`AgentBlock`] (`role:"user"`, `turn`), redacted body in `input` (`prompts` class); span = `turn_span_id(trace,turn)` |
//! | `type:"gemini"` (content) | [`Kind::Agent`] assistant message, redacted body in `output` (`prompts` class) |
//! | `type:"gemini"` (`thoughts`) | [`Kind::Agent`] reasoning event, redacted thoughts in `output` (`prompts` class) |
//! | `type:"gemini"` (`model`/`tokens`) | [`Kind::Llm`] + [`LlmBlock`] (`model`, token counts, `model_metadata` class) |
//!
//! Every emitted event sets a **deterministic** `ev.id`
//! ([`import_event_id`](crate::import_event_id)`(trace, coord, role)`) and a
//! deterministic `ev.timestamp` — the **native `timestamp`** when present
//! (preserved exactly, in micros), else `base_ts + index` with
//! `imported_timestamp="approx"`. It also stamps `harness="gemini"`, the
//! scrubbed `harness_version`, `turn`, and a `gemini_session_id` attribute. The
//! adapter is **tolerant**: a message of an unknown `type`, or a `gemini`
//! message carrying no content, thoughts, model, or tokens, yields no event — it
//! never panics, never drops the rest.
//!
//! ## Redaction is sacred (plan §9)
//! As with every adapter, no payload (prompt, assistant text, reasoning, model
//! name) reaches an [`Event`] before it is routed through the adapter's
//! [`HarnessContext`] — force-redacted (secrets floor always on) + class-capped.
//! The source moves only opaque [`serde_json::Value`]s; this adapter is the sole
//! component that redacts and builds events.

use serde_json::Value;

use logbook_core::{
    AgentBlock, Category, Event, Kind, LlmBlock, MicrosTimestamp, SessionId, Status, TraceId,
};

use crate::context::HarnessContext;
use crate::{class, import_event_id, turn_span_id};

/// The Gemini retroactive-import adapter.
///
/// Holds the session [`TraceId`] every event shares, the [`HarnessContext`] each
/// payload is routed through, the scrubbed `harness_version`, the deterministic
/// timestamp base (`base_ts`) for undated messages, and the native
/// `gemini_session_id` stamped on each event for correlation.
#[derive(Debug)]
pub struct GeminiAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
    /// Deterministic timestamp base (the source file's `mtime`, in micros).
    /// Undated messages get `base_ts + record_index` so a re-import reproduces
    /// the same timestamps (never `now()`).
    base_ts: i64,
    /// The Gemini native session id (the file's `sessionId`), stamped on every
    /// event as `gemini_session_id` for correlation and used as the `coord`
    /// prefix.
    gemini_session_id: String,
    /// Running turn counter, advanced on each user message (matching the live
    /// adapters).
    turn: u64,
    /// Whether a user message has been seen yet (so the first turn is 0).
    turn_open: bool,
}

impl GeminiAdapter {
    /// The stable harness name (matches the source's `tool()` and the `tool`
    /// stamped on each `DiscoveredSession`).
    pub const NAME: &'static str = "gemini";
    /// The `agent` label stamped on agent/LLM blocks.
    pub const AGENT: &'static str = "gemini";

    /// Build the adapter for a session `trace`.
    ///
    /// - `ctx` — the redaction + capture-policy context every payload is routed
    ///   through (the CLI owns its resolution).
    /// - `harness_version` — attacker-controlled metadata (the Gemini CLI
    ///   version, if known); scrubbed through the secrets floor + a length cap
    ///   before being stamped on every event.
    /// - `gemini_session_id` — the native `sessionId`, stamped as
    ///   `gemini_session_id` and used as the `coord` prefix.
    /// - `base_ts` — the deterministic timestamp base (the source file's `mtime`
    ///   in micros) for messages that carry no native `timestamp`.
    #[must_use]
    pub fn new(
        trace: TraceId,
        ctx: HarnessContext,
        harness_version: impl Into<String>,
        gemini_session_id: impl Into<String>,
        base_ts: i64,
    ) -> Self {
        let harness_version =
            ctx.scrub_metadata(&harness_version.into(), crate::HARNESS_VERSION_MAX);
        Self {
            trace,
            ctx,
            harness_version,
            base_ts,
            gemini_session_id: gemini_session_id.into(),
            turn: 0,
            turn_open: false,
        }
    }

    /// Convenience: default recorder-on policy + enabled redactor, a zero
    /// timestamp base, and an empty session id. Intended for tests / ad-hoc use;
    /// the CLI uses [`GeminiAdapter::new`] with a real context + base.
    #[must_use]
    pub fn with_defaults(trace: TraceId) -> Self {
        Self::new(trace, HarnessContext::with_defaults(), "unknown", "", 0)
    }

    /// Parse a whole Gemini `messages[]` stream into logbook [`Event`]s, in
    /// record order.
    ///
    /// `records` is the native message slice the source produces (see the module
    /// docs for its shape); `_meta` is the session-level metadata Value
    /// (title/workspace/session id) — currently unused here because the session
    /// id arrives via the constructor and every other field is present
    /// per-message, but accepted so the seam matches the other adapters and
    /// future per-session enrichment needs no signature change.
    ///
    /// Each user message advances the turn counter. Unknown/empty messages are
    /// skipped.
    #[must_use]
    pub fn parse_records(&mut self, records: &[Value], _meta: &Value) -> Vec<Event> {
        let mut out = Vec::new();
        for (index, raw) in records.iter().enumerate() {
            out.extend(self.parse_message(raw, index));
        }
        out
    }

    /// Parse one message at position `index`, returning zero or more events.
    fn parse_message(&mut self, raw: &Value, index: usize) -> Vec<Event> {
        let Some(ty) = raw.get("type").and_then(Value::as_str) else {
            return Vec::new();
        };
        // The message's intrinsic stable key: `{sessionId}:{index}` (the index is
        // the only stable per-message coordinate Gemini gives us within a file).
        let coord = format!("{}:{index}", self.gemini_session_id);

        let mut out = Vec::new();
        match ty {
            "user" => {
                self.note_user_turn();
                let turn = self.turn;
                if let Some(ev) = self.user_event(raw, &coord, turn, index) {
                    out.push(ev);
                }
            }
            "gemini" => {
                let turn = self.turn;
                if let Some(ev) = self.assistant_message_event(raw, &coord, turn, index) {
                    out.push(ev);
                }
                if let Some(ev) = self.thoughts_event(raw, &coord, turn, index) {
                    out.push(ev);
                }
                if let Some(ev) = self.llm_event(raw, &coord, turn, index) {
                    out.push(ev);
                }
            }
            // Any other type is an unknown message shape: skip.
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

    /// The deterministic timestamp for the message at `index`: the native
    /// `timestamp` (Gemini records it in **milliseconds**, normalized to micros)
    /// when present, else `base_ts + index`. Returns `(timestamp, is_approx)`.
    fn timestamp_for(&self, raw: &Value, index: usize) -> (MicrosTimestamp, bool) {
        match raw.get("timestamp").and_then(Value::as_i64) {
            Some(ms) => (MicrosTimestamp(ms.saturating_mul(1000)), false),
            None => (
                MicrosTimestamp(self.base_ts.saturating_add(index as i64)),
                true,
            ),
        }
    }

    /// Base event scaffold: a fresh event on the session trace stamped with the
    /// **deterministic** id (`import_event_id(trace, coord, role)`) and timestamp,
    /// plus `harness`, `harness_version`, `turn`, the `gemini_session_id`, and the
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
            .with_session(SessionId::new(&self.gemini_session_id));
        // Deterministic id + timestamp are MANDATORY on the import path: never
        // leave the random `Event::new` id / `now()` timestamp.
        ev.id = import_event_id(self.trace, coord, role);
        ev.timestamp = timestamp;
        if !self.gemini_session_id.is_empty() {
            ev = ev.with_attr("gemini_session_id", self.gemini_session_id.clone());
        }
        if approx {
            ev = ev.with_attr("imported_timestamp", "approx");
        }
        ev
    }

    // ---- user prompt -----------------------------------------------------

    /// Build a [`Kind::Agent`] user-prompt event with the redacted body in
    /// `input`. The event's own span id is the turn span, so the assistant /
    /// reasoning / LLM events on the same turn parent to it. Returns `None` when
    /// the message carries no content.
    fn user_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let text = message_content(raw);
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
    /// message carries no content (a model-only or thoughts-only assistant
    /// message still yields its own LLM/reasoning event via the other builders).
    fn assistant_message_event(
        &self,
        raw: &Value,
        coord: &str,
        turn: u64,
        index: usize,
    ) -> Option<Event> {
        let text = message_content(raw);
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
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, &text);
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        Some(ev)
    }

    // ---- assistant / reasoning ------------------------------------------

    /// Build a [`Kind::Agent`] reasoning event from a `gemini` message's
    /// `thoughts`, parented to the turn span. Reasoning is prompt-sensitive, so
    /// the redacted thoughts land in `output` under the `prompts` class. Returns
    /// `None` when the message carries no (non-empty) thoughts.
    fn thoughts_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let thoughts = stringify_text(raw.get("thoughts")?);
        if thoughts.is_empty() {
            return None;
        }
        let parent = turn_span_id(self.trace, turn);
        // A distinct role ("reasoning") keeps this event's deterministic id from
        // colliding with the assistant message / LLM events on the same coord.
        let mut ev = self
            .base(Kind::Agent, "agent.reasoning", coord, "reasoning", turn, raw, index)
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
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, &thoughts);
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        Some(ev)
    }

    // ---- assistant / llm -------------------------------------------------

    /// Build a [`Kind::Llm`] event carrying the model + token attribution,
    /// parented to the turn span. Returns `None` when the message names neither a
    /// model nor any token counts (an empty LlmBlock would be a bare,
    /// content-free row).
    fn llm_event(&self, raw: &Value, coord: &str, turn: u64, index: usize) -> Option<Event> {
        let model = raw
            .get("model")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty());
        let tokens = raw.get("tokens");
        let (input_tokens, output_tokens, total_tokens) = token_counts(tokens);

        // Nothing to attribute ⇒ no LLM event.
        if model.is_none() && input_tokens.is_none() && output_tokens.is_none() && total_tokens.is_none()
        {
            return None;
        }
        let parent = turn_span_id(self.trace, turn);

        // Model metadata (model name + token counts) is the one default-exported
        // class; capture-gate it but it needs no body redaction. The model NAME is
        // still routed through the secrets-floor scrubber defensively.
        let llm = if self.ctx.captures(class::MODEL_METADATA) {
            LlmBlock {
                model: model.map(|m| self.ctx.scrub_metadata(m, crate::HARNESS_VERSION_MAX)),
                input_tokens,
                output_tokens,
                total_tokens,
                ..Default::default()
            }
        } else {
            LlmBlock::default()
        };

        let name = match (self.ctx.captures(class::MODEL_METADATA), model) {
            (true, Some(m)) => self.ctx.scrub_metadata(m, crate::HARNESS_VERSION_MAX),
            _ => "assistant".to_string(),
        };

        // The LLM event uses the role "llm" in its deterministic id so it never
        // collides with the assistant message / reasoning events on the same coord.
        let ev = self
            .base(Kind::Llm, "llm.completion", coord, "llm", turn, raw, index)
            .with_parent(parent)
            .with_op("completion")
            .with_name(name)
            .with_status(Status::Ok)
            .with_llm(llm);
        Some(ev)
    }
}

/// Extract a Gemini message's `content` as a plain string. Gemini stores
/// `content` as a string, but tolerate the array-of-`{text}` form defensively
/// (matching the Continue shape) so a future format tweak does not silently drop
/// the body.
fn message_content(raw: &Value) -> String {
    match raw.get("content") {
        Some(v) => stringify_text(v),
        None => String::new(),
    }
}

/// Stringify a text-ish Gemini value: a plain string, or an array of
/// `{text:"…"}`/bare-string parts joined by newlines (used for both `content`
/// and `thoughts`, which Gemini may store either way).
fn stringify_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|part| match part {
                Value::String(s) => Some(s.clone()),
                Value::Object(_) => part.get("text").and_then(Value::as_str).map(str::to_string),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Pull `(input, output, total)` token counts from a Gemini `tokens` object,
/// tolerating the common key spellings Gemini and adjacent tools use
/// (`input`/`inputTokens`/`prompt`, `output`/`outputTokens`/`completion`,
/// `total`/`totalTokens`). A missing/non-object value yields all `None`.
fn token_counts(tokens: Option<&Value>) -> (Option<u64>, Option<u64>, Option<u64>) {
    let Some(obj) = tokens else {
        return (None, None, None);
    };
    let pick = |keys: &[&str]| -> Option<u64> {
        keys.iter()
            .find_map(|k| obj.get(*k).and_then(Value::as_u64))
    };
    let input = pick(&["input", "inputTokens", "input_tokens", "prompt", "promptTokens"]);
    let output = pick(&[
        "output",
        "outputTokens",
        "output_tokens",
        "completion",
        "completionTokens",
    ]);
    let total = pick(&["total", "totalTokens", "total_tokens"]);
    (input, output, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> TraceId {
        TraceId::from_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x02,
        ])
    }

    fn adapter() -> GeminiAdapter {
        // A fixed non-zero base so undated messages get deterministic timestamps.
        GeminiAdapter::new(
            trace(),
            HarnessContext::with_defaults(),
            "gemini-0.1",
            "sess-g1",
            1_700_000_000_000_000,
        )
    }

    /// The golden fixture: a user message (with a planted secret + native
    /// timestamp), a gemini message (content + thoughts + model + tokens).
    /// Asserts exact kinds, redaction, token counts, parents, and the exact
    /// deterministic id + timestamp the import contract requires.
    #[test]
    fn golden_gemini_stream_normalizes_all_shapes() {
        let mut a = adapter();
        let records = vec![
            serde_json::json!({
                "type": "user",
                "content": "deploy with AKIAIOSFODNN7EXAMPLE please",
                "timestamp": 1_700_000_111_000_i64
            }),
            serde_json::json!({
                "type": "gemini",
                "content": "Sure, deploying now.",
                "thoughts": "I should call the deploy tool with AKIAIOSFODNN7EXAMPLE.",
                "model": "gemini-2.0-flash",
                "tokens": { "input": 12, "output": 34, "total": 46 },
                "timestamp": 1_700_000_222_000_i64
            }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        // user prompt, assistant message, reasoning, llm = 4 events.
        assert_eq!(evs.len(), 4, "got {} events: {evs:#?}", evs.len());

        // Common invariants.
        for ev in &evs {
            assert_eq!(ev.trace_id, trace());
            assert_eq!(ev.session_id.as_ref().map(|s| s.as_str()), Some("sess-g1"));
            assert_eq!(
                ev.attributes.get("harness").and_then(Value::as_str),
                Some("gemini")
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
        assert_eq!(user.id, import_event_id(trace(), "sess-g1:0", "user"));
        // Native ts (millis) → micros; NOT marked approx.
        assert_eq!(user.timestamp, MicrosTimestamp(1_700_000_111_000_000));
        assert!(user.attributes.get("imported_timestamp").is_none());

        // (2) assistant message → Kind::Agent assistant, redacted output, parents
        // to turn-0 span, native ts preserved.
        let msg = &evs[1];
        assert_eq!(msg.kind, Kind::Agent);
        assert_eq!(msg.type_, "agent.message");
        assert_eq!(msg.output.as_ref().unwrap().as_str().unwrap(), "Sure, deploying now.");
        assert_eq!(msg.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(msg.id, import_event_id(trace(), "sess-g1:1", "assistant"));
        assert_eq!(msg.timestamp, MicrosTimestamp(1_700_000_222_000_000));

        // (3) reasoning → Kind::Agent reasoning, redacted thoughts, distinct id.
        let reasoning = &evs[2];
        assert_eq!(reasoning.kind, Kind::Agent);
        assert_eq!(reasoning.type_, "agent.reasoning");
        let thoughts = reasoning.output.as_ref().unwrap().as_str().unwrap();
        assert!(!thoughts.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in thoughts: {thoughts}");
        assert_eq!(reasoning.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(reasoning.id, import_event_id(trace(), "sess-g1:1", "reasoning"));

        // (4) llm → Kind::Llm, model + token attribution, distinct id (role "llm").
        let llm = &evs[3];
        assert_eq!(llm.kind, Kind::Llm);
        let lb = llm.blocks.llm.as_ref().unwrap();
        assert_eq!(lb.model.as_deref(), Some("gemini-2.0-flash"));
        assert_eq!(lb.input_tokens, Some(12), "input tokens on LlmBlock");
        assert_eq!(lb.output_tokens, Some(34), "output tokens on LlmBlock");
        assert_eq!(lb.total_tokens, Some(46), "total tokens on LlmBlock");
        assert_eq!(llm.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(llm.id, import_event_id(trace(), "sess-g1:1", "llm"));
        // The message + reasoning + llm share a coord but have distinct ids.
        assert_ne!(llm.id, msg.id);
        assert_ne!(llm.id, reasoning.id);
    }

    #[test]
    fn undated_message_uses_base_ts_plus_index_and_marks_approx() {
        // With no native timestamp, the adapter stamps base_ts + index and marks
        // imported_timestamp="approx".
        let mut a = adapter();
        let records = vec![
            serde_json::json!({ "type": "user", "content": "hi" }),
            serde_json::json!({ "type": "gemini", "content": "yo" }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].timestamp, MicrosTimestamp(1_700_000_000_000_000));
        assert_eq!(
            evs[0].attributes.get("imported_timestamp").and_then(Value::as_str),
            Some("approx")
        );
        assert_eq!(evs[1].timestamp, MicrosTimestamp(1_700_000_000_000_001));
        assert_eq!(
            evs[1].attributes.get("imported_timestamp").and_then(Value::as_str),
            Some("approx")
        );
    }

    #[test]
    fn unknown_message_shape_is_skipped() {
        let mut a = adapter();
        let records = vec![
            // No type.
            serde_json::json!({ "content": "orphan" }),
            // Unknown type.
            serde_json::json!({ "type": "system", "content": "sys" }),
            // User with empty content ⇒ nothing to emit.
            serde_json::json!({ "type": "user", "content": "" }),
            // Gemini with no content, thoughts, model, or tokens ⇒ nothing.
            serde_json::json!({ "type": "gemini" }),
            // Not even an object.
            serde_json::json!("a bare string"),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert!(evs.is_empty(), "unknown/empty messages must be skipped, got {}", evs.len());
    }

    #[test]
    fn turn_advances_on_user_messages() {
        let mut a = adapter();
        let records = vec![
            serde_json::json!({ "type": "user", "content": "first" }),
            serde_json::json!({ "type": "gemini", "content": "a0" }),
            serde_json::json!({ "type": "user", "content": "second" }),
            serde_json::json!({ "type": "gemini", "content": "a1" }),
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
    fn model_only_gemini_message_still_yields_llm_event() {
        // A gemini message with only a model (no content/thoughts/tokens) still
        // produces an LLM attribution event (and nothing else).
        let mut a = adapter();
        let records = vec![serde_json::json!({ "type": "gemini", "model": "gemini-pro" })];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, Kind::Llm);
        assert_eq!(evs[0].blocks.llm.as_ref().unwrap().model.as_deref(), Some("gemini-pro"));
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
        let mut a = GeminiAdapter::new(trace(), ctx, "v", "s", 1000);
        let records = vec![
            serde_json::json!({ "type": "user", "content": "secret AKIAIOSFODNN7EXAMPLE" }),
            serde_json::json!({ "type": "gemini", "content": "secret reply", "thoughts": "secret think" }),
        ];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        // user prompt + assistant message + reasoning = 3 events (no llm: no model/tokens).
        assert_eq!(evs.len(), 3);
        assert!(evs[0].input.is_none(), "prompts off ⇒ no user body");
        assert!(evs[1].output.is_none(), "prompts off ⇒ no assistant body");
        assert!(evs[2].output.is_none(), "prompts off ⇒ no reasoning body");
    }

    #[test]
    fn deterministic_across_reparse() {
        // Re-running the adapter over the same records reproduces byte-identical
        // events (ids + timestamps included).
        let records = vec![
            serde_json::json!({ "type": "user", "content": "hi", "timestamp": 1_700_000_000_000_i64 }),
            serde_json::json!({ "type": "gemini", "content": "yo", "model": "m", "tokens": { "input": 1 } }),
        ];
        let mut a1 = adapter();
        let mut a2 = adapter();
        let e1 = a1.parse_records(&records, &serde_json::json!({}));
        let e2 = a2.parse_records(&records, &serde_json::json!({}));
        assert_eq!(e1, e2, "re-parse must be byte-identical");
    }

    #[test]
    fn content_array_form_is_concatenated() {
        // Defensive: a content array of {text} parts is joined (tolerated even
        // though Gemini normally stores a string).
        let mut a = adapter();
        let records = vec![serde_json::json!({
            "type": "user",
            "content": [ { "type": "text", "text": "part one" }, { "type": "text", "text": "part two" } ]
        })];
        let evs = a.parse_records(&records, &serde_json::json!({}));
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].input.as_ref().unwrap().as_str().unwrap(), "part one\npart two");
    }

    #[test]
    fn hostile_harness_version_is_scrubbed_and_capped() {
        let hostile = format!("g {} AKIAIOSFODNN7EXAMPLE", "p".repeat(300));
        let mut a = GeminiAdapter::new(trace(), HarnessContext::with_defaults(), hostile, "s", 0);
        let evs = a.parse_records(
            &[serde_json::json!({ "type": "user", "content": "hi" })],
            &serde_json::json!({}),
        );
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in harness_version: {v}");
        assert!(v.len() <= 64 + 3, "harness_version not capped: {} bytes", v.len());
    }
}
