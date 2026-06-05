//! Claude Code adapter (plan "Phase 2", Claude Code row).
//!
//! Normalizes two Claude Code record shapes into logbook [`Event`]s:
//!
//! 1. **Hook events** — the JSON a Claude Code hook receives on stdin, keyed by
//!    `hook_event_name`: `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
//!    `Stop`. (POSTed to a collector route in the full pipeline.)
//! 2. **Session-log JSONL transcript records** — one line of
//!    `~/.claude/projects/**/*.jsonl`, keyed by `type` (`user` / `assistant` /
//!    `system`) carrying an Anthropic `message` object. (Tailing these is
//!    **opt-in**, not recorder-on.)
//!
//! ## Mapping
//! | Record | Event |
//! |---|---|
//! | user prompt (hook `UserPromptSubmit` or session `type:user` text) | [`Kind::Agent`] + [`AgentBlock`] `role:"user"`, redacted prompt in `input` |
//! | tool call (hook `Pre`/`PostToolUse` or session `tool_use` block) | [`Kind::Tool`] + [`ToolBlock`] (redacted `arguments`, `is_write`), `parent_id` → turn span, redacted result in `output` |
//! | assistant step (session `type:assistant`) | [`Kind::Llm`] + [`LlmBlock`] (`model`, tokens, `cost_usd`, `finish_reason`) |
//!
//! Every event is parented to its **turn span** ([`crate::turn_span_id`]) so the
//! turn → tool/LLM hierarchy is wired even when records stream one at a time. A
//! `harness_version` attribute is stamped on every event; unrecognized records
//! are **skipped** (empty `Vec`).

use serde_json::Value;

use logbook_core::{
    truncate_with_ellipsis, AgentBlock, Category, Event, Kind, LlmBlock, Status, ToolBlock,
    TraceId,
};

use crate::context::HarnessContext;
use crate::{class, turn_span_id, HarnessAdapter};

/// The Claude Code adapter. Holds the [`TraceId`] all its events share, the
/// [`HarnessContext`] (redactor + policy), and the harness version string
/// stamped on every event.
#[derive(Debug)]
pub struct ClaudeCodeAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
}

/// Tools whose names indicate a mutating ("write") operation. Used to populate
/// [`ToolBlock::is_write`] when the harness doesn't say so directly.
const WRITE_TOOLS: &[&str] = &[
    "write", "edit", "multiedit", "notebookedit", "create", "delete", "rename", "move", "bash",
    "applypatch", "str_replace", "str_replace_editor",
];

impl ClaudeCodeAdapter {
    /// The stable harness name.
    pub const NAME: &'static str = "claude-code";
    /// The `agent` label stamped on agent/tool/LLM blocks.
    pub const AGENT: &'static str = "claude";

    /// Build the adapter for a session `trace`, with the redaction +
    /// capture-policy [`HarnessContext`] every payload is routed through, and the
    /// `harness_version` stamped on each event (e.g. the Claude Code CLI
    /// version; pass `"unknown"` if not known).
    #[must_use]
    pub fn new(trace: TraceId, ctx: HarnessContext, harness_version: impl Into<String>) -> Self {
        // `harness_version` is attacker-controlled (it arrives from the harness);
        // scrub it through the secrets floor + a length cap before it is stamped
        // on every event. Redaction-before-persistence applies to metadata too.
        let harness_version = ctx.scrub_metadata(&harness_version.into(), crate::HARNESS_VERSION_MAX);
        Self {
            trace,
            ctx,
            harness_version,
        }
    }

    /// Convenience constructor with the default recorder-on policy + an enabled
    /// redactor (capture on, redaction on).
    #[must_use]
    pub fn with_defaults(trace: TraceId, harness_version: impl Into<String>) -> Self {
        Self::new(trace, HarnessContext::with_defaults(), harness_version)
    }

    /// Base event scaffold: fresh event on the session trace, with the
    /// `harness_version` attribute stamped.
    fn base(&self, kind: Kind, type_: &str) -> Event {
        Event::new(self.trace, kind, Category::Agent, type_)
            .with_attr("harness_version", self.harness_version.clone())
            .with_attr("harness", Self::NAME)
    }

    /// Whether a tool name looks like a mutating operation.
    fn is_write_tool(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        WRITE_TOOLS.iter().any(|w| lower == *w)
    }

    // ---- prompt ----------------------------------------------------------

    /// Build a [`Kind::Agent`] user-prompt event on turn `turn` with the
    /// redacted prompt in `input`. The event's own span id is the turn span, so
    /// tool/LLM events on the same turn parent to it.
    fn user_prompt_event(&self, prompt: &str, turn: u64) -> Event {
        let mut ev = self
            .base(Kind::Agent, "agent.user_prompt")
            .with_op("prompt")
            .with_name("user prompt")
            .with_status(Status::Ok)
            .with_agent(AgentBlock {
                agent: Some(Self::AGENT.to_string()),
                role: Some("user".to_string()),
                turn: Some(turn),
                ..Default::default()
            })
            .with_attr("turn", turn);

        if self.ctx.captures(class::PROMPTS) {
            let (red, truncated) = self.ctx.redact_text(class::PROMPTS, prompt);
            ev.input = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("input_truncated", true);
            }
        }
        ev
    }

    // ---- tool ------------------------------------------------------------

    /// Build a [`Kind::Tool`] event for a tool call, `parent_id`-linked to its
    /// turn span. Arguments and result are redacted before they land on the
    /// event.
    fn tool_event(
        &self,
        tool_name: &str,
        arguments: Option<&Value>,
        result: Option<&str>,
        tool_call_id: Option<&str>,
        turn: u64,
    ) -> Event {
        let parent = turn_span_id(self.trace, turn);
        let mut tool = ToolBlock {
            tool_name: Some(tool_name.to_string()),
            is_write: Some(Self::is_write_tool(tool_name)),
            ..Default::default()
        };

        let mut args_truncated = false;
        if let Some(args) = arguments {
            if self.ctx.captures(class::TOOL_ARGS) {
                // tool_args are force-redacted AND byte-capped (plan §capture
                // policy); an over-cap blob is stored as a bounded string.
                let (red_args, truncated) = self.ctx.redact_tool_args(args);
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
            .base(Kind::Tool, "tool.call")
            .with_parent(parent)
            .with_op("tool")
            .with_name(tool_name.to_string())
            .with_status(Status::Ok)
            .with_attr("turn", turn)
            .with_tool(tool);

        if args_truncated {
            ev = ev.with_attr("arguments_truncated", true);
        }
        if let Some(id) = tool_call_id {
            ev = ev.with_attr("tool_call_id", id.to_string());
        }
        // The (already-redacted) full result body goes in `output` when captured.
        if let Some((red, truncated)) = redacted_result {
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        ev
    }

    // ---- assistant / llm -------------------------------------------------

    /// Build a [`Kind::Llm`] event for an assistant step, `parent_id`-linked to
    /// its turn span.
    #[allow(clippy::too_many_arguments)]
    fn llm_event(
        &self,
        model: Option<&str>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cost_usd: Option<f64>,
        finish_reason: Option<&str>,
        turn: u64,
    ) -> Event {
        let parent = turn_span_id(self.trace, turn);
        // Model metadata is the one default-exported class; capture-gate it but
        // never needs redaction (it carries no payload).
        let llm = if self.ctx.captures(class::MODEL_METADATA) {
            LlmBlock {
                provider: Some("anthropic".to_string()),
                model: model.map(str::to_string),
                input_tokens,
                output_tokens,
                cost_usd,
                finish_reason: finish_reason.map(str::to_string),
                ..Default::default()
            }
        } else {
            LlmBlock::default()
        };

        // Note: the LLM event records its turn via the `turn` attribute, not an
        // AgentBlock — an Event carries at most one typed block (see
        // `Event::validate`), and this event already carries the LlmBlock. The
        // assistant role is implicit in `Kind::Llm`.
        self.base(Kind::Llm, "llm.completion")
            .with_parent(parent)
            .with_op("completion")
            .with_name(model.unwrap_or("assistant").to_string())
            .with_status(Status::Ok)
            .with_attr("turn", turn)
            .with_llm(llm)
    }

    // ---- hook events -----------------------------------------------------

    /// Parse a Claude Code **hook** event (detected by `hook_event_name`).
    fn parse_hook(&self, raw: &Value, hook: &str) -> Vec<Event> {
        // Hooks don't carry an explicit turn index; allow an injected hint and
        // default to turn 0 (a single-turn hook stream).
        let turn = raw.get("turn").and_then(Value::as_u64).unwrap_or(0);
        match hook {
            "UserPromptSubmit" => {
                let prompt = raw
                    .get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if prompt.is_empty() {
                    return Vec::new();
                }
                vec![self.user_prompt_event(prompt, turn)]
            }
            "PreToolUse" | "PostToolUse" => {
                let Some(tool_name) = raw.get("tool_name").and_then(Value::as_str) else {
                    return Vec::new();
                };
                let arguments = raw.get("tool_input");
                // PostToolUse carries the result under `tool_response`.
                let result = raw
                    .get("tool_response")
                    .map(stringify_result);
                let tool_call_id = raw.get("tool_use_id").and_then(Value::as_str);
                vec![self.tool_event(
                    tool_name,
                    arguments,
                    result.as_deref(),
                    tool_call_id,
                    turn,
                )]
            }
            // `Stop`/`SubagentStop` carry no capturable payload of their own; we
            // emit nothing (the session's events already exist). Recognized but
            // intentionally empty.
            "Stop" | "SubagentStop" => Vec::new(),
            _ => Vec::new(),
        }
    }

    // ---- session-log JSONL records --------------------------------------

    /// Parse a Claude Code **session-log JSONL** record (detected by `type` ∈
    /// {user, assistant, system} carrying a `message`).
    fn parse_session_record(&self, raw: &Value, ty: &str) -> Vec<Event> {
        let turn = raw.get("turn").and_then(Value::as_u64).unwrap_or(0);
        let message = raw.get("message");

        match ty {
            "user" => {
                let mut out = Vec::new();
                // A user record is either a plain prompt or a carrier of
                // tool_result blocks (Claude inlines tool results as user turns).
                if let Some(msg) = message {
                    // tool_result content blocks → attach as results on tool events.
                    for block in content_blocks(msg) {
                        if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                            let tool_use_id =
                                block.get("tool_use_id").and_then(Value::as_str);
                            let result = block.get("content").map(stringify_result);
                            // We don't know the tool name from a bare result; emit
                            // a tool event keyed by id so it links to the turn.
                            out.push(self.tool_event(
                                "tool_result",
                                None,
                                result.as_deref(),
                                tool_use_id,
                                turn,
                            ));
                        }
                    }
                    // Plain user text prompt.
                    let text = collect_text(msg);
                    if !text.is_empty() {
                        out.push(self.user_prompt_event(&text, turn));
                    }
                }
                out
            }
            "assistant" => {
                let mut out = Vec::new();
                let Some(msg) = message else {
                    return out;
                };
                let model = msg.get("model").and_then(Value::as_str);
                let stop_reason = msg.get("stop_reason").and_then(Value::as_str);
                let usage = msg.get("usage");
                let input_tokens = usage
                    .and_then(|u| u.get("input_tokens"))
                    .and_then(Value::as_u64);
                let output_tokens = usage
                    .and_then(|u| u.get("output_tokens"))
                    .and_then(Value::as_u64);
                let cost_usd = raw
                    .get("costUSD")
                    .or_else(|| raw.get("cost_usd"))
                    .and_then(Value::as_f64);

                // The assistant LLM step.
                out.push(self.llm_event(
                    model,
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    stop_reason,
                    turn,
                ));

                // tool_use content blocks → tool call events on this turn.
                for block in content_blocks(msg) {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                        let tool_name = block
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("tool");
                        let arguments = block.get("input");
                        let tool_call_id = block.get("id").and_then(Value::as_str);
                        out.push(self.tool_event(
                            tool_name,
                            arguments,
                            None,
                            tool_call_id,
                            turn,
                        ));
                    }
                }
                out
            }
            // `system` records (meta / hooks summaries) carry no agent payload.
            _ => Vec::new(),
        }
    }
}

impl HarnessAdapter for ClaudeCodeAdapter {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn parse_record(&self, raw: &Value) -> Vec<Event> {
        // A hook event is keyed by `hook_event_name`; a session-log record by
        // `type`. Anything else is skipped (tolerant).
        if let Some(hook) = raw.get("hook_event_name").and_then(Value::as_str) {
            return self.parse_hook(raw, hook);
        }
        if let Some(ty) = raw.get("type").and_then(Value::as_str) {
            if matches!(ty, "user" | "assistant" | "system") {
                return self.parse_session_record(raw, ty);
            }
        }
        Vec::new()
    }
}

/// Extract the `content` blocks of an Anthropic `message` as a slice of objects.
/// Content may be a string (no blocks) or an array of block objects.
fn content_blocks(message: &Value) -> Vec<&Value> {
    match message.get("content") {
        Some(Value::Array(arr)) => arr.iter().collect(),
        _ => Vec::new(),
    }
}

/// Collect the concatenated `text` from an Anthropic `message`'s content. Handles
/// both a bare string `content` and an array of `{type:text, text:…}` blocks.
fn collect_text(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => {
            let mut parts = Vec::new();
            for block in arr {
                if block.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        parts.push(t.to_string());
                    }
                }
            }
            parts.join("\n")
        }
        _ => String::new(),
    }
}

/// Render a tool result (which may be a string, an array of content blocks, or
/// an arbitrary object) into a single string for redaction + summary.
fn stringify_result(value: &Value) -> String {
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
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ])
    }

    fn adapter() -> ClaudeCodeAdapter {
        ClaudeCodeAdapter::with_defaults(trace(), "1.2.3")
    }

    // ---- golden fixture: a full session-log turn -------------------------

    #[test]
    fn golden_session_log_turn_normalizes_to_prompt_llm_and_tool() {
        let a = adapter();

        // 1) user prompt record (with a planted secret to prove redaction).
        let user = serde_json::json!({
            "type": "user",
            "sessionId": "abc",
            "turn": 0,
            "message": {
                "role": "user",
                "content": "read config and deploy with AKIAIOSFODNN7EXAMPLE"
            }
        });
        let evs = a.parse_record(&user);
        assert_eq!(evs.len(), 1, "user prompt → one Agent event");
        let p = &evs[0];
        assert_eq!(p.kind, Kind::Agent);
        let ablock = p.blocks.agent.as_ref().expect("agent block");
        assert_eq!(ablock.role.as_deref(), Some("user"));
        assert_eq!(ablock.turn, Some(0));
        // The prompt is redacted in `input`.
        let input = p.input.as_ref().unwrap().as_str().unwrap();
        assert!(!input.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in prompt: {input}");
        assert!(input.contains("REDACTED:CLOUD_KEY:"), "no redaction placeholder: {input}");
        // The prompt event's own span is the turn span (parents for tools).
        assert!(p.validate().is_ok());

        // 2) assistant record with usage + a tool_use block (Edit = write).
        let assistant = serde_json::json!({
            "type": "assistant",
            "turn": 0,
            "costUSD": 0.0123,
            "message": {
                "role": "assistant",
                "model": "claude-3-5-sonnet-20241022",
                "stop_reason": "tool_use",
                "usage": { "input_tokens": 120, "output_tokens": 45 },
                "content": [
                    { "type": "text", "text": "I'll edit the file." },
                    {
                        "type": "tool_use",
                        "id": "toolu_01ABC",
                        "name": "Edit",
                        "input": { "file_path": "/app/main.rs", "new_string": "token=AKIAIOSFODNN7EXAMPLE" }
                    }
                ]
            }
        });
        let evs = a.parse_record(&assistant);
        assert_eq!(evs.len(), 2, "assistant → one Llm + one Tool event");

        let llm = &evs[0];
        assert_eq!(llm.kind, Kind::Llm);
        let lblock = llm.blocks.llm.as_ref().expect("llm block");
        assert_eq!(lblock.model.as_deref(), Some("claude-3-5-sonnet-20241022"));
        assert_eq!(lblock.input_tokens, Some(120));
        assert_eq!(lblock.output_tokens, Some(45));
        assert_eq!(lblock.finish_reason.as_deref(), Some("tool_use"));
        assert_eq!(lblock.cost_usd, Some(0.0123));
        assert!(llm.validate().is_ok());

        let tool = &evs[1];
        assert_eq!(tool.kind, Kind::Tool);
        let tblock = tool.blocks.tool.as_ref().expect("tool block");
        assert_eq!(tblock.tool_name.as_deref(), Some("Edit"));
        assert_eq!(tblock.is_write, Some(true), "Edit is a write tool");
        // Tool arguments are redacted.
        let args = tblock.arguments.as_ref().unwrap();
        let args_s = serde_json::to_string(args).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in args: {args_s}");
        assert!(args_s.contains("/app/main.rs"), "non-secret arg lost: {args_s}");

        // ---- HIERARCHY: the tool + llm parent to the SAME turn span as the
        // user prompt's own span id (turn 0 over this trace). ----
        let turn0 = turn_span_id(trace(), 0);
        assert_eq!(tool.parent_id, Some(turn0), "tool must parent to its turn span");
        assert_eq!(llm.parent_id, Some(turn0), "llm must parent to its turn span");
        // All three events share the session trace.
        assert_eq!(p.trace_id, trace());
        assert_eq!(tool.trace_id, trace());
        assert_eq!(llm.trace_id, trace());
        // harness_version stamped everywhere.
        for ev in [p, llm, tool] {
            assert_eq!(
                ev.attributes.get("harness_version").and_then(Value::as_str),
                Some("1.2.3")
            );
        }
    }

    // ---- golden fixture: hook events -------------------------------------

    #[test]
    fn golden_hooks_normalize_prompt_and_tool() {
        let a = adapter();

        let prompt_hook = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s1",
            "cwd": "/work",
            "prompt": "fix the bug, here is my key ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        });
        let evs = a.parse_record(&prompt_hook);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, Kind::Agent);
        let input = evs[0].input.as_ref().unwrap().as_str().unwrap();
        assert!(!input.contains("ghp_0123456789abcdefghijklmnopqrstuvwxyz"), "leaked: {input}");
        assert!(input.contains("REDACTED:CLOUD_KEY:"));

        let post_tool = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_use_id": "toolu_99",
            "tool_input": { "command": "echo hi" },
            "tool_response": { "stdout": "hi\n", "stderr": "" }
        });
        let evs = a.parse_record(&post_tool);
        assert_eq!(evs.len(), 1);
        let tool = &evs[0];
        assert_eq!(tool.kind, Kind::Tool);
        let tblock = tool.blocks.tool.as_ref().unwrap();
        assert_eq!(tblock.tool_name.as_deref(), Some("Bash"));
        assert_eq!(tblock.is_write, Some(true), "Bash counts as a write tool");
        assert!(tblock.result_summary.is_some(), "post-tool result captured");
        // Parents to turn 0 span.
        assert_eq!(tool.parent_id, Some(turn_span_id(trace(), 0)));
        // tool_call_id surfaced as an attribute.
        assert_eq!(
            tool.attributes.get("tool_call_id").and_then(Value::as_str),
            Some("toolu_99")
        );
    }

    #[test]
    fn stop_hook_and_unknown_records_are_skipped() {
        let a = adapter();
        assert!(a
            .parse_record(&serde_json::json!({"hook_event_name": "Stop", "stop_hook_active": true}))
            .is_empty());
        // Totally unknown record.
        assert!(a.parse_record(&serde_json::json!({"foo": "bar"})).is_empty());
        // A `type` we don't model.
        assert!(a
            .parse_record(&serde_json::json!({"type": "summary", "message": {}}))
            .is_empty());
        // Empty prompt hook → skipped.
        assert!(a
            .parse_record(&serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": ""}))
            .is_empty());
    }

    #[test]
    fn read_tool_is_not_a_write() {
        let a = adapter();
        let ev = &a.parse_record(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": "/x" }
        }))[0];
        assert_eq!(ev.blocks.tool.as_ref().unwrap().is_write, Some(false));
    }

    #[test]
    fn prompts_off_yields_no_prompt_body_but_still_an_event() {
        // With `prompts` capture off, the Agent event is still emitted (turn
        // anchor) but carries no input payload — metadata only.
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.prompts.capture = false;
                p
            },
            true,
        );
        let a = ClaudeCodeAdapter::new(trace(), ctx, "1.0");
        let evs = a.parse_record(&serde_json::json!({
            "type": "user",
            "message": { "role": "user", "content": "secret plan AKIAIOSFODNN7EXAMPLE" }
        }));
        assert_eq!(evs.len(), 1);
        assert!(evs[0].input.is_none(), "prompts off ⇒ no prompt body persisted");
    }

    #[test]
    fn huge_tool_input_is_capped_with_marker_and_attr() {
        // A tool_input far exceeding the tool_args cap ⇒ arguments stored as a
        // bounded STRING (truncation marker), `arguments_truncated` attribute set,
        // and the persisted body never contains the full blob.
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.tool_args.max_bytes = Some(128);
                p
            },
            true,
        );
        let a = ClaudeCodeAdapter::new(trace(), ctx, "1.0");
        let big = "Z".repeat(50_000);
        let evs = a.parse_record(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": big }
        }));
        assert_eq!(evs.len(), 1);
        let tool = &evs[0];
        // arguments_truncated attribute is stamped.
        assert_eq!(
            tool.attributes.get("arguments_truncated").and_then(Value::as_bool),
            Some(true),
            "arguments_truncated must be set when args exceed the cap"
        );
        let args = tool.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap();
        // Over-cap args are stored as a STRING, not the structured object.
        let s = args.as_str().expect("capped args stored as a string");
        assert!(s.contains("[diff truncated"), "truncation marker missing: head={:.40}", s);
        // Bounded well under the input: kept-prefix cap (128) + marker overhead.
        assert!(s.len() <= 128 + 64, "capped body not bounded: {} bytes", s.len());
        assert!(!s.contains(&big), "full blob persisted uncapped");
    }

    #[test]
    fn tool_result_is_redacted_once_and_summary_matches_output() {
        // The result is redacted a single time; result_summary is derived from
        // the SAME already-redacted output (a prefix of it), and the secret is
        // gone from both.
        let a = adapter();
        let evs = a.parse_record(&serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "t1",
            "tool_input": { "command": "cat .env" },
            "tool_response": { "stdout": "value AKIAIOSFODNN7EXAMPLE done", "stderr": "" }
        }));
        assert_eq!(evs.len(), 1);
        let tool = &evs[0];
        let out = tool.output.as_ref().unwrap().as_str().unwrap();
        let summary = tool.blocks.tool.as_ref().unwrap().result_summary.as_ref().unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in output: {out}");
        assert!(!summary.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in summary: {summary}");
        // The summary is derived from the redacted output: it is that string,
        // possibly truncated with an ellipsis (here the body is short ⇒ equal).
        assert_eq!(summary, out, "summary must derive from the redacted output");
        assert!(out.contains("REDACTED:CLOUD_KEY:"), "result not redacted: {out}");
    }

    #[test]
    fn hostile_harness_version_is_scrubbed_and_capped() {
        // A harness_version carrying a secret and far over the length cap ⇒ the
        // stamped attribute is scrubbed (no secret) and bounded.
        let hostile = format!("v9 AKIAIOSFODNN7EXAMPLE {}", "q".repeat(300));
        let a = ClaudeCodeAdapter::with_defaults(trace(), hostile);
        let evs = a.parse_record(&serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello"
        }));
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in harness_version: {v}");
        assert!(v.len() <= 64 + 3, "harness_version not capped: {} bytes", v.len());
    }

    #[test]
    fn tool_result_user_block_links_to_turn() {
        // A user record that only carries a tool_result block (Claude inlines
        // results as user turns) becomes a tool event linked to the turn.
        let a = adapter();
        let evs = a.parse_record(&serde_json::json!({
            "type": "user",
            "turn": 0,
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01ABC",
                        "content": "file written ok, key was AKIAIOSFODNN7EXAMPLE"
                    }
                ]
            }
        }));
        assert_eq!(evs.len(), 1, "tool_result-only user record → one tool event");
        let tool = &evs[0];
        assert_eq!(tool.kind, Kind::Tool);
        assert_eq!(tool.parent_id, Some(turn_span_id(trace(), 0)));
        // The redacted result is in output + summary.
        let out = tool.output.as_ref().unwrap().as_str().unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "leaked tool result: {out}");
    }
}
