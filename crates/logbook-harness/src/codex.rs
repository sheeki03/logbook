//! Codex adapter (plan "Phase 2", Codex row) — **best-effort** normalization of
//! Codex's own JSONL session/rollout records.
//!
//! Codex (the OpenAI coding CLI) writes a JSONL rollout where each line is a
//! record with a `type` discriminator. This adapter recognizes the common
//! shapes and is deliberately tolerant — drift is contained here and a record it
//! doesn't understand is skipped (empty `Vec`):
//!
//! | Record `type` | Event |
//! |---|---|
//! | `message` / `user_message` with `role:"user"` | [`Kind::Agent`] user prompt, redacted text in `input` |
//! | `message` / `assistant_message` with `role:"assistant"` | [`Kind::Llm`] step (model/tokens/finish_reason) |
//! | `function_call` / `tool_call` | [`Kind::Tool`] (redacted `arguments`, `is_write`), `parent_id` → turn span |
//! | `function_call_output` / `tool_result` | [`Kind::Tool`] with the redacted result in `output` |
//!
//! Every event shares the session [`TraceId`], parents to its turn span
//! ([`crate::turn_span_id`]), and is stamped with `harness_version`.

use serde_json::Value;

use logbook_core::{
    truncate_with_ellipsis, AgentBlock, Category, Event, Kind, LlmBlock, Status, ToolBlock,
    TraceId,
};

use crate::context::HarnessContext;
use crate::{class, turn_span_id, HarnessAdapter};

/// The Codex adapter.
#[derive(Debug)]
pub struct CodexAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
}

/// Codex/shell tool names considered mutating.
const WRITE_TOOLS: &[&str] = &[
    "shell", "bash", "exec", "apply_patch", "applypatch", "write", "edit", "create_file",
    "patch", "str_replace",
];

impl CodexAdapter {
    /// Stable harness name.
    pub const NAME: &'static str = "codex";
    /// `agent` label.
    pub const AGENT: &'static str = "codex";

    /// Build the adapter for a session `trace` with a redaction + policy
    /// [`HarnessContext`] and the `harness_version` stamped on each event.
    #[must_use]
    pub fn new(trace: TraceId, ctx: HarnessContext, harness_version: impl Into<String>) -> Self {
        // Attacker-controlled: scrub through the secrets floor + length cap
        // before it is stamped on every event (redaction-before-persistence).
        let harness_version = ctx.scrub_metadata(&harness_version.into(), crate::HARNESS_VERSION_MAX);
        Self {
            trace,
            ctx,
            harness_version,
        }
    }

    /// Convenience: default recorder-on policy + enabled redactor.
    #[must_use]
    pub fn with_defaults(trace: TraceId, harness_version: impl Into<String>) -> Self {
        Self::new(trace, HarnessContext::with_defaults(), harness_version)
    }

    fn base(&self, kind: Kind, type_: &str) -> Event {
        Event::new(self.trace, kind, Category::Agent, type_)
            .with_attr("harness_version", self.harness_version.clone())
            .with_attr("harness", Self::NAME)
    }

    fn is_write_tool(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        WRITE_TOOLS.iter().any(|w| lower == *w)
    }

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
                // Codex `arguments` is often a JSON string; redact as a string if
                // so, else as structured JSON. Either way it is force-redacted
                // AND byte-capped.
                let (red_args, truncated) = self.redact_arguments(args);
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
        if let Some((red, truncated)) = redacted_result {
            ev.output = Some(Value::String(red));
            if truncated {
                ev = ev.with_attr("output_truncated", true);
            }
        }
        ev
    }

    /// Redact tool arguments that may be either a JSON string or a structured
    /// value, returning `(value, truncated)`. A JSON string is
    /// parsed-then-redacted-then-restored as a string; a structured value is
    /// redacted in place. In **all** cases the redacted form is byte-capped to
    /// the `tool_args` bound (force-redact + 64 KiB cap), so an oversized blob is
    /// never stored uncapped.
    fn redact_arguments(&self, args: &Value) -> (Value, bool) {
        if let Value::String(s) = args {
            // Try to parse the embedded JSON; if it parses, redact structurally,
            // re-stringify so the shape (and key names) survive, then cap the
            // serialized string.
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                let red = self.ctx.redact_json(class::TOOL_ARGS, &parsed);
                let serialized = serde_json::to_string(&red).unwrap_or_default();
                let (capped, _orig, truncated) =
                    self.ctx.policy().cap_body(class::TOOL_ARGS, &serialized);
                return (Value::String(capped.into_owned()), truncated);
            }
            // A non-JSON string: redact + cap as text (already byte-capped).
            let (red, truncated) = self.ctx.redact_text(class::TOOL_ARGS, s);
            return (Value::String(red), truncated);
        }
        // A structured value: force-redact + cap via the shared helper.
        self.ctx.redact_tool_args(args)
    }

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
        let llm = if self.ctx.captures(class::MODEL_METADATA) {
            LlmBlock {
                provider: Some("openai".to_string()),
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
        self.base(Kind::Llm, "llm.completion")
            .with_parent(parent)
            .with_op("completion")
            .with_name(model.unwrap_or("assistant").to_string())
            .with_status(Status::Ok)
            .with_attr("turn", turn)
            .with_llm(llm)
    }
}

impl HarnessAdapter for CodexAdapter {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn parse_record(&self, raw: &Value) -> Vec<Event> {
        // Codex records discriminate on `type` (sometimes `record_type`). A
        // turn hint may be present as `turn`.
        let ty = raw
            .get("type")
            .or_else(|| raw.get("record_type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let turn = raw.get("turn").and_then(Value::as_u64).unwrap_or(0);

        match ty {
            "message" | "user_message" | "assistant_message" => {
                let role = raw
                    .get("role")
                    .and_then(Value::as_str)
                    .or(match ty {
                        "user_message" => Some("user"),
                        "assistant_message" => Some("assistant"),
                        _ => None,
                    })
                    .unwrap_or("");
                match role {
                    "user" => {
                        let text = codex_text(raw);
                        if text.is_empty() {
                            return Vec::new();
                        }
                        vec![self.user_prompt_event(&text, turn)]
                    }
                    "assistant" => {
                        let model = raw
                            .get("model")
                            .and_then(Value::as_str);
                        let (input_tokens, output_tokens) = codex_usage(raw);
                        let finish = raw
                            .get("finish_reason")
                            .or_else(|| raw.get("stop_reason"))
                            .and_then(Value::as_str);
                        let cost = raw.get("cost_usd").and_then(Value::as_f64);
                        vec![self.llm_event(
                            model,
                            input_tokens,
                            output_tokens,
                            cost,
                            finish,
                            turn,
                        )]
                    }
                    _ => Vec::new(),
                }
            }
            "function_call" | "tool_call" => {
                let Some(name) = raw
                    .get("name")
                    .or_else(|| raw.get("tool_name"))
                    .and_then(Value::as_str)
                else {
                    return Vec::new();
                };
                let args = raw.get("arguments").or_else(|| raw.get("input"));
                let id = raw
                    .get("call_id")
                    .or_else(|| raw.get("id"))
                    .and_then(Value::as_str);
                vec![self.tool_event(name, args, None, id, turn)]
            }
            "function_call_output" | "tool_result" | "tool_output" => {
                let id = raw
                    .get("call_id")
                    .or_else(|| raw.get("id"))
                    .and_then(Value::as_str);
                let result = raw
                    .get("output")
                    .or_else(|| raw.get("result"))
                    .or_else(|| raw.get("content"))
                    .map(codex_stringify);
                let name = raw
                    .get("name")
                    .or_else(|| raw.get("tool_name"))
                    .and_then(Value::as_str)
                    .unwrap_or("tool_result");
                vec![self.tool_event(name, None, result.as_deref(), id, turn)]
            }
            _ => Vec::new(),
        }
    }
}

/// Pull a user message's text out of a Codex record. Handles `content` as a
/// string, an array of `{type:..,text:..}`/`{type:input_text,text:..}` blocks,
/// or a `text` field.
fn codex_text(raw: &Value) -> String {
    if let Some(t) = raw.get("text").and_then(Value::as_str) {
        return t.to_string();
    }
    match raw.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => {
            let mut parts = Vec::new();
            for b in arr {
                if let Some(t) = b.get("text").and_then(Value::as_str) {
                    parts.push(t.to_string());
                } else if let Value::String(s) = b {
                    parts.push(s.clone());
                }
            }
            parts.join("\n")
        }
        _ => String::new(),
    }
}

/// Extract `(input_tokens, output_tokens)` from a Codex assistant record, looking
/// under `usage` with either OpenAI (`prompt_tokens`/`completion_tokens`) or
/// Anthropic-style (`input_tokens`/`output_tokens`) keys.
fn codex_usage(raw: &Value) -> (Option<u64>, Option<u64>) {
    let usage = raw.get("usage");
    let get = |k: &str| usage.and_then(|u| u.get(k)).and_then(Value::as_u64);
    let input = get("input_tokens").or_else(|| get("prompt_tokens"));
    let output = get("output_tokens").or_else(|| get("completion_tokens"));
    (input, output)
}

/// Stringify a Codex result value (string, array, or object) for redaction.
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
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0x01,
        ])
    }

    fn adapter() -> CodexAdapter {
        CodexAdapter::with_defaults(trace(), "codex-0.9")
    }

    #[test]
    fn golden_codex_turn_normalizes_prompt_llm_tool() {
        let a = adapter();

        // user prompt
        let user = serde_json::json!({
            "type": "message",
            "role": "user",
            "turn": 0,
            "content": [{ "type": "input_text", "text": "run the build, token sk-ant-abc123DEF456ghi789JKL" }]
        });
        let evs = a.parse_record(&user);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, Kind::Agent);
        assert_eq!(evs[0].blocks.agent.as_ref().unwrap().role.as_deref(), Some("user"));
        let input = evs[0].input.as_ref().unwrap().as_str().unwrap();
        assert!(!input.contains("sk-ant-abc123DEF456ghi789JKL"), "leaked: {input}");
        assert!(input.contains("REDACTED:CLOUD_KEY:"));

        // assistant message with usage
        let asst = serde_json::json!({
            "type": "assistant_message",
            "turn": 0,
            "model": "gpt-5-codex",
            "finish_reason": "tool_calls",
            "usage": { "prompt_tokens": 200, "completion_tokens": 30 }
        });
        let evs = a.parse_record(&asst);
        assert_eq!(evs.len(), 1);
        let llm = &evs[0];
        assert_eq!(llm.kind, Kind::Llm);
        let l = llm.blocks.llm.as_ref().unwrap();
        assert_eq!(l.model.as_deref(), Some("gpt-5-codex"));
        assert_eq!(l.input_tokens, Some(200));
        assert_eq!(l.output_tokens, Some(30));
        assert_eq!(l.finish_reason.as_deref(), Some("tool_calls"));
        assert_eq!(l.provider.as_deref(), Some("openai"));
        assert_eq!(llm.parent_id, Some(turn_span_id(trace(), 0)));

        // function call (arguments as a JSON string, with a planted secret)
        let call = serde_json::json!({
            "type": "function_call",
            "turn": 0,
            "name": "shell",
            "call_id": "call_1",
            "arguments": "{\"command\":\"deploy --key AKIAIOSFODNN7EXAMPLE\"}"
        });
        let evs = a.parse_record(&call);
        assert_eq!(evs.len(), 1);
        let tool = &evs[0];
        assert_eq!(tool.kind, Kind::Tool);
        let t = tool.blocks.tool.as_ref().unwrap();
        assert_eq!(t.tool_name.as_deref(), Some("shell"));
        assert_eq!(t.is_write, Some(true), "shell is a write tool");
        let args_s = serde_json::to_string(t.arguments.as_ref().unwrap()).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "leaked in args: {args_s}");
        // HIERARCHY: parents to the same turn span as the prompt/llm.
        assert_eq!(tool.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(
            tool.attributes.get("tool_call_id").and_then(Value::as_str),
            Some("call_1")
        );

        // function_call_output → result on a tool event
        let out = serde_json::json!({
            "type": "function_call_output",
            "turn": 0,
            "call_id": "call_1",
            "output": "deployed ok"
        });
        let evs = a.parse_record(&out);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, Kind::Tool);
        assert!(evs[0].output.is_some());
        assert_eq!(evs[0].parent_id, Some(turn_span_id(trace(), 0)));

        // harness_version stamped.
        assert_eq!(
            tool.attributes.get("harness_version").and_then(Value::as_str),
            Some("codex-0.9")
        );
    }

    #[test]
    fn huge_json_string_args_are_capped_with_marker_and_attr() {
        // Codex sends `arguments` as a JSON string; an oversized one ⇒ capped
        // STRING value + arguments_truncated attribute, secret scrubbed.
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.tool_args.max_bytes = Some(128);
                p
            },
            true,
        );
        let a = CodexAdapter::new(trace(), ctx, "codex-1");
        let big = "W".repeat(50_000);
        let raw_args = format!("{{\"command\":\"deploy AKIAIOSFODNN7EXAMPLE {big}\"}}");
        let evs = a.parse_record(&serde_json::json!({
            "type": "function_call",
            "name": "shell",
            "call_id": "c1",
            "arguments": raw_args
        }));
        assert_eq!(evs.len(), 1);
        let tool = &evs[0];
        assert_eq!(
            tool.attributes.get("arguments_truncated").and_then(Value::as_bool),
            Some(true),
            "arguments_truncated must be set on oversized codex args"
        );
        let s = tool.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap().as_str().unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: head={:.60}", s);
        assert!(s.contains("[diff truncated"), "marker missing");
        assert!(s.len() <= 128 + 64, "not bounded: {} bytes", s.len());
    }

    #[test]
    fn hostile_harness_version_is_scrubbed_and_capped() {
        let hostile = format!("c {} AKIAIOSFODNN7EXAMPLE", "p".repeat(300));
        let a = CodexAdapter::with_defaults(trace(), hostile);
        let evs = a.parse_record(&serde_json::json!({
            "type": "message", "role": "user", "content": "hi"
        }));
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {v}");
        assert!(v.len() <= 64 + 3, "not capped: {} bytes", v.len());
    }

    #[test]
    fn unknown_codex_record_is_skipped() {
        let a = adapter();
        assert!(a.parse_record(&serde_json::json!({"type": "session_meta"})).is_empty());
        assert!(a.parse_record(&serde_json::json!({"nope": 1})).is_empty());
    }
}
