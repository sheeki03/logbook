//! Aider adapter (plan "Phase 2", Aider row) — **best-effort** normalization of
//! Aider's own record shapes.
//!
//! Aider keeps its chat as markdown history, but its in-memory message log and
//! analytics stream are JSON-shaped. This adapter handles the two JSON shapes a
//! collector is most likely to feed it, and skips anything else (empty `Vec`):
//!
//! 1. **Chat messages** — OpenAI-style `{"role":"user"|"assistant","content":…}`
//!    objects (optionally with `model` / `usage` on assistant turns):
//!    - `role:"user"` → [`Kind::Agent`] user prompt (redacted text in `input`);
//!    - `role:"assistant"` → [`Kind::Llm`] step (model/tokens/finish_reason),
//!      and any embedded `tool_calls` → [`Kind::Tool`] events parented to the
//!      turn.
//! 2. **Analytics events** — `{"event":"<name>","properties":{…}}`. A
//!    `message_send` / `model_response` event maps to a [`Kind::Llm`] step using
//!    the `properties` (model, token counts); others are skipped.
//!
//! Every event shares the session [`TraceId`], parents to its turn span
//! ([`crate::turn_span_id`]), and is stamped with `harness_version`.

use serde_json::Value;

use logbook_core::{
    AgentBlock, Category, Event, Kind, LlmBlock, Status, ToolBlock, TraceId,
};

use crate::context::HarnessContext;
use crate::{class, turn_span_id, HarnessAdapter};

/// The Aider adapter.
#[derive(Debug)]
pub struct AiderAdapter {
    trace: TraceId,
    ctx: HarnessContext,
    harness_version: String,
}

/// Tool names Aider/its shells treat as mutating.
const WRITE_TOOLS: &[&str] = &[
    "run", "shell", "bash", "edit", "write", "create", "apply_edit", "replace", "diff_edit",
];

impl AiderAdapter {
    /// Stable harness name.
    pub const NAME: &'static str = "aider";
    /// `agent` label.
    pub const AGENT: &'static str = "aider";

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
                // Force-redact AND byte-cap tool args; an over-cap blob is stored
                // as a bounded string rather than uncapped structure.
                let (red_args, truncated) = self.redact_arguments(args);
                tool.arguments = Some(red_args);
                args_truncated = truncated;
            }
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
        ev
    }

    /// Redact tool arguments that may be a JSON string or structured value
    /// (Aider follows the OpenAI function-call convention where `arguments` is a
    /// JSON string), returning `(value, truncated)`. In all cases the redacted
    /// form is byte-capped to the `tool_args` bound (force-redact + 64 KiB cap).
    fn redact_arguments(&self, args: &Value) -> (Value, bool) {
        if let Value::String(s) = args {
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                let red = self.ctx.redact_json(class::TOOL_ARGS, &parsed);
                let serialized = serde_json::to_string(&red).unwrap_or_default();
                let (capped, _orig, truncated) =
                    self.ctx.policy().cap_body(class::TOOL_ARGS, &serialized);
                return (Value::String(capped.into_owned()), truncated);
            }
            let (red, truncated) = self.ctx.redact_text(class::TOOL_ARGS, s);
            return (Value::String(red), truncated);
        }
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

    /// Parse an OpenAI-style chat message record.
    fn parse_chat_message(&self, raw: &Value, role: &str, turn: u64) -> Vec<Event> {
        match role {
            "user" => {
                let text = message_text(raw);
                if text.is_empty() {
                    return Vec::new();
                }
                vec![self.user_prompt_event(&text, turn)]
            }
            "assistant" => {
                let mut out = Vec::new();
                let model = raw.get("model").and_then(Value::as_str);
                let (input_tokens, output_tokens) = usage_tokens(raw.get("usage"));
                let finish = raw
                    .get("finish_reason")
                    .or_else(|| raw.get("stop_reason"))
                    .and_then(Value::as_str);
                let cost = raw.get("cost").or_else(|| raw.get("cost_usd")).and_then(Value::as_f64);
                out.push(self.llm_event(model, input_tokens, output_tokens, cost, finish, turn));

                // OpenAI-style tool_calls array on the assistant message.
                if let Some(Value::Array(calls)) = raw.get("tool_calls") {
                    for call in calls {
                        let func = call.get("function").unwrap_or(call);
                        let name = func
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("tool");
                        let args = func.get("arguments");
                        let id = call.get("id").and_then(Value::as_str);
                        out.push(self.tool_event(name, args, id, turn));
                    }
                }
                out
            }
            _ => Vec::new(),
        }
    }
}

impl HarnessAdapter for AiderAdapter {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn parse_record(&self, raw: &Value) -> Vec<Event> {
        let turn = raw.get("turn").and_then(Value::as_u64).unwrap_or(0);

        // Shape 1: an OpenAI-style chat message ({role, content}).
        if let Some(role) = raw.get("role").and_then(Value::as_str) {
            return self.parse_chat_message(raw, role, turn);
        }

        // Shape 2: an analytics event ({event, properties}).
        if let Some(event) = raw.get("event").and_then(Value::as_str) {
            return self.parse_analytics(raw, event, turn);
        }

        Vec::new()
    }
}

impl AiderAdapter {
    /// Parse an Aider analytics event. Only model/response events carry
    /// capturable metadata; everything else is skipped.
    fn parse_analytics(&self, raw: &Value, event: &str, turn: u64) -> Vec<Event> {
        match event {
            "message_send" | "model_response" | "response" | "command_completion" => {
                let props = raw.get("properties").unwrap_or(&Value::Null);
                let model = props.get("main_model").or_else(|| props.get("model")).and_then(Value::as_str);
                let input_tokens = props
                    .get("prompt_tokens")
                    .or_else(|| props.get("input_tokens"))
                    .and_then(Value::as_u64);
                let output_tokens = props
                    .get("completion_tokens")
                    .or_else(|| props.get("output_tokens"))
                    .and_then(Value::as_u64);
                let cost = props.get("cost").and_then(Value::as_f64);
                // Nothing to record if there is no metadata at all.
                if model.is_none() && input_tokens.is_none() && output_tokens.is_none() {
                    return Vec::new();
                }
                vec![self.llm_event(model, input_tokens, output_tokens, cost, None, turn)]
            }
            _ => Vec::new(),
        }
    }
}

/// Extract a chat message's text `content` (string or array-of-blocks).
fn message_text(raw: &Value) -> String {
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

/// `(input, output)` token counts from a `usage` object (OpenAI or Anthropic
/// key names).
fn usage_tokens(usage: Option<&Value>) -> (Option<u64>, Option<u64>) {
    let get = |k: &str| usage.and_then(|u| u.get(k)).and_then(Value::as_u64);
    let input = get("prompt_tokens").or_else(|| get("input_tokens"));
    let output = get("completion_tokens").or_else(|| get("output_tokens"));
    (input, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> TraceId {
        TraceId::from_bytes([
            0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79,
            0x62, 0xdb,
        ])
    }

    fn adapter() -> AiderAdapter {
        AiderAdapter::with_defaults(trace(), "aider-0.66")
    }

    #[test]
    fn golden_aider_chat_turn_normalizes_prompt_llm_tool() {
        let a = adapter();

        // user prompt with a planted JWT.
        let user = serde_json::json!({
            "role": "user",
            "turn": 0,
            "content": "refactor main; my token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigpartHEREok"
        });
        let evs = a.parse_record(&user);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, Kind::Agent);
        assert_eq!(evs[0].blocks.agent.as_ref().unwrap().role.as_deref(), Some("user"));
        let input = evs[0].input.as_ref().unwrap().as_str().unwrap();
        assert!(!input.contains("eyJhbGciOiJIUzI1NiJ9"), "leaked jwt: {input}");
        assert!(input.contains("REDACTED:JWT:"));

        // assistant with usage + a tool call (arguments as JSON string w/ secret).
        let asst = serde_json::json!({
            "role": "assistant",
            "turn": 0,
            "model": "gpt-4o",
            "finish_reason": "tool_calls",
            "usage": { "prompt_tokens": 80, "completion_tokens": 12 },
            "tool_calls": [
                {
                    "id": "call_a",
                    "function": {
                        "name": "run",
                        "arguments": "{\"cmd\":\"deploy AKIAIOSFODNN7EXAMPLE\"}"
                    }
                }
            ]
        });
        let evs = a.parse_record(&asst);
        assert_eq!(evs.len(), 2, "assistant → Llm + Tool");

        let llm = &evs[0];
        assert_eq!(llm.kind, Kind::Llm);
        let l = llm.blocks.llm.as_ref().unwrap();
        assert_eq!(l.model.as_deref(), Some("gpt-4o"));
        assert_eq!(l.input_tokens, Some(80));
        assert_eq!(l.output_tokens, Some(12));
        assert_eq!(l.finish_reason.as_deref(), Some("tool_calls"));
        assert_eq!(llm.parent_id, Some(turn_span_id(trace(), 0)));

        let tool = &evs[1];
        assert_eq!(tool.kind, Kind::Tool);
        let t = tool.blocks.tool.as_ref().unwrap();
        assert_eq!(t.tool_name.as_deref(), Some("run"));
        assert_eq!(t.is_write, Some(true));
        let args_s = serde_json::to_string(t.arguments.as_ref().unwrap()).unwrap();
        assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "leaked in args: {args_s}");
        // HIERARCHY.
        assert_eq!(tool.parent_id, Some(turn_span_id(trace(), 0)));
        assert_eq!(
            tool.attributes.get("tool_call_id").and_then(Value::as_str),
            Some("call_a")
        );
        // harness_version stamped.
        assert_eq!(
            llm.attributes.get("harness_version").and_then(Value::as_str),
            Some("aider-0.66")
        );
    }

    #[test]
    fn golden_aider_analytics_event_maps_to_llm() {
        let a = adapter();
        let ev = serde_json::json!({
            "event": "message_send",
            "turn": 0,
            "properties": {
                "main_model": "claude-3-5-sonnet",
                "prompt_tokens": 150,
                "completion_tokens": 40,
                "cost": 0.002
            }
        });
        let evs = a.parse_record(&ev);
        assert_eq!(evs.len(), 1);
        let llm = &evs[0];
        assert_eq!(llm.kind, Kind::Llm);
        let l = llm.blocks.llm.as_ref().unwrap();
        assert_eq!(l.model.as_deref(), Some("claude-3-5-sonnet"));
        assert_eq!(l.input_tokens, Some(150));
        assert_eq!(l.output_tokens, Some(40));
        assert_eq!(l.cost_usd, Some(0.002));
    }

    #[test]
    fn huge_tool_call_args_are_capped_with_marker_and_attr() {
        // An oversized OpenAI-style tool_call arguments JSON string ⇒ capped
        // STRING + arguments_truncated attribute, secret scrubbed.
        let ctx = HarnessContext::new(
            logbook_core::Redactor::new(),
            {
                let mut p = logbook_core::CapturePolicy::default();
                p.classes.tool_args.max_bytes = Some(128);
                p
            },
            true,
        );
        let a = AiderAdapter::new(trace(), ctx, "aider-1");
        let big = "Q".repeat(50_000);
        let raw_args = format!("{{\"cmd\":\"run AKIAIOSFODNN7EXAMPLE {big}\"}}");
        let evs = a.parse_record(&serde_json::json!({
            "role": "assistant",
            "model": "gpt-4o",
            "tool_calls": [
                { "id": "c1", "function": { "name": "run", "arguments": raw_args } }
            ]
        }));
        assert_eq!(evs.len(), 2, "assistant → Llm + Tool");
        let tool = &evs[1];
        assert_eq!(
            tool.attributes.get("arguments_truncated").and_then(Value::as_bool),
            Some(true),
            "arguments_truncated must be set on oversized aider args"
        );
        let s = tool.blocks.tool.as_ref().unwrap().arguments.as_ref().unwrap().as_str().unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: head={:.60}", s);
        assert!(s.contains("[diff truncated"), "marker missing");
        assert!(s.len() <= 128 + 64, "not bounded: {} bytes", s.len());
    }

    #[test]
    fn hostile_harness_version_is_scrubbed_and_capped() {
        let hostile = format!("a {} AKIAIOSFODNN7EXAMPLE", "r".repeat(300));
        let a = AiderAdapter::with_defaults(trace(), hostile);
        let evs = a.parse_record(&serde_json::json!({
            "role": "user", "content": "hi"
        }));
        let v = evs[0].attributes.get("harness_version").and_then(Value::as_str).unwrap();
        assert!(!v.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {v}");
        assert!(v.len() <= 64 + 3, "not capped: {} bytes", v.len());
    }

    #[test]
    fn unknown_aider_records_are_skipped() {
        let a = adapter();
        // analytics event with no useful metadata.
        assert!(a
            .parse_record(&serde_json::json!({"event": "launch", "properties": {}}))
            .is_empty());
        // a system role we don't model.
        assert!(a
            .parse_record(&serde_json::json!({"role": "system", "content": "you are aider"}))
            .is_empty());
        // junk.
        assert!(a.parse_record(&serde_json::json!({"x": 1})).is_empty());
    }
}
