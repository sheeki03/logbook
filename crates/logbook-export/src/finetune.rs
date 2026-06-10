//! Fine-tuning export (plan "Phase 2 — Fine-tuning export (payload-gated)").
//!
//! The other export targets in this crate are **span**-oriented: each [`Event`]
//! is lowered to one [`CanonicalSpan`](crate::CanonicalSpan) and re-keyed into an
//! OTLP/OpenInference/Langfuse/MLflow span. A fine-tuning dataset is a different
//! shape entirely — it is **conversation-shaped**: one chat record per trace,
//! each a list of `{role, content}` turns. So this module is a **distinct path**
//! that does *not* go through [`SpanExportAdapter`](crate::SpanExportAdapter); it
//! folds the timeline directly into chat JSONL.
//!
//! # The record schema
//!
//! Events are grouped by [`Event::trace_id`], ordered by [`Event::timestamp`],
//! and each trace becomes **one JSONL line**:
//!
//! ```jsonc
//! // include_payloads = true (bodies emitted; already-redacted)
//! {"messages":[{"role":"user","content":"…"},{"role":"assistant","content":"…"}],
//!  "source":"cursor","model":"claude-3.5-sonnet","trace_id":"<32-hex>"}
//!
//! // include_payloads = false (DEFAULT — metadata/structure only, NO bodies)
//! {"messages":[{"role":"user","redacted_chars":42},{"role":"assistant","redacted_chars":17}],
//!  "source":"cursor","model":"claude-3.5-sonnet","trace_id":"<32-hex>"}
//! ```
//!
//! - **`messages`** — the conversation turns. `user` content comes from
//!   [`Kind::Agent`] role=`"user"` events (their `input`); `assistant` content
//!   from [`Kind::Agent`] role=`"assistant"` events (their `output`).
//! - **`source`** — the agent/tool that produced the trace (the `harness`
//!   attribute, else the [`AgentBlock::agent`] label), e.g. `cursor`, `claude`,
//!   `codex`. Omitted when unknown.
//! - **`model`** — model attribution, contributed by [`Kind::Llm`] events. These
//!   metadata-only LLM events (model/tokens, **no text body**) are otherwise
//!   **skipped** — they never produce an empty assistant turn. Omitted when no
//!   LLM event named a model.
//! - **`trace_id`** — the 32-hex trace id, so a record is traceable back to the
//!   timeline.
//! - **`tools`** — present only when [`FinetuneOptions::include_tools`] is set: a
//!   separate array of `{name, is_write, arguments?, result_summary?}` tool-call
//!   objects. Tool calls are **never** folded into message `content`.
//!
//! Messages whose content is empty are dropped, and a trace that folds to zero
//! messages emits no line at all.
//!
//! # Safety: payloads are opt-in (plan §"Secrets vs IP")
//!
//! Every event here is **already** secrets-floored (redaction runs upstream at
//! capture, before persistence). But **redaction ≠ "safe to train on"**: the
//! floor scrubs secrets (API keys, tokens) *by construction*; it does **not**
//! scrub intellectual property — proprietary source code, internal file paths,
//! and private prompts survive redaction intact. So emitting message bodies is
//! **explicit opt-in** via [`FinetuneOptions::include_payloads`] (default
//! `false`). With it off, only metadata/structure is emitted (role + a
//! `redacted_chars` length placeholder), never the bodies themselves.

use std::collections::BTreeMap;

use logbook_core::{Event, Kind};
use serde_json::{json, Map, Value};

/// Options controlling the fine-tuning export, centred on the **payload safety
/// gate**.
///
/// The defaults are the safe ones: no bodies, no tool schema. A caller must opt
/// in to each. See the [module docs](self) for why payloads are gated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinetuneOptions {
    /// Emit the (already-redacted) message bodies as `content`. Defaults to
    /// `false` → metadata/structure only (role + a `redacted_chars` placeholder),
    /// because "redacted" is **not** the same as "safe to train on": proprietary
    /// code, file paths, and private prompts remain after secret redaction. The
    /// CLI prints a stderr warning when this is enabled.
    pub include_payloads: bool,
    /// Emit a separate `tools` array of tool-call objects per record. Defaults to
    /// `false`. Tool arguments/results are themselves payloads, so they are only
    /// emitted as bodies when [`FinetuneOptions::include_payloads`] is *also* set;
    /// otherwise the tool schema carries name/`is_write`/length metadata only.
    pub include_tools: bool,
}

/// Fold a slice of (already-redacted) timeline [`Event`]s into chat JSONL — one
/// conversation record per trace, ordered by timestamp.
///
/// The returned string is newline-terminated JSONL: each line is one trace's
/// `{"messages":[…], "source":…, "model"?:…, "trace_id":…, "tools"?:[…]}`
/// record (see the [module docs](self) for the full schema and the
/// payload-on/off forms). Traces are emitted in ascending earliest-timestamp
/// order so the dataset reads in timeline order; an empty input (or every trace
/// folding to zero messages) yields an empty string.
///
/// Honors the [`FinetuneOptions`] safety gate: with `include_payloads` off no
/// message bodies are emitted, only role + a `redacted_chars` length placeholder.
#[must_use]
pub fn events_to_finetune_jsonl(events: &[Event], opts: FinetuneOptions) -> String {
    // Group by trace, preserving a stable cross-trace order. We key the grouping
    // map on the hex trace id and remember each group's earliest timestamp so the
    // final ordering is deterministic (earliest trace first), independent of the
    // input order.
    let mut groups: BTreeMap<String, Vec<&Event>> = BTreeMap::new();
    for ev in events {
        groups
            .entry(ev.trace_id.to_hex())
            .or_default()
            .push(ev);
    }

    // Order traces by their earliest event timestamp (then hex for a total order),
    // and each trace's events by timestamp (then a stable tiebreak on the event id
    // so a re-export of the same store is byte-identical).
    let mut ordered: Vec<(String, Vec<&Event>)> = groups.into_iter().collect();
    ordered.sort_by(|a, b| {
        let ka = earliest_ts(&a.1);
        let kb = earliest_ts(&b.1);
        ka.cmp(&kb).then_with(|| a.0.cmp(&b.0))
    });

    let mut out = String::new();
    for (trace_hex, mut group) in ordered {
        group.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.id.as_str().cmp(b.id.as_str()))
        });
        if let Some(record) = fold_trace(&trace_hex, &group, opts) {
            // serde_json::to_string never fails for a Value built from owned data.
            if let Ok(line) = serde_json::to_string(&record) {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
    out
}

/// The earliest timestamp in a (non-empty) group, for cross-trace ordering.
fn earliest_ts(group: &[&Event]) -> i64 {
    group
        .iter()
        .map(|e| e.timestamp.as_micros())
        .min()
        .unwrap_or(i64::MAX)
}

/// Fold one trace's (timestamp-ordered) events into a single chat record, or
/// `None` if it yields no messages.
fn fold_trace(trace_hex: &str, group: &[&Event], opts: FinetuneOptions) -> Option<Value> {
    let mut messages: Vec<Value> = Vec::new();
    let mut tools: Vec<Value> = Vec::new();
    let mut model: Option<String> = None;
    let mut source: Option<String> = None;

    for ev in group {
        // Source attribution: the first `harness` attribute (else an AgentBlock
        // agent label) seen on the trace.
        if source.is_none() {
            source = source_of(ev);
        }

        // Metadata-only LLM events (model/tokens, no text body) MUST NOT become
        // empty assistant turns; they only contribute model attribution. Capture
        // the first non-empty model named on the trace; the event produces no
        // message regardless.
        if model.is_none() && ev.kind == Kind::Llm {
            model = ev
                .blocks
                .llm
                .as_ref()
                .and_then(|l| l.model.clone())
                .filter(|m| !m.is_empty());
        }

        match ev.kind {
            Kind::Agent => {
                if let Some(msg) = agent_message(ev, opts) {
                    messages.push(msg);
                }
            }
            Kind::Tool if opts.include_tools => {
                if let Some(t) = tool_object(ev, opts) {
                    tools.push(t);
                }
            }
            // Llm contributes only the model attribution captured above; any
            // other kind (Log, Browser, Network, Finding, Test, Span, Other) is
            // not part of the conversation surface — skip.
            _ => {}
        }
    }

    if messages.is_empty() {
        return None;
    }

    let mut record = Map::new();
    record.insert("messages".to_string(), Value::Array(messages));
    if let Some(source) = source {
        record.insert("source".to_string(), Value::String(source));
    }
    if let Some(model) = model {
        record.insert("model".to_string(), Value::String(model));
    }
    record.insert("trace_id".to_string(), Value::String(trace_hex.to_string()));
    if opts.include_tools {
        record.insert("tools".to_string(), Value::Array(tools));
    }
    Some(Value::Object(record))
}

/// The source/agent label for an event: the `harness` attribute (set by the
/// import + live adapters), falling back to the [`AgentBlock::agent`] label.
fn source_of(ev: &Event) -> Option<String> {
    if let Some(h) = ev.attributes.get("harness").and_then(Value::as_str) {
        if !h.is_empty() {
            return Some(h.to_string());
        }
    }
    ev.blocks
        .agent
        .as_ref()
        .and_then(|a| a.agent.clone())
        .filter(|a| !a.is_empty())
}

/// Build a chat message from a [`Kind::Agent`] event, honoring the payload gate.
///
/// The role comes from the [`AgentBlock`](logbook_core::AgentBlock) (`user` →
/// `input`, `assistant` → `output`); any other role is skipped. When the
/// resolved body is empty the message is dropped. With `include_payloads` off the
/// body is replaced by a `redacted_chars` length placeholder (no content key).
fn agent_message(ev: &Event, opts: FinetuneOptions) -> Option<Value> {
    let role = ev.blocks.agent.as_ref().and_then(|a| a.role.as_deref())?;
    let body = match role {
        "user" => payload_text(ev.input.as_ref()),
        "assistant" => payload_text(ev.output.as_ref()),
        // system / tool / unknown roles are not part of the user↔assistant
        // fine-tuning surface; skip.
        _ => return None,
    };
    let body = body?;
    if body.is_empty() {
        // Drop messages whose content is empty (an empty turn is noise and would
        // never have been emitted by the adapter for a body-less event anyway).
        return None;
    }

    let mut msg = Map::new();
    msg.insert("role".to_string(), Value::String(role.to_string()));
    if opts.include_payloads {
        msg.insert("content".to_string(), Value::String(body));
    } else {
        // Metadata/structure only: keep the shape + length, never the body.
        msg.insert("redacted_chars".to_string(), json!(body.chars().count()));
    }
    Some(Value::Object(msg))
}

/// Extract a body string from an `input`/`output` payload [`Value`]. A JSON
/// string is taken verbatim; any other JSON value is compactly serialized (the
/// adapters store bodies as strings, but a structured body still folds losslessly
/// so nothing is silently dropped).
fn payload_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => serde_json::to_string(other).ok(),
    }
}

/// Build a tool-call object from a [`Kind::Tool`] event for the optional `tools`
/// array. Carries the tool name + `is_write` always; arguments and the result
/// summary are payloads, so they are emitted as bodies only when
/// `include_payloads` is set, otherwise as length metadata.
fn tool_object(ev: &Event, opts: FinetuneOptions) -> Option<Value> {
    let tb = ev.blocks.tool.as_ref()?;
    let mut obj = Map::new();
    obj.insert(
        "name".to_string(),
        Value::String(tb.tool_name.clone().unwrap_or_else(|| "tool".to_string())),
    );
    if let Some(is_write) = tb.is_write {
        obj.insert("is_write".to_string(), Value::Bool(is_write));
    }

    if opts.include_payloads {
        if let Some(args) = tb.arguments.clone() {
            obj.insert("arguments".to_string(), args);
        }
        if let Some(summary) = tb.result_summary.clone() {
            obj.insert("result_summary".to_string(), Value::String(summary));
        }
    } else {
        // Structure only: how many argument keys + result length, no bodies.
        if let Some(args) = tb.arguments.as_ref() {
            let n = match args {
                Value::Object(m) => m.len(),
                Value::Array(a) => a.len(),
                _ => 0,
            };
            obj.insert("arguments_len".to_string(), json!(n));
        }
        if let Some(summary) = tb.result_summary.as_ref() {
            obj.insert("result_chars".to_string(), json!(summary.chars().count()));
        }
    }
    Some(Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{
        AgentBlock, Category, LlmBlock, MicrosTimestamp, ToolBlock, TraceId,
    };

    /// The planted secret: present pre-redaction, must never appear in output.
    const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

    fn trace(seed: u8) -> TraceId {
        let mut b = [0u8; 16];
        b[15] = seed;
        b[0] = 0xab;
        TraceId::from_bytes(b)
    }

    /// A user agent event whose redacted body is `text` (mimics what the Cursor
    /// adapter stores: a `Kind::Agent` role="user" with the body in `input`).
    fn user_event(trace: TraceId, ts: i64, text: &str) -> Event {
        let mut ev = Event::new(trace, Kind::Agent, Category::Agent, "agent.user_prompt")
            .with_agent(AgentBlock {
                agent: Some("cursor".into()),
                role: Some("user".into()),
                ..Default::default()
            })
            .with_attr("harness", "cursor");
        ev.timestamp = MicrosTimestamp(ts);
        ev.input = Some(Value::String(text.to_string()));
        ev
    }

    /// An assistant agent event whose redacted body is `text`, in `output`.
    fn assistant_event(trace: TraceId, ts: i64, text: &str) -> Event {
        let mut ev = Event::new(trace, Kind::Agent, Category::Agent, "agent.message")
            .with_agent(AgentBlock {
                agent: Some("cursor".into()),
                role: Some("assistant".into()),
                ..Default::default()
            })
            .with_attr("harness", "cursor");
        ev.timestamp = MicrosTimestamp(ts);
        ev.output = Some(Value::String(text.to_string()));
        ev
    }

    /// A metadata-only LLM event: model + tokens, NO text body. This must never
    /// produce an empty assistant message.
    fn llm_meta_event(trace: TraceId, ts: i64, model: &str) -> Event {
        let mut ev = Event::new(trace, Kind::Llm, Category::Agent, "llm.completion")
            .with_llm(LlmBlock {
                model: Some(model.to_string()),
                input_tokens: Some(120),
                output_tokens: Some(45),
                ..Default::default()
            });
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    /// A tool event with redacted args + result summary.
    fn tool_event(trace: TraceId, ts: i64) -> Event {
        let mut ev = Event::new(trace, Kind::Tool, Category::Agent, "tool.call")
            .with_tool(ToolBlock {
                tool_name: Some("edit_file".into()),
                is_write: Some(true),
                arguments: Some(json!({ "path": "/app/main.rs" })),
                result_summary: Some("applied 1 edit".into()),
            });
        ev.timestamp = MicrosTimestamp(ts);
        ev.output = Some(Value::String("applied 1 edit".into()));
        ev
    }

    /// Build two traces, each: user + assistant + metadata-only LLM + tool.
    /// Redaction has already run, so bodies carry the placeholder, NOT the raw
    /// secret (we assert on the already-redacted bodies — the secret is absent).
    fn two_traces() -> Vec<Event> {
        let t1 = trace(1);
        let t2 = trace(2);
        // Bodies as they exist post-redaction: secret replaced by a placeholder.
        let redacted_user = "deploy with [REDACTED:CLOUD_KEY] please";
        vec![
            // Trace 1 (earlier timestamps).
            user_event(t1, 1_000, redacted_user),
            llm_meta_event(t1, 1_100, "claude-3.5-sonnet"),
            assistant_event(t1, 1_200, "Editing the file now."),
            tool_event(t1, 1_300),
            // Trace 2 (later timestamps), inserted out of order on purpose.
            tool_event(t2, 2_300),
            assistant_event(t2, 2_200, "Done."),
            llm_meta_event(t2, 2_100, "gpt-4o"),
            user_event(t2, 2_000, "ship it"),
        ]
    }

    #[test]
    fn one_line_per_trace_with_correct_order_and_roles() {
        let events = two_traces();
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: false,
            },
        );
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2, "one JSONL line per trace: {jsonl}");

        // Trace 1 sorts first (earliest ts). Parse and check ordering + roles.
        let r1: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(r1["trace_id"], json!(trace(1).to_hex()));
        assert_eq!(r1["source"], json!("cursor"));
        assert_eq!(r1["model"], json!("claude-3.5-sonnet"));
        let msgs = r1["messages"].as_array().unwrap();
        // Exactly two messages: the metadata-only LLM produced NO assistant turn.
        assert_eq!(msgs.len(), 2, "metadata-only LLM must not add a turn: {msgs:?}");
        assert_eq!(msgs[0]["role"], json!("user"));
        assert_eq!(msgs[1]["role"], json!("assistant"));

        // Trace 2 second, with its own model.
        let r2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r2["trace_id"], json!(trace(2).to_hex()));
        assert_eq!(r2["model"], json!("gpt-4o"));
        let msgs2 = r2["messages"].as_array().unwrap();
        assert_eq!(msgs2.len(), 2);
        assert_eq!(msgs2[0]["role"], json!("user"));
        assert_eq!(msgs2[1]["role"], json!("assistant"));
    }

    #[test]
    fn metadata_only_llm_produces_no_empty_assistant_message() {
        // A trace that is ONLY a user turn + a metadata-only LLM: it must fold to
        // exactly one (user) message — never an empty assistant turn.
        let t = trace(7);
        let events = vec![
            user_event(t, 10, "hello"),
            llm_meta_event(t, 20, "some-model"),
        ];
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: false,
            },
        );
        let r: Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        let msgs = r["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1, "only the user turn: {msgs:?}");
        assert_eq!(msgs[0]["role"], json!("user"));
        // The model attribution still rides along on the record.
        assert_eq!(r["model"], json!("some-model"));
        // No assistant turn anywhere.
        assert!(
            !msgs.iter().any(|m| m["role"] == json!("assistant")),
            "no assistant message should exist: {msgs:?}"
        );
    }

    #[test]
    fn planted_secret_never_appears() {
        // Sanity: had the secret survived into a body, it would show in the JSONL.
        // The events carry already-redacted bodies, so it must be absent — with
        // payloads ON (bodies present) and the secret nowhere in them.
        let t = trace(3);
        let redacted = "use [REDACTED:CLOUD_KEY] now"; // post-redaction form
        let events = vec![
            user_event(t, 1, redacted),
            assistant_event(t, 2, "ok, [REDACTED:CLOUD_KEY] applied"),
        ];
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: true,
            },
        );
        assert!(
            !jsonl.contains(SECRET),
            "the raw secret must never appear in the export: {jsonl}"
        );
    }

    #[test]
    fn payloads_off_emits_no_bodies() {
        let events = two_traces();
        let jsonl = events_to_finetune_jsonl(&events, FinetuneOptions::default());
        // Default is payloads OFF.
        assert!(!FinetuneOptions::default().include_payloads);

        // No body text at all — the assistant body string must not be present.
        assert!(
            !jsonl.contains("Editing the file now."),
            "bodies must not be emitted with payloads off: {jsonl}"
        );
        assert!(!jsonl.contains(SECRET));

        // Structure survives: each message has a role + a redacted_chars
        // placeholder and NO content key.
        let r1: Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        let msgs = r1["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        for m in msgs {
            assert!(m.get("content").is_none(), "no content with payloads off: {m}");
            assert!(m.get("redacted_chars").is_some(), "length placeholder present: {m}");
        }
        // Model attribution (metadata, not a body) is still useful and emitted.
        assert_eq!(r1["model"], json!("claude-3.5-sonnet"));
        // No tools array when include_tools is off.
        assert!(r1.get("tools").is_none());
    }

    #[test]
    fn payloads_on_emits_bodies() {
        let events = two_traces();
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: false,
            },
        );
        let r1: Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        let msgs = r1["messages"].as_array().unwrap();
        assert_eq!(msgs[1]["content"], json!("Editing the file now."));
        // The already-redacted user body is present verbatim (placeholder, no
        // secret).
        assert_eq!(
            msgs[0]["content"],
            json!("deploy with [REDACTED:CLOUD_KEY] please")
        );
        assert!(msgs[0].get("redacted_chars").is_none());
    }

    #[test]
    fn include_tools_adds_the_tool_schema_separately() {
        let events = two_traces();
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: true,
            },
        );
        let r1: Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        // Tools are a SEPARATE array, not folded into message content.
        let tools = r1["tools"].as_array().expect("tools array present");
        assert_eq!(tools.len(), 1, "one tool call on trace 1: {tools:?}");
        assert_eq!(tools[0]["name"], json!("edit_file"));
        assert_eq!(tools[0]["is_write"], json!(true));
        // Args present as a body (payloads on); summary too.
        assert_eq!(tools[0]["arguments"], json!({ "path": "/app/main.rs" }));
        assert_eq!(tools[0]["result_summary"], json!("applied 1 edit"));
        // The tool body did NOT leak into a message turn.
        let msgs = r1["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs.iter().all(|m| m["role"] != json!("tool")));
    }

    #[test]
    fn include_tools_with_payloads_off_is_metadata_only() {
        let events = two_traces();
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: false,
                include_tools: true,
            },
        );
        let r1: Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        let tools = r1["tools"].as_array().unwrap();
        assert_eq!(tools[0]["name"], json!("edit_file"));
        // No argument/result bodies; length metadata instead.
        assert!(tools[0].get("arguments").is_none());
        assert!(tools[0].get("result_summary").is_none());
        assert_eq!(tools[0]["arguments_len"], json!(1));
        assert!(tools[0].get("result_chars").is_some());
    }

    #[test]
    fn empty_input_yields_empty_string() {
        assert_eq!(events_to_finetune_jsonl(&[], FinetuneOptions::default()), "");
    }

    #[test]
    fn trace_with_only_metadata_llm_emits_no_line() {
        // No agent messages ⇒ no conversation ⇒ no record.
        let t = trace(9);
        let events = vec![llm_meta_event(t, 5, "m")];
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: true,
            },
        );
        assert_eq!(jsonl, "", "a metadata-only trace folds to no line: {jsonl}");
    }

    #[test]
    fn empty_bodies_are_dropped() {
        // An assistant event whose body is empty must not yield a message.
        let t = trace(11);
        let events = vec![
            user_event(t, 1, "q"),
            assistant_event(t, 2, ""),
        ];
        let jsonl = events_to_finetune_jsonl(
            &events,
            FinetuneOptions {
                include_payloads: true,
                include_tools: false,
            },
        );
        let r: Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        let msgs = r["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1, "empty assistant body dropped: {msgs:?}");
        assert_eq!(msgs[0]["role"], json!("user"));
    }

    #[test]
    fn deterministic_across_reexport() {
        // A re-export of the same events is byte-identical (stable ordering).
        let events = two_traces();
        let opts = FinetuneOptions {
            include_payloads: true,
            include_tools: true,
        };
        let a = events_to_finetune_jsonl(&events, opts);
        let b = events_to_finetune_jsonl(&events, opts);
        assert_eq!(a, b);
    }
}
