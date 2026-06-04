//! Deterministic event fixtures shared by the golden tests.
//!
//! The plan (§8) calls for a fixed set of events: an LLM call, a tool call, an
//! app log, a browser network event, a security finding, and an agent action.
//! These must be **fully deterministic** (fixed ids, trace ids, timestamps,
//! durations) so the emitted JSON is byte-stable against the golden fixtures.
//!
//! `Event::new` mints a random id and a `now()` timestamp, so each builder
//! overwrites those with fixed values.

#![allow(dead_code)] // each test binary uses a subset

use logbook_core::{
    AgentBlock, Category, ConsoleBlock, Event, EventId, FindingBlock, Kind, LlmBlock,
    MicrosTimestamp, NetworkBlock, Severity, Status, ToolBlock, TraceId,
};

/// A single fixed trace id all fixtures share, so cross-event correlation is
/// visible in the output (everything is one trace).
pub const TRACE_HEX: &str = "0af7651916cd43dd8448eb211c80319c";

/// A fixed parent span id for the events that hang off the agent turn.
pub const PARENT_SPAN_HEX: &str = "b7ad6b7169203331";

/// 2024-01-02T03:04:05.678Z expressed in microseconds since the UNIX epoch.
/// Used as a base; individual events offset from it so ids/times differ.
pub const BASE_MICROS: i64 = 1_704_164_645_678_000;

fn trace() -> TraceId {
    TRACE_HEX.parse().expect("valid trace hex")
}

/// Apply deterministic identity to an event: fixed id, fixed trace, fixed
/// timestamp. `id_hex` must be 32 lowercase hex chars (trace-width), matching
/// the store's `EventId::generate()` shape.
fn fix(mut ev: Event, id_hex: &str, micros: i64) -> Event {
    ev.id = EventId::new(id_hex);
    ev.trace_id = trace();
    ev.timestamp = MicrosTimestamp(micros);
    ev
}

/// An LLM chat-completion call (root of the trace).
pub fn llm_call() -> Event {
    let mut ev = fix(
        Event::new(trace(), Kind::Llm, Category::Agent, "chat.completion")
            .with_name("anthropic chat")
            .with_status(Status::Ok)
            .with_duration_ms(1234.5)
            .with_llm(LlmBlock {
                provider: Some("anthropic".into()),
                model: Some("claude-3-5-sonnet".into()),
                input_tokens: Some(1200),
                output_tokens: Some(345),
                total_tokens: Some(1545),
                temperature: Some(0.2),
                cost_usd: Some(0.0123),
            }),
        "1111111111111111aaaaaaaaaaaaaaaa",
        BASE_MICROS,
    );
    ev.input = Some(serde_json::json!([{"role": "user", "content": "Summarize the build log."}]));
    ev.output =
        Some(serde_json::json!({"role": "assistant", "content": "The build failed at step 3."}));
    ev
}

/// A tool / function call made by the agent (child of the LLM turn).
pub fn tool_call() -> Event {
    let mut ev = fix(
        Event::new(trace(), Kind::Tool, Category::Agent, "tool.call")
            .with_name("read_file")
            .with_op("call")
            .with_status(Status::Ok)
            .with_duration_ms(12.0)
            .with_tool(ToolBlock {
                tool_name: Some("read_file".into()),
                is_write: Some(false),
                arguments: Some(serde_json::json!({"path": "src/main.rs"})),
            }),
        "2222222222222222bbbbbbbbbbbbbbbb",
        BASE_MICROS + 1_000_000,
    );
    ev.output = Some(serde_json::json!("fn main() { println!(\"hi\"); }"));
    ev.parent_id = Some(PARENT_SPAN_HEX.parse().expect("valid span hex"));
    ev
}

/// An application log line captured via the PTY pipeline.
pub fn app_log() -> Event {
    fix(
        Event::new(trace(), Kind::Log, Category::AppLog, "stderr")
            .with_name("build error line")
            .with_op("log")
            .with_status(Status::Error)
            .with_error("error[E0308]: mismatched types")
            .with_console(ConsoleBlock {
                level: Some("error".into()),
                message: Some("error[E0308]: mismatched types".into()),
                url: None,
                stack: None,
            }),
        "3333333333333333cccccccccccccccc",
        BASE_MICROS + 2_000_000,
    )
}

/// A browser network request captured by the injected-JS adapter.
pub fn browser_network() -> Event {
    fix(
        Event::new(trace(), Kind::Browser, Category::Browser, "fetch")
            .with_name("GET /api/users")
            .with_op("request")
            .with_status(Status::Ok)
            .with_duration_ms(48.0)
            .with_network(NetworkBlock {
                method: Some("GET".into()),
                url: Some("https://app.example.test/api/users".into()),
                status_code: Some(200),
                request_bytes: Some(0),
                response_bytes: Some(2048),
            }),
        "4444444444444444dddddddddddddddd",
        BASE_MICROS + 3_000_000,
    )
}

/// A security finding imported from a scanner (Semgrep-style).
pub fn security_finding() -> Event {
    fix(
        Event::new(trace(), Kind::Finding, Category::Security, "semgrep.finding")
            .with_name("hardcoded-secret")
            .with_op("finding")
            .with_status(Status::Error)
            .with_finding(FindingBlock {
                source: Some("semgrep".into()),
                rule_id: Some("rust.lang.security.hardcoded-secret".into()),
                severity: Some(Severity::High),
                file: Some("src/config.rs".into()),
                line: Some(42),
                message: Some("Possible hardcoded secret".into()),
            }),
        "5555555555555555eeeeeeeeeeeeeeee",
        BASE_MICROS + 4_000_000,
    )
}

/// A high-level agent action / turn (the `logbook agent <cli>` capture).
pub fn agent_action() -> Event {
    fix(
        Event::new(trace(), Kind::Agent, Category::Agent, "agent.turn")
            .with_name("assistant turn 1")
            .with_op("turn")
            .with_status(Status::Ok)
            .with_duration_ms(2500.0)
            .with_agent(AgentBlock {
                agent: Some("claude".into()),
                step: Some(1),
                role: Some("assistant".into()),
            }),
        "6666666666666666ffffffffffffffff",
        BASE_MICROS + 5_000_000,
    )
    .with_attr("logbook.session.cwd", "/work/repo")
}

/// All six fixtures in the plan's stated order.
pub fn all() -> Vec<Event> {
    vec![
        llm_call(),
        tool_call(),
        app_log(),
        browser_network(),
        security_finding(),
        agent_action(),
    ]
}
