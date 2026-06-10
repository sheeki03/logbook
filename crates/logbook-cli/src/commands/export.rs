//! `logbook export ...` — span export (plan §8), wired to `logbook-export`.
//!
//! v1 is **schema only**: read events from the store, lower each to a canonical
//! OTLP span, re-key into the requested target schema (OTel / OpenInference /
//! Langfuse / MLflow), and write the JSON to stdout or a file. There is **no**
//! network export (that is v1.5) — this command only emits documents.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use logbook_export::{
    events_to_finetune_jsonl, spans_to_otlp_document, to_canonical, FinetuneOptions,
    LangfuseAdapter, MlflowAdapter, OpenInferenceAdapter, OtelAdapter, SpanExportAdapter,
};
use logbook_store::{Query, Store};

/// `logbook export [opts]`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Out-dir holding the logbook store to export from.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Target tracing schema.
    #[arg(long, value_enum, default_value_t = ExportFormat::Otel)]
    pub format: ExportFormat,

    /// Export only events on this correlated trace id (hex). Omit to export all.
    #[arg(long)]
    pub trace: Option<String>,

    /// Cap on the number of events exported.
    #[arg(long)]
    pub limit: Option<u32>,

    /// Write to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// (`--format finetune` only) Emit the already-redacted message bodies as
    /// `content`. **Off by default**: redaction floors *secrets*, not
    /// intellectual property — proprietary code, file paths, and private prompts
    /// survive it. "Redacted" is NOT the same as "safe to train on", so bodies
    /// are opt-in. With this off, the export is metadata/structure only (no
    /// bodies). Ignored by the span formats.
    #[arg(long, default_value_t = false)]
    pub include_payloads: bool,

    /// (`--format finetune` only) Emit a separate `tools` array of tool-call
    /// objects per record. Off by default; tool args/results are only emitted as
    /// bodies when `--include-payloads` is also set. Ignored by the span formats.
    #[arg(long, default_value_t = false)]
    pub include_tools: bool,
}

/// The export target schema (plan §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// OTLP/JSON. With this format the output is a single OTLP document
    /// (`resourceSpans` envelope); the others emit a JSON array of spans.
    Otel,
    /// OpenInference span attributes.
    Openinference,
    /// Langfuse trace/observation shape.
    Langfuse,
    /// MLflow span shape.
    Mlflow,
    /// Conversation-shaped fine-tuning dataset. Unlike the span formats, the
    /// output is **chat JSONL** (one `{"messages":[…]}` record per trace), not a
    /// span document/array. **Payload-gated**: bodies are emitted only with
    /// `--include-payloads` (see that flag's caveat).
    Finetune,
}

/// Dispatch an `export` invocation.
///
/// # Errors
/// Returns an error if the store cannot be opened, an event cannot be mapped to
/// the target schema, or the output file cannot be written.
pub fn run(args: ExportArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;

    // Oldest-first so the exported document reads in timeline order.
    let mut query = Query::new().oldest_first();
    if let Some(trace) = &args.trace {
        query = query.trace(trace.clone());
    }
    if let Some(limit) = args.limit {
        query = query.limit(limit);
    }
    let events = store.query(&query)?;

    // The fine-tuning export is conversation-shaped (chat JSONL), not a span
    // document/array — so it takes a distinct path that does not run through the
    // `SpanExportAdapter` re-keyers or the pretty-printer below.
    if args.format == ExportFormat::Finetune {
        if args.include_payloads {
            // The body gate is open: warn loudly. Redaction floors secrets, not
            // IP, so emitted bodies may still carry proprietary code/paths.
            eprintln!(
                "logbook: WARNING --include-payloads emits message bodies. These are \
                 secrets-redacted but may still contain proprietary code, file paths, and \
                 private prompts. \"redacted\" is NOT the same as \"safe to train on\" — \
                 review before sharing or training."
            );
        }
        let opts = FinetuneOptions {
            include_payloads: args.include_payloads,
            include_tools: args.include_tools,
        };
        let jsonl = events_to_finetune_jsonl(&events, opts);
        match &args.output {
            Some(path) => {
                std::fs::write(path, &jsonl)?;
                eprintln!(
                    "logbook: exported {} record(s) as finetune JSONL to {} (from {} event(s)).",
                    jsonl.lines().count(),
                    path.display(),
                    events.len()
                );
            }
            None => print!("{jsonl}"),
        }
        return Ok(0);
    }

    let json = match args.format {
        ExportFormat::Otel => {
            // The OTel target gets the wrapped OTLP document, not a bare array.
            let spans: Vec<_> = events.iter().map(to_canonical).collect();
            spans_to_otlp_document(&spans)
        }
        ExportFormat::Openinference => array(&OpenInferenceAdapter, &events)?,
        ExportFormat::Langfuse => array(&LangfuseAdapter, &events)?,
        ExportFormat::Mlflow => array(&MlflowAdapter, &events)?,
        // Handled above on its own JSONL path; unreachable here.
        ExportFormat::Finetune => unreachable!("finetune is handled before the span path"),
    };

    let rendered = serde_json::to_string_pretty(&json)?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, rendered)?;
            eprintln!(
                "logbook: exported {} event(s) as {:?} to {}.",
                events.len(),
                args.format,
                path.display()
            );
        }
        None => println!("{rendered}"),
    }
    Ok(0)
}

/// Map every event through `adapter` into a JSON array of spans.
fn array(
    adapter: &impl SpanExportAdapter,
    events: &[logbook_core::Event],
) -> anyhow::Result<serde_json::Value> {
    let spans = adapter.events_to_json(events)?;
    Ok(serde_json::Value::Array(spans))
}

// `OtelAdapter` is re-exported for callers who want bare OTel spans (without the
// document envelope) via the generic `array` path; keep the symbol referenced so
// the import doesn't dangle if the document path above changes.
#[allow(dead_code)]
fn _otel_adapter_is_available() -> &'static str {
    OtelAdapter.target()
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{AgentBlock, Category, Event, Kind, LlmBlock, MicrosTimestamp, TraceId};
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Export(ExportArgs),
    }

    #[test]
    fn parses_format_and_trace() {
        let cli = TestCli::try_parse_from([
            "x",
            "export",
            "--format",
            "openinference",
            "--trace",
            "deadbeef",
        ])
        .unwrap();
        match cli.cmd {
            TestCmd::Export(a) => {
                assert_eq!(a.format, ExportFormat::Openinference);
                assert_eq!(a.trace.as_deref(), Some("deadbeef"));
            }
        }
    }

    #[test]
    fn default_format_is_otel() {
        let cli = TestCli::try_parse_from(["x", "export"]).unwrap();
        match cli.cmd {
            TestCmd::Export(a) => assert_eq!(a.format, ExportFormat::Otel),
        }
    }

    #[test]
    fn export_writes_openinference_array_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let trace = TraceId::new();
        store
            .insert(
                &Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
                    .with_llm(LlmBlock {
                        model: Some("gpt-4o".into()),
                        ..Default::default()
                    }),
            )
            .unwrap();

        let out = dir.path().join("spans.json");
        let code = run(ExportArgs {
            out_dir: dir.path().to_path_buf(),
            format: ExportFormat::Openinference,
            trace: Some(trace.to_hex()),
            limit: None,
            output: Some(out.clone()),
            include_payloads: false,
            include_tools: false,
        })
        .unwrap();
        assert_eq!(code, 0);

        let text = std::fs::read_to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let arr = v.as_array().expect("array of spans");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["attributes"]["openinference.span.kind"], "LLM");
        assert_eq!(arr[0]["attributes"]["llm.model_name"], "gpt-4o");
    }

    #[test]
    fn export_otel_emits_resource_spans_document() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        store
            .insert(&Event::new(
                TraceId::new(),
                Kind::Span,
                Category::AppLog,
                "op",
            ))
            .unwrap();

        let out = dir.path().join("otlp.json");
        run(ExportArgs {
            out_dir: dir.path().to_path_buf(),
            format: ExportFormat::Otel,
            trace: None,
            limit: None,
            output: Some(out.clone()),
            include_payloads: false,
            include_tools: false,
        })
        .unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        // OTLP document envelope present.
        assert!(v.get("resourceSpans").is_some(), "expected resourceSpans envelope: {v}");
    }

    #[test]
    fn parses_finetune_format_with_include_payloads() {
        let cli = TestCli::try_parse_from([
            "x",
            "export",
            "--format",
            "finetune",
            "--include-payloads",
        ])
        .unwrap();
        match cli.cmd {
            TestCmd::Export(a) => {
                assert_eq!(a.format, ExportFormat::Finetune);
                assert!(a.include_payloads, "--include-payloads should be set");
                // --include-tools defaults off.
                assert!(!a.include_tools);
            }
        }
    }

    #[test]
    fn finetune_include_payloads_defaults_off() {
        let cli =
            TestCli::try_parse_from(["x", "export", "--format", "finetune"]).unwrap();
        match cli.cmd {
            TestCmd::Export(a) => {
                assert_eq!(a.format, ExportFormat::Finetune);
                assert!(!a.include_payloads, "payloads must default off");
            }
        }
    }

    /// End-to-end: seed a store with a user + assistant + a metadata-only LLM
    /// event on one trace, export as finetune JSONL, and assert the record shape.
    /// Mirrors `export_writes_openinference_array_to_file`.
    #[test]
    fn export_writes_finetune_jsonl_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let trace = TraceId::new();

        // user turn (Kind::Agent role=user, body in input).
        let mut user = Event::new(trace, Kind::Agent, Category::Agent, "agent.user_prompt")
            .with_agent(AgentBlock {
                agent: Some("claude".into()),
                role: Some("user".into()),
                ..Default::default()
            })
            .with_attr("harness", "claude");
        user.timestamp = MicrosTimestamp(1_000);
        user.input = Some(serde_json::Value::String("hello there".into()));

        // metadata-only LLM (model + tokens, no text) — must NOT add an assistant
        // turn, only model attribution.
        let mut llm = Event::new(trace, Kind::Llm, Category::Agent, "llm.completion")
            .with_llm(LlmBlock {
                model: Some("claude-3-5-sonnet".into()),
                input_tokens: Some(10),
                ..Default::default()
            });
        llm.timestamp = MicrosTimestamp(1_100);

        // assistant turn (body in output).
        let mut asst = Event::new(trace, Kind::Agent, Category::Agent, "agent.message")
            .with_agent(AgentBlock {
                agent: Some("claude".into()),
                role: Some("assistant".into()),
                ..Default::default()
            })
            .with_attr("harness", "claude");
        asst.timestamp = MicrosTimestamp(1_200);
        asst.output = Some(serde_json::Value::String("general kenobi".into()));

        store.insert_batch(vec![user, llm, asst]).unwrap();

        // Default (payloads off): structure only, no bodies.
        let out = dir.path().join("ft.jsonl");
        let code = run(ExportArgs {
            out_dir: dir.path().to_path_buf(),
            format: ExportFormat::Finetune,
            trace: Some(trace.to_hex()),
            limit: None,
            output: Some(out.clone()),
            include_payloads: false,
            include_tools: false,
        })
        .unwrap();
        assert_eq!(code, 0);

        let text = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "one JSONL line per trace: {text}");
        let rec: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec["trace_id"], serde_json::json!(trace.to_hex()));
        assert_eq!(rec["source"], serde_json::json!("claude"));
        assert_eq!(rec["model"], serde_json::json!("claude-3-5-sonnet"));
        let msgs = rec["messages"].as_array().unwrap();
        // user + assistant only; the metadata-only LLM added no turn.
        assert_eq!(msgs.len(), 2, "metadata-only LLM must not add a turn: {msgs:?}");
        assert_eq!(msgs[0]["role"], serde_json::json!("user"));
        assert_eq!(msgs[1]["role"], serde_json::json!("assistant"));
        // Payloads off ⇒ no bodies, length placeholder instead.
        assert!(msgs[0].get("content").is_none());
        assert!(msgs[0].get("redacted_chars").is_some());
        assert!(!text.contains("general kenobi"), "no body with payloads off: {text}");

        // With payloads on, bodies appear.
        let out2 = dir.path().join("ft_full.jsonl");
        run(ExportArgs {
            out_dir: dir.path().to_path_buf(),
            format: ExportFormat::Finetune,
            trace: Some(trace.to_hex()),
            limit: None,
            output: Some(out2.clone()),
            include_payloads: true,
            include_tools: false,
        })
        .unwrap();
        let full = std::fs::read_to_string(&out2).unwrap();
        let rec2: serde_json::Value =
            serde_json::from_str(full.lines().next().unwrap()).unwrap();
        let msgs2 = rec2["messages"].as_array().unwrap();
        assert_eq!(msgs2[0]["content"], serde_json::json!("hello there"));
        assert_eq!(msgs2[1]["content"], serde_json::json!("general kenobi"));
    }
}
