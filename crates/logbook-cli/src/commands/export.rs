//! `logbook export ...` — span export (plan §8), wired to `logbook-export`.
//!
//! v1 is **schema only**: read events from the store, lower each to a canonical
//! OTLP span, re-key into the requested target schema (OTel / OpenInference /
//! Langfuse / MLflow), and write the JSON to stdout or a file. There is **no**
//! network export (that is v1.5) — this command only emits documents.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use logbook_export::{
    spans_to_otlp_document, to_canonical, LangfuseAdapter, MlflowAdapter, OpenInferenceAdapter,
    OtelAdapter, SpanExportAdapter,
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

    let json = match args.format {
        ExportFormat::Otel => {
            // The OTel target gets the wrapped OTLP document, not a bare array.
            let spans: Vec<_> = events.iter().map(to_canonical).collect();
            spans_to_otlp_document(&spans)
        }
        ExportFormat::Openinference => array(&OpenInferenceAdapter, &events)?,
        ExportFormat::Langfuse => array(&LangfuseAdapter, &events)?,
        ExportFormat::Mlflow => array(&MlflowAdapter, &events)?,
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
    use logbook_core::{Category, Event, Kind, LlmBlock, TraceId};
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
        })
        .unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        // OTLP document envelope present.
        assert!(v.get("resourceSpans").is_some(), "expected resourceSpans envelope: {v}");
    }
}
