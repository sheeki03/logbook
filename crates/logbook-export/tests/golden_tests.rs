//! Golden tests for the export adapters (plan §8, §11 "OTel golden tests").
//!
//! For the fixed set of fixture events (LLM call, tool call, app log, browser
//! network event, security finding, agent action), we assert that each
//! adapter's emitted JSON exactly matches a checked-in golden fixture under
//! `tests/golden/`.
//!
//! ## Regenerating fixtures
//! Run with `LOGBOOK_BLESS=1` to (re)write the golden files instead of
//! asserting against them:
//!
//! ```text
//! LOGBOOK_BLESS=1 cargo test -p logbook-export --test golden_tests
//! ```
//!
//! Review any diff before committing — a change here is a wire-schema change.

#[path = "common/mod.rs"]
mod fixtures;

use std::path::PathBuf;

use logbook_core::Event;
use logbook_export::{
    spans_to_otlp_document, to_canonical, LangfuseAdapter, MlflowAdapter, OpenInferenceAdapter,
    OtelAdapter, SpanExportAdapter,
};
use serde_json::Value;

/// A zero-arg fixture builder.
type Fixture = fn() -> Event;

/// Directory holding the golden JSON fixtures.
fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Whether to (re)write fixtures instead of asserting.
fn blessing() -> bool {
    std::env::var_os("LOGBOOK_BLESS").is_some()
}

/// Pretty-print a JSON value with a trailing newline so the files are
/// diff-friendly and editor-clean.
fn pretty(value: &Value) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("serialize golden JSON");
    s.push('\n');
    s
}

/// Compare `actual` JSON against the golden file `name` (under `tests/golden/`),
/// or write it when blessing.
fn assert_golden(name: &str, actual: &Value) {
    let path = golden_dir().join(name);
    let rendered = pretty(actual);

    if blessing() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create golden dir");
        }
        std::fs::write(&path, &rendered)
            .unwrap_or_else(|e| panic!("write golden {}: {e}", path.display()));
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden fixture {} ({e}). Run with LOGBOOK_BLESS=1 to create it.",
            path.display()
        )
    });

    // Compare as parsed JSON first for a clean structural assertion, then as
    // text so formatting drift is also caught.
    let expected_json: Value = serde_json::from_str(&expected)
        .unwrap_or_else(|e| panic!("golden {} is not valid JSON: {e}", path.display()));
    assert_eq!(
        actual,
        &expected_json,
        "JSON mismatch for {}\n--- expected ---\n{}\n--- actual ---\n{}",
        path.display(),
        expected,
        rendered,
    );
    assert_eq!(
        rendered,
        expected,
        "formatting mismatch for {} (run LOGBOOK_BLESS=1 to refresh)",
        path.display()
    );
}

/// Map every fixture through an adapter and assert one golden file per fixture.
fn check_per_event<A: SpanExportAdapter>(adapter: &A) {
    let cases: &[(&str, Fixture)] = &[
        ("llm_call", fixtures::llm_call),
        ("tool_call", fixtures::tool_call),
        ("app_log", fixtures::app_log),
        ("browser_network", fixtures::browser_network),
        ("security_finding", fixtures::security_finding),
        ("agent_action", fixtures::agent_action),
    ];
    for (label, build) in cases {
        let ev = build();
        let json = adapter
            .event_to_json(&ev)
            .unwrap_or_else(|e| panic!("{} failed on {label}: {e}", adapter.target()));
        assert_golden(&format!("{}/{label}.json", adapter.target()), &json);
    }
}

#[test]
fn otel_spans_match_golden() {
    check_per_event(&OtelAdapter);
}

#[test]
fn openinference_spans_match_golden() {
    check_per_event(&OpenInferenceAdapter);
}

#[test]
fn langfuse_observations_match_golden() {
    check_per_event(&LangfuseAdapter);
}

#[test]
fn mlflow_spans_match_golden() {
    check_per_event(&MlflowAdapter);
}

/// The full OTLP/JSON `TracesData` document for all six events as one batch —
/// exercises the resource/scope envelope, not just individual spans.
#[test]
fn otel_full_document_matches_golden() {
    let spans: Vec<_> = fixtures::all().iter().map(to_canonical).collect();
    let doc = spans_to_otlp_document(&spans);
    assert_golden("otel/_document.json", &doc);
}

/// Sanity: the canonical layer is deterministic — the same fixture lowers to an
/// identical span every time (guards against hidden nondeterminism leaking into
/// the goldens).
#[test]
fn canonical_mapping_is_deterministic() {
    for build in [
        fixtures::llm_call as Fixture,
        fixtures::tool_call,
        fixtures::app_log,
        fixtures::browser_network,
        fixtures::security_finding,
        fixtures::agent_action,
    ] {
        let a = to_canonical(&build());
        let b = to_canonical(&build());
        assert_eq!(a, b, "canonical mapping must be deterministic");
    }
}

/// Cross-adapter invariant: every adapter must agree on the trace id and the
/// derived span id for the same event (they all re-key the same canonical span).
#[test]
fn adapters_agree_on_ids() {
    let ev = fixtures::llm_call();
    let canon = to_canonical(&ev);

    let otel = OtelAdapter.event_to_json(&ev).unwrap();
    let oi = OpenInferenceAdapter.event_to_json(&ev).unwrap();
    let lf = LangfuseAdapter.event_to_json(&ev).unwrap();
    let mf = MlflowAdapter.event_to_json(&ev).unwrap();

    assert_eq!(otel["traceId"], canon.trace_id);
    assert_eq!(otel["spanId"], canon.span_id);
    assert_eq!(oi["trace_id"], canon.trace_id);
    assert_eq!(oi["span_id"], canon.span_id);
    assert_eq!(lf["traceId"], canon.trace_id);
    assert_eq!(lf["id"], canon.span_id);
    assert_eq!(mf["context"]["trace_id"], canon.trace_id);
    assert_eq!(mf["context"]["span_id"], canon.span_id);
}
