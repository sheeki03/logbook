//! Logpoint descriptors and DAP `setBreakpoints` argument construction.
//!
//! A **logpoint** is a breakpoint with a `logMessage`: per the DAP spec, when a
//! `SourceBreakpoint` carries a `logMessage`, the adapter must **log the
//! interpolated message instead of stopping** at that location. Expressions are
//! interpolated with `{expr}` syntax inside the message. This is exactly the
//! "log an expression at `file:line` without stopping and without editing
//! source" capability the plan calls for (plan §6, Tier 2 alpha).
//!
//! When a logpoint fires, the adapter sends an `output` event whose body
//! carries the rendered text; [`output_event_to_event`] maps that into an
//! logbook [`Event`] for ingestion.

use logbook_core::{Category, ConsoleBlock, Event, Kind, SessionId, Status, TraceId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A logpoint: an expression to log at a `file:line`, optionally guarded by a
/// `condition` and/or a `hitCondition`. **Never stops execution.**
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logpoint {
    /// Absolute path to the source file the adapter is debugging.
    pub file: String,
    /// One-based line number.
    pub line: u32,
    /// One-based column (optional; some adapters honor it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// The log message. `{expr}` segments are interpolated by the adapter at
    /// hit time. Plain text is logged verbatim. Because the message is logged
    /// rather than executed as a side-effecting statement, and no source file
    /// is written, this is non-invasive.
    pub log_message: String,
    /// Optional condition expression: only log when it evaluates truthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Optional hit condition (e.g. `>5`): only log after N hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hit_condition: Option<String>,
}

impl Logpoint {
    /// Construct a logpoint that logs `log_message` at `file:line`.
    #[must_use]
    pub fn new(file: impl Into<String>, line: u32, log_message: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line,
            column: None,
            log_message: log_message.into(),
            condition: None,
            hit_condition: None,
        }
    }

    /// Convenience: a logpoint that logs a single expression value, labelled.
    /// Produces a `log_message` of the form `"<label>={expr}"`.
    #[must_use]
    pub fn expr(file: impl Into<String>, line: u32, label: &str, expr: &str) -> Self {
        Self::new(file, line, format!("{label}={{{expr}}}"))
    }

    /// Render this logpoint as a DAP `SourceBreakpoint` object.
    #[must_use]
    pub fn to_source_breakpoint(&self) -> Value {
        let mut bp = serde_json::Map::new();
        bp.insert("line".to_string(), json!(self.line));
        if let Some(col) = self.column {
            bp.insert("column".to_string(), json!(col));
        }
        // The defining property: `logMessage` makes this a logpoint, not a stop.
        bp.insert("logMessage".to_string(), json!(self.log_message));
        if let Some(cond) = &self.condition {
            bp.insert("condition".to_string(), json!(cond));
        }
        if let Some(hit) = &self.hit_condition {
            bp.insert("hitCondition".to_string(), json!(hit));
        }
        Value::Object(bp)
    }
}

/// Build the `arguments` for a `setBreakpoints` request that installs the given
/// logpoints on a single source file.
///
/// All `breakpoints` for one `setBreakpoints` call must target the same
/// `source`; callers group by file and issue one call per file. The returned
/// value is the request `arguments` object.
#[must_use]
pub fn set_breakpoints_arguments(file: &str, logpoints: &[Logpoint]) -> Value {
    let breakpoints: Vec<Value> = logpoints
        .iter()
        .filter(|lp| lp.file == file)
        .map(Logpoint::to_source_breakpoint)
        .collect();
    json!({
        "source": { "path": file },
        "breakpoints": breakpoints,
        // We never want the adapter to fall back to stopping.
        "sourceModified": false,
    })
}

/// Map a DAP `output` event body into an logbook [`Event`].
///
/// `output` events look like
/// `{ "category": "console"|"stdout"|"stderr"|..., "output": "<text>", "line": n?, "source": {"path": ...}? }`.
/// A logpoint's rendered text arrives as one of these. We classify it as a
/// browser/console-style [`Kind::Log`] event on the supplied trace/session so it
/// lands on the timeline next to the rest of the run's evidence.
#[must_use]
pub fn output_event_to_event(
    trace: TraceId,
    session: &SessionId,
    body: &Value,
    redactor: &logbook_core::Redactor,
) -> Event {
    let category = body
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("console");
    let raw = body.get("output").and_then(Value::as_str).unwrap_or("");
    let message = redactor.redact(raw).into_owned();
    let url = body
        .get("source")
        .and_then(|s| s.get("path"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let line = body.get("line").and_then(Value::as_i64);

    // `stderr` output from a logpoint is unusual but, if seen, is informational
    // here (a logpoint is not itself an error); keep status Ok.
    let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "dap.logpoint.output")
        .with_op("logpoint")
        .with_name(format!("logpoint:{category}"))
        .with_status(Status::Ok)
        .with_session(session.clone())
        .with_attr("dap_category", category)
        .with_console(ConsoleBlock {
            level: Some(level_for(category).to_string()),
            message: Some(message),
            url,
            stack: None,
        });
    if let Some(l) = line {
        ev = ev.with_attr("line", l);
    }
    ev
}

/// Map a DAP output `category` to a console level.
fn level_for(category: &str) -> &'static str {
    match category {
        "stderr" => "error",
        "important" => "warn",
        _ => "log",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logpoint_renders_as_logmessage_breakpoint() {
        let lp = Logpoint::expr("/src/main.rs", 42, "x", "x + 1");
        let bp = lp.to_source_breakpoint();
        assert_eq!(bp["line"], json!(42));
        assert_eq!(bp["logMessage"], json!("x={x + 1}"));
        // Crucially: no `condition`/`hitCondition` unless set, and it IS a
        // logpoint (has logMessage) so the adapter logs instead of stopping.
        assert!(bp.get("condition").is_none());
    }

    #[test]
    fn set_breakpoints_groups_by_file_and_marks_logpoints() {
        let lps = vec![
            Logpoint::new("/a.rs", 1, "hit a1"),
            Logpoint::new("/b.rs", 2, "hit b2"),
            Logpoint::new("/a.rs", 3, "hit a3"),
        ];
        let args = set_breakpoints_arguments("/a.rs", &lps);
        assert_eq!(args["source"]["path"], json!("/a.rs"));
        let bps = args["breakpoints"].as_array().unwrap();
        assert_eq!(bps.len(), 2, "only /a.rs logpoints included");
        assert!(bps.iter().all(|b| b.get("logMessage").is_some()));
        assert_eq!(args["sourceModified"], json!(false));
    }

    #[test]
    fn output_event_maps_and_redacts() {
        let trace = TraceId::new();
        let sess = SessionId::new("s1");
        let red = logbook_core::Redactor::new();
        let body = json!({
            "category": "stdout",
            "output": "token=AKIAIOSFODNN7EXAMPLE",
            "line": 12,
            "source": {"path": "/src/main.rs"}
        });
        let ev = output_event_to_event(trace, &sess, &body, &red);
        assert_eq!(ev.kind, Kind::Log);
        assert_eq!(ev.session_id.as_ref().unwrap().as_str(), "s1");
        let msg = ev.blocks.console.as_ref().unwrap().message.as_ref().unwrap();
        assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {msg}");
        assert_eq!(ev.attributes["line"], json!(12));
    }
}
