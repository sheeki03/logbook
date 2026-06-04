//! Turning cleaned terminal lines into structured [`Event`]s (plan §3).
//!
//! The capture pipeline fans each PTY chunk to a structured-event sink in
//! addition to the file tiers. This module owns that transformation:
//!
//! 1. Split a (possibly multi-line) cleaned text fragment into individual lines,
//!    buffering an unterminated trailing fragment until its newline arrives.
//! 2. Best-effort extract a log **level** (`error`/`warn`/`info`/`debug`/`trace`)
//!    from each line.
//! 3. **Redact** the line via [`logbook_core::Redactor`] before it becomes an
//!    `Event` — nothing reaches the store un-redacted.
//! 4. Emit an `Event { kind: Log, category: AppLog }` carrying the redacted line
//!    as a [`ConsoleBlock`], with `status = Error` when the level is `error`.
//!
//! The level heuristic is deliberately conservative (it recognises the common
//! framings: bare leading keyword, `[LEVEL]`, `LEVEL:`, and `"level":"..."`),
//! and only ever annotates — it never drops or rewrites the message text.

use logbook_core::{Category, ConsoleBlock, Event, Kind, Redactor, Status, TraceId};

/// A recognised log level, ordered least-to-most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    /// Very fine-grained tracing.
    Trace,
    /// Debug detail.
    Debug,
    /// Informational.
    Info,
    /// Warning.
    Warn,
    /// Error.
    Error,
}

impl LogLevel {
    /// The canonical lowercase wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    fn from_keyword(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "error" | "err" | "fatal" | "panic" | "critical" | "crit" => Some(LogLevel::Error),
            "warn" | "warning" => Some(LogLevel::Warn),
            "info" | "notice" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "trace" | "verbose" => Some(LogLevel::Trace),
            _ => None,
        }
    }
}

/// Best-effort extract a [`LogLevel`] from a single cleaned log line.
///
/// Recognised framings (checked in this order, first match wins):
/// 1. leading bracketed level — `[ERROR] ...`, `[ warn ] ...`
/// 2. JSON `"level":"error"` (anywhere on the line)
/// 3. a leading keyword token — the first whitespace/`:`-delimited word, so this
///    covers both `ERROR: ...` and a bare `ERROR something happened`
///
/// Note the JSON form is checked **before** the leading bare keyword, so a line
/// like `error: {"level":"info"}` resolves to `info` (the embedded JSON level
/// wins over the leading `error`).
///
/// Returns `None` when no level is confidently identified.
#[must_use]
pub fn extract_level(line: &str) -> Option<LogLevel> {
    let trimmed = line.trim_start();

    // [LEVEL] ...
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let inner = rest[..end].trim();
            if let Some(level) = LogLevel::from_keyword(inner) {
                return Some(level);
            }
        }
    }

    // JSON-ish "level":"error" / "level": "error"
    if let Some(level) = extract_json_level(line) {
        return Some(level);
    }

    // Leading `WORD:` or leading bare `WORD ` (first whitespace/colon-delimited token).
    let first_token: String = trimmed
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !first_token.is_empty() {
        if let Some(level) = LogLevel::from_keyword(&first_token) {
            return Some(level);
        }
    }

    None
}

fn extract_json_level(line: &str) -> Option<LogLevel> {
    let key = "\"level\"";
    let idx = line.find(key)?;
    let after = &line[idx + key.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    LogLevel::from_keyword(&after[..end])
}

/// Build one structured [`Event`] from a single (already line-split) cleaned
/// log line, redacting the line first. `trace_id` ties the line into the run's
/// trace. The event is `Kind::Log` / `Category::AppLog`, `type = "stdout"`.
#[must_use]
pub fn line_to_event(redactor: &Redactor, trace_id: TraceId, line: &str) -> Event {
    let level = extract_level(line);
    let redacted = redactor.redact(line).into_owned();

    let status = match level {
        Some(LogLevel::Error) => Status::Error,
        _ => Status::Unset,
    };

    let mut event = Event::new(trace_id, Kind::Log, Category::AppLog, "stdout")
        .with_op("log")
        .with_name(truncate_name(&redacted))
        .with_status(status)
        .with_console(ConsoleBlock {
            level: level.map(|l| l.as_str().to_string()),
            message: Some(redacted.clone()),
            ..Default::default()
        });

    if status == Status::Error {
        event.error = Some(redacted);
    }
    event
}

/// Trim a display name to a reasonable length (the full text lives in the
/// console block); avoids unbounded `name` rows in the store. Uses the shared
/// UTF-8-safe truncation helper so the boundary logic and ellipsis marker stay
/// consistent across the workspace.
fn truncate_name(line: &str) -> String {
    const MAX: usize = 200;
    logbook_core::truncate_with_ellipsis(line, MAX)
}

/// Largest unterminated line the parser will buffer before force-emitting it as
/// a synthetic event and resetting. Bounds memory growth when a captured program
/// emits a very large amount of output with no `\n` (a giant single-line JSON
/// blob, a base64 payload, …); without this the buffer would grow unboundedly
/// for the lifetime of the run.
const MAX_LINE_BUFFER: usize = 4 * 1024 * 1024;

/// Incrementally splits a stream of cleaned text fragments into whole lines,
/// emitting structured [`Event`]s for each completed line. An unterminated
/// trailing fragment is buffered until its newline arrives (or [`finish`] is
/// called at end-of-stream).
///
/// Input fragments are expected to already be ANSI-stripped and newline-
/// normalized (i.e. the output of [`crate::clean::StreamCleaner`]), so the
/// splitter only needs to split on `\n`.
///
/// The buffered partial line is capped at [`MAX_LINE_BUFFER`] bytes: a line that
/// exceeds it without a newline is force-emitted as a synthetic event so the
/// buffer cannot grow without bound on newline-less output.
///
/// [`finish`]: LineParser::finish
pub struct LineParser {
    trace_id: TraceId,
    buffer: String,
}

impl LineParser {
    /// Create a parser that tags every emitted event with `trace_id`.
    #[must_use]
    pub fn new(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            buffer: String::new(),
        }
    }

    /// Feed a cleaned text fragment, redacting and emitting an [`Event`] for
    /// every newline-terminated line it completes. The trailing partial line
    /// (if any) is retained for the next call.
    pub fn push(&mut self, redactor: &Redactor, fragment: &str) -> Vec<Event> {
        self.buffer.push_str(fragment);
        let mut events = Vec::new();
        // Repeatedly peel off complete lines.
        while let Some(nl) = self.buffer.find('\n') {
            let line: String = self.buffer.drain(..=nl).collect();
            let line = line.strip_suffix('\n').unwrap_or(&line);
            events.push(line_to_event(redactor, self.trace_id, line));
        }
        // Force-emit an over-long unterminated line so a newline-less stream
        // can't grow the buffer without bound. We emit the buffered prefix as a
        // synthetic line and keep any tail that lands mid-UTF-8-char so the next
        // push continues cleanly. (`line_to_event` truncates the stored name.)
        if self.buffer.len() >= MAX_LINE_BUFFER {
            let cut = logbook_core::floor_char_boundary(&self.buffer, MAX_LINE_BUFFER);
            let line: String = self.buffer.drain(..cut).collect();
            events.push(line_to_event(redactor, self.trace_id, &line));
        }
        events
    }

    /// Flush any buffered final line (without a trailing newline) at
    /// end-of-stream. Returns an event for it, or `None` if the buffer is empty.
    pub fn finish(&mut self, redactor: &Redactor) -> Option<Event> {
        if self.buffer.is_empty() {
            return None;
        }
        let line = std::mem::take(&mut self.buffer);
        Some(line_to_event(redactor, self.trace_id, &line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bracketed_level() {
        assert_eq!(extract_level("[ERROR] boom"), Some(LogLevel::Error));
        assert_eq!(extract_level("[ warn ] careful"), Some(LogLevel::Warn));
        assert_eq!(extract_level("[INFO] ok"), Some(LogLevel::Info));
    }

    #[test]
    fn extracts_prefixed_level() {
        assert_eq!(extract_level("ERROR: something"), Some(LogLevel::Error));
        assert_eq!(extract_level("warn: heads up"), Some(LogLevel::Warn));
        assert_eq!(extract_level("DEBUG verbose detail"), Some(LogLevel::Debug));
        assert_eq!(extract_level("fatal: cannot continue"), Some(LogLevel::Error));
    }

    #[test]
    fn extracts_json_level() {
        assert_eq!(
            extract_level(r#"{"ts":1,"level":"error","msg":"x"}"#),
            Some(LogLevel::Error)
        );
        assert_eq!(
            extract_level(r#"{"level": "warn"}"#),
            Some(LogLevel::Warn)
        );
    }

    #[test]
    fn no_level_for_plain_lines() {
        assert_eq!(extract_level("just a normal line"), None);
        assert_eq!(extract_level("Compiling logbook-capture v0.1.0"), None);
        assert_eq!(extract_level(""), None);
    }

    #[test]
    fn from_keyword_maps_every_alias() {
        // Pin the full alias table so dropping one in a refactor (e.g. losing
        // `panic`→Error, which gates panic-line Status::Error flagging) fails CI.
        let cases: &[(&str, LogLevel)] = &[
            ("error", LogLevel::Error),
            ("err", LogLevel::Error),
            ("fatal", LogLevel::Error),
            ("panic", LogLevel::Error),
            ("critical", LogLevel::Error),
            ("crit", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("warning", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("notice", LogLevel::Info),
            ("debug", LogLevel::Debug),
            ("trace", LogLevel::Trace),
            ("verbose", LogLevel::Trace),
        ];
        for (word, expected) in cases {
            assert_eq!(
                LogLevel::from_keyword(word),
                Some(*expected),
                "lowercase alias {word:?}"
            );
            // Case-insensitive.
            assert_eq!(
                LogLevel::from_keyword(&word.to_uppercase()),
                Some(*expected),
                "uppercase alias {word:?}"
            );
        }
        assert_eq!(LogLevel::from_keyword("nope"), None);
    }

    #[test]
    fn panic_keyword_flags_error_status() {
        // The panic->Error mapping is load-bearing: it controls Status::Error.
        let ev = line_to_event(&Redactor::new(), TraceId::new(), "panic: goroutine blew up");
        assert_eq!(ev.status, Status::Error);
        assert!(ev.error.is_some());
    }

    #[test]
    fn json_level_wins_over_leading_keyword() {
        // Embedded JSON level is checked before the leading bare keyword, so the
        // JSON value wins. Pin this so the precedence can't be silently inverted.
        assert_eq!(
            extract_level(r#"error: {"level":"info"}"#),
            Some(LogLevel::Info)
        );
        // A bracketed level still wins over everything (checked first).
        assert_eq!(
            extract_level(r#"[warn] {"level":"info"}"#),
            Some(LogLevel::Warn)
        );
    }

    #[test]
    fn line_event_is_log_applog_and_redacted() {
        let r = Redactor::new();
        let ev = line_to_event(&r, TraceId::new(), "ERROR: leaked AKIAIOSFODNN7EXAMPLE here");
        assert_eq!(ev.kind, Kind::Log);
        assert_eq!(ev.category, Category::AppLog);
        assert_eq!(ev.status, Status::Error);
        let msg = ev.blocks.console.as_ref().unwrap().message.clone().unwrap();
        assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into event: {msg}");
        assert_eq!(ev.blocks.console.as_ref().unwrap().level.as_deref(), Some("error"));
        // error message set when level is error.
        assert!(ev.error.as_deref().unwrap().contains("REDACTED"));
    }

    #[test]
    fn non_error_line_has_unset_status_and_no_error() {
        let r = Redactor::new();
        let ev = line_to_event(&r, TraceId::new(), "INFO: all good");
        assert_eq!(ev.status, Status::Unset);
        assert!(ev.error.is_none());
        assert_eq!(ev.blocks.console.as_ref().unwrap().level.as_deref(), Some("info"));
    }

    #[test]
    fn line_parser_splits_and_buffers_partial() {
        let r = Redactor::new();
        let trace = TraceId::new();
        let mut p = LineParser::new(trace);

        // Two complete lines + a partial.
        let evs = p.push(&r, "line one\nline two\npartial");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].blocks.console.as_ref().unwrap().message.as_deref(), Some("line one"));
        assert_eq!(evs[1].blocks.console.as_ref().unwrap().message.as_deref(), Some("line two"));
        assert!(evs.iter().all(|e| e.trace_id == trace));

        // Completing the partial line.
        let evs2 = p.push(&r, " completed\n");
        assert_eq!(evs2.len(), 1);
        assert_eq!(
            evs2[0].blocks.console.as_ref().unwrap().message.as_deref(),
            Some("partial completed")
        );

        assert!(p.finish(&r).is_none(), "buffer should be empty after newline");
    }

    #[test]
    fn line_parser_caps_unterminated_buffer() {
        // A newline-less stream larger than the cap must not grow the buffer
        // without bound: it force-emits a synthetic line and drains the prefix.
        let r = Redactor::new();
        let mut p = LineParser::new(TraceId::new());
        // First push under the cap buffers silently (no newline, no force-emit).
        let evs = p.push(&r, &"a".repeat(MAX_LINE_BUFFER - 10));
        assert!(evs.is_empty(), "under-cap partial line should not emit");
        // Crossing the cap force-emits exactly one synthetic line and drains it.
        let evs = p.push(&r, &"b".repeat(100));
        assert_eq!(evs.len(), 1, "over-cap line should force-emit once");
        // The retained buffer is now bounded well under the cap.
        assert!(p.buffer.len() < MAX_LINE_BUFFER, "buffer must shrink after force-emit");
        // Buffer remained valid UTF-8 throughout (no mid-char panic).
        let _ = p.finish(&r);
    }

    #[test]
    fn line_parser_finish_flushes_trailing_line() {
        let r = Redactor::new();
        let mut p = LineParser::new(TraceId::new());
        let evs = p.push(&r, "no newline at end");
        assert!(evs.is_empty());
        let last = p.finish(&r).expect("trailing line should flush");
        assert_eq!(
            last.blocks.console.as_ref().unwrap().message.as_deref(),
            Some("no newline at end")
        );
    }
}
