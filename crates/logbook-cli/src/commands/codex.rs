//! `logbook codex -- <codex exec args...>` — run Codex's non-interactive
//! `codex exec --json` under capture, turning its **structured event stream**
//! into first-class redacted logbook events (plan "Phase 2", Codex row — the
//! Codex equivalent of the Claude hooks tier).
//!
//! `logbook agent -- codex exec ...` already captures the transcript + file
//! diffs. This command goes further: `codex exec --json` emits a rich typed
//! event stream (one JSON object per stdout line — LLM turns + token usage,
//! shell tool calls, file changes, MCP calls, web searches, reasoning), which
//! [`logbook_harness::CodexJsonAdapter`] normalizes into the unified [`Event`]
//! spine.
//!
//! ## Flow
//! 1. Spawn `codex exec --json <args...>` (the user's args passed through after
//!    `--`; **no** sandbox flag is added unless the user passed one), stdout
//!    piped, stderr inherited so the user sees codex's progress/errors live.
//! 2. Read stdout line by line; parse each non-empty line as JSON and collect.
//! 3. Resolve the [`CapturePolicy`] **fail-closed** ([`CapturePolicy::resolve`]),
//!    build a [`HarnessContext`], run the adapter, and persist via [`Store`].
//!    Every prompt/tool-arg/tool-result/message body is redacted at this
//!    persistence boundary (force-redact + secrets floor + per-class cap), and
//!    the structured-tier / per-class capture gates are honoured exactly like the
//!    `/v1/hooks` lane (metadata-only when a class is off; nothing when the tier
//!    is off / capture paused).
//! 4. Print a concise summary and exit with codex's exit code.
//!
//! ## Redaction is sacred (plan §9)
//! The adapter never holds a raw secret: this command resolves the posture and
//! hands it a [`HarnessContext`]; the adapter routes every payload through it
//! before building an [`Event`]. `--no-redact` disables only the **general**
//! redactor — the mandatory secrets floor always runs, so a cloud key / JWT /
//! bearer in a command argument or tool output is scrubbed regardless.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use clap::Args;
use serde_json::Value;

use logbook_core::{CapturePolicy, CliOverlay, Event, Kind, Redactor, SensitivityClass};
use logbook_harness::{CodexJsonAdapter, HarnessContext};
use logbook_store::Store;

/// `logbook codex [opts] -- <codex exec args...>`.
#[derive(Debug, Args)]
pub struct CodexArgs {
    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`) the structured
    /// codex events are written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the `[capture]` policy +
    /// `[redaction]` patterns). Defaults to the current directory, matching how
    /// `logbook run`/`agent`/`hooks` resolve their config root.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Disable the **general** (non-secret) redactor for the captured events. The
    /// secrets floor (cloud keys, JWT, bearer, PEM, …) is **never** disabled —
    /// `--no-redact` only drops the general / `deny`-pattern layer; prompts/tool
    /// args/results are force-redacted regardless.
    #[arg(long)]
    pub no_redact: bool,

    /// The codex `exec` arguments to run (everything after `--`), e.g.
    /// `"Create fizzbuzz.py"`. Passed through verbatim; `codex exec --json` is
    /// prepended and **no** sandbox flag is added unless you pass one here.
    #[arg(trailing_var_arg = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// A tally of what a codex session produced, for the closing summary.
#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    /// `turn.completed` LLM events.
    llm_turns: usize,
    /// `command_execution` / `mcp_tool_call` / `web_search` tool events.
    tool_calls: usize,
    /// `file_change` tool events (a subset broken out for the summary).
    file_changes: usize,
    /// Summed input+output tokens across the LLM turns.
    tokens: u64,
}

impl Summary {
    /// Tally a batch of normalized events (after redaction) for the summary line.
    fn tally(events: &[Event]) -> Self {
        let mut s = Summary::default();
        for ev in events {
            match ev.kind {
                Kind::Llm => {
                    s.llm_turns += 1;
                    if let Some(llm) = &ev.blocks.llm {
                        s.tokens += llm.input_tokens.unwrap_or(0) + llm.output_tokens.unwrap_or(0);
                    }
                }
                Kind::Tool => {
                    let is_file_change = ev
                        .blocks
                        .tool
                        .as_ref()
                        .and_then(|t| t.tool_name.as_deref())
                        == Some("file_change");
                    if is_file_change {
                        s.file_changes += 1;
                    } else {
                        s.tool_calls += 1;
                    }
                }
                _ => {}
            }
        }
        s
    }
}

/// Run `logbook codex`. Spawns `codex exec --json`, collects + parses its event
/// stream, normalizes + redacts + persists, prints a summary, and returns
/// codex's exit code.
///
/// # Errors
/// Returns an error if `codex` cannot be spawned (e.g. not on `PATH`), its stdout
/// cannot be read, or the store cannot be opened / written.
pub fn run(args: CodexArgs) -> anyhow::Result<i32> {
    if args.no_redact {
        eprintln!(
            "logbook: WARNING --no-redact is set; the secrets floor still applies, but \
             non-secret codex payloads may be persisted to {}.",
            args.out_dir.display()
        );
    }

    // Spawn `codex exec --json <args...>`. stdout piped (we parse it), stderr
    // inherited so the user sees codex's live progress/errors on our stderr.
    let mut child = Command::new("codex")
        .arg("exec")
        .arg("--json")
        .args(&args.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn `codex exec --json`: {e} (is `codex` on PATH?)"))?;

    // Read stdout line by line, parsing each non-empty line as one JSON event.
    // A non-JSON line (a stray banner, a partial flush) is skipped, not fatal —
    // the stream must survive noise (tolerant, mirroring the adapter).
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("codex child stdout was not captured"))?;
    let mut stream: Vec<Value> = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| anyhow::anyhow!("reading codex stdout: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(v) => stream.push(v),
            Err(e) => {
                tracing::warn!(error = %e, "skipping non-JSON codex stdout line");
            }
        }
    }

    // Wait for codex to exit so we can propagate its code (137 etc. on signal).
    let status = child
        .wait()
        .map_err(|e| anyhow::anyhow!("waiting on codex: {e}"))?;
    let exit_code = exit_code_of(&status);

    // Resolve + persist the captured stream (best-effort: a store/persist hiccup
    // must not change codex's own exit code — we log + still return it).
    match persist_stream(&args, &stream) {
        Ok((session_id, summary)) => print_summary(session_id.as_deref(), &summary),
        Err(e) => {
            tracing::error!(error = %e, "failed to persist codex session");
            eprintln!("logbook: failed to persist codex session: {e:#}");
        }
    }

    Ok(exit_code)
}

/// Resolve the capture policy + redactor, run the [`CodexJsonAdapter`] over the
/// collected stream, persist the (already-redacted) events, and return the codex
/// `thread_id` (if any) + the [`Summary`].
///
/// This is the persistence boundary: it mirrors the `/v1/hooks` lane —
/// fail-closed [`CapturePolicy::resolve`], a per-session [`HarnessContext`]
/// (general redactor gated by `--no-redact`, mandatory secrets floor always on),
/// the structured-tier gate, and per-class redaction/omission inside the adapter.
fn persist_stream(args: &CodexArgs, stream: &[Value]) -> anyhow::Result<(Option<String>, Summary)> {
    // (1) Resolve the capture policy fail-closed through the shared helper so the
    // cross-process pause toggle (`<out_dir>/capture-state.json`) silences codex
    // capture too. Only `--no-redact` is carried on the overlay here.
    let overlay = CliOverlay {
        no_redact: args.no_redact,
        ..Default::default()
    };
    let policy = CapturePolicy::resolve(&args.root, &args.out_dir, overlay);

    // (2) Structured-tier gate (mirrors `/v1/hooks`'s `structured_capture_open`):
    // codex events normalize into prompts/tool_args/tool_results/model_metadata —
    // all structured-tier classes. When the master switch is paused or the
    // structured tier is off, none is captured: persist nothing. The session still
    // ran; we just record no structured rows (the secrets floor is moot — nothing
    // is written).
    if !structured_capture_open(&policy) {
        return Ok((thread_id_of(stream), Summary::default()));
    }

    // (3) Build the general redactor from `<root>/logbook.toml [redaction]`
    // (honouring the user's deny/allow patterns + the enabled bit), gated by
    // `--no-redact`. The HarnessContext layers the mandatory secrets floor on top
    // regardless, so `--no-redact` can never expose a secret.
    let cfg = logbook_core::LogbookConfig::load_from_root_or_default(&args.root);
    let general_redaction_enabled = cfg.redaction.enabled && !args.no_redact;
    let redactor = if general_redaction_enabled {
        logbook_core::redact::from_config(true, &cfg.redaction.deny, &cfg.redaction.allow)
            .unwrap_or_else(|_| {
                tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
                Redactor::new().with_process_env()
            })
    } else {
        // Secrets floor only (the floor is constructed inside HarnessContext too,
        // but a disabled general redactor keeps non-secret content intact under
        // `--no-redact`).
        Redactor::disabled()
    };

    let ctx = HarnessContext::new(redactor, policy, general_redaction_enabled);

    // (4) Normalize the whole stream (one trace per `thread.started`; every event
    // redacted at construction by the context + tagged with the codex thread_id).
    let codex_version = std::env::var("CODEX_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let mut adapter = CodexJsonAdapter::new(logbook_core::TraceId::new(), ctx, codex_version);
    let events = adapter.parse_stream(stream);
    let summary = Summary::tally(&events);
    let session_id = events
        .iter()
        .find_map(|e| e.session_id.as_ref().map(|s| s.as_str().to_string()))
        .or_else(|| thread_id_of(stream));

    // (5) Persist (the events are already redacted + ready).
    if !events.is_empty() {
        let store = Store::open_in_dir(&args.out_dir)?;
        store.insert_batch(events)?;
    }

    Ok((session_id, summary))
}

/// Whether *any* structured-tier content class a codex event can emit is captured
/// under `policy`. A codex stream normalizes into `prompts` / `tool_args` /
/// `tool_results` / `model_metadata` events; all four are gated by the master
/// switch + the `structured` tier. Returning `false` ⇒ persist nothing (mirrors
/// the `/v1/hooks` producer-level gate). Returning `true` does **not** relax
/// per-class redaction/omission inside the adapter.
fn structured_capture_open(policy: &CapturePolicy) -> bool {
    policy.should_capture(SensitivityClass::Prompts)
        || policy.should_capture(SensitivityClass::ToolArgs)
        || policy.should_capture(SensitivityClass::ToolResults)
        || policy.should_capture(SensitivityClass::ModelMetadata)
}

/// Pull the codex `thread_id` from the first `thread.started` line, for the
/// summary when nothing was persisted (capture off).
fn thread_id_of(stream: &[Value]) -> Option<String> {
    stream.iter().find_map(|v| {
        if v.get("type").and_then(Value::as_str) == Some("thread.started") {
            v.get("thread_id").and_then(Value::as_str).map(str::to_string)
        } else {
            None
        }
    })
}

/// The process exit code from an [`ExitStatus`](std::process::ExitStatus):
/// the code if exited normally, else `128 + signal` (POSIX convention), else `1`.
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

/// Print the concise closing summary (e.g.
/// `codex session th_abc: 2 llm turns, 3 tool calls, 1 file change, 1288 tokens`).
fn print_summary(session_id: Option<&str>, s: &Summary) {
    let sess = session_id.unwrap_or("<none>");
    println!(
        "codex session {sess}: {} llm turn{}, {} tool call{}, {} file change{}, {} token{}",
        s.llm_turns,
        plural(s.llm_turns),
        s.tool_calls,
        plural(s.tool_calls),
        s.file_changes,
        plural(s.file_changes),
        s.tokens,
        plural(s.tokens as usize),
    );
}

/// `""`/`"s"` pluralization helper for the summary counts.
fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Codex(CodexArgs),
    }

    fn parse(argv: &[&str]) -> CodexArgs {
        let cli = TestCli::try_parse_from(argv).expect("parse");
        match cli.cmd {
            TestCmd::Codex(c) => c,
        }
    }

    #[test]
    fn parses_codex_defaults_and_passthrough_args() {
        let c = parse(&["x", "codex", "--", "Create fizzbuzz.py"]);
        assert_eq!(c.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(c.root, PathBuf::from("."));
        assert!(!c.no_redact);
        // The user's exec args are passed through verbatim (no sandbox flag added).
        assert_eq!(c.args, vec!["Create fizzbuzz.py"]);
    }

    #[test]
    fn parses_codex_opts_and_hyphenated_passthrough() {
        // Flags before `--`; codex's own hyphenated flags after `--` survive
        // (allow_hyphen_values), and no sandbox flag is injected.
        let c = parse(&[
            "x", "codex", "--out-dir", "/tmp/o", "--root", "/repo", "--no-redact", "--",
            "exec-prompt", "--full-auto", "-m", "gpt-5-codex",
        ]);
        assert_eq!(c.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(c.root, PathBuf::from("/repo"));
        assert!(c.no_redact);
        assert_eq!(c.args, vec!["exec-prompt", "--full-auto", "-m", "gpt-5-codex"]);
    }

    #[test]
    fn requires_at_least_one_arg() {
        let cli = TestCli::try_parse_from(["x", "codex"]);
        assert!(cli.is_err(), "codex requires trailing exec args");
    }

    /// End-to-end persistence: feed a small canned `--json` transcript through the
    /// adapter→redact→store path (the same `persist_stream` the command runs) and
    /// assert a redacted `Kind::Tool` event lands — the secret in a command arg is
    /// scrubbed in the persisted row.
    #[test]
    fn canned_stream_persists_redacted_tool_event() {
        let outdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap(); // no logbook.toml ⇒ recorder-on
        let args = CodexArgs {
            out_dir: outdir.path().to_path_buf(),
            root: root.path().to_path_buf(),
            no_redact: false,
            args: vec!["noop".into()],
        };
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "th_persist" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "id": "c1",
                    "type": "command_execution",
                    "command": "deploy --key AKIAIOSFODNN7EXAMPLE",
                    "status": "completed",
                    "aggregated_output": "ok",
                    "exit_code": 0
                }
            }),
            serde_json::json!({
                "type": "turn.completed",
                "usage": { "input_tokens": 10, "output_tokens": 5 }
            }),
        ];

        let (session_id, summary) = persist_stream(&args, &stream).unwrap();
        assert_eq!(session_id.as_deref(), Some("th_persist"));
        assert_eq!(summary.llm_turns, 1);
        assert_eq!(summary.tool_calls, 1);
        assert_eq!(summary.tokens, 15);

        // Read the persisted rows back through the public typed query API
        // (the body JSON is the source of truth) and confirm the secret was
        // redacted in the persisted tool event before it hit the store.
        let store = Store::open_in_dir(outdir.path()).unwrap();
        assert!(store.count().unwrap() >= 2, "expected the tool + llm rows persisted");
        let events = store
            .query(&logbook_store::Query::new().session("th_persist"))
            .unwrap();
        let tool = events
            .iter()
            .find(|e| e.kind == Kind::Tool)
            .expect("a tool event must be persisted under the session");
        let args = tool
            .blocks
            .tool
            .as_ref()
            .and_then(|t| t.arguments.as_ref())
            .expect("the persisted tool event carries redacted arguments");
        let args_s = serde_json::to_string(args).unwrap();
        assert!(
            !args_s.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked into persisted tool arguments: {args_s}"
        );
        assert!(
            args_s.contains("REDACTED:CLOUD_KEY:"),
            "persisted tool arguments must be redacted: {args_s}"
        );
        // The session id is carried on the persisted event (correlation).
        assert_eq!(tool.session_id.as_ref().map(|s| s.as_str()), Some("th_persist"));
    }

    /// Capture paused (master off via the cross-process `capture-state.json`
    /// overlay) ⇒ `persist_stream` writes nothing, but still reports the session
    /// id from the stream for the summary.
    #[test]
    fn capture_paused_persists_nothing() {
        let outdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        // The UI toggle's narrow-only overlay: master off.
        let state = logbook_core::CaptureState {
            enabled: Some(false),
            ..Default::default()
        };
        state.save(outdir.path()).unwrap();

        let args = CodexArgs {
            out_dir: outdir.path().to_path_buf(),
            root: root.path().to_path_buf(),
            no_redact: false,
            args: vec!["noop".into()],
        };
        let stream = vec![
            serde_json::json!({ "type": "thread.started", "thread_id": "th_paused" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "c1", "type": "command_execution", "command": "echo hi", "status": "completed", "aggregated_output": "hi", "exit_code": 0 }
            }),
        ];
        let (session_id, summary) = persist_stream(&args, &stream).unwrap();
        assert_eq!(session_id.as_deref(), Some("th_paused"));
        assert_eq!(summary, Summary::default(), "paused ⇒ nothing tallied/persisted");
        // The store has no rows (open it lazily — nothing was written).
        if let Ok(store) = Store::open_in_dir(outdir.path()) {
            assert_eq!(store.count().unwrap(), 0, "master-off ⇒ no codex rows persisted");
        }
    }

    #[test]
    fn summary_tally_counts_kinds_and_tokens() {
        // A mixed batch: 1 llm (15 tok), 1 shell tool, 1 file_change, 1 agent msg.
        let mut a = CodexJsonAdapter::with_defaults(logbook_core::TraceId::new(), "t");
        let evs = a.parse_stream(&[
            serde_json::json!({ "type": "thread.started", "thread_id": "t" }),
            serde_json::json!({ "type": "turn.started" }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "c", "type": "command_execution", "command": "ls", "status": "completed", "aggregated_output": "x", "exit_code": 0 }
            }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "f", "type": "file_change", "status": "completed", "changes": [{"path": "a"}] }
            }),
            serde_json::json!({
                "type": "item.completed",
                "item": { "id": "m", "type": "agent_message", "text": "done" }
            }),
            serde_json::json!({ "type": "turn.completed", "usage": { "input_tokens": 10, "output_tokens": 5 } }),
        ]);
        let s = Summary::tally(&evs);
        assert_eq!(s.llm_turns, 1);
        assert_eq!(s.tool_calls, 1, "shell counts as a tool call");
        assert_eq!(s.file_changes, 1, "file_change is broken out");
        assert_eq!(s.tokens, 15);
    }

    #[test]
    fn exit_code_of_reads_normal_exit() {
        // A normal exit code is propagated. (Signal mapping is unix-only and not
        // easily constructed portably in a unit test; the code path is small.)
        use std::process::Command;
        let status = Command::new("sh").arg("-c").arg("exit 7").status().unwrap();
        assert_eq!(exit_code_of(&status), 7);
        let ok = Command::new("sh").arg("-c").arg("exit 0").status().unwrap();
        assert_eq!(exit_code_of(&ok), 0);
    }
}
