//! `logbook import <cursor|gemini|continue>` — retroactively pull a historical
//! GUI/IDE-agent session off disk, redact it through the mandatory secrets floor,
//! and land it on the **same** SQLite timeline as live captures (plan "Phase 0"
//! + the `logbook import` CLI surface).
//!
//! This is a **read-shaped** command (it reads conversation stores the tool
//! already wrote) so — like `security import` — it carries **no permission gate**.
//! It is the persistence boundary for the import path: it resolves the
//! [`CapturePolicy`] + redactor (copying the `logbook codex` wiring), mints a
//! fresh [`HarnessContext`] per session, runs the tool's harness adapter
//! ([`CursorAdapter`] / [`GeminiAdapter`] / [`ContinueAdapter`], dispatched by
//! [`build_session_events`]) via [`logbook_import::runner::import_session`], and
//! persists the resulting [`ImportBatch`] — an `agent_sessions` header row
//! (mandatory: the Sessions list/replay reads it first) plus the redacted
//! events. All three tools share this one persistence path.
//!
//! ## Determinism (plan §Determinism contract)
//! Every imported id + timestamp is derived, never random / `now()`, so
//! re-importing an unchanged store reproduces byte-identical rows. The CLI mints
//! the per-session [`TraceId`] via [`import_trace_id`] and the session id via
//! [`import_session_id`] (both fold in the store's `origin_fingerprint`, so two
//! workspaces sharing a native key never collide).
//!
//! ## Redaction is sacred (plan §9)
//! The source moves only opaque [`serde_json::Value`]s; the adapter is the sole
//! component that redacts and builds events. `--no-redact` disables only the
//! **general** redactor — the secrets floor always runs.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use logbook_core::{
    CapturePolicy, CliOverlay, Event, Kind, MicrosTimestamp, Redactor, TraceId,
};
use logbook_harness::{ContinueAdapter, CursorAdapter, GeminiAdapter, HarnessContext};
use logbook_import::{
    discover_sessions, import_session_id, import_trace_id, origin_fingerprint, runner, source_for,
    Diag, DiscoveredSession, ImportSessionHeader, Level, SessionRecords, Tool,
};
use logbook_inventory::store_ext::insert_agent_session;
use logbook_inventory::AgentSessionRecord;
use logbook_store::Store;

/// Sessions above this count require an explicit `--yes` (a large sweep is opt-in,
/// matching `forget`'s non-interactive confirmation posture). Below it, the
/// command proceeds without prompting.
const LARGE_SWEEP_THRESHOLD: usize = 25;

/// The tools `logbook import` can pull from (the CLI's own `ValueEnum`; the
/// library has a parallel [`Tool`]). All three — Cursor (SQLite), Gemini and
/// Continue (JSON transcripts) — are functional.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ImportTool {
    /// The Cursor IDE (SQLite `state.vscdb` conversation stores).
    Cursor,
    /// The Gemini CLI/assistant (`session-*.json` transcripts).
    Gemini,
    /// The Continue extension (`~/.continue/sessions/*.json` history files).
    Continue,
}

impl ImportTool {
    /// Map to the library [`Tool`].
    fn to_lib(self) -> Tool {
        match self {
            ImportTool::Cursor => Tool::Cursor,
            ImportTool::Gemini => Tool::Gemini,
            ImportTool::Continue => Tool::Continue,
        }
    }
}

/// `logbook import <tool> [opts]`.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Which tool's on-disk conversation stores to import from.
    #[arg(value_enum)]
    pub tool: ImportTool,

    /// Import exactly one discovered session by its `import_id`
    /// (`<origin_fingerprint>:<native_key>`, the globally-unique selector). A bare
    /// `<native_key>` is accepted only when it matches exactly one discovered
    /// session, else the command errors listing the candidate `import_id`s.
    #[arg(long)]
    pub session: Option<String>,

    /// Only import sessions active within this duration (e.g. `7d`, `24h`, `30m`,
    /// `90s`, or a bare integer = seconds). Undated sessions are **included with a
    /// warning** (dropping them silently is worse for a blind-spot tool).
    #[arg(long)]
    pub since: Option<String>,

    /// Cap the number of sessions imported (after `--since` filtering).
    #[arg(long)]
    pub max_sessions: Option<usize>,

    /// Confirm a large sweep (> 25 sessions). Without it such a sweep errors
    /// rather than prompting (the CLI is used non-interactively).
    #[arg(long)]
    pub yes: bool,

    /// Preview only: open no store, insert nothing — print the sessions that
    /// would be imported (+ any discovery diagnostics) and exit 0.
    #[arg(long)]
    pub dry_run: bool,

    /// Override discovery: point at a single store file or directory (fixtures,
    /// non-standard installs, a store copied off another machine) instead of the
    /// per-OS data roots.
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Disable the **general** (non-secret) redactor. The secrets floor (cloud
    /// keys, JWT, bearer, PEM, …) is **never** disabled.
    #[arg(long)]
    pub no_redact: bool,

    /// Out-dir holding the logbook store the imported session is written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root holding `logbook.toml` (the `[capture]` policy +
    /// `[redaction]` patterns). Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
}

/// A per-import tally for the closing summary.
#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    /// Sessions persisted.
    sessions: usize,
    /// `Kind::Agent` events (user prompts + assistant messages).
    agent_events: usize,
    /// `Kind::Llm` events.
    llm_events: usize,
    /// `Kind::Tool` events.
    tool_events: usize,
    /// Sessions skipped due to a read error (a `Diag` was emitted).
    skipped: usize,
}

impl Summary {
    /// Fold one session's events into the tally.
    fn add_events(&mut self, events: &[Event]) {
        for ev in events {
            match ev.kind {
                Kind::Agent => self.agent_events += 1,
                Kind::Llm => self.llm_events += 1,
                Kind::Tool => self.tool_events += 1,
                _ => {}
            }
        }
    }
}

/// Dispatch a `logbook import` invocation.
///
/// # Errors
/// Returns an error if `--session` is ambiguous, a large sweep lacks `--yes`, a
/// `--since` duration cannot be parsed, or the store cannot be opened / written.
pub fn run(args: ImportArgs) -> anyhow::Result<i32> {
    let tool = args.tool.to_lib();

    // Resolve the discovery roots: an explicit `--path` overrides the per-OS data
    // roots entirely (fixtures / copied stores).
    let roots = match &args.path {
        Some(p) => logbook_import::discovery::from_path(p.clone()),
        None => logbook_import::discovery::resolve(),
    };

    let (discovered, discovery_diags) = discover_sessions(tool, &roots);

    // Apply the --since / --session / --max-sessions filters.
    let mut selected = discovered.clone();
    let mut filter_diags: Vec<Diag> = Vec::new();
    if let Some(since) = &args.since {
        selected = filter_since(selected, since, &mut filter_diags)?;
    }
    if let Some(sel) = &args.session {
        selected = vec![select_one(&selected, sel)?];
    }
    if let Some(max) = args.max_sessions {
        selected.truncate(max);
    }

    // --dry-run: open no store, print a table + diags, return 0.
    if args.dry_run {
        print_dry_run(tool, &selected, &discovery_diags, &filter_diags);
        return Ok(0);
    }

    // A large sweep without --yes errors (non-interactive, matching `forget`).
    if selected.len() > LARGE_SWEEP_THRESHOLD && !args.yes && args.session.is_none() {
        anyhow::bail!(
            "{} sessions to import; re-run with --yes (or --dry-run to preview)",
            selected.len()
        );
    }

    if args.no_redact {
        eprintln!(
            "logbook: WARNING --no-redact is set; the secrets floor still applies, but \
             non-secret payloads may be persisted to {}.",
            args.out_dir.display()
        );
    }

    // Surface discovery + filter diagnostics up front (locked stores, undated
    // sessions, …) so the user sees them even on a successful import.
    print_diags(&discovery_diags);
    print_diags(&filter_diags);

    if selected.is_empty() {
        println!("import {tool}: no sessions to import.");
        return Ok(0);
    }

    let summary = import_all(tool, &args, &selected)?;
    print_summary(tool, &summary);
    Ok(0)
}

/// Import every selected session, persisting each [`ImportBatch`] (header →
/// `AgentSessionRecord`, then events), and return the [`Summary`].
fn import_all(tool: Tool, args: &ImportArgs, selected: &[DiscoveredSession]) -> anyhow::Result<Summary> {
    let source = source_for(tool);
    let store = Store::open_in_dir(&args.out_dir)?;
    let mut summary = Summary::default();

    for session in selected {
        // Mint the deterministic identity for THIS session up front (the closure
        // below + the header both need it).
        let fp = origin_fingerprint(&session.origin);
        let trace = import_trace_id(tool, &fp, &session.native_id);
        let session_id = import_session_id(tool, &fp, &session.native_id);

        // The adapter seam: a fresh HarnessContext per session (it is not Clone),
        // run the tool's harness adapter, and assemble the deterministic header.
        let build = |records: &SessionRecords| -> (Vec<Event>, ImportSessionHeader) {
            let ctx = build_context(args);
            let mut events = build_session_events(tool, trace, ctx, session, records);

            // Stamp the deterministic session id on every event (the adapter set
            // the native per-tool session id; the timeline key is
            // import_session_id).
            for ev in &mut events {
                ev.session_id = Some(logbook_core::SessionId::new(&session_id));
            }

            let header = build_header(tool, &session_id, trace, session, &events);
            (events, header)
        };

        match runner::import_session(source.as_ref(), session, &build) {
            Ok(batch) => {
                // Persist: the header FIRST (the Sessions list/replay reads the
                // agent_sessions row before the events), then the events.
                let record = header_to_record(&batch.header);
                insert_agent_session(&store, &record)
                    .map_err(|e| anyhow::anyhow!("persisting session header: {e}"))?;
                summary.add_events(&batch.events);
                summary.sessions += 1;
                if !batch.events.is_empty() {
                    store.insert_batch(batch.events)?;
                }
                // Any adapter-level diagnostics (none today, but future-proof).
                print_diags(&batch.diagnostics);
            }
            Err(e) => {
                // A read failure (lock, corruption) → a Diag + skip, never fatal.
                summary.skipped += 1;
                let diag = Diag::warn(session.origin.clone(), format!("skipped {}: {e}", session.import_id));
                print_diags(std::slice::from_ref(&diag));
            }
        }
    }

    Ok(summary)
}

/// Build one session's redacted [`Event`]s by routing its raw records through
/// the tool's harness adapter.
///
/// The three retroactive-import adapters ([`CursorAdapter`], [`GeminiAdapter`],
/// [`ContinueAdapter`]) share an identical construction shape
/// (`new(trace, ctx, version, native_session_id, base_ts)`) and the same
/// `parse_records(&records, &meta)` entry point, but are distinct types with no
/// shared object-safe trait, so dispatch is a small `match` here. Each is the
/// **sole** redactor + event builder for its tool; the source moved only opaque
/// [`serde_json::Value`]s. `base_ts` is the discovered store's `mtime` (the
/// deterministic fallback timestamp for undated records).
fn build_session_events(
    tool: Tool,
    trace: TraceId,
    ctx: HarnessContext,
    session: &DiscoveredSession,
    records: &SessionRecords,
) -> Vec<Event> {
    let version = tool_version(tool);
    let native = session.native_id.clone();
    let base_ts = session.mtime.as_micros();
    match tool {
        Tool::Cursor => CursorAdapter::new(trace, ctx, version, native, base_ts)
            .parse_records(&records.records, &records.session_meta),
        Tool::Gemini => GeminiAdapter::new(trace, ctx, version, native, base_ts)
            .parse_records(&records.records, &records.session_meta),
        Tool::Continue => ContinueAdapter::new(trace, ctx, version, native, base_ts)
            .parse_records(&records.records, &records.session_meta),
    }
}

/// Build the per-session [`HarnessContext`] (copied from `logbook codex`):
/// resolve the capture policy fail-closed, build the general redactor from
/// `<root>/logbook.toml [redaction]` gated by `--no-redact`, and layer the
/// mandatory secrets floor (inside the context) on top regardless.
fn build_context(args: &ImportArgs) -> HarnessContext {
    let overlay = CliOverlay {
        no_redact: args.no_redact,
        ..Default::default()
    };
    let policy = CapturePolicy::resolve(&args.root, &args.out_dir, overlay);

    let cfg = logbook_core::LogbookConfig::load_from_root_or_default(&args.root);
    let general_redaction_enabled = cfg.redaction.enabled && !args.no_redact;
    let redactor = if general_redaction_enabled {
        logbook_core::redact::from_config(true, &cfg.redaction.deny, &cfg.redaction.allow)
            .unwrap_or_else(|_| {
                tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
                Redactor::new().with_process_env()
            })
    } else {
        // Secrets floor only (constructed inside HarnessContext); a disabled
        // general redactor keeps non-secret content intact under `--no-redact`.
        Redactor::disabled()
    };

    HarnessContext::new(redactor, policy, general_redaction_enabled)
}

/// Build the deterministic [`ImportSessionHeader`]: ids derived above, the
/// `started_at`/`ended_at` from the min/max event timestamp (falling back to the
/// store `mtime` when the session produced no events).
fn build_header(
    tool: Tool,
    session_id: &str,
    trace: TraceId,
    session: &DiscoveredSession,
    events: &[Event],
) -> ImportSessionHeader {
    let (started_at, ended_at) = timestamp_span(events, session.mtime);
    ImportSessionHeader {
        session_id: session_id.to_string(),
        trace_id: trace.to_hex(),
        agent: tool.as_str().to_string(),
        command: format!("import:{tool}"),
        started_at,
        ended_at: Some(ended_at),
    }
}

/// The min/max event timestamp, falling back to the store `mtime` for a session
/// that produced no events (so the header is always deterministic, never
/// `now()`).
fn timestamp_span(events: &[Event], mtime: MicrosTimestamp) -> (i64, i64) {
    let mut min = None::<i64>;
    let mut max = None::<i64>;
    for ev in events {
        let ts = ev.timestamp.as_micros();
        min = Some(min.map_or(ts, |m| m.min(ts)));
        max = Some(max.map_or(ts, |m| m.max(ts)));
    }
    match (min, max) {
        (Some(lo), Some(hi)) => (lo, hi),
        _ => (mtime.as_micros(), mtime.as_micros()),
    }
}

/// Map the neutral [`ImportSessionHeader`] onto an
/// [`AgentSessionRecord`] for `insert_agent_session`. Imported sessions carry no
/// endpoint / exit code, so those are `None`.
fn header_to_record(header: &ImportSessionHeader) -> AgentSessionRecord {
    AgentSessionRecord {
        session_id: header.session_id.clone(),
        endpoint_id: None,
        agent: header.agent.clone(),
        command: header.command.clone(),
        trace_id: header.trace_id.clone(),
        started_at: header.started_at,
        ended_at: header.ended_at,
        exit_code: None,
    }
}

// ---------------------------------------------------------------------------
// Selection / filtering
// ---------------------------------------------------------------------------

/// Filter sessions to those active within `since` (a duration before now).
/// Undated sessions (no `last_active`) are **kept** with a warning — silently
/// dropping them is worse for a blind-spot tool; they fall back to `mtime`.
fn filter_since(
    sessions: Vec<DiscoveredSession>,
    since: &str,
    diags: &mut Vec<Diag>,
) -> anyhow::Result<Vec<DiscoveredSession>> {
    let cutoff = cutoff_micros(since, MicrosTimestamp::now().as_micros())?;
    let mut undated = 0usize;
    let out: Vec<DiscoveredSession> = sessions
        .into_iter()
        .filter(|s| {
            // Prefer last_active; fall back to mtime; if neither dates the
            // session, keep it (with a warning) rather than drop it.
            let stamp = s.last_active.map(|t| t.as_micros()).unwrap_or(s.mtime.as_micros());
            if s.last_active.is_none() {
                undated += 1;
            }
            stamp >= cutoff
        })
        .collect();
    if undated > 0 {
        diags.push(Diag::warn(
            PathBuf::from("(discovery)"),
            format!("{undated} session(s) had no last-active time; included via store mtime"),
        ));
    }
    Ok(out)
}

/// Resolve a `--session` selector to exactly one discovered session. Accepts the
/// full `import_id` (`fp:native_key`) or a bare native key when it is unique;
/// errors listing the candidate `import_id`s on ambiguity / no match.
fn select_one(sessions: &[DiscoveredSession], sel: &str) -> anyhow::Result<DiscoveredSession> {
    // Exact import_id match wins.
    if let Some(s) = sessions.iter().find(|s| s.import_id == sel) {
        return Ok(s.clone());
    }
    // Else a bare native key, accepted only when unique.
    let matches: Vec<&DiscoveredSession> = sessions.iter().filter(|s| s.native_id == sel).collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => anyhow::bail!(
            "no discovered session matches --session {sel:?}; run with --dry-run to list candidates"
        ),
        many => {
            let ids: Vec<&str> = many.iter().map(|s| s.import_id.as_str()).collect();
            anyhow::bail!(
                "--session {sel:?} is ambiguous ({} matches); pass one of the import_ids: {}",
                many.len(),
                ids.join(", ")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Print the `--dry-run` table: one row per session + diagnostics + footer.
fn print_dry_run(tool: Tool, sessions: &[DiscoveredSession], discovery: &[Diag], filter: &[Diag]) {
    println!(
        "{:<8} {:<40} {:<28} {:<22} {:<8} origin",
        "tool", "import_id", "native_id", "title", "msgs"
    );
    for s in sessions {
        let title = s.title.as_deref().unwrap_or("");
        let msgs = s
            .approx_messages
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        println!(
            "{:<8} {:<40} {:<28} {:<22} {:<8} {}",
            tool,
            truncate(&s.import_id, 40),
            truncate(&s.native_id, 28),
            truncate(title, 22),
            msgs,
            s.origin.display()
        );
    }
    print_diags(discovery);
    print_diags(filter);
    println!(
        "would import {} session{}.",
        sessions.len(),
        plural(sessions.len())
    );
}

/// Print the closing import summary.
fn print_summary(tool: Tool, s: &Summary) {
    println!(
        "import {tool}: {} session{}, {} agent / {} llm / {} tool event{}{}.",
        s.sessions,
        plural(s.sessions),
        s.agent_events,
        s.llm_events,
        s.tool_events,
        plural(s.agent_events + s.llm_events + s.tool_events),
        if s.skipped > 0 {
            format!(", {} skipped", s.skipped)
        } else {
            String::new()
        }
    );
}

/// Print diagnostics to stderr (one line each, level-tagged).
fn print_diags(diags: &[Diag]) {
    for d in diags {
        let tag = match d.level {
            Level::Warn => "WARNING",
            Level::Error => "ERROR",
        };
        eprintln!("logbook: {tag} [{}] {}", d.origin.display(), d.msg);
    }
}

/// Truncate a string to `max` chars for the dry-run table columns.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

/// `""`/`"s"` pluralization helper.
fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// The per-tool version banner stamped on events (best-effort from the env; the
/// adapter scrubs + caps it regardless). Each tool reads its own `*_VERSION` env
/// var, defaulting to `"unknown"`.
fn tool_version(tool: Tool) -> String {
    let var = match tool {
        Tool::Cursor => "CURSOR_VERSION",
        Tool::Gemini => "GEMINI_VERSION",
        Tool::Continue => "CONTINUE_VERSION",
    };
    std::env::var(var).unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Duration parsing (mirrors `forget --before`)
// ---------------------------------------------------------------------------

/// Compute the absolute microsecond cut-off for `--since <duration>`: sessions
/// active at/after `now - duration` are kept. Clamped at `0`.
fn cutoff_micros(spec: &str, now_micros: i64) -> anyhow::Result<i64> {
    let secs = duration_to_secs(spec)?;
    let span = secs.saturating_mul(1_000_000);
    Ok(now_micros.saturating_sub(span).max(0))
}

/// Parse a `<int><unit>` duration into whole seconds (`d`/`h`/`m`/`s`; a bare
/// integer is seconds). Mirrors `forget`'s parser so the two read identically.
fn duration_to_secs(spec: &str) -> anyhow::Result<i64> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("--since requires a duration (e.g. 7d, 24h, 30m, 90s)");
    }
    let (digits, unit) = match spec.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((idx, _)) => (&spec[..idx], &spec[idx..]),
        None => (spec, ""),
    };
    if digits.is_empty() {
        anyhow::bail!("invalid --since duration {spec:?}: expected a leading integer (e.g. 7d)");
    }
    let n: i64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --since duration {spec:?}: {digits:?} is not an integer"))?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        other => anyhow::bail!(
            "invalid --since duration unit {other:?}: use d (days), h (hours), m (minutes), or s (seconds)"
        ),
    };
    Ok(n.saturating_mul(mult))
}

/// Group-by helper used only by tests below (kept here so the test module stays
/// terse). Counts events per `Kind`.
#[cfg(test)]
fn kind_counts(events: &[Event]) -> std::collections::BTreeMap<&'static str, usize> {
    let mut m = std::collections::BTreeMap::new();
    for ev in events {
        *m.entry(ev.kind.as_str()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rusqlite::params;
    use rusqlite::Connection;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Import(ImportArgs),
    }

    fn parse(argv: &[&str]) -> Result<ImportArgs, clap::Error> {
        TestCli::try_parse_from(argv).map(|c| match c.cmd {
            TestCmd::Import(a) => a,
        })
    }

    /// Seed a workspace `state.vscdb` with one chat tab carrying a planted secret.
    fn seed_store(path: &std::path::Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)", [])
            .unwrap();
        let chat = serde_json::json!({
            "tabs": [{
                "tabId": "tab-1",
                "chatTitle": "Imported chat",
                "bubbles": [
                    { "type": "user", "rawText": "deploy with AKIAIOSFODNN7EXAMPLE" },
                    { "type": "assistant", "text": "done" }
                ]
            }]
        });
        conn.execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params!["workbench.panel.aichat.view.aichat.chatdata", chat.to_string()],
        )
        .unwrap();
    }

    fn import_args(tool: ImportTool, path: PathBuf, out_dir: PathBuf, root: PathBuf) -> ImportArgs {
        ImportArgs {
            tool,
            session: None,
            since: None,
            max_sessions: None,
            yes: false,
            dry_run: false,
            path: Some(path),
            no_redact: false,
            out_dir,
            root,
        }
    }

    #[test]
    fn parses_cursor_defaults() {
        let a = parse(&["x", "import", "cursor"]).unwrap();
        assert_eq!(a.tool, ImportTool::Cursor);
        assert_eq!(a.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(a.root, PathBuf::from("."));
        assert!(!a.no_redact && !a.dry_run && !a.yes);
    }

    #[test]
    fn parses_all_flags_and_tools() {
        let a = parse(&[
            "x", "import", "cursor", "--session", "fp:chat/tab-1", "--since", "7d",
            "--max-sessions", "3", "--yes", "--dry-run", "--path", "/tmp/s", "--no-redact",
            "--out-dir", "/tmp/o", "--root", "/repo",
        ])
        .unwrap();
        assert_eq!(a.session.as_deref(), Some("fp:chat/tab-1"));
        assert_eq!(a.since.as_deref(), Some("7d"));
        assert_eq!(a.max_sessions, Some(3));
        assert!(a.yes && a.dry_run && a.no_redact);
        assert_eq!(a.path, Some(PathBuf::from("/tmp/s")));
        // gemini + continue parse as values.
        assert_eq!(parse(&["x", "import", "gemini"]).unwrap().tool, ImportTool::Gemini);
        assert_eq!(parse(&["x", "import", "continue"]).unwrap().tool, ImportTool::Continue);
    }

    /// Seed a Gemini `session-*.json` transcript with a planted secret + native
    /// timestamps + tokens.
    fn seed_gemini(path: &std::path::Path) {
        let session = serde_json::json!({
            "sessionId": "gem-sess-1",
            "projectHash": "proj-abc",
            "lastUpdated": 1_700_000_500_000_i64,
            "messages": [
                { "type": "user", "content": "deploy with AKIAIOSFODNN7EXAMPLE", "timestamp": 1_700_000_111_000_i64 },
                { "type": "gemini", "content": "done", "model": "gemini-2.0-flash", "tokens": { "input": 5, "output": 7 }, "timestamp": 1_700_000_222_000_i64 }
            ]
        });
        std::fs::write(path, session.to_string()).unwrap();
    }

    /// Seed a Continue `*.json` history file with a planted secret + a tool call.
    fn seed_continue(path: &std::path::Path) {
        let session = serde_json::json!({
            "sessionId": "cont-sess-1",
            "title": "Imported Continue chat",
            "workspaceDirectory": "/home/me/proj",
            "history": [
                { "message": { "role": "user", "content": "deploy with AKIAIOSFODNN7EXAMPLE" } },
                {
                    "message": {
                        "role": "assistant",
                        "content": "editing now",
                        "toolCalls": [ { "id": "c1", "function": { "name": "edit_file", "arguments": "{\"path\":\"/app/x.rs\"}" } } ]
                    },
                    "toolCallStates": [ { "status": "done", "toolCallId": "c1", "output": "edit applied" } ]
                }
            ]
        });
        std::fs::write(path, session.to_string()).unwrap();
    }

    /// End-to-end: `--path` a Gemini transcript → the persisted user-prompt body
    /// is redacted, `session_id` is set, an `agent_sessions` row exists, and the
    /// native timestamp is preserved on the persisted event.
    #[test]
    fn gemini_import_persists_redacted_session_with_header() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("session-gem.json");
        seed_gemini(&file);

        let out = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let code = run(import_args(
            ImportTool::Gemini,
            file.clone(),
            out.path().to_path_buf(),
            root.path().to_path_buf(),
        ))
        .unwrap();
        assert_eq!(code, 0);

        let store = Store::open_in_dir(out.path()).unwrap();
        let sessions = logbook_ui::sessions::list_sessions(&store).unwrap();
        assert_eq!(sessions.len(), 1, "exactly one imported Gemini session header");
        assert_eq!(sessions[0].agent, "gemini");
        let sid = sessions[0].session_id.clone();
        let detail = logbook_ui::sessions::load_session(&store, &sid)
            .unwrap()
            .expect("load_session must return the imported Gemini session");
        assert!(!detail.events.is_empty());

        let user = detail
            .events
            .iter()
            .find(|e| e.kind == Kind::Agent && e.input.is_some())
            .expect("a user prompt event with a body");
        let body = user.input.as_ref().unwrap().as_str().unwrap();
        assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {body}");
        assert!(body.contains("REDACTED:CLOUD_KEY:"), "not redacted: {body}");
        // The native millis timestamp (1_700_000_111_000) survives as micros.
        assert_eq!(user.timestamp, MicrosTimestamp(1_700_000_111_000_000));
        // An LLM event carries the token counts.
        let llm = detail
            .events
            .iter()
            .find(|e| e.kind == Kind::Llm)
            .expect("an llm event");
        let lb = llm.blocks.llm.as_ref().unwrap();
        assert_eq!(lb.input_tokens, Some(5));
        assert_eq!(lb.output_tokens, Some(7));
    }

    /// End-to-end: `--path` a Continue history file → the persisted body is
    /// redacted, the tool-call result is redacted, and `session_id`/header land.
    #[test]
    fn continue_import_persists_redacted_session_with_header() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cont-session.json");
        seed_continue(&file);

        let out = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let code = run(import_args(
            ImportTool::Continue,
            file.clone(),
            out.path().to_path_buf(),
            root.path().to_path_buf(),
        ))
        .unwrap();
        assert_eq!(code, 0);

        let store = Store::open_in_dir(out.path()).unwrap();
        let sessions = logbook_ui::sessions::list_sessions(&store).unwrap();
        assert_eq!(sessions.len(), 1, "exactly one imported Continue session header");
        assert_eq!(sessions[0].agent, "continue");
        let sid = sessions[0].session_id.clone();
        let detail = logbook_ui::sessions::load_session(&store, &sid)
            .unwrap()
            .expect("load_session must return the imported Continue session");

        for ev in &detail.events {
            assert_eq!(ev.session_id.as_ref().map(|s| s.as_str()), Some(sid.as_str()));
            // Continue is undated ⇒ every event is approx.
            assert_eq!(
                ev.attributes.get("imported_timestamp").and_then(|v| v.as_str()),
                Some("approx")
            );
        }
        let user = detail
            .events
            .iter()
            .find(|e| e.kind == Kind::Agent && e.input.is_some())
            .expect("a user prompt event with a body");
        let body = user.input.as_ref().unwrap().as_str().unwrap();
        assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {body}");
        // A tool event is present (edit_file) and is a write.
        let tool = detail
            .events
            .iter()
            .find(|e| e.kind == Kind::Tool)
            .expect("a tool event");
        assert_eq!(tool.blocks.tool.as_ref().unwrap().is_write, Some(true));
    }

    /// The determinism test for the Continue (JSON, undated) path: importing the
    /// SAME unchanged file twice reproduces byte-identical rows (ids, timestamps,
    /// bodies) and does NOT grow the store. The mtime+index fallback is stable for
    /// an unchanged file.
    #[test]
    fn continue_double_import_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cont-session.json");
        seed_continue(&file);
        let out = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();

        let run_once = || {
            run(import_args(
                ImportTool::Continue,
                file.clone(),
                out.path().to_path_buf(),
                root.path().to_path_buf(),
            ))
            .unwrap()
        };

        run_once();
        let store = Store::open_in_dir(out.path()).unwrap();
        let count1 = store.count().unwrap();
        let trace1 = first_trace(&store);
        let events1 = store.trace(&trace1).unwrap();

        run_once(); // second import of the unchanged file
        let store2 = Store::open_in_dir(out.path()).unwrap();
        let count2 = store2.count().unwrap();
        let events2 = store2.trace(&trace1).unwrap();

        assert_eq!(count1, count2, "re-import must not grow the store");
        assert_eq!(
            events1, events2,
            "re-import must reproduce byte-identical event rows (ids/timestamps/bodies)"
        );
        let sessions = logbook_ui::sessions::list_sessions(&store2).unwrap();
        assert_eq!(sessions.len(), 1, "still exactly one session after re-import");
    }

    /// End-to-end: `--path` a temp store at a path with spaces + unicode →
    /// the persisted row is redacted, `session_id` is set, an `agent_sessions`
    /// row exists, and a `load_session`-style read returns it.
    #[test]
    fn import_persists_redacted_session_with_header() {
        let dir = tempfile::tempdir().unwrap();
        // Path with spaces + unicode (the plan's explicit requirement).
        let weird = dir.path().join("Cursor störe — wîth spaces");
        std::fs::create_dir_all(&weird).unwrap();
        let db = weird.join("state.vscdb");
        seed_store(&db);

        let out = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap(); // no logbook.toml ⇒ recorder-on
        let args = import_args(
            ImportTool::Cursor,
            db.clone(),
            out.path().to_path_buf(),
            root.path().to_path_buf(),
        );
        let code = run(args).unwrap();
        assert_eq!(code, 0);

        // The agent_sessions header row exists and load_session returns it.
        let store = Store::open_in_dir(out.path()).unwrap();
        let sessions = logbook_ui::sessions::list_sessions(&store).unwrap();
        assert_eq!(sessions.len(), 1, "exactly one imported session header");
        let sid = sessions[0].session_id.clone();
        assert_eq!(sessions[0].agent, "cursor");
        let detail = logbook_ui::sessions::load_session(&store, &sid)
            .unwrap()
            .expect("load_session must return the imported session");
        assert!(!detail.events.is_empty(), "the session's events are correlated by trace");

        // Every persisted event carries the import session id, and the planted
        // secret is redacted out of the user-prompt body.
        for ev in &detail.events {
            assert_eq!(ev.session_id.as_ref().map(|s| s.as_str()), Some(sid.as_str()));
        }
        let user = detail
            .events
            .iter()
            .find(|e| e.kind == Kind::Agent && e.input.is_some())
            .expect("a user prompt event with a body");
        let body = user.input.as_ref().unwrap().as_str().unwrap();
        assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {body}");
        assert!(body.contains("REDACTED:CLOUD_KEY:"), "not redacted: {body}");
    }

    /// The key determinism test: importing the SAME unchanged store twice
    /// reproduces byte-identical rows (ids, timestamps, bodies) and does NOT grow
    /// the store.
    #[test]
    fn double_import_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        seed_store(&db);
        let out = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();

        let run_once = || {
            run(import_args(
                ImportTool::Cursor,
                db.clone(),
                out.path().to_path_buf(),
                root.path().to_path_buf(),
            ))
            .unwrap()
        };

        run_once();
        let store = Store::open_in_dir(out.path()).unwrap();
        let count1 = store.count().unwrap();
        let trace1 = first_trace(&store);
        let events1 = store.trace(&trace1).unwrap();

        run_once(); // second import of the unchanged store
        let store2 = Store::open_in_dir(out.path()).unwrap();
        let count2 = store2.count().unwrap();
        let events2 = store2.trace(&trace1).unwrap();

        assert_eq!(count1, count2, "re-import must not grow the store");
        assert_eq!(
            events1, events2,
            "re-import must reproduce byte-identical event rows (ids/timestamps/bodies)"
        );

        // The header row is also stable (one session, same id/timestamps).
        let sessions = logbook_ui::sessions::list_sessions(&store2).unwrap();
        assert_eq!(sessions.len(), 1, "still exactly one session after re-import");
    }

    #[test]
    fn dry_run_opens_no_store_and_lists() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        seed_store(&db);
        let out = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut args = import_args(
            ImportTool::Cursor,
            db.clone(),
            out.path().to_path_buf(),
            root.path().to_path_buf(),
        );
        args.dry_run = true;
        let code = run(args).unwrap();
        assert_eq!(code, 0);
        // No store was created in the out-dir (dry-run opens nothing).
        assert!(
            !out.path().join(logbook_store::DB_FILENAME).exists(),
            "--dry-run must not create the store"
        );
    }

    #[test]
    fn select_one_disambiguates_or_errors() {
        let s = |fp: &str, native: &str| DiscoveredSession {
            tool: "cursor".into(),
            native_id: native.into(),
            import_id: DiscoveredSession::make_import_id(fp, native),
            origin: PathBuf::from("/x"),
            locator: logbook_import::SessionLocator::Key(native.into()),
            title: None,
            last_active: None,
            mtime: MicrosTimestamp(0),
            approx_messages: None,
            workspace: None,
        };
        let sessions = vec![s("aaa", "chat/tab-1"), s("bbb", "chat/tab-1")];
        // Full import_id selects exactly.
        let one = select_one(&sessions, "aaa:chat/tab-1").unwrap();
        assert_eq!(one.import_id, "aaa:chat/tab-1");
        // A bare native key shared by both is ambiguous → error lists candidates.
        let err = select_one(&sessions, "chat/tab-1").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ambiguous"), "got: {msg}");
        assert!(msg.contains("aaa:chat/tab-1") && msg.contains("bbb:chat/tab-1"));
        // A unique bare key resolves.
        let unique = vec![s("ccc", "chat/only")];
        assert_eq!(select_one(&unique, "chat/only").unwrap().import_id, "ccc:chat/only");
        // No match errors.
        assert!(select_one(&unique, "nope").is_err());
    }

    #[test]
    fn duration_units_parse_like_forget() {
        assert_eq!(duration_to_secs("90").unwrap(), 90);
        assert_eq!(duration_to_secs("30m").unwrap(), 1_800);
        assert_eq!(duration_to_secs("24h").unwrap(), 86_400);
        assert_eq!(duration_to_secs("7d").unwrap(), 604_800);
        assert!(duration_to_secs("7y").is_err());
        assert!(duration_to_secs("").is_err());
    }

    #[test]
    fn kind_counts_tallies() {
        let trace = TraceId::new();
        let evs = vec![
            Event::new(trace, Kind::Agent, logbook_core::Category::Agent, "a"),
            Event::new(trace, Kind::Tool, logbook_core::Category::Agent, "t"),
            Event::new(trace, Kind::Tool, logbook_core::Category::Agent, "t"),
        ];
        let c = kind_counts(&evs);
        assert_eq!(c.get("agent"), Some(&1));
        assert_eq!(c.get("tool"), Some(&2));
    }

    /// Read the trace id of the first persisted event (helper for the
    /// determinism test).
    fn first_trace(store: &Store) -> String {
        let events = store.query(&logbook_store::Query::new()).unwrap();
        events.first().map(|e| e.trace_id.to_hex()).unwrap_or_default()
    }
}
