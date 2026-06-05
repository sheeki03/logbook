//! `logbook detect [<session-id>] [--severity <min>]` — run the Phase-3 risk
//! rules over a recorded session (or recent events), print the findings, and
//! **persist** each as a `Kind::Finding` / `Category::Security` event (plan
//! §Phase 3 "Anomaly/risk detection" + "Orbit additions"), wired to
//! `logbook-detect` + `logbook-store`.
//!
//! Detection runs **after** redaction — the store is a redacted sink, so the
//! rules look for the *evidence* of risk (e.g. the redaction marker a scrubbed
//! secret leaves in a diff), never raw secret values. The built-in rule set
//! (`secret_in_diff`, `dangerous_shell`, `risky_git`, `egress_unallowlisted`,
//! `token_cost_spike`, `tool_call_rate`) is configured from `logbook.toml`'s
//! `[permissions].allowed_domains` (the egress allowlist) with the documented
//! `DetectConfig` defaults for the cost/token/rate knobs.
//!
//! ## Scope
//! - `logbook detect <session-id>` evaluates only that session's events.
//! - `logbook detect` (no id) evaluates the most recent events (newest-first,
//!   capped by `--limit`) — a quick "what looks risky lately?" pass.
//!
//! `--severity <min>` filters which findings are printed and persisted (e.g.
//! `--severity high` shows only High/Critical). The numeric findings count is
//! returned as success/`0`; a non-zero *exit on findings* is the `guard`
//! command's job (this command is a reporter).

use std::path::PathBuf;

use clap::Args;

use logbook_core::{Category, Event, Kind, LogbookConfig, SessionId, Severity, TraceId};
use logbook_detect::{builtin_rules, detect, DetectConfig};
use logbook_inventory::store_ext::{self, AgentActionDiff};
use logbook_store::{Query, Store};

/// How many recent events to scan when no session id is given.
const DEFAULT_RECENT_LIMIT: u32 = 5_000;

/// `logbook detect [<session-id>] [opts]`.
#[derive(Debug, Args)]
pub struct DetectArgs {
    /// Restrict detection to this recorded session. Omit to scan recent events
    /// across all sessions.
    pub session_id: Option<String>,

    /// Out-dir holding the logbook store the events were recorded in.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root holding `logbook.toml` (read for
    /// `[permissions].allowed_domains`, the egress allowlist the
    /// `egress_unallowlisted` rule checks against). Defaults to the current dir.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Only report/persist findings at or above this severity (`info`, `low`,
    /// `medium`, `high`, `critical`). Default: all findings.
    #[arg(long)]
    pub severity: Option<Severity>,

    /// When scanning recent events (no session id), cap how many newest events
    /// are considered.
    #[arg(long, default_value_t = DEFAULT_RECENT_LIMIT)]
    pub limit: u32,

    /// Print the findings but do **not** persist them as events.
    #[arg(long)]
    pub no_persist: bool,
}

/// Dispatch a `detect` invocation.
///
/// # Errors
/// Returns an error if the store cannot be opened, the event query fails, or
/// (when persisting) the findings cannot be inserted.
pub fn run(args: DetectArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;

    // Gather the events to evaluate: a single session (oldest-first so rate/
    // window rules see chronological order), or recent events across sessions.
    let events = gather_events(&store, &args)?;

    // Build the rule set, sourcing the egress allowlist from logbook.toml; the
    // cost/token/rate thresholds use the documented DetectConfig defaults.
    let cfg = detect_config(&args.root);
    let rules = builtin_rules(&cfg);
    let mut findings = detect(&events, &rules);

    // Severity floor (printed + persisted): keep only findings >= the minimum.
    if let Some(min) = args.severity {
        findings.retain(|f| finding_severity(f).is_some_and(|s| s >= min));
    }

    print_findings(&findings, args.session_id.as_deref());

    if !args.no_persist && !findings.is_empty() {
        store.insert_batch(findings.clone())?;
    }

    // This command reports; it always succeeds (the failing-exit-on-finding
    // behaviour belongs to `logbook guard`).
    Ok(0)
}

/// Collect the events to feed the rules. With a session id, scope to that
/// session (oldest-first); without one, take the newest `--limit` events.
///
/// `logbook agent` records its per-file diffs in the `agent_actions` table, not
/// the `events` table, so a query of `events` alone never shows the rules a
/// session's diffs — and `secret_in_diff` (which fires on a redaction marker in a
/// diff) would silently miss every wrapped session. We therefore fold the
/// session's `agent_actions` diffs in as synthetic `Kind::Agent` diff events (see
/// [`synthetic_diff_events`]).
fn gather_events(store: &Store, args: &DetectArgs) -> anyhow::Result<Vec<Event>> {
    match &args.session_id {
        // Session scope: reuse the shared gather so `logbook detect <id>` and
        // `logbook guard` fold diffs identically.
        Some(id) => gather_session_events(store, id),
        // No-session "recent" pass: newest `--limit` events, plus recent diffs
        // across all sessions (capped the same) so a bare `logbook detect` isn't
        // blind to diff secrets either.
        None => {
            let mut events = store.query(&Query::new().limit(args.limit))?;
            let actions = store_ext::recent_agent_action_diffs(store, args.limit)?;
            events.extend(synthetic_diff_events(&actions, None));
            Ok(events)
        }
    }
}

/// Gather the events the rules evaluate for **one recorded session**: its stored
/// `events` (oldest-first) plus its `agent_actions` diffs folded in as synthetic
/// `Kind::Agent` diff events (see [`synthetic_diff_events`]). Shared by `logbook
/// detect <session>` and `logbook guard` so both see a session's per-file diffs —
/// without this, `secret_in_diff` never fires on a wrapped session.
///
/// # Errors
/// Returns an error if the event query or the `agent_actions` read fails.
pub(crate) fn gather_session_events(store: &Store, session_id: &str) -> anyhow::Result<Vec<Event>> {
    let mut events = store.query(&Query::new().session(session_id.to_string()).oldest_first())?;
    let actions = store_ext::agent_actions_for_session(store, session_id)?;
    events.extend(synthetic_diff_events(&actions, Some(session_id)));
    Ok(events)
}

/// Turn recorded `agent_actions` rows (path, redacted diff, owning trace) into
/// synthetic `Kind::Agent` diff events the rules can scan.
///
/// Only actions that carry a **non-empty** `diff` produce an event (a NULL/empty
/// diff has nothing for `secret_in_diff` to find). The diff text is carried in
/// the `diff` attribute — exactly the carrier the rule's `secret_in_diff`
/// fixtures use — so `view::haystack` concatenates it and `first_redaction_class`
/// can spot a `«REDACTED:…»` marker; `Kind::Agent` already satisfies the rule's
/// `looks_like_diff` gate (and the `diff` attribute independently would too). The
/// file `path` is set as the event name and as the `path` attribute (the latter
/// feeds the finding's file locator).
///
/// Each event is correlated on the action's session trace (parsed from the hex
/// `trace_id` joined off `agent_sessions`); a missing/malformed trace falls back
/// to a fresh id so the event is still well-formed. When a `session_id` scope is
/// known it is stamped on every event so the finding lands on that session.
fn synthetic_diff_events(actions: &[AgentActionDiff], session_id: Option<&str>) -> Vec<Event> {
    let mut out = Vec::new();
    for (path, diff, trace_hex) in actions {
        let Some(diff) = diff.as_deref().filter(|d| !d.is_empty()) else {
            continue;
        };
        let trace = trace_hex
            .as_deref()
            .and_then(|h| h.parse::<TraceId>().ok())
            .unwrap_or_else(TraceId::new);

        let name = path.as_deref().unwrap_or("agent.action");
        let mut ev = Event::new(trace, Kind::Agent, Category::Agent, "agent.action")
            .with_name(name)
            .with_attr("diff", diff.to_string());
        if let Some(p) = path.as_deref() {
            ev = ev.with_attr("path", p.to_string());
        }
        if let Some(sid) = session_id {
            ev = ev.with_session(SessionId::new(sid));
        }
        out.push(ev);
    }
    out
}

/// Build the [`DetectConfig`] for this run: the egress allowlist comes from
/// `<root>/logbook.toml`'s `[permissions].allowed_domains` (a missing or
/// malformed file degrades to the empty allowlist — which flags *all* remote
/// egress, the conservative posture); the remaining thresholds use the
/// documented defaults.
fn detect_config(root: &std::path::Path) -> DetectConfig {
    let allowed_domains = LogbookConfig::load_from_root(root)
        .map(|c| c.permissions.allowed_domains)
        .unwrap_or_default();
    DetectConfig {
        allowed_domains,
        ..DetectConfig::default()
    }
}

/// Read a finding event's severity (from its `FindingBlock`).
fn finding_severity(ev: &Event) -> Option<Severity> {
    ev.blocks.finding.as_ref().and_then(|f| f.severity)
}

/// Print a one-line summary per finding plus a total. Findings carry their rule,
/// severity, optional file locator, and message in the `FindingBlock`.
fn print_findings(findings: &[Event], session_id: Option<&str>) {
    let scope = match session_id {
        Some(id) => format!("session {id}"),
        None => "recent events".to_string(),
    };

    if findings.is_empty() {
        println!("detect: no findings in {scope}.");
        return;
    }

    for f in findings {
        let block = f.blocks.finding.as_ref();
        let rule = block
            .and_then(|b| b.rule_id.as_deref())
            .unwrap_or(&f.operation);
        let sev = finding_severity(f).map(|s| s.as_str()).unwrap_or("?");
        let msg = block
            .and_then(|b| b.message.as_deref())
            .unwrap_or(&f.name);
        match block.and_then(|b| b.file.as_deref()) {
            Some(file) => println!("  [{sev}] {rule}: {msg} ({file})"),
            None => println!("  [{sev}] {rule}: {msg}"),
        }
    }
    println!("detect: {} finding(s) in {scope}.", findings.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use logbook_core::{Category, Kind, SessionId, TraceId};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Detect(DetectArgs),
    }

    fn parse(argv: &[&str]) -> DetectArgs {
        match TestCli::try_parse_from(argv).expect("parse").cmd {
            TestCmd::Detect(a) => a,
        }
    }

    #[test]
    fn parses_with_no_session_id() {
        let a = parse(&["x", "detect"]);
        assert!(a.session_id.is_none());
        assert_eq!(a.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(a.root, PathBuf::from("."));
        assert!(a.severity.is_none());
        assert_eq!(a.limit, DEFAULT_RECENT_LIMIT);
        assert!(!a.no_persist);
    }

    #[test]
    fn parses_session_id_and_severity() {
        let a = parse(&["x", "detect", "sess-1", "--severity", "high", "--out-dir", "/tmp/o"]);
        assert_eq!(a.session_id.as_deref(), Some("sess-1"));
        assert_eq!(a.severity, Some(Severity::High));
        assert_eq!(a.out_dir, PathBuf::from("/tmp/o"));
    }

    #[test]
    fn severity_value_is_validated() {
        // An unknown severity is rejected at parse time (clap uses Severity's FromStr).
        assert!(TestCli::try_parse_from(["x", "detect", "--severity", "bogus"]).is_err());
    }

    #[test]
    fn detect_persists_findings_for_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();

        // A dangerous-shell command on a known session → exactly one finding.
        let trace = TraceId::new();
        let danger = Event::new(trace, Kind::Log, Category::AppLog, "stdout")
            .with_name("rm -rf /")
            .with_session(SessionId::new("sess-danger"));
        store.insert(&danger).unwrap();

        let code = run(DetectArgs {
            session_id: Some("sess-danger".into()),
            out_dir: dir.path().to_path_buf(),
            root: dir.path().to_path_buf(),
            severity: None,
            limit: DEFAULT_RECENT_LIMIT,
            no_persist: false,
        })
        .unwrap();
        assert_eq!(code, 0);

        // The finding was persisted as a Kind::Finding event on the same session.
        let findings = store
            .query(&Query::new().session("sess-danger".to_string()))
            .unwrap();
        let found: Vec<_> = findings.iter().filter(|e| e.kind == Kind::Finding).collect();
        assert_eq!(found.len(), 1, "expected one persisted finding");
        assert_eq!(found[0].category, Category::Security);
    }

    #[test]
    fn no_persist_reports_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        store
            .insert(
                &Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout")
                    .with_name("rm -rf /")
                    .with_session(SessionId::new("s2")),
            )
            .unwrap();

        run(DetectArgs {
            session_id: Some("s2".into()),
            out_dir: dir.path().to_path_buf(),
            root: dir.path().to_path_buf(),
            severity: None,
            limit: DEFAULT_RECENT_LIMIT,
            no_persist: true,
        })
        .unwrap();

        // Nothing persisted: no Finding events exist.
        let findings = store.query(&Query::new().session("s2".to_string())).unwrap();
        assert!(findings.iter().all(|e| e.kind != Kind::Finding));
    }

    #[test]
    fn severity_floor_filters_lower_findings() {
        // A risky-git `rebase` is Medium; with --severity high it is filtered out
        // and nothing is persisted.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        store
            .insert(
                &Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout")
                    .with_name("git rebase -i HEAD~3")
                    .with_session(SessionId::new("s3")),
            )
            .unwrap();

        run(DetectArgs {
            session_id: Some("s3".into()),
            out_dir: dir.path().to_path_buf(),
            root: dir.path().to_path_buf(),
            severity: Some(Severity::High),
            limit: DEFAULT_RECENT_LIMIT,
            no_persist: false,
        })
        .unwrap();

        let findings = store.query(&Query::new().session("s3".to_string())).unwrap();
        assert!(
            findings.iter().all(|e| e.kind != Kind::Finding),
            "a Medium finding must be filtered out by --severity high"
        );
    }

    /// Regression (dogfood): `logbook agent` stores its file diffs in
    /// `agent_actions`, not `events`. A redaction marker inside such a diff must
    /// be caught by `secret_in_diff` even though NO `events` row carries it — the
    /// gather folds the session's `agent_actions` diffs in as synthetic diff
    /// events. Before the fix, `gather_events` only saw `events` and produced
    /// "no findings".
    #[test]
    fn secret_in_diff_fires_on_agent_actions_diff_with_no_events_row() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();

        // Seed a session header + one action whose redacted diff still shows a
        // `«REDACTED:CLOUD_KEY:20»` marker inside a `diff --git`/`@@` body — the
        // exact shape the wrapper persists for a scrubbed AWS key in creds.txt.
        // Deliberately insert NO `events` row carrying the diff.
        let trace = TraceId::new();
        let trace_hex = trace.to_hex();
        store
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                     VALUES ('sess-diff', NULL, 'claude', 'claude -- edit creds', ?1, 100, 200, 0)",
                    [&trace_hex],
                )?;
                conn.execute(
                    "INSERT INTO agent_actions \
                       (id, session_id, kind, path, detail, observed_at, \
                        diff, diff_bytes, post_hash, revert_safe, max_sensitivity) \
                     VALUES ('act-diff', 'sess-diff', 'file_modified', 'creds.txt', NULL, 160, \
                             ?1, NULL, NULL, 0, 'file_diffs')",
                    [
                        "diff --git a/creds.txt b/creds.txt\n@@ -1 +1 @@\n\
                         +aws_key = \u{ab}REDACTED:CLOUD_KEY:20\u{bb}\n",
                    ],
                )?;
                Ok(())
            })
            .unwrap();

        // Sanity: the `events` table is genuinely empty for this session, so a
        // pre-fix gather (events only) would have nothing to flag.
        assert!(
            store
                .query(&Query::new().session("sess-diff".to_string()))
                .unwrap()
                .is_empty(),
            "precondition: no events row carries the diff"
        );

        // Gather (folds the agent_actions diff in) + run the full rule set.
        let events = gather_session_events(&store, "sess-diff").unwrap();
        let rules = builtin_rules(&DetectConfig::default());
        let findings = detect(&events, &rules);

        let secret_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.blocks
                    .finding
                    .as_ref()
                    .and_then(|b| b.rule_id.as_deref())
                    == Some("secret_in_diff")
            })
            .collect();
        assert_eq!(
            secret_findings.len(),
            1,
            "exactly one secret_in_diff finding expected; got {findings:#?}"
        );
        // It is a High finding correlated onto the session, with the class +
        // file locator surfaced.
        let f = secret_findings[0];
        assert_eq!(finding_severity(f), Some(Severity::High));
        assert_eq!(f.session_id.as_ref().map(SessionId::as_str), Some("sess-diff"));
        assert_eq!(
            f.attributes.get("secret_class").and_then(|v| v.as_str()),
            Some("CLOUD_KEY")
        );
    }
}
