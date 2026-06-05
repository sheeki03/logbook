//! Clap command surface for the inventory feature (plan §7b, §12).
//!
//! Exposes the `inventory` subcommand tree (`scan` / `watch` / `report`) and the
//! `agent <cli...>` wrapper as `clap` types plus a [`run`] dispatcher. The
//! top-level `logbook-cli` binary wires these into its own command enum; this
//! keeps all inventory argument handling inside the inventory crate.
//!
//! Permission rule (plan §7b / §9.1): `scan` and `report` are user-triggered and
//! always allowed (read-only). Continuous `watch` requires
//! `[permissions].enabled_writes` to include `"inventory_watch"`.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};

use logbook_core::{CapturePolicy, CliOverlay, Redactor, SensitivityClass};
use logbook_store::Store;

use crate::error::Result;
use crate::model::SessionTranscriptRecord;
use crate::report;
use crate::scan::{self, ScanContext};
use crate::store_ext;
use crate::wrapper::{self, LogbookOptions};

/// `logbook inventory <subcommand>`.
#[derive(Debug, Args)]
pub struct InventoryArgs {
    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`). Defaults to
    /// `.logbook`.
    #[arg(long, global = true, default_value = ".logbook")]
    pub out_dir: PathBuf,

    /// Override the project directory scanned for `.mcp.json` etc. (defaults to
    /// the current directory).
    #[arg(long, global = true)]
    pub project: Option<PathBuf>,

    /// The inventory subcommand.
    #[command(subcommand)]
    pub command: InventoryCommand,
}

/// The `inventory` subcommands.
#[derive(Debug, Subcommand)]
pub enum InventoryCommand {
    /// One-shot discovery scan (user-triggered, read-only): detect agent CLIs,
    /// MCP servers, processes, and reusable tools; surface risk/shadow findings;
    /// persist to the inventory tables.
    Scan(ScanArgs),
    /// Continuous incremental scan. Opt-in: requires `inventory_watch` in
    /// `[permissions].enabled_writes`.
    Watch(WatchArgs),
    /// Render the latest scan as a human report or JSON.
    Report(ReportArgs),
}

/// `inventory scan` flags.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Print the report after scanning.
    #[arg(long)]
    pub report: bool,
    /// When printing, emit JSON instead of human text.
    #[arg(long)]
    pub json: bool,
}

/// `inventory watch` flags.
#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Seconds between incremental scans.
    #[arg(long, default_value_t = 30)]
    pub interval_secs: u64,
    /// Run at most this many iterations then stop (0 = unbounded). Bounded runs
    /// keep the surface testable and scripts terminating.
    #[arg(long, default_value_t = 0)]
    pub iterations: u64,
}

/// `inventory report` flags.
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
    /// Re-scan before reporting (otherwise report from a fresh discovery, since
    /// v1 does not snapshot a prior scan into a single restorable report blob).
    #[arg(long, default_value_t = true)]
    pub rescan: bool,
}

/// `logbook agent <cli...>` — wrap an agent CLI, recording a session +
/// session-accurate redacted file diffs (plan §1.5).
#[derive(Debug, Args)]
pub struct AgentArgs {
    /// Out-dir holding the logbook store + transcript files.
    #[arg(long, default_value = ".logbook")]
    pub out_dir: PathBuf,

    /// Capture session-accurate file diffs (the Phase-1 default; redacted-only).
    #[arg(long, overrides_with = "no_capture_diffs")]
    pub capture_diffs: bool,
    /// Disable file-diff capture for this session (`diff = None`, behaviour
    /// identical to pre-Orbit).
    #[arg(long, overrides_with = "capture_diffs")]
    pub no_capture_diffs: bool,

    /// Per-file redacted-diff body cap, in bytes (overrides the `file_diffs`
    /// class default of 256 KiB).
    #[arg(long)]
    pub diff_max_bytes: Option<u64>,

    /// Opt in to encrypted preimages so a dirty-tree session is revertable.
    /// **Not yet available** — rejected with a clear error (key management
    /// pending). The clean-tree path is always revertable via git itself.
    #[arg(long)]
    pub reversible: bool,

    /// Disable the **general** (non-secret) redactor for this session. The
    /// secrets floor (cloud keys, JWT, bearer, PEM, …) is **never** disabled —
    /// `--no-redact` only drops the general / `deny`-pattern layer.
    #[arg(long)]
    pub no_redact: bool,

    /// Phase-2 flag (rejected in Phase 1): structured prompt capture has no
    /// mechanism yet, so this is refused rather than silently no-op'd.
    #[arg(long)]
    pub capture_prompts: bool,

    /// Fidelity tier. Only `universal` is meaningful in Phase 1; `structured` /
    /// `complete` are **rejected** (they land in Phase 2 / Phase 4).
    #[arg(long)]
    pub tier: Option<String>,

    /// The agent command line to run (e.g. `claude --resume`). Everything after
    /// the subcommand is captured verbatim.
    #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
}

impl AgentArgs {
    /// The resolved `--capture-diffs` / `--no-capture-diffs` choice as the
    /// `CliOverlay::capture_diffs` tri-state (`None` = neither flag set, leave the
    /// layered value untouched).
    fn capture_diffs_choice(&self) -> Option<bool> {
        match (self.capture_diffs, self.no_capture_diffs) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }

    /// Reject the Phase-2/4 flags that have no capture mechanism in Phase 1, so a
    /// user is never misled into thinking structured capture is happening.
    ///
    /// # Errors
    /// Returns [`InventoryError::UnsupportedFlag`] for `--capture-prompts` or a
    /// `--tier structured|complete`.
    fn reject_phase2_flags(&self) -> Result<()> {
        if self.capture_prompts {
            return Err(crate::error::InventoryError::UnsupportedFlag {
                flag: "--capture-prompts".to_string(),
            });
        }
        if let Some(tier) = self.tier.as_deref() {
            match tier.to_ascii_lowercase().as_str() {
                "universal" => {}
                "structured" | "complete" => {
                    return Err(crate::error::InventoryError::UnsupportedFlag {
                        flag: format!("--tier {tier}"),
                    });
                }
                other => {
                    return Err(crate::error::InventoryError::UnsupportedFlag {
                        flag: format!("--tier {other} (expected `universal`)"),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Dispatch an `inventory` invocation, writing output to `out`.
///
/// Builds a [`ScanContext`] from the process environment + args, then delegates
/// to [`run_with_context`].
///
/// # Errors
/// Returns a [`crate::InventoryError`] on permission denial, IO, or store
/// failure.
pub fn run(args: &InventoryArgs, out: &mut impl Write) -> Result<()> {
    let project = args
        .project
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let home = home_dir();
    let ctx = ScanContext::discover(&home, &project);
    run_with_context(args, ctx, out)
}

/// Dispatch using a caller-supplied [`ScanContext`]. This is the seam tests use
/// to inject discovery options (e.g. a PATH-scoped agent scan) without mutating
/// global process state.
///
/// # Errors
/// Returns a [`crate::InventoryError`] on permission denial, IO, or store
/// failure.
pub fn run_with_context(
    args: &InventoryArgs,
    ctx: ScanContext,
    out: &mut impl Write,
) -> Result<()> {
    match &args.command {
        InventoryCommand::Scan(scan_args) => {
            let store = Store::open_in_dir(&args.out_dir)?;
            let report = scan::scan_and_persist(&ctx, &store)?;
            if scan_args.report {
                emit_report(&report, scan_args.json, out)?;
            } else {
                let high = report
                    .findings
                    .iter()
                    .filter(|f| f.severity >= logbook_core::Severity::High)
                    .count();
                writeln!(
                    out,
                    "inventory scan complete: {} agents, {} MCP servers, {} findings ({} high).",
                    report.agents.len(),
                    report.mcp_servers.len(),
                    report.findings.len(),
                    high
                )?;
            }
            Ok(())
        }
        InventoryCommand::Watch(watch_args) => {
            // Gate: continuous watch is opt-in.
            ctx.config.require_watch_enabled()?;
            run_watch(&ctx, &args.out_dir, watch_args, out)
        }
        InventoryCommand::Report(report_args) => {
            // `report` is read-only; we re-scan to produce a fresh view.
            let store = Store::open_in_dir(&args.out_dir)?;
            let report = if report_args.rescan {
                scan::scan_and_persist(&ctx, &store)?
            } else {
                scan::scan(&ctx)
            };
            emit_report(&report, report_args.json, out)?;
            Ok(())
        }
    }
}

/// Run the `agent` wrapper: drive the agent CLI through the PTY capture pipeline
/// and record a session, session-accurate redacted file diffs, and a transcript
/// row — all under one `trace_id`/`session_id` (plan §1.1/§1.2/§1.3).
///
/// The capture policy is resolved via the shared, **fail-closed**
/// [`CapturePolicy::resolve`] (recorder-on defaults → strict `<root>/logbook.toml`
/// `[capture]` → `<out_dir>/capture-state.json` narrow-only → CLI flags), so the
/// cross-process UI pause toggle is honoured here too. Diff capture is gated on
/// `should_capture(FileDiffs)`.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if a rejected Phase-2 flag was passed, the
/// agent cannot be launched, capture fails, `--reversible` is requested on a
/// dirty tree, or the session cannot be persisted.
pub fn run_agent_wrapper(args: &AgentArgs, out: &mut impl Write) -> Result<()> {
    let project = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    run_agent_wrapper_in(args, project, out)
}

/// Like [`run_agent_wrapper`] but with an explicit project/cwd root (the seam
/// tests use to run + diff in a chosen directory without mutating process state,
/// mirroring [`run_with_context`]). The `project` dir is both the agent's working
/// directory and the root the capture policy + `[redaction]` config load from.
///
/// # Errors
/// Same as [`run_agent_wrapper`].
pub fn run_agent_wrapper_in(
    args: &AgentArgs,
    project: PathBuf,
    out: &mut impl Write,
) -> Result<()> {
    // Reject Phase-2/4 flags up front (no misleading no-ops).
    args.reject_phase2_flags()?;

    // The general-redaction switch from `[redaction].enabled` (the security-
    // bearing capture policy is loaded fail-closed below via `resolve`; this soft
    // load only supplies the redactor's deny/allow patterns + enabled bit).
    let inv_cfg = crate::config::InventoryConfig::load_from_dir(&project);
    let general_redaction_enabled = inv_cfg.redaction.enabled && !args.no_redact;

    // Resolve the capture policy through the shared fail-closed helper, layering
    // the CLI flags on top (`--capture-diffs`, `--diff-max-bytes`, `--no-redact`).
    let overlay = CliOverlay {
        capture_diffs: args.capture_diffs_choice(),
        diff_max_bytes: args.diff_max_bytes,
        no_redact: args.no_redact,
        master_enabled: None,
    };
    let policy = CapturePolicy::resolve(&project, &args.out_dir, overlay);

    // Build the redactor: the full general redactor when enabled (honouring the
    // user's `[redaction] deny`/`allow` patterns), else the secrets floor only.
    // The floor always runs — `--no-redact` can never expose a secret, and the
    // `file_diffs` class is force-redacted (`RedactionMode::Always`) regardless.
    let redactor = if general_redaction_enabled {
        logbook_core::redact::from_config(true, &inv_cfg.redaction.deny, &inv_cfg.redaction.allow)
            .unwrap_or_else(|_| {
                tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
                Redactor::new().with_process_env()
            })
    } else {
        Redactor::secrets_floor_with_process_env()
    };

    if args.no_redact {
        writeln!(
            out,
            "logbook: WARNING --no-redact is set; the secrets floor still applies, \
             but non-secret content in diffs/transcript may be persisted to {}.",
            args.out_dir.display()
        )?;
    }

    let endpoint = crate::endpoint::local_endpoint();
    let opts = LogbookOptions {
        cwd: project,
        out_dir: args.out_dir.clone(),
        endpoint_id: Some(endpoint.id.clone()),
        spawn: true,
        policy,
        redaction_enabled: general_redaction_enabled,
        reversible: args.reversible,
    };

    let store = Store::open_in_dir(&args.out_dir)?;
    store_ext::upsert_endpoint(&store, &endpoint)?;

    // Drive the async capture pipeline on a small current-thread runtime (like
    // `commands/run.rs`). Interactive stdin keeps working — the PTY forwards it.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(crate::error::InventoryError::Io)?;
    let outcome = rt.block_on(wrapper::run_agent(&args.command, &opts, &redactor))?;

    store_ext::insert_agent_session(&store, &outcome.session)?;
    store_ext::insert_agent_actions(&store, &outcome.session.session_id, &outcome.actions)?;

    // Write the `session_transcripts` row from the capture outcome (plan §1.3),
    // only when a transcript was actually captured (the Transcript class may have
    // been narrowed off by the policy / UI toggle, leaving both tiers absent).
    if let Some(t) = &outcome.transcript {
        if t.terminal_log_path.is_some() || t.text_path.is_some() {
            let rec = SessionTranscriptRecord {
                session_id: outcome.session.session_id.clone(),
                trace_id: outcome.session.trace_id.clone(),
                terminal_log_path: t
                    .terminal_log_path
                    .as_ref()
                    .map(|p| p.display().to_string()),
                text_path: t.text_path.as_ref().map(|p| p.display().to_string()),
                line_count: Some(t.line_count as i64),
                byte_size: Some(t.byte_size as i64),
                max_sensitivity: SensitivityClass::Transcript.as_str().to_string(),
            };
            store_ext::insert_session_transcript(&store, &rec)?;
        }
    }

    writeln!(
        out,
        "agent session recorded: {} ({} file action(s), exit {}).",
        outcome.session.agent,
        outcome.actions.len(),
        outcome
            .session
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".into())
    )?;
    Ok(())
}

/// Run the bounded/unbounded watch loop. Each iteration is a full re-scan +
/// persist; incremental in the sense that upserts only change what moved.
fn run_watch(
    ctx: &ScanContext,
    out_dir: &std::path::Path,
    args: &WatchArgs,
    out: &mut impl Write,
) -> Result<()> {
    // Fatal setup error: if the store can't even be opened, there's nothing to
    // watch. Per-iteration scan/persist errors below are *not* fatal.
    let store = Store::open_in_dir(out_dir)?;
    let mut iter = 0u64;
    loop {
        // A transient scan/persist failure (a momentary SQLITE_BUSY, a brief I/O
        // hiccup, a config file unreadable mid-rescan) must not kill a
        // long-running monitor: log it and continue to the next interval.
        match scan::scan_and_persist(ctx, &store) {
            Ok(report) => {
                writeln!(
                    out,
                    "[watch] scan: {} agents, {} MCP servers, {} findings",
                    report.agents.len(),
                    report.mcp_servers.len(),
                    report.findings.len()
                )?;
            }
            Err(err) => {
                tracing::warn!(error = %err, "inventory watch scan failed; continuing");
                writeln!(out, "[watch] scan error (continuing): {err}")?;
            }
        }
        iter += 1;
        if args.iterations != 0 && iter >= args.iterations {
            break;
        }
        // A real daemon would sleep here; we keep the sleep out of the hot path
        // so tests can run a bounded loop instantly. When iterations == 0
        // (unbounded) we do sleep to avoid a busy loop.
        if args.iterations == 0 {
            std::thread::sleep(std::time::Duration::from_secs(args.interval_secs.max(1)));
        }
    }
    Ok(())
}

fn emit_report(report: &scan::ScanReport, json: bool, out: &mut impl Write) -> Result<()> {
    if json {
        writeln!(out, "{}", report::to_json(report)?)?;
    } else {
        write!(out, "{}", report::to_human(report))?;
    }
    Ok(())
}

/// Best-effort home directory (`$HOME`, then `$USERPROFILE`, then `.`).
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rusqlite::params;

    // A tiny test harness CLI that embeds InventoryArgs, to exercise parsing.
    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        inv: TopCmd,
    }

    #[derive(Debug, Subcommand)]
    enum TopCmd {
        Inventory(InventoryArgs),
        Agent(AgentArgs),
    }

    fn write_fake_bin(dir: &std::path::Path, name: &str) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh\ntrue").unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn parses_inventory_scan() {
        let cli =
            TestCli::try_parse_from(["x", "inventory", "scan", "--report", "--json"]).unwrap();
        match cli.inv {
            TopCmd::Inventory(a) => match a.command {
                InventoryCommand::Scan(s) => {
                    assert!(s.report && s.json);
                }
                _ => panic!("expected scan"),
            },
            _ => panic!("expected inventory"),
        }
    }

    /// A bare `AgentArgs` for an out-dir + command (all new flags default off).
    fn agent_args(out_dir: PathBuf, command: Vec<String>) -> AgentArgs {
        AgentArgs {
            out_dir,
            capture_diffs: false,
            no_capture_diffs: false,
            diff_max_bytes: None,
            reversible: false,
            no_redact: false,
            capture_prompts: false,
            tier: None,
            command,
        }
    }

    fn init_repo(cwd: &std::path::Path) {
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
        let _ = std::process::Command::new("git")
            .args(["config", "user.email", "t@t"])
            .current_dir(cwd)
            .status();
        let _ = std::process::Command::new("git")
            .args(["config", "user.name", "t"])
            .current_dir(cwd)
            .status();
    }

    #[test]
    fn parses_agent_trailing_args() {
        let cli = TestCli::try_parse_from(["x", "agent", "claude", "--resume", "--model", "opus"])
            .unwrap();
        match cli.inv {
            TopCmd::Agent(a) => {
                assert_eq!(a.command, vec!["claude", "--resume", "--model", "opus"]);
            }
            _ => panic!("expected agent"),
        }
    }

    #[test]
    fn parses_agent_capture_flags() {
        // `--no-capture-diffs` after the subcommand, before the trailing command.
        let cli = TestCli::try_parse_from([
            "x",
            "agent",
            "--no-capture-diffs",
            "--diff-max-bytes",
            "1024",
            "--no-redact",
            "--",
            "claude",
        ])
        .unwrap();
        match cli.inv {
            TopCmd::Agent(a) => {
                assert!(a.no_capture_diffs && !a.capture_diffs);
                assert_eq!(a.capture_diffs_choice(), Some(false));
                assert_eq!(a.diff_max_bytes, Some(1024));
                assert!(a.no_redact);
                assert_eq!(a.command, vec!["claude"]);
            }
            _ => panic!("expected agent"),
        }
    }

    #[test]
    fn rejects_phase2_flags() {
        let outdir = tempfile::tempdir().unwrap();
        // --capture-prompts is rejected.
        let mut a = agent_args(outdir.path().to_path_buf(), vec!["/bin/sh".into()]);
        a.capture_prompts = true;
        assert!(matches!(
            a.reject_phase2_flags(),
            Err(crate::error::InventoryError::UnsupportedFlag { .. })
        ));
        // --tier structured / complete are rejected; universal is accepted.
        let mut a2 = agent_args(outdir.path().to_path_buf(), vec!["/bin/sh".into()]);
        a2.tier = Some("structured".into());
        assert!(a2.reject_phase2_flags().is_err());
        a2.tier = Some("complete".into());
        assert!(a2.reject_phase2_flags().is_err());
        a2.tier = Some("universal".into());
        assert!(a2.reject_phase2_flags().is_ok());
    }

    #[test]
    fn scan_command_runs_and_persists() {
        let bindir = tempfile::tempdir().unwrap();
        write_fake_bin(bindir.path(), "aider");
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".mcp.json"),
            r#"{ "mcpServers": { "evil": { "command": "x",
                 "env": { "TOKEN": "ghp_0123456789abcdefghijklmnopqrstuvwxyz" } } } }"#,
        )
        .unwrap();

        let args = InventoryArgs {
            out_dir: outdir.path().to_path_buf(),
            project: Some(project.path().to_path_buf()),
            command: InventoryCommand::Scan(ScanArgs {
                report: true,
                json: true,
            }),
        };
        // Inject a PATH-scoped agent scan via the context seam — no global env
        // mutation, so this is safe to run in parallel with sibling tests.
        let mut ctx = ScanContext::discover(home_dir(), project.path());
        ctx.agents = crate::agents::AgentScanOptions::with_path(bindir.path().to_string_lossy());
        let mut buf = Vec::new();
        run_with_context(&args, ctx, &mut buf).unwrap();

        let text = String::from_utf8(buf).unwrap();
        // JSON report emitted; planted items present; secret redacted.
        assert!(text.contains("\"evil\""), "mcp not in report: {text}");
        assert!(text.contains("\"aider\""), "agent not in report: {text}");
        assert!(!text.contains("ghp_0123456789"), "leaked secret: {text}");
        assert!(text.contains("\"has_secret\": true"));
    }

    #[test]
    fn watch_blocked_without_permission() {
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap(); // no logbook.toml → read-only default
        let args = InventoryArgs {
            out_dir: outdir.path().to_path_buf(),
            project: Some(project.path().to_path_buf()),
            command: InventoryCommand::Watch(WatchArgs {
                interval_secs: 1,
                iterations: 1,
            }),
        };
        let mut buf = Vec::new();
        let err = run(&args, &mut buf).unwrap_err();
        assert!(matches!(err, crate::error::InventoryError::WatchNotEnabled));
    }

    #[test]
    fn watch_runs_bounded_when_enabled() {
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        // Enable inventory_watch.
        std::fs::write(
            project.path().join("logbook.toml"),
            "[permissions]\nenabled_writes = [\"inventory_watch\"]\n",
        )
        .unwrap();
        let args = InventoryArgs {
            out_dir: outdir.path().to_path_buf(),
            project: Some(project.path().to_path_buf()),
            command: InventoryCommand::Watch(WatchArgs {
                interval_secs: 1,
                iterations: 2,
            }),
        };
        let mut buf = Vec::new();
        run(&args, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(
            text.matches("[watch] scan").count(),
            2,
            "bounded to 2 iters"
        );
    }

    #[test]
    fn agent_wrapper_records_session() {
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let args = agent_args(
            outdir.path().to_path_buf(),
            vec!["/bin/sh".into(), "-c".into(), "true".into()],
        );
        let mut buf = Vec::new();
        run_agent_wrapper_in(&args, project.path().to_path_buf(), &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("agent session recorded"));
        // Confirm a row landed.
        let store = Store::open_in_dir(outdir.path()).unwrap();
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::AgentSessions).unwrap(),
            1
        );
    }

    #[test]
    fn one_trace_shared_across_transcript_events_session_and_actions() {
        // §1.6: `logbook agent -- /bin/sh -c "echo hi > f.txt"` ⇒ one trace_id
        // shared by the transcript file pointers, the structured line-events, the
        // agent_sessions row, the agent_actions, and the session_transcripts row.
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        init_repo(project.path());

        // Emit a line to the PTY stdout (→ a structured line-event) AND create a
        // file (→ a diffed action), so the single shared trace is exercised across
        // the transcript, the line-events, the session, the actions, and the
        // transcript row all at once.
        let args = agent_args(
            outdir.path().to_path_buf(),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo session-line; echo hi > f.txt".into(),
            ],
        );
        let mut buf = Vec::new();
        run_agent_wrapper_in(&args, project.path().to_path_buf(), &mut buf).unwrap();

        let store = Store::open_in_dir(outdir.path()).unwrap();
        // The session row + its trace.
        let (sess_id, sess_trace): (String, String) = store
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT id, trace_id FROM agent_sessions",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(sess_trace.len(), 32);
        // The session_transcripts row shares the session id + trace.
        let (tr_sess, tr_trace, has_terminal): (String, String, bool) = store
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT session_id, trace_id, terminal_log_path IS NOT NULL
                     FROM session_transcripts",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? == 1)),
                )?)
            })
            .unwrap();
        assert_eq!(tr_sess, sess_id, "transcript joins the session");
        assert_eq!(tr_trace, sess_trace, "transcript shares the trace");
        assert!(has_terminal, "transcript pointer recorded");
        // The agent_actions for this session carry the file diff under the session.
        let sess_id_for_q = sess_id.clone();
        let action_count: i64 = store
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM agent_actions WHERE session_id = ?1",
                    params![sess_id_for_q],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(action_count >= 1, "expected ≥1 diffed action");
        // The structured line-events captured by the PTY share the same trace.
        let event_trace_matches = !store.trace(&sess_trace).unwrap().is_empty();
        assert!(event_trace_matches, "line-events recorded under the shared trace");
    }

    #[test]
    fn cross_process_toggle_master_off_captures_nothing() {
        // §1.6 cross-process toggle: writing <out_dir>/capture-state.json with the
        // master switch off makes a subsequent `logbook agent` capture nothing —
        // no transcript row, no diffed actions (the secrets floor still applies to
        // anything that *would* be written).
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        init_repo(project.path());
        // The UI toggle's narrow-only overlay: master off.
        let state = logbook_core::CaptureState {
            enabled: Some(false),
            ..Default::default()
        };
        state.save(outdir.path()).unwrap();

        let args = agent_args(
            outdir.path().to_path_buf(),
            vec!["/bin/sh".into(), "-c".into(), "echo hi > paused.txt".into()],
        );
        let mut buf = Vec::new();
        run_agent_wrapper_in(&args, project.path().to_path_buf(), &mut buf).unwrap();

        let store = Store::open_in_dir(outdir.path()).unwrap();
        // Session row still recorded (the session happened), but no diffs captured.
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::AgentSessions).unwrap(),
            1
        );
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::AgentActions).unwrap(),
            0,
            "master-off ⇒ no diffed actions"
        );
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::SessionTranscripts).unwrap(),
            0,
            "master-off ⇒ transcript tier not written ⇒ no transcript row"
        );
    }

    #[test]
    fn no_capture_diffs_flag_yields_no_actions() {
        // §1.6: --no-capture-diffs ⇒ diff=None / no actions, behaviour identical
        // to pre-Orbit.
        let outdir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        init_repo(project.path());
        let mut args = agent_args(
            outdir.path().to_path_buf(),
            vec!["/bin/sh".into(), "-c".into(), "echo hi > x.txt".into()],
        );
        args.no_capture_diffs = true;
        let mut buf = Vec::new();
        run_agent_wrapper_in(&args, project.path().to_path_buf(), &mut buf).unwrap();
        let store = Store::open_in_dir(outdir.path()).unwrap();
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::AgentActions).unwrap(),
            0,
            "--no-capture-diffs ⇒ no actions"
        );
    }
}
