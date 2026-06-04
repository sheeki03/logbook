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

use logbook_store::Store;

use crate::config::InventoryConfig;
use crate::error::Result;
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

/// `logbook agent <cli...>` — wrap an agent CLI, recording a session + diffs.
#[derive(Debug, Args)]
pub struct AgentArgs {
    /// Out-dir holding the logbook store.
    #[arg(long, default_value = ".logbook")]
    pub out_dir: PathBuf,
    /// The agent command line to run (e.g. `claude --resume`). Everything after
    /// the subcommand is captured verbatim.
    #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
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

/// Run the `agent` wrapper: spawn the agent CLI, record a session + diffs.
///
/// # Errors
/// Returns a [`crate::InventoryError`] if the agent cannot be launched or the
/// session cannot be persisted.
pub fn run_agent_wrapper(args: &AgentArgs, out: &mut impl Write) -> Result<()> {
    let project = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = InventoryConfig::load_from_dir(&project);
    let redactor = scan::ScanContext::discover(home_dir(), &project).redactor();
    let _ = config;

    let endpoint = crate::endpoint::local_endpoint();
    let opts = LogbookOptions {
        cwd: project,
        endpoint_id: Some(endpoint.id.clone()),
        spawn: true,
    };

    let store = Store::open_in_dir(&args.out_dir)?;
    store_ext::upsert_endpoint(&store, &endpoint)?;

    let outcome = wrapper::run_agent(&args.command, &opts, &redactor)?;
    store_ext::insert_agent_session(&store, &outcome.session)?;
    store_ext::insert_agent_actions(&store, &outcome.session.session_id, &outcome.actions)?;

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
        let args = AgentArgs {
            out_dir: outdir.path().to_path_buf(),
            command: vec!["/bin/sh".into(), "-c".into(), "true".into()],
        };
        let mut buf = Vec::new();
        run_agent_wrapper(&args, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("agent session recorded"));
        // Confirm a row landed.
        let store = Store::open_in_dir(outdir.path()).unwrap();
        assert_eq!(
            store_ext::count_rows(&store, store_ext::InventoryTable::AgentSessions).unwrap(),
            1
        );
    }
}
