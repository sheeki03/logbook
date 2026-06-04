//! `logbook run` and `logbook tail` — the OpenLogs capture/tail ports
//! (plan §3, §12), wired to `logbook-capture`.
//!
//! `run` mirrors the OpenLogs `cli.ts` `main()`: it starts the collector
//! alongside the capture (so injected-JS browser events have somewhere to land
//! and `/health` is up), runs the command inside a capturing PTY, and tears the
//! collector down afterwards — the same start/stop lifecycle as OpenLogs'
//! `startCollector` / `stopCollector`. The wrapped command's exit code (or
//! `128 + signum` on a wrapper signal) is preserved.
//!
//! `tail` is a thin pass-through to [`logbook_capture::tail`].

use std::path::PathBuf;

use clap::Args;

use logbook_capture::{tail, CaptureConfig};
use logbook_collector::{CollectorConfig, RunningCollector, TokenMode};
use logbook_store::Store;

/// `logbook run [opts] -- <command...>`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Output directory for logs, the SQLite store, and collector files.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Explicit run name (otherwise the slugified command is used).
    #[arg(long)]
    pub name: Option<String>,

    /// Do not write timestamped history files (only `latest` / named).
    #[arg(long)]
    pub no_history: bool,

    /// Print the resolved log paths to stderr at startup.
    #[arg(long)]
    pub print_paths: bool,

    /// Only write the `*.terminal.log` transcript tier (skip cleaned `*.txt`).
    #[arg(long, conflicts_with = "text_only")]
    pub terminal_only: bool,

    /// Only write the cleaned `*.txt` tier (skip the `*.terminal.log`
    /// transcript).
    #[arg(long)]
    pub text_only: bool,

    /// Disable secret redaction (DANGEROUS — secrets may be persisted).
    #[arg(long)]
    pub no_redact: bool,

    /// Do not start the collector alongside the capture (skip `/health` +
    /// `/ingest`). Useful for non-web commands.
    #[arg(long)]
    pub no_collector: bool,

    /// The command (and its arguments) to run. Everything after the flags — or
    /// after a literal `--` — is the wrapped command.
    #[arg(trailing_var_arg = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// `logbook tail [opts] [query] [-- <tail args...>]`.
#[derive(Debug, Args)]
pub struct TailCmdArgs {
    /// Output directory to look in.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Tail the `*.terminal.log` transcript instead of the cleaned `*.txt`.
    #[arg(long)]
    pub terminal: bool,

    /// Optional fuzzy query selecting a specific run (by name / command /
    /// timestamp). Omit to tail the latest log.
    pub query: Option<String>,

    /// Extra arguments forwarded verbatim to `tail` (e.g. `-n 20`, `-f`). Put
    /// them after a `--`.
    #[arg(last = true)]
    pub tail_args: Vec<String>,
}

/// Run the `run` subcommand. Builds a [`CaptureConfig`], starts the collector,
/// drives the PTY capture, and stops the collector. Returns the wrapped
/// command's exit code.
///
/// # Errors
/// Returns an error if the capture pipeline fails to start (e.g. the PTY cannot
/// be opened). A non-zero command exit is returned as `Ok(code)`, not an error,
/// matching OpenLogs.
pub fn run(args: RunArgs) -> anyhow::Result<i32> {
    let cfg = build_capture_config(&args);
    if cfg.command.is_empty() {
        anyhow::bail!("no command given");
    }
    if args.no_redact {
        eprintln!(
            "logbook: WARNING --no-redact is set; secrets in output may be persisted to {}.",
            cfg.out_dir.display()
        );
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        // Start the collector alongside the capture (OpenLogs `startCollector`).
        let collector = if args.no_collector {
            None
        } else {
            start_collector(&cfg).await
        };

        // Drive the capture to completion. We keep the exit code regardless of
        // how the collector teardown goes.
        let result = logbook_capture::run(cfg).await;

        // Stop the collector (OpenLogs `stopCollector`: SIGTERM-equivalent +
        // await). Removes collector.json / collector.token for this pid.
        if let Some(c) = collector {
            c.shutdown().await;
        }

        Ok(result?)
    })
}

/// Run the `tail` subcommand (thin pass-through to `logbook-capture`).
///
/// # Errors
/// Returns an error only if spawning the system `tail` fails. A missing log
/// prints a friendly message and returns `Ok(1)` (OpenLogs parity).
pub fn tail(args: TailCmdArgs) -> anyhow::Result<i32> {
    let opts = tail::TailOptions {
        out_dir: args.out_dir,
        query: args.query,
        terminal: args.terminal,
        tail_args: args.tail_args,
    };
    Ok(tail::run(&opts)?)
}

/// Translate parsed CLI flags into a [`CaptureConfig`].
fn build_capture_config(args: &RunArgs) -> CaptureConfig {
    let mut cfg = CaptureConfig::new(args.command.clone());
    cfg.out_dir = args.out_dir.clone();
    cfg.name = args.name.clone();
    cfg.history = !args.no_history;
    cfg.print_paths = args.print_paths;
    cfg.redact = !args.no_redact;
    // Tier selection: `--terminal-only` drops text; `--text-only` drops the
    // transcript. Both default on (mirrors OpenLogs `writeRaw`/`writeText`).
    if args.terminal_only {
        cfg.write_text = false;
    }
    if args.text_only {
        cfg.write_terminal = false;
    }
    cfg
}

/// Start the collector in the current tokio runtime, sharing the run's out-dir
/// and a fresh store handle. Best-effort: a bind/token failure logs a warning
/// and returns `None` so the capture still proceeds (OpenLogs degrades the same
/// way — the collector is an auxiliary, not a hard dependency of `run`).
async fn start_collector(cfg: &CaptureConfig) -> Option<RunningCollector> {
    let store = match Store::open_in_dir(&cfg.out_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "collector: store open failed; skipping collector");
            return None;
        }
    };

    // Dev origin defaults to the common Vite port; CORS stays scoped (never
    // `*`). The preferred port is 4318 to match OpenLogs' collector port; the
    // number is reused for familiarity, but this collector speaks logbook's own
    // `/health` + `/ingest` protocol, not OTLP. Auto-increment on a busy port
    // is handled inside the collector.
    let mut collector_cfg = CollectorConfig::new(cfg.out_dir.clone(), "http://localhost:5173")
        .with_port(4318);
    if !cfg.redact {
        collector_cfg = collector_cfg.without_redaction();
    }
    // Honor an explicit env token if present (LOGBOOK_INGEST_TOKEN), else generate.
    let token_mode = if std::env::var_os("LOGBOOK_INGEST_TOKEN").is_some() {
        TokenMode::Env
    } else {
        TokenMode::Generated
    };
    collector_cfg = collector_cfg.with_token_mode(token_mode);

    match logbook_collector::start(collector_cfg, store).await {
        Ok(c) => {
            tracing::info!(port = c.port(), "collector listening");
            Some(c)
        }
        Err(e) => {
            tracing::warn!(error = %e, "collector failed to start; continuing without it");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn default_out_dir() -> PathBuf {
        PathBuf::from(super::super::DEFAULT_OUT_DIR)
    }

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Run(RunArgs),
        Tail(TailCmdArgs),
    }

    #[test]
    fn run_parses_command_after_double_dash() {
        let cli = TestCli::try_parse_from([
            "x", "run", "--out-dir", "/tmp/o", "--no-history", "--", "echo", "hi",
        ])
        .unwrap();
        match cli.cmd {
            TestCmd::Run(a) => {
                assert_eq!(a.out_dir, PathBuf::from("/tmp/o"));
                assert!(a.no_history);
                assert_eq!(a.command, vec!["echo", "hi"]);
                let cfg = build_capture_config(&a);
                assert!(!cfg.history);
                assert!(cfg.write_text && cfg.write_terminal);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn run_terminal_only_drops_text_tier() {
        let cli = TestCli::try_parse_from(["x", "run", "--terminal-only", "--", "ls"]).unwrap();
        match cli.cmd {
            TestCmd::Run(a) => {
                let cfg = build_capture_config(&a);
                assert!(cfg.write_terminal);
                assert!(!cfg.write_text);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn run_text_only_drops_transcript_tier() {
        let cli = TestCli::try_parse_from(["x", "run", "--text-only", "--", "ls"]).unwrap();
        match cli.cmd {
            TestCmd::Run(a) => {
                let cfg = build_capture_config(&a);
                assert!(!cfg.write_terminal);
                assert!(cfg.write_text);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn run_command_can_lead_with_hyphen_flag() {
        // `allow_hyphen_values` lets the wrapped command carry its own flags
        // without a `--` separator confusing clap.
        let cli = TestCli::try_parse_from(["x", "run", "--", "ls", "-la"]).unwrap();
        match cli.cmd {
            TestCmd::Run(a) => assert_eq!(a.command, vec!["ls", "-la"]),
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn tail_parses_query_and_forwarded_args() {
        let cli =
            TestCli::try_parse_from(["x", "tail", "--terminal", "server", "--", "-n", "20"])
                .unwrap();
        match cli.cmd {
            TestCmd::Tail(a) => {
                assert!(a.terminal);
                assert_eq!(a.query.as_deref(), Some("server"));
                assert_eq!(a.tail_args, vec!["-n", "20"]);
            }
            _ => panic!("expected tail"),
        }
    }

    #[test]
    fn tail_defaults_out_dir() {
        let cli = TestCli::try_parse_from(["x", "tail"]).unwrap();
        match cli.cmd {
            TestCmd::Tail(a) => assert_eq!(a.out_dir, default_out_dir()),
            _ => panic!("expected tail"),
        }
    }
}
