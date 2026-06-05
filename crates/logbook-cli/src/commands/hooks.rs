//! `logbook hooks` — run the collector's **harness hook receiver** and print how
//! to point a harness at it (plan "Phase 2", Ingest/OTLP row + "Consolidated
//! changes" CLI row: `logbook hooks`).
//!
//! This starts the same loopback [`logbook_collector`] axum server `logbook run`
//! uses, but as a **standalone, long-lived** endpoint dedicated to receiving a
//! coding harness's own records:
//! - **`POST /v1/hooks`** — Claude Code `PreToolUse`/`PostToolUse`/
//!   `UserPromptSubmit`/`Stop` hook JSON (or a session-log line), normalized via
//!   the [`logbook_harness`] adapters into **redacted** events and persisted;
//! - **`POST /v1/traces`** — a minimal OTLP-JSON spans envelope.
//!
//! Both routes are bearer-gated (the same per-run ingest token as `/ingest`) and
//! honour the resolved [`CapturePolicy`] (so a paused capture toggle drops
//! prompt/tool payloads). On startup the command prints the endpoint URL, the
//! bearer token, and a copy-pasteable Claude Code hooks snippet so a user can
//! wire their harness to it, then blocks until Ctrl-C / SIGTERM.
//!
//! ## Redaction is sacred (plan §9)
//! Every prompt / tool arg / tool result is redacted **before** persistence
//! inside the collector's per-request [`HarnessContext`]; this command only
//! resolves the posture (fail-closed [`CapturePolicy::resolve`]) and hands it to
//! the collector. Ingesting a harness's own logs is **opt-in** — running this
//! receiver is the explicit opt-in (it is not started by `logbook run`/`agent`).

use std::path::PathBuf;

use clap::Args;

use logbook_collector::{CollectorConfig, RunningCollector, TokenMode};
use logbook_core::{CapturePolicy, CliOverlay};
use logbook_store::Store;

/// `logbook hooks [opts]`.
#[derive(Debug, Args)]
pub struct HooksArgs {
    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`) that ingested
    /// hook/OTLP events are written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the `[capture]` policy).
    /// Defaults to the current directory, matching how `logbook run`/`agent`
    /// resolve their config root.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Preferred port; auto-increments on conflict (matches `logbook run`'s
    /// collector default of 4318).
    #[arg(long, default_value_t = 4318)]
    pub port: u16,

    /// Origin allowed by CORS (scoped, never `*`). Only relevant if a browser
    /// page posts hooks; harness CLIs are unaffected.
    #[arg(long, default_value = "http://localhost:5173")]
    pub dev_origin: String,

    /// Disable the **general** (non-secret) redactor for ingested payloads. The
    /// secrets floor is **never** disabled — `--no-redact` only drops the
    /// general / `deny`-pattern layer; prompts/tool args/results are
    /// force-redacted regardless.
    #[arg(long)]
    pub no_redact: bool,
}

/// Run the hook receiver until Ctrl-C / SIGTERM.
///
/// Resolves the capture policy fail-closed, starts the collector with that
/// policy, prints the endpoint + token + a harness-wiring snippet, and blocks on
/// the server task (which itself stops on SIGINT/SIGTERM).
///
/// # Errors
/// Returns an error if the store cannot be opened or no port in the
/// auto-increment range is free.
pub fn run(args: HooksArgs) -> anyhow::Result<i32> {
    // Resolve the capture policy through the shared fail-closed helper so the
    // cross-process pause toggle (`<out_dir>/capture-state.json`) silences hook
    // ingest too. Only `--no-redact` is carried on the overlay here.
    let overlay = CliOverlay {
        no_redact: args.no_redact,
        ..Default::default()
    };
    let policy = CapturePolicy::resolve(&args.root, &args.out_dir, overlay);

    let store = Store::open_in_dir(&args.out_dir)?;

    // Honor an explicit env token if present (LOGBOOK_INGEST_TOKEN), else mint
    // one — same sourcing as `logbook run`'s collector.
    let token_mode = if std::env::var_os(logbook_collector::INGEST_TOKEN_ENV).is_some() {
        TokenMode::Env
    } else {
        TokenMode::Generated
    };

    let mut collector_cfg = CollectorConfig::new(args.out_dir.clone(), args.dev_origin.clone())
        .with_port(args.port)
        .with_token_mode(token_mode)
        .with_capture_policy(policy);
    if args.no_redact {
        collector_cfg = collector_cfg.without_redaction();
    }

    if args.no_redact {
        eprintln!(
            "logbook: WARNING --no-redact is set; the secrets floor still applies, but \
             non-secret hook payloads may be persisted to {}.",
            args.out_dir.display()
        );
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let collector = logbook_collector::start(collector_cfg, store).await?;
        print_instructions(&collector);
        // The collector's server task stops on its own SIGINT/SIGTERM handler;
        // awaiting `join` blocks here until then (or the parent-PID watchdog).
        collector.join().await;
        anyhow::Ok(())
    })?;

    Ok(0)
}

/// Print the endpoint, bearer token, and a copy-pasteable Claude Code hooks
/// snippet to **stdout** so a user can point a harness at the receiver.
fn print_instructions(collector: &RunningCollector) {
    let addr = collector.addr();
    let base = format!("http://{addr}");
    println!("logbook hooks: receiver listening on {base}");
    println!("  POST {base}/v1/hooks   (harness hook JSON: PreToolUse/PostToolUse/UserPromptSubmit/Stop)");
    println!("  POST {base}/v1/traces  (minimal OTLP-JSON spans)");
    match collector.token() {
        Some(token) => {
            println!();
            println!("Authorization: Bearer {token}");
            println!();
            println!("Point Claude Code at it by adding a hook that POSTs each event, e.g. in");
            println!("your Claude Code settings `hooks` (one entry per event):");
            println!();
            println!("  PreToolUse / PostToolUse / UserPromptSubmit / Stop ->");
            println!(
                "    curl -sS -X POST {base}/v1/hooks \\\n      \
                 -H 'Authorization: Bearer {token}' \\\n      \
                 -H 'Content-Type: application/json' \\\n      \
                 --data-binary @-"
            );
            println!();
            println!("(pipe the hook's JSON payload on stdin; the receiver redacts before storing.)");
        }
        None => {
            println!();
            println!("(token disabled — dev/test only; every request is accepted.)");
        }
    }
    println!();
    println!("Press Ctrl-C to stop.");
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
        Hooks(HooksArgs),
    }

    fn parse(argv: &[&str]) -> HooksArgs {
        let cli = TestCli::try_parse_from(argv).expect("parse");
        match cli.cmd {
            TestCmd::Hooks(h) => h,
        }
    }

    #[test]
    fn parses_hooks_defaults() {
        let h = parse(&["x", "hooks"]);
        assert_eq!(h.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(h.root, PathBuf::from("."));
        assert_eq!(h.port, 4318);
        assert_eq!(h.dev_origin, "http://localhost:5173");
        assert!(!h.no_redact);
    }

    #[test]
    fn parses_hooks_opts() {
        let h = parse(&[
            "x", "hooks", "--out-dir", "/tmp/o", "--root", "/repo", "--port", "9000",
            "--dev-origin", "http://localhost:3000", "--no-redact",
        ]);
        assert_eq!(h.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(h.root, PathBuf::from("/repo"));
        assert_eq!(h.port, 9000);
        assert_eq!(h.dev_origin, "http://localhost:3000");
        assert!(h.no_redact);
    }
}
