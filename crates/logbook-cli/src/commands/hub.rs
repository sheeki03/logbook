//! `logbook hub serve` — run the **fleet receiver + governance plane** (plan
//! "Phase 4 — Complete Tier & Fleet" → Hub; "Consolidated changes" CLI row:
//! `logbook hub`), wired to [`logbook_hub`].
//!
//! The local plane (`logbook run`/`agent`, the collector) stays the source of
//! truth; the hub is an **opt-in central receiver** many endpoints forward into.
//! It reuses the collector's loopback + bearer-token server model and adds the
//! governance plane: idempotent fleet ingest with a tamper-evident hash chain,
//! RBAC read projection, server-side retention, and a multi-endpoint inventory
//! roll-up.
//!
//! `hub serve` starts the same kind of loopback-only, bearer-gated axum server
//! [`logbook_hub::run_hub`] builds (plus a periodic retention sweep), prints the
//! endpoint + token + the routes, and blocks until Ctrl-C / SIGTERM.
//!
//! ## Routes (all bearer-gated except `/health`)
//! - `GET  /health`        — liveness;
//! - `POST /hub/ingest`    — `{endpoint_id, events:[…]}`: idempotent receive +
//!   audit-chain append of each newly-inserted row;
//! - `GET  /hub/verify`    — verify the hash chain (first break, if any);
//! - `GET  /hub/events`    — RBAC read (`X-Logbook-Role: viewer|auditor`);
//! - `GET  /hub/inventory` — fleet inventory roll-up;
//! - `POST /hub/prune`     — trigger the retention sweep on demand.
//!
//! ## Redaction is sacred (plan §9)
//! The hub never sees a raw provider payload — endpoints forward
//! **already-redacted** rows, and redaction runs upstream at capture before
//! anything reaches the hub. The hash chain is tamper-evidence over those stored,
//! already-redacted rows; it does not prove pre-redaction safety (see the crate
//! docs). The resolved [`CapturePolicy`] is still threaded so a paused capture
//! posture and the per-class retention caps are honoured server-side.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use logbook_core::{CapturePolicy, CliOverlay, LogbookConfig};
use logbook_hub::{run_hub, HubConfig, RunningHub, TokenMode, HUB_TOKEN_ENV};
use logbook_store::Store;

/// `logbook hub <command>` — the v1.5 fleet receiver / governance plane.
#[derive(Debug, Args)]
pub struct HubArgs {
    /// The hub subcommand.
    #[command(subcommand)]
    pub command: HubCommand,
}

/// The `hub` subcommands. Only `serve` ships today.
#[derive(Debug, Subcommand)]
pub enum HubCommand {
    /// Run the fleet receiver: a loopback-only, bearer-gated axum server with a
    /// periodic retention sweep. Blocks until Ctrl-C / SIGTERM.
    Serve(HubServeArgs),
}

/// `logbook hub serve [opts]`.
#[derive(Debug, Args)]
pub struct HubServeArgs {
    /// Out-dir holding the hub's logbook store (`<out_dir>/logbook.db`) that
    /// forwarded fleet events are written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the `[capture]` policy + the
    /// `[retention]` caps the server-side sweep enforces). Defaults to the
    /// current directory, matching how the other producers resolve their root.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Preferred port; auto-increments on conflict.
    #[arg(long, default_value_t = 4319)]
    pub port: u16,

    /// Origin allowed by CORS (scoped, never `*`). Only relevant if a browser
    /// page calls the hub; forwarding endpoints / CLIs are unaffected.
    #[arg(long, default_value = "http://localhost:5173")]
    pub dev_origin: String,
}

/// Dispatch a `hub` subcommand.
///
/// # Errors
/// Propagates the underlying hub/store error as an `anyhow` error.
pub fn run(args: HubArgs) -> anyhow::Result<i32> {
    match args.command {
        HubCommand::Serve(serve_args) => run_serve(serve_args),
    }
}

/// Run the hub receiver until Ctrl-C / SIGTERM.
///
/// Resolves the capture policy + retention caps the same way every producer does
/// (fail-closed [`CapturePolicy::resolve`] + [`LogbookConfig::retention`]), starts
/// the hub with them, prints the endpoint + token + routes, then blocks until a
/// termination signal and drains the server task.
///
/// # Errors
/// Returns an error if the store cannot be opened, the token cannot be resolved,
/// or no port in the auto-increment range is free.
fn run_serve(args: HubServeArgs) -> anyhow::Result<i32> {
    // Resolve the capture policy through the shared fail-closed helper (recorder-on
    // defaults → strict `<root>/logbook.toml [capture]` → `<out_dir>/
    // capture-state.json` narrow-only). The hub carries no CLI redaction knobs, so
    // the default overlay leaves the layered policy untouched.
    let policy = CapturePolicy::resolve(&args.root, &args.out_dir, CliOverlay::default());

    // Retention caps for the server-side sweep come from the same `logbook.toml`
    // (`[retention]`), defaulting when absent — matching the `prune_retention`
    // helper the ui/agent startup sweep uses.
    let retention = LogbookConfig::load_from_root(&args.root)
        .map(|c| c.retention)
        .unwrap_or_default();

    // Source the bearer token like the collector / hooks receiver: an explicit env
    // token (LOGBOOK_HUB_TOKEN) wins, else mint a fresh one at startup.
    let token_mode = if std::env::var_os(HUB_TOKEN_ENV).is_some() {
        TokenMode::Env
    } else {
        TokenMode::Generated
    };

    let config = HubConfig::new(args.out_dir.clone(), args.dev_origin.clone())
        .with_port(args.port)
        .with_token_mode(token_mode)
        .with_capture_policy(policy)
        .with_retention(retention);

    let store = Store::open_in_dir(&args.out_dir)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let hub = run_hub(config, store).await?;
        print_instructions(&hub);
        // `RunningHub` does not install its own signal handler, so the CLI owns
        // the shutdown wait: block until Ctrl-C / SIGTERM, then drain the server
        // task (which also stops the periodic retention sweep).
        wait_for_shutdown().await;
        eprintln!("logbook hub: shutting down…");
        hub.shutdown().await;
        anyhow::Ok(0)
    })
}

/// Print the endpoint, bearer token, and the route list to **stdout** so a fleet
/// endpoint can be pointed at the receiver.
fn print_instructions(hub: &RunningHub) {
    let addr = hub.addr();
    let base = format!("http://{addr}");
    println!("logbook hub: fleet receiver listening on {base}");
    println!("  GET  {base}/health        (liveness; unauthenticated)");
    println!("  POST {base}/hub/ingest    {{endpoint_id, events:[…]}} (idempotent receive + audit append)");
    println!("  GET  {base}/hub/verify    (hash-chain tamper check)");
    println!("  GET  {base}/hub/events    ?trace=&limit=  (RBAC read; X-Logbook-Role: viewer|auditor)");
    println!("  GET  {base}/hub/inventory (fleet roll-up)");
    println!("  POST {base}/hub/prune     (retention sweep)");
    match hub.token() {
        Some(token) => {
            println!();
            println!("Authorization: Bearer {token}");
            println!();
            println!("Point an endpoint at it by POSTing its already-redacted events, e.g.:");
            println!(
                "  curl -sS -X POST {base}/hub/ingest \\\n      \
                 -H 'Authorization: Bearer {token}' \\\n      \
                 -H 'Content-Type: application/json' \\\n      \
                 -d '{{\"endpoint_id\":\"laptop-1\",\"events\":[]}}'"
            );
        }
        None => {
            println!();
            println!("(token disabled — dev/test only; every request is accepted.)");
        }
    }
    println!();
    println!("Press Ctrl-C to stop.");
}

/// Block until a termination signal (Ctrl-C, or SIGTERM on Unix) arrives.
///
/// [`RunningHub`] exposes `shutdown()`/`join()` but does not install its own
/// signal handler, so the CLI waits here and then calls `shutdown()`. On non-Unix
/// targets we fall back to Ctrl-C only; the binary is POSIX-only regardless (see
/// `main.rs`).
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        match term.as_mut() {
            Some(term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
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

    #[derive(Debug, Subcommand)]
    enum TestCmd {
        Hub(HubArgs),
    }

    fn parse(argv: &[&str]) -> HubServeArgs {
        let cli = TestCli::try_parse_from(argv).expect("parse");
        match cli.cmd {
            TestCmd::Hub(h) => match h.command {
                HubCommand::Serve(s) => s,
            },
        }
    }

    #[test]
    fn parses_hub_serve_defaults() {
        let s = parse(&["x", "hub", "serve"]);
        assert_eq!(s.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(s.root, PathBuf::from("."));
        assert_eq!(s.port, 4319);
        assert_eq!(s.dev_origin, "http://localhost:5173");
    }

    #[test]
    fn parses_hub_serve_opts() {
        let s = parse(&[
            "x", "hub", "serve", "--out-dir", "/tmp/o", "--root", "/repo", "--port", "9200",
            "--dev-origin", "http://localhost:3000",
        ]);
        assert_eq!(s.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(s.root, PathBuf::from("/repo"));
        assert_eq!(s.port, 9200);
        assert_eq!(s.dev_origin, "http://localhost:3000");
    }

    /// `hub` requires a subcommand — bare `hub` (the old v1 placeholder swallowed
    /// trailing args) must now error rather than silently no-op.
    #[test]
    fn bare_hub_requires_a_subcommand() {
        assert!(TestCli::try_parse_from(["x", "hub"]).is_err());
    }
}
