//! `logbook inventory ...` and `logbook agent <cli>` — wired to
//! `logbook-inventory` (plan §7b, §12).
//!
//! The inventory crate already exposes `clap` argument structs
//! ([`InventoryArgs`], [`AgentArgs`]) and dispatchers
//! ([`logbook_inventory::cli::run`], [`logbook_inventory::cli::run_agent_wrapper`]),
//! so this module is a paper-thin adapter: forward to those, writing their
//! human/JSON output to stdout.

use std::io::Write;
use std::path::PathBuf;

use logbook_inventory::cli::{self, AgentArgs, InventoryArgs};
use logbook_store::Store;

/// Run an `inventory` subcommand, streaming output to stdout.
///
/// # Errors
/// Propagates any [`logbook_inventory::InventoryError`] (permission denial for
/// `watch`, IO, store) as an `anyhow` error.
pub fn inventory(args: &InventoryArgs) -> anyhow::Result<i32> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    cli::run(args, &mut out)?;
    out.flush()?;
    Ok(0)
}

/// Run the `agent <cli...>` wrapper, recording a session + file diffs.
///
/// Enforces retention before recording (plan §3 / Phase 3: `Store::prune` "run
/// at `ui`/`agent` startup"): the resolved [`CapturePolicy`] +
/// [`LogbookConfig::retention`] drive a best-effort prune of the event store, so
/// the age/size caps are actually applied on every `agent` invocation. The root
/// (`std::env::current_dir()`) and `out_dir` mirror exactly what
/// [`cli::run_agent_wrapper`] resolves for the session itself, so prune reads the
/// same `logbook.toml` the capture uses.
///
/// [`CapturePolicy`]: logbook_core::CapturePolicy
/// [`LogbookConfig::retention`]: logbook_core::LogbookConfig
///
/// # Errors
/// Propagates any [`logbook_inventory::InventoryError`] (e.g. the agent binary
/// could not be launched) as an `anyhow` error. A prune failure is **not** an
/// error — it is logged and recording proceeds.
pub fn agent(args: &AgentArgs) -> anyhow::Result<i32> {
    // Best-effort retention sweep on startup, against the same store/root the
    // capture pipeline writes to. Opening the store here is cheap (it is opened
    // again inside the wrapper); a failure to open or prune must not stop the
    // agent from running, so it is logged and skipped.
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match Store::open_in_dir(&args.out_dir) {
        Ok(store) => super::prune_retention(&store, &root, &args.out_dir),
        Err(e) => tracing::warn!(error = %e, "could not open store for retention prune; continuing"),
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    cli::run_agent_wrapper(args, &mut out)?;
    out.flush()?;
    Ok(0)
}
