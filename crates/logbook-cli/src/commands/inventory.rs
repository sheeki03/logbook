//! `logbook inventory ...` and `logbook agent <cli>` — wired to
//! `logbook-inventory` (plan §7b, §12).
//!
//! The inventory crate already exposes `clap` argument structs
//! ([`InventoryArgs`], [`AgentArgs`]) and dispatchers
//! ([`logbook_inventory::cli::run`], [`logbook_inventory::cli::run_agent_wrapper`]),
//! so this module is a paper-thin adapter: forward to those, writing their
//! human/JSON output to stdout.

use std::io::Write;

use logbook_inventory::cli::{self, AgentArgs, InventoryArgs};

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
/// # Errors
/// Propagates any [`logbook_inventory::InventoryError`] (e.g. the agent binary
/// could not be launched) as an `anyhow` error.
pub fn agent(args: &AgentArgs) -> anyhow::Result<i32> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    cli::run_agent_wrapper(args, &mut out)?;
    out.flush()?;
    Ok(0)
}
