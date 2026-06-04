//! `logbook` — command-line entry point (plan §1, §12).
//!
//! A thin dispatcher: `clap` (derive) parses a subcommand and each arm wires
//! straight through to the crate that owns the behaviour. No business logic
//! lives here beyond argument shaping and the POSIX-only guard.
//!
//! | subcommand          | crate                |
//! |---------------------|----------------------|
//! | `run` / `tail`      | `logbook-capture`   |
//! | `mcp`               | `logbook-mcp`       |
//! | `ui`                | `logbook-ui`        |
//! | `agent`,`inventory` | `logbook-inventory` |
//! | `debug`             | `logbook-debug`     |
//! | `security`          | `logbook-security`  |
//! | `export`            | `logbook-export`    |
//! | `hub`               | (v1.5 placeholder)   |
//!
//! POSIX-only, matching OpenLogs: on Windows the binary prints a notice and
//! exits `1` before doing anything else.
//!
//! ## Diagnostics
//! A `tracing` subscriber is installed once at the top of [`main`] so the
//! `tracing::warn!`/`error!`/`info!` sites across every crate (the project's
//! "warn-and-continue" diagnostics strategy) are actually emitted instead of
//! being silently dropped by the no-op `NoSubscriber`. The subscriber writes to
//! **stderr only** — never stdout — because the `mcp` subcommand speaks
//! JSON-RPC over stdout and any stray log line there would corrupt the protocol
//! stream. Verbosity is controlled by `RUST_LOG` (default `info`).

#![forbid(unsafe_code)]

mod commands;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use logbook_inventory::cli::{AgentArgs, InventoryArgs};

use commands::{debug as debug_cmd, export as export_cmd, mcp as mcp_cmd, run as run_cmd,
    security as security_cmd, ui as ui_cmd};

/// Local-first observability plane for agent-built software.
#[derive(Debug, Parser)]
#[command(
    name = "logbook",
    version,
    about = "logbook — local-first observability plane for agent-built software",
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Top-level subcommands (plan §1).
#[derive(Debug, Subcommand)]
enum Command {
    /// Run a command inside a capturing PTY (logs, transcript, structured
    /// events) with the collector alongside. The OpenLogs `run` port.
    Run(run_cmd::RunArgs),

    /// Tail a captured log (latest / fuzzy / transcript). The OpenLogs `tail`
    /// port.
    Tail(run_cmd::TailCmdArgs),

    /// Serve the MCP tool surface over stdio (read-only by default).
    Mcp(mcp_cmd::McpArgs),

    /// Serve the embedded web UI (timeline + inventory tabs) over loopback.
    Ui(ui_cmd::UiArgs),

    /// Wrap an agent CLI, recording a session + file diffs (inventory).
    Agent(AgentArgs),

    /// Endpoint Inventory Lite: scan / watch / report.
    Inventory(InventoryArgs),

    /// Non-invasive debug session: passive evidence (+ DAP logpoints, alpha).
    Debug(debug_cmd::DebugArgs),

    /// Security scan runner + SARIF/JSON import.
    Security(security_cmd::SecurityArgs),

    /// Export captured events to a tracing schema (OTel / OpenInference /
    /// Langfuse / MLflow). v1 = schema only, no network export.
    Export(export_cmd::ExportArgs),

    /// logbook hub (v1.5) — receiver / retention / audit / RBAC.
    Hub(HubArgs),
}

/// `logbook hub` — placeholder for the v1.5 fleet receiver (plan §10, §12).
#[derive(Debug, clap::Args)]
struct HubArgs {
    /// Captured but ignored: the hub is not implemented in v1.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    rest: Vec<String>,
}

fn main() -> ExitCode {
    // POSIX-only guard (OpenLogs `cli.ts`: rejects win32 up front).
    if cfg!(windows) {
        eprintln!("logbook currently requires a POSIX terminal (macOS/Linux).");
        return ExitCode::FAILURE;
    }

    init_tracing();

    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => exit_code(code),
        Err(err) => {
            eprintln!("logbook: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch a parsed command, returning the process exit code on success.
fn dispatch(command: Command) -> anyhow::Result<i32> {
    match command {
        Command::Run(args) => run_cmd::run(args),
        Command::Tail(args) => run_cmd::tail(args),
        Command::Mcp(args) => mcp_cmd::run(args),
        Command::Ui(args) => ui_cmd::run(args),
        Command::Agent(args) => commands::inventory::agent(&args),
        Command::Inventory(args) => commands::inventory::inventory(&args),
        Command::Debug(args) => debug_cmd::run(args),
        Command::Security(args) => security_cmd::run(args),
        Command::Export(args) => export_cmd::run(args),
        Command::Hub(_) => {
            // Explicit v1 cut line (plan §12): announce + succeed.
            println!("logbook hub: v1.5 — not yet implemented");
            Ok(0)
        }
    }
}

/// Install the process-wide `tracing` subscriber.
///
/// Without this, the `tracing` facade falls back to the no-op `NoSubscriber`
/// and every `warn!`/`error!`/`info!` across the workspace is silently dropped,
/// turning the codebase's "warn-and-continue" paths into truly silent failures.
///
/// The subscriber writes to **stderr only**: the `mcp` subcommand speaks
/// JSON-RPC over stdout, so a log line on stdout would corrupt the protocol.
/// Verbosity follows `RUST_LOG` (e.g. `RUST_LOG=debug`), defaulting to `info`.
///
/// Uses `try_init` so a pre-existing global subscriber (e.g. set by a test
/// harness or an embedding process) is tolerated rather than causing a panic.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .try_init();
}

/// Map a Unix-style `i32` exit code to a process [`ExitCode`].
///
/// `ExitCode::from` only takes a `u8`, so codes are clamped into that range
/// (matching the shell's `code & 0xff` truncation); `0` stays success.
fn exit_code(code: i32) -> ExitCode {
    ExitCode::from((code & 0xff) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the "no subscriber is ever installed" defect:
    /// `init_tracing` must register a subscriber, and (because it uses
    /// `try_init`) calling it more than once in the same process must not
    /// panic. A regression to `.init()` would abort here on the second call.
    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        init_tracing();
        // A global dispatcher is now installed, so the facade is no longer the
        // no-op `NoSubscriber` and tracing events are actually dispatched.
        assert!(
            tracing::dispatcher::has_been_set(),
            "init_tracing must install a global tracing dispatcher"
        );
    }
}
