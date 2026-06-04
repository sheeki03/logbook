//! `logbook debug ...` — non-invasive debug sessions (plan §6), wired to
//! `logbook-debug`.
//!
//! v1 surfaces the **passive** tier (Tier 1), which is the reliable default:
//! open a session, pull already-captured evidence (logs / console / network /
//! errors / findings) scoped by trace, session, time window, or full-text
//! match, print it, and end the session. No process or source file is touched —
//! the crate's `git status`-clean guarantee holds.
//!
//! DAP logpoints (Tier 2) are alpha and require attaching to a live adapter;
//! they are exercised by the crate's own tests rather than this one-shot CLI.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use logbook_debug::{DebugMode, DebugSession, EvidenceFilter};
use logbook_store::Store;

/// `logbook debug <subcommand>`.
#[derive(Debug, Args)]
pub struct DebugArgs {
    /// Out-dir holding the logbook store to investigate.
    #[arg(long, global = true, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// The debug subcommand.
    #[command(subcommand)]
    pub command: DebugCommand,
}

/// `debug` subcommands.
#[derive(Debug, Subcommand)]
pub enum DebugCommand {
    /// Open a passive session, fetch evidence, print it (JSON), and end the
    /// session. The non-invasive Tier-1 loop.
    Fetch(FetchArgs),
    /// List recorded debug sessions.
    Sessions,
}

/// `debug fetch [opts]`.
#[derive(Debug, Args)]
pub struct FetchArgs {
    /// Scope evidence to a single correlated trace id (hex).
    #[arg(long)]
    pub trace: Option<String>,

    /// Scope evidence to a captured session id.
    #[arg(long)]
    pub session: Option<String>,

    /// Full-text search (FTS5 MATCH syntax) to hone on a specific message.
    #[arg(long)]
    pub query: Option<String>,

    /// Cap on the number of rows pulled.
    #[arg(long)]
    pub limit: Option<u32>,

    /// A free-form target description recorded on the session (process name,
    /// `file:line`, …).
    #[arg(long)]
    pub target: Option<String>,
}

/// Dispatch a `debug` invocation.
///
/// # Errors
/// Returns an error if the store cannot be opened or the session lifecycle /
/// evidence query fails.
pub fn run(args: DebugArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;
    match args.command {
        DebugCommand::Fetch(fetch) => fetch_evidence(&store, fetch),
        DebugCommand::Sessions => list_sessions(&store),
    }
}

/// The passive Tier-1 loop: start → fetch → end, printing the bucketed evidence
/// as JSON.
fn fetch_evidence(store: &Store, args: FetchArgs) -> anyhow::Result<i32> {
    let mut session = DebugSession::start_session(store, DebugMode::Passive, args.target.clone())?;

    let mut filter = EvidenceFilter::new();
    filter.trace_id = args.trace;
    filter.session_id = args.session;
    filter.text = args.query;
    filter.limit = args.limit;

    let evidence = session.fetch_evidence(Some(filter))?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);

    // End synchronously via a short-lived runtime: `end_session` detaches any
    // DAP client (none here) and marks the row `ended`.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(session.end_session())?;
    Ok(0)
}

/// List recorded debug sessions as JSON.
fn list_sessions(store: &Store) -> anyhow::Result<i32> {
    let rows = logbook_debug::list_sessions(store)?;
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(0)
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
        Debug(DebugArgs),
    }

    #[test]
    fn parses_fetch_with_scopes() {
        let cli = TestCli::try_parse_from([
            "x", "debug", "fetch", "--trace", "abcd", "--query", "panic", "--limit", "10",
        ])
        .unwrap();
        match cli.cmd {
            TestCmd::Debug(a) => match a.command {
                DebugCommand::Fetch(f) => {
                    assert_eq!(f.trace.as_deref(), Some("abcd"));
                    assert_eq!(f.query.as_deref(), Some("panic"));
                    assert_eq!(f.limit, Some(10));
                }
                _ => panic!("expected fetch"),
            },
        }
    }

    #[test]
    fn fetch_runs_full_passive_loop() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        // No evidence planted — an empty fetch should still succeed and end the
        // session cleanly.
        let code = fetch_evidence(
            &store,
            FetchArgs {
                trace: None,
                session: None,
                query: None,
                limit: None,
                target: Some("svc".into()),
            },
        )
        .unwrap();
        assert_eq!(code, 0);
        // The session was recorded and ended.
        let rows = logbook_debug::list_sessions(&store).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, logbook_debug::DebugStatus::Ended);
    }
}
