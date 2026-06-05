//! `logbook session export <session-id> [-o <file>]` — write a self-contained,
//! **per-class sanitized** bundle for a recorded session (plan §Phase 3 "Orbit
//! additions" → `logbook session export <id>`), wired to `logbook-inventory`'s
//! `governance::export_session`.
//!
//! ## Redaction-before-persistence is sacred (plan §9, "Privacy defaults")
//! The bundle is **not** a raw dump. `governance::export_session` applies the
//! export projection from the recorder-on [`CapturePolicy`]: every sensitivity
//! class whose `ClassRule.export = false` (i.e. **every payload class** —
//! prompts, tool args/results, file-diff bodies, transcript bytes) is dropped or
//! reduced to a metadata pointer; **only `model_metadata` exports by default**.
//! A metadata+prompt LLM row therefore exports its model/token/cost block and
//! omits the prompt; a file action exports its path/kind and a `diff_present`
//! flag but withholds the diff body; the transcript ships as a pointer (paths +
//! counters), never inlined. We serialize that already-sanitized bundle verbatim;
//! the CLI never widens the projection.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use logbook_inventory::governance;
use logbook_store::Store;

/// `logbook session <subcommand>` — governance actions over a recorded session.
#[derive(Debug, Args)]
pub struct SessionArgs {
    /// The session subcommand.
    #[command(subcommand)]
    pub command: SessionCommand,
}

/// `session` subcommands. Only `export` ships here; `list`/`show`/`diff` (plan
/// §1.4 / §Consolidated changes) are served by the UI's `/api/sessions` surface.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Write the sanitized export bundle for a session as JSON (the projection
    /// drops every payload class except `model_metadata`).
    Export(ExportArgs),
}

/// `logbook session export <session-id> [-o <file>]`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// The recorded session id to export.
    pub session_id: String,

    /// Out-dir holding the logbook store the session was recorded in.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Write the bundle to this file instead of stdout.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}

/// Dispatch a `session` invocation.
///
/// # Errors
/// Returns an error if the store cannot be opened, the session does not exist
/// (`governance::export_session` returns `InventoryError::SessionNotFound`), the
/// bundle cannot be serialized, or the output file cannot be written.
pub fn run(args: SessionArgs) -> anyhow::Result<i32> {
    match args.command {
        SessionCommand::Export(export_args) => export(export_args),
    }
}

/// Build the sanitized [`governance::ExportBundle`] for the session and emit it
/// as pretty JSON to stdout or a file.
fn export(args: ExportArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;
    // The default policy is the recorder-on export projection (metadata-only);
    // no widening knob is exposed on the CLI — the bundle leaves with payload
    // classes already dropped/redacted.
    let bundle = governance::export_session(&store, &args.session_id)?;
    let rendered = serde_json::to_string_pretty(&bundle)?;

    match &args.output {
        Some(path) => {
            std::fs::write(path, &rendered)?;
            // Status to stderr so a redirect of stdout is unaffected; the bundle
            // itself went to the file.
            eprintln!(
                "logbook: exported session {} ({} action(s), {} event(s)) to {}.",
                bundle.session.session_id,
                bundle.actions.len(),
                bundle.events.len(),
                path.display()
            );
        }
        None => println!("{rendered}"),
    }
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

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Session(SessionArgs),
    }

    fn parse_export(argv: &[&str]) -> ExportArgs {
        match TestCli::try_parse_from(argv).expect("parse").cmd {
            TestCmd::Session(s) => match s.command {
                SessionCommand::Export(e) => e,
            },
        }
    }

    #[test]
    fn parses_export_session_id_and_defaults() {
        let e = parse_export(&["x", "session", "export", "sess-1"]);
        assert_eq!(e.session_id, "sess-1");
        assert_eq!(e.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert!(e.output.is_none());
    }

    #[test]
    fn parses_export_output_short_and_long() {
        let short = parse_export(&["x", "session", "export", "s", "-o", "/tmp/b.json"]);
        assert_eq!(short.output, Some(PathBuf::from("/tmp/b.json")));
        let long = parse_export(&[
            "x", "session", "export", "s", "--output", "/tmp/b2.json", "--out-dir", "/tmp/o",
        ]);
        assert_eq!(long.output, Some(PathBuf::from("/tmp/b2.json")));
        assert_eq!(long.out_dir, PathBuf::from("/tmp/o"));
    }

    #[test]
    fn export_session_id_is_required() {
        assert!(TestCli::try_parse_from(["x", "session", "export"]).is_err());
    }
}
