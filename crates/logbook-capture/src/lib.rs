//! `logbook-capture` — faithful Rust port of the OpenLogs PTY capture pipeline
//! (plan §3).
//!
//! This crate spawns a user command inside a pseudo-terminal and fans its output
//! to four sinks while supervising the entire descendant process tree:
//!
//! - **[`pty`]** — the capture driver. Spawns the command in a PTY and fans each
//!   output chunk to (a) stdout passthrough, (b) a redacted `*.terminal.log`
//!   transcript, (c) a cleaned `*.txt`, and (d) structured `Event{kind:Log}`
//!   rows into [`logbook_store`]. Forwards stdin, turns Ctrl-C (byte `0x03`)
//!   into a `SIGINT` to the tree (not a forwarded byte), resizes on `SIGWINCH`,
//!   and runs the controlling terminal in raw mode.
//! - **[`supervisor`]** — native (`nix`) descendant-tree discovery and signal
//!   cascade: walk the full tree (macOS `ps`, Linux `/proc`), signal
//!   deepest-first, grace ~10 s for `SIGINT` else ~1 s, then `SIGKILL`
//!   survivors. Reaps `setsid` / double-forked orphans, not just the process
//!   group, and preserves exit code `128 + signum`.
//! - **[`clean`]** — strip ANSI/VT escapes, fold `\r\n` / lone `\r` to `\n`,
//!   streaming UTF-8 decode with a final flush, and a whole-transcript rewrite
//!   pass at teardown.
//! - **[`paths`]** — `latest` + slugified-command-key + timestamped history
//!   files, the `runs.jsonl` run index, and reverse-chronological fuzzy `tail`
//!   lookup.
//! - **[`parse`]** — split cleaned text into lines, extract a log level, redact,
//!   and build `Event{kind:Log}` rows.
//! - **[`term`]** — raw-mode and terminal-size helpers for the controlling
//!   terminal.
//!
//! POSIX-only: constructing the driver or supervisor on Windows errors with
//! [`error::CaptureError::UnsupportedPlatform`].
//!
//! Secret redaction (via [`logbook_core::Redactor`]) runs **before** anything is
//! persisted — the transcript, the cleaned text, the capture scratch buffer, and
//! every structured event are all redacted; no un-redacted byte stream is ever
//! written to disk.

#![forbid(unsafe_code)]
#![cfg_attr(not(unix), allow(unused))]
// `term` and a few `nix`/`libc` interop points need `unsafe`; scope the
// allowance to this crate rather than blanket-forbidding it crate-wide.

pub mod clean;
pub mod error;
pub mod parse;
pub mod paths;
pub mod pty;
pub mod supervisor;
pub mod tail;
pub mod term;

pub use error::{CaptureError, Result};
pub use parse::{extract_level, line_to_event, LineParser, LogLevel};
pub use paths::{
    find_matching_run, log_key, log_paths, resolve_tail_path, slugify, LogPaths, PathOptions,
    RunRecord,
};
pub use pty::{run, CaptureConfig};
pub use supervisor::{descendants, parse_pid_ppid, ProcSource, Supervisor};
pub use tail::{TailOptions, run as tail_run};
