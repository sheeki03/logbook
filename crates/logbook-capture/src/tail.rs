//! `tail` support: resolve a log file (latest / fuzzy / raw) and stream it
//! (plan §3, ported from OpenLogs `cli.ts` `runTail`).
//!
//! The resolution rules live in [`crate::paths::resolve_tail_path`]; this module
//! adds the runtime behaviour: a friendly error when no matching log exists, and
//! delegating the actual streaming to the system `tail` (so `-n`, `-f`, etc. all
//! work exactly as users expect), matching OpenLogs.

use std::path::Path;

use crate::error::{CaptureError, Result};
use crate::paths;

/// Options for a `tail` invocation.
#[derive(Clone, Debug)]
pub struct TailOptions {
    /// Output directory to look in.
    pub out_dir: std::path::PathBuf,
    /// Optional fuzzy query selecting a specific run.
    pub query: Option<String>,
    /// Tail the `*.terminal.log` transcript instead of the cleaned `*.txt`.
    pub terminal: bool,
    /// Extra arguments forwarded verbatim to `tail` (e.g. `-n 20`, `-f`).
    pub tail_args: Vec<String>,
}

/// Compose the friendly "no log found" message, matching OpenLogs wording (with
/// `openlogs`→`logbook`).
#[must_use]
pub fn not_found_message(out_dir: &Path, query: Option<&str>, path: &Path) -> String {
    match query {
        Some(q) => format!(
            "No log found for {q:?} in {}. Run your command with \"logbook <command>\" first, or pass --name to make it easier to find.",
            out_dir.display()
        ),
        None => format!(
            "No log found at {}. Run your command with \"logbook <command>\" first, or pass --out-dir if your logs live elsewhere.",
            path.display()
        ),
    }
}

/// Resolve the file `tail` should read, returning the friendly error string (as
/// an `Err`) if it does not exist. The `Ok` value is the resolved path.
///
/// # Errors
/// Returns [`CaptureError::Pty`] carrying the friendly message when no matching
/// log file exists (the variant is reused only as a string carrier here).
pub fn resolve(options: &TailOptions) -> Result<std::path::PathBuf> {
    let path = paths::resolve_tail_path(&options.out_dir, options.query.as_deref(), options.terminal);
    if !path.exists() {
        return Err(CaptureError::NotFound(not_found_message(
            &options.out_dir,
            options.query.as_deref(),
            &path,
        )));
    }
    Ok(path)
}

/// Run `tail` against the resolved path, inheriting stdio, returning its exit
/// code. On a missing log the friendly message is printed to stderr and `1` is
/// returned (matching OpenLogs' `{ code: 1 }`).
///
/// # Errors
/// Returns a [`CaptureError`] only if spawning `tail` itself fails.
pub fn run(options: &TailOptions) -> Result<i32> {
    let path = match resolve(options) {
        Ok(p) => p,
        Err(CaptureError::NotFound(msg)) => {
            eprintln!("{msg}");
            return Ok(1);
        }
        Err(e) => return Err(e),
    };

    let status = std::process::Command::new("tail")
        .args(&options.tail_args)
        .arg(&path)
        .status()
        .map_err(|e| CaptureError::Pty(format!("spawning tail failed: {e}")))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friendly_message_with_query() {
        let dir = std::path::Path::new("/tmp/out");
        let path = std::path::Path::new("/tmp/out/server.txt");
        let msg = not_found_message(dir, Some("server"), path);
        assert!(msg.contains(r#"No log found for "server""#), "{msg}");
        assert!(msg.contains("/tmp/out"), "{msg}");
    }

    #[test]
    fn friendly_message_without_query() {
        let dir = std::path::Path::new("/tmp/out");
        let path = std::path::Path::new("/tmp/out/latest.txt");
        let msg = not_found_message(dir, None, path);
        assert!(msg.contains("No log found at /tmp/out/latest.txt."), "{msg}");
    }

    #[test]
    fn resolve_errs_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let opts = TailOptions {
            out_dir: dir.path().to_path_buf(),
            query: Some("server".into()),
            terminal: false,
            tail_args: vec![],
        };
        let err = resolve(&opts).unwrap_err();
        assert!(matches!(err, CaptureError::NotFound(_)));
    }

    #[test]
    fn resolve_ok_when_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("latest.txt"), "hi\n").unwrap();
        let opts = TailOptions {
            out_dir: dir.path().to_path_buf(),
            query: None,
            terminal: false,
            tail_args: vec![],
        };
        let p = resolve(&opts).unwrap();
        assert_eq!(p, dir.path().join("latest.txt"));
    }
}
