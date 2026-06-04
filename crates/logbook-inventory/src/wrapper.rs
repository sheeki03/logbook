//! The `logbook agent <agent-cli>` wrapper (plan §7b, v2 #4 capture).
//!
//! Runs the agent's own CLI as a child process and records what it did:
//! - an `agent_sessions` row (agent, command, trace id, timing, exit code), and
//! - `agent_actions` rows describing the git/file diff the agent produced
//!   during the session.
//!
//! Implementation note: the dedicated PTY capture pipeline lives in
//! `logbook-capture`, which is still a foundation-phase stub. To keep this
//! crate self-contained and within its boundary, the wrapper spawns the agent
//! with **inherited stdio** (so interactive agents work) and derives actions
//! from a git working-tree diff taken before vs. after the run. When the
//! capture crate lands, the collector/PTY tier can enrich the same
//! `agent_sessions` / `agent_actions` rows — the schema is shared.
//!
//! Everything persisted is redacted upstream where it could contain secrets
//! (command line, diff detail).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use logbook_core::{Redactor, SessionId, TraceId};

use crate::error::{InventoryError, Result};

/// A recorded `agent_sessions` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSessionRecord {
    /// Session id (also the `agent_sessions.id`).
    pub session_id: String,
    /// Endpoint id, if known.
    pub endpoint_id: Option<String>,
    /// Agent name (e.g. `claude`).
    pub agent: String,
    /// The (redacted) full command line that was run.
    pub command: String,
    /// The correlation trace id (hex) shared with any emitted events.
    pub trace_id: String,
    /// Start time, microseconds.
    pub started_at: i64,
    /// End time, microseconds.
    pub ended_at: Option<i64>,
    /// Process exit code (`128 + signum` semantics preserved from the OS).
    pub exit_code: Option<i32>,
}

/// A recorded `agent_actions` row (one file/git change).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAction {
    /// Stable id.
    pub id: String,
    /// Action kind (`file_modified`, `file_added`, `file_deleted`). There is no
    /// rename detection — a rename surfaces as a `file_deleted` + `file_added`.
    pub kind: String,
    /// Affected path (relative to the repo root), if applicable.
    pub path: Option<String>,
    /// Extra detail (e.g. the raw porcelain status code), already redacted.
    pub detail: Option<String>,
    /// When observed, microseconds.
    pub observed_at: i64,
}

/// The result of running an agent under the wrapper.
#[derive(Clone, Debug)]
pub struct LogbookOutcome {
    /// The session record.
    pub session: AgentSessionRecord,
    /// The diffed actions.
    pub actions: Vec<AgentAction>,
}

/// Options for the wrapper.
#[derive(Clone, Debug)]
pub struct LogbookOptions {
    /// Working directory to run in / diff against (defaults to the cwd).
    pub cwd: PathBuf,
    /// Endpoint id to stamp on the session.
    pub endpoint_id: Option<String>,
    /// Whether to actually spawn the child. When `false`, only the
    /// before-snapshot is taken (used by tests that diff a synthetic change).
    pub spawn: bool,
}

impl Default for LogbookOptions {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            endpoint_id: None,
            spawn: true,
        }
    }
}

/// Run `<agent> <args...>` under the wrapper, capturing a session + git/file
/// diff actions.
///
/// `argv[0]` is the agent CLI name/path; the rest are passed through verbatim.
///
/// # Errors
/// Returns [`InventoryError::AgentSpawn`] if the child cannot be launched, or
/// [`InventoryError::Io`] for diff/IO failures.
pub fn run_agent(
    argv: &[String],
    opts: &LogbookOptions,
    redactor: &Redactor,
) -> Result<LogbookOutcome> {
    assert!(!argv.is_empty(), "run_agent requires a non-empty argv");
    let agent = agent_name_from(&argv[0]);
    let trace = TraceId::new();
    let session_id = SessionId::generate();
    let command_line = redactor.redact(&argv.join(" ")).into_owned();
    let started_at = now_micros();

    // Snapshot the working tree before the run (best-effort; empty if not a repo).
    let before = git_tracked_snapshot(&opts.cwd);

    let exit_code = if opts.spawn {
        let status = Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(&opts.cwd)
            .status()
            .map_err(|source| InventoryError::AgentSpawn {
                command: command_line.clone(),
                source,
            })?;
        Some(exit_code_of(&status))
    } else {
        None
    };

    let ended_at = now_micros();
    let after = git_tracked_snapshot(&opts.cwd);
    let actions = diff_snapshots(&before, &after, ended_at, redactor);

    Ok(LogbookOutcome {
        session: AgentSessionRecord {
            session_id: session_id.into_inner(),
            endpoint_id: opts.endpoint_id.clone(),
            agent,
            command: command_line,
            trace_id: trace.to_hex(),
            started_at,
            ended_at: Some(ended_at),
            exit_code,
        },
        actions,
    })
}

/// Compute the diff actions between two snapshots without spawning anything.
/// Public for tests and for callers that want to re-diff a known before/after.
#[must_use]
pub fn diff_snapshots(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    at: i64,
    redactor: &Redactor,
) -> Vec<AgentAction> {
    let mut actions = Vec::new();
    // Added or modified.
    for (path, hash) in after {
        match before.get(path) {
            None => actions.push(action("file_added", path, None, at, redactor)),
            Some(old) if old != hash => {
                actions.push(action("file_modified", path, None, at, redactor));
            }
            _ => {}
        }
    }
    // Deleted.
    for path in before.keys() {
        if !after.contains_key(path) {
            actions.push(action("file_deleted", path, None, at, redactor));
        }
    }
    actions.sort_by(|a, b| a.path.cmp(&b.path).then(a.kind.cmp(&b.kind)));
    actions
}

fn action(
    kind: &str,
    path: &str,
    detail: Option<&str>,
    at: i64,
    redactor: &Redactor,
) -> AgentAction {
    AgentAction {
        id: format!("act-{}", SessionId::generate().into_inner()),
        kind: kind.to_string(),
        path: Some(redactor.redact(path).into_owned()),
        detail: detail.map(|d| redactor.redact(d).into_owned()),
        observed_at: at,
    }
}

/// Take a snapshot of the git-tracked (plus untracked-not-ignored) files under
/// `cwd` as a `path -> len:mtime fingerprint` map. This is a cheap stat-based
/// change heuristic (see [`file_fingerprint`]) — file contents are **not** read
/// and **not** hashed, and `git hash-object` is never invoked.
///
/// Returns an empty map if `cwd` is not a git repo or git is unavailable (the
/// wrapper still records the session). A *genuine* git failure (a locked index,
/// dubious-ownership refusal, a permissions error) also yields an empty map but
/// is logged at `warn` so an empty diff is not silently mistaken for "no
/// changes" — see [`git_listed_files`].
fn git_tracked_snapshot(cwd: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    // `git status --porcelain` is enough to drive the *diff during the run* when
    // combined with a content fingerprint, but to detect changes *caused by the
    // run* we fingerprint the tracked + untracked files directly.
    let files = match git_listed_files(cwd) {
        Some(f) => f,
        None => return map,
    };
    for rel in files {
        let full = cwd.join(&rel);
        if let Some(fp) = file_fingerprint(&full) {
            map.insert(rel, fp);
        }
    }
    map
}

/// List files git knows about (tracked) plus untracked-but-not-ignored files,
/// so a newly created file is detected as `file_added`.
///
/// Returns `None` (an empty snapshot) in three cases, but only the first two are
/// silent — the third is logged at `warn` so a genuine failure is not mistaken
/// for "no changes":
/// 1. `git` is not installed (spawn fails with [`std::io::ErrorKind::NotFound`]).
/// 2. `cwd` is not a git repository (git exits non-zero saying so).
/// 3. git ran but failed for another reason (dubious-ownership refusal, a locked
///    `.git`, a corrupted index, a permissions problem) — **warned**.
fn git_listed_files(cwd: &Path) -> Option<Vec<String>> {
    let out = match Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(cwd)
        .output()
    {
        Ok(out) => out,
        // git not installed: legitimate empty-snapshot path, stay quiet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        // Any other spawn failure (e.g. permission denied) is a real error.
        Err(e) => {
            tracing::warn!(
                cwd = %cwd.display(),
                error = %e,
                "could not run `git ls-files`; recording session without a file diff"
            );
            return None;
        }
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "not a git repository" is the expected, legitimate empty-snapshot
        // case; anything else (dubious ownership, locked index, …) is a genuine
        // git failure that would otherwise masquerade as "no changes".
        if !stderr.to_ascii_lowercase().contains("not a git repository") {
            tracing::warn!(
                cwd = %cwd.display(),
                status = ?out.status.code(),
                stderr = %stderr.trim(),
                "`git ls-files` failed; recording session without a file diff"
            );
        }
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(
        text.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// A cheap content fingerprint: `len:mtime_nanos`. Good enough to detect a file
/// changing during a single wrapped session without hashing large files.
fn file_fingerprint(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let len = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Some(format!("{len}:{mtime}"))
}

/// Extract the canonical agent name from `argv[0]` (basename, strip extension).
fn agent_name_from(arg0: &str) -> String {
    let base = Path::new(arg0)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| arg0.to_string());
    base.trim_end_matches(".exe").to_string()
}

/// Map an `ExitStatus` to an exit code, preserving `128 + signum` for
/// signal-terminated children (OpenLogs fidelity, plan §3).
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

fn now_micros() -> i64 {
    logbook_core::MicrosTimestamp::now().as_micros()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red() -> Redactor {
        Redactor::new()
    }

    #[test]
    fn agent_name_extraction() {
        assert_eq!(agent_name_from("/usr/local/bin/claude"), "claude");
        assert_eq!(agent_name_from("codex"), "codex");
        assert_eq!(agent_name_from("C:/tools/aider.exe"), "aider");
    }

    #[test]
    fn diff_detects_add_modify_delete() {
        let mut before = BTreeMap::new();
        before.insert("keep.rs".to_string(), "10:1".to_string());
        before.insert("changed.rs".to_string(), "10:1".to_string());
        before.insert("gone.rs".to_string(), "5:1".to_string());

        let mut after = BTreeMap::new();
        after.insert("keep.rs".to_string(), "10:1".to_string()); // unchanged
        after.insert("changed.rs".to_string(), "12:2".to_string()); // modified
        after.insert("new.rs".to_string(), "3:9".to_string()); // added
                                                               // gone.rs removed

        let actions = diff_snapshots(&before, &after, 1000, &red());
        let kinds: BTreeMap<&str, &str> = actions
            .iter()
            .map(|a| (a.path.as_deref().unwrap(), a.kind.as_str()))
            .collect();
        assert_eq!(kinds.get("new.rs"), Some(&"file_added"));
        assert_eq!(kinds.get("changed.rs"), Some(&"file_modified"));
        assert_eq!(kinds.get("gone.rs"), Some(&"file_deleted"));
        assert!(
            !kinds.contains_key("keep.rs"),
            "unchanged file must not appear"
        );
    }

    #[test]
    fn diff_paths_are_redacted() {
        // A path that *contains* a secret-shaped token should be redacted in the
        // recorded action (defensive; paths rarely contain secrets but we never
        // want to persist one in the clear).
        let before = BTreeMap::new();
        let mut after = BTreeMap::new();
        after.insert(
            "Bearer abcDEF123456ghiJKL.txt".to_string(),
            "1:1".to_string(),
        );
        let actions = diff_snapshots(&before, &after, 1, &red());
        assert_eq!(actions.len(), 1);
        assert!(!actions[0]
            .path
            .as_ref()
            .unwrap()
            .contains("abcDEF123456ghiJKL"));
    }

    #[test]
    fn run_agent_records_session_and_diff_in_real_repo() {
        // Create a real temp git repo, run a command that creates a file, and
        // confirm the wrapper records the session + a file_added action.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        // init repo
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
        // configure identity so any future commit ops won't fail (not needed here)
        let _ = Command::new("git")
            .args(["config", "user.email", "t@t"])
            .current_dir(cwd)
            .status();
        let _ = Command::new("git")
            .args(["config", "user.name", "t"])
            .current_dir(cwd)
            .status();

        let opts = LogbookOptions {
            cwd: cwd.to_path_buf(),
            endpoint_id: Some("endpoint-test".into()),
            spawn: true,
        };
        // Use /bin/sh as the "agent": it creates a new file, simulating an edit.
        // An absolute path keeps the test independent of $PATH.
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hello > created_by_agent.txt".to_string(),
        ];
        let outcome = run_agent(&argv, &opts, &red()).unwrap();
        assert_eq!(outcome.session.agent, "sh", "basename of /bin/sh");
        assert_eq!(outcome.session.exit_code, Some(0));
        assert!(outcome.session.trace_id.len() == 32);
        // The created file should appear as an added action.
        let added: Vec<&str> = outcome
            .actions
            .iter()
            .filter(|a| a.kind == "file_added")
            .filter_map(|a| a.path.as_deref())
            .collect();
        assert!(
            added.iter().any(|p| p.ends_with("created_by_agent.txt")),
            "expected file_added for created file, got actions: {:?}",
            outcome.actions
        );
    }

    #[test]
    fn run_agent_outside_repo_still_records_session() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = LogbookOptions {
            cwd: tmp.path().to_path_buf(),
            endpoint_id: None,
            spawn: true,
        };
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()];
        let outcome = run_agent(&argv, &opts, &red()).unwrap();
        assert_eq!(outcome.session.exit_code, Some(0));
        assert!(outcome.actions.is_empty(), "no repo → no diffed actions");
    }

    #[test]
    fn run_agent_preserves_nonzero_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = LogbookOptions {
            cwd: tmp.path().to_path_buf(),
            endpoint_id: None,
            spawn: true,
        };
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 7".to_string(),
        ];
        let outcome = run_agent(&argv, &opts, &red()).unwrap();
        assert_eq!(outcome.session.exit_code, Some(7));
    }

    #[test]
    fn missing_agent_binary_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = LogbookOptions {
            cwd: tmp.path().to_path_buf(),
            endpoint_id: None,
            spawn: true,
        };
        let argv = vec!["definitely-not-a-real-agent-binary-xyz".to_string()];
        let err = run_agent(&argv, &opts, &red()).unwrap_err();
        assert!(matches!(err, InventoryError::AgentSpawn { .. }));
    }

    #[test]
    fn command_line_is_redacted_in_session() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = LogbookOptions {
            cwd: tmp.path().to_path_buf(),
            endpoint_id: None,
            spawn: true,
        };
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "true".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
        ];
        let outcome = run_agent(&argv, &opts, &red()).unwrap();
        assert!(
            !outcome.session.command.contains("AKIAIOSFODNN7EXAMPLE"),
            "leaked: {}",
            outcome.session.command
        );
    }
}
