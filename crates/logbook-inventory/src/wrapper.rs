//! The `logbook agent <agent-cli>` wrapper (plan §1.1/§1.2, v2 #4 capture).
//!
//! Runs the agent's own CLI **through the PTY capture pipeline**
//! ([`logbook_capture::run_with_outcome`]) and records what it did under **one**
//! `trace_id`/`session_id`:
//! - an `agent_sessions` row (agent, command, trace id, timing, exit code),
//! - `agent_actions` rows describing the **session-accurate file diff** the agent
//!   produced (a per-file redacted start→end content diff — *not* a `git diff`
//!   hunk subtraction, which is unstable when a session edit lands adjacent to
//!   pre-existing dirt), and
//! - (written by the caller from the returned [`logbook_capture::CaptureOutcome`])
//!   a `session_transcripts` row pointing at the redacted transcript files.
//!
//! # Session-accurate, redaction-safe diffs (plan §1.2)
//! Diffs must reflect **what THIS session changed**, not pre-existing dirt, and
//! must never violate the core rule (redaction before persistence).
//! **logbook never persists raw file preimages.** At session start the wrapper
//! builds an *ephemeral, in-memory* per-file baseline of the **redacted content**
//! of the tracked + untracked-not-ignored set (size-capped per file + in total,
//! `.gitignore` respected). At teardown, for each file whose redacted content
//! changed, it diffs the redacted start content → redacted end content
//! (in-memory via the `similar` crate — no temp files, no `git diff --no-index`).
//! Only the redacted diff is persisted, capped to the `file_diffs` class bound.
//!
//! # Revert safety
//! `revert_safe = true` only for a **clean tree at start** (git itself is the
//! preimage). A dirty tree yields an accurate redacted diff but `revert_safe =
//! false` (the redacted diff cannot exactly restore content). Files over the
//! baseline cap surface a "diff omitted (size)" marker with `revert_safe =
//! false`. The `--reversible` opt-in (encrypted preimages) is **not yet
//! available** and returns a clear error.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use logbook_core::{CapturePolicy, Redactor, SensitivityClass, SessionId, TraceId};

use crate::error::{InventoryError, Result};

/// Per-file size cap for the in-memory redacted-content baseline (~1 MiB). A file
/// larger than this is *tracked for change* (by length) but its content is not
/// held, so a change surfaces a "diff omitted (size)" marker rather than a body.
const PER_FILE_BASELINE_CAP: u64 = 1024 * 1024;

/// Total size cap across the whole in-memory baseline (64 MiB). Accounted in raw
/// on-disk bytes (a safe upper bound on the redacted content actually held) so the
/// budget gate and the running total speak the same unit. Once the accumulated raw
/// length reaches this, further files are tracked by a marker only (no content
/// baseline) so a huge working tree cannot blow up memory.
const TOTAL_BASELINE_CAP: u64 = 64 * 1024 * 1024;

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
    /// Extra detail (e.g. a "diff omitted (size)" marker), already redacted.
    pub detail: Option<String>,
    /// When observed, microseconds.
    pub observed_at: i64,
    /// The redacted, size-capped per-file diff (redacted start→end content).
    /// `None` when diff capture is off, the change is a deletion-only marker, or
    /// the file exceeded the baseline cap.
    pub diff: Option<String>,
    /// Original (pre-truncation) diff byte length. `diff_bytes > len(diff)` flags
    /// a truncated body (see [`CapturePolicy::cap_body`]).
    pub diff_bytes: Option<u64>,
    /// Post-state content hash (of the **redacted** end content) — never of raw
    /// content. `logbook revert` (Phase 3) only applies if the file still matches.
    pub post_hash: Option<String>,
    /// Whether this action can be safely reverted (clean tree at start). Dirty
    /// trees keep an accurate diff but `revert_safe = false`.
    pub revert_safe: bool,
    /// Most-sensitive class present in the action (snake_case wire string), or
    /// `None` when no body was captured.
    pub max_sensitivity: Option<String>,
}

/// The result of running an agent under the wrapper.
#[derive(Clone, Debug)]
pub struct LogbookOutcome {
    /// The session record.
    pub session: AgentSessionRecord,
    /// The diffed actions.
    pub actions: Vec<AgentAction>,
    /// Transcript pointers + counters surfaced from the capture pipeline, for the
    /// `session_transcripts` row. `None` when the child was not spawned
    /// (`spawn = false`).
    pub transcript: Option<logbook_capture::TranscriptInfo>,
}

/// Options for the wrapper.
#[derive(Clone, Debug)]
pub struct LogbookOptions {
    /// Working directory to run in / diff against (defaults to the cwd).
    pub cwd: PathBuf,
    /// Out-dir holding the logbook store + transcript files (capture needs it).
    pub out_dir: PathBuf,
    /// Endpoint id to stamp on the session.
    pub endpoint_id: Option<String>,
    /// Whether to actually spawn the child through capture. When `false`, no
    /// child runs and no baseline/diff is computed (used by tests that diff a
    /// synthetic before/after via [`diff_snapshots`]).
    pub spawn: bool,
    /// The resolved capture policy (gates `file_diffs` capture + provides the
    /// per-file body cap). Defaults to the recorder-on [`CapturePolicy::default`].
    pub policy: CapturePolicy,
    /// Whether the general (non-secret) redactor is enabled — the resolved
    /// `[redaction].enabled && !--no-redact`. The secrets floor always applies
    /// regardless (the passed redactor carries it).
    pub redaction_enabled: bool,
    /// `--reversible` opt-in for encrypted dirty-tree preimages. **Not yet
    /// available**: when `true` on a dirty tree the wrapper returns a clear error.
    pub reversible: bool,
}

impl Default for LogbookOptions {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            out_dir: PathBuf::from(logbook_capture::paths::DEFAULT_OUT_DIR),
            endpoint_id: None,
            spawn: true,
            policy: CapturePolicy::default(),
            redaction_enabled: true,
            reversible: false,
        }
    }
}

/// Run `<agent> <args...>` under the wrapper, capturing a session + a
/// session-accurate redacted file diff.
///
/// `argv[0]` is the agent CLI name/path; the rest are passed through verbatim.
/// The agent runs **through the PTY capture pipeline** under the supplied
/// `trace`/`session`/`cwd`, so the transcript, the structured line-events, the
/// `agent_sessions` row, the diffed `agent_actions`, and the `session_transcripts`
/// row (written by the caller from [`LogbookOutcome::transcript`]) all share one
/// `trace_id`/`session_id`. Interactive agents keep working (the PTY forwards
/// stdin).
///
/// # Errors
/// Returns [`InventoryError::AgentSpawn`] if the child cannot be launched,
/// [`InventoryError::Capture`] if the capture pipeline fails, or
/// [`InventoryError::ReversibleUnavailable`] when `--reversible` is requested for
/// a dirty tree (not yet implemented).
pub async fn run_agent(
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

    // Whether the tree is clean at session start: clean ⇒ git itself is the
    // preimage ⇒ revert_safe. Computed before the run so a session that *makes*
    // the tree dirty is still scored against its start state.
    let clean_at_start = git_tree_is_clean(&opts.cwd);

    // `--reversible` (encrypted dirty-tree preimages) is not yet implemented; a
    // dirty tree that asks for it must fail loudly rather than silently fall back
    // to revert_safe=false (which would mislead a caller expecting reversibility).
    if opts.reversible && !clean_at_start {
        return Err(InventoryError::ReversibleUnavailable);
    }

    // Build the ephemeral in-memory redacted-content baseline before the run.
    // Skipped entirely when diff capture is off (or the child won't be spawned).
    let capture_diffs = opts.spawn && opts.policy.should_capture(SensitivityClass::FileDiffs);
    let before = if capture_diffs {
        build_redacted_baseline(&opts.cwd, redactor)
    } else {
        RedactedBaseline::default()
    };

    // Drive the child through the PTY capture pipeline under the shared identity.
    let (exit_code, transcript) = if opts.spawn {
        let mut cfg = logbook_capture::CaptureConfig::new(argv.to_vec());
        cfg.out_dir = opts.out_dir.clone();
        cfg.cwd = Some(opts.cwd.clone());
        cfg.trace_id = Some(trace);
        cfg.session_id = Some(session_id.clone());
        // `redact = false` makes the capture pipeline drop to the secrets floor
        // only (mirroring `--no-redact`); the general redactor stays on otherwise.
        cfg.redact = opts.redaction_enabled;
        let outcome = logbook_capture::run_with_outcome(cfg)
            .await
            .map_err(|source| InventoryError::Capture {
                command: command_line.clone(),
                source,
            })?;
        (Some(outcome.exit_code), Some(outcome.transcript))
    } else {
        (None, None)
    };

    let ended_at = now_micros();

    // Teardown: re-snapshot and diff redacted-start → redacted-end per file.
    let actions = if capture_diffs {
        let after = build_redacted_baseline(&opts.cwd, redactor);
        diff_redacted_baselines(&before, &after, ended_at, clean_at_start, &opts.policy, redactor)
    } else {
        Vec::new()
    };

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
        transcript,
    })
}

/// A per-file snapshot in the ephemeral in-memory baseline: the file's
/// **redacted** content (or `None` when the file exceeded the per-file / total
/// baseline cap) plus a stable hash of that redacted content for cheap
/// change-detection. Raw content is never held.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FileSnapshot {
    /// Redacted file content, or `None` when over the baseline cap (content not
    /// held; only `redacted_hash` distinguishes a change).
    content: Option<String>,
    /// Stable hash of the redacted content. Over-cap files (content not held)
    /// instead carry a content-sensitive `len:..:mtime:..:h:..` marker
    /// (see [`over_cap_marker`]) so an equal-length in-place edit still changes it.
    redacted_hash: String,
}

/// The ephemeral in-memory baseline: `path -> redacted snapshot`.
#[derive(Clone, Debug, Default)]
struct RedactedBaseline {
    files: BTreeMap<String, FileSnapshot>,
}

/// Build the ephemeral in-memory **redacted-content** baseline of the tracked +
/// untracked-not-ignored files under `cwd` (plan §1.2).
///
/// Each file's content is read, redacted in memory, and held keyed by path,
/// bounded by [`PER_FILE_BASELINE_CAP`] per file and [`TOTAL_BASELINE_CAP`] in
/// total. `.gitignore`d trees (`node_modules`/`target`) are excluded because the
/// file list comes from `git ls-files --exclude-standard`. Returns an empty
/// baseline when `cwd` is not a git repo or git is unavailable.
///
/// Raw file content never leaves this function: only the redacted content (and a
/// hash of it) is retained, and nothing is written to disk.
fn build_redacted_baseline(cwd: &Path, redactor: &Redactor) -> RedactedBaseline {
    let mut baseline = RedactedBaseline::default();
    let files = match git_listed_files(cwd) {
        Some(f) => f,
        None => return baseline,
    };
    let mut total_held: u64 = 0;
    for rel in files {
        let full = cwd.join(&rel);
        let meta = match std::fs::metadata(&full) {
            Ok(m) if m.is_file() => m,
            // Skip directories (submodule gitlinks) and unreadable entries.
            _ => continue,
        };
        let len = meta.len();
        // Over the per-file cap, or holding it would exceed the total cap: track
        // by a CONTENT-SENSITIVE marker (no content baseline) so huge/binary files
        // can't blow up memory — a change still surfaces (via the marker hash) as a
        // "diff omitted (size)" action. The marker hashes the raw bytes (and folds
        // in mtime) so an equal-length in-place edit changes it; the bytes are
        // hashed transiently and dropped — never retained — so memory stays bounded.
        //
        // Budget accounting uses raw `len` here, matching the gate below, so the
        // gate and the accumulator speak the same unit (raw on-disk length, a safe
        // upper bound on memory) and the baseline cannot exceed TOTAL_BASELINE_CAP.
        if len > PER_FILE_BASELINE_CAP || total_held.saturating_add(len) > TOTAL_BASELINE_CAP {
            total_held = total_held.saturating_add(len);
            baseline.files.insert(
                rel,
                FileSnapshot {
                    content: None,
                    redacted_hash: over_cap_marker(&full, len, &meta),
                },
            );
            continue;
        }
        // Read + redact in memory. A non-UTF-8 (binary) file reads lossily; we
        // still redact it but treat it as content for change-detection. Unreadable
        // files are skipped (they cannot be diffed).
        let Ok(raw) = std::fs::read(&full) else {
            continue;
        };
        let redacted = redact_bytes(redactor, &raw);
        let hash = stable_hash(&redacted);
        total_held = total_held.saturating_add(len);
        baseline.files.insert(
            rel,
            FileSnapshot {
                content: Some(redacted),
                redacted_hash: hash,
            },
        );
    }
    baseline
}

/// Redact raw file bytes in memory, decoding UTF-8 lossily first (binary files
/// are still scrubbed of any embedded secret-shaped text). The returned string is
/// the **redacted** content — the only form ever retained or persisted.
fn redact_bytes(redactor: &Redactor, raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    redactor.redact(&text).into_owned()
}

/// Build the change-detection marker for an over-cap file (one whose content is
/// *not* held). It must be **content-sensitive without retaining content**: an
/// equal-length in-place edit to a >1 MiB file has to change the marker so
/// [`diff_redacted_baselines`] still emits a "diff omitted (size)" action via the
/// over-cap branch in [`build_diff_action`].
///
/// The raw bytes are read and hashed *transiently* (the buffer is dropped at the
/// end of this call — never stored on the [`FileSnapshot`]), so memory stays
/// bounded by [`PER_FILE_BASELINE_CAP`] regardless of file size. mtime is folded
/// in as a cheap second signal so a touch is also detected. If the bytes cannot be
/// read (a race, a permissions flip), fall back to a `len:{len}` + mtime marker:
/// still no content retained, and an mtime change alone surfaces the edit.
fn over_cap_marker(full: &Path, len: u64, meta: &std::fs::Metadata) -> String {
    let mtime = mtime_nanos(meta);
    match std::fs::read(full) {
        // Hash the raw bytes transiently; `raw` is dropped when this arm returns.
        Ok(raw) => {
            let hash = stable_hash_bytes(&raw);
            format!("len:{len}:mtime:{mtime}:h:{hash}")
        }
        // Unreadable now: keep length + mtime so an equal-length edit that also
        // bumps mtime is still distinguishable, without ever holding content.
        Err(_) => format!("len:{len}:mtime:{mtime}"),
    }
}

/// Best-effort modification time as nanoseconds since the Unix epoch, or `0` when
/// the platform / filesystem does not expose it. Used only as a change-detection
/// signal in [`over_cap_marker`], never as a wall-clock value.
fn mtime_nanos(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Diff two redacted baselines into session-accurate [`AgentAction`]s (plan
/// §1.2). For each file whose redacted content changed, produce a unified diff of
/// the **redacted** start→end content (in-memory, via `similar` — no temp files),
/// capped to the `file_diffs` class bound. This isolates exactly the session's
/// change vs pre-existing dirt, for tracked and untracked-at-start files alike.
///
/// `revert_safe` is `true` only when `clean_at_start` (git is the preimage) and
/// the file's content baseline was held (not over-cap).
fn diff_redacted_baselines(
    before: &RedactedBaseline,
    after: &RedactedBaseline,
    at: i64,
    clean_at_start: bool,
    policy: &CapturePolicy,
    redactor: &Redactor,
) -> Vec<AgentAction> {
    let mut actions = Vec::new();

    // Added or modified.
    for (path, post) in &after.files {
        let pre = before.files.get(path);
        match pre {
            None => actions.push(build_diff_action(
                "file_added",
                path,
                None,
                post,
                at,
                clean_at_start,
                policy,
                redactor,
            )),
            Some(pre) if pre.redacted_hash != post.redacted_hash => actions.push(build_diff_action(
                "file_modified",
                path,
                Some(pre),
                post,
                at,
                clean_at_start,
                policy,
                redactor,
            )),
            _ => {}
        }
    }

    // Deleted.
    for (path, pre) in &before.files {
        if !after.files.contains_key(path) {
            actions.push(build_diff_action(
                "file_deleted",
                path,
                Some(pre),
                &FileSnapshot::default(),
                at,
                clean_at_start,
                policy,
                redactor,
            ));
        }
    }

    actions.sort_by(|a, b| a.path.cmp(&b.path).then(a.kind.cmp(&b.kind)));
    actions
}

/// Build one [`AgentAction`] for a changed file, computing its redacted diff body
/// (capped), post-state hash, and revert safety.
#[allow(clippy::too_many_arguments)]
fn build_diff_action(
    kind: &str,
    path: &str,
    pre: Option<&FileSnapshot>,
    post: &FileSnapshot,
    at: i64,
    clean_at_start: bool,
    policy: &CapturePolicy,
    redactor: &Redactor,
) -> AgentAction {
    let redacted_path = redactor.redact(path).into_owned();
    let pre_content = pre.and_then(|s| s.content.as_deref());
    let post_content = post.content.as_deref();
    let is_deletion = kind == "file_deleted";

    // A file is "over-cap" on either side when its content baseline was not held
    // (the snapshot exists but `content` is None). Such a change is real but its
    // body is omitted (huge/binary) — marker only, never revert_safe.
    let pre_over_cap = pre.is_some_and(|s| s.content.is_none());
    let post_over_cap = !is_deletion && post.content.is_none();

    if pre_over_cap || post_over_cap {
        return AgentAction {
            id: new_action_id(),
            kind: kind.to_string(),
            path: Some(redacted_path),
            detail: Some("diff omitted (size)".to_string()),
            observed_at: at,
            diff: None,
            diff_bytes: None,
            // Hash the (redacted) end content when held; an over-cap end carries
            // the content-sensitive `len:..:mtime:..:h:..` marker, which is still a
            // usable post-state fingerprint.
            post_hash: if is_deletion { None } else { Some(post.redacted_hash.clone()) },
            // Over-cap bodies can never be exactly reverted.
            revert_safe: false,
            // No body persisted, so no content sensitivity class applies.
            max_sensitivity: None,
        };
    }

    // Compute the redacted unified diff in memory (no temp files, no git).
    let body = unified_redacted_diff(path, pre_content, post_content);
    let (capped, original_bytes, _truncated) = policy.cap_body(SensitivityClass::FileDiffs, &body);

    AgentAction {
        id: new_action_id(),
        kind: kind.to_string(),
        path: Some(redacted_path),
        detail: None,
        observed_at: at,
        diff: Some(capped.into_owned()),
        diff_bytes: Some(original_bytes),
        // Post-state hash of the redacted end content (never raw). A deletion has
        // no post state.
        post_hash: if is_deletion {
            None
        } else {
            Some(post.redacted_hash.clone())
        },
        // Clean tree at start ⇒ git is the preimage ⇒ safe to revert. Dirty tree
        // keeps the accurate diff but is not revert_safe (the redacted diff cannot
        // exactly restore content).
        revert_safe: clean_at_start,
        max_sensitivity: Some(SensitivityClass::FileDiffs.as_str().to_string()),
    }
}

/// Produce a unified diff of two **already-redacted** contents using `similar`
/// (in-memory; no temp files). `None` content means absent (added/deleted). The
/// header uses git-style `a/<path>` / `b/<path>` labels so the UI can render it
/// like a normal patch.
fn unified_redacted_diff(path: &str, before: Option<&str>, after: Option<&str>) -> String {
    let before = before.unwrap_or("");
    let after = after.unwrap_or("");
    let diff = similar::TextDiff::from_lines(before, after);
    diff.unified_diff()
        .context_radius(3)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string()
}

/// Compute the diff actions between two **fingerprint** snapshots without
/// spawning anything (the legacy `len:mtime` heuristic). Retained for callers /
/// tests that diff a synthetic before/after; the real session path uses the
/// redacted-content baseline ([`build_redacted_baseline`]). These actions carry
/// no diff body (`diff = None`, `revert_safe = false`).
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
        id: new_action_id(),
        kind: kind.to_string(),
        path: Some(redactor.redact(path).into_owned()),
        detail: detail.map(|d| redactor.redact(d).into_owned()),
        observed_at: at,
        diff: None,
        diff_bytes: None,
        post_hash: None,
        revert_safe: false,
        max_sensitivity: None,
    }
}

fn new_action_id() -> String {
    format!("act-{}", SessionId::generate().into_inner())
}

/// A stable, non-cryptographic hash of redacted content, hex-encoded. Two seeded
/// `DefaultHasher` passes give a 128-bit-wide digest — wide enough for the
/// Phase-3 revert "still matches?" check without pulling in a crypto dependency.
/// Hashing **redacted** content is intentional: raw content is never hashed
/// (consistent with the "never persist a raw preimage" rule).
fn stable_hash(redacted: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h1 = std::collections::hash_map::DefaultHasher::new();
    redacted.hash(&mut h1);
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    0x9E37_79B9_7F4A_7C15u64.hash(&mut h2);
    redacted.hash(&mut h2);
    format!("{:016x}{:016x}", h1.finish(), h2.finish())
}

/// Byte-oriented sibling of [`stable_hash`]: a stable, non-cryptographic 128-bit
/// digest of raw bytes, hex-encoded. Used for the over-cap change-detection marker
/// ([`over_cap_marker`]), where the file content is *not* retained — the bytes are
/// hashed transiently and dropped. Hashing the raw bytes directly (rather than a
/// lossy UTF-8 decode) means an equal-length in-place edit to a binary file still
/// changes the digest. The bytes are never persisted; only the digest is.
fn stable_hash_bytes(raw: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h1 = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut h1);
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    0x9E37_79B9_7F4A_7C15u64.hash(&mut h2);
    raw.hash(&mut h2);
    format!("{:016x}{:016x}", h1.finish(), h2.finish())
}

/// Whether the git working tree under `cwd` is clean (no staged or unstaged
/// changes, no untracked-not-ignored files) at session start. A clean tree means
/// git itself is the preimage, so the session's diff is exactly revertable.
///
/// Returns `false` (treat as dirty, the conservative default) when `cwd` is not a
/// git repo or git is unavailable — a non-repo session is never revert_safe.
fn git_tree_is_clean(cwd: &Path) -> bool {
    let out = match Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(cwd)
        .output()
    {
        Ok(out) if out.status.success() => out,
        // Not a repo / git missing / git error: conservatively treat as dirty.
        _ => return false,
    };
    String::from_utf8_lossy(&out.stdout).trim().is_empty()
}

/// List files git knows about (tracked) plus untracked-but-not-ignored files,
/// so a newly created file is detected as `file_added` and `.gitignore`d trees
/// (`node_modules`/`target`) are excluded from the baseline.
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

/// Extract the canonical agent name from `argv[0]` (basename, strip extension).
fn agent_name_from(arg0: &str) -> String {
    let base = Path::new(arg0)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| arg0.to_string());
    base.trim_end_matches(".exe").to_string()
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

    /// A small current-thread runtime to drive the async `run_agent` from sync
    /// tests (mirrors `cli.rs::run_agent_wrapper`).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn init_repo(cwd: &Path) {
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
        let _ = Command::new("git")
            .args(["config", "user.email", "t@t"])
            .current_dir(cwd)
            .status();
        let _ = Command::new("git")
            .args(["config", "user.name", "t"])
            .current_dir(cwd)
            .status();
    }

    fn commit_all(cwd: &Path) {
        assert!(Command::new("git")
            .args(["add", "-A"])
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-q", "-m", "base"])
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
    }

    fn opts_for(cwd: &Path, out: &Path) -> LogbookOptions {
        LogbookOptions {
            cwd: cwd.to_path_buf(),
            out_dir: out.to_path_buf(),
            endpoint_id: Some("endpoint-test".into()),
            spawn: true,
            policy: CapturePolicy::default(),
            redaction_enabled: true,
            reversible: false,
        }
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
        // confirm the wrapper records the session + a file_added action with a
        // diff body. The shared trace ties the session to its transcript.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);

        let opts = opts_for(cwd, out.path());
        // Use /bin/sh as the "agent": it creates a new file, simulating an edit.
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hello > created_by_agent.txt".to_string(),
        ];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert_eq!(outcome.session.agent, "sh", "basename of /bin/sh");
        assert_eq!(outcome.session.exit_code, Some(0));
        assert_eq!(outcome.session.trace_id.len(), 32);
        // The created file should appear as an added action with a diff body.
        let added: Vec<&AgentAction> = outcome
            .actions
            .iter()
            .filter(|a| a.kind == "file_added")
            .filter(|a| a.path.as_deref().is_some_and(|p| p.ends_with("created_by_agent.txt")))
            .collect();
        assert_eq!(added.len(), 1, "expected one file_added; got {:?}", outcome.actions);
        let act = added[0];
        assert!(act.diff.as_deref().unwrap().contains("hello"), "diff body: {:?}", act.diff);
        assert!(act.diff_bytes.unwrap() > 0);
        assert!(act.revert_safe, "clean tree at start ⇒ revert_safe");
        assert_eq!(act.max_sensitivity.as_deref(), Some("file_diffs"));
        // The capture pipeline produced a transcript pointer under the same trace.
        let t = outcome.transcript.expect("transcript info");
        assert!(t.terminal_log_path.is_some());
    }

    #[test]
    fn session_accurate_diff_excludes_preexisting_dirt() {
        // A repo with pre-existing dirty + staged changes, and a session edit on a
        // line ADJACENT to pre-existing dirt + a further-modified untracked file.
        // The recorded diff must contain ONLY the session's change.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);
        // Committed baseline: a 5-line file.
        std::fs::write(cwd.join("code.txt"), "l1\nl2\nl3\nl4\nl5\n").unwrap();
        commit_all(cwd);
        // Pre-existing DIRT: modify l1 (unstaged) and stage a separate file.
        std::fs::write(cwd.join("code.txt"), "DIRT\nl2\nl3\nl4\nl5\n").unwrap();
        std::fs::write(cwd.join("staged.txt"), "staged-content\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "staged.txt"])
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
        // An untracked-at-start file with initial content.
        std::fs::write(cwd.join("untracked.txt"), "u1\nu2\n").unwrap();

        let opts = opts_for(cwd, out.path());
        // The "agent" edits a line ADJACENT to the dirt (l2→SESSION on code.txt)
        // and appends to the untracked file. Pre-existing l1=DIRT must not leak.
        let script = "perl -0pi -e 's/^l2/SESSION/m' code.txt; printf 'u3\\n' >> untracked.txt";
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();

        let by_path = |p: &str| {
            outcome
                .actions
                .iter()
                .find(|a| a.path.as_deref().is_some_and(|x| x.ends_with(p)))
                .unwrap_or_else(|| panic!("no action for {p}; got {:?}", outcome.actions))
        };
        // code.txt: the diff attributes ONLY the session's l2→SESSION change. The
        // pre-existing l1=DIRT is part of the start baseline, so it appears as an
        // unchanged *context* line (prefix space) — never as a `+DIRT`/`-DIRT`
        // *change* line. This is exactly what hunk-subtraction would get wrong
        // (it would merge the adjacent edits and mis-attribute the dirt); the
        // redacted start→end content diff isolates the real change correctly.
        let code = by_path("code.txt");
        let code_diff = code.diff.as_deref().unwrap();
        assert!(
            code_diff.lines().any(|l| l == "+SESSION"),
            "session change must be the added line: {code_diff}"
        );
        assert!(
            code_diff.lines().any(|l| l == "-l2"),
            "the replaced line must be removed: {code_diff}"
        );
        // The pre-existing dirt is never *attributed* to the session (no +/- line).
        assert!(
            !code_diff
                .lines()
                .any(|l| (l.starts_with('+') || l.starts_with('-')) && l.contains("DIRT")),
            "pre-existing dirt must not appear as a session change: {code_diff}"
        );
        // untracked.txt: only the appended u3 line is the session change; u1/u2
        // were the start baseline so they are context (unchanged), and the added
        // line u3 shows. The pre-existing baseline (u1/u2) is not a "+add".
        let untracked = by_path("untracked.txt");
        let u_diff = untracked.diff.as_deref().unwrap();
        assert!(u_diff.contains("+u3"), "appended line present: {u_diff}");
        assert!(!u_diff.contains("+u1"), "baseline must be context, not an add: {u_diff}");
        // staged.txt was pre-existing dirt the session never touched ⇒ no action.
        assert!(
            outcome.actions.iter().all(|a| !a.path.as_deref().unwrap_or("").ends_with("staged.txt")),
            "untouched pre-existing staged file must not appear: {:?}",
            outcome.actions
        );
        // Dirty tree at start ⇒ not revert_safe.
        assert!(!code.revert_safe, "dirty tree ⇒ revert_safe=false");
    }

    #[test]
    fn no_raw_preimage_written_during_dirty_session() {
        // During a dirty-tree session, assert no unredacted content is written to
        // .git/objects or the out-dir: the baseline is in-memory and the persisted
        // diff is redacted. We plant a secret in a pre-existing file and in the
        // session change, then scan disk for the cleartext.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);
        let secret = "AKIAIOSFODNN7EXAMPLE";
        // Pre-existing dirt containing a secret (committed then modified).
        std::fs::write(cwd.join("conf.txt"), "k=old\n").unwrap();
        commit_all(cwd);
        std::fs::write(cwd.join("conf.txt"), format!("k={secret}\n")).unwrap();

        let opts = opts_for(cwd, out.path());
        // Session writes a NEW file also containing the secret.
        let script = format!("printf 'token={secret}\\n' > planted.txt");
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();

        // The persisted diff for planted.txt must NOT contain the cleartext secret.
        let planted = outcome
            .actions
            .iter()
            .find(|a| a.path.as_deref().is_some_and(|p| p.ends_with("planted.txt")))
            .expect("planted.txt action");
        assert!(
            !planted.diff.as_deref().unwrap().contains(secret),
            "secret leaked into persisted diff: {:?}",
            planted.diff
        );

        // Scan the out-dir on disk: no file logbook wrote may contain the secret.
        for entry in walk(out.path()) {
            if let Ok(bytes) = std::fs::read(&entry) {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains(secret),
                    "raw secret found on disk in {}",
                    entry.display()
                );
            }
        }
    }

    /// Recursively list files under `dir` (test helper).
    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    #[test]
    fn revert_safe_true_on_clean_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);
        std::fs::write(cwd.join("a.txt"), "one\n").unwrap();
        commit_all(cwd); // tree is now CLEAN

        let opts = opts_for(cwd, out.path());
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo two >> a.txt".to_string(),
        ];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        let act = outcome
            .actions
            .iter()
            .find(|a| a.path.as_deref().is_some_and(|p| p.ends_with("a.txt")))
            .unwrap();
        assert!(act.revert_safe, "clean tree at start ⇒ revert_safe=true");
        assert!(act.post_hash.is_some(), "post_hash recorded");
    }

    #[test]
    fn reversible_on_dirty_tree_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);
        std::fs::write(cwd.join("a.txt"), "one\n").unwrap();
        commit_all(cwd);
        std::fs::write(cwd.join("a.txt"), "DIRTY\n").unwrap(); // dirty

        let mut opts = opts_for(cwd, out.path());
        opts.reversible = true;
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()];
        let err = block_on(run_agent(&argv, &opts, &red())).unwrap_err();
        assert!(matches!(err, InventoryError::ReversibleUnavailable), "got {err:?}");
    }

    #[test]
    fn cwd_is_honored_for_child_and_diff() {
        // run_agent diffs in opts.cwd, not the process cwd: create the repo in a
        // dir that is NOT the process cwd and confirm the file is detected there.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);

        let opts = opts_for(cwd, out.path());
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hi > in_cwd.txt".to_string(),
        ];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert!(
            outcome
                .actions
                .iter()
                .any(|a| a.path.as_deref().is_some_and(|p| p.ends_with("in_cwd.txt"))),
            "child must run + diff in opts.cwd: {:?}",
            outcome.actions
        );
        // The file really landed in cwd, not the process dir.
        assert!(cwd.join("in_cwd.txt").exists());
    }

    #[test]
    fn no_redact_still_redacts_secret_in_diff() {
        // With the general redactor disabled (--no-redact ⇒ secrets floor only), a
        // planted AWS key in a session change is STILL redacted in the diff, but a
        // benign string is preserved.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);

        let mut opts = opts_for(cwd, out.path());
        opts.redaction_enabled = false; // --no-redact
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let script = format!("printf 'benign-marker\\nkey={secret}\\n' > s.txt");
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        // The wrapper diff runs through the secrets-floor redactor under --no-redact.
        let floor = Redactor::secrets_floor_with_process_env();
        let outcome = block_on(run_agent(&argv, &opts, &floor)).unwrap();
        let act = outcome
            .actions
            .iter()
            .find(|a| a.path.as_deref().is_some_and(|p| p.ends_with("s.txt")))
            .unwrap();
        let diff = act.diff.as_deref().unwrap();
        assert!(!diff.contains(secret), "secrets floor must still redact: {diff}");
        assert!(diff.contains("benign-marker"), "non-secret preserved: {diff}");
    }

    #[test]
    fn no_capture_diffs_yields_no_diff() {
        // With file_diffs capture off, run_agent records the session but no
        // actions (diff=None behavior, identical to pre-Orbit).
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);

        let mut opts = opts_for(cwd, out.path());
        opts.policy.classes.file_diffs.capture = false;
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hi > nope.txt".to_string(),
        ];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert_eq!(outcome.session.exit_code, Some(0));
        assert!(outcome.actions.is_empty(), "no diffs captured ⇒ no actions");
    }

    #[test]
    fn diff_max_bytes_truncates_and_marks() {
        // A tiny file_diffs cap truncates the body and sets diff_bytes > len(diff).
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);

        let mut opts = opts_for(cwd, out.path());
        opts.policy.classes.file_diffs.max_bytes = Some(16);
        // Write a file whose diff body comfortably exceeds 16 bytes.
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf 'aaaaaaaaaa\\nbbbbbbbbbb\\ncccccccccc\\n' > big.txt".to_string(),
        ];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        let act = outcome
            .actions
            .iter()
            .find(|a| a.path.as_deref().is_some_and(|p| p.ends_with("big.txt")))
            .unwrap();
        let diff = act.diff.as_deref().unwrap();
        assert!(diff.contains("[diff truncated"), "marker present: {diff}");
        assert!(
            act.diff_bytes.unwrap() > diff.len() as u64,
            "diff_bytes ({:?}) must exceed stored len ({})",
            act.diff_bytes,
            diff.len()
        );
    }

    #[test]
    fn run_agent_outside_repo_still_records_session() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let opts = opts_for(tmp.path(), out.path());
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert_eq!(outcome.session.exit_code, Some(0));
        assert!(outcome.actions.is_empty(), "no repo → no diffed actions");
    }

    #[test]
    fn run_agent_preserves_nonzero_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let opts = opts_for(tmp.path(), out.path());
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "exit 7".to_string()];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert_eq!(outcome.session.exit_code, Some(7));
    }

    #[test]
    fn command_line_is_redacted_in_session() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let opts = opts_for(tmp.path(), out.path());
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "true".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
        ];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert!(
            !outcome.session.command.contains("AKIAIOSFODNN7EXAMPLE"),
            "leaked: {}",
            outcome.session.command
        );
    }

    /// Regression (HIGH): an equal-length in-place edit to an over-cap (>1 MiB)
    /// file must still surface a "diff omitted (size)" action. Before the fix the
    /// over-cap marker was `len:{len}` (raw byte length only), so an equal-length
    /// edit left the marker identical and the change was silently dropped. The
    /// marker is now content-sensitive (hashes the raw bytes, never retaining
    /// them), so the over-cap branch in `build_diff_action` fires.
    ///
    /// This drives the baseline + diff functions directly (no spawn) so the
    /// assertion targets exactly the fixed change-detection path and is immune to
    /// mtime-resolution or PTY differences across platforms.
    #[test]
    fn over_cap_equal_length_edit_still_emits_diff_omitted() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        init_repo(cwd);

        // A file comfortably over PER_FILE_BASELINE_CAP (1 MiB), all 'a' bytes.
        let size = (PER_FILE_BASELINE_CAP + 64 * 1024) as usize;
        let path = cwd.join("big.bin");
        std::fs::write(&path, vec![b'a'; size]).unwrap();
        commit_all(cwd); // tracked, so it appears in the baseline

        // Baseline before: over-cap snapshot (content not held, marker only).
        let before = build_redacted_baseline(cwd, &red());
        let pre = before
            .files
            .get("big.bin")
            .expect("over-cap file present in baseline");
        assert!(
            pre.content.is_none(),
            "an over-cap file must not hold content"
        );

        // Equal-length in-place edit: flip ONE byte, keeping the byte length the
        // same. Under the old `len:{len}` marker this produced an identical marker.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] = b'b';
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            size as u64,
            "edit must preserve byte length to exercise the regression"
        );

        let after = build_redacted_baseline(cwd, &red());
        let post = after.files.get("big.bin").expect("file still present");
        assert!(post.content.is_none(), "still over-cap after the edit");
        assert_ne!(
            pre.redacted_hash, post.redacted_hash,
            "an equal-length edit MUST change the over-cap marker"
        );

        // The diff must now emit a `file_modified` "diff omitted (size)" action.
        let actions = diff_redacted_baselines(
            &before,
            &after,
            1_000,
            /* clean_at_start */ true,
            &CapturePolicy::default(),
            &red(),
        );
        let act = actions
            .iter()
            .find(|a| a.path.as_deref().is_some_and(|p| p.ends_with("big.bin")))
            .unwrap_or_else(|| panic!("no action for big.bin; got {actions:?}"));
        assert_eq!(act.kind, "file_modified");
        assert_eq!(
            act.detail.as_deref(),
            Some("diff omitted (size)"),
            "over-cap change must surface the size marker"
        );
        assert!(act.diff.is_none(), "over-cap action carries no body");
        assert!(!act.revert_safe, "over-cap bodies are never revert_safe");
    }

    /// End-to-end variant of the regression: the same equal-length in-place edit
    /// performed by the spawned "agent" (via `dd conv=notrunc`, which overwrites
    /// one byte without truncating) still yields a "diff omitted (size)" action.
    #[test]
    fn over_cap_equal_length_edit_via_agent_emits_diff_omitted() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let out = tempfile::tempdir().unwrap();
        init_repo(cwd);

        let size = (PER_FILE_BASELINE_CAP + 64 * 1024) as usize;
        std::fs::write(cwd.join("huge.bin"), vec![b'a'; size]).unwrap();
        commit_all(cwd);

        let opts = opts_for(cwd, out.path());
        // Overwrite exactly one byte at offset 10 in place (no truncation): this
        // keeps the file length identical while changing its content.
        let script = "printf 'b' | dd of=huge.bin bs=1 seek=10 count=1 conv=notrunc 2>/dev/null";
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
        let outcome = block_on(run_agent(&argv, &opts, &red())).unwrap();
        assert_eq!(outcome.session.exit_code, Some(0));
        // Length is unchanged after the edit.
        assert_eq!(
            std::fs::metadata(cwd.join("huge.bin")).unwrap().len(),
            size as u64
        );

        let act = outcome
            .actions
            .iter()
            .find(|a| a.path.as_deref().is_some_and(|p| p.ends_with("huge.bin")))
            .unwrap_or_else(|| {
                panic!(
                    "equal-length over-cap edit dropped; got {:?}",
                    outcome.actions
                )
            });
        assert_eq!(act.kind, "file_modified");
        assert_eq!(act.detail.as_deref(), Some("diff omitted (size)"));
        assert!(act.diff.is_none(), "over-cap action carries no body");
    }
}
