//! Phase-3 governance **actions** for captured agent sessions (plan "Phase 3 —
//! Correlation, Risk & Governance" → "Orbit additions").
//!
//! This module owns the four session-governance verbs that operate on the data
//! the Phase-1/2 capture pipeline already produced (`agent_sessions` +
//! `agent_actions` redacted diffs + the `events` spine + on-disk transcripts).
//! The deletion / read primitives live in `logbook_store::retention`
//! ([`Store::forget_session`] / [`Store::forget_before`] / [`Store::session_tree`]);
//! the governance *policy* (revert safety, export sanitization, on-disk cleanup)
//! lives here, next to the wrapper that wrote the data.
//!
//! - [`revert`] — reverse a session's file changes, but **only** for actions the
//!   wrapper marked `revert_safe = true` (clean tree at start, git HEAD is the
//!   preimage). Each such file is first re-checked against its recorded
//!   `post_hash` (recomputed via [`wrapper::redacted_content_hash`]) and
//!   **refused** if it diverged (the user edited it since). The recomputed hash
//!   matches the recorded one **only when the current `[redaction]` deny/allow
//!   patterns + `enabled` equal what ran at capture** — a redactor whose rules
//!   have since changed produces a different redacted-content hash and the file
//!   is conservatively refused as a mismatch (not silently reverted). `revert_safe
//!   = false` actions are never touched (no preimage exists). Restore is `git
//!   checkout HEAD -- <path>` for modified/deleted files and a file removal for
//!   added files.
//! - [`export_session`] — a self-contained, **per-class sanitized** JSON bundle
//!   of a session (header + transcript pointer + redacted diffs + events), with
//!   the export projection applied: any [`SensitivityClass`] whose
//!   `ClassRule.export = false` is dropped/omitted, so only `model_metadata` +
//!   non-payload fields leave by default. Suitable to attach to a bug report.
//! - [`forget`] — a thin wrapper over the store forget helpers that also removes
//!   the session's on-disk transcript files + any `<out_dir>/sessions/<id>/` dir.
//!   The session id is **validated** (32-hex shape, no separators / `..` /
//!   absolute) before any deletion, and every on-disk removal is **containment-
//!   checked** (canonicalized + asserted within `<out_dir>`) so a crafted id or a
//!   stray DB path can never delete a tree outside the out-dir.
//! - [`session_diffs_up_to_turn`] — the cumulative **redacted** diffs up to turn
//!   N: a review-only "time-travel" view. Exact content reconstruction needs the
//!   `--reversible` encrypted preimage (not yet available); see the type docs.
//!
//! Everything read or shipped here is **already redacted at write time** (the
//! persisted diff is the redacted start→end content diff; the secrets floor
//! scrubbed the transcript before it hit disk; plan §9). Export additionally
//! drops whole payload classes per the projection, so a bundle carries no raw
//! prompt/diff/tool payload beyond what the redacted, export-allowed projection
//! permits.

use std::path::Path;
use std::process::Command;

use logbook_core::{CapturePolicy, Event, Redactor, SensitivityClass, Status};
use logbook_store::Store;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::error::{InventoryError, Result};
use crate::model::SessionTranscriptRecord;
use crate::wrapper;

// ===========================================================================
// revert — reverse a session's file changes (revert_safe actions only)
// ===========================================================================

/// What [`revert`] did with one action's file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertDisposition {
    /// The file was restored (git checkout HEAD, or removed for an added file).
    Applied,
    /// The action was not `revert_safe` (dirty tree at start / over-cap body), so
    /// there is no preimage to restore from — skipped, never touched.
    SkippedNotSafe,
    /// The file no longer matches its recorded `post_hash` (the user edited it
    /// since the session) — **refused** to avoid clobbering newer work.
    RefusedHashMismatch,
    /// The recorded action carried no `post_hash` to verify against (and is not a
    /// deletion, which legitimately has none) — refused, conservatively.
    RefusedNoPostHash,
    /// git refused / failed to restore the file (see the per-file error). Treated
    /// as a refusal: nothing was written for this file.
    RefusedGitError,
}

/// One file's outcome in a [`RevertReport`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevertOutcome {
    /// The repo-relative path (already redacted at write time).
    pub path: String,
    /// The recorded action kind (`file_modified` | `file_added` | `file_deleted`).
    pub kind: String,
    /// What happened.
    pub disposition: RevertDisposition,
    /// A human-readable detail (the git error, the hash-mismatch note, …), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The result of a [`revert`]: a per-file outcome list. Inspect
/// [`RevertReport::applied`] / [`skipped`](RevertReport::skipped) /
/// [`refused`](RevertReport::refused) for counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevertReport {
    /// The session that was reverted.
    pub session_id: String,
    /// Per-file outcomes, in the order the actions were recorded.
    pub files: Vec<RevertOutcome>,
}

impl RevertReport {
    /// Count of files actually restored.
    #[must_use]
    pub fn applied(&self) -> usize {
        self.count(RevertDisposition::Applied)
    }

    /// Count of `revert_safe = false` actions skipped (no preimage).
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.count(RevertDisposition::SkippedNotSafe)
    }

    /// Count of files refused (hash mismatch, missing post-hash, or git error).
    #[must_use]
    pub fn refused(&self) -> usize {
        self.files
            .iter()
            .filter(|f| {
                matches!(
                    f.disposition,
                    RevertDisposition::RefusedHashMismatch
                        | RevertDisposition::RefusedNoPostHash
                        | RevertDisposition::RefusedGitError
                )
            })
            .count()
    }

    fn count(&self, want: RevertDisposition) -> usize {
        self.files.iter().filter(|f| f.disposition == want).count()
    }
}

/// A recorded `agent_actions` row, as read back for revert. Only the columns
/// revert needs (the diff body is never re-applied — git HEAD is the preimage).
struct RevertAction {
    kind: String,
    path: Option<String>,
    post_hash: Option<String>,
    revert_safe: bool,
}

/// Reverse the file changes of a session, restoring from **git HEAD** — but only
/// for actions the wrapper marked `revert_safe = true` (clean tree at start, so
/// HEAD *is* the preimage). This never reads or trusts a logbook-stored diff body
/// to reconstruct content; the redacted diff cannot exactly restore bytes, so
/// revert relies on the user's own git history instead.
///
/// For each `revert_safe` action, in recorded order:
/// 1. **Verify** the file still matches its recorded `post_hash` — recomputed via
///    [`wrapper::redacted_content_hash`] (the same redacted-content hashing the
///    wrapper used at capture). If it diverged, **refuse** (the user edited it
///    since) — [`RevertDisposition::RefusedHashMismatch`].
/// 2. **Restore**: `file_modified` / `file_deleted` → `git checkout HEAD -- <path>`
///    (HEAD restores the pre-session content, including re-creating a deleted
///    file); `file_added` → remove the file (HEAD has no such path).
///
/// `revert_safe = false` actions are **never touched** ([`RevertDisposition::SkippedNotSafe`]):
/// a dirty-tree session has no exact preimage, and `logbook revert` refuses them
/// by design (plan §1.2 / Phase-3 tests).
///
/// `cwd` is the repo root the session ran in (the same dir the wrapper diffed),
/// used both to recompute hashes and as git's working directory.
///
/// # Errors
/// Returns [`InventoryError::SessionNotFound`] if `session_id` has no
/// `agent_sessions` row, or a store error if the action read fails. Per-file git
/// failures are **not** returned as errors — they are recorded as
/// [`RevertDisposition::RefusedGitError`] in the report so one bad file never
/// aborts the others.
pub fn revert(store: &Store, session_id: &str, cwd: &Path) -> Result<RevertReport> {
    // The recorded `post_hash` is over whatever redactor ran at capture. The
    // recorder-on default is the general redactor seeded with the process env
    // (`Redactor::new().with_process_env()`), so we recompute with that to match a
    // normally captured session. Note the hashes match **only when the current
    // `[redaction]` deny/allow patterns + `enabled` equal what ran at capture**:
    // if the redaction rules changed since (custom deny/allow added/removed, or
    // redaction toggled), the recomputed redacted content differs and revert
    // conservatively refuses the file as a `post_hash` mismatch rather than
    // clobbering it. A session captured under `--no-redact` recorded a floor-only
    // hash; revert it via [`revert_with_redactor`] passing
    // [`Redactor::secrets_floor_with_process_env`].
    let redactor = Redactor::new().with_process_env();
    revert_with_redactor(store, session_id, cwd, &redactor)
}

/// Like [`revert`] but with an explicit `redactor` for recomputing the
/// post-state hash — so a session captured under `--no-redact` (a floor-only
/// hash) can be reverted by passing [`Redactor::secrets_floor_with_process_env`],
/// matching the redactor that ran at capture. The default [`revert`] uses the
/// general redactor (the recorder-on default).
///
/// # Errors
/// See [`revert`].
pub fn revert_with_redactor(
    store: &Store,
    session_id: &str,
    cwd: &Path,
    redactor: &Redactor,
) -> Result<RevertReport> {
    let actions = load_actions_for_revert(store, session_id)?;
    let mut files = Vec::with_capacity(actions.len());
    for action in actions {
        let path = action.path.clone().unwrap_or_default();
        let outcome = revert_one(&action, &path, cwd, redactor);
        files.push(RevertOutcome {
            path,
            kind: action.kind,
            disposition: outcome.0,
            detail: outcome.1,
        });
    }
    Ok(RevertReport {
        session_id: session_id.to_string(),
        files,
    })
}

/// Revert one action, returning its disposition + optional detail. Never panics
/// and never returns a hard error — a git failure becomes a refusal.
fn revert_one(
    action: &RevertAction,
    path: &str,
    cwd: &Path,
    redactor: &Redactor,
) -> (RevertDisposition, Option<String>) {
    // (0) Only revert_safe actions have a usable preimage (git HEAD). Anything
    // else is skipped untouched — no preimage, by design.
    if !action.revert_safe {
        return (RevertDisposition::SkippedNotSafe, None);
    }
    if path.is_empty() {
        return (
            RevertDisposition::RefusedGitError,
            Some("action has no path".to_string()),
        );
    }

    let is_deletion = action.kind == "file_deleted";

    // (1) Verify the file still matches its recorded post_hash, EXCEPT for a
    // deletion (which has no post state — the file was removed by the session, so
    // there is nothing on disk to hash; HEAD will re-create it).
    if !is_deletion {
        let Some(expected) = action.post_hash.as_deref() else {
            // A non-deletion revert_safe action with no post_hash cannot be
            // verified; refuse rather than risk clobbering newer content.
            return (
                RevertDisposition::RefusedNoPostHash,
                Some("no recorded post_hash to verify against".to_string()),
            );
        };
        match current_redacted_hash(cwd, path, redactor) {
            Some(actual) if actual == expected => { /* matches → safe to revert */ }
            Some(_) => {
                return (
                    RevertDisposition::RefusedHashMismatch,
                    Some("file changed since the session (post_hash mismatch); not reverting".to_string()),
                );
            }
            None => {
                // The recorded action says the session left content here, but the
                // file is now gone/unreadable — the user changed it. Refuse.
                return (
                    RevertDisposition::RefusedHashMismatch,
                    Some("recorded file is now missing/unreadable; not reverting".to_string()),
                );
            }
        }
    }

    // (2) Restore.
    if action.kind == "file_added" {
        // HEAD has no such path; the session created it → remove it.
        match std::fs::remove_file(cwd.join(path)) {
            Ok(()) => (RevertDisposition::Applied, None),
            // Already gone counts as reverted (idempotent).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (RevertDisposition::Applied, None),
            Err(e) => (
                RevertDisposition::RefusedGitError,
                Some(format!("could not remove added file: {e}")),
            ),
        }
    } else {
        // file_modified / file_deleted → restore the HEAD version (re-creates a
        // deleted file, reverts a modification).
        match git_checkout_head(cwd, path) {
            Ok(()) => (RevertDisposition::Applied, None),
            Err(detail) => (RevertDisposition::RefusedGitError, Some(detail)),
        }
    }
}

/// Recompute the **redacted-content** hash of the file at `cwd/path`, the same
/// way the wrapper recorded `post_hash`. Returns `None` if the file is absent or
/// unreadable. Raw bytes are read transiently and dropped inside
/// [`wrapper::redacted_content_hash`].
fn current_redacted_hash(cwd: &Path, path: &str, redactor: &Redactor) -> Option<String> {
    let raw = std::fs::read(cwd.join(path)).ok()?;
    Some(wrapper::redacted_content_hash(redactor, &raw))
}

/// `git checkout HEAD -- <path>` in `cwd`. Returns the trimmed git stderr (or a
/// spawn-error string) on failure so the caller can record it as a refusal.
fn git_checkout_head(cwd: &Path, path: &str) -> std::result::Result<(), String> {
    let out = Command::new("git")
        .args(["checkout", "HEAD", "--", path])
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Read a session's actions for revert. Errors if the session row is absent
/// (so `logbook revert typo` fails loudly rather than silently reverting nothing).
fn load_actions_for_revert(store: &Store, session_id: &str) -> Result<Vec<RevertAction>> {
    let sid = session_id.to_string();
    let rows = store.read(move |conn| {
        // Confirm the session exists first — an absent id is a user error,
        // surfaced as `None` here and mapped to a typed error by the caller (a
        // `StoreError` closure cannot itself return an `InventoryError`).
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM agent_sessions WHERE id = ?1",
                params![sid],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Ok(None);
        }
        let mut stmt = conn.prepare(
            "SELECT kind, path, post_hash, revert_safe \
             FROM agent_actions WHERE session_id = ?1 ORDER BY observed_at ASC, id ASC",
        )?;
        let mapped = stmt
            .query_map(params![sid], |r| {
                Ok(RevertAction {
                    kind: r.get(0)?,
                    path: r.get(1)?,
                    post_hash: r.get(2)?,
                    revert_safe: r.get::<_, i64>(3)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Some(mapped))
    })?;
    rows.ok_or_else(|| InventoryError::SessionNotFound(session_id.to_string()))
}

// ===========================================================================
// export_session — per-class sanitized bundle
// ===========================================================================

/// A self-contained, **per-class sanitized** export of one session (plan
/// "Orbit additions" → `logbook session export`). Built by [`export_session`]
/// with the export projection applied, so any [`SensitivityClass`] whose
/// `ClassRule.export = false` is dropped/omitted — only `model_metadata` +
/// non-payload fields leave by default. Serialize this to JSON and attach it to a
/// bug report.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExportBundle {
    /// A short schema marker so a consumer can tell sanitized bundles apart.
    pub kind: &'static str,
    /// The session header (already-redacted command line, agent, timing, exit).
    pub session: ExportedSession,
    /// Transcript **pointer** + counters (never the bulk bytes), if a transcript
    /// row exists. The transcript files themselves are redacted on disk but are
    /// `transcript`-class payload, so the bundle ships only the metadata pointer,
    /// not their contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<ExportedTranscript>,
    /// Recorded file-diff actions, sanitized: a `file_diffs`-class diff body is
    /// **omitted** (export=false by default), leaving only the path/kind/metadata.
    pub actions: Vec<ExportedAction>,
    /// The session's events with the per-class export projection applied (each
    /// event's payload-class content dropped unless that class exports).
    pub events: Vec<Event>,
}

/// The exported session header — all non-payload metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExportedSession {
    /// Session id.
    pub session_id: String,
    /// Agent name.
    pub agent: String,
    /// The already-redacted command line.
    pub command: String,
    /// Correlation trace id (hex).
    pub trace_id: Option<String>,
    /// Start time, microseconds.
    pub started_at: i64,
    /// End time, microseconds.
    pub ended_at: Option<i64>,
    /// Exit code.
    pub exit_code: Option<i64>,
}

/// A transcript **pointer** in the bundle (paths + counters only; the bytes are
/// the `transcript` payload class and stay on disk).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExportedTranscript {
    /// Path to the redacted terminal log on disk, if recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_log_path: Option<String>,
    /// Path to the ANSI-stripped cleaned text on disk, if recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_path: Option<String>,
    /// Line count, if recorded.
    pub line_count: Option<i64>,
    /// Byte size, if recorded.
    pub byte_size: Option<i64>,
}

/// A sanitized `agent_actions` row: path/kind/metadata only. The `diff` body is a
/// `file_diffs`-class payload (export=false by default) and is **omitted** unless
/// the policy exports `file_diffs`; `diff_present` records whether one existed so
/// a reader knows a (withheld) diff was captured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExportedAction {
    /// Action kind.
    pub kind: String,
    /// Affected path (already redacted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Whether a diff body was captured for this action (the body itself is
    /// omitted unless `file_diffs` exports).
    pub diff_present: bool,
    /// The redacted diff body — present **only** when the policy exports the
    /// `file_diffs` class (it does not by default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    /// Whether the action is revert-safe (metadata).
    pub revert_safe: bool,
}

/// A raw `agent_actions` row as read for export (before projection).
struct RawAction {
    kind: String,
    path: Option<String>,
    diff: Option<String>,
    revert_safe: bool,
}

/// Build a self-contained, **per-class sanitized** [`ExportBundle`] for a session
/// (plan "Orbit additions"). The projection drops/omits any class whose
/// `ClassRule.export = false` (every payload class by default; only
/// `model_metadata` exports):
///
/// - the **diff body** of each action (`file_diffs` payload) is omitted unless
///   `file_diffs.export`;
/// - the **transcript** ships as a pointer only (its bytes are `transcript`
///   payload), never inlined;
/// - each **event** is run through [`project_event_for_export`], which drops the
///   `input`/`output` payloads and the typed blocks of any non-exporting class —
///   so a metadata+prompt LLM row exports its `model_metadata` block and omits the
///   prompt, and a tool row drops its args/results.
///
/// The default [`CapturePolicy`] is the recorder-on projection (only
/// `model_metadata` exports); pass a custom policy to widen/narrow what leaves.
///
/// # Errors
/// Returns [`InventoryError::SessionNotFound`] if the session has no
/// `agent_sessions` row, or a store error if a read fails.
pub fn export_session(store: &Store, session_id: &str) -> Result<ExportBundle> {
    export_session_with_policy(store, session_id, &CapturePolicy::default())
}

/// Like [`export_session`] but with an explicit projection policy (so a caller
/// can, e.g., export `file_diffs` for an internal triage bundle). Defaults to the
/// recorder-on projection via [`export_session`].
///
/// # Errors
/// See [`export_session`].
pub fn export_session_with_policy(
    store: &Store,
    session_id: &str,
    policy: &CapturePolicy,
) -> Result<ExportBundle> {
    let sid = session_id.to_string();

    // Read header + transcript pointer + raw actions in one pass.
    let read = {
        let sid = sid.clone();
        store.read(move |conn| {
            let header = conn
                .query_row(
                    "SELECT id, agent, command, trace_id, started_at, ended_at, exit_code \
                     FROM agent_sessions WHERE id = ?1",
                    params![sid],
                    |r| {
                        Ok(ExportedSession {
                            session_id: r.get(0)?,
                            agent: r.get(1)?,
                            command: r.get(2)?,
                            trace_id: r.get(3)?,
                            started_at: r.get(4)?,
                            ended_at: r.get(5)?,
                            exit_code: r.get(6)?,
                        })
                    },
                )
                .optional()?;
            let Some(header) = header else {
                return Ok(None);
            };

            let transcript = conn
                .query_row(
                    "SELECT terminal_log_path, text_path, line_count, byte_size \
                     FROM session_transcripts WHERE session_id = ?1",
                    params![sid],
                    |r| {
                        Ok(ExportedTranscript {
                            terminal_log_path: r.get(0)?,
                            text_path: r.get(1)?,
                            line_count: r.get(2)?,
                            byte_size: r.get(3)?,
                        })
                    },
                )
                .optional()?;

            let mut stmt = conn.prepare(
                "SELECT kind, path, diff, revert_safe \
                 FROM agent_actions WHERE session_id = ?1 ORDER BY observed_at ASC, id ASC",
            )?;
            let actions = stmt
                .query_map(params![sid], |r| {
                    Ok(RawAction {
                        kind: r.get(0)?,
                        path: r.get(1)?,
                        diff: r.get(2)?,
                        revert_safe: r.get::<_, i64>(3)? != 0,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            Ok(Some((header, transcript, actions)))
        })?
    };

    let Some((session, transcript, raw_actions)) = read else {
        return Err(InventoryError::SessionNotFound(sid));
    };

    // The session's events under the shared trace (oldest-first), then projected.
    let events = match session.trace_id.as_deref() {
        Some(trace) => store.trace(trace)?,
        None => Vec::new(),
    };
    let events = events
        .into_iter()
        .map(|ev| project_event_for_export(ev, policy))
        .collect();

    // Project actions: omit the file_diffs body unless that class exports.
    let export_diffs = policy.rule(SensitivityClass::FileDiffs).export;
    let actions = raw_actions
        .into_iter()
        .map(|a| ExportedAction {
            kind: a.kind,
            path: a.path,
            diff_present: a.diff.is_some(),
            diff: if export_diffs { a.diff } else { None },
            revert_safe: a.revert_safe,
        })
        .collect();

    Ok(ExportBundle {
        kind: "logbook.session.export.v1",
        session,
        transcript,
        actions,
        events,
    })
}

/// Apply the per-class export projection to one event: drop **all** payload
/// (`input` / `output` / `error` / non-allowlisted `attributes`) and the typed
/// domain block of any [`SensitivityClass`] that does not export, leaving only the
/// event's structural metadata (ids, timing, kind/category/op/name, status) plus a
/// strict non-payload attribute allowlist and any exporting block intact.
///
/// **Why `error`, `name`, `input`, `output`, and `attributes` are all scrubbed for
/// a non-exporting class:** any of them can carry payload. `input`/`output` are the
/// raw prompt/tool/diff bytes; `error` can echo a tool result or a model
/// completion; `name` can be set to a prompt/argument by an OTLP/harness ingester;
/// and `attributes` is a free-form bag that ingesters fill with prompts,
/// completions, tool results, file contents, or OTLP span attributes. So for a
/// payload-bearing class the projection keeps **none** of them — only a small
/// allowlist of provenance/structural attribute keys (see
/// [`ATTR_EXPORT_ALLOWLIST`]) survives, and `name` is reset to the (non-payload)
/// `operation` verb.
///
/// The dominant-class decision mirrors `schema::max_sensitivity_for` (the same
/// block-first resolution the retention column uses), so export is consistent with
/// how the row is classified for retention:
/// - a **tool** block is `tool_args` (no output) / `tool_results` (with output) —
///   both default export=false → the block + all payload are dropped;
/// - an **llm** block is `prompts` when it carries an input/output payload, else
///   `model_metadata` — a metadata-only LLM block (no payload) **exports** (the one
///   class that does) and keeps its `attributes`/`error`; a prompt-bearing LLM row
///   is a non-exporting `prompts` row, so it drops its payload/`error`/attributes
///   and downgrades to the metadata-only `model_metadata` block (kept only if that
///   class exports);
/// - `console`/`network` blocks are `browser_data`/`transcript`-class context and
///   are dropped with all payload unless that class exports;
/// - an **agent step / bare log** is `transcript`-class; its payload drops unless
///   transcript exports, but the agent block (turn/step/role metadata) is retained
///   so the turn tree survives;
/// - a **finding** block (NULL class — a security/inventory record, already
///   redacted) is structural and is always retained with its `attributes`/`error`.
#[must_use]
pub fn project_event_for_export(mut ev: Event, policy: &CapturePolicy) -> Event {
    // The dominant/most-sensitive class of the row (block-first, mirroring
    // `schema::max_sensitivity_for`). `None` = a structural row with no payload
    // class (finding/test/inventory) — treated as exporting (nothing to scrub).
    let dominant = dominant_export_class(&ev);
    let dominant_exports = dominant.map_or(true, |c| policy.rule(c).export);

    // ---- drop the typed domain block of a non-exporting class ------------
    let exports = |c: SensitivityClass| policy.rule(c).export;
    if ev.blocks.tool.is_some() {
        let class = if ev.output.is_some() {
            SensitivityClass::ToolResults
        } else {
            SensitivityClass::ToolArgs
        };
        if !exports(class) {
            ev.blocks.tool = None;
        }
    } else if ev.blocks.llm.is_some() {
        // The metadata block that remains after the payload is dropped is
        // model_metadata-class; keep it only if that class exports.
        if !exports(SensitivityClass::ModelMetadata) {
            ev.blocks.llm = None;
        }
    } else if ev.blocks.console.is_some() || ev.blocks.network.is_some() {
        let class = match ev.category {
            logbook_core::Category::Browser => SensitivityClass::BrowserData,
            _ => SensitivityClass::Transcript,
        };
        if !exports(class) {
            ev.blocks.console = None;
            ev.blocks.network = None;
        }
    }
    // The agent block (turn/step/role metadata) and a finding block carry no
    // class payload and are always retained.

    // ---- strict payload scrub for a non-exporting dominant class ---------
    // Drop EVERY payload-bearing field, since any of them can carry a leak:
    // input/output (prompt/tool/diff bytes), error (echoed result/completion),
    // name (an OTLP/harness ingester can set it to a prompt/argument), and all
    // attributes except the non-payload provenance/structural allowlist.
    if !dominant_exports {
        ev.input = None;
        ev.output = None;
        ev.error = None;
        // status/error must stay coherent (Event::validate): an Error status with
        // no message would be rejected, so downgrade the status to Ok once the
        // (possibly payload-bearing) error text is dropped.
        if ev.status == Status::Error {
            ev.status = Status::Ok;
        }
        // `name` defaults to the type/op verb but can be overwritten with payload
        // by an ingester; reset it to the (non-payload) operation verb.
        ev.name = ev.operation.clone();
        ev.attributes = filter_export_attributes(std::mem::take(&mut ev.attributes));
    }
    ev
}

/// The non-payload attribute keys allowed to survive the export projection for a
/// non-exporting class. These are provenance / structural / correlation markers an
/// ingester or the recorder sets — never user/model payload. Any key ending in
/// `_truncated` (a body-cap flag, e.g. `diff_truncated`) is also kept; everything
/// else is dropped.
const ATTR_EXPORT_ALLOWLIST: &[&str] = &[
    "source",
    "harness",
    "harness_version",
    "turn",
    "tool_call_id",
    "mcp_request_id",
    "status",
];

/// Keep only the non-payload allowlisted attribute keys (plus any `*_truncated`
/// body-cap flag); drop everything else (which may carry prompt/tool/diff/OTLP
/// payload an ingester stuffed into the free-form bag).
fn filter_export_attributes(
    attrs: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    attrs
        .into_iter()
        .filter(|(k, _)| ATTR_EXPORT_ALLOWLIST.contains(&k.as_str()) || k.ends_with("_truncated"))
        .collect()
}

/// The dominant (most-sensitive) [`SensitivityClass`] of an event, block-first,
/// mirroring `schema::max_sensitivity_for` so the export decision is consistent
/// with the retention classification. `None` = a structural row with no payload
/// class (security/inventory/test finding), which the projection treats as
/// exporting (it has nothing to scrub).
fn dominant_export_class(ev: &Event) -> Option<SensitivityClass> {
    use logbook_core::{Category, Kind};
    if ev.blocks.tool.is_some() {
        return Some(if ev.output.is_some() {
            SensitivityClass::ToolResults
        } else {
            SensitivityClass::ToolArgs
        });
    }
    if ev.blocks.llm.is_some() {
        return Some(if ev.input.is_some() || ev.output.is_some() {
            SensitivityClass::Prompts
        } else {
            SensitivityClass::ModelMetadata
        });
    }
    match ev.category {
        Category::Browser => Some(SensitivityClass::BrowserData),
        Category::AppLog | Category::Agent => Some(SensitivityClass::Transcript),
        Category::CodeTest | Category::Security | Category::Inventory => match ev.kind {
            Kind::Browser | Kind::Log => Some(SensitivityClass::Transcript),
            _ => None,
        },
    }
}

// ===========================================================================
// forget — store deletion + on-disk transcript/sessions-dir removal
// ===========================================================================

/// What [`forget`] removed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ForgetReport {
    /// Events deleted from the store.
    pub events: u64,
    /// `agent_sessions` rows deleted (their actions/transcripts cascade).
    pub agent_sessions: u64,
    /// On-disk transcript files removed (terminal log + cleaned text).
    pub files_removed: u64,
    /// `<out_dir>/sessions/<id>/` directories removed.
    pub dirs_removed: u64,
}

/// A `logbook forget` target: a single session id, or everything before a
/// microsecond cut-off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgetTarget {
    /// `logbook forget <session>` — one session by id.
    Session(String),
    /// `logbook forget --before <micros>` — everything older than `micros`.
    Before(i64),
}

/// Forget a session (or everything before a cut-off): a thin wrapper over the
/// store forget helpers ([`Store::forget_session`] / [`Store::forget_before`])
/// that **also** removes the on-disk artifacts the store does not own — the
/// session's redacted transcript files and any `<out_dir>/sessions/<id>/`
/// directory (where the `--reversible` opt-in would write encrypted preimages).
///
/// On-disk cleanup runs **before** the store delete (so the transcript pointers
/// are still readable to locate the files), and is best-effort: a missing file/dir
/// is not an error (idempotent). The `--before` case now **also** cleans on-disk
/// artifacts: it enumerates the sessions older than the cut-off (by `started_at`),
/// removes each one's transcript files + `<out_dir>/sessions/<id>/` dir (via the
/// same containment-checked helpers as the by-id path), then deletes the store
/// rows. The encrypted-preimage purge for a time range is also `prune`'s job (plan
/// §3); this removal covers the redacted transcripts + per-session dirs the store
/// does not own.
///
/// Every on-disk removal is containment-checked (canonicalized + asserted within
/// `<out_dir>`), and the by-id path additionally validates the id shape and only
/// removes the per-session dir when the session actually exists in the store.
///
/// # Errors
/// Returns [`InventoryError::InvalidSessionId`] if a by-id target is not a
/// well-formed session id, or a store error if a delete fails.
pub fn forget(store: &Store, target: ForgetTarget, out_dir: &Path) -> Result<ForgetReport> {
    match target {
        ForgetTarget::Session(session_id) => forget_session(store, &session_id, out_dir),
        ForgetTarget::Before(micros) => forget_before(store, micros, out_dir),
    }
}

/// Whether `session_id` is a well-formed session id: a non-empty 32-character
/// lowercase-hex string (the exact shape [`logbook_core::SessionId::generate`]
/// mints via `TraceId::to_hex`), with **no** path separator (`/` or `\`), no `..`
/// component, and not absolute. This is the strict guard `forget` applies before
/// any filesystem deletion so a crafted id (`../../..`, an absolute path, a
/// `sessions/..`-style id) can never be joined onto `<out_dir>/sessions/` and reach
/// `remove_dir_all` outside the out-dir.
///
/// The hex-shape requirement makes the check allowlist-based (only known-good ids
/// pass) rather than blocklist-based, so it is robust to separators or traversal
/// tokens this code did not think to enumerate.
#[must_use]
pub fn is_valid_session_id(session_id: &str) -> bool {
    use logbook_core::TraceId;
    // Exactly the generated width, all lowercase hex. This already excludes the
    // empty string, any `/`/`\` separator, `.`/`..`, and absolute paths (none of
    // which are hex), but we keep the explicit traversal/separator rejections too
    // as defense-in-depth + documentation of intent.
    if session_id.len() != TraceId::HEX_LEN {
        return false;
    }
    if session_id.contains('/') || session_id.contains('\\') {
        return false;
    }
    if session_id
        .split(['/', '\\'])
        .any(|c| c == "..")
    {
        return false;
    }
    if Path::new(session_id).is_absolute() {
        return false;
    }
    // Lowercase hex only — exactly what `TraceId::to_hex` emits (uppercase A-F is
    // rejected, since `generate()` never produces it).
    session_id
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Forget one session by id + remove its on-disk transcript files and
/// `<out_dir>/sessions/<id>/` dir.
fn forget_session(store: &Store, session_id: &str, out_dir: &Path) -> Result<ForgetReport> {
    // (0) Reject a malformed id BEFORE any filesystem touch. A crafted id like
    // `../../..` (or an absolute path) must never be joined onto
    // `<out_dir>/sessions/` and reach `remove_dir_all`.
    if !is_valid_session_id(session_id) {
        return Err(InventoryError::InvalidSessionId(session_id.to_string()));
    }

    // (1) Locate the on-disk transcript files via the (still-present) pointer row
    // BEFORE deleting the DB rows. Each path is containment-checked against
    // <out_dir> (a DB-sourced path is not implicitly trusted).
    let transcript = load_transcript_pointer(store, session_id)?;
    let mut files_removed = 0u64;
    if let Some(t) = transcript {
        for path in [t.terminal_log_path.as_deref(), t.text_path.as_deref()]
            .into_iter()
            .flatten()
        {
            if remove_transcript_file_scoped(Path::new(path), out_dir) {
                files_removed += 1;
            }
        }
    }

    // (2) Remove the session's dedicated dir, if any (the `--reversible`
    // encrypted-preimage location, `<out_dir>/sessions/<id>/`), but ONLY when the
    // session actually exists in the store — so a (validated) id for a session we
    // never captured does not delete an unrelated `<out_dir>/sessions/<id>/` tree.
    // The removal is additionally containment-checked.
    let mut dirs_removed = 0u64;
    if session_exists(store, session_id)? {
        let sess_dir = out_dir.join("sessions").join(session_id);
        if remove_session_dir_scoped(&sess_dir, out_dir) {
            dirs_removed += 1;
        }
    }

    // (3) Delete the store rows (events + agent_sessions; actions/transcripts
    // cascade).
    let stats = store.forget_session(session_id)?;

    Ok(ForgetReport {
        events: stats.events,
        agent_sessions: stats.agent_sessions,
        files_removed,
        dirs_removed,
    })
}

/// Forget everything before a cut-off + clean the affected sessions' on-disk
/// artifacts (transcript files + `<out_dir>/sessions/<id>/` dirs), then delete the
/// store rows. Closes the gap where the `--before` arm dropped DB rows but left
/// the redacted transcripts + per-session dirs on disk.
///
/// On-disk removal reuses the same containment-checked helpers as the by-id path,
/// so a stray DB transcript path can never delete outside `<out_dir>` and only a
/// valid-shaped session id is joined onto `<out_dir>/sessions/`.
fn forget_before(store: &Store, micros: i64, out_dir: &Path) -> Result<ForgetReport> {
    // (1) Enumerate the sessions older than the cut-off, with their transcript
    // pointers, BEFORE the store delete (the rows are still present to read).
    let affected = load_sessions_before(store, micros)?;

    let mut files_removed = 0u64;
    let mut dirs_removed = 0u64;
    for sess in &affected {
        for path in [
            sess.terminal_log_path.as_deref(),
            sess.text_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if remove_transcript_file_scoped(Path::new(path), out_dir) {
                files_removed += 1;
            }
        }
        // Only join + remove a dir for a well-formed id (defense-in-depth: ids
        // come from our own store, but a corrupt/imported row must not traverse).
        if is_valid_session_id(&sess.session_id) {
            let sess_dir = out_dir.join("sessions").join(&sess.session_id);
            if remove_session_dir_scoped(&sess_dir, out_dir) {
                dirs_removed += 1;
            }
        }
    }

    // (2) Delete the store rows.
    let stats = store.forget_before(micros)?;

    Ok(ForgetReport {
        events: stats.events,
        agent_sessions: stats.agent_sessions,
        files_removed,
        dirs_removed,
    })
}

/// Whether an `agent_sessions` row exists for `session_id` (so `forget` only
/// removes the per-session dir for a session we actually captured).
fn session_exists(store: &Store, session_id: &str) -> Result<bool> {
    let sid = session_id.to_string();
    let exists = store.read(move |conn| {
        let row: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM agent_sessions WHERE id = ?1",
                params![sid],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row.is_some())
    })?;
    Ok(exists)
}

/// A session id + its transcript pointer, enumerated for a `--before` purge.
struct SessionForgetTarget {
    session_id: String,
    terminal_log_path: Option<String>,
    text_path: Option<String>,
}

/// Load `(id, terminal_log_path, text_path)` for every session older than `micros`
/// (left-joined to its transcript pointer), so `forget --before` can clean each
/// one's on-disk artifacts before deleting the rows.
fn load_sessions_before(store: &Store, micros: i64) -> Result<Vec<SessionForgetTarget>> {
    let targets = store.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT s.id, t.terminal_log_path, t.text_path \
             FROM agent_sessions s \
             LEFT JOIN session_transcripts t ON t.session_id = s.id \
             WHERE s.started_at < ?1",
        )?;
        let rows = stmt
            .query_map(params![micros], |r| {
                Ok(SessionForgetTarget {
                    session_id: r.get(0)?,
                    terminal_log_path: r.get(1)?,
                    text_path: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })?;
    Ok(targets)
}

/// Load the transcript pointer row (paths only) for on-disk cleanup. `None` when
/// the session has no transcript row.
fn load_transcript_pointer(
    store: &Store,
    session_id: &str,
) -> Result<Option<SessionTranscriptRecord>> {
    let sid = session_id.to_string();
    let rec = store.read(move |conn| {
        let row = conn
            .query_row(
                "SELECT session_id, trace_id, terminal_log_path, text_path, \
                        line_count, byte_size, max_sensitivity \
                 FROM session_transcripts WHERE session_id = ?1",
                params![sid],
                |r| {
                    Ok(SessionTranscriptRecord {
                        session_id: r.get(0)?,
                        trace_id: r.get(1)?,
                        terminal_log_path: r.get(2)?,
                        text_path: r.get(3)?,
                        line_count: r.get(4)?,
                        byte_size: r.get(5)?,
                        max_sensitivity: r.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    })?;
    Ok(rec)
}

/// Whether `candidate` resolves to a path **inside** `out_dir`, comparing
/// canonicalized forms so `..` / symlinks cannot escape. Used to fence every
/// `forget` on-disk removal to the out-dir.
///
/// `out_dir` is canonicalized (it must exist — it is logbook's own store dir). The
/// candidate's **parent** is canonicalized (the candidate itself may have just
/// been removed or may not exist; its parent is what bounds it), then the resolved
/// candidate (`canonical_parent/<file_name>`) is checked with `starts_with` against
/// the canonical out-dir. Returns `false` (refuse) on any canonicalization failure
/// or a candidate with no file name — fail-closed, never delete on doubt.
fn is_within_out_dir(candidate: &Path, out_dir: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(out_dir) else {
        return false;
    };
    let Some(parent) = candidate.parent() else {
        return false;
    };
    let Some(file_name) = candidate.file_name() else {
        return false;
    };
    // Canonicalize the parent (resolves `..`/symlinks in the directory chain),
    // then re-attach the final component so we test the real resolved location
    // without requiring the candidate itself to still exist.
    let Ok(canon_parent) = std::fs::canonicalize(parent) else {
        return false;
    };
    let resolved = canon_parent.join(file_name);
    resolved.starts_with(&root)
}

/// Remove a DB-sourced transcript file, returning whether it was actually removed.
/// The path is **containment-checked** against `out_dir` first: a path outside the
/// out-dir (a stray/hostile DB row) is skipped with a warning, never unlinked. A
/// missing file is not an error (idempotent forget).
fn remove_transcript_file_scoped(path: &Path, out_dir: &Path) -> bool {
    if !is_within_out_dir(path, out_dir) {
        tracing::warn!(
            path = %path.display(),
            out_dir = %out_dir.display(),
            "forget: refusing to remove transcript file outside out_dir"
        );
        return false;
    }
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "forget: could not remove transcript file");
            false
        }
    }
}

/// Remove a session's `<out_dir>/sessions/<id>/` dir tree, returning whether it was
/// actually removed. Defense-in-depth: even though the path is built from a
/// validated id, it is **containment-checked** against `out_dir` before
/// `remove_dir_all`. A missing dir is not an error (idempotent forget).
fn remove_session_dir_scoped(path: &Path, out_dir: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if !is_within_out_dir(path, out_dir) {
        tracing::warn!(
            path = %path.display(),
            out_dir = %out_dir.display(),
            "forget: refusing to remove session dir outside out_dir"
        );
        return false;
    }
    match std::fs::remove_dir_all(path) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "forget: could not remove session dir");
            false
        }
    }
}

// ===========================================================================
// session_diffs_up_to_turn — review-only cumulative time-travel view
// ===========================================================================

/// A review-only "time-travel" view of a session's **redacted** diffs up to a
/// turn (plan "Orbit additions" → "workspace time-travel").
///
/// **What this is:** the cumulative set of redacted per-file diffs the session
/// recorded *up to and including* turn N, as a review aid ("show me what the
/// agent had changed by turn 3"). The diffs are the same redacted start→end
/// content diffs the wrapper persisted — already safe to display.
///
/// **What this is NOT (documented honestly):** an exact byte-level
/// reconstruction of the repo at turn N. logbook never persists raw preimages by
/// default (plan §1.2), so the redacted diff cannot losslessly rebuild file
/// content. Exact reconstruction needs the `--reversible` encrypted preimage
/// chain, which is **not yet available** (key management pending — see
/// [`InventoryError::ReversibleUnavailable`]). [`SessionTurnDiffs::reconstructable`]
/// is therefore always `false` until that lands.
///
/// **Turn attribution:** an `agent_actions` row has no `turn` column (file diffs
/// are computed once at session teardown, not per turn). To attribute diffs to a
/// turn we use the correlation timeline: diffs whose recorded `observed_at`
/// falls at or before the **end** of turn N's event span are "up to turn N". When
/// the session has no turn-stamped events (the common Phase-1 case — diffs are a
/// teardown snapshot), every diff is attributed to the (single) final state, so
/// `up_to_turn(last)` returns them all and earlier turns return the empties.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionTurnDiffs {
    /// The session id.
    pub session_id: String,
    /// The turn the view was taken at (inclusive).
    pub turn: i64,
    /// The cumulative redacted per-file diffs up to `turn`, in path order.
    pub diffs: Vec<TurnFileDiff>,
    /// Whether an **exact** content reconstruction is possible (always `false`
    /// until the `--reversible` encrypted preimage chain ships). A reviewer
    /// should treat `diffs` as a redacted summary, not a restorable snapshot.
    pub reconstructable: bool,
}

/// One file's redacted diff in a [`SessionTurnDiffs`] view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TurnFileDiff {
    /// The affected path (already redacted).
    pub path: Option<String>,
    /// The action kind.
    pub kind: String,
    /// The redacted diff body, if one was captured (omitted for over-cap files).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

/// Build the cumulative redacted-diff view up to (and including) `turn` for a
/// session (a review-only time-travel view; see [`SessionTurnDiffs`] for the
/// honest caveat that this is **not** an exact reconstruction).
///
/// The turn cut-off is resolved from the session's correlation timeline
/// ([`Store::session_tree`]): we find the latest event timestamp belonging to a
/// turn `<= turn`, and include every `agent_actions` row whose `observed_at` is
/// at or before that cut-off. With no turn-stamped events, the cut-off is the end
/// of time (all diffs are the final teardown snapshot), so `up_to_turn(N)` for an
/// N at/above the max present returns the full redacted diff set.
///
/// # Errors
/// Returns [`InventoryError::SessionNotFound`] if the session has no
/// `agent_sessions` row, or a store error if a read fails.
pub fn session_diffs_up_to_turn(
    store: &Store,
    session_id: &str,
    turn: i64,
) -> Result<SessionTurnDiffs> {
    // Resolve the inclusive timestamp cut-off for `turn` from the timeline.
    let cutoff = turn_cutoff_micros(store, session_id, turn)?;

    let sid = session_id.to_string();
    let diffs = store.read(move |conn| {
        // Confirm the session exists (loud failure on a typo).
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM agent_sessions WHERE id = ?1",
                params![sid],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Ok(None);
        }
        let mut stmt = conn.prepare(
            "SELECT kind, path, diff FROM agent_actions \
             WHERE session_id = ?1 AND observed_at <= ?2 \
             ORDER BY path ASC, kind ASC",
        )?;
        let rows = stmt
            .query_map(params![sid, cutoff], |r| {
                Ok(TurnFileDiff {
                    kind: r.get(0)?,
                    path: r.get(1)?,
                    diff: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Some(rows))
    })?;

    let diffs = diffs.ok_or_else(|| InventoryError::SessionNotFound(session_id.to_string()))?;

    Ok(SessionTurnDiffs {
        session_id: session_id.to_string(),
        turn,
        diffs,
        // Exact reconstruction needs the not-yet-available encrypted preimage.
        reconstructable: false,
    })
}

/// Resolve the inclusive `observed_at` cut-off (microseconds) for "up to turn N":
/// the maximum event timestamp across all turn groups with `turn <= N`. Returns
/// [`i64::MAX`] when the session has no turn-stamped events (so all teardown diffs
/// are included), and also when `turn` is at/above the max present.
fn turn_cutoff_micros(store: &Store, session_id: &str, turn: i64) -> Result<i64> {
    let tree = store.session_tree(session_id)?;
    // Collect the max timestamp among groups whose turn index is <= the target.
    // The turn-less (None) group is the teardown/uncategorized bucket; it always
    // counts toward the final state.
    let mut cutoff: Option<i64> = None;
    let mut saw_stamped_turn = false;
    for group in &tree.turns {
        let include = match group.turn {
            Some(t) => {
                saw_stamped_turn = true;
                t <= turn
            }
            // Turn-less events (tool/log/finding without a stamped turn, plus the
            // teardown snapshot) are part of the running state.
            None => true,
        };
        if include {
            for ev in &group.events {
                let ts = ev.timestamp.as_micros();
                cutoff = Some(cutoff.map_or(ts, |c| c.max(ts)));
            }
        }
    }
    // If no turn was ever stamped, diffs are a single teardown snapshot — include
    // everything (cut-off = end of time). Likewise if the requested turn is at/above
    // the max and there were turn-stamped events, the cut-off naturally covers them.
    if !saw_stamped_turn {
        return Ok(i64::MAX);
    }
    Ok(cutoff.unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    // `super::*` already brings in `Command`, `params`, `Path`, `Redactor`,
    // `Store`, the error type, and the governance items under test.
    use super::*;
    use logbook_core::{
        AgentBlock, Category, Kind, LlmBlock, MicrosTimestamp, SessionId, ToolBlock, TraceId,
    };

    /// The exact redactor [`revert`] recomputes hashes with (general redactor +
    /// process env). Seeding recorded `post_hash`es with this guarantees parity
    /// regardless of the test host's environment.
    fn revert_red() -> Redactor {
        Redactor::new().with_process_env()
    }

    // ---- git repo helpers (mirror wrapper.rs tests) ----------------------

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

    /// Insert an `agent_sessions` row + its `agent_actions`.
    #[allow(clippy::type_complexity)]
    fn seed_session_with_actions(
        store: &Store,
        session_id: &str,
        trace: &TraceId,
        actions: &[(&str, &str, Option<&str>, Option<&str>, bool, i64)], // kind, path, diff, post_hash, revert_safe, observed_at
    ) {
        let sid = session_id.to_string();
        let trace_hex = trace.to_hex();
        let acts: Vec<_> = actions
            .iter()
            .map(|(k, p, d, h, rs, at)| {
                (
                    k.to_string(),
                    p.to_string(),
                    d.map(str::to_string),
                    h.map(str::to_string),
                    *rs,
                    *at,
                )
            })
            .collect();
        store
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO agent_sessions (id, agent, command, trace_id, started_at) \
                     VALUES (?1, 'sh', 'sh -c', ?2, 100)",
                    params![sid, trace_hex],
                )?;
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare(
                        "INSERT INTO agent_actions \
                         (id, session_id, kind, path, observed_at, diff, post_hash, revert_safe, max_sensitivity) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'file_diffs')",
                    )?;
                    for (i, (kind, path, diff, hash, rs, at)) in acts.iter().enumerate() {
                        stmt.execute(params![
                            format!("act-{i}"),
                            sid,
                            kind,
                            path,
                            at,
                            diff,
                            hash,
                            i64::from(*rs),
                        ])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .unwrap();
    }

    // ---- revert ----------------------------------------------------------

    #[test]
    fn revert_restores_clean_tree_session() {
        // A clean-tree session that modified a tracked file + added a new file.
        // Revert must restore the modified file to HEAD and remove the added file.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        init_repo(cwd);
        std::fs::write(cwd.join("tracked.txt"), "original\n").unwrap();
        commit_all(cwd); // HEAD = "original"

        // Simulate the post-session state: tracked.txt modified, added.txt created.
        std::fs::write(cwd.join("tracked.txt"), "session-edit\n").unwrap();
        std::fs::write(cwd.join("added.txt"), "new file\n").unwrap();

        // The recorded post_hash must match what the wrapper would have stored:
        // the redacted-content hash of the END content (computed with the same
        // redactor `revert` recomputes with, so parity holds on any host).
        let tracked_hash = wrapper::redacted_content_hash(&revert_red(), b"session-edit\n");
        let added_hash = wrapper::redacted_content_hash(&revert_red(), b"new file\n");

        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        seed_session_with_actions(
            &store,
            "sess-revert",
            &trace,
            &[
                ("file_modified", "tracked.txt", Some("@@\n-original\n+session-edit"), Some(&tracked_hash), true, 110),
                ("file_added", "added.txt", Some("@@\n+new file"), Some(&added_hash), true, 120),
            ],
        );

        let report = revert(&store, "sess-revert", cwd).unwrap();
        assert_eq!(report.applied(), 2, "both files restored: {report:?}");
        assert_eq!(report.refused(), 0);
        assert_eq!(report.skipped(), 0);

        // tracked.txt is back to HEAD; added.txt is gone.
        assert_eq!(std::fs::read_to_string(cwd.join("tracked.txt")).unwrap(), "original\n");
        assert!(!cwd.join("added.txt").exists(), "added file removed");
    }

    #[test]
    fn revert_refuses_when_post_hash_diverged() {
        // The recorded post_hash is for "session-edit", but the user has since
        // changed the file to "user-changed". Revert must REFUSE (not clobber).
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        init_repo(cwd);
        std::fs::write(cwd.join("f.txt"), "original\n").unwrap();
        commit_all(cwd);

        // The user edited the file AFTER the session left "session-edit".
        std::fs::write(cwd.join("f.txt"), "user-changed-since\n").unwrap();
        let session_post_hash = wrapper::redacted_content_hash(&revert_red(), b"session-edit\n");

        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        seed_session_with_actions(
            &store,
            "sess-diverged",
            &trace,
            &[("file_modified", "f.txt", Some("@@\n-original\n+session-edit"), Some(&session_post_hash), true, 110)],
        );

        let report = revert(&store, "sess-diverged", cwd).unwrap();
        assert_eq!(report.applied(), 0, "must not apply a diverged file");
        assert_eq!(report.refused(), 1, "diverged file refused");
        assert_eq!(report.files[0].disposition, RevertDisposition::RefusedHashMismatch);
        // The user's content is UNTOUCHED — revert clobbered nothing.
        assert_eq!(
            std::fs::read_to_string(cwd.join("f.txt")).unwrap(),
            "user-changed-since\n",
            "revert must not overwrite a diverged file"
        );
    }

    #[test]
    fn revert_skips_non_revert_safe_actions() {
        // A revert_safe=false action (dirty-tree session) must be skipped entirely
        // — never touched, regardless of the file's current state.
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        init_repo(cwd);
        std::fs::write(cwd.join("dirty.txt"), "current\n").unwrap();
        // Note: NOT committed → and the action is marked revert_safe=false anyway.

        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        seed_session_with_actions(
            &store,
            "sess-dirty",
            &trace,
            &[("file_modified", "dirty.txt", Some("@@ redacted"), Some("anyhash"), false, 110)],
        );

        let report = revert(&store, "sess-dirty", cwd).unwrap();
        assert_eq!(report.skipped(), 1, "revert_safe=false ⇒ skipped");
        assert_eq!(report.applied(), 0);
        assert_eq!(report.refused(), 0);
        assert_eq!(report.files[0].disposition, RevertDisposition::SkippedNotSafe);
        // The file is untouched.
        assert_eq!(std::fs::read_to_string(cwd.join("dirty.txt")).unwrap(), "current\n");
    }

    #[test]
    fn revert_unknown_session_errors() {
        let store = Store::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = revert(&store, "ghost", tmp.path()).unwrap_err();
        assert!(matches!(err, InventoryError::SessionNotFound(_)), "got {err:?}");
    }

    // ---- export ----------------------------------------------------------

    #[test]
    fn export_omits_payload_classes() {
        // The default projection (recorder-on) exports only model_metadata. A
        // session with: a prompt-bearing LLM event, a tool event with output, an
        // agent step, and a file_diffs action must export NONE of the raw
        // prompt/diff/tool payloads — only the redacted metadata projection.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-export");

        // Seed the session header + a file_diffs action carrying a (redacted) diff.
        seed_session_with_actions(
            &store,
            "sess-export",
            &trace,
            &[("file_modified", "code.rs", Some("@@\n-old\n+new SECRETLINE"), Some("h"), true, 110)],
        );

        // A prompt-bearing LLM event (payload = the prompt) under the shared trace.
        let mut llm = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_session(sess.clone())
            .with_llm(LlmBlock {
                provider: Some("anthropic".into()),
                model: Some("claude".into()),
                input_tokens: Some(10),
                ..Default::default()
            });
        llm.input = Some(serde_json::json!("the secret system prompt"));
        llm.output = Some(serde_json::json!("the model reply"));
        llm.timestamp = MicrosTimestamp(120);
        store.insert(&llm).unwrap();

        // A tool event with a result payload, plus payload smuggled into the
        // OTHER payload-bearing fields a non-exporting class must also scrub:
        // `error` (an echoed result), `name` (an ingester-set value), and a
        // free-form `attributes` entry (the OTLP/harness leak surface). A
        // non-payload `source` attribute is kept (allowlist), proving the filter
        // is selective, not a blanket wipe.
        let mut tool = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_session(sess.clone())
            .with_attr("source", "mcp")
            .with_attr("otlp_prompt_attr", "ATTRLEAK file contents")
            .with_tool(ToolBlock {
                tool_name: Some("read_file".into()),
                arguments: Some(serde_json::json!({"path": "/etc/passwd"})),
                ..Default::default()
            });
        tool.output = Some(serde_json::json!("file contents leak"));
        tool.error = Some("ERRLEAK secret from a tool error".to_string());
        tool.status = Status::Error;
        tool.name = "NAMELEAK prompt text".to_string();
        tool.timestamp = MicrosTimestamp(130);
        store.insert(&tool).unwrap();

        // An agent step (transcript-class) carrying turn metadata.
        let agent = Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_session(sess.clone())
            .with_agent(AgentBlock {
                agent: Some("claude".into()),
                turn: Some(0),
                ..Default::default()
            });
        store.insert(&agent).unwrap();

        let bundle = export_session(&store, "sess-export").unwrap();
        let json = serde_json::to_string(&bundle).unwrap();

        // (1) The file_diffs body is omitted (export=false) — its content gone.
        assert!(bundle.actions[0].diff.is_none(), "diff body must be omitted");
        assert!(bundle.actions[0].diff_present, "but a diff was recorded");
        assert!(!json.contains("SECRETLINE"), "diff payload leaked: {json}");

        // (2) The prompt payload is dropped from the LLM event; metadata survives.
        let llm_ev = bundle
            .events
            .iter()
            .find(|e| e.kind == Kind::Llm)
            .expect("llm event present");
        assert!(llm_ev.input.is_none(), "prompt input must be dropped");
        assert!(llm_ev.output.is_none(), "completion output must be dropped");
        assert!(llm_ev.blocks.llm.is_some(), "model_metadata block survives");
        assert_eq!(
            llm_ev.blocks.llm.as_ref().unwrap().model.as_deref(),
            Some("claude"),
            "model metadata exported"
        );
        assert!(!json.contains("secret system prompt"), "prompt leaked: {json}");
        assert!(!json.contains("the model reply"), "reply leaked: {json}");

        // (3) The tool args/results are dropped entirely (tool_args/tool_results),
        // and so is EVERY other payload-bearing field on a non-exporting class:
        // output, error, the payload `name`, and the non-allowlisted attribute.
        let tool_ev = bundle
            .events
            .iter()
            .find(|e| e.kind == Kind::Tool)
            .expect("tool event present");
        assert!(tool_ev.blocks.tool.is_none(), "tool block must be dropped");
        assert!(tool_ev.output.is_none(), "tool result must be dropped");
        assert!(tool_ev.error.is_none(), "tool error text must be dropped");
        assert_eq!(
            tool_ev.status,
            Status::Ok,
            "status downgraded to Ok once the error message is scrubbed (stays coherent)"
        );
        assert!(tool_ev.validate().is_ok(), "projected event must stay valid");
        // `name` is reset to the non-payload operation verb (not the leak).
        assert_eq!(tool_ev.name, tool_ev.operation, "name reset to the op verb");
        assert_ne!(tool_ev.name, "NAMELEAK prompt text");
        // The non-payload `source` attribute survives; the payload one is gone.
        assert_eq!(
            tool_ev.attributes.get("source").and_then(|v| v.as_str()),
            Some("mcp"),
            "allowlisted provenance attribute kept"
        );
        assert!(
            !tool_ev.attributes.contains_key("otlp_prompt_attr"),
            "non-allowlisted (payload) attribute must be dropped"
        );
        assert!(!json.contains("/etc/passwd"), "tool args leaked: {json}");
        assert!(!json.contains("file contents leak"), "tool result leaked: {json}");
        assert!(!json.contains("ERRLEAK"), "tool error payload leaked: {json}");
        assert!(!json.contains("NAMELEAK"), "name payload leaked: {json}");
        assert!(!json.contains("ATTRLEAK"), "attribute payload leaked: {json}");

        // (4) The agent step's turn metadata survives (no payload to leak).
        let agent_ev = bundle
            .events
            .iter()
            .find(|e| e.kind == Kind::Agent)
            .expect("agent event present");
        assert_eq!(
            agent_ev.blocks.agent.as_ref().and_then(|a| a.turn),
            Some(0),
            "turn metadata retained for the timeline"
        );
    }

    #[test]
    fn export_metadata_only_llm_block_is_kept() {
        // A metadata-only LLM event (no input/output) is the one class that
        // exports — the whole block must survive the projection.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        store
            .write({
                let trace_hex = trace.to_hex();
                move |conn| {
                    conn.execute(
                        "INSERT INTO agent_sessions (id, agent, command, trace_id, started_at) \
                         VALUES ('s-meta', 'claude', 'claude', ?1, 1)",
                        params![trace_hex],
                    )?;
                    Ok(())
                }
            })
            .unwrap();
        let meta = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_session(SessionId::new("s-meta"))
            .with_llm(LlmBlock {
                provider: Some("openai".into()),
                model: Some("gpt-4".into()),
                input_tokens: Some(100),
                output_tokens: Some(50),
                cost_usd: Some(0.01),
                ..Default::default()
            });
        store.insert(&meta).unwrap();

        let bundle = export_session(&store, "s-meta").unwrap();
        let llm = bundle.events.iter().find(|e| e.kind == Kind::Llm).unwrap();
        let block = llm.blocks.llm.as_ref().expect("metadata block kept");
        assert_eq!(block.model.as_deref(), Some("gpt-4"));
        assert_eq!(block.input_tokens, Some(100));
        assert_eq!(block.cost_usd, Some(0.01));
    }

    #[test]
    fn export_with_policy_can_include_diffs() {
        // A caller that opts file_diffs.export=true gets the redacted diff body
        // (still redacted — the projection controls *whether* a class leaves, not
        // its redaction). Proves the projection is policy-driven, not hard-coded.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        seed_session_with_actions(
            &store,
            "s-incl",
            &trace,
            &[("file_modified", "a.rs", Some("@@\n+line"), Some("h"), true, 5)],
        );
        let mut policy = CapturePolicy::default();
        policy.classes.file_diffs.export = true;
        let bundle = export_session_with_policy(&store, "s-incl", &policy).unwrap();
        assert_eq!(bundle.actions[0].diff.as_deref(), Some("@@\n+line"));
    }

    #[test]
    fn export_unknown_session_errors() {
        let store = Store::open_in_memory().unwrap();
        let err = export_session(&store, "ghost").unwrap_err();
        assert!(matches!(err, InventoryError::SessionNotFound(_)));
    }

    // ---- forget ----------------------------------------------------------

    #[test]
    fn forget_removes_session_and_on_disk_transcript() {
        let store = Store::open_in_memory().unwrap();
        let out = tempfile::tempdir().unwrap();
        let trace = TraceId::new();
        // A real (valid-shape) session id — `forget` now rejects ids that are not
        // the 32-hex shape, so use a generated one (mirrors the wrapper).
        let sid = SessionId::generate().into_inner();

        // Write on-disk transcript files + a session dir to be cleaned.
        let term = out.path().join("sess.terminal.log");
        let text = out.path().join("sess.txt");
        std::fs::write(&term, "redacted transcript\n").unwrap();
        std::fs::write(&text, "redacted text\n").unwrap();
        let sess_dir = out.path().join("sessions").join(&sid);
        std::fs::create_dir_all(&sess_dir).unwrap();
        std::fs::write(sess_dir.join("preimage.enc"), b"opaque").unwrap();

        // Seed the session + a transcript pointer at those paths + an event.
        seed_session_with_actions(
            &store,
            &sid,
            &trace,
            &[("file_modified", "f.txt", Some("@@"), Some("h"), true, 1)],
        );
        store
            .write({
                let trace_hex = trace.to_hex();
                let term = term.display().to_string();
                let text = text.display().to_string();
                let sid = sid.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO session_transcripts \
                         (session_id, trace_id, terminal_log_path, text_path, line_count, byte_size, max_sensitivity, created_at) \
                         VALUES (?4, ?1, ?2, ?3, 1, 10, 'transcript', 1)",
                        params![trace_hex, term, text, sid],
                    )?;
                    Ok(())
                }
            })
            .unwrap();
        let mut ev = Event::new(trace, Kind::Log, Category::Agent, "line")
            .with_session(SessionId::new(sid.clone()));
        ev.timestamp = MicrosTimestamp(2);
        store.insert(&ev).unwrap();

        // Sanity before.
        assert!(term.exists() && text.exists() && sess_dir.exists());

        let report = forget(&store, ForgetTarget::Session(sid.clone()), out.path()).unwrap();

        // Store rows gone.
        assert_eq!(report.agent_sessions, 1, "session row removed");
        assert!(report.events >= 1, "session event removed");
        // On-disk artifacts gone.
        assert_eq!(report.files_removed, 2, "both transcript files removed");
        assert_eq!(report.dirs_removed, 1, "session dir removed");
        assert!(!term.exists(), "terminal log deleted");
        assert!(!text.exists(), "text deleted");
        assert!(!sess_dir.exists(), "session dir deleted");

        // The session really is gone from the store (idempotent re-forget = noop).
        // The dir is also already gone AND the session no longer exists, so the
        // dir-removal branch is not even entered the second time.
        let again = forget(&store, ForgetTarget::Session(sid), out.path()).unwrap();
        assert_eq!(again.agent_sessions, 0);
        assert_eq!(again.files_removed, 0);
        assert_eq!(again.dirs_removed, 0);
    }

    #[test]
    fn forget_rejects_traversal_and_invalid_ids() {
        // CRITICAL: `forget <id>` must REFUSE a non-well-formed id BEFORE touching
        // the filesystem, so a crafted id can never reach remove_dir_all outside
        // the out-dir. We additionally plant a sentinel dir OUTSIDE the out-dir and
        // assert it survives a traversal attempt.
        let store = Store::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        std::fs::create_dir_all(out.join("sessions")).unwrap();
        // A victim tree a `..` id would reach: <root>/victim/ (sibling of out).
        let victim = root.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("keep.txt"), b"precious").unwrap();

        // The bad ids: a `..` traversal, an absolute path, separator ids, the
        // empty id, a non-hex id, and a 32-char-but-not-hex id. None is the 32-hex
        // shape, so all must be refused before any filesystem touch.
        let bad_ids: Vec<String> = vec![
            "../victim".to_string(),
            "../../victim".to_string(),
            "/etc".to_string(),
            "sessions/../../victim".to_string(),
            "a/b".to_string(),
            "a\\b".to_string(),
            String::new(),
            "not-hex".to_string(),
            "g".repeat(32), // 32 chars, but 'g' is not a hex digit
        ];
        for bad in &bad_ids {
            let err = forget(&store, ForgetTarget::Session(bad.clone()), &out).unwrap_err();
            assert!(
                matches!(err, InventoryError::InvalidSessionId(_)),
                "id {bad:?} must be refused as InvalidSessionId, got {err:?}"
            );
        }
        // The out-of-tree victim is untouched.
        assert!(victim.join("keep.txt").exists(), "traversal must not delete the victim tree");

        // is_valid_session_id agrees: a generated id passes, the bad shapes fail.
        assert!(is_valid_session_id(&SessionId::generate().into_inner()));
        assert!(!is_valid_session_id("../victim"));
        assert!(!is_valid_session_id("/etc/passwd"));
        assert!(!is_valid_session_id(""));
        assert!(!is_valid_session_id(&"a".repeat(31)), "wrong width rejected");
        assert!(!is_valid_session_id(&"A".repeat(32)), "uppercase hex rejected (generate is lowercase)");
    }

    #[test]
    fn forget_valid_id_for_uncaptured_session_does_not_touch_its_dir() {
        // A valid-shape id whose session was never captured must NOT delete an
        // unrelated `<out_dir>/sessions/<id>/` tree (the dir-removal is gated on
        // the session actually existing in the store).
        let store = Store::open_in_memory().unwrap();
        let out = tempfile::tempdir().unwrap();
        let sid = SessionId::generate().into_inner();
        let sess_dir = out.path().join("sessions").join(&sid);
        std::fs::create_dir_all(&sess_dir).unwrap();
        std::fs::write(sess_dir.join("preimage.enc"), b"opaque").unwrap();

        let report = forget(&store, ForgetTarget::Session(sid), out.path()).unwrap();
        assert_eq!(report.agent_sessions, 0, "no such session in the store");
        assert_eq!(report.dirs_removed, 0, "must not remove an uncaptured session's dir");
        assert!(sess_dir.exists(), "the dir of an uncaptured session is left intact");
    }

    #[test]
    fn forget_refuses_transcript_path_outside_out_dir() {
        // MEDIUM: a DB-sourced transcript path outside <out_dir> must be skipped
        // (containment-checked), never unlinked. We point the transcript pointer at
        // a sentinel file OUTSIDE the out-dir and assert forget leaves it alone.
        let store = Store::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        // A file OUTSIDE the out-dir that a stray DB row points at.
        let outside = root.path().join("outside.terminal.log");
        std::fs::write(&outside, b"must survive").unwrap();
        // A second, IN-dir transcript that should be removed normally.
        let inside = out.join("inside.txt");
        std::fs::write(&inside, b"redacted").unwrap();

        let trace = TraceId::new();
        let sid = SessionId::generate().into_inner();
        seed_session_with_actions(&store, &sid, &trace, &[]);
        store
            .write({
                let trace_hex = trace.to_hex();
                let outside_s = outside.display().to_string();
                let inside_s = inside.display().to_string();
                let sid = sid.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO session_transcripts \
                         (session_id, trace_id, terminal_log_path, text_path, line_count, byte_size, max_sensitivity, created_at) \
                         VALUES (?3, ?1, ?2, ?4, 1, 10, 'transcript', 1)",
                        // terminal_log_path = OUTSIDE (must be refused),
                        // text_path = INSIDE (must be removed).
                        params![trace_hex, outside_s, sid, inside_s],
                    )?;
                    Ok(())
                }
            })
            .unwrap();

        let report = forget(&store, ForgetTarget::Session(sid), &out).unwrap();
        // Only the in-dir file was removed; the out-of-dir one was refused.
        assert_eq!(report.files_removed, 1, "only the in-out_dir transcript is removed");
        assert!(outside.exists(), "a transcript path outside out_dir must NOT be unlinked");
        assert!(!inside.exists(), "the in-out_dir transcript is removed normally");
    }

    #[test]
    fn forget_before_removes_on_disk_files_and_dirs() {
        // MEDIUM: `forget --before` must also delete the affected sessions' on-disk
        // transcripts + <out_dir>/sessions/<id>/ dirs, not only the DB rows.
        let store = Store::open_in_memory().unwrap();
        let out = tempfile::tempdir().unwrap();
        let trace = TraceId::new();
        let sid = SessionId::generate().into_inner();

        // On-disk artifacts for an OLD session (started_at < cutoff).
        let term = out.path().join("old.terminal.log");
        let text = out.path().join("old.txt");
        std::fs::write(&term, b"redacted").unwrap();
        std::fs::write(&text, b"redacted").unwrap();
        let sess_dir = out.path().join("sessions").join(&sid);
        std::fs::create_dir_all(&sess_dir).unwrap();
        std::fs::write(sess_dir.join("preimage.enc"), b"opaque").unwrap();

        seed_session_with_actions(&store, &sid, &trace, &[]);
        store
            .write({
                let trace_hex = trace.to_hex();
                let term = term.display().to_string();
                let text = text.display().to_string();
                let sid = sid.clone();
                move |conn| {
                    // started_at = 100 (well below the 5_000 cutoff).
                    conn.execute(
                        "UPDATE agent_sessions SET started_at = 100 WHERE id = ?1",
                        params![sid],
                    )?;
                    conn.execute(
                        "INSERT INTO session_transcripts \
                         (session_id, trace_id, terminal_log_path, text_path, line_count, byte_size, max_sensitivity, created_at) \
                         VALUES (?4, ?1, ?2, ?3, 1, 10, 'transcript', 1)",
                        params![trace_hex, term, text, sid],
                    )?;
                    Ok(())
                }
            })
            .unwrap();

        assert!(term.exists() && text.exists() && sess_dir.exists());

        let report = forget(&store, ForgetTarget::Before(5_000), out.path()).unwrap();
        assert_eq!(report.agent_sessions, 1, "old session row dropped by --before");
        assert_eq!(report.files_removed, 2, "both old transcript files removed");
        assert_eq!(report.dirs_removed, 1, "old session dir removed");
        assert!(!term.exists() && !text.exists() && !sess_dir.exists(), "on-disk artifacts purged");
    }

    #[test]
    fn forget_before_only_touches_old_sessions() {
        // A session NEWER than the cutoff keeps its on-disk artifacts; only the
        // old one's are removed.
        let store = Store::open_in_memory().unwrap();
        let out = tempfile::tempdir().unwrap();

        let mk = |sid: &str, started: i64, fname: &str| {
            let trace = TraceId::new();
            let f = out.path().join(fname);
            std::fs::write(&f, b"redacted").unwrap();
            seed_session_with_actions(&store, sid, &trace, &[]);
            store
                .write({
                    let trace_hex = trace.to_hex();
                    let f = f.display().to_string();
                    let sid = sid.to_string();
                    move |conn| {
                        conn.execute(
                            "UPDATE agent_sessions SET started_at = ?2 WHERE id = ?1",
                            params![sid, started],
                        )?;
                        conn.execute(
                            "INSERT INTO session_transcripts \
                             (session_id, trace_id, terminal_log_path, text_path, line_count, byte_size, max_sensitivity, created_at) \
                             VALUES (?3, ?1, ?2, NULL, 1, 10, 'transcript', 1)",
                            params![trace_hex, f, sid],
                        )?;
                        Ok(())
                    }
                })
                .unwrap();
            f
        };
        let old_id = SessionId::generate().into_inner();
        let new_id = SessionId::generate().into_inner();
        let old_f = mk(&old_id, 100, "old.log");
        let new_f = mk(&new_id, 9_000, "new.log");

        let report = forget(&store, ForgetTarget::Before(5_000), out.path()).unwrap();
        assert_eq!(report.agent_sessions, 1, "only the old session dropped");
        assert_eq!(report.files_removed, 1, "only the old transcript removed");
        assert!(!old_f.exists(), "old transcript purged");
        assert!(new_f.exists(), "newer session's transcript kept");
    }

    // ---- session_diffs_up_to_turn ----------------------------------------

    #[test]
    fn diffs_up_to_turn_is_cumulative_and_not_reconstructable() {
        // Two turns with events at known timestamps; an action observed mid-turn-0
        // and another after turn-1. up_to_turn(0) sees only the first; up_to_turn(1)
        // sees both.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("sess-tt");

        // Turn 0 event @100, turn 1 event @300.
        let mk_turn = |turn: u64, ts: i64| {
            let mut ev = Event::new(trace, Kind::Agent, Category::Agent, "step")
                .with_session(sess.clone())
                .with_agent(AgentBlock {
                    turn: Some(turn),
                    ..Default::default()
                });
            ev.timestamp = MicrosTimestamp(ts);
            ev
        };

        seed_session_with_actions(
            &store,
            "sess-tt",
            &trace,
            &[
                // Observed during turn 0 (<=100).
                ("file_added", "early.txt", Some("@@\n+early"), Some("h1"), true, 100),
                // Observed after turn 1 (300).
                ("file_added", "late.txt", Some("@@\n+late"), Some("h2"), true, 300),
            ],
        );
        store.insert(&mk_turn(0, 100)).unwrap();
        store.insert(&mk_turn(1, 300)).unwrap();

        // up_to_turn(0): cut-off = max ts of turn<=0 = 100 → only early.txt.
        let t0 = session_diffs_up_to_turn(&store, "sess-tt", 0).unwrap();
        assert!(!t0.reconstructable, "redacted diffs are never an exact restore");
        let paths0: Vec<_> = t0.diffs.iter().filter_map(|d| d.path.as_deref()).collect();
        assert_eq!(paths0, vec!["early.txt"], "turn 0 sees only the early diff");

        // up_to_turn(1): cut-off = max ts of turn<=1 = 300 → both.
        let t1 = session_diffs_up_to_turn(&store, "sess-tt", 1).unwrap();
        let mut paths1: Vec<_> = t1.diffs.iter().filter_map(|d| d.path.as_deref()).collect();
        paths1.sort_unstable();
        assert_eq!(paths1, vec!["early.txt", "late.txt"], "turn 1 sees both diffs");
    }

    #[test]
    fn diffs_up_to_turn_no_stamped_turns_returns_all() {
        // The common Phase-1 case: diffs are a teardown snapshot, no turn-stamped
        // events. Every diff is the final state → up_to_turn(anything) returns all.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        seed_session_with_actions(
            &store,
            "sess-flat",
            &trace,
            &[
                ("file_modified", "a.txt", Some("@@\n+a"), Some("h"), true, 50),
                ("file_added", "b.txt", Some("@@\n+b"), Some("h"), true, 60),
            ],
        );
        let view = session_diffs_up_to_turn(&store, "sess-flat", 0).unwrap();
        assert_eq!(view.diffs.len(), 2, "no stamped turns ⇒ all diffs included");
        assert!(!view.reconstructable);
    }

    #[test]
    fn diffs_up_to_turn_unknown_session_errors() {
        let store = Store::open_in_memory().unwrap();
        let err = session_diffs_up_to_turn(&store, "ghost", 0).unwrap_err();
        assert!(matches!(err, InventoryError::SessionNotFound(_)));
    }
}
