//! Continue source — reads the Continue extension's per-session JSON history
//! files (plan "Phase 1").
//!
//! The module is named `continue_` because `continue` is a Rust keyword; the
//! public type is [`ContinueSource`] and its tool name is `"continue"`.
//!
//! Continue persists each conversation as a standalone JSON file under
//! `~/.continue/sessions/*.json` (with a reserved `sessions.json` index file
//! that is **not** a conversation). This source discovers and reads those files
//! **read-only**, passing each file's native `history[]` array straight through
//! as the uniform record stream the
//! [`ContinueAdapter`](logbook_harness::ContinueAdapter) consumes. It never
//! persists, redacts, or builds events — it moves only opaque
//! [`serde_json::Value`]s.
//!
//! ## Store location
//! Continue keeps its data dir at `~/.continue`; sessions live directly in
//! `~/.continue/sessions/`. [`DataRoots`] supplies the per-OS base directories
//! (home is one of them); this source appends `.continue/sessions` beneath each
//! root and lists every `*.json` file there, skipping the reserved
//! `sessions.json` index.
//!
//! ## One file → one session
//! Each session file is `{ sessionId, title, workspaceDirectory, history:[…] }`.
//! Discovery records the `sessionId` (or the file stem) as the native id, the
//! `title`/`workspaceDirectory`, and the file `mtime` as the deterministic
//! timestamp base. Continue stores **no timestamp**, so `last_active` is `None`
//! (the `--since` filter falls back to the file mtime, with a warning).
//! [`ContinueSource::read`] re-parses the file and hands the `history[]` array
//! through unchanged.
//!
//! ## Tolerant + total
//! A directory that cannot be read becomes a [`Diag`] (never silent loss); a
//! single session file that is not valid JSON is skipped during discovery (with
//! a warning) and surfaces as [`ReadError::Json`] on a direct `read`. Record
//! *shape* drift is tolerated later, inside the adapter.

use std::path::{Path, PathBuf};

use serde_json::Value;

use logbook_core::MicrosTimestamp;

use crate::discovery::DataRoots;
use crate::{
    origin_fingerprint, Diag, DiscoveredSession, ReadError, SessionLocator, SessionRecords,
    SessionSource,
};

/// The reserved index file in `~/.continue/sessions` that is **not** a
/// conversation transcript (it lists the sessions); skipped during discovery.
const SESSIONS_INDEX: &str = "sessions.json";

/// The [`SessionSource`] for the Continue extension.
///
/// Stateless: all per-session state lives on the [`DiscoveredSession`] it returns
/// (the `origin` file path + the native `sessionId`), so a single instance
/// discovers and reads any number of sessions.
#[derive(Debug, Default)]
pub struct ContinueSource;

impl ContinueSource {
    /// The stable tool name (matches the adapter's `NAME`).
    pub const NAME: &'static str = "continue";

    /// Construct a Continue source.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SessionSource for ContinueSource {
    fn tool(&self) -> &str {
        Self::NAME
    }

    fn discover(&self, roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
        let mut sessions = Vec::new();
        let mut diags = Vec::new();
        for file in continue_session_files(roots, &mut diags) {
            discover_in_file(&file, &mut sessions, &mut diags);
        }
        (sessions, diags)
    }

    fn read(&self, session: &DiscoveredSession) -> Result<SessionRecords, ReadError> {
        let data = read_json_file(&session.origin)?;
        let records = data
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(SessionRecords {
            native_id: session.native_id.clone(),
            records,
            session_meta: session_meta(session),
        })
    }
}

// ---------------------------------------------------------------------------
// File enumeration
// ---------------------------------------------------------------------------

/// Walk the data roots for every Continue session `*.json` file (minus the
/// reserved index). IO problems (an unreadable dir) become [`Diag`]s, never
/// silent loss.
///
/// Under each root we probe `.continue/sessions`, then list its `*.json` files.
/// The `--path` override may point directly at a session JSON file (read as one
/// session) or at a directory that *is* a `sessions` dir / a `.continue` dir.
fn continue_session_files(roots: &DataRoots, diags: &mut Vec<Diag>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in &roots.roots {
        // `--path` may name a single session file directly (any `*.json` that is
        // not the reserved index).
        if root.is_file() {
            if is_session_file(root) {
                files.push(root.clone());
            }
            continue;
        }
        for dir in continue_session_dirs(root) {
            collect_session_files(&dir, diags, &mut files);
        }
    }
    files.sort();
    files.dedup();
    files
}

/// Candidate Continue `sessions` directories under `root`: the standard
/// `.continue/sessions`, plus `root/sessions` and `root` itself (so a fixture or
/// `--path` pointing at a `.continue` dir, a `sessions` dir, or a dir of session
/// files directly is honoured).
fn continue_session_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let standard = root.join(".continue").join("sessions");
    if standard.is_dir() {
        dirs.push(standard);
    }
    let sessions = root.join("sessions");
    if sessions.is_dir() {
        dirs.push(sessions);
    }
    // `root` itself may be a sessions dir (holds the session `*.json` files).
    if root.is_dir() {
        dirs.push(root.to_path_buf());
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Collect every Continue session `*.json` file (minus the reserved index) in a
/// `sessions` dir. An unreadable dir becomes a warning.
fn collect_session_files(sessions_dir: &Path, diags: &mut Vec<Diag>, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(sessions_dir) {
        Ok(e) => e,
        Err(e) => {
            diags.push(Diag::warn(
                sessions_dir.to_path_buf(),
                format!("could not read Continue sessions dir: {e}"),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && is_session_file(&path) {
            out.push(path);
        }
    }
}

/// Whether a path names a Continue session transcript: a `*.json` file that is
/// not the reserved `sessions.json` index.
fn is_session_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".json") && name != SESSIONS_INDEX
}

// ---------------------------------------------------------------------------
// Per-file discovery (cheap: top-level structure only, no bodies built)
// ---------------------------------------------------------------------------

/// Discover the single session in one file, appending to `sessions` (and any
/// problem to `diags`). A file that cannot be read/parsed becomes a warning
/// [`Diag`] and is skipped (discovery stays total).
fn discover_in_file(path: &Path, sessions: &mut Vec<DiscoveredSession>, diags: &mut Vec<Diag>) {
    let data = match read_json_file(path) {
        Ok(v) => v,
        Err(e) => {
            diags.push(Diag::warn(
                path.to_path_buf(),
                format!("Continue session unreadable: {e}"),
            ));
            return;
        }
    };
    let history = data.get("history").and_then(Value::as_array);
    let count = history.map(Vec::len).unwrap_or(0);
    // A session with no history is empty; skip (no empty sessions).
    if count == 0 {
        return;
    }

    let native_id = data
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| file_stem(path));

    let fp = origin_fingerprint(path);
    let import_id = DiscoveredSession::make_import_id(&fp, &native_id);
    sessions.push(DiscoveredSession {
        tool: ContinueSource::NAME.to_string(),
        native_id,
        import_id,
        origin: path.to_path_buf(),
        locator: SessionLocator::File(path.to_path_buf()),
        title: data.get("title").and_then(Value::as_str).map(str::to_string),
        // Continue stores no per-conversation timestamp; leave last_active None
        // (the CLI's `--since` falls back to mtime, with a warning).
        last_active: None,
        mtime: file_mtime(path),
        approx_messages: Some(count),
        workspace: data
            .get("workspaceDirectory")
            .and_then(Value::as_str)
            .map(str::to_string),
    });
}

/// Build the session-level metadata Value handed to the adapter. Opaque to the
/// import crate; the adapter may fold it in.
fn session_meta(session: &DiscoveredSession) -> Value {
    serde_json::json!({
        "title": session.title,
        "workspace": session.workspace,
        "native_id": session.native_id,
    })
}

// ---------------------------------------------------------------------------
// File IO (read-only JSON)
// ---------------------------------------------------------------------------

/// Read + parse a JSON file, mapping an IO failure to [`ReadError::Io`] and a
/// parse failure to [`ReadError::Json`]. Uses a buffered `from_reader`.
fn read_json_file(path: &Path) -> Result<Value, ReadError> {
    let file = std::fs::File::open(path).map_err(|source| ReadError::Io {
        origin: path.to_path_buf(),
        source,
    })?;
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader).map_err(|source| ReadError::Json {
        origin: path.to_path_buf(),
        source,
    })
}

/// The file's `mtime` in microseconds — the deterministic timestamp base (every
/// Continue event uses `mtime + index`, since Continue is undated). A file whose
/// mtime cannot be read falls back to `0` (still deterministic for an unchanged
/// file).
fn file_mtime(path: &Path) -> MicrosTimestamp {
    let micros = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0);
    MicrosTimestamp(micros)
}

/// The file stem (filename without extension), as an owned string, for the
/// native-id fallback when no `sessionId` is stored.
fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery;

    /// Write a Continue session JSON file at `path`.
    fn write_session(path: &Path, value: &Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value.to_string()).unwrap();
    }

    fn sample_session() -> Value {
        serde_json::json!({
            "sessionId": "sess-xyz",
            "title": "My Continue chat",
            "workspaceDirectory": "/home/me/proj",
            "history": [
                { "message": { "role": "user", "content": "hello with AKIAIOSFODNN7EXAMPLE" } },
                { "message": { "role": "assistant", "content": "hi there" } }
            ]
        })
    }

    /// A standard layout under a data root: `{root}/.continue/sessions/{id}.json`.
    fn seed_standard_layout(root: &Path) -> PathBuf {
        let file = root
            .join(".continue")
            .join("sessions")
            .join("sess-xyz.json");
        write_session(&file, &sample_session());
        file
    }

    #[test]
    fn discovers_session_file_with_native_id_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let file = seed_standard_layout(dir.path());

        let src = ContinueSource::new();
        let (sessions, diags) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(diags.is_empty(), "no diags expected: {diags:?}");
        assert_eq!(sessions.len(), 1, "got: {sessions:#?}");

        let s = &sessions[0];
        assert_eq!(s.native_id, "sess-xyz");
        assert_eq!(s.title.as_deref(), Some("My Continue chat"));
        assert_eq!(s.workspace.as_deref(), Some("/home/me/proj"));
        assert_eq!(s.approx_messages, Some(2));
        // Continue is undated.
        assert_eq!(s.last_active, None, "Continue records no last-active time");
        let fp = origin_fingerprint(&file);
        assert_eq!(s.import_id, format!("{fp}:sess-xyz"));
    }

    #[test]
    fn reads_history_array_into_records() {
        let dir = tempfile::tempdir().unwrap();
        seed_standard_layout(dir.path());
        let src = ContinueSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));

        let recs = src.read(&sessions[0]).unwrap();
        assert_eq!(recs.records.len(), 2);
        // The source moves the RAW value through (redaction is the adapter's job).
        assert_eq!(recs.records[0]["message"]["role"], serde_json::json!("user"));
        assert!(recs.records[0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(recs.records[1]["message"]["role"], serde_json::json!("assistant"));
    }

    #[test]
    fn skips_the_reserved_sessions_index() {
        let dir = tempfile::tempdir().unwrap();
        let sessions_dir = dir.path().join(".continue").join("sessions");
        // A real session plus the reserved index file.
        write_session(&sessions_dir.join("real.json"), &sample_session());
        write_session(
            &sessions_dir.join(SESSIONS_INDEX),
            &serde_json::json!([{ "sessionId": "real", "title": "x" }]),
        );

        let src = ContinueSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));
        // Only the real session is discovered; sessions.json is skipped.
        assert_eq!(sessions.len(), 1, "the reserved index must be skipped: {sessions:#?}");
        assert_eq!(sessions[0].native_id, "sess-xyz");
    }

    #[test]
    fn discovers_via_direct_path_to_session_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("some-session.json");
        write_session(&file, &sample_session());

        let src = ContinueSource::new();
        let (sessions, diags) = src.discover(&discovery::from_path(file.clone()));
        assert!(diags.is_empty(), "diags: {diags:?}");
        assert_eq!(sessions.len(), 1);
        assert_eq!(src.read(&sessions[0]).unwrap().records.len(), 2);
    }

    #[test]
    fn file_stem_native_id_when_session_id_absent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join(".continue")
            .join("sessions")
            .join("fallback-id.json");
        write_session(
            &file,
            &serde_json::json!({ "history": [ { "message": { "role": "user", "content": "x" } } ] }),
        );
        let src = ContinueSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].native_id, "fallback-id");
    }

    #[test]
    fn empty_history_files_are_not_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join(".continue")
            .join("sessions")
            .join("empty.json");
        write_session(&file, &serde_json::json!({ "sessionId": "empty", "history": [] }));
        let src = ContinueSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(sessions.is_empty(), "empty sessions must not be discovered");
    }

    #[test]
    fn malformed_json_file_surfaces_read_error_and_discovery_diag() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join(".continue")
            .join("sessions")
            .join("bad.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{ not valid json :: ]").unwrap();

        let src = ContinueSource::new();
        let (sessions, diags) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(sessions.is_empty());
        assert_eq!(diags.len(), 1, "a malformed file must produce one diagnostic");
        assert_eq!(diags[0].origin, file);

        let probe = DiscoveredSession {
            tool: ContinueSource::NAME.to_string(),
            native_id: "x".to_string(),
            import_id: "fp:x".to_string(),
            origin: file.clone(),
            locator: SessionLocator::File(file.clone()),
            title: None,
            last_active: None,
            mtime: MicrosTimestamp(0),
            approx_messages: None,
            workspace: None,
        };
        let err = src.read(&probe).unwrap_err();
        assert!(matches!(err, ReadError::Json { .. }), "got: {err:?}");
    }

    /// Two session files at different paths sharing the SAME `sessionId` must
    /// yield two DISTINCT import ids (origin_fingerprint namespacing).
    #[test]
    fn two_files_sharing_session_id_get_distinct_import_ids() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a").join("s.json");
        let b = dir.path().join("b").join("s.json");
        write_session(&a, &sample_session());
        write_session(&b, &sample_session());

        let src = ContinueSource::new();
        let (sa, _) = src.discover(&discovery::from_path(a.clone()));
        let (sb, _) = src.discover(&discovery::from_path(b.clone()));
        assert_eq!(sa.len(), 1);
        assert_eq!(sb.len(), 1);
        assert_eq!(sa[0].native_id, sb[0].native_id, "same sessionId");
        assert_ne!(
            sa[0].import_id, sb[0].import_id,
            "two files with the same sessionId must namespace to distinct import ids"
        );
    }
}
