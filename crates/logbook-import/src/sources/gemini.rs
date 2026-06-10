//! Gemini source — reads the Gemini CLI's per-session JSON transcripts (plan
//! "Phase 1").
//!
//! The Gemini CLI persists each conversation as a standalone JSON file under
//! `…/gemini/tmp/{project_hash}/chats/session-*.json`. This source discovers and
//! reads those files **read-only**, passing each file's native `messages[]`
//! array straight through as the uniform record stream the
//! [`GeminiAdapter`](logbook_harness::GeminiAdapter) consumes. It never persists,
//! redacts, or builds events — it moves only opaque [`serde_json::Value`]s.
//!
//! ## Store locations
//! The CLI keeps its data dir at `~/.gemini` (also `~/.config/gemini`,
//! `~/.local/share/gemini`). Under a data dir, session files live at
//! `tmp/{project_hash}/chats/session-*.json`. [`DataRoots`] supplies the per-OS
//! base directories; this source appends both the `gemini` and `.gemini`
//! sub-directory names beneath each root and globs the `tmp/*/chats/session-*.json`
//! pattern.
//!
//! ## One file → one session
//! Each session file is `{ sessionId, projectHash, startTime, lastUpdated,
//! messages:[…] }`. Discovery records the `sessionId` (or the file stem) as the
//! native id, `lastUpdated` as the last-active time, the file `mtime` as the
//! deterministic timestamp base, and `messages.len()` as the bounded message
//! count. [`GeminiSource::read`] re-parses the file and hands the `messages[]`
//! array through unchanged.
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

/// The sub-directory names the Gemini CLI uses for its data dir, beneath each
/// data root. Both the dotted and plain spellings are probed.
const GEMINI_DIRS: &[&str] = &["gemini", ".gemini"];

/// The [`SessionSource`] for the Gemini CLI.
///
/// Stateless: all per-session state lives on the [`DiscoveredSession`] it returns
/// (the `origin` file path + the native `sessionId`), so a single instance
/// discovers and reads any number of sessions.
#[derive(Debug, Default)]
pub struct GeminiSource;

impl GeminiSource {
    /// The stable tool name (matches the adapter's `NAME`).
    pub const NAME: &'static str = "gemini";

    /// Construct a Gemini source.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SessionSource for GeminiSource {
    fn tool(&self) -> &str {
        Self::NAME
    }

    fn discover(&self, roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
        let mut sessions = Vec::new();
        let mut diags = Vec::new();
        for file in gemini_session_files(roots, &mut diags) {
            discover_in_file(&file, &mut sessions, &mut diags);
        }
        (sessions, diags)
    }

    fn read(&self, session: &DiscoveredSession) -> Result<SessionRecords, ReadError> {
        let data = read_json_file(&session.origin)?;
        let records = data
            .get("messages")
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

/// Walk the data roots for every Gemini `session-*.json` file. IO problems (an
/// unreadable dir) become [`Diag`]s, never silent loss.
///
/// Under each root we probe both the `gemini` and `.gemini` data dirs, then glob
/// `tmp/{project_hash}/chats/session-*.json` beneath each. The `--path` override
/// may point directly at a session JSON file (read as one session) or at a
/// directory that *is* a Gemini data dir / holds the `tmp/.../chats` layout.
fn gemini_session_files(roots: &DataRoots, diags: &mut Vec<Diag>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in &roots.roots {
        // `--path` may name a single session file directly.
        if root.is_file() {
            if is_session_file(root) {
                files.push(root.clone());
            }
            continue;
        }
        for base in gemini_data_dirs(root) {
            collect_session_files(&base, diags, &mut files);
        }
    }
    files.sort();
    files.dedup();
    files
}

/// Candidate Gemini data directories under `root`: the standard `gemini` /
/// `.gemini` sub-dirs, plus `root` itself (so a fixture or `--path` pointing
/// straight at a data dir, or at a dir holding the `tmp/.../chats` layout, is
/// honoured).
fn gemini_data_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for name in GEMINI_DIRS {
        let dir = root.join(name);
        if dir.is_dir() {
            dirs.push(dir);
        }
    }
    // `root` itself may be a data dir (holds `tmp/`).
    if root.join("tmp").is_dir() {
        dirs.push(root.to_path_buf());
    }
    dirs
}

/// Collect every `tmp/{hash}/chats/session-*.json` file under a Gemini data dir.
/// An unreadable `tmp` dir becomes a warning; missing intermediate dirs are just
/// skipped.
fn collect_session_files(data_dir: &Path, diags: &mut Vec<Diag>, out: &mut Vec<PathBuf>) {
    let tmp = data_dir.join("tmp");
    if !tmp.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(&tmp) {
        Ok(e) => e,
        Err(e) => {
            diags.push(Diag::warn(
                tmp.clone(),
                format!("could not read Gemini tmp dir: {e}"),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let chats = entry.path().join("chats");
        if !chats.is_dir() {
            continue;
        }
        let chat_entries = match std::fs::read_dir(&chats) {
            Ok(e) => e,
            Err(e) => {
                diags.push(Diag::warn(
                    chats.clone(),
                    format!("could not read Gemini chats dir: {e}"),
                ));
                continue;
            }
        };
        for chat in chat_entries.flatten() {
            let path = chat.path();
            if path.is_file() && is_session_file(&path) {
                out.push(path);
            }
        }
    }
}

/// Whether a path names a Gemini session transcript (`session-*.json`).
fn is_session_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with("session-") && name.ends_with(".json")
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
                format!("Gemini session unreadable: {e}"),
            ));
            return;
        }
    };
    let messages = data.get("messages").and_then(Value::as_array);
    let count = messages.map(Vec::len).unwrap_or(0);
    // A session with no messages is empty; skip (no empty sessions).
    if count == 0 {
        return;
    }

    // Native id: prefer the stored sessionId, else the file stem.
    let native_id = data
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| file_stem(path));

    let mtime = file_mtime(path);
    // last-active: prefer `lastUpdated`; the field may be epoch millis or an
    // ISO-8601 string — only the numeric form is used (string dates are left to
    // the mtime fallback in `--since`).
    let last_active = data
        .get("lastUpdated")
        .and_then(Value::as_i64)
        .map(normalize_millis)
        .or(Some(mtime));

    let fp = origin_fingerprint(path);
    let import_id = DiscoveredSession::make_import_id(&fp, &native_id);
    sessions.push(DiscoveredSession {
        tool: GeminiSource::NAME.to_string(),
        native_id,
        import_id,
        origin: path.to_path_buf(),
        locator: SessionLocator::File(path.to_path_buf()),
        title: data
            .get("projectHash")
            .and_then(Value::as_str)
            .map(str::to_string),
        last_active,
        mtime,
        approx_messages: Some(count),
        workspace: data
            .get("projectHash")
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
/// parse failure to [`ReadError::Json`]. Uses a buffered `from_reader` so large
/// transcripts do not require a full intermediate `String`.
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

/// The file's `mtime` in microseconds — the deterministic timestamp base for
/// undated messages. A file whose mtime cannot be read falls back to `0` (still
/// deterministic for an unchanged file).
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

/// Normalize a millisecond epoch to microseconds (Gemini records `lastUpdated`
/// in ms when numeric).
fn normalize_millis(ms: i64) -> MicrosTimestamp {
    MicrosTimestamp(ms.saturating_mul(1000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery;

    /// Write a Gemini session JSON file at `path`.
    fn write_session(path: &Path, value: &Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value.to_string()).unwrap();
    }

    fn sample_session() -> Value {
        serde_json::json!({
            "sessionId": "sess-abc",
            "projectHash": "proj123",
            "startTime": 1_700_000_000_000_i64,
            "lastUpdated": 1_700_000_500_000_i64,
            "messages": [
                { "type": "user", "content": "hello with AKIAIOSFODNN7EXAMPLE", "timestamp": 1_700_000_111_000_i64 },
                { "type": "gemini", "content": "hi there", "model": "gemini-2.0-flash", "tokens": { "input": 5, "output": 7 } }
            ]
        })
    }

    /// A standard layout under a data root: `{root}/.gemini/tmp/{hash}/chats/session-*.json`.
    fn seed_standard_layout(root: &Path) -> PathBuf {
        let file = root
            .join(".gemini")
            .join("tmp")
            .join("hash1")
            .join("chats")
            .join("session-0001.json");
        write_session(&file, &sample_session());
        file
    }

    #[test]
    fn discovers_session_file_with_native_id_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let file = seed_standard_layout(dir.path());

        let src = GeminiSource::new();
        let (sessions, diags) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(diags.is_empty(), "no diags expected: {diags:?}");
        assert_eq!(sessions.len(), 1, "got: {sessions:#?}");

        let s = &sessions[0];
        assert_eq!(s.native_id, "sess-abc");
        assert_eq!(s.approx_messages, Some(2));
        assert_eq!(s.workspace.as_deref(), Some("proj123"));
        // import_id is fp:native_id, fingerprinting the file path.
        let fp = origin_fingerprint(&file);
        assert_eq!(s.import_id, format!("{fp}:sess-abc"));
        // last_active comes from lastUpdated (millis → micros).
        assert_eq!(s.last_active, Some(MicrosTimestamp(1_700_000_500_000_000)));
    }

    #[test]
    fn reads_messages_array_into_records() {
        let dir = tempfile::tempdir().unwrap();
        seed_standard_layout(dir.path());
        let src = GeminiSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));

        let recs = src.read(&sessions[0]).unwrap();
        assert_eq!(recs.records.len(), 2);
        // The source moves the RAW value through (redaction is the adapter's job):
        // the secret is still present in the opaque record here, by design.
        assert_eq!(recs.records[0]["type"], serde_json::json!("user"));
        assert!(recs.records[0]["content"].as_str().unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(recs.records[1]["type"], serde_json::json!("gemini"));
        assert_eq!(recs.records[1]["model"], serde_json::json!("gemini-2.0-flash"));
    }

    #[test]
    fn discovers_via_direct_path_to_session_file() {
        // `--path` pointed straight at a session-*.json file reads it directly.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("session-direct.json");
        write_session(&file, &sample_session());

        let src = GeminiSource::new();
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
            .join("gemini")
            .join("tmp")
            .join("h")
            .join("chats")
            .join("session-fallback.json");
        write_session(
            &file,
            &serde_json::json!({ "messages": [ { "type": "user", "content": "x" } ] }),
        );
        let src = GeminiSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert_eq!(sessions.len(), 1);
        // No sessionId ⇒ native id is the file stem.
        assert_eq!(sessions[0].native_id, "session-fallback");
    }

    #[test]
    fn empty_message_files_are_not_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join(".gemini")
            .join("tmp")
            .join("h")
            .join("chats")
            .join("session-empty.json");
        write_session(&file, &serde_json::json!({ "sessionId": "empty", "messages": [] }));
        let src = GeminiSource::new();
        let (sessions, _) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(sessions.is_empty(), "empty sessions must not be discovered");
    }

    #[test]
    fn malformed_json_file_surfaces_read_error_and_discovery_diag() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join(".gemini")
            .join("tmp")
            .join("h")
            .join("chats")
            .join("session-bad.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{ this is not valid json ]").unwrap();

        // discover() emits a warning Diag and no session for this file.
        let src = GeminiSource::new();
        let (sessions, diags) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(sessions.is_empty());
        assert_eq!(diags.len(), 1, "a malformed file must produce one diagnostic");
        assert_eq!(diags[0].origin, file);

        // A direct read() of a session pointing at the malformed file → Json error.
        let probe = DiscoveredSession {
            tool: GeminiSource::NAME.to_string(),
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

    #[test]
    fn missing_file_read_surfaces_io_error() {
        let probe = DiscoveredSession {
            tool: GeminiSource::NAME.to_string(),
            native_id: "x".to_string(),
            import_id: "fp:x".to_string(),
            origin: PathBuf::from("/nonexistent/gemini/session-x.json"),
            locator: SessionLocator::File(PathBuf::from("/nonexistent/gemini/session-x.json")),
            title: None,
            last_active: None,
            mtime: MicrosTimestamp(0),
            approx_messages: None,
            workspace: None,
        };
        let err = GeminiSource::new().read(&probe).unwrap_err();
        assert!(matches!(err, ReadError::Io { .. }), "got: {err:?}");
    }

    /// Two session files at different paths sharing the SAME `sessionId` must
    /// yield two DISTINCT import ids (origin_fingerprint namespacing).
    #[test]
    fn two_files_sharing_session_id_get_distinct_import_ids() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a").join("session-1.json");
        let b = dir.path().join("b").join("session-1.json");
        write_session(&a, &sample_session());
        write_session(&b, &sample_session());

        let src = GeminiSource::new();
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
