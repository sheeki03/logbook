//! `logbook-import` — retroactive session importers for GUI/IDE coding agents.
//!
//! logbook records only sessions you *explicitly start* (`logbook agent -- …`,
//! the hooks/MCP/LLM-proxy tiers). GUI/IDE agents that route LLM traffic through
//! their own cloud backend (Cursor, Gemini, Continue, …) are invisible to all of
//! those, yet every conversation they have had sits on disk. This crate reads
//! those on-disk **source stores** and hands their records to the harness
//! adapters, which redact and normalize them onto the same [`Event`] timeline as
//! live captures.
//!
//! # Boundaries (why this crate exists, and what it must *not* do)
//!
//! - **Reads sources; never persists.** A source parses raw DB/JSON values in
//!   memory (it cannot avoid that) but only moves **opaque
//!   [`serde_json::Value`] records** to the adapter via [`SessionRecords`]. It
//!   never persists, logs, or redacts a raw payload itself — the harness adapter
//!   is the *sole* component that redacts (via its `HarnessContext`) and builds
//!   [`Event`]s. The neutral [`ImportBatch`] this crate produces is what the CLI
//!   persists.
//! - **No store / inventory dependency.** This crate depends on neither
//!   `logbook-store` nor `logbook-inventory`. Inventory will depend on *this*
//!   crate (for read-only discovery), and the CLI is the sole persister
//!   (mapping [`ImportSessionHeader`] → `AgentSessionRecord`). Keeping the
//!   dependency arrow pointing this way is what prevents a cycle.
//!
//! # Determinism
//!
//! Re-importing an *unchanged* source store must reproduce **byte-identical**
//! rows, so every id is derived (never random) and every timestamp comes from
//! the source or a deterministic fallback (never `now()`). The id derivations
//! live here ([`origin_fingerprint`], [`import_trace_id`], [`import_session_id`])
//! and in the harness (`import_event_id`); all are nonzero-guarded and folded
//! over `logbook_core::fnv1a_128`. A tool's native key is **not** globally unique
//! (Cursor's legacy chat key is the same string in every workspace DB), so
//! identity is always `(tool, origin_fingerprint, native_key)`.
//!
//! # Status
//!
//! This is the shared foundation (Wave 1): the trait surface, neutral contract
//! types, id helpers, and discovery seams are complete and stable. The
//! per-tool sources are placeholders ([`source_for`]) that discover nothing and
//! return [`ReadError::Unsupported`] from `read`; later waves replace each arm
//! with a real reader + harness adapter without redesigning this surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use logbook_core::{fnv1a_128, Event, MicrosTimestamp, TraceId};

pub mod discovery;
pub mod runner;
pub mod sources;

pub use discovery::DataRoots;
pub use sources::{ContinueSource, CursorSource, GeminiSource};

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Severity of a discovery/read [`Diag`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// A recoverable problem the user should know about but that did not stop
    /// the import (e.g. one store skipped, an undated session included anyway).
    Warn,
    /// A problem that prevented a unit of work (e.g. a store could not be read).
    Error,
}

/// A human-surfaced diagnostic from discovery or read.
///
/// Sources emit these instead of swallowing IO problems silently: a locked or
/// corrupt store, a permission error, or a tolerated-but-notable condition
/// becomes a `Diag` that the CLI prints in its summary. Record-*shape* drift, by
/// contrast, is tolerated *inside the adapter* (an empty event `Vec`), not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diag {
    /// How serious the condition is.
    pub level: Level,
    /// The file or directory the diagnostic concerns.
    pub origin: PathBuf,
    /// A short, user-facing message (already free of payload bodies).
    pub msg: String,
}

impl Diag {
    /// Build a [`Level::Warn`] diagnostic.
    #[must_use]
    pub fn warn(origin: impl Into<PathBuf>, msg: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            origin: origin.into(),
            msg: msg.into(),
        }
    }

    /// Build a [`Level::Error`] diagnostic.
    #[must_use]
    pub fn error(origin: impl Into<PathBuf>, msg: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            origin: origin.into(),
            msg: msg.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery results
// ---------------------------------------------------------------------------

/// Where a discovered session physically lives, so [`SessionSource::read`] can
/// reopen it.
///
/// Different tools store a conversation as a row keyed inside a shared DB
/// ([`SessionLocator::Key`]), a standalone file ([`SessionLocator::File`]), or a
/// directory tree assembled in order ([`SessionLocator::Dir`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionLocator {
    /// A logical key inside the store at [`DiscoveredSession::origin`] (e.g. a
    /// Cursor `composerData:{id}` / `bubbleId:{composer}:…` key).
    Key(String),
    /// A standalone file holding the whole session (e.g. a Gemini/Continue JSON
    /// transcript).
    File(PathBuf),
    /// A directory whose contents are assembled into one session (e.g. an
    /// OpenCode message/part tree).
    Dir(PathBuf),
}

/// A session found on disk by [`SessionSource::discover`], described cheaply
/// (stat + bounded structural counts only — **no payload bodies**).
///
/// The `import_id` is the globally-unique selector used by `--session` and by
/// the deterministic id derivations: `"{origin_fingerprint}:{native_key}"`,
/// where `origin_fingerprint` namespaces an otherwise-ambiguous native key
/// across stores (see [`origin_fingerprint`]). `native_id` is the human-readable
/// native key shown to users.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredSession {
    /// The tool that owns this store (matches the source's [`SessionSource::tool`]).
    pub tool: String,
    /// The tool's native session key (shown to users; not globally unique).
    pub native_id: String,
    /// Globally-unique selector: `"{origin_fingerprint}:{native_key}"`.
    pub import_id: String,
    /// The store file/dir this session was discovered in.
    pub origin: PathBuf,
    /// How to reopen the session for reading.
    pub locator: SessionLocator,
    /// A short human title for the session, if the store records one.
    pub title: Option<String>,
    /// Last-activity time, if the store records one (used by `--since`).
    pub last_active: Option<MicrosTimestamp>,
    /// The store's modification time — the deterministic timestamp base when a
    /// record carries no native timestamp of its own.
    pub mtime: MicrosTimestamp,
    /// A bounded structural message count (row/key `COUNT`, array length), if it
    /// can be obtained without parsing bodies. `None` when even a count would
    /// require a full parse.
    pub approx_messages: Option<usize>,
    /// The workspace/project this session belongs to, if known.
    pub workspace: Option<String>,
}

impl DiscoveredSession {
    /// Build the `import_id` for `(origin_fingerprint, native_key)` — the
    /// globally-unique `"{fp}:{key}"` selector. Centralized so every call site
    /// (and Wave 2 sources) format it identically.
    #[must_use]
    pub fn make_import_id(origin_fp: &str, native_key: &str) -> String {
        format!("{origin_fp}:{native_key}")
    }
}

/// The raw records read out of one source session, opaque to this crate.
///
/// These [`serde_json::Value`]s are handed straight to a harness adapter, which
/// is the only component that inspects, redacts, and turns them into [`Event`]s.
/// `session_meta` carries store-level metadata (title, workspace, native
/// timestamps) the adapter may fold into the session header.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionRecords {
    /// The tool's native session key these records belong to.
    pub native_id: String,
    /// The per-message/turn records, in source order. Opaque here.
    pub records: Vec<serde_json::Value>,
    /// Session-level metadata (opaque here; interpreted by the adapter).
    pub session_meta: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Neutral output contract (the CLI persists these; no store/inventory deps)
// ---------------------------------------------------------------------------

/// The neutral, persistence-free header for an imported session.
///
/// The CLI maps this directly onto `logbook_inventory::AgentSessionRecord`
/// (field types are chosen to match: `started_at: i64`, `ended_at:
/// Option<i64>`) and calls `insert_agent_session`, then persists the events.
/// This header is **mandatory**: the Sessions list/replay reads the
/// `agent_sessions` row first, so events alone are not enough. Every field is
/// deterministic (derived ids; min/max record timestamp or `mtime`) — never
/// `now()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSessionHeader {
    /// `import_session_id(...)` — also every event's `session_id` and the
    /// `agent_sessions.id`.
    pub session_id: String,
    /// `import_trace_id(...)` rendered as hex — the trace shared by the events.
    pub trace_id: String,
    /// The owning tool (the `agent` column), e.g. `cursor`.
    pub agent: String,
    /// A synthetic command line, e.g. `import:cursor`.
    pub command: String,
    /// Session start, microseconds (maps to `AgentSessionRecord::started_at`).
    pub started_at: i64,
    /// Session end, microseconds (maps to `AgentSessionRecord::ended_at`).
    pub ended_at: Option<i64>,
}

/// The neutral result of importing one session: a header, the redacted events,
/// and any diagnostics gathered along the way.
///
/// Produced by [`runner::import_session`]; consumed (persisted) by the CLI.
/// Carries no `logbook-store`/`logbook-inventory` types, so this crate stays free
/// of those dependencies.
#[derive(Clone, Debug)]
pub struct ImportBatch {
    /// The mandatory session header (→ `AgentSessionRecord` in the CLI).
    pub header: ImportSessionHeader,
    /// The redacted events for this session, ready to persist.
    pub events: Vec<Event>,
    /// Diagnostics surfaced while reading/building this session.
    pub diagnostics: Vec<Diag>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure reading a source store.
///
/// IO failures (lock, corruption, permission, unsupported store) surface as
/// `Err` so the runner can emit a [`Diag`] and skip the session. Record-*shape*
/// drift does **not** belong here — that is tolerated inside the adapter (an
/// empty event `Vec`).
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// A filesystem error opening or reading the store.
    #[error("I/O error reading {origin}: {source}")]
    Io {
        /// The store the error concerns.
        origin: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A SQLite error (open/query) against a DB-backed store.
    #[error("SQLite error reading {origin}: {source}")]
    Sqlite {
        /// The store the error concerns.
        origin: PathBuf,
        /// The underlying error.
        source: rusqlite::Error,
    },
    /// The store's JSON could not be parsed.
    #[error("malformed JSON in {origin}: {source}")]
    Json {
        /// The store the error concerns.
        origin: PathBuf,
        /// The underlying parse error.
        source: serde_json::Error,
    },
    /// The store is locked by the running tool (e.g. `SQLITE_BUSY`); the user
    /// should close the tool and retry.
    #[error("{origin} is locked (close the tool and re-run): {detail}")]
    Locked {
        /// The store the error concerns.
        origin: PathBuf,
        /// A short detail string.
        detail: String,
    },
    /// This source does not (yet) support reading — the Wave 1 placeholder
    /// arms return this so the crate compiles before the real readers land.
    #[error("import for {tool} is not yet implemented")]
    Unsupported {
        /// The tool whose source is unimplemented.
        tool: String,
    },
}

// ---------------------------------------------------------------------------
// The source trait
// ---------------------------------------------------------------------------

/// Reads one tool's on-disk conversation stores.
///
/// Implementors own the (drift-prone) knowledge of a single tool's storage
/// format. Discovery is cheap and total; reading is fallible so native IO
/// problems surface as [`ReadError`] (→ a [`Diag`] in the runner) rather than
/// silent loss.
pub trait SessionSource {
    /// The tool this source reads. **Must** equal the matching harness adapter's
    /// name, and the `tool` stamped on every [`DiscoveredSession`] it returns.
    fn tool(&self) -> &str;

    /// Cheaply enumerate sessions under `roots`.
    ///
    /// Stat + keys + bounded structural counts only — **never** payload bodies.
    /// IO problems become [`Diag`]s in the second tuple element, not silence; a
    /// source that finds nothing returns two empty `Vec`s.
    fn discover(&self, roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>);

    /// Read one discovered session's raw records.
    ///
    /// # Errors
    /// Returns [`ReadError`] on an IO/lock/corruption/unsupported condition; the
    /// runner turns that into a [`Diag`] and skips the session. Record-shape
    /// drift is *not* an error here — that is tolerated later, inside the
    /// adapter.
    fn read(&self, session: &DiscoveredSession) -> Result<SessionRecords, ReadError>;
}

// ---------------------------------------------------------------------------
// Tool enum
// ---------------------------------------------------------------------------

/// The coding tools this crate can import from.
///
/// Deliberately free of `clap` derives: the CLI owns its own `ValueEnum`; this
/// enum is the library-level dispatch key. Mirrors the harness adapter names via
/// [`Tool::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tool {
    /// The Cursor IDE (SQLite `state.vscdb` bubble stores).
    Cursor,
    /// The Gemini CLI/assistant (JSON transcripts).
    Gemini,
    /// The Continue extension (JSON history).
    Continue,
}

impl Tool {
    /// Every supported tool, for callers that enumerate (e.g. `discover_all`).
    pub const ALL: &'static [Tool] = &[Tool::Cursor, Tool::Gemini, Tool::Continue];

    /// The stable lowercase name (matches the harness adapter name and the
    /// `tool` field on [`DiscoveredSession`]).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Tool::Cursor => "cursor",
            Tool::Gemini => "gemini",
            Tool::Continue => "continue",
        }
    }
}

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error returned when a string does not name a known [`Tool`].
#[derive(Debug, thiserror::Error)]
#[error("unknown import tool {0:?} (expected one of: cursor, gemini, continue)")]
pub struct UnknownTool(pub String);

impl FromStr for Tool {
    type Err = UnknownTool;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cursor" => Ok(Tool::Cursor),
            "gemini" => Ok(Tool::Gemini),
            "continue" => Ok(Tool::Continue),
            other => Err(UnknownTool(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic id helpers
// ---------------------------------------------------------------------------

/// Domain-separation tag for trace-id derivation.
const TRACE_TAG: &[u8] = b"lb-import/trace/v1\0";
/// Domain-separation tag for session-id derivation.
const SESSION_TAG: &[u8] = b"lb-import/session/v1\0";

/// Fingerprint a store's `origin` path into a stable hex string.
///
/// Two workspace DBs can share the same legacy native key, so every id
/// derivation namespaces by where the store lives. Best-effort canonicalizes the
/// path (so equivalent paths fingerprint identically) and falls back to the raw
/// path bytes when canonicalization fails (e.g. the path no longer exists). The
/// result is `hex(fnv1a_128(path_bytes))`, 32 lowercase hex chars.
#[must_use]
pub fn origin_fingerprint(origin: &Path) -> String {
    let canonical = std::fs::canonicalize(origin).unwrap_or_else(|_| origin.to_path_buf());
    hex_lower(&fnv1a_128(path_bytes(&canonical).as_ref()))
}

/// Derive the deterministic [`TraceId`] for a source session.
///
/// `fnv1a_128(b"lb-import/trace/v1\0" ‖ tool ‖ 0 ‖ origin_fp ‖ 0 ‖ native_key)`,
/// **nonzero-guarded** (note `TraceId::from_bytes` accepts the all-zero value,
/// which is invalid), then `TraceId::from_bytes`. The domain-separation tag and
/// `tool` prefix prevent cross-tool collisions; `origin_fp` prevents
/// cross-store collisions of an otherwise-ambiguous `native_key`.
#[must_use]
pub fn import_trace_id(tool: Tool, origin_fp: &str, native_key: &str) -> TraceId {
    let digest = derive_16(TRACE_TAG, tool, origin_fp, native_key);
    TraceId::from_bytes(digest)
}

/// Derive the deterministic session id for a source session, as hex.
///
/// Same inputs as [`import_trace_id`] but under the
/// `b"lb-import/session/v1\0"` tag, so the trace id and session id never
/// coincide. Used for **both** every `Event.session_id` and the
/// `agent_sessions` row id, rendered as 32 lowercase hex chars.
#[must_use]
pub fn import_session_id(tool: Tool, origin_fp: &str, native_key: &str) -> String {
    let digest = derive_16(SESSION_TAG, tool, origin_fp, native_key);
    hex_lower(&digest)
}

/// Shared derivation: `fnv1a_128(tag ‖ tool ‖ 0 ‖ origin_fp ‖ 0 ‖ native_key)`,
/// nonzero-guarded.
fn derive_16(tag: &[u8], tool: Tool, origin_fp: &str, native_key: &str) -> [u8; 16] {
    let tool = tool.as_str().as_bytes();
    let fp = origin_fp.as_bytes();
    let key = native_key.as_bytes();
    let mut buf = Vec::with_capacity(tag.len() + tool.len() + 1 + fp.len() + 1 + key.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(tool);
    buf.push(0u8);
    buf.extend_from_slice(fp);
    buf.push(0u8);
    buf.extend_from_slice(key);

    let mut digest = fnv1a_128(&buf);
    if digest == [0u8; 16] {
        digest[15] = 0x01;
    }
    digest
}

/// Lowercase-hex encode a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// The bytes of a path for hashing. Uses the OS-native byte view where possible
/// so non-UTF-8 paths still fingerprint stably; falls back to the lossy form on
/// platforms without `OsStr` byte access.
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::borrow::Cow::Borrowed(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::borrow::Cow::Owned(path.to_string_lossy().into_owned().into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Source dispatch
// ---------------------------------------------------------------------------

/// Construct the [`SessionSource`] for `tool`.
///
/// Every arm now returns a concrete reader (Wave 2 wired Cursor; Wave 3 wired the
/// Gemini + Continue JSON sources), so this never produces a no-op source.
/// Callers that just want results should prefer [`discover_sessions`] /
/// [`discover_all_sessions`].
#[must_use]
pub fn source_for(tool: Tool) -> Box<dyn SessionSource> {
    match tool {
        Tool::Cursor => Box::new(CursorSource::new()),
        Tool::Gemini => Box::new(GeminiSource::new()),
        Tool::Continue => Box::new(ContinueSource::new()),
    }
}

/// Discover all sessions for a single `tool` under `roots`.
///
/// Thin dispatch over [`source_for`]; read-only and body-free. Returns the
/// discovered sessions and any discovery [`Diag`]s.
#[must_use]
pub fn discover_sessions(tool: Tool, roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
    source_for(tool).discover(roots)
}

/// Discover sessions for **every** supported tool under `roots`.
///
/// Used by `inventory scan` to surface native conversation stores read-only.
/// Aggregates each tool's [`discover_sessions`] output, preserving the
/// per-tool order in [`Tool::ALL`].
#[must_use]
pub fn discover_all_sessions(roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
    let mut sessions = Vec::new();
    let mut diags = Vec::new();
    for &tool in Tool::ALL {
        let (mut s, mut d) = discover_sessions(tool, roots);
        sessions.append(&mut s);
        diags.append(&mut d);
    }
    (sessions, diags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_roundtrips_through_str() {
        for &t in Tool::ALL {
            assert_eq!(Tool::from_str(t.as_str()).unwrap(), t);
        }
        assert!(Tool::from_str("windsurf").is_err());
    }

    #[test]
    fn import_ids_are_deterministic_and_distinct() {
        let fp = "00112233445566778899aabbccddeeff";
        let key = "composerData:abc";
        let trace = import_trace_id(Tool::Cursor, fp, key);
        assert_eq!(trace, import_trace_id(Tool::Cursor, fp, key));
        assert!(!trace.is_zero());

        let sid = import_session_id(Tool::Cursor, fp, key);
        assert_eq!(sid, import_session_id(Tool::Cursor, fp, key));
        assert_eq!(sid.len(), 32);
        // Trace and session derivations differ (distinct domain tags).
        assert_ne!(trace.to_hex(), sid);
    }

    #[test]
    fn origin_fingerprint_namespaces_native_key() {
        // The SAME native key in two different stores must yield different
        // trace/session ids (the cross-workspace collision the fingerprint
        // prevents).
        let key = "workbench.panel.aichat.view.aichat.chatdata";
        let fp_a = origin_fingerprint(Path::new("/ws/a/state.vscdb"));
        let fp_b = origin_fingerprint(Path::new("/ws/b/state.vscdb"));
        assert_ne!(fp_a, fp_b);
        assert_ne!(
            import_trace_id(Tool::Cursor, &fp_a, key),
            import_trace_id(Tool::Cursor, &fp_b, key)
        );
        assert_ne!(
            import_session_id(Tool::Cursor, &fp_a, key),
            import_session_id(Tool::Cursor, &fp_b, key)
        );
    }

    #[test]
    fn cross_tool_ids_differ() {
        let fp = "deadbeefdeadbeefdeadbeefdeadbeef";
        let key = "same-key";
        assert_ne!(
            import_trace_id(Tool::Cursor, fp, key),
            import_trace_id(Tool::Gemini, fp, key)
        );
    }

    #[test]
    fn origin_fingerprint_is_32_hex() {
        let fp = origin_fingerprint(Path::new("/nonexistent/path/state.vscdb"));
        assert_eq!(fp.len(), 32);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn make_import_id_is_fp_colon_key() {
        assert_eq!(
            DiscoveredSession::make_import_id("abc", "key:1"),
            "abc:key:1"
        );
    }

    #[test]
    fn every_source_discovers_nothing_under_empty_roots() {
        // With empty roots every (now-concrete) source finds nothing without
        // erroring — discovery is total and tolerant.
        let roots = DataRoots::default();
        for &tool in Tool::ALL {
            let (sessions, diags) = discover_sessions(tool, &roots);
            assert!(sessions.is_empty(), "{tool} found sessions under empty roots");
            assert!(diags.is_empty(), "{tool} emitted diags under empty roots");
        }
        let (all, all_diags) = discover_all_sessions(&roots);
        assert!(all.is_empty());
        assert!(all_diags.is_empty());
    }

    #[test]
    fn json_sources_read_of_missing_file_surfaces_io_error() {
        // Every Wave-3 JSON source is concrete now (no Unsupported placeholder):
        // reading a session whose backing file does not exist surfaces an IO
        // error, never `Unsupported`.
        let probe = DiscoveredSession {
            tool: "gemini".into(),
            native_id: "k".into(),
            import_id: "fp:k".into(),
            origin: PathBuf::from("/nonexistent/import/session-x.json"),
            locator: SessionLocator::File(PathBuf::from("/nonexistent/import/session-x.json")),
            title: None,
            last_active: None,
            mtime: MicrosTimestamp(0),
            approx_messages: None,
            workspace: None,
        };
        for tool in [Tool::Gemini, Tool::Continue] {
            assert!(
                matches!(source_for(tool).read(&probe), Err(ReadError::Io { .. })),
                "{tool} read of a missing file must be an IO error"
            );
        }
    }
}
