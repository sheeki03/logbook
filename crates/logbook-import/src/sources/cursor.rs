//! Cursor source — reads Cursor's `state.vscdb` SQLite stores (plan "Phase 0").
//!
//! Cursor persists conversations in four layouts across two store locations.
//! This source discovers and reads all four, **read-only**, and flattens each
//! into the uniform bubble-record shape the
//! [`CursorAdapter`](logbook_harness::CursorAdapter) consumes (documented on
//! that adapter). It never persists, redacts, or builds events — it moves only
//! opaque [`serde_json::Value`]s.
//!
//! ## Store locations
//! - **Workspace** stores: `…/Cursor/User/workspaceStorage/{hash}/state.vscdb`.
//!   Each holds an `ItemTable` with the legacy chat key
//!   (`workbench.panel.aichat.view.aichat.chatdata`), the workspace-composer key
//!   (`composer.composerData`), and the old `aiService.prompts` /
//!   `aiService.generations` paired arrays.
//! - **Global** store: `…/Cursor/User/globalStorage/state.vscdb`. Holds a
//!   `cursorDiskKV` table with global composers (`composerData:{id}`, either
//!   inline `conversation[]` or via separate `bubbleId:{composer}:{bubble}`
//!   rows).
//!
//! ## Variants → one session each
//! A discovered session is one of:
//! - [`CursorVariant::Chat`] — one legacy chat **tab** in the `ItemTable` chat
//!   key (native key `chat:{tabId}`).
//! - [`CursorVariant::WorkspaceComposer`] — one composer in
//!   `composer.composerData.allComposers` (native key `wscomposer:{composerId}`).
//! - [`CursorVariant::AiService`] — the whole old paired-array conversation in a
//!   workspace store (native key `aiService`).
//! - [`CursorVariant::GlobalComposer`] — one global composer row
//!   `composerData:{id}` (native key the composer id), inline or separate.
//!
//! ## Read-only open (plan §10)
//! Opens with `Connection::open_with_flags(path, SQLITE_OPEN_READ_ONLY)` (a real
//! `&Path` — no URI string, so spaces/unicode just work), then
//! `busy_timeout(2000ms)` + `PRAGMA query_only=ON`. A persistent `SQLITE_BUSY`
//! maps to [`ReadError::Locked`]; other sqlite errors to [`ReadError::Sqlite`];
//! a stored value that is not valid JSON to [`ReadError::Json`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

use logbook_core::MicrosTimestamp;

use crate::discovery::DataRoots;
use crate::{
    origin_fingerprint, Diag, DiscoveredSession, ReadError, SessionLocator, SessionRecords,
    SessionSource,
};

/// The legacy chat-mode key (workspace `ItemTable`).
const KEY_CHAT: &str = "workbench.panel.aichat.view.aichat.chatdata";
/// The workspace-composer key (workspace `ItemTable`).
const KEY_WS_COMPOSER: &str = "composer.composerData";
/// The old aiService prompt-array key (workspace `ItemTable`).
const KEY_AISERVICE_PROMPTS: &str = "aiService.prompts";
/// The old aiService generation-array key (workspace `ItemTable`).
const KEY_AISERVICE_GENERATIONS: &str = "aiService.generations";

/// Busy-timeout for a brief writer lock (Cursor running) before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_millis(2000);

/// Which Cursor storage layout a discovered session came from. Carried in the
/// native key prefix so [`CursorSource::read`] reopens the right store + query
/// without re-walking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CursorVariant {
    /// Legacy chat tab (`ItemTable` chat key).
    Chat,
    /// Workspace composer (`ItemTable` `composer.composerData`).
    WorkspaceComposer,
    /// Old paired prompt/generation arrays (`ItemTable` aiService keys).
    AiService,
    /// Global composer row (`cursorDiskKV` `composerData:{id}`).
    GlobalComposer,
}

/// The [`SessionSource`] for Cursor.
///
/// Stateless: all per-session state lives on the [`DiscoveredSession`] it
/// returns (the `origin` store + the variant-prefixed `native_id`), so a single
/// instance discovers and reads any number of sessions.
#[derive(Debug, Default)]
pub struct CursorSource;

impl CursorSource {
    /// The stable tool name (matches the adapter's `NAME`).
    pub const NAME: &'static str = "cursor";

    /// Construct a Cursor source.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SessionSource for CursorSource {
    fn tool(&self) -> &str {
        Self::NAME
    }

    fn discover(&self, roots: &DataRoots) -> (Vec<DiscoveredSession>, Vec<Diag>) {
        let mut sessions = Vec::new();
        let mut diags = Vec::new();
        for store in cursor_stores(roots, &mut diags) {
            discover_in_store(&store, &mut sessions, &mut diags);
        }
        (sessions, diags)
    }

    fn read(&self, session: &DiscoveredSession) -> Result<SessionRecords, ReadError> {
        let conn = open_readonly(&session.origin)?;
        let (variant, key) = split_native(&session.native_id);
        let records = match variant {
            CursorVariant::Chat => read_chat_tab(&conn, &session.origin, key)?,
            CursorVariant::WorkspaceComposer => {
                read_workspace_composer(&conn, &session.origin, key)?
            }
            CursorVariant::AiService => read_aiservice(&conn, &session.origin)?,
            CursorVariant::GlobalComposer => read_global_composer(&conn, &session.origin, key)?,
        };
        Ok(SessionRecords {
            native_id: session.native_id.clone(),
            records,
            session_meta: session_meta(session),
        })
    }
}

// ---------------------------------------------------------------------------
// Store enumeration
// ---------------------------------------------------------------------------

/// A discovered Cursor store on disk, with its modification time (the
/// deterministic timestamp base).
///
/// Whether a store is a workspace store (`ItemTable`) or the global store
/// (`cursorDiskKV`) is determined at discovery time by probing which tables it
/// actually has ([`probe_tables`]), not by its path — so a `--path` pointed
/// straight at a global store still reads correctly.
struct CursorStore {
    /// The `state.vscdb` path.
    path: PathBuf,
    /// The store's `mtime`, microseconds.
    mtime: MicrosTimestamp,
    /// The workspace hash (the `workspaceStorage/{hash}` dir name), if known.
    workspace: Option<String>,
}

/// Walk the data roots for every Cursor `state.vscdb` store, recording each
/// store's `mtime`. IO problems (an unreadable dir) become [`Diag`]s, never
/// silent loss.
///
/// Under each root we look for both `Cursor/User/workspaceStorage/{hash}/state.vscdb`
/// and `Cursor/User/globalStorage/state.vscdb`. The `--path` override may point
/// directly at a `state.vscdb` file (treated as a workspace store) or at a
/// directory containing the Cursor layout.
fn cursor_stores(roots: &DataRoots, diags: &mut Vec<Diag>) -> Vec<CursorStore> {
    let mut stores = Vec::new();
    for root in &roots.roots {
        // `--path` may name the `state.vscdb` file itself. Its variant is decided
        // later by probing its tables, not by the path.
        if root.is_file() {
            if let Some(store) = store_from_file(root, None) {
                stores.push(store);
            }
            continue;
        }

        // Otherwise treat `root` as a base that *might* contain the Cursor
        // layout, OR be a Cursor user dir directly (fixtures often pass the
        // `…/User` dir or a dir holding `state.vscdb`).
        for base in cursor_user_dirs(root) {
            collect_workspace_stores(&base, diags, &mut stores);
            collect_global_store(&base, &mut stores);
        }
    }
    stores
}

/// Candidate `Cursor/User` directories under `root` (the standard layout), plus
/// `root` itself (so a fixture passing a `…/User` dir, or a dir that directly
/// holds `workspaceStorage`/`globalStorage`, is honoured).
fn cursor_user_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let standard = root.join("Cursor").join("User");
    if standard.is_dir() {
        dirs.push(standard);
    }
    // A direct `…/User`-style dir (holds workspaceStorage/globalStorage).
    if root.join("workspaceStorage").is_dir() || root.join("globalStorage").is_dir() {
        dirs.push(root.to_path_buf());
    }
    dirs
}

/// Collect every workspace store `workspaceStorage/{hash}/state.vscdb` under a
/// `…/User` dir. An unreadable `workspaceStorage` dir becomes a warning.
fn collect_workspace_stores(user_dir: &Path, diags: &mut Vec<Diag>, out: &mut Vec<CursorStore>) {
    let ws_root = user_dir.join("workspaceStorage");
    if !ws_root.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(&ws_root) {
        Ok(e) => e,
        Err(e) => {
            diags.push(Diag::warn(
                ws_root.clone(),
                format!("could not read Cursor workspaceStorage: {e}"),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        // Skip the dev sentinel dir Cursor keeps (mirrors the reference script).
        if dir.file_name().map(|n| n == "ext-dev").unwrap_or(false) {
            continue;
        }
        let db = dir.join("state.vscdb");
        if db.is_file() {
            let workspace = dir.file_name().map(|n| n.to_string_lossy().into_owned());
            if let Some(store) = store_from_file(&db, workspace) {
                out.push(store);
            }
        }
    }
}

/// Collect the single global store `globalStorage/state.vscdb` under a `…/User`
/// dir, if present.
fn collect_global_store(user_dir: &Path, out: &mut Vec<CursorStore>) {
    let db = user_dir.join("globalStorage").join("state.vscdb");
    if db.is_file() {
        if let Some(store) = store_from_file(&db, None) {
            out.push(store);
        }
    }
}

/// Build a [`CursorStore`] from a `state.vscdb` path, reading its `mtime`. The
/// `mtime` is the deterministic timestamp base; a store whose mtime cannot be
/// read falls back to `0` (still deterministic for an unchanged file).
fn store_from_file(path: &Path, workspace: Option<String>) -> Option<CursorStore> {
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0);
    Some(CursorStore {
        path: path.to_path_buf(),
        mtime: MicrosTimestamp(mtime),
        workspace,
    })
}

// ---------------------------------------------------------------------------
// Per-store discovery (cheap: keys + bounded structural counts, no bodies)
// ---------------------------------------------------------------------------

/// Discover every session in one store, appending to `sessions` (and any
/// problems to `diags`). A store that cannot be opened/probed becomes **one**
/// [`Diag`] (locked ⇒ warn so the rest of discovery proceeds; corrupt/other ⇒
/// error) rather than one-per-key noise.
fn discover_in_store(store: &CursorStore, sessions: &mut Vec<DiscoveredSession>, diags: &mut Vec<Diag>) {
    let conn = match open_readonly(&store.path) {
        Ok(c) => c,
        Err(e) => {
            push_store_diag(diags, &store.path, &e);
            return;
        }
    };

    // Probe which tables exist ONCE. This first real query is also where a
    // corrupt header or a held lock surfaces — collapse it to a single diagnostic
    // instead of one per missing key. The presence of `cursorDiskKV` vs
    // `ItemTable` also routes the store, overriding the path-based `global` guess
    // (so a `--path` pointed straight at a global store still reads correctly).
    let tables = match probe_tables(&conn, &store.path) {
        Ok(t) => t,
        Err(e) => {
            push_store_diag(diags, &store.path, &e);
            return;
        }
    };

    let fp = origin_fingerprint(&store.path);
    if tables.disk_kv {
        discover_global_composers(&conn, store, &fp, sessions, diags);
    }
    if tables.item_table {
        discover_chat_tabs(&conn, store, &fp, sessions, diags);
        discover_workspace_composers(&conn, store, &fp, sessions, diags);
        discover_aiservice(&conn, store, &fp, sessions, diags);
    }
}

/// Push one store-level diagnostic for a read failure: a lock is a recoverable
/// warning (close the tool and retry), anything else (corruption, permission) is
/// an error. Keeps the "locked ⇒ warn, other ⇒ error" policy in one place.
fn push_store_diag(diags: &mut Vec<Diag>, path: &Path, err: &ReadError) {
    match err {
        ReadError::Locked { detail, .. } => diags.push(Diag::warn(
            path.to_path_buf(),
            format!("Cursor store is locked (close Cursor and re-run): {detail}"),
        )),
        other => diags.push(Diag::error(path.to_path_buf(), other.to_string())),
    }
}

/// Which Cursor tables a store has. Workspace stores carry `ItemTable`; the
/// global store carries `cursorDiskKV`; some stores carry both.
#[derive(Clone, Copy, Debug, Default)]
struct StoreTables {
    item_table: bool,
    disk_kv: bool,
}

/// Probe `sqlite_master` for the Cursor tables. This is the first real query
/// against the store, so a corrupt header / held lock surfaces here as a single
/// [`ReadError`] (mapped to one diagnostic by the caller).
fn probe_tables(conn: &Connection, origin: &Path) -> Result<StoreTables, ReadError> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ItemTable','cursorDiskKV')")
        .map_err(|s| map_sqlite(origin, s))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|s| map_sqlite(origin, s))?;
    let mut tables = StoreTables::default();
    for name in names {
        match name.map_err(|s| map_sqlite(origin, s))?.as_str() {
            "ItemTable" => tables.item_table = true,
            "cursorDiskKV" => tables.disk_kv = true,
            _ => {}
        }
    }
    Ok(tables)
}

/// Read a single `ItemTable` value by key as JSON, if present. `Ok(None)` when
/// the key is absent; an `Err` for a real sqlite/JSON failure.
fn item_table_json(conn: &Connection, origin: &Path, key: &str) -> Result<Option<Value>, ReadError> {
    let raw: Option<String> = query_opt_string(
        conn,
        origin,
        "SELECT value FROM ItemTable WHERE key = ?1",
        [key],
    )?;
    parse_opt_json(origin, raw)
}

/// Discover legacy chat tabs in a workspace store (one session per non-empty
/// tab). Cheap: counts the bubbles per tab structurally; bodies are not built.
fn discover_chat_tabs(
    conn: &Connection,
    store: &CursorStore,
    fp: &str,
    sessions: &mut Vec<DiscoveredSession>,
    diags: &mut Vec<Diag>,
) {
    let data = match item_table_json(conn, &store.path, KEY_CHAT) {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            diags.push(Diag::warn(store.path.clone(), format!("chat key unreadable: {e}")));
            return;
        }
    };
    let Some(tabs) = data.get("tabs").and_then(Value::as_array) else {
        return;
    };
    for (i, tab) in tabs.iter().enumerate() {
        let bubbles = tab.get("bubbles").and_then(Value::as_array);
        let count = bubbles.map(|a| a.len()).unwrap_or(0);
        if count == 0 {
            continue;
        }
        // Prefer a stable tab id; fall back to the ordinal so the native key is
        // always present + reproducible.
        let tab_id = tab
            .get("tabId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| i.to_string());
        let title = tab
            .get("chatTitle")
            .and_then(Value::as_str)
            .map(str::to_string);
        sessions.push(make_session(
            store,
            fp,
            CursorVariant::Chat,
            &tab_id,
            title,
            Some(count),
        ));
    }
}

/// Discover workspace composers (`composer.composerData.allComposers`), one
/// session each. Counts conversation bubbles structurally.
fn discover_workspace_composers(
    conn: &Connection,
    store: &CursorStore,
    fp: &str,
    sessions: &mut Vec<DiscoveredSession>,
    diags: &mut Vec<Diag>,
) {
    let data = match item_table_json(conn, &store.path, KEY_WS_COMPOSER) {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            diags.push(Diag::warn(
                store.path.clone(),
                format!("workspace composer key unreadable: {e}"),
            ));
            return;
        }
    };
    let Some(all) = data.get("allComposers").and_then(Value::as_array) else {
        return;
    };
    for (i, composer) in all.iter().enumerate() {
        let count = composer
            .get("conversation")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        if count == 0 {
            continue;
        }
        let id = composer
            .get("composerId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| i.to_string());
        let title = composer
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string);
        sessions.push(make_session(
            store,
            fp,
            CursorVariant::WorkspaceComposer,
            &id,
            title,
            Some(count),
        ));
    }
}

/// Discover the old aiService paired-array conversation (one session per store
/// when present). Counts `max(len(prompts), len(generations))`.
fn discover_aiservice(
    conn: &Connection,
    store: &CursorStore,
    fp: &str,
    sessions: &mut Vec<DiscoveredSession>,
    diags: &mut Vec<Diag>,
) {
    let prompts = match item_table_json(conn, &store.path, KEY_AISERVICE_PROMPTS) {
        Ok(v) => v,
        Err(e) => {
            diags.push(Diag::warn(store.path.clone(), format!("aiService.prompts unreadable: {e}")));
            None
        }
    };
    let gens = match item_table_json(conn, &store.path, KEY_AISERVICE_GENERATIONS) {
        Ok(v) => v,
        Err(e) => {
            diags.push(Diag::warn(
                store.path.clone(),
                format!("aiService.generations unreadable: {e}"),
            ));
            None
        }
    };
    let plen = prompts.as_ref().and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    let glen = gens.as_ref().and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    let count = plen.max(glen);
    if count == 0 {
        return;
    }
    sessions.push(make_session(
        store,
        fp,
        CursorVariant::AiService,
        "conversation",
        Some("aiService conversation".to_string()),
        Some(count),
    ));
}

/// Discover global composers (`cursorDiskKV` rows `composerData:{id}`), one
/// session each. The bounded count is the inline `conversation[]` length, or the
/// number of `bubbleId:{composer}:%` rows for separate storage (a cheap `COUNT`).
fn discover_global_composers(
    conn: &Connection,
    store: &CursorStore,
    fp: &str,
    sessions: &mut Vec<DiscoveredSession>,
    diags: &mut Vec<Diag>,
) {
    // Pull (key, value) for every composer head row. The value can be large but
    // we only read its top-level structure (composerId, name, conversation len),
    // not message bodies.
    let rows = match query_kv_like(conn, &store.path, "composerData:%") {
        Ok(r) => r,
        Err(ReadError::Sqlite { .. }) => {
            // No `cursorDiskKV` table (or query failure) ⇒ nothing to discover
            // here; not fatal for the rest of discovery.
            return;
        }
        Err(e) => {
            diags.push(Diag::warn(store.path.clone(), format!("global composers unreadable: {e}")));
            return;
        }
    };
    for (key, value) in rows {
        let data: Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(_) => continue, // skip a single corrupt row (tolerant)
        };
        let id = data
            .get("composerId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                key.split_once(':').map(|(_, rest)| rest).unwrap_or("").to_string()
            });
        if id.is_empty() {
            continue;
        }
        let inline_len = data
            .get("conversation")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let count = if inline_len > 0 {
            Some(inline_len)
        } else {
            // Separate storage: a cheap COUNT of the bubble rows.
            count_kv_like(conn, &store.path, &format!("bubbleId:{id}:%")).ok()
        };
        // A composer with neither inline messages nor bubble rows is empty; skip.
        if count == Some(0) {
            continue;
        }
        let title = data.get("name").and_then(Value::as_str).map(str::to_string);
        let last_active = data
            .get("lastUpdatedAt")
            .and_then(Value::as_i64)
            .map(normalize_millis);
        let mut session = make_session(store, fp, CursorVariant::GlobalComposer, &id, title, count);
        session.last_active = last_active.or(session.last_active);
        sessions.push(session);
    }
}

/// Build a [`DiscoveredSession`] for a variant + native key, applying the
/// variant prefix to the native id and deriving the `import_id` from the store
/// fingerprint.
fn make_session(
    store: &CursorStore,
    fp: &str,
    variant: CursorVariant,
    key: &str,
    title: Option<String>,
    approx_messages: Option<usize>,
) -> DiscoveredSession {
    let native_id = join_native(variant, key);
    let import_id = DiscoveredSession::make_import_id(fp, &native_id);
    DiscoveredSession {
        tool: CursorSource::NAME.to_string(),
        native_id,
        import_id,
        origin: store.path.clone(),
        locator: SessionLocator::Key(key.to_string()),
        title,
        // Cursor rarely records a reliable per-conversation last-active for the
        // workspace variants; default to the store mtime (the global-composer
        // path overrides with `lastUpdatedAt` when present).
        last_active: Some(store.mtime),
        mtime: store.mtime,
        approx_messages,
        workspace: store.workspace.clone(),
    }
}

// ---------------------------------------------------------------------------
// Per-variant reads → uniform bubble records
// ---------------------------------------------------------------------------

/// Read one legacy chat tab into bubble records. `coord` = `chat:{tab}:{i}` per
/// bubble (stable across re-imports within an unchanged tab).
fn read_chat_tab(conn: &Connection, origin: &Path, tab_key: &str) -> Result<Vec<Value>, ReadError> {
    let data = item_table_json(conn, origin, KEY_CHAT)?.unwrap_or(Value::Null);
    let tabs = data.get("tabs").and_then(Value::as_array);
    let Some(tabs) = tabs else {
        return Ok(Vec::new());
    };
    // Match the tab by id, else by ordinal (the native key may be the ordinal).
    let tab = tabs
        .iter()
        .enumerate()
        .find(|(i, t)| {
            t.get("tabId").and_then(Value::as_str) == Some(tab_key) || i.to_string() == tab_key
        })
        .map(|(_, t)| t);
    let Some(tab) = tab else {
        return Ok(Vec::new());
    };
    let bubbles = tab.get("bubbles").and_then(Value::as_array);
    let Some(bubbles) = bubbles else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    let mut turn: u64 = 0;
    let mut turn_open = false;
    for (i, bubble) in bubbles.iter().enumerate() {
        // Chat-mode bubbles use a STRING type: "user" / "assistant".
        let ty = bubble.get("type").and_then(Value::as_str).unwrap_or("");
        let role = match ty {
            "user" => "user",
            // Anything non-user in this layout is the model side.
            _ => "assistant",
        };
        advance_turn(role, &mut turn, &mut turn_open);
        let text = bubble
            .get("rawText")
            .and_then(Value::as_str)
            .or_else(|| bubble.get("text").and_then(Value::as_str))
            .unwrap_or("");
        let coord = format!("chat:{tab_key}:{i}");
        let mut rec = base_record(role, text, &coord, turn);
        attach_code_context(&mut rec, bubble.get("selections"));
        attach_tool_results(&mut rec, bubble.get("suggestedDiffs"));
        out.push(rec);
    }
    Ok(out)
}

/// Read one workspace composer into bubble records. `coord` =
/// `wscomposer:{id}:{i}` per bubble.
fn read_workspace_composer(
    conn: &Connection,
    origin: &Path,
    composer_key: &str,
) -> Result<Vec<Value>, ReadError> {
    let data = item_table_json(conn, origin, KEY_WS_COMPOSER)?.unwrap_or(Value::Null);
    let all = data.get("allComposers").and_then(Value::as_array);
    let Some(all) = all else {
        return Ok(Vec::new());
    };
    let composer = all
        .iter()
        .enumerate()
        .find(|(i, c)| {
            c.get("composerId").and_then(Value::as_str) == Some(composer_key)
                || i.to_string() == composer_key
        })
        .map(|(_, c)| c);
    let Some(composer) = composer else {
        return Ok(Vec::new());
    };
    let model = composer
        .get("modelConfig")
        .and_then(|m| m.get("modelName"))
        .and_then(Value::as_str);
    let conversation = composer.get("conversation").and_then(Value::as_array);
    let Some(conversation) = conversation else {
        return Ok(Vec::new());
    };
    Ok(records_from_inline_bubbles(
        conversation,
        &format!("wscomposer:{composer_key}"),
        model,
    ))
}

/// Read the old aiService paired arrays into bubble records. `coord` =
/// `aiService:user:{i}` / `aiService:assistant:{i}` (assistant responses are
/// sparse in this layout — only summaries persist).
fn read_aiservice(conn: &Connection, origin: &Path) -> Result<Vec<Value>, ReadError> {
    let prompts = item_table_json(conn, origin, KEY_AISERVICE_PROMPTS)?
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let gens = item_table_json(conn, origin, KEY_AISERVICE_GENERATIONS)?
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let max = prompts.len().max(gens.len());

    let mut out = Vec::new();
    for i in 0..max {
        let turn = i as u64;
        if let Some(p) = prompts.get(i) {
            let text = p.get("text").and_then(Value::as_str).unwrap_or("");
            if !text.is_empty() {
                out.push(base_record("user", text, &format!("aiService:user:{i}"), turn));
            }
        }
        if let Some(g) = gens.get(i) {
            let text = g
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| g.get("message").and_then(Value::as_str))
                .unwrap_or("");
            let model = g
                .get("model")
                .or_else(|| g.get("modelId"))
                .or_else(|| g.get("modelName"))
                .and_then(Value::as_str);
            // Emit the assistant bubble when it has text OR a model (so the model
            // attribution still lands even when the body is only a summary).
            if !text.is_empty() || model.is_some() {
                let mut rec = base_record("assistant", text, &format!("aiService:assistant:{i}"), turn);
                if let Some(m) = model {
                    rec["model"] = Value::String(m.to_string());
                }
                out.push(rec);
            }
        }
    }
    Ok(out)
}

/// Read one global composer (`composerData:{id}`) into bubble records, handling
/// both inline (`conversation[]`) and separate (`bubbleId:{id}:{bubble}` rows)
/// storage. `coord` = `composerId:{i}` (inline) or the `bubbleId:…` key
/// (separate).
fn read_global_composer(
    conn: &Connection,
    origin: &Path,
    composer_id: &str,
) -> Result<Vec<Value>, ReadError> {
    let key = format!("composerData:{composer_id}");
    let raw = query_opt_string(
        conn,
        origin,
        "SELECT value FROM cursorDiskKV WHERE key = ?1",
        [key.as_str()],
    )?;
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let data: Value = serde_json::from_str(&raw).map_err(|source| ReadError::Json {
        origin: origin.to_path_buf(),
        source,
    })?;
    let model = data
        .get("modelConfig")
        .and_then(|m| m.get("modelName"))
        .and_then(Value::as_str);

    let inline = data.get("conversation").and_then(Value::as_array);
    match inline {
        Some(conversation) if !conversation.is_empty() => Ok(records_from_inline_bubbles(
            conversation,
            &format!("composerId:{composer_id}"),
            model,
        )),
        // Separate storage: assemble the `bubbleId:{id}:%` rows in key order.
        _ => read_separate_bubbles(conn, origin, composer_id, model),
    }
}

/// Read separate-storage bubbles for a global composer: each
/// `bubbleId:{composer}:{bubble}` row is one bubble; `coord` = the row key
/// itself (stable). Rows are ordered by key so the conversation is reproducible.
fn read_separate_bubbles(
    conn: &Connection,
    origin: &Path,
    composer_id: &str,
    model: Option<&str>,
) -> Result<Vec<Value>, ReadError> {
    let pattern = format!("bubbleId:{composer_id}:%");
    let rows = query_kv_like_ordered(conn, origin, &pattern)?;
    let mut out = Vec::new();
    let mut turn: u64 = 0;
    let mut turn_open = false;
    for (key, value) in rows {
        let bubble: Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(_) => continue, // skip a single corrupt bubble row
        };
        let role = bubble_role(&bubble);
        advance_turn(role, &mut turn, &mut turn_open);
        let text = bubble.get("text").and_then(Value::as_str).unwrap_or("");
        let mut rec = base_record(role, text, &key, turn);
        if role == "assistant" {
            if let Some(m) = bubble_model(&bubble).or(model) {
                rec["model"] = Value::String(m.to_string());
            }
            attach_tool_results(&mut rec, bubble.get("toolResults"));
        } else {
            attach_code_context(&mut rec, bubble.get("selections"));
        }
        out.push(rec);
    }
    Ok(out)
}

/// Turn an inline `conversation[]` array (workspace or global) into bubble
/// records. `coord_base` is `composerId:{id}` / `wscomposer:{key}`; each bubble's
/// coord is `{coord_base}:{i}`. `type` is the integer 1=user / 2=assistant.
fn records_from_inline_bubbles(
    conversation: &[Value],
    coord_base: &str,
    composer_model: Option<&str>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let mut turn: u64 = 0;
    let mut turn_open = false;
    for (i, bubble) in conversation.iter().enumerate() {
        let role = bubble_role(bubble);
        advance_turn(role, &mut turn, &mut turn_open);
        let text = bubble.get("text").and_then(Value::as_str).unwrap_or("");
        let coord = format!("{coord_base}:{i}");
        let mut rec = base_record(role, text, &coord, turn);
        if role == "assistant" {
            if let Some(m) = bubble_model(bubble).or(composer_model) {
                rec["model"] = Value::String(m.to_string());
            }
            attach_tool_results(&mut rec, bubble.get("toolResults"));
        } else {
            attach_code_context(&mut rec, bubble.get("context").and_then(|c| c.get("selections")));
        }
        out.push(rec);
    }
    out
}

// ---------------------------------------------------------------------------
// Bubble-record helpers (the source↔adapter contract)
// ---------------------------------------------------------------------------

/// Build a base uniform bubble record `{role, text, coord, turn}`. `text` is
/// omitted (left absent) when empty so the adapter's body-less skip logic fires.
fn base_record(role: &str, text: &str, coord: &str, turn: u64) -> Value {
    let mut rec = serde_json::Map::new();
    rec.insert("role".to_string(), Value::String(role.to_string()));
    if !text.is_empty() {
        rec.insert("text".to_string(), Value::String(text.to_string()));
    }
    rec.insert("coord".to_string(), Value::String(coord.to_string()));
    rec.insert("turn".to_string(), Value::Number(turn.into()));
    Value::Object(rec)
}

/// Attach a non-empty `tool_results` payload to a bubble record, if present.
fn attach_tool_results(rec: &mut Value, tool_results: Option<&Value>) {
    if let Some(v) = tool_results {
        if !v.is_null() && !is_empty_collection(v) {
            rec["tool_results"] = v.clone();
        }
    }
}

/// Attach a non-empty `code_context` payload to a bubble record, if present.
fn attach_code_context(rec: &mut Value, code_context: Option<&Value>) {
    if let Some(v) = code_context {
        if !v.is_null() && !is_empty_collection(v) {
            rec["code_context"] = v.clone();
        }
    }
}

/// Whether a JSON value is an empty array or empty object (so we don't attach a
/// noise field that carries nothing).
fn is_empty_collection(v: &Value) -> bool {
    match v {
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// The role of a `type`-integer bubble: 1 ⇒ user, anything else ⇒ assistant.
fn bubble_role(bubble: &Value) -> &'static str {
    match bubble.get("type").and_then(Value::as_i64) {
        Some(1) => "user",
        _ => "assistant",
    }
}

/// Extract a model name from a bubble's common key spellings.
fn bubble_model(bubble: &Value) -> Option<&str> {
    bubble
        .get("modelId")
        .or_else(|| bubble.get("model"))
        .or_else(|| bubble.get("modelName"))
        .and_then(Value::as_str)
}

/// Advance the turn counter for a bubble role (first user ⇒ 0).
fn advance_turn(role: &str, turn: &mut u64, turn_open: &mut bool) {
    if role == "user" {
        if *turn_open {
            *turn += 1;
        } else {
            *turn_open = true;
        }
    }
}

/// Normalize a Cursor millisecond epoch to microseconds (Cursor stores
/// `createdAt`/`lastUpdatedAt` in ms).
fn normalize_millis(ms: i64) -> MicrosTimestamp {
    MicrosTimestamp(ms.saturating_mul(1000))
}

/// Build the session-level metadata Value handed to the adapter (`title`,
/// `workspace`). Opaque to the import crate; the adapter may fold it in.
fn session_meta(session: &DiscoveredSession) -> Value {
    serde_json::json!({
        "title": session.title,
        "workspace": session.workspace,
        "native_id": session.native_id,
    })
}

// ---------------------------------------------------------------------------
// Native-key encoding (variant ‖ key)
// ---------------------------------------------------------------------------

/// The prefix tag for each variant in the native key.
const TAG_CHAT: &str = "chat";
const TAG_WS_COMPOSER: &str = "wscomposer";
const TAG_AISERVICE: &str = "aiservice";
const TAG_GLOBAL_COMPOSER: &str = "gcomposer";

/// Join a variant + native key into the stored `native_id` (`{tag}/{key}`). The
/// `/` separator never appears in a Cursor composer id / tab id.
fn join_native(variant: CursorVariant, key: &str) -> String {
    let tag = match variant {
        CursorVariant::Chat => TAG_CHAT,
        CursorVariant::WorkspaceComposer => TAG_WS_COMPOSER,
        CursorVariant::AiService => TAG_AISERVICE,
        CursorVariant::GlobalComposer => TAG_GLOBAL_COMPOSER,
    };
    format!("{tag}/{key}")
}

/// Split a stored `native_id` back into its variant + key. An unknown/malformed
/// prefix defaults to [`CursorVariant::GlobalComposer`] with the whole string as
/// the key (defensive; in practice every native id we mint is well-formed).
fn split_native(native_id: &str) -> (CursorVariant, &str) {
    match native_id.split_once('/') {
        Some((TAG_CHAT, key)) => (CursorVariant::Chat, key),
        Some((TAG_WS_COMPOSER, key)) => (CursorVariant::WorkspaceComposer, key),
        Some((TAG_AISERVICE, key)) => (CursorVariant::AiService, key),
        Some((TAG_GLOBAL_COMPOSER, key)) => (CursorVariant::GlobalComposer, key),
        _ => (CursorVariant::GlobalComposer, native_id),
    }
}

// ---------------------------------------------------------------------------
// SQLite plumbing (read-only)
// ---------------------------------------------------------------------------

/// Open a Cursor store **read-only without a URI string** (plan §10): a real
/// `&Path` (so spaces/unicode just work), `SQLITE_OPEN_READ_ONLY`, a 2s busy
/// timeout for a brief writer lock, and `PRAGMA query_only=ON`.
///
/// # Errors
/// - [`ReadError::Locked`] when the store is busy (Cursor holding the lock).
/// - [`ReadError::Sqlite`] for any other open/pragma failure.
fn open_readonly(path: &Path) -> Result<Connection, ReadError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| map_sqlite(path, source))?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(|source| map_sqlite(path, source))?;
    // Belt-and-suspenders: refuse any write attempt at the engine level.
    conn.pragma_update(None, "query_only", "ON")
        .map_err(|source| map_sqlite(path, source))?;
    Ok(conn)
}

/// Map a rusqlite error to the right [`ReadError`], distinguishing a busy/locked
/// store from other sqlite failures (so the CLI can tell the user to close
/// Cursor).
fn map_sqlite(path: &Path, source: rusqlite::Error) -> ReadError {
    if is_busy(&source) {
        ReadError::Locked {
            origin: path.to_path_buf(),
            detail: source.to_string(),
        }
    } else {
        ReadError::Sqlite {
            origin: path.to_path_buf(),
            source,
        }
    }
}

/// Whether a rusqlite error is a `SQLITE_BUSY` / `SQLITE_LOCKED` condition.
fn is_busy(err: &rusqlite::Error) -> bool {
    use rusqlite::ErrorCode;
    match err {
        rusqlite::Error::SqliteFailure(e, _) => {
            matches!(e.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        }
        _ => false,
    }
}

/// Query a single optional string value (the first column of the first row).
fn query_opt_string<P: rusqlite::Params>(
    conn: &Connection,
    origin: &Path,
    sql: &str,
    params: P,
) -> Result<Option<String>, ReadError> {
    let mut stmt = conn.prepare(sql).map_err(|s| map_sqlite(origin, s))?;
    let mut rows = stmt.query(params).map_err(|s| map_sqlite(origin, s))?;
    match rows.next().map_err(|s| map_sqlite(origin, s))? {
        Some(row) => {
            let v: String = row.get(0).map_err(|s| map_sqlite(origin, s))?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// Parse an optional stored string as JSON, mapping a parse failure to
/// [`ReadError::Json`].
fn parse_opt_json(origin: &Path, raw: Option<String>) -> Result<Option<Value>, ReadError> {
    match raw {
        Some(s) => {
            let v = serde_json::from_str(&s).map_err(|source| ReadError::Json {
                origin: origin.to_path_buf(),
                source,
            })?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// Query all `(key, value)` pairs from `cursorDiskKV` whose key matches a LIKE
/// pattern (no particular order — used for the composer head rows).
fn query_kv_like(
    conn: &Connection,
    origin: &Path,
    pattern: &str,
) -> Result<Vec<(String, String)>, ReadError> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM cursorDiskKV WHERE key LIKE ?1")
        .map_err(|s| map_sqlite(origin, s))?;
    let rows = stmt
        .query_map([pattern], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|s| map_sqlite(origin, s))?;
    collect_rows(origin, rows)
}

/// Like [`query_kv_like`] but ordered by key (so separate-storage bubbles
/// assemble in a stable, reproducible order).
fn query_kv_like_ordered(
    conn: &Connection,
    origin: &Path,
    pattern: &str,
) -> Result<Vec<(String, String)>, ReadError> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM cursorDiskKV WHERE key LIKE ?1 ORDER BY key")
        .map_err(|s| map_sqlite(origin, s))?;
    let rows = stmt
        .query_map([pattern], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|s| map_sqlite(origin, s))?;
    collect_rows(origin, rows)
}

/// Collect a mapped row iterator into a Vec, mapping any per-row error.
fn collect_rows(
    origin: &Path,
    rows: impl Iterator<Item = rusqlite::Result<(String, String)>>,
) -> Result<Vec<(String, String)>, ReadError> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|s| map_sqlite(origin, s))?);
    }
    Ok(out)
}

/// Cheap `COUNT(*)` of `cursorDiskKV` rows matching a LIKE pattern (for the
/// separate-storage bubble count during discovery — no bodies read).
fn count_kv_like(conn: &Connection, origin: &Path, pattern: &str) -> Result<usize, ReadError> {
    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM cursorDiskKV WHERE key LIKE ?1")
        .map_err(|s| map_sqlite(origin, s))?;
    let n: i64 = stmt
        .query_row([pattern], |row| row.get(0))
        .map_err(|s| map_sqlite(origin, s))?;
    Ok(usize::try_from(n).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery;
    use rusqlite::params;

    /// Build a workspace `state.vscdb` at `path` with an `ItemTable` and the given
    /// (key, json) entries. Mirrors Cursor's schema (key TEXT PRIMARY KEY, value).
    fn write_item_table(path: &Path, entries: &[(&str, Value)]) {
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        for (k, v) in entries {
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                params![k, v.to_string()],
            )
            .unwrap();
        }
    }

    /// Build a global `state.vscdb` with a `cursorDiskKV` table and entries.
    fn write_disk_kv(path: &Path, entries: &[(&str, Value)]) {
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        for (k, v) in entries {
            conn.execute(
                "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
                params![k, v.to_string()],
            )
            .unwrap();
        }
    }

    fn chat_value() -> Value {
        serde_json::json!({
            "tabs": [{
                "tabId": "tab-1",
                "chatTitle": "My chat",
                "bubbles": [
                    { "type": "user", "rawText": "hello with AKIAIOSFODNN7EXAMPLE" },
                    { "type": "assistant", "text": "hi there" }
                ]
            }]
        })
    }

    fn ws_composer_value() -> Value {
        serde_json::json!({
            "allComposers": [{
                "composerId": "wc-1",
                "name": "WS composer",
                "modelConfig": { "modelName": "gpt-4o" },
                "conversation": [
                    { "type": 1, "text": "user says hi" },
                    { "type": 2, "text": "assistant replies" }
                ]
            }]
        })
    }

    /// A full workspace store with all three workspace variants seeded.
    fn seed_workspace_store(path: &Path) {
        write_item_table(
            path,
            &[
                (KEY_CHAT, chat_value()),
                (KEY_WS_COMPOSER, ws_composer_value()),
                (
                    KEY_AISERVICE_PROMPTS,
                    serde_json::json!([{ "text": "old prompt" }]),
                ),
                (
                    KEY_AISERVICE_GENERATIONS,
                    serde_json::json!([{ "text": "old gen", "modelName": "gpt-3.5" }]),
                ),
            ],
        );
    }

    #[test]
    fn discovers_all_workspace_variants_with_counts() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        seed_workspace_store(&db);

        let src = CursorSource::new();
        let (sessions, diags) = src.discover(&discovery::from_path(db.clone()));
        assert!(diags.is_empty(), "no diags expected: {diags:?}");
        // chat + workspace composer + aiService = 3 sessions.
        assert_eq!(sessions.len(), 3, "got: {sessions:#?}");

        // Each session's import_id is fp:native_id and native_id is variant-tagged.
        let fp = origin_fingerprint(&db);
        let chat = sessions.iter().find(|s| s.native_id.starts_with("chat/")).unwrap();
        assert_eq!(chat.import_id, format!("{fp}:{}", chat.native_id));
        assert_eq!(chat.title.as_deref(), Some("My chat"));
        assert_eq!(chat.approx_messages, Some(2));

        assert!(sessions.iter().any(|s| s.native_id == "wscomposer/wc-1"));
        assert!(sessions.iter().any(|s| s.native_id == "aiservice/conversation"));
    }

    #[test]
    fn reads_chat_tab_into_redactable_bubble_records() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        seed_workspace_store(&db);
        let src = CursorSource::new();
        let (sessions, _) = src.discover(&discovery::from_path(db.clone()));
        let chat = sessions.iter().find(|s| s.native_id.starts_with("chat/")).unwrap();

        let recs = src.read(chat).unwrap();
        assert_eq!(recs.records.len(), 2);
        // The source moves the RAW value through (redaction is the adapter's job):
        // the secret is still present in the opaque record here, by design.
        let user = &recs.records[0];
        assert_eq!(user["role"], serde_json::json!("user"));
        assert_eq!(user["coord"], serde_json::json!("chat:tab-1:0"));
        assert!(user["text"].as_str().unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
        let asst = &recs.records[1];
        assert_eq!(asst["role"], serde_json::json!("assistant"));
        assert_eq!(asst["coord"], serde_json::json!("chat:tab-1:1"));
    }

    #[test]
    fn reads_workspace_composer_with_model_and_turns() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        seed_workspace_store(&db);
        let src = CursorSource::new();
        let (sessions, _) = src.discover(&discovery::from_path(db.clone()));
        let wc = sessions.iter().find(|s| s.native_id == "wscomposer/wc-1").unwrap();

        let recs = src.read(wc).unwrap();
        assert_eq!(recs.records.len(), 2);
        assert_eq!(recs.records[0]["role"], serde_json::json!("user"));
        assert_eq!(recs.records[0]["turn"], serde_json::json!(0));
        assert_eq!(recs.records[0]["coord"], serde_json::json!("wscomposer:wc-1:0"));
        // Assistant bubble carries the modelConfig model.
        assert_eq!(recs.records[1]["model"], serde_json::json!("gpt-4o"));
    }

    #[test]
    fn reads_aiservice_pairs_with_sparse_assistant() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        seed_workspace_store(&db);
        let src = CursorSource::new();
        let (sessions, _) = src.discover(&discovery::from_path(db.clone()));
        let ai = sessions.iter().find(|s| s.native_id == "aiservice/conversation").unwrap();

        let recs = src.read(ai).unwrap();
        // One user + one assistant (with model) for the single pair.
        assert_eq!(recs.records.len(), 2);
        assert_eq!(recs.records[0]["coord"], serde_json::json!("aiService:user:0"));
        assert_eq!(recs.records[1]["coord"], serde_json::json!("aiService:assistant:0"));
        assert_eq!(recs.records[1]["model"], serde_json::json!("gpt-3.5"));
    }

    #[test]
    fn reads_global_composer_inline_and_separate() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        write_disk_kv(
            &db,
            &[
                // Inline-storage composer.
                (
                    "composerData:inline-1",
                    serde_json::json!({
                        "composerId": "inline-1",
                        "name": "Inline",
                        "modelConfig": { "modelName": "claude-3.5" },
                        "conversation": [
                            { "type": 1, "text": "inline user" },
                            { "type": 2, "text": "inline assistant" }
                        ]
                    }),
                ),
                // Separate-storage composer (head row has empty conversation).
                (
                    "composerData:sep-1",
                    serde_json::json!({ "composerId": "sep-1", "name": "Separate", "conversation": [] }),
                ),
                (
                    "bubbleId:sep-1:0001",
                    serde_json::json!({ "type": 1, "text": "sep user" }),
                ),
                (
                    "bubbleId:sep-1:0002",
                    serde_json::json!({
                        "type": 2, "text": "sep assistant",
                        "modelName": "gpt-4o",
                        "toolResults": { "name": "edit_file", "result": "ok" }
                    }),
                ),
            ],
        );

        let src = CursorSource::new();
        let (sessions, diags) = src.discover(&discovery::from_path(db.clone()));
        assert!(diags.is_empty(), "diags: {diags:?}");
        assert_eq!(sessions.len(), 2, "two global composers: {sessions:#?}");

        let inline = sessions.iter().find(|s| s.native_id == "gcomposer/inline-1").unwrap();
        assert_eq!(inline.approx_messages, Some(2));
        let inline_recs = src.read(inline).unwrap();
        assert_eq!(inline_recs.records.len(), 2);
        assert_eq!(inline_recs.records[0]["coord"], serde_json::json!("composerId:inline-1:0"));
        assert_eq!(inline_recs.records[1]["model"], serde_json::json!("claude-3.5"));

        let sep = sessions.iter().find(|s| s.native_id == "gcomposer/sep-1").unwrap();
        assert_eq!(sep.approx_messages, Some(2), "separate-storage COUNT");
        let sep_recs = src.read(sep).unwrap();
        assert_eq!(sep_recs.records.len(), 2);
        // Separate-storage coord is the row key itself.
        assert_eq!(sep_recs.records[0]["coord"], serde_json::json!("bubbleId:sep-1:0001"));
        assert_eq!(sep_recs.records[1]["model"], serde_json::json!("gpt-4o"));
        assert!(sep_recs.records[1].get("tool_results").is_some());
    }

    /// The cross-workspace-collision guard (plan fix #P1): two workspace stores
    /// sharing the SAME legacy chat key must yield two DISTINCT import ids
    /// (origin_fingerprint namespacing), which downstream become distinct
    /// trace/session ids.
    #[test]
    fn two_workspaces_sharing_chat_key_get_distinct_import_ids() {
        let dir = tempfile::tempdir().unwrap();
        let db_a = dir.path().join("ws-a").join("state.vscdb");
        let db_b = dir.path().join("ws-b").join("state.vscdb");
        std::fs::create_dir_all(db_a.parent().unwrap()).unwrap();
        std::fs::create_dir_all(db_b.parent().unwrap()).unwrap();
        // Identical chat content (same tabId) in both stores.
        write_item_table(&db_a, &[(KEY_CHAT, chat_value())]);
        write_item_table(&db_b, &[(KEY_CHAT, chat_value())]);

        let src = CursorSource::new();
        let (sa, _) = src.discover(&discovery::from_path(db_a.clone()));
        let (sb, _) = src.discover(&discovery::from_path(db_b.clone()));
        assert_eq!(sa.len(), 1);
        assert_eq!(sb.len(), 1);
        // Same native_id (chat/tab-1) but DIFFERENT import_id (origin fp differs).
        assert_eq!(sa[0].native_id, sb[0].native_id);
        assert_ne!(
            sa[0].import_id, sb[0].import_id,
            "two stores with the same chat key must namespace to distinct import ids"
        );
        // And the derived trace/session ids differ too.
        let fp_a = origin_fingerprint(&db_a);
        let fp_b = origin_fingerprint(&db_b);
        assert_ne!(
            crate::import_trace_id(crate::Tool::Cursor, &fp_a, &sa[0].native_id),
            crate::import_trace_id(crate::Tool::Cursor, &fp_b, &sb[0].native_id)
        );
        assert_ne!(
            crate::import_session_id(crate::Tool::Cursor, &fp_a, &sa[0].native_id),
            crate::import_session_id(crate::Tool::Cursor, &fp_b, &sb[0].native_id)
        );
    }

    /// A corrupt/non-SQLite store must surface as a [`ReadError`] (→ a `Diag` in
    /// discovery), never a panic or a silent skip.
    #[test]
    fn corrupt_db_surfaces_read_error_and_discovery_diag() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        // Garbage bytes: not a SQLite file.
        std::fs::write(&db, b"this is definitely not a sqlite database").unwrap();

        // discover() emits a Diag (error level) and no sessions for this store.
        let src = CursorSource::new();
        let (sessions, diags) = src.discover(&discovery::from_path(db.clone()));
        assert!(sessions.is_empty());
        assert_eq!(diags.len(), 1, "a corrupt store must produce one diagnostic");
        assert_eq!(diags[0].origin, db);

        // A direct read() of a session pointing at the corrupt store errors
        // (Sqlite or Locked, depending on how SQLite reports the bad header) —
        // never a panic.
        let probe = DiscoveredSession {
            tool: CursorSource::NAME.to_string(),
            native_id: "chat/tab-1".to_string(),
            import_id: "fp:chat/tab-1".to_string(),
            origin: db.clone(),
            locator: SessionLocator::Key("tab-1".to_string()),
            title: None,
            last_active: None,
            mtime: MicrosTimestamp(0),
            approx_messages: None,
            workspace: None,
        };
        let err = src.read(&probe).unwrap_err();
        assert!(
            matches!(err, ReadError::Sqlite { .. } | ReadError::Locked { .. } | ReadError::Json { .. }),
            "corrupt store must error, got: {err:?}"
        );
    }

    /// A LOCKED store (exclusive write lock held) must map to a warning diagnostic
    /// (not an error, not a panic) so discovery proceeds.
    #[test]
    fn locked_db_surfaces_locked_warning() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        write_item_table(&db, &[(KEY_CHAT, chat_value())]);

        // Hold an EXCLUSIVE lock on the DB in another connection so the read-only
        // open's busy_timeout elapses → SQLITE_BUSY → Locked.
        let locker = Connection::open(&db).unwrap();
        locker.pragma_update(None, "locking_mode", "EXCLUSIVE").unwrap();
        locker.execute_batch("BEGIN EXCLUSIVE").unwrap();

        let src = CursorSource::new();
        let (sessions, diags) = src.discover(&discovery::from_path(db.clone()));
        assert!(sessions.is_empty());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].level, crate::Level::Warn, "a locked store warns (not errors)");
        assert!(
            diags[0].msg.to_lowercase().contains("lock"),
            "diag should mention the lock: {}",
            diags[0].msg
        );

        // Clean up the lock so the tempdir can be removed.
        locker.execute_batch("COMMIT").ok();
    }

    #[test]
    fn read_only_open_refuses_writes() {
        // The read-only connection must reject a write (query_only=ON + RO flag).
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        write_item_table(&db, &[(KEY_CHAT, chat_value())]);
        let conn = open_readonly(&db).unwrap();
        let err = conn.execute("INSERT INTO ItemTable (key, value) VALUES ('x','y')", []);
        assert!(err.is_err(), "a read-only connection must refuse writes");
    }

    #[test]
    fn special_char_path_opens_without_uri_escaping() {
        // A path with spaces + unicode must open via open_with_flags (real &Path,
        // no URI escaping) — the plan's explicit requirement.
        let dir = tempfile::tempdir().unwrap();
        let weird = dir.path().join("Cursor data — ünïcødé & spaces");
        std::fs::create_dir_all(&weird).unwrap();
        let db = weird.join("state.vscdb");
        write_item_table(&db, &[(KEY_CHAT, chat_value())]);

        let src = CursorSource::new();
        let (sessions, diags) = src.discover(&discovery::from_path(db.clone()));
        assert!(diags.is_empty(), "diags: {diags:?}");
        assert_eq!(sessions.len(), 1);
        let recs = src.read(&sessions[0]).unwrap();
        assert_eq!(recs.records.len(), 2);
    }

    #[test]
    fn empty_tabs_and_composers_are_not_discovered() {
        // Zero-bubble tabs / zero-message composers are skipped (no empty
        // sessions).
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.vscdb");
        write_item_table(
            &db,
            &[
                (KEY_CHAT, serde_json::json!({ "tabs": [{ "tabId": "t", "bubbles": [] }] })),
                (
                    KEY_WS_COMPOSER,
                    serde_json::json!({ "allComposers": [{ "composerId": "c", "conversation": [] }] }),
                ),
            ],
        );
        let src = CursorSource::new();
        let (sessions, _) = src.discover(&discovery::from_path(db));
        assert!(sessions.is_empty(), "empty conversations must not be discovered");
    }

    #[test]
    fn discovers_via_standard_user_layout() {
        // A root containing the standard Cursor/User/workspaceStorage/{hash}
        // layout is walked (not just a direct state.vscdb path).
        let dir = tempfile::tempdir().unwrap();
        let ws = dir
            .path()
            .join("Cursor")
            .join("User")
            .join("workspaceStorage")
            .join("abc123");
        std::fs::create_dir_all(&ws).unwrap();
        seed_workspace_store(&ws.join("state.vscdb"));
        // Also a global store.
        let gs = dir.path().join("Cursor").join("User").join("globalStorage");
        std::fs::create_dir_all(&gs).unwrap();
        write_disk_kv(
            &gs.join("state.vscdb"),
            &[(
                "composerData:g1",
                serde_json::json!({
                    "composerId": "g1",
                    "conversation": [{ "type": 1, "text": "hi" }]
                }),
            )],
        );

        let src = CursorSource::new();
        let (sessions, diags) = src.discover(&discovery::resolve_for_test(dir.path()));
        assert!(diags.is_empty(), "diags: {diags:?}");
        // 3 workspace + 1 global = 4, and the workspace hash is recorded.
        assert_eq!(sessions.len(), 4, "got: {sessions:#?}");
        let chat = sessions.iter().find(|s| s.native_id.starts_with("chat/")).unwrap();
        assert_eq!(chat.workspace.as_deref(), Some("abc123"));
    }
}
