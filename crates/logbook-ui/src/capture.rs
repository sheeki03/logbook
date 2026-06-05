//! Capture on/off toggle: the `GET`/`POST /api/capture-policy` handlers and
//! their trust model (Orbit plan §1.4, "Capture on/off button + its trust
//! model").
//!
//! `logbook-ui` is otherwise read-only GET (the timeline/inventory/sessions
//! APIs). This is the one deliberate, fenced **write** boundary, with two write
//! targets at two trust levels:
//!
//! 1. **Runtime override → `<out_dir>/capture-state.json`** (default-allowed,
//!    cross-process). A small narrow-only state file
//!    ([`logbook_core::CaptureState`]): master on/off + per-class booleans, with
//!    `secrets` locked. Every producer's [`logbook_core::CapturePolicy::resolve`]
//!    overlays it, so flipping it pauses capture for *subsequent*
//!    `logbook run`/`agent` runs — not just the live UI. This is what makes the
//!    toggle work across processes.
//! 2. **Durable default → `<root>/logbook.toml [capture]`** (gated). Persisting
//!    requires launching `logbook ui --allow-config-write` (off by default).
//!
//! Both writes get, per the plan:
//! - **same-origin + CSRF-token check** — a loopback server is reachable by any
//!   local web page, so a forged cross-site `POST` must be rejected. The server
//!   mints an unguessable per-process CSRF token (returned by the `GET`); the
//!   browser echoes it in [`CSRF_HEADER`]. A cross-origin attacker cannot read
//!   the `GET` (CORS) so cannot learn the token. `Sec-Fetch-Site` / `Origin` are
//!   checked as defence-in-depth.
//! - **atomic write** (temp + rename) — via [`CaptureState::save`] for the
//!   runtime target and a temp+rename for the config target.
//! - **conflict detection** — the client sends the `version` (mtime+hash) it
//!   last read; the server recomputes and rejects a stale write (409), so a
//!   concurrent edit is never blind-overwritten (read-modify-write).
//! - **server-enforced secrets floor** — disabling `secrets` is rejected (the
//!   class is not even addressable in the request body).

use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use logbook_core::{
    CapturePolicy, CaptureState, CaptureStateClasses, CliOverlay, LogbookConfig, SensitivityClass,
};

use crate::state::AppState;

/// Header the browser must echo the per-process CSRF token in on a write.
pub const CSRF_HEADER: &str = "x-logbook-csrf";

/// The write target: the narrow-only runtime state file (default) or the durable
/// `logbook.toml` (gated behind `--allow-config-write`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteTarget {
    /// `<out_dir>/capture-state.json` — narrow-only, cross-process, always
    /// allowed.
    #[default]
    Runtime,
    /// `<root>/logbook.toml [capture]` — durable, requires `--allow-config-write`.
    Config,
}

/// Per-class capture toggles exposed to the UI. `secrets` is deliberately absent
/// — it is the locked floor and is not addressable here (server-enforced).
///
/// On the `GET` these are the *effective* (resolved) capture booleans; on the
/// `POST` a `Some(false)` requests narrowing that class off and `Some(true)`
/// requests re-enabling it (only honoured up to what config + defaults allow, on
/// the runtime path).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureClassToggles {
    /// Transcript capture.
    pub transcript: Option<bool>,
    /// Prompts capture (Phase 2 mechanism; toggle persists now).
    pub prompts: Option<bool>,
    /// Tool-args capture.
    pub tool_args: Option<bool>,
    /// Tool-results capture.
    pub tool_results: Option<bool>,
    /// File-diffs capture.
    pub file_diffs: Option<bool>,
    /// Commands capture.
    pub commands: Option<bool>,
    /// Browser-data capture.
    pub browser_data: Option<bool>,
    /// Model-metadata capture.
    pub model_metadata: Option<bool>,
}

/// Response of `GET /api/capture-policy`: the effective policy the UI renders,
/// the CSRF token to echo on a write, whether config writes are allowed, and the
/// opaque version token for conflict detection.
#[derive(Clone, Debug, Serialize)]
pub struct CapturePolicyView {
    /// Effective master switch (after config + overlay resolution).
    pub enabled: bool,
    /// Effective per-class capture booleans.
    pub classes: ClassEnabled,
    /// `secrets` is always on + always force-redacted; surfaced as a locked flag
    /// so the UI renders it disabled.
    pub secrets_locked: bool,
    /// Whether the server was launched with `--allow-config-write` (controls
    /// whether the `config` write target is permitted).
    pub allow_config_write: bool,
    /// Per-process CSRF token; echo it in the [`CSRF_HEADER`] on a `POST`.
    pub csrf_token: String,
    /// Opaque version of `<out_dir>/capture-state.json` for conflict detection.
    /// Send it back as `expected_version` on a `POST`.
    pub version: String,
}

/// Effective capture booleans for every addressable class (secrets excluded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClassEnabled {
    /// Whether transcript is captured.
    pub transcript: bool,
    /// Whether prompts are captured.
    pub prompts: bool,
    /// Whether tool-args are captured.
    pub tool_args: bool,
    /// Whether tool-results are captured.
    pub tool_results: bool,
    /// Whether file-diffs are captured.
    pub file_diffs: bool,
    /// Whether commands are captured.
    pub commands: bool,
    /// Whether browser-data is captured.
    pub browser_data: bool,
    /// Whether model-metadata is captured.
    pub model_metadata: bool,
}

impl ClassEnabled {
    /// Project the effective capture state of every addressable class from a
    /// resolved policy.
    fn from_policy(policy: &CapturePolicy) -> Self {
        Self {
            transcript: policy.should_capture(SensitivityClass::Transcript),
            prompts: policy.should_capture(SensitivityClass::Prompts),
            tool_args: policy.should_capture(SensitivityClass::ToolArgs),
            tool_results: policy.should_capture(SensitivityClass::ToolResults),
            file_diffs: policy.should_capture(SensitivityClass::FileDiffs),
            commands: policy.should_capture(SensitivityClass::Commands),
            browser_data: policy.should_capture(SensitivityClass::BrowserData),
            model_metadata: policy.should_capture(SensitivityClass::ModelMetadata),
        }
    }
}

/// Request body of `POST /api/capture-policy`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct CapturePolicyUpdate {
    /// Where to write (`runtime` = capture-state.json, `config` = logbook.toml).
    pub target: WriteTarget,
    /// Desired master switch. `Some(false)` pauses capture.
    pub enabled: Option<bool>,
    /// Desired per-class capture toggles. `secrets` is not addressable.
    pub classes: CaptureClassToggles,
    /// The `version` the client last read (from the `GET`). A mismatch with the
    /// current on-disk version is a 409 conflict.
    pub expected_version: Option<String>,
}

impl AppState {
    /// Resolve the effective capture policy for this server's root + out-dir
    /// (no CLI overlay — the UI is the runtime override surface itself).
    fn resolve_policy(&self) -> CapturePolicy {
        CapturePolicy::resolve(&self.capture_root, &self.out_dir, CliOverlay::default())
    }
}

/// `GET /api/capture-policy` — the current effective policy, the CSRF token, the
/// config-write capability, and the conflict-detection version.
pub async fn get_capture_policy(State(state): State<AppState>) -> Json<CapturePolicyView> {
    let policy = state.resolve_policy();
    Json(CapturePolicyView {
        enabled: policy.enabled,
        classes: ClassEnabled::from_policy(&policy),
        secrets_locked: true,
        allow_config_write: state.allow_config_write,
        csrf_token: state.csrf_token.clone(),
        version: state_version(&state.out_dir),
    })
}

/// `POST /api/capture-policy` — narrow/widen the runtime overlay (default) or, if
/// `--allow-config-write`, the durable `logbook.toml [capture]`. Guarded by the
/// CSRF token, a same-origin check, conflict detection, and the secrets floor.
pub async fn set_capture_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<CapturePolicyUpdate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // (1) CSRF + same-origin: reject before reading the body.
    if let Err(e) = check_csrf(&state, &headers) {
        return e.into_response();
    }

    let Json(update) = match body {
        Ok(json) => json,
        Err(_) => return CaptureApiError::bad_request("invalid JSON").into_response(),
    };

    let result = match update.target {
        WriteTarget::Runtime => write_runtime(&state, &update),
        WriteTarget::Config => write_config(&state, &update),
    };

    match result {
        Ok(()) => {
            // Echo back the freshly-resolved policy + the new version so the UI
            // can reconcile without a second round-trip.
            let policy = state.resolve_policy();
            (
                StatusCode::OK,
                Json(CapturePolicyView {
                    enabled: policy.enabled,
                    classes: ClassEnabled::from_policy(&policy),
                    secrets_locked: true,
                    allow_config_write: state.allow_config_write,
                    csrf_token: state.csrf_token.clone(),
                    version: state_version(&state.out_dir),
                }),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Verify the CSRF token header matches and the request is same-origin.
///
/// The CSRF token is the primary defence (an unguessable per-process value the
/// attacker cannot read cross-origin). `Sec-Fetch-Site` is checked as
/// defence-in-depth: a genuine same-origin fetch sends `same-origin`; a forged
/// cross-site POST sends `cross-site`. A missing `Sec-Fetch-Site` (older client,
/// or a non-browser caller like a test) is allowed *only* with a valid token.
fn check_csrf(state: &AppState, headers: &HeaderMap) -> Result<(), CaptureApiError> {
    // Same-origin defence-in-depth: an explicit `cross-site`/`same-site` fetch is
    // never legitimate for this endpoint.
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site != "same-origin" && site != "none" {
            return Err(CaptureApiError::forbidden("cross-origin request rejected"));
        }
    }
    let Some(got) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return Err(CaptureApiError::forbidden("missing CSRF token"));
    };
    if !constant_time_eq(got.as_bytes(), state.csrf_token.as_bytes()) {
        return Err(CaptureApiError::forbidden("bad CSRF token"));
    }
    Ok(())
}

/// Apply the requested toggles to the narrow-only `<out_dir>/capture-state.json`
/// via a read-modify-write: load the existing state, fold in the request, then
/// [`CaptureState::save`] (atomic temp+rename).
fn write_runtime(state: &AppState, update: &CapturePolicyUpdate) -> Result<(), CaptureApiError> {
    reject_secrets_disable(update)?;
    check_version(&state.out_dir, update)?;

    // Read-modify-write so we never blind-overwrite a concurrent change.
    let mut current = CaptureState::load(&state.out_dir)
        .map_err(|e| CaptureApiError::internal(e.to_string()))?
        .unwrap_or_default();

    if let Some(enabled) = update.enabled {
        current.enabled = Some(enabled);
    }
    apply_class_toggles(&mut current.classes, &update.classes);

    current
        .save(&state.out_dir)
        .map_err(|e| CaptureApiError::internal(e.to_string()))?;
    Ok(())
}

/// Persist the requested toggles into `<root>/logbook.toml [capture]` (gated on
/// `--allow-config-write`). Read-modify-write of the parsed config so unrelated
/// sections are preserved; written atomically (temp + rename) and validated
/// before write so the secrets floor can never be relaxed.
fn write_config(state: &AppState, update: &CapturePolicyUpdate) -> Result<(), CaptureApiError> {
    if !state.allow_config_write {
        return Err(CaptureApiError::forbidden(
            "writing logbook.toml requires launching `logbook ui --allow-config-write`",
        ));
    }
    reject_secrets_disable(update)?;
    // For the config target, conflict-detection is over logbook.toml's bytes.
    check_config_version(&state.capture_root, update)?;

    // Read-modify-write the full config so other sections survive.
    let path = LogbookConfig::path_in_root(&state.capture_root);
    let mut cfg = LogbookConfig::load_from_root(&state.capture_root)
        .map_err(|e| CaptureApiError::internal(e.to_string()))?;

    if let Some(enabled) = update.enabled {
        cfg.capture.enabled = enabled;
    }
    apply_config_class_toggles(&mut cfg.capture, &update.classes);

    // Never write a policy that violates the floor (defensive — the toggles
    // cannot reach `secrets`, but validate before persisting regardless).
    cfg.capture
        .validate()
        .map_err(|e| CaptureApiError::bad_request(e.to_string()))?;

    let body = toml::to_string(&cfg).map_err(|e| CaptureApiError::internal(e.to_string()))?;
    atomic_write(&path, body.as_bytes()).map_err(|e| CaptureApiError::internal(e.to_string()))?;
    Ok(())
}

/// Reject any request that tries to disable the locked `secrets` floor. The
/// request body has no `secrets` field, but a future field or a hand-rolled
/// client could try; this is the server-side enforcement the plan requires.
fn reject_secrets_disable(_update: &CapturePolicyUpdate) -> Result<(), CaptureApiError> {
    // `CaptureClassToggles` intentionally has no `secrets` field, so a disable
    // is structurally impossible from the wire. The function exists as the
    // documented enforcement point; if a `secrets` toggle is ever added it must
    // be rejected here.
    Ok(())
}

/// Fold the request toggles into a [`CaptureStateClasses`] overlay, only setting
/// fields the request names (a `None` leaves the existing override untouched).
fn apply_class_toggles(into: &mut CaptureStateClasses, from: &CaptureClassToggles) {
    if from.transcript.is_some() {
        into.transcript = from.transcript;
    }
    if from.prompts.is_some() {
        into.prompts = from.prompts;
    }
    if from.tool_args.is_some() {
        into.tool_args = from.tool_args;
    }
    if from.tool_results.is_some() {
        into.tool_results = from.tool_results;
    }
    if from.file_diffs.is_some() {
        into.file_diffs = from.file_diffs;
    }
    if from.commands.is_some() {
        into.commands = from.commands;
    }
    if from.browser_data.is_some() {
        into.browser_data = from.browser_data;
    }
    if from.model_metadata.is_some() {
        into.model_metadata = from.model_metadata;
    }
}

/// Apply the request toggles directly onto a [`CapturePolicy`]'s class rules (the
/// durable config path). Only classes the request names are changed.
fn apply_config_class_toggles(policy: &mut CapturePolicy, from: &CaptureClassToggles) {
    let pairs: [(Option<bool>, SensitivityClass); 8] = [
        (from.transcript, SensitivityClass::Transcript),
        (from.prompts, SensitivityClass::Prompts),
        (from.tool_args, SensitivityClass::ToolArgs),
        (from.tool_results, SensitivityClass::ToolResults),
        (from.file_diffs, SensitivityClass::FileDiffs),
        (from.commands, SensitivityClass::Commands),
        (from.browser_data, SensitivityClass::BrowserData),
        (from.model_metadata, SensitivityClass::ModelMetadata),
    ];
    for (flag, class) in pairs {
        if let Some(capture) = flag {
            set_class_capture(policy, class, capture);
        }
    }
}

/// Set a single class's `capture` flag on a policy (the `secrets` floor is never
/// touched — it is not in the toggle set).
fn set_class_capture(policy: &mut CapturePolicy, class: SensitivityClass, capture: bool) {
    let rule = match class {
        SensitivityClass::Transcript => &mut policy.classes.transcript,
        SensitivityClass::Prompts => &mut policy.classes.prompts,
        SensitivityClass::ToolArgs => &mut policy.classes.tool_args,
        SensitivityClass::ToolResults => &mut policy.classes.tool_results,
        SensitivityClass::FileDiffs => &mut policy.classes.file_diffs,
        SensitivityClass::Commands => &mut policy.classes.commands,
        SensitivityClass::BrowserData => &mut policy.classes.browser_data,
        SensitivityClass::ModelMetadata => &mut policy.classes.model_metadata,
        // The floor: never reachable from the toggle set; leave untouched.
        SensitivityClass::Secrets => return,
    };
    // Only the `capture` flag is toggled; `rule.redaction` is left untouched so
    // re-enabling a payload class can never relax its force-redaction posture.
    rule.capture = capture;
}

/// Conflict detection for the runtime target: the version the client last read
/// must match the current `<out_dir>/capture-state.json` version.
fn check_version(out_dir: &Path, update: &CapturePolicyUpdate) -> Result<(), CaptureApiError> {
    let Some(expected) = update.expected_version.as_deref() else {
        return Ok(()); // no version supplied => caller opts out of the check
    };
    let current = state_version(out_dir);
    if expected != current {
        return Err(CaptureApiError::conflict(
            "capture-state.json changed since it was read; reload and retry",
        ));
    }
    Ok(())
}

/// Conflict detection for the config target, over `logbook.toml`'s bytes.
fn check_config_version(root: &Path, update: &CapturePolicyUpdate) -> Result<(), CaptureApiError> {
    let Some(expected) = update.expected_version.as_deref() else {
        return Ok(());
    };
    let current = file_version(&LogbookConfig::path_in_root(root));
    if expected != current {
        return Err(CaptureApiError::conflict(
            "logbook.toml changed since it was read; reload and retry",
        ));
    }
    Ok(())
}

/// An opaque version token for `<out_dir>/capture-state.json` (mtime + size +
/// content hash), used for conflict detection. A missing file hashes to a
/// stable `"absent"` so the first write (expecting absent) succeeds.
fn state_version(out_dir: &Path) -> String {
    file_version(&CaptureState::path_in_out_dir(out_dir))
}

/// Opaque version of a file: `"absent"` when missing, else `len:mtime:hash` over
/// its current bytes. A blind overwrite of a concurrently-changed file therefore
/// mismatches and is rejected (read-modify-write contract).
fn file_version(path: &Path) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return "absent".to_string();
    };
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_micros())
        .unwrap_or(0);
    format!("{}:{}:{:016x}", bytes.len(), mtime, fnv1a(&bytes))
}

/// A small, dependency-free 64-bit FNV-1a hash for the version token. This is a
/// change-detector, not a security primitive — collisions only weaken conflict
/// detection, never the secrets floor or the CSRF check.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Atomic write (temp sibling + rename) for the config target, mirroring the
/// discipline in [`CaptureState::save`]. Creates the parent dir if needed.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Length-checked constant-time byte comparison for the CSRF token (no early
/// exit, mirroring the collector's bearer check).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Errors for the capture-policy write endpoint. A client-facing message is
/// returned for 400/403/409 (they describe a fixable client condition and carry
/// no sensitive detail); a 500's detail is logged, not echoed.
#[derive(Debug)]
enum CaptureApiError {
    BadRequest(String),
    Forbidden(String),
    Conflict(String),
    Internal(String),
}

impl CaptureApiError {
    fn bad_request(m: impl Into<String>) -> Self {
        Self::BadRequest(m.into())
    }
    fn forbidden(m: impl Into<String>) -> Self {
        Self::Forbidden(m.into())
    }
    fn conflict(m: impl Into<String>) -> Self {
        Self::Conflict(m.into())
    }
    fn internal(m: impl Into<String>) -> Self {
        Self::Internal(m.into())
    }
}

impl IntoResponse for CaptureApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            CaptureApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            CaptureApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            CaptureApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            CaptureApiError::Internal(m) => {
                tracing::error!(error = %m, "capture-policy write failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

/// Mint a fresh per-process CSRF token from OS entropy (reusing the 128-bit
/// `TraceId` generator — unguessable, no new dependency).
#[must_use]
pub fn new_csrf_token() -> String {
    logbook_core::TraceId::new().to_hex()
}

/// The default capture-policy root (where `logbook.toml` lives): when no
/// explicit root is configured it is the out-dir's parent, falling back to the
/// out-dir itself when there is no usable parent component (e.g. a bare
/// relative out-dir like `.logbook`, whose `parent()` is the empty path).
#[must_use]
pub fn default_capture_root(out_dir: &Path) -> PathBuf {
    match out_dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => out_dir.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::RedactionMode;

    #[test]
    fn fnv1a_changes_with_content() {
        assert_ne!(fnv1a(b"a"), fnv1a(b"b"));
        assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
    }

    #[test]
    fn version_is_absent_for_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(state_version(tmp.path()), "absent");
    }

    #[test]
    fn version_changes_after_save() {
        let tmp = tempfile::tempdir().unwrap();
        let before = state_version(tmp.path());
        CaptureState {
            enabled: Some(false),
            ..CaptureState::default()
        }
        .save(tmp.path())
        .unwrap();
        let after = state_version(tmp.path());
        assert_ne!(before, after, "version must change once the file exists");
        assert_ne!(after, "absent");
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn apply_class_toggles_only_sets_named_fields() {
        let mut classes = CaptureStateClasses {
            transcript: Some(false),
            ..CaptureStateClasses::default()
        };
        let toggles = CaptureClassToggles {
            file_diffs: Some(false),
            ..CaptureClassToggles::default()
        };
        apply_class_toggles(&mut classes, &toggles);
        // The pre-existing transcript override survives (request didn't name it).
        assert_eq!(classes.transcript, Some(false));
        // The newly-named file_diffs is applied.
        assert_eq!(classes.file_diffs, Some(false));
        // An un-named class stays None.
        assert_eq!(classes.commands, None);
    }

    #[test]
    fn config_toggles_preserve_force_redaction() {
        // Re-enabling file_diffs must keep its Always redaction (force-redacted).
        let mut policy = CapturePolicy::default();
        policy.classes.file_diffs.capture = false;
        let toggles = CaptureClassToggles {
            file_diffs: Some(true),
            ..CaptureClassToggles::default()
        };
        apply_config_class_toggles(&mut policy, &toggles);
        assert!(policy.classes.file_diffs.capture);
        assert_eq!(policy.classes.file_diffs.redaction, RedactionMode::Always);
        // The secrets floor is never disturbed.
        assert!(policy.classes.secrets.capture);
        assert_eq!(policy.classes.secrets.redaction, RedactionMode::Always);
    }

    #[test]
    fn default_capture_root_is_out_dir_parent() {
        assert_eq!(
            default_capture_root(Path::new("/proj/.logbook")),
            PathBuf::from("/proj")
        );
        // A bare relative out-dir has no parent path component -> falls back.
        assert_eq!(
            default_capture_root(Path::new(".logbook")),
            PathBuf::from(".logbook")
        );
    }
}
