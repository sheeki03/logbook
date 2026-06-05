//! Capture policy + sensitivity classes — the governance layer (Orbit, plan
//! "Capture policy + sensitivity classes").
//!
//! `logbook` records an agent session **recorder-on by default**: every
//! auto-capturable class (transcript, commands, diffs, tool args/results,
//! prompts, model metadata) is captured the moment a session is explicitly
//! wrapped via `logbook agent`/`logbook run`. This module is the single home for
//! that decision — a `[capture]` TOML section plus a load-time
//! [`CapturePolicy::validate`] and a shared [`CapturePolicy::resolve`] every
//! producer calls so the on/off behaviour is identical everywhere.
//!
//! # Three things keep this safe
//! 1. **Secrets floor** — the `secrets` class is *locked on* and force-redacted.
//!    A `[capture]` that sets `secrets.capture=false` or `secrets.redaction =
//!    "never"` is **rejected at load** ([`CapturePolicy::validate`]).
//! 2. **Fail-closed loading** — [`CapturePolicy::resolve`] loads
//!    `<root>/logbook.toml` **strictly**; on *any* parse/validate error it
//!    **degrades to capture-OFF** (logged), never to the recorder-on default.
//!    Recorder-on applies only to a *validly absent* `[capture]` section.
//! 3. **Narrow-only overlay** — the UI on/off toggle writes a small
//!    `<out_dir>/capture-state.json` ([`CaptureState`]) that may only *narrow*
//!    capture (flip things off), never widen it. A malformed overlay is ignored.
//!
//! The policy is consulted at each producer's *persistence boundary* (never
//! inside the store) via [`CapturePolicy::should_capture`],
//! [`CapturePolicy::should_redact`], and [`CapturePolicy::cap_body`].

use std::borrow::Cow;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, LogbookConfig};
use crate::text::floor_char_boundary;

/// The runtime-state filename written by the UI capture toggle, resolved against
/// `<out_dir>` (so a custom `--out-dir` works). Read as a **narrow-only** overlay
/// by [`CapturePolicy::resolve`].
pub const CAPTURE_STATE_FILENAME: &str = "capture-state.json";

/// How a sensitivity class is redacted, relative to the global
/// `[redaction].enabled` switch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// Always redact (at least the secrets floor) regardless of the global
    /// switch — `--no-redact` cannot expose this class.
    Always,
    /// Never redact this class (only legal for non-secret classes).
    Never,
    /// Obey the global `[redaction].enabled` / `--no-redact` switch.
    #[default]
    Default,
}

/// A sensitivity class: the unit at which capture, redaction, retention, and
/// export are decided. The secrets floor applies to *every* row regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityClass {
    /// Redacted terminal transcript + cleaned text (the Universal tier).
    Transcript,
    /// Prompts sent to a model (Phase 2; governance-sensitive).
    Prompts,
    /// Tool / function-call arguments (Phase 2).
    ToolArgs,
    /// Tool / function-call results (Phase 2; largest leak surface).
    ToolResults,
    /// Session-accurate file diffs (the Phase-1 headline).
    FileDiffs,
    /// Shell commands + exit codes.
    Commands,
    /// The redaction *floor* — locked on, force-redacted. Records only a
    /// "secret redacted" marker, never the value.
    Secrets,
    /// Passive browser `/ingest` events (Phase 2; collector-side gate).
    BrowserData,
    /// Provider / model / token / cost metadata — the one class exported by
    /// default (no payload).
    ModelMetadata,
}

impl SensitivityClass {
    /// Every class (used to apply defaults / iterate rules).
    pub const ALL: [SensitivityClass; 9] = [
        SensitivityClass::Transcript,
        SensitivityClass::Prompts,
        SensitivityClass::ToolArgs,
        SensitivityClass::ToolResults,
        SensitivityClass::FileDiffs,
        SensitivityClass::Commands,
        SensitivityClass::Secrets,
        SensitivityClass::BrowserData,
        SensitivityClass::ModelMetadata,
    ];

    /// Stable snake_case wire string (mirrors `Kind::as_str` in `event.rs` and
    /// the serde representation). This is the value written into the
    /// `max_sensitivity` column and read back by the export projection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SensitivityClass::Transcript => "transcript",
            SensitivityClass::Prompts => "prompts",
            SensitivityClass::ToolArgs => "tool_args",
            SensitivityClass::ToolResults => "tool_results",
            SensitivityClass::FileDiffs => "file_diffs",
            SensitivityClass::Commands => "commands",
            SensitivityClass::Secrets => "secrets",
            SensitivityClass::BrowserData => "browser_data",
            SensitivityClass::ModelMetadata => "model_metadata",
        }
    }
}

/// 256 KiB — the per-file redacted-diff cap (`file_diffs`).
const KIB_256: u64 = 256 * 1024;
/// 128 KiB — the prompt body cap (`prompts`).
const KIB_128: u64 = 128 * 1024;
/// 64 KiB — the tool args/results body cap.
const KIB_64: u64 = 64 * 1024;

/// Per-class capture rule. All fields are `#[serde(default)]` so a partial
/// `[capture.classes.<c>]` table keeps the recorder-on defaults for the rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassRule {
    /// Whether this class is captured at all.
    pub capture: bool,
    /// How this class is redacted relative to the global switch.
    pub redaction: RedactionMode,
    /// Per-class retention age, in days (`None` = use the global retention).
    pub max_age_days: Option<u32>,
    /// Per-row body cap, in bytes (`None` = uncapped). Bodies are truncated on a
    /// char boundary by [`CapturePolicy::cap_body`].
    pub max_bytes: Option<u64>,
    /// Whether this class is included in the `logbook export` projection. Every
    /// payload class defaults to `false`; only `model_metadata` exports.
    pub export: bool,
}

impl Default for ClassRule {
    /// A captured, default-redacted, uncapped, not-exported class — the base
    /// recorder-on posture before per-class overrides in [`ClassRules::default`].
    fn default() -> Self {
        Self {
            capture: true,
            redaction: RedactionMode::Default,
            max_age_days: None,
            max_bytes: None,
            export: false,
        }
    }
}

/// Per-sensitivity-class rules. One [`ClassRule`] per class. All
/// `#[serde(default)]`, so an absent `[capture.classes]` (or any subset) keeps
/// the recorder-on defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassRules {
    /// Redacted terminal transcript + cleaned text.
    pub transcript: ClassRule,
    /// Prompts sent to a model.
    pub prompts: ClassRule,
    /// Tool / function-call arguments.
    pub tool_args: ClassRule,
    /// Tool / function-call results.
    pub tool_results: ClassRule,
    /// Session-accurate file diffs.
    pub file_diffs: ClassRule,
    /// Shell commands + exit codes.
    pub commands: ClassRule,
    /// The redaction floor — locked on + force-redacted.
    pub secrets: ClassRule,
    /// Passive browser `/ingest` events.
    pub browser_data: ClassRule,
    /// Provider / model / token / cost metadata.
    pub model_metadata: ClassRule,
}

impl Default for ClassRules {
    /// The recorder-on defaults from the plan table: every class captures; the
    /// payload classes (`file_diffs`, `tool_args`, `tool_results`, `prompts`,
    /// `secrets`) are force-redacted (`Always`) and size-capped; only
    /// `model_metadata` is exported.
    fn default() -> Self {
        Self {
            transcript: ClassRule::default(),
            commands: ClassRule::default(),
            browser_data: ClassRule::default(),
            // The one class exported by default (metadata, no payload).
            model_metadata: ClassRule {
                export: true,
                ..ClassRule::default()
            },
            // Force-redacted, size-capped payload classes.
            file_diffs: ClassRule {
                redaction: RedactionMode::Always,
                max_bytes: Some(KIB_256),
                ..ClassRule::default()
            },
            tool_args: ClassRule {
                redaction: RedactionMode::Always,
                max_bytes: Some(KIB_64),
                ..ClassRule::default()
            },
            tool_results: ClassRule {
                redaction: RedactionMode::Always,
                max_bytes: Some(KIB_64),
                ..ClassRule::default()
            },
            prompts: ClassRule {
                redaction: RedactionMode::Always,
                max_bytes: Some(KIB_128),
                ..ClassRule::default()
            },
            // The secrets floor: locked on + force-redacted (enforced by
            // `validate()`), no body persisted.
            secrets: ClassRule {
                capture: true,
                redaction: RedactionMode::Always,
                ..ClassRule::default()
            },
        }
    }
}

/// Per-tier master switches. Universal + Structured default on, Complete off
/// (the LLM-proxy tier is opt-in by mechanism and requires explicit confirm).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tiers {
    /// Tier 1 — redacted transcript, commands, exit codes, session-accurate file
    /// diffs.
    pub universal: bool,
    /// Tier 2 — prompts, tool calls + args/results, model/token/cost metadata.
    pub structured: bool,
    /// Tier 3 — full provider traffic, governance-grade audit. Off by default.
    pub complete: bool,
}

impl Default for Tiers {
    fn default() -> Self {
        Self {
            universal: true,
            structured: true,
            complete: false,
        }
    }
}

/// The `[capture]` policy: per-tier master switches + per-class rules, plus the
/// global enable (the UI-toggle target) and the reversible-dirty opt-in.
///
/// `Default` is **recorder-on** (plan table): `enabled=true`,
/// `universal=true`/`structured=true`/`complete=false`, every class captures,
/// payload classes force-redacted + size-capped, `reversible_dirty=false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CapturePolicy {
    /// Master capture switch (the UI on/off toggle target).
    pub enabled: bool,
    /// Per-tier master switches.
    pub tiers: Tiers,
    /// Per-sensitivity-class rules.
    pub classes: ClassRules,
    /// Opt-in: additionally store **encrypted** preimages so a dirty-tree
    /// session is revertable. Off by default (only redacted diffs persist).
    pub reversible_dirty: bool,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            tiers: Tiers::default(),
            classes: ClassRules::default(),
            reversible_dirty: false,
        }
    }
}

impl CapturePolicy {
    /// A fully capture-OFF policy — used as the fail-closed degrade target when
    /// strict config load or [`Self::validate`] fails. Every class still keeps
    /// its redaction posture (the secrets floor never relaxes), but `enabled` is
    /// false so [`Self::should_capture`] returns `false` for every content
    /// class.
    #[must_use]
    pub fn off() -> Self {
        Self {
            enabled: false,
            tiers: Tiers {
                universal: false,
                structured: false,
                complete: false,
            },
            ..Self::default()
        }
    }

    /// The rule for a sensitivity class.
    #[must_use]
    pub fn rule(&self, class: SensitivityClass) -> &ClassRule {
        match class {
            SensitivityClass::Transcript => &self.classes.transcript,
            SensitivityClass::Prompts => &self.classes.prompts,
            SensitivityClass::ToolArgs => &self.classes.tool_args,
            SensitivityClass::ToolResults => &self.classes.tool_results,
            SensitivityClass::FileDiffs => &self.classes.file_diffs,
            SensitivityClass::Commands => &self.classes.commands,
            SensitivityClass::Secrets => &self.classes.secrets,
            SensitivityClass::BrowserData => &self.classes.browser_data,
            SensitivityClass::ModelMetadata => &self.classes.model_metadata,
        }
    }

    /// Mutable access to a class rule (used by overlay narrowing + the UI
    /// writer). Prefer [`Self::rule`] for reads.
    fn rule_mut(&mut self, class: SensitivityClass) -> &mut ClassRule {
        match class {
            SensitivityClass::Transcript => &mut self.classes.transcript,
            SensitivityClass::Prompts => &mut self.classes.prompts,
            SensitivityClass::ToolArgs => &mut self.classes.tool_args,
            SensitivityClass::ToolResults => &mut self.classes.tool_results,
            SensitivityClass::FileDiffs => &mut self.classes.file_diffs,
            SensitivityClass::Commands => &mut self.classes.commands,
            SensitivityClass::Secrets => &mut self.classes.secrets,
            SensitivityClass::BrowserData => &mut self.classes.browser_data,
            SensitivityClass::ModelMetadata => &mut self.classes.model_metadata,
        }
    }

    /// Whether the tier master-switch gating a class is on. The Universal tier
    /// gates transcript/commands/file_diffs; the Structured tier gates
    /// prompts/tool_args/tool_results/browser_data/model_metadata. `Secrets` is
    /// the floor and is not gated by any tier (always allowed). The Complete
    /// tier gates no Phase-1 class — it governs the raw-provider-traffic classes
    /// that land in Phase 4 — so it is consulted there, not here.
    fn tier_allows(&self, class: SensitivityClass) -> bool {
        match class {
            SensitivityClass::Transcript
            | SensitivityClass::Commands
            | SensitivityClass::FileDiffs => self.tiers.universal,
            SensitivityClass::Prompts
            | SensitivityClass::ToolArgs
            | SensitivityClass::ToolResults
            | SensitivityClass::BrowserData
            | SensitivityClass::ModelMetadata => self.tiers.structured,
            SensitivityClass::Secrets => true,
        }
    }

    /// Whether to capture this class at this persistence boundary:
    /// `enabled && tier-allows && rule.capture`.
    ///
    /// `Secrets` is the redaction **floor**, not a content toggle: it is
    /// effectively always-on (the floor scrubber runs even when the master
    /// switch is off), so `should_capture(Secrets)` returns `true` regardless of
    /// `enabled` — callers use it to mean "the secrets marker may be recorded".
    #[must_use]
    pub fn should_capture(&self, class: SensitivityClass) -> bool {
        if class == SensitivityClass::Secrets {
            return true;
        }
        self.enabled && self.tier_allows(class) && self.rule(class).capture
    }

    /// Whether to redact this class, given the resolved global redaction switch
    /// (`[redaction].enabled` AND not `--no-redact`):
    /// `Always => true`, `Never => false`, `Default => global_enabled`.
    ///
    /// Note the secrets floor is *independent* of this decision — even a
    /// `false` here only disables the **general** redactor; callers must still
    /// run [`crate::Redactor::secrets_floor`] (see `redact.rs`).
    #[must_use]
    pub fn should_redact(&self, class: SensitivityClass, global_enabled: bool) -> bool {
        match self.rule(class).redaction {
            RedactionMode::Always => true,
            RedactionMode::Never => false,
            RedactionMode::Default => global_enabled,
        }
    }

    /// Cap `body` to this class's `max_bytes` on a UTF-8 char boundary, returning
    /// `(capped, original_bytes, truncated)`.
    ///
    /// When the body fits (or the class is uncapped) it is borrowed unchanged and
    /// `truncated` is `false`. When truncated, the kept prefix is snapped down to
    /// a char boundary and a `… [diff truncated N bytes]` marker is appended
    /// (the dropped-byte count `N` lets the UI render a "truncated" badge).
    /// `original_bytes` is always the pre-truncation byte length.
    #[must_use]
    pub fn cap_body<'a>(&self, class: SensitivityClass, body: &'a str) -> (Cow<'a, str>, u64, bool) {
        let original_bytes = body.len() as u64;
        let Some(max) = self.rule(class).max_bytes else {
            return (Cow::Borrowed(body), original_bytes, false);
        };
        let max = max as usize;
        if body.len() <= max {
            return (Cow::Borrowed(body), original_bytes, false);
        }
        // Snap the kept prefix down to a char boundary (reusing the shared text
        // helper) so we never split a multibyte char, then append a byte-count
        // marker.
        let end = floor_char_boundary(body, max);
        let dropped = body.len() - end;
        let mut out = String::with_capacity(end + 32);
        out.push_str(&body[..end]);
        out.push_str(&format!("… [diff truncated {dropped} bytes]"));
        (Cow::Owned(out), original_bytes, true)
    }

    /// Validate the policy at load. **Rejects** (plan guardrails):
    /// - `secrets.capture = false` — the floor cannot be turned off;
    /// - `secrets.redaction = "never"` — the floor cannot be un-redacted;
    /// - the `complete` tier enabled without an explicit confirm (a guard against
    ///   the raw-provider-traffic tier being switched on by a stray config).
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] describing the first violated guardrail.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.classes.secrets.capture {
            return Err(ConfigError::Parse(
                "[capture.classes.secrets] capture=false is rejected: the secrets floor is locked on"
                    .to_string(),
            ));
        }
        if self.classes.secrets.redaction == RedactionMode::Never {
            return Err(ConfigError::Parse(
                "[capture.classes.secrets] redaction=\"never\" is rejected: the secrets floor cannot be disabled"
                    .to_string(),
            ));
        }
        if self.tiers.complete {
            return Err(ConfigError::Parse(
                "[capture.tiers] complete=true requires explicit confirmation (the complete tier captures raw provider traffic and is not enabled by config alone)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve the effective policy for a producer, layering (lowest → highest
    /// precedence):
    /// 1. built-in recorder-on [`Self::default`];
    /// 2. `<root>/logbook.toml` `[capture]` — loaded **strictly**
    ///    ([`LogbookConfig::load_from_root`] + [`Self::validate`]); on **any**
    ///    parse/validate error the whole policy **degrades to capture-OFF**
    ///    ([`Self::off`], logged via `tracing::warn!`) — never recorder-on;
    /// 3. `<out_dir>/capture-state.json` ([`CaptureState`]) — a **narrow-only**
    ///    runtime overlay (may flip things off, never widen); a malformed file is
    ///    ignored (it cannot increase capture);
    /// 4. the CLI [`CliOverlay`].
    ///
    /// This is the one shared helper `run`/`agent`/`collector`/`ui` all call, so
    /// the cross-process pause switch behaves identically everywhere.
    #[must_use]
    pub fn resolve(root: &Path, out_dir: &Path, overlay: CliOverlay) -> CapturePolicy {
        // (1)+(2): strict, fail-closed load of <root>/logbook.toml [capture].
        let mut policy = match LogbookConfig::load_from_root(root) {
            Ok(cfg) => {
                let candidate = cfg.capture;
                if let Err(e) = candidate.validate() {
                    tracing::warn!(
                        error = %e,
                        root = %root.display(),
                        "[capture] failed validation; degrading to capture-OFF (fail-closed)"
                    );
                    CapturePolicy::off()
                } else {
                    candidate
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    root = %root.display(),
                    "logbook.toml failed strict load; degrading capture to OFF (fail-closed)"
                );
                CapturePolicy::off()
            }
        };

        // (3): narrow-only runtime overlay from <out_dir>/capture-state.json.
        match CaptureState::load(out_dir) {
            Ok(Some(state)) => state.narrow(&mut policy),
            Ok(None) => {}
            Err(e) => {
                // A malformed/unreadable overlay can only *narrow*, so ignoring
                // it cannot widen capture. Log and continue (not capture-off).
                tracing::warn!(
                    error = %e,
                    out_dir = %out_dir.display(),
                    "capture-state.json unreadable/malformed; ignoring overlay (narrow-only)"
                );
            }
        }

        // (4): CLI flags (also narrow-only in spirit — see CliOverlay::apply).
        overlay.apply(&mut policy);
        policy
    }
}

/// The CLI-flag overlay applied last by [`CapturePolicy::resolve`]. Every field
/// is optional so an unset flag leaves the layered value untouched.
///
/// In Phase 1 the only flags that can *widen* are guarded by the strict config
/// already present; in practice these flags narrow or set bounds:
/// - `capture_diffs` — `--capture-diffs` / `--no-capture-diffs`
///   (toggles the `file_diffs` class capture);
/// - `diff_max_bytes` — `--diff-max-bytes` (sets the `file_diffs` body cap);
/// - `no_redact` — `--no-redact` (parity flag; recorded so producers disable
///   only the **general** redactor — never the secrets floor);
/// - `master_enabled` — programmatic master on/off (the UI/CLI pause switch).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CliOverlay {
    /// `--capture-diffs` (`Some(true)`) / `--no-capture-diffs` (`Some(false)`).
    pub capture_diffs: Option<bool>,
    /// `--diff-max-bytes N` — the per-file `file_diffs` body cap.
    pub diff_max_bytes: Option<u64>,
    /// `--no-redact` — disable only `Default`-mode (non-secret) redaction. The
    /// secrets floor is unaffected. This flag is carried on the policy for
    /// producers to consult; it does not change any class's `RedactionMode`.
    pub no_redact: bool,
    /// Programmatic master switch (`Some(false)` pauses capture, `Some(true)`
    /// re-enables within what config+defaults already allow).
    pub master_enabled: Option<bool>,
}

impl CliOverlay {
    /// Whether `--no-redact` was passed (disables only the general redactor).
    #[must_use]
    pub fn no_redact(&self) -> bool {
        self.no_redact
    }

    /// Apply the CLI flags onto a resolved policy.
    fn apply(&self, policy: &mut CapturePolicy) {
        if let Some(master) = self.master_enabled {
            policy.enabled = master;
        }
        if let Some(capture_diffs) = self.capture_diffs {
            policy.classes.file_diffs.capture = capture_diffs;
        }
        if let Some(max) = self.diff_max_bytes {
            policy.classes.file_diffs.max_bytes = Some(max);
        }
        // `no_redact` deliberately does NOT mutate any RedactionMode here: the
        // secrets floor must remain, and `Always` classes stay `Always`. It is
        // surfaced via `CliOverlay::no_redact()` so producers feed it as the
        // `global_enabled` argument to `should_redact`.
    }
}

/// The on-disk runtime overlay written by the UI capture toggle and read by
/// [`CapturePolicy::resolve`]. Lives at `<out_dir>/capture-state.json`.
///
/// **Narrow-only**: this overlay may only *disable* the master switch or
/// individual classes; it can never widen capture beyond what `logbook.toml` +
/// defaults already allow (enforced by [`CaptureState::narrow`]). The `secrets`
/// class is intentionally absent — it cannot be toggled here.
///
/// All fields are `#[serde(default)]` so a partial file (or a future field) is
/// tolerated; an absent field means "no override for this knob".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureState {
    /// Master on/off override. `Some(false)` pauses all content capture across
    /// processes; `Some(true)` is honoured only as "do not narrow the master".
    pub enabled: Option<bool>,
    /// Per-class capture overrides. A `Some(false)` disables that class;
    /// `Some(true)` is ignored (narrow-only). `secrets` is never read.
    pub classes: CaptureStateClasses,
}

/// Per-class booleans for [`CaptureState`]. Each is `Option<bool>`; `None` means
/// "no override". `secrets` is deliberately omitted (locked floor).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureStateClasses {
    /// Transcript capture override.
    pub transcript: Option<bool>,
    /// Prompts capture override.
    pub prompts: Option<bool>,
    /// Tool-args capture override.
    pub tool_args: Option<bool>,
    /// Tool-results capture override.
    pub tool_results: Option<bool>,
    /// File-diffs capture override.
    pub file_diffs: Option<bool>,
    /// Commands capture override.
    pub commands: Option<bool>,
    /// Browser-data capture override.
    pub browser_data: Option<bool>,
    /// Model-metadata capture override.
    pub model_metadata: Option<bool>,
}

impl CaptureState {
    /// Resolve the overlay path inside an out-dir.
    #[must_use]
    pub fn path_in_out_dir(out_dir: impl AsRef<Path>) -> std::path::PathBuf {
        out_dir.as_ref().join(CAPTURE_STATE_FILENAME)
    }

    /// Load the overlay from `<out_dir>/capture-state.json`.
    ///
    /// A **missing file is `Ok(None)`** (no overlay). A present-but-malformed or
    /// unreadable file returns an error; callers in [`CapturePolicy::resolve`]
    /// treat that as "ignore the overlay" since it can only narrow.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file exists but cannot be read or parsed.
    pub fn load(out_dir: impl AsRef<Path>) -> Result<Option<Self>, ConfigError> {
        let path = Self::path_in_out_dir(out_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).map(Some).map_err(|e| {
                    ConfigError::Parse(format!("{CAPTURE_STATE_FILENAME}: {e}"))
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ConfigError::Io { path, source: e }),
        }
    }

    /// Persist the overlay to `<out_dir>/capture-state.json` **atomically**
    /// (write a sibling temp file, then rename over the target so a reader never
    /// sees a half-written file). Creates `out_dir` if needed.
    ///
    /// # Errors
    /// Returns [`ConfigError`] on serialization or I/O failure.
    pub fn save(&self, out_dir: impl AsRef<Path>) -> Result<(), ConfigError> {
        use std::io::Write;

        let out_dir = out_dir.as_ref();
        let path = Self::path_in_out_dir(out_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Unique-ish temp sibling so concurrent writers don't collide.
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| ConfigError::Io {
                path: tmp.clone(),
                source: e,
            })?;
            f.write_all(body.as_bytes())
                .and_then(|()| f.flush())
                .map_err(|e| ConfigError::Io {
                    path: tmp.clone(),
                    source: e,
                })?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            ConfigError::Io { path, source: e }
        })
    }

    /// Apply this overlay onto `policy`, **narrowing only**: a `Some(false)`
    /// master/class flips the policy off; a `Some(true)` or `None` leaves the
    /// layered value untouched (never widens). The `secrets` class is never
    /// touched (it has no field here).
    fn narrow(&self, policy: &mut CapturePolicy) {
        if self.enabled == Some(false) {
            policy.enabled = false;
        }
        // Pair each overlay field with its class; only `Some(false)` narrows.
        let pairs: [(Option<bool>, SensitivityClass); 8] = [
            (self.classes.transcript, SensitivityClass::Transcript),
            (self.classes.prompts, SensitivityClass::Prompts),
            (self.classes.tool_args, SensitivityClass::ToolArgs),
            (self.classes.tool_results, SensitivityClass::ToolResults),
            (self.classes.file_diffs, SensitivityClass::FileDiffs),
            (self.classes.commands, SensitivityClass::Commands),
            (self.classes.browser_data, SensitivityClass::BrowserData),
            (self.classes.model_metadata, SensitivityClass::ModelMetadata),
        ];
        for (flag, class) in pairs {
            if flag == Some(false) {
                policy.rule_mut(class).capture = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- recorder-on defaults --------------------------------------------

    #[test]
    fn default_is_recorder_on() {
        let p = CapturePolicy::default();
        assert!(p.enabled, "master enabled");
        assert!(p.tiers.universal && p.tiers.structured);
        assert!(!p.tiers.complete, "complete tier off by default");
        assert!(!p.reversible_dirty);
        // Every class captures.
        for c in SensitivityClass::ALL {
            assert!(p.rule(c).capture, "{} should capture", c.as_str());
        }
        // Force-redact set.
        for c in [
            SensitivityClass::FileDiffs,
            SensitivityClass::ToolArgs,
            SensitivityClass::ToolResults,
            SensitivityClass::Prompts,
            SensitivityClass::Secrets,
        ] {
            assert_eq!(
                p.rule(c).redaction,
                RedactionMode::Always,
                "{} must force-redact",
                c.as_str()
            );
        }
        // Caps.
        assert_eq!(p.rule(SensitivityClass::FileDiffs).max_bytes, Some(256 * 1024));
        assert_eq!(p.rule(SensitivityClass::ToolArgs).max_bytes, Some(64 * 1024));
        assert_eq!(p.rule(SensitivityClass::ToolResults).max_bytes, Some(64 * 1024));
        assert_eq!(p.rule(SensitivityClass::Prompts).max_bytes, Some(128 * 1024));
        // Export: only model_metadata.
        for c in SensitivityClass::ALL {
            let want = c == SensitivityClass::ModelMetadata;
            assert_eq!(p.rule(c).export, want, "export({})", c.as_str());
        }
    }

    #[test]
    fn class_as_str_is_snake_case_and_matches_serde() {
        for c in SensitivityClass::ALL {
            assert_eq!(
                serde_json::to_value(c).unwrap(),
                serde_json::json!(c.as_str()),
                "serde must match as_str for {}",
                c.as_str()
            );
        }
        assert_eq!(SensitivityClass::ToolArgs.as_str(), "tool_args");
        assert_eq!(SensitivityClass::ModelMetadata.as_str(), "model_metadata");
        assert_eq!(SensitivityClass::FileDiffs.as_str(), "file_diffs");
    }

    // ---- config layering -------------------------------------------------

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn absent_capture_section_is_recorder_on() {
        let tmp = tempfile::tempdir().unwrap();
        // A logbook.toml with NO [capture] table.
        write(tmp.path(), "logbook.toml", "[redaction]\nenabled = true\n");
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert_eq!(p, CapturePolicy::default(), "valid-absent => recorder-on");
        assert!(p.should_capture(SensitivityClass::FileDiffs));
    }

    #[test]
    fn missing_logbook_toml_is_recorder_on() {
        let tmp = tempfile::tempdir().unwrap();
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert_eq!(p, CapturePolicy::default());
    }

    #[test]
    fn malformed_capture_degrades_to_off() {
        let tmp = tempfile::tempdir().unwrap();
        // `tiers` is a table, not a string — schema mismatch => strict load err.
        write(tmp.path(), "logbook.toml", "[capture]\ntiers = \"not-a-table\"\n");
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert!(!p.enabled, "malformed [capture] must fail closed to OFF");
        assert!(!p.should_capture(SensitivityClass::FileDiffs));
        // Secrets floor is still considered always-on.
        assert!(p.should_capture(SensitivityClass::Secrets));
    }

    #[test]
    fn secrets_capture_false_is_rejected() {
        let p = CapturePolicy {
            classes: ClassRules {
                secrets: ClassRule {
                    capture: false,
                    ..ClassRule::default()
                },
                ..ClassRules::default()
            },
            ..CapturePolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn secrets_redaction_never_is_rejected_via_toml() {
        // Round-trips the documented guardrail through the strict resolve path.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "logbook.toml",
            "[capture.classes.secrets]\nredaction = \"never\"\n",
        );
        // Direct validate() on the parsed policy errors...
        let cfg = LogbookConfig::load_from_root(tmp.path()).unwrap();
        assert!(cfg.capture.validate().is_err(), "never on secrets must reject");
        // ...and resolve() therefore degrades to OFF (fail-closed).
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert!(!p.enabled);
    }

    #[test]
    fn complete_tier_enable_is_rejected() {
        let p = CapturePolicy {
            tiers: Tiers {
                complete: true,
                ..Tiers::default()
            },
            ..CapturePolicy::default()
        };
        assert!(p.validate().is_err(), "complete tier needs explicit confirm");
    }

    // ---- narrow-only overlay --------------------------------------------

    #[test]
    fn capture_state_overlay_narrows_only() {
        let tmp = tempfile::tempdir().unwrap();
        // Config is recorder-on (no [capture] => default).
        // Overlay tries to: disable file_diffs (narrow, allowed) AND
        // "enable" complete-ish widening by setting transcript=true (no-op).
        let state = CaptureState {
            enabled: Some(true), // a Some(true) must NOT widen anything
            classes: CaptureStateClasses {
                file_diffs: Some(false), // narrow
                transcript: Some(true),  // widen attempt -> ignored
                ..CaptureStateClasses::default()
            },
        };
        state.save(tmp.path()).unwrap();

        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        // Narrowed off.
        assert!(!p.should_capture(SensitivityClass::FileDiffs), "file_diffs narrowed off");
        // Master still on (Some(true) didn't force anything, default was on).
        assert!(p.enabled);
        // transcript stays captured (the Some(true) is a no-op, not a widen).
        assert!(p.should_capture(SensitivityClass::Transcript));
    }

    #[test]
    fn capture_state_cannot_widen_a_disabled_class() {
        // Start from a config that disables a class, then an overlay tries to
        // re-enable it. The overlay must NOT widen it back on.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "logbook.toml",
            "[capture.classes.file_diffs]\ncapture = false\n",
        );
        let state = CaptureState {
            classes: CaptureStateClasses {
                file_diffs: Some(true), // widen attempt
                ..CaptureStateClasses::default()
            },
            ..CaptureState::default()
        };
        state.save(tmp.path()).unwrap();

        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert!(
            !p.should_capture(SensitivityClass::FileDiffs),
            "overlay must not widen a config-disabled class back on"
        );
    }

    #[test]
    fn capture_state_master_off_pauses_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let state = CaptureState {
            enabled: Some(false),
            ..CaptureState::default()
        };
        state.save(tmp.path()).unwrap();
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert!(!p.enabled, "master-off overlay pauses capture cross-process");
        assert!(!p.should_capture(SensitivityClass::Transcript));
        // Floor still on.
        assert!(p.should_capture(SensitivityClass::Secrets));
    }

    #[test]
    fn malformed_capture_state_is_ignored_not_off() {
        let tmp = tempfile::tempdir().unwrap();
        // Recorder-on config + garbage overlay => overlay ignored, stays on.
        std::fs::write(
            CaptureState::path_in_out_dir(tmp.path()),
            "{ not valid json",
        )
        .unwrap();
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), CliOverlay::default());
        assert!(p.enabled, "malformed overlay is ignored (can only narrow)");
        assert!(p.should_capture(SensitivityClass::FileDiffs));
    }

    #[test]
    fn capture_state_save_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let state = CaptureState {
            enabled: Some(false),
            classes: CaptureStateClasses {
                prompts: Some(false),
                ..CaptureStateClasses::default()
            },
        };
        state.save(tmp.path()).unwrap();
        let back = CaptureState::load(tmp.path()).unwrap().unwrap();
        assert_eq!(state, back);
        // No leftover temp file.
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "atomic save must leave no temp file");
    }

    #[test]
    fn capture_state_missing_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(CaptureState::load(tmp.path()).unwrap(), None);
    }

    // ---- CLI overlay -----------------------------------------------------

    #[test]
    fn cli_overlay_sets_diff_cap_and_master() {
        let tmp = tempfile::tempdir().unwrap();
        let overlay = CliOverlay {
            capture_diffs: Some(false),
            diff_max_bytes: Some(1024),
            no_redact: true,
            master_enabled: Some(false),
        };
        let p = CapturePolicy::resolve(tmp.path(), tmp.path(), overlay);
        assert!(!p.enabled, "--master off");
        assert!(!p.classes.file_diffs.capture, "--no-capture-diffs");
        assert_eq!(p.classes.file_diffs.max_bytes, Some(1024), "--diff-max-bytes");
        // no_redact never changes a RedactionMode (floor + Always preserved).
        assert_eq!(p.classes.file_diffs.redaction, RedactionMode::Always);
    }

    // ---- should_capture / should_redact / cap_body -----------------------

    #[test]
    fn should_capture_respects_master_tier_and_rule() {
        let mut p = CapturePolicy::default();
        assert!(p.should_capture(SensitivityClass::FileDiffs));
        // Master off.
        p.enabled = false;
        assert!(!p.should_capture(SensitivityClass::FileDiffs));
        // Secrets floor unaffected by master.
        assert!(p.should_capture(SensitivityClass::Secrets));
        // Tier off.
        p.enabled = true;
        p.tiers.universal = false;
        assert!(!p.should_capture(SensitivityClass::FileDiffs), "universal tier gates file_diffs");
        assert!(p.should_capture(SensitivityClass::ModelMetadata), "structured tier still on");
        // Rule off.
        p.tiers.universal = true;
        p.classes.file_diffs.capture = false;
        assert!(!p.should_capture(SensitivityClass::FileDiffs));
    }

    #[test]
    fn should_redact_maps_modes() {
        let p = CapturePolicy::default();
        // Always => true regardless of global.
        assert!(p.should_redact(SensitivityClass::FileDiffs, false));
        assert!(p.should_redact(SensitivityClass::Secrets, false));
        // Default => obeys global.
        assert!(p.should_redact(SensitivityClass::Transcript, true));
        assert!(!p.should_redact(SensitivityClass::Transcript, false));
        // Never => false. (Build a policy with a Never class to exercise it.)
        let mut p2 = CapturePolicy::default();
        p2.classes.transcript.redaction = RedactionMode::Never;
        assert!(!p2.should_redact(SensitivityClass::Transcript, true));
    }

    #[test]
    fn cap_body_truncates_on_char_boundary() {
        let p = CapturePolicy::default();
        // Uncapped class returns borrowed, untruncated.
        let (c, orig, trunc) = p.cap_body(SensitivityClass::Transcript, "hello");
        assert_eq!(c, "hello");
        assert_eq!(orig, 5);
        assert!(!trunc);

        // Capped class, body within cap -> borrowed.
        let (c, _o, trunc) = p.cap_body(SensitivityClass::ToolArgs, "small");
        assert_eq!(c, "small");
        assert!(!trunc);

        // Force a tiny cap to exercise truncation + marker + char boundary.
        let mut p2 = CapturePolicy::default();
        p2.classes.file_diffs.max_bytes = Some(4);
        let body = "abcé"; // bytes: a b c 0xC3 0xA9 = 5 bytes; cap 4 lands mid-é
        let (c, orig, trunc) = p2.cap_body(SensitivityClass::FileDiffs, body);
        assert!(trunc);
        assert_eq!(orig, 5);
        // Kept prefix snaps down to 3 bytes ("abc"); marker reports 2 dropped.
        assert!(c.starts_with("abc"), "got: {c}");
        assert!(c.contains("[diff truncated 2 bytes]"), "marker: {c}");
        assert!(!c.contains('é'), "must not split the multibyte char: {c}");
    }
}
