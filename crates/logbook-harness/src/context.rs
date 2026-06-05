//! [`HarnessContext`] — the redaction + capture-policy surface every adapter
//! routes payloads through (plan §9: "Redaction-before-persistence is sacred").
//!
//! No adapter builds an [`Event`](logbook_core::Event) field from a raw harness
//! payload directly. Instead it calls [`HarnessContext::redact_text`] /
//! [`HarnessContext::redact_json`], which:
//!
//! 1. consult [`CapturePolicy::should_redact`] for the payload's
//!    [`SensitivityClass`] to decide whether the **general** redactor runs (so
//!    `--no-redact` disables only non-secret redaction);
//! 2. **always** run the mandatory secrets floor
//!    ([`Redactor::secrets_floor`]) on top — so a cloud key / JWT / bearer /
//!    PEM is scrubbed even when the general redactor is disabled and even for a
//!    `RedactionMode::Never` class; and
//! 3. cap the result to the class's `max_bytes` via [`CapturePolicy::cap_body`].
//!
//! The capture gate ([`CapturePolicy::should_capture`]) is surfaced separately
//! via [`HarnessContext::captures`] so a caller can drop a whole class (e.g.
//! `prompts` off ⇒ metadata-only) — but anything that *is* emitted is always
//! redacted.

use serde_json::Value;

use logbook_core::{CapturePolicy, Redactor, SensitivityClass};

/// Wraps a [`Redactor`] + [`CapturePolicy`] + the resolved global-redaction flag
/// and exposes the redaction / capacity / capture helpers the adapters use.
///
/// Construct via [`HarnessContext::new`] (or the crate-level
/// [`context`](crate::context) helper). Cheap to clone is **not** provided
/// because [`Redactor`] is not `Clone`; build one context and pass it by
/// reference, or construct per adapter.
#[derive(Debug)]
pub struct HarnessContext {
    /// The general (non-secret) redactor. May be [`Redactor::disabled`] under
    /// `--no-redact`; the secrets floor is applied separately and always.
    general: Redactor,
    /// The mandatory secrets-floor redactor, seeded with the process env. Runs
    /// on **every** emitted payload regardless of the general switch or class
    /// redaction mode, so a raw secret can never reach an `Event`.
    floor: Redactor,
    /// The resolved capture policy (per-class capture, redaction mode, caps).
    policy: CapturePolicy,
    /// The resolved global redaction switch (`[redaction].enabled && !--no-redact`),
    /// fed to [`CapturePolicy::should_redact`] for `RedactionMode::Default`
    /// classes.
    global_redaction_enabled: bool,
}

impl HarnessContext {
    /// Build a context from the **general** redactor, the resolved capture
    /// policy, and the resolved global redaction switch.
    ///
    /// The mandatory secrets floor is constructed internally
    /// ([`Redactor::secrets_floor_with_process_env`]) and applied to every
    /// emitted payload, so callers need not (and must not) rely on `redactor`
    /// alone to scrub secrets.
    #[must_use]
    pub fn new(redactor: Redactor, policy: CapturePolicy, global_redaction_enabled: bool) -> Self {
        Self {
            general: redactor,
            floor: Redactor::secrets_floor_with_process_env(),
            policy,
            global_redaction_enabled,
        }
    }

    /// A context with the default recorder-on policy and an enabled general
    /// redactor — the common case (capture on, redaction on).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Redactor::new(), CapturePolicy::default(), true)
    }

    /// The resolved capture policy (read-only).
    #[must_use]
    pub fn policy(&self) -> &CapturePolicy {
        &self.policy
    }

    /// Whether the policy says to capture `class` at all
    /// ([`CapturePolicy::should_capture`]). A caller may use this to omit an
    /// entire class (e.g. drop the prompt body when `prompts` is off) — but any
    /// payload that *is* emitted is still redacted.
    #[must_use]
    pub fn captures(&self, class: SensitivityClass) -> bool {
        self.policy.should_capture(class)
    }

    /// Redact `text` for `class` and cap it, returning `(redacted, truncated)`.
    ///
    /// The general redactor runs only when
    /// [`CapturePolicy::should_redact`]`(class, global)` is true; the secrets
    /// floor **always** runs on top. The result is then capped to the class's
    /// `max_bytes`. The returned string is owned and safe to place on an
    /// `Event`.
    #[must_use]
    pub fn redact_text(&self, class: SensitivityClass, text: &str) -> (String, bool) {
        // (1) general redaction, gated by class redaction mode + global switch.
        let general = if self.policy.should_redact(class, self.global_redaction_enabled) {
            self.general.redact(text)
        } else {
            std::borrow::Cow::Borrowed(text)
        };
        // (2) mandatory secrets floor — runs regardless, so a secret is scrubbed
        // even under `--no-redact` or a `Never` class.
        let floored = self.floor.redact(general.as_ref()).into_owned();
        // (3) cap to the class body bound.
        let (capped, _orig, truncated) = self.policy.cap_body(class, &floored);
        (capped.into_owned(), truncated)
    }

    /// Recursively redact every string inside `value` for `class`, returning a
    /// fresh, redacted [`Value`] safe to place on an `Event` (e.g. tool
    /// `arguments`).
    ///
    /// Object **keys** are preserved (only values are scrubbed), matching
    /// [`Redactor::redact_json`]. The general redactor is gated as in
    /// [`Self::redact_text`]; the secrets floor always runs on top. JSON bodies
    /// are **not** byte-capped here (the structure is preserved); cap a
    /// stringified form via [`Self::redact_text`] if a size bound is needed.
    #[must_use]
    pub fn redact_json(&self, class: SensitivityClass, value: &Value) -> Value {
        let mut out = value.clone();
        if self.policy.should_redact(class, self.global_redaction_enabled) {
            self.general.redact_json(&mut out);
        }
        // Mandatory secrets floor on top, always.
        self.floor.redact_json(&mut out);
        out
    }

    /// Redact tool-call arguments **and enforce the `tool_args` byte cap**,
    /// returning `(value, truncated)` ready to place on
    /// [`ToolBlock::arguments`](logbook_core::ToolBlock).
    ///
    /// Unlike [`Self::redact_json`] (which preserves structure but is *not*
    /// byte-capped), this is the storage path the plan mandates for tool
    /// arguments (`tool_args`: force-redact **+ 64 KiB cap**). It:
    /// 1. recursively redacts the structured `value` ([`Self::redact_json`] —
    ///    general layer gated by class, secrets floor always on);
    /// 2. serializes the redacted value and runs
    ///    [`CapturePolicy::cap_body`]`(ToolArgs, …)`; and
    /// 3. when the serialized form is **within** the cap, returns the redacted
    ///    structured [`Value`] unchanged (`truncated = false`); when it **exceeds**
    ///    the cap, returns the **capped string** as a [`Value::String`]
    ///    (`truncated = true`) — the structured shape is dropped in favor of a
    ///    bounded body so an oversized argument blob can never be persisted
    ///    uncapped.
    ///
    /// Callers should stamp an `arguments_truncated` attribute on the event when
    /// the returned flag is `true`.
    #[must_use]
    pub fn redact_tool_args(&self, value: &Value) -> (Value, bool) {
        // (1) structural redaction (general gated by class + secrets floor).
        let redacted = self.redact_json(SensitivityClass::ToolArgs, value);
        // (2) serialize + cap to the tool_args byte bound.
        let serialized = serde_json::to_string(&redacted).unwrap_or_default();
        let (capped, _orig, truncated) =
            self.policy.cap_body(SensitivityClass::ToolArgs, &serialized);
        if truncated {
            // (3b) over-cap: store the bounded STRING (with the truncation
            // marker), not the full structured value.
            (Value::String(capped.into_owned()), true)
        } else {
            // (3a) within cap: keep the redacted structure intact.
            (redacted, false)
        }
    }

    /// Convenience: redact a short summary string for the `tool_results` class
    /// (the `ToolBlock.result_summary` digest). Caps to the `tool_results`
    /// bound; the floor always applies.
    #[must_use]
    pub fn redact_summary(&self, text: &str) -> String {
        self.redact_text(SensitivityClass::ToolResults, text).0
    }

    /// Scrub a short, attacker-controlled **metadata string** (e.g. the
    /// `harness_version` stamped on every event) before it lands on an
    /// attribute: run the **mandatory secrets floor** over it and cap it to
    /// `max_bytes` (snapped to a char boundary, with an ellipsis when shortened).
    ///
    /// Unlike [`Self::redact_text`] this is class-agnostic — it intentionally
    /// applies only the secrets floor (not the general, capture-policy-gated
    /// redactor), because a version banner is not a payload class but still
    /// arrives from the harness and must never be a secret-exfiltration or
    /// unbounded-growth vector.
    #[must_use]
    pub fn scrub_metadata(&self, text: &str, max_bytes: usize) -> String {
        let floored = self.floor.redact(text);
        logbook_core::truncate_with_ellipsis(floored.as_ref(), max_bytes)
    }
}

impl Default for HarnessContext {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::RedactionMode;

    #[test]
    fn redact_text_scrubs_secret_and_caps() {
        let ctx = HarnessContext::with_defaults();
        let (out, trunc) = ctx.redact_text(
            SensitivityClass::Prompts,
            "please use AKIAIOSFODNN7EXAMPLE to deploy",
        );
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {out}");
        assert!(out.contains("REDACTED:CLOUD_KEY:"), "no placeholder: {out}");
        assert!(!trunc, "short prompt should not truncate");
    }

    #[test]
    fn secrets_floor_applies_even_when_general_redaction_off() {
        // Simulate `--no-redact`: a disabled general redactor and global=false.
        // The mandatory floor must still scrub a cloud key. A non-secret string
        // is left intact (the floor is secrets-only).
        let ctx = HarnessContext::new(Redactor::disabled(), CapturePolicy::default(), false);
        let (out, _t) = ctx.redact_text(
            SensitivityClass::Prompts,
            "leak AKIAIOSFODNN7EXAMPLE but keep benignword",
        );
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "floor failed: {out}");
        assert!(out.contains("benignword"), "over-redacted: {out}");
    }

    #[test]
    fn never_class_still_gets_secrets_floor() {
        // A class explicitly set to RedactionMode::Never must STILL be scrubbed
        // of secrets by the floor — "never" only disables the general layer.
        let mut policy = CapturePolicy::default();
        policy.classes.prompts.redaction = RedactionMode::Never;
        let ctx = HarnessContext::new(Redactor::new(), policy, true);
        let (out, _t) = ctx.redact_text(SensitivityClass::Prompts, "AKIAIOSFODNN7EXAMPLE here");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "Never class leaked secret: {out}");
    }

    #[test]
    fn redact_json_scrubs_values_not_keys() {
        let ctx = HarnessContext::with_defaults();
        let raw = serde_json::json!({
            "AWS_SECRET": "AKIAIOSFODNN7EXAMPLE",
            "path": "/tmp/clean",
        });
        let red = ctx.redact_json(SensitivityClass::ToolArgs, &raw);
        let s = serde_json::to_string(&red).unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "leaked in json: {s}");
        assert!(s.contains("AWS_SECRET"), "key lost: {s}");
        assert!(s.contains("/tmp/clean"), "clean value lost: {s}");
    }

    #[test]
    fn redact_tool_args_keeps_structure_when_small() {
        // A small structured argument blob: redacted + within cap ⇒ the
        // structured Value is preserved (object), not stringified, and the
        // truncated flag is false.
        let ctx = HarnessContext::with_defaults();
        let raw = serde_json::json!({
            "command": "deploy",
            "key": "AKIAIOSFODNN7EXAMPLE",
        });
        let (val, trunc) = ctx.redact_tool_args(&raw);
        assert!(!trunc, "small args must not truncate");
        assert!(val.is_object(), "small args keep their structure: {val:?}");
        let s = serde_json::to_string(&val).unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {s}");
        assert!(s.contains("command"), "key lost: {s}");
    }

    #[test]
    fn redact_tool_args_caps_oversized_blob() {
        // A huge tool-arg blob exceeding the tool_args cap ⇒ the result is a
        // bounded STRING (truncation marker), the full body is NOT persisted,
        // and the truncated flag is set.
        let mut policy = CapturePolicy::default();
        policy.classes.tool_args.max_bytes = Some(64);
        let ctx = HarnessContext::new(Redactor::new(), policy, true);
        let big = "x".repeat(10_000);
        let raw = serde_json::json!({ "blob": big });
        let (val, trunc) = ctx.redact_tool_args(&raw);
        assert!(trunc, "oversized args must truncate");
        let s = val.as_str().expect("capped args stored as a string");
        // Bounded: kept-prefix cap (64) + the marker overhead, well under input.
        assert!(s.len() <= 64 + 64, "capped body not bounded: {} bytes", s.len());
        assert!(s.contains("[diff truncated"), "truncation marker missing: {s}");
    }

    #[test]
    fn redact_tool_args_scrubs_secret_even_when_capped() {
        // Even on the capped path the secrets floor must have run before
        // serialization, so a secret near the start can never survive.
        let mut policy = CapturePolicy::default();
        policy.classes.tool_args.max_bytes = Some(80);
        let ctx = HarnessContext::new(Redactor::new(), policy, true);
        let raw = serde_json::json!({
            "key": "AKIAIOSFODNN7EXAMPLE",
            "pad": "y".repeat(10_000),
        });
        let (val, trunc) = ctx.redact_tool_args(&raw);
        assert!(trunc, "should truncate beyond the cap");
        let s = val.as_str().unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked past cap: {s}");
    }

    #[test]
    fn cap_body_truncates_oversized_prompt() {
        let mut policy = CapturePolicy::default();
        policy.classes.prompts.max_bytes = Some(8);
        let ctx = HarnessContext::new(Redactor::new(), policy, true);
        let (out, trunc) = ctx.redact_text(SensitivityClass::Prompts, "0123456789abcdef");
        assert!(trunc, "should truncate beyond the 8-byte cap");
        assert!(out.contains("[diff truncated"), "marker missing: {out}");
    }

    #[test]
    fn scrub_metadata_scrubs_secret_and_caps_length() {
        // An attacker-controlled harness_version carrying a secret and far over
        // the length cap: the floor must scrub the secret AND the result must be
        // bounded to the cap (+ ellipsis).
        let ctx = HarnessContext::with_defaults();
        let hostile = format!("v1 AKIAIOSFODNN7EXAMPLE {}", "z".repeat(500));
        let out = ctx.scrub_metadata(&hostile, 64);
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in version: {out}");
        // Kept-prefix cap is 64 bytes; ellipsis ('…') adds 3 ⇒ <= 67.
        assert!(out.len() <= 64 + 3, "version not capped: {} bytes", out.len());
        // A short, benign version is returned intact (no ellipsis, no change).
        assert_eq!(ctx.scrub_metadata("1.2.3", 64), "1.2.3");
    }

    #[test]
    fn captures_reflects_policy() {
        let ctx = HarnessContext::with_defaults();
        assert!(ctx.captures(SensitivityClass::Prompts));
        // Master off ⇒ nothing captures (except the secrets floor marker).
        let ctx = HarnessContext::new(Redactor::new(), CapturePolicy::off(), true);
        assert!(!ctx.captures(SensitivityClass::Prompts));
    }
}
