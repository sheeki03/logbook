//! Role-based access control for hub reads (plan "Phase 4 — Complete Tier &
//! Fleet" → Hub: "**RBAC** keyed off `classes.<c>.export` (viewer sees the
//! exportable projection; auditor sees all)").
//!
//! The hub serves stored events at two trust levels:
//!
//! - a [`Role::Viewer`] read returns the **per-class export projection** — each
//!   event run through [`logbook_inventory::governance::project_event_for_export`],
//!   which drops every [`SensitivityClass`](logbook_core::SensitivityClass) whose
//!   `export = false` (every payload class by default; only `model_metadata`
//!   exports). A Viewer therefore *never* sees a prompt, a tool arg/result, a
//!   file-diff body, or a transcript line — exactly the sanitization the
//!   `logbook export` bundle uses;
//! - a [`Role::Auditor`] read returns the **full rows** unchanged (an auditor is
//!   trusted with the already-redacted payload classes for governance review).
//!
//! Both tiers see only **already-redacted** data — redaction happens upstream at
//! capture, before anything is persisted or forwarded. The projection is a
//! second, *export-sensitivity* gate on top of that, not the redaction itself.

use logbook_core::{CapturePolicy, Event};
use logbook_inventory::governance::project_event_for_export;

/// A hub access role (plan "Phase 4" → Hub RBAC). Determines whether a read sees
/// the sanitized export projection or the full already-redacted rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Least privilege (the default): reads return the per-class **export
    /// projection**, so a viewer never sees any payload class
    /// (`prompts`/`tool_args`/`tool_results`/`file_diffs`/`transcript`/…) — only
    /// `model_metadata` + structural fields survive.
    #[default]
    Viewer,
    /// Trusted reviewer: reads return the **full** already-redacted rows,
    /// including payload classes, for governance/audit work.
    Auditor,
}

impl Role {
    /// Parse the wire/string form (`viewer` / `auditor`). Unknown values fall
    /// back to the least-privileged [`Role::Viewer`] (fail-safe).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "auditor" => Role::Auditor,
            _ => Role::Viewer,
        }
    }

    /// The lowercase wire string for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Auditor => "auditor",
        }
    }

    /// Whether this role sees the full (already-redacted) rows. `false` for a
    /// [`Role::Viewer`], which gets the export projection instead.
    #[must_use]
    pub const fn sees_full_rows(self) -> bool {
        matches!(self, Role::Auditor)
    }
}

/// Apply the role's visibility to a batch of stored events.
///
/// - [`Role::Auditor`] → the events are returned unchanged (full, already-redacted
///   rows).
/// - [`Role::Viewer`] → each event is run through
///   [`project_event_for_export`] under `policy`, dropping every non-exporting
///   class's payload + typed block. The default [`CapturePolicy`] exports only
///   `model_metadata`, so a viewer sees metadata + structural fields and nothing
///   of the payload classes.
///
/// `policy` governs *which* classes export (it is the same policy the store/hub
/// is configured with). Passing a custom policy lets a deployment widen/narrow
/// what a viewer may see, but the default is the recorder-on, metadata-only
/// projection.
#[must_use]
pub fn project_for_role(role: Role, policy: &CapturePolicy, events: Vec<Event>) -> Vec<Event> {
    if role.sees_full_rows() {
        return events;
    }
    events
        .into_iter()
        .map(|ev| project_event_for_export(ev, policy))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{Category, Kind, LlmBlock, TraceId};

    #[test]
    fn role_parse_and_wire() {
        assert_eq!(Role::parse("auditor"), Role::Auditor);
        assert_eq!(Role::parse("AUDITOR"), Role::Auditor);
        assert_eq!(Role::parse("viewer"), Role::Viewer);
        // Unknown → least privilege.
        assert_eq!(Role::parse("root"), Role::Viewer);
        assert_eq!(Role::Viewer.as_str(), "viewer");
        assert_eq!(Role::Auditor.as_str(), "auditor");
        assert!(Role::Auditor.sees_full_rows());
        assert!(!Role::Viewer.sees_full_rows());
        // Default is the least-privileged role.
        assert_eq!(Role::default(), Role::Viewer);
    }

    /// An LLM event carrying a prompt payload + model metadata: the Viewer must
    /// lose the prompt (a `prompts`-class payload, export=false) while the
    /// Auditor keeps it. The metadata block survives for both (model_metadata
    /// exports).
    #[test]
    fn viewer_drops_payload_auditor_keeps_it() {
        let policy = CapturePolicy::default();
        let trace = TraceId::new();
        let mut ev = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_op("chat.completion")
            .with_llm(LlmBlock {
                model: Some("claude-3-5-sonnet".into()),
                ..Default::default()
            });
        // The prompt payload — a `prompts`-class body the Viewer must lose.
        ev.input = Some("SECRET-PROMPT-please-do-x".into());

        // Auditor: untouched.
        let auditor = project_for_role(Role::Auditor, &policy, vec![ev.clone()]);
        assert_eq!(auditor.len(), 1);
        assert_eq!(
            auditor[0].input.as_ref().and_then(|v| v.as_str()),
            Some("SECRET-PROMPT-please-do-x"),
            "auditor sees the full row"
        );

        // Viewer: prompt payload dropped, metadata kept.
        let viewer = project_for_role(Role::Viewer, &policy, vec![ev]);
        assert_eq!(viewer.len(), 1);
        assert!(
            viewer[0].input.is_none(),
            "viewer must not see the prompt payload"
        );
        // The model metadata block is the one exporting class and stays.
        assert!(
            viewer[0].blocks.llm.is_some(),
            "viewer keeps model_metadata (the one exporting class)"
        );
        let model = viewer[0]
            .blocks
            .llm
            .as_ref()
            .and_then(|b| b.model.as_deref());
        assert_eq!(model, Some("claude-3-5-sonnet"), "viewer keeps the model name");
    }
}
