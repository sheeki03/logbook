//! `logbook-detect` — anomaly / risk detection over the unified event stream
//! (plan §Phase 3 "Anomaly/risk detection").
//!
//! This crate turns a slice of already-captured, already-**redacted**
//! [`Event`]s into a set of **findings**: new [`Event`]s with
//! [`Kind::Finding`] / [`Category::Security`] carrying a [`FindingBlock`]
//! `{ source: "detect", rule_id, severity, file?, line?, message }`. It never
//! mutates the input, performs no I/O, and is async- and dependency-light (it
//! depends only on `logbook-core`), so it can run anywhere a recorded session's
//! events are available — at session teardown, in the live guard, or over a
//! historical query.
//!
//! # Threat model & redaction
//! Detection runs **after** redaction (the store is a redacted sink), so the
//! rules look for the *evidence* of risk, not raw secrets. In particular the
//! [`SecretInDiff`] rule keys off the length-/class-preserving redaction marker
//! [`logbook_core::redact::placeholder`] (`«REDACTED:CLASS:n»`) that the
//! capture pipeline writes when it scrubs a secret out of a diff — i.e. it flags
//! "a secret was present in a code change", which is exactly what the redacted
//! record can prove without ever seeing the value.
//!
//! # The rule engine
//! A [`Rule`] is a named pure function `&[Event] -> Vec<Event>` (findings).
//! [`detect`] runs a slice of boxed rules over the same input and concatenates
//! their findings, in rule order then finding order. Each built-in rule is its
//! own type with a constructor and a [`Default`] impl carrying sane, documented
//! thresholds (see [`DetectConfig`] for the consolidated knobs and
//! [`builtin_rules`] for the default set).
//!
//! ```
//! use logbook_detect::{detect, builtin_rules, DetectConfig};
//! use logbook_core::{Event, Kind, Category};
//!
//! // A dangerous shell command somewhere on the timeline.
//! let danger = Event::new(logbook_core::TraceId::new(), Kind::Log, Category::AppLog, "stdout")
//!     .with_name("rm -rf /");
//! let rules = builtin_rules(&DetectConfig::default());
//! let findings = detect(&[danger], &rules);
//! assert_eq!(findings.len(), 1);
//! assert_eq!(findings[0].kind, Kind::Finding);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use logbook_core::{Category, Event, FindingBlock, Kind, Severity, Status};

mod view;

pub mod rules;

pub use rules::{
    DangerousShell, EgressUnallowlisted, RiskyGit, SecretInDiff, ToolCallRate, TokenCostSpike,
};

/// The `source` value stamped onto every finding this crate emits.
pub const DETECT_SOURCE: &str = "detect";

/// A detection rule: a named, pure mapping from an event stream to findings.
///
/// Rules **must not** mutate the input and **must** return events that are
/// valid findings ([`Kind::Finding`] + [`Category::Security`] + a
/// [`FindingBlock`] whose `source` is [`DETECT_SOURCE`]). The [`new_finding`]
/// helper builds a correctly-shaped finding event; built-in rules use it.
///
/// Determinism: for a given input slice a rule should produce the same findings
/// in the same order on every call (built-ins iterate the input in order).
pub trait Rule {
    /// Stable, lowercase rule identifier (also used as the finding `rule_id`),
    /// e.g. `secret_in_diff`.
    fn name(&self) -> &str;

    /// Evaluate the rule over `events`, returning zero or more finding events.
    fn evaluate(&self, events: &[Event]) -> Vec<Event>;
}

/// Run `rules` over `events` and return all findings, concatenated in rule
/// order (and, within a rule, in the order the rule emits them).
///
/// The input is borrowed and never modified. The result is a fresh `Vec` of
/// finding events; an empty result means "nothing flagged".
#[must_use]
pub fn detect(events: &[Event], rules: &[Box<dyn Rule>]) -> Vec<Event> {
    let mut out = Vec::new();
    for rule in rules {
        out.extend(rule.evaluate(events));
    }
    out
}

/// Build a correctly-shaped finding [`Event`] from a source event and rule
/// metadata.
///
/// The finding is minted on the **same `trace_id`** as `source` (so it
/// correlates onto the same session timeline), with `parent_id` pointing at the
/// source event's span where one exists, `kind = Finding`,
/// `category = Security`, `operation = "detect"`, and a [`FindingBlock`] whose
/// `source` is [`DETECT_SOURCE`]. High/critical findings are marked
/// [`Status::Error`] (mirroring `message` into `Event::error` so the existing
/// error-centric views surface them), matching the convention in
/// `logbook-security`'s `Finding::into_event`. The session id of `source` (if
/// any) is carried over.
///
/// `file` / `line` are optional locators (e.g. the file a risky diff touched).
#[must_use]
pub fn new_finding(
    source: &Event,
    rule_id: &str,
    severity: Severity,
    message: impl Into<String>,
    file: Option<String>,
    line: Option<u32>,
) -> Event {
    let message = message.into();
    let high = matches!(severity, Severity::High | Severity::Critical);

    let block = FindingBlock {
        source: Some(DETECT_SOURCE.to_string()),
        rule_id: Some(rule_id.to_string()),
        severity: Some(severity),
        file,
        line,
        message: Some(message.clone()),
    };

    let mut ev = Event::new(source.trace_id, Kind::Finding, Category::Security, rule_id)
        .with_op("detect")
        .with_name(message.clone())
        .with_finding(block)
        .with_attr("rule", rule_id.to_string())
        .with_attr("severity", severity.as_str());

    if let Some(parent) = source.parent_id {
        ev = ev.with_parent(parent);
    }
    if let Some(session) = source.session_id.clone() {
        ev = ev.with_session(session);
    }
    if high {
        ev = ev.with_error(message);
    } else {
        ev = ev.with_status(Status::Ok);
    }
    ev.debug_assert_valid();
    ev
}

/// Consolidated, documented thresholds for the built-in rules. Every field has
/// a sane default via [`Default`]; override only what you need and pass it to
/// [`builtin_rules`] (or construct individual rules directly).
///
/// Defaults are deliberately conservative — chosen to flag the clearly-risky
/// without drowning a normal coding session in noise.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectConfig {
    /// Hosts an agent is allowed to reach without flagging (used by
    /// [`EgressUnallowlisted`]). Typically sourced from
    /// `logbook.toml`'s `[permissions].allowed_domains`. A network event whose
    /// host is **not** an exact match or a subdomain of one of these raises a
    /// finding. **Empty means "everything is unallowlisted"** — i.e. every
    /// outbound host is flagged, matching the v1 browser-egress posture where an
    /// empty allowlist blocks all external navigation.
    pub allowed_domains: Vec<String>,

    /// Cost (USD) at or above which a single LLM event / rollup is flagged by
    /// [`TokenCostSpike`]. Default `5.0`.
    pub cost_usd_threshold: f64,

    /// Total-token count at or above which a single LLM event / rollup is
    /// flagged by [`TokenCostSpike`], when no cost is reported. Default
    /// `1_000_000`.
    pub token_threshold: u64,

    /// Number of tool calls within [`tool_rate_window_ms`] at or above which
    /// [`ToolCallRate`] raises a finding. Default `50`.
    pub tool_rate_max_calls: usize,

    /// Sliding-window width in milliseconds for [`ToolCallRate`]. Default
    /// `10_000` (10s).
    pub tool_rate_window_ms: i64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            cost_usd_threshold: 5.0,
            token_threshold: 1_000_000,
            tool_rate_max_calls: 50,
            tool_rate_window_ms: 10_000,
        }
    }
}

/// The default set of built-in rules, configured from `cfg`.
///
/// Order is stable (it determines the order findings appear in [`detect`]'s
/// output): `secret_in_diff`, `dangerous_shell`, `risky_git`,
/// `egress_unallowlisted`, `token_cost_spike`, `tool_call_rate`.
#[must_use]
pub fn builtin_rules(cfg: &DetectConfig) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SecretInDiff::new()),
        Box::new(DangerousShell::new()),
        Box::new(RiskyGit::new()),
        Box::new(EgressUnallowlisted::new(cfg.allowed_domains.clone())),
        Box::new(TokenCostSpike::new(cfg.cost_usd_threshold, cfg.token_threshold)),
        Box::new(ToolCallRate::new(cfg.tool_rate_max_calls, cfg.tool_rate_window_ms)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::TraceId;

    fn log(name: &str) -> Event {
        Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout").with_name(name)
    }

    #[test]
    fn detect_concatenates_in_rule_order() {
        // One dangerous shell + one risky git on the timeline; with the default
        // rule set the dangerous_shell finding (rule index 1) precedes the
        // risky_git finding (rule index 2).
        let events = vec![log("rm -rf /tmp/x"), log("git reset --hard HEAD~3")];
        let rules = builtin_rules(&DetectConfig::default());
        let findings = detect(&events, &rules);
        assert_eq!(findings.len(), 2);
        assert_eq!(rule_id(&findings[0]), "dangerous_shell");
        assert_eq!(rule_id(&findings[1]), "risky_git");
    }

    #[test]
    fn clean_stream_yields_no_findings() {
        let events = vec![log("echo hello"), log("cargo build"), log("ls -la")];
        let rules = builtin_rules(&DetectConfig::default());
        assert!(detect(&events, &rules).is_empty());
    }

    #[test]
    fn findings_are_valid_and_correlated() {
        let mut src = log("rm -rf /");
        src.session_id = Some(logbook_core::SessionId::new("sess-1"));
        let trace = src.trace_id;
        let rules = builtin_rules(&DetectConfig::default());
        let findings = detect(&[src], &rules);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.validate().is_ok());
        assert_eq!(f.kind, Kind::Finding);
        assert_eq!(f.category, Category::Security);
        assert_eq!(f.trace_id, trace, "finding correlates onto the source trace");
        assert_eq!(
            f.session_id.as_ref().map(|s| s.as_str()),
            Some("sess-1"),
            "finding inherits the source session"
        );
        let block = f.blocks.finding.as_ref().unwrap();
        assert_eq!(block.source.as_deref(), Some(DETECT_SOURCE));
    }

    #[test]
    fn empty_rule_set_is_empty() {
        let rules: Vec<Box<dyn Rule>> = Vec::new();
        assert!(detect(&[log("rm -rf /")], &rules).is_empty());
    }

    /// Helper: a finding's `rule_id`.
    pub(crate) fn rule_id(ev: &Event) -> &str {
        ev.blocks
            .finding
            .as_ref()
            .and_then(|f| f.rule_id.as_deref())
            .unwrap_or("")
    }
}
