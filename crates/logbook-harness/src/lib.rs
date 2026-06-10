//! `logbook-harness` — structured agent-capture adapters (Orbit Phase 2,
//! "Structured Agent Capture").
//!
//! This crate turns a coding **harness's** own records — Claude Code hook
//! events and session-log transcript lines, Codex JSONL rollouts + the
//! `codex exec --json` structured event stream, Aider history — into the
//! unified [`Event`](logbook_core::Event) spine the rest of logbook speaks.
//! Most adapters implement the small per-record [`HarnessAdapter`] trait; the
//! Codex `--json` stream needs cross-line correlation state (thread id, turn),
//! so [`CodexJsonAdapter`](codex_json::CodexJsonAdapter) exposes a whole-stream
//! entry point ([`parse_codex_json_stream`](codex_json::parse_codex_json_stream))
//! instead:
//!
//! ```text
//! trait HarnessAdapter {
//!     fn name(&self) -> &str;
//!     fn parse_record(&self, raw: &serde_json::Value) -> Vec<Event>;
//! }
//! ```
//!
//! A record maps to zero or more events:
//! - a **user prompt** → [`Kind::Agent`] + [`AgentBlock`] (`role:"user"`, with a
//!   per-turn span), the redacted prompt in [`Event::input`];
//! - a **tool call** → [`Kind::Tool`] + [`ToolBlock`] (redacted `arguments`,
//!   `is_write`), `parent_id`-linked to its turn span, redacted result in
//!   [`Event::output`];
//! - an **assistant / LLM step** → [`Kind::Llm`] + [`LlmBlock`] (`model`,
//!   token counts, `cost_usd`, `finish_reason`), parented to the turn.
//!
//! Every adapter stamps a `harness_version` attribute and **tolerates / skips**
//! records it doesn't recognize (returning an empty `Vec`), so format drift is
//! contained per-adapter and never panics the caller.
//!
//! # Redaction is sacred (plan §9)
//!
//! Tailing pre-existing harness logs is **opt-in** (not recorder-on), and **no
//! payload ever enters an `Event` before it is redacted.** Adapters never hold a
//! raw secret: every prompt, tool argument, and tool result is routed through a
//! [`HarnessContext`] that wraps a [`Redactor`](logbook_core::Redactor) plus the
//! [`CapturePolicy`](logbook_core::CapturePolicy). The context:
//! 1. consults [`CapturePolicy::should_redact`] for the class to decide whether
//!    the **general** redactor runs (so `--no-redact` disables only non-secret
//!    redaction), then
//! 2. **always** runs the mandatory secrets floor on top (so a cloud key / JWT /
//!    bearer token is scrubbed even under `--no-redact`), and
//! 3. caps the body to the class's `max_bytes` via [`CapturePolicy::cap_body`].
//!
//! The [`CapturePolicy::should_capture`] gate is also surfaced
//! ([`HarnessContext::captures`]) so a caller can drop a class entirely (e.g.
//! `prompts` off → metadata-only) — but redaction is unconditional for anything
//! that *is* emitted.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde_json::Value;

use logbook_core::{
    fnv1a_128, CapturePolicy, Event, EventId, Redactor, SensitivityClass, SpanId, TraceId,
};

mod context;

pub mod aider;
pub mod claude;
pub mod codex;
pub mod codex_json;
pub mod continue_;
pub mod cursor;
pub mod gemini;

pub use aider::AiderAdapter;
pub use claude::ClaudeCodeAdapter;
pub use codex::CodexAdapter;
pub use codex_json::{parse_codex_json_stream, CodexJsonAdapter};
pub use context::HarnessContext;
pub use continue_::ContinueAdapter;
pub use cursor::CursorAdapter;
pub use gemini::GeminiAdapter;

/// An adapter that normalizes one harness's native records into logbook
/// [`Event`]s.
///
/// Implementors own the (drift-prone) knowledge of a single harness's record
/// shapes — Claude Code hooks + session-log JSONL, Codex JSONL, Aider history —
/// and translate each into the unified event model. The contract is
/// deliberately tiny so new harnesses are cheap to add and easy to golden-test.
///
/// ## Contract
/// - **Total & infallible.** [`parse_record`](HarnessAdapter::parse_record)
///   never returns an error and never panics on malformed input: an
///   unrecognized or partial record yields an **empty** `Vec` (skip), so a
///   collector can stream a whole log and ignore noise.
/// - **Redaction before construction.** Every payload placed on a returned
///   `Event` (prompt, tool args/result, error text) must already be redacted via
///   the adapter's [`HarnessContext`]. A returned event is safe to persist.
/// - **One trace, turn-linked.** Events from records belonging to the same
///   logical session share the adapter's [`TraceId`]; tool/LLM events are
///   `parent_id`-linked to the turn span they belong to (the turn id is derived
///   deterministically from the session + turn index, so links survive even when
///   records arrive one at a time).
pub trait HarnessAdapter {
    /// The stable harness name (e.g. `claude-code`, `codex`, `aider`). Used in
    /// logs and as the default `agent` label.
    fn name(&self) -> &str;

    /// Normalize one raw harness record into zero or more [`Event`]s.
    ///
    /// Returns an empty `Vec` for records this adapter does not understand
    /// (tolerant skip). All emitted events are redacted and ready to persist.
    fn parse_record(&self, raw: &Value) -> Vec<Event>;
}

/// Derive the **deterministic** turn span id for `(trace, turn)`.
///
/// A harness streams records one at a time, so a tool/LLM event often arrives
/// without the user-prompt event that opened its turn in the same batch. Rather
/// than mint a random [`SpanId`] per call (which would not match across records),
/// every adapter derives the turn's span id from the trace bytes XOR the turn
/// index. This is stable, collision-resistant within a trace, and lets a
/// `Kind::Tool` event point its `parent_id` at the same turn span the
/// `Kind::Agent` prompt event uses as its own span — wiring the turn → tool
/// hierarchy without shared mutable state.
///
/// The mapping is intentionally simple and reproducible (golden fixtures assert
/// exact ids): take the low 8 bytes of the trace and XOR the big-endian turn
/// index into them.
#[must_use]
pub fn turn_span_id(trace: TraceId, turn: u64) -> SpanId {
    let tb = trace.as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&tb[..8]);
    let ti = turn.to_be_bytes();
    for (o, t) in out.iter_mut().zip(ti.iter()) {
        *o ^= *t;
    }
    // Guard the (invalid) all-zero span id: flip a bit deterministically.
    if out == [0u8; 8] {
        out[7] = 0x01;
    }
    SpanId::from_bytes(out)
}

/// Derive the **deterministic** [`EventId`] for an imported record on `trace`.
///
/// Live capture lets [`Event::new`] mint a random id, but the *import* path must
/// be reproducible: re-importing an unchanged source store has to reproduce
/// byte-identical event rows (id included), so an event's id is derived from its
/// content coordinates instead of OS entropy. [`EventId::generate`] is therefore
/// **banned** on this path.
///
/// The id is `hex(fnv1a_128(trace.as_bytes() ‖ coord ‖ 0x00 ‖ role))`:
/// - `trace` already folds in the source's `origin_fingerprint` (see the import
///   crate's `import_trace_id`), so event ids inherit cross-store namespacing
///   even when `coord` (e.g. an inline bubble index) repeats across stores;
/// - `coord` is the record's intrinsic stable key (a bubble id, message index,
///   …) — the thing that is stable across re-imports of the same store;
/// - `role` disambiguates the 1-record → N-events fan-out (e.g. a single
///   assistant turn that yields both an `Agent` message and an `Llm` step), and
///   a `0x00` separator keeps `(coord, role)` unambiguous so `("ab", "c")` and
///   `("a", "bc")` can never collide.
///
/// The 16-byte digest is rendered as 32 lowercase hex characters. The id is
/// **nonzero-guarded** (an all-zero digest has its last byte set to `1`) so it
/// can never be the empty/degenerate id; in practice FNV-1a never produces an
/// all-zero digest for these inputs, but the guard makes the invariant explicit.
#[must_use]
pub fn import_event_id(trace: TraceId, coord: &str, role: &str) -> EventId {
    let mut buf = Vec::with_capacity(TraceId::LEN + coord.len() + 1 + role.len());
    buf.extend_from_slice(trace.as_bytes());
    buf.extend_from_slice(coord.as_bytes());
    buf.push(0u8);
    buf.extend_from_slice(role.as_bytes());

    let mut digest = fnv1a_128(&buf);
    // Guard the degenerate all-zero id (parallels `turn_span_id`'s guard).
    if digest == [0u8; 16] {
        digest[15] = 0x01;
    }
    EventId::new(hex_lower(&digest))
}

/// Lowercase-hex encode a byte slice (small, allocation-light helper for the
/// deterministic id derivations). Mirrors the encoder in `logbook_core::ids`.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Shared constructor surface for the adapters: a [`Redactor`] plus the
/// [`CapturePolicy`] and the resolved global-redaction flag, packaged into a
/// [`HarnessContext`]. A thin alias for [`HarnessContext::new`] so callers can
/// build a context once and hand it to several adapters.
///
/// `redactor` is the **general** redactor (it may be [`Redactor::disabled`]
/// under `--no-redact`); the context layers the mandatory secrets floor on top
/// regardless, so a secret can never reach an `Event`.
#[must_use]
pub fn harness_context(
    redactor: Redactor,
    policy: CapturePolicy,
    global_redaction_enabled: bool,
) -> HarnessContext {
    HarnessContext::new(redactor, policy, global_redaction_enabled)
}

/// Byte cap for the short `ToolBlock.result_summary` digest, derived from the
/// (already redacted + class-capped) full result body via
/// [`truncate_with_ellipsis`](logbook_core::truncate_with_ellipsis). Keeps the
/// summary a small preview while the full body lives in `output`.
pub(crate) const RESULT_SUMMARY_MAX: usize = 256;

/// Byte cap for the attacker-controlled `harness_version` attribute. The value
/// is run through the secrets floor and capped to this length before being
/// stamped, so a hostile/over-long banner can neither exfiltrate a secret nor
/// bloat every event.
pub(crate) const HARNESS_VERSION_MAX: usize = 64;

/// The sensitivity class a given harness payload belongs to, for the redaction +
/// capacity decisions in [`HarnessContext`]. Re-exported convenience so adapter
/// code reads `class::PROMPTS` etc. without importing the core enum directly.
pub mod class {
    use super::SensitivityClass;
    /// Prompt text sent to a model.
    pub const PROMPTS: SensitivityClass = SensitivityClass::Prompts;
    /// Tool / function-call arguments.
    pub const TOOL_ARGS: SensitivityClass = SensitivityClass::ToolArgs;
    /// Tool / function-call results.
    pub const TOOL_RESULTS: SensitivityClass = SensitivityClass::ToolResults;
    /// Provider / model / token / cost metadata.
    pub const MODEL_METADATA: SensitivityClass = SensitivityClass::ModelMetadata;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_span_id_is_deterministic_and_nonzero() {
        let trace = TraceId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let a = turn_span_id(trace, 0);
        let b = turn_span_id(trace, 0);
        assert_eq!(a, b, "same (trace,turn) must yield the same span id");
        assert!(!a.is_zero());
        // Different turns differ.
        assert_ne!(turn_span_id(trace, 0), turn_span_id(trace, 1));
        // Turn 0 over this trace is just the low 8 bytes.
        assert_eq!(a.to_hex(), "0102030405060708");
    }

    #[test]
    fn turn_span_id_guards_all_zero() {
        // A trace whose low 8 bytes equal the turn index would XOR to zero;
        // the guard flips the last byte so the span id stays valid.
        let trace = TraceId::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 5, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        ]);
        let span = turn_span_id(trace, 5);
        assert!(!span.is_zero(), "guard must avoid the invalid all-zero span id");
        assert_eq!(span.to_hex(), "0000000000000001");
    }

    #[test]
    fn import_event_id_is_deterministic_and_32_hex() {
        let trace = TraceId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let a = import_event_id(trace, "bubble:7", "user");
        let b = import_event_id(trace, "bubble:7", "user");
        assert_eq!(a, b, "same (trace,coord,role) must yield the same event id");
        // 16 bytes → 32 lowercase hex chars.
        assert_eq!(a.as_str().len(), 32);
        assert!(
            a.as_str()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "event id hex must be lowercase: {}",
            a.as_str()
        );
    }

    #[test]
    fn import_event_id_varies_by_coord_and_role() {
        let trace = TraceId::from_bytes([0xab; 16]);
        let base = import_event_id(trace, "msg:1", "user");
        // Different coord differs.
        assert_ne!(base, import_event_id(trace, "msg:2", "user"));
        // Different role differs (the 1-record → N-events fan-out).
        assert_ne!(base, import_event_id(trace, "msg:1", "assistant"));
        // The 0x00 separator keeps (coord,role) unambiguous: ("ab","c") vs
        // ("a","bc") must not collide.
        assert_ne!(
            import_event_id(trace, "ab", "c"),
            import_event_id(trace, "a", "bc")
        );
        // Different trace differs even with identical (coord,role).
        let other = TraceId::from_bytes([0xcd; 16]);
        assert_ne!(base, import_event_id(other, "msg:1", "user"));
    }

    #[test]
    fn import_event_id_is_nonzero() {
        // No input should yield the degenerate all-zero (64-zero-char) id.
        let trace = TraceId::from_bytes([0x00; 16]);
        let id = import_event_id(trace, "", "");
        assert_ne!(id.as_str(), "0".repeat(32));
    }

    #[test]
    fn context_helper_builds_a_usable_context() {
        let ctx = harness_context(Redactor::new(), CapturePolicy::default(), true);
        // A prompt class captures + redacts by default.
        assert!(ctx.captures(class::PROMPTS));
        let (red, _trunc) = ctx.redact_text(class::PROMPTS, "key AKIAIOSFODNN7EXAMPLE");
        assert!(!red.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {red}");
    }
}
