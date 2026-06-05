//! The cross-tier **trace correlation** contract.
//!
//! A single `logbook agent -- <agent>` session can be observed by three
//! independent producers that each mint events on their own lane:
//! - the **agent wrapper** (transcript + session-accurate file diffs),
//! - the **LLM proxy** (`logbook proxy llm`, one event per upstream call), and
//! - the **harness hook receiver** (`logbook hooks`, tool/prompt events).
//!
//! Left alone, each lane mints its **own** [`TraceId`], so the same session is
//! scattered across several unrelated traces. To stitch them into **one**
//! correlated trace we use standard trace propagation: the wrapper mints the
//! identity and exports it into the wrapped child's environment ([`TRACE_ENV`] /
//! [`SESSION_ENV`]); the receivers (proxy, hooks) honour an incoming
//! [`TRACE_HEADER`] request header and record under that trace instead of a
//! freshly minted one.
//!
//! The header name is fixed by the proxy's existing reader
//! (`logbook-llmproxy`), so all three lanes agree on the literal
//! `x-logbook-trace`. The env-var names are the wrapper→child half of the same
//! contract.
//!
//! ```
//! use logbook_core::correlation::{TRACE_ENV, TRACE_HEADER, trace_from_env};
//!
//! // The wrapper sets `LOGBOOK_TRACE=<hex>`; a child (or its hooks) can read it
//! // back and forward it as the `x-logbook-trace` header.
//! std::env::set_var(TRACE_ENV, "00112233445566778899aabbccddeeff");
//! let trace = trace_from_env().expect("valid 32-hex trace in LOGBOOK_TRACE");
//! assert_eq!(trace.to_hex(), "00112233445566778899aabbccddeeff");
//! assert_eq!(TRACE_HEADER, "x-logbook-trace");
//! # std::env::remove_var(TRACE_ENV);
//! ```

use std::str::FromStr;

use crate::ids::TraceId;

/// The HTTP request header carrying the correlation [`TraceId`] (32 lowercase
/// hex chars) from a producer to a receiver.
///
/// This MUST match the literal the LLM proxy already reads
/// (`logbook-llmproxy/src/record.rs`), so the proxy, the hook receiver, and any
/// other receiver all correlate on the **same** header. Do not rename without
/// updating every reader.
pub const TRACE_HEADER: &str = "x-logbook-trace";

/// The environment variable the agent wrapper exports into the wrapped child so
/// the child (and any process it spawns, e.g. a harness firing hooks) can read
/// the session's [`TraceId`] back and forward it as [`TRACE_HEADER`].
///
/// Value: the trace rendered as 32 lowercase hex chars (`TraceId::to_hex`).
pub const TRACE_ENV: &str = "LOGBOOK_TRACE";

/// The environment variable the agent wrapper exports into the wrapped child
/// carrying the session id (`SessionId`), so a child can correlate by session in
/// addition to trace.
///
/// Value: the opaque session-id string (`SessionId::into_inner`).
pub const SESSION_ENV: &str = "LOGBOOK_SESSION";

/// Read a correlation [`TraceId`] from the [`TRACE_ENV`] environment variable.
///
/// Returns `Some` only when the variable is present **and** holds a well-formed
/// 32-hex W3C trace id that is not the (invalid) all-zero value. A missing,
/// empty, wrong-width, non-hex, or all-zero value yields `None` — the caller
/// then mints its own fresh trace, exactly as if no correlation were in effect.
/// This is the env-var analogue of the proxy's header parser, so a malformed
/// hand-off never produces a bogus (e.g. zero) trace.
#[must_use]
pub fn trace_from_env() -> Option<TraceId> {
    parse_trace(std::env::var(TRACE_ENV).ok()?.as_str())
}

/// Parse a 32-hex-char W3C trace id, rejecting a wrong width, non-hex input, or
/// the all-zero id. Factored out of [`trace_from_env`] so the validation is
/// testable without mutating the process environment, and so receivers can reuse
/// the exact same acceptance rule on a header value.
#[must_use]
pub fn parse_trace(s: &str) -> Option<TraceId> {
    let trace = TraceId::from_str(s.trim()).ok()?;
    if trace.is_zero() {
        return None;
    }
    Some(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_proxy_literal() {
        // The proxy reads this exact literal; keep them in lockstep.
        assert_eq!(TRACE_HEADER, "x-logbook-trace");
    }

    #[test]
    fn env_names_are_the_contract() {
        assert_eq!(TRACE_ENV, "LOGBOOK_TRACE");
        assert_eq!(SESSION_ENV, "LOGBOOK_SESSION");
    }

    #[test]
    fn parse_trace_accepts_valid_32_hex() {
        let hex = "00112233445566778899aabbccddeeff";
        let t = parse_trace(hex).expect("valid trace");
        assert_eq!(t.to_hex(), hex);
        // Surrounding whitespace is tolerated (header/env values may be padded).
        assert_eq!(parse_trace("  00112233445566778899aabbccddeeff  ").unwrap(), t);
        // Uppercase parses but renders lowercase (matches `TraceId::from_str`).
        assert_eq!(
            parse_trace("00112233445566778899AABBCCDDEEFF").unwrap().to_hex(),
            hex
        );
    }

    #[test]
    fn parse_trace_rejects_malformed() {
        assert!(parse_trace("").is_none(), "empty");
        assert!(parse_trace("abc").is_none(), "too short");
        assert!(
            parse_trace("0123456789abcdef").is_none(),
            "16 hex is a span width, not a trace width"
        );
        assert!(
            parse_trace("zz112233445566778899aabbccddeeff").is_none(),
            "non-hex"
        );
        assert!(
            parse_trace("00112233445566778899aabbccddeeff00").is_none(),
            "too long"
        );
    }

    #[test]
    fn parse_trace_rejects_all_zero() {
        // The all-zero trace is invalid per W3C trace-context; a malformed
        // hand-off must not yield it.
        assert!(parse_trace(&"0".repeat(32)).is_none());
    }

    /// `trace_from_env` reads [`TRACE_ENV`] and applies the same acceptance rule.
    /// Env mutation is process-global, so this single test exercises the
    /// present-valid, present-malformed, and absent cases in sequence (under one
    /// test fn so they cannot interleave with a sibling test's env writes).
    #[test]
    fn trace_from_env_round_trips_and_rejects() {
        let hex = "0123456789abcdef0123456789abcdef";
        std::env::set_var(TRACE_ENV, hex);
        assert_eq!(trace_from_env().expect("valid env trace").to_hex(), hex);

        std::env::set_var(TRACE_ENV, "not-a-trace");
        assert!(trace_from_env().is_none(), "malformed env value ⇒ None");

        std::env::set_var(TRACE_ENV, "0".repeat(32));
        assert!(trace_from_env().is_none(), "all-zero env value ⇒ None");

        std::env::remove_var(TRACE_ENV);
        assert!(trace_from_env().is_none(), "absent env var ⇒ None");
    }
}
