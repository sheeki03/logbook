//! `logbook forget <session-id | --before <duration>>` — delete a recorded
//! session (or everything older than a cut-off) from the store **and** its
//! on-disk artifacts (plan §Phase 3 "Orbit additions" → `logbook forget`),
//! wired to `logbook-inventory`'s `governance::forget`.
//!
//! This is the privacy panic-purge surface, so it is **confirm-gated**: because
//! it irreversibly deletes data it requires an explicit `--yes` flag (there is no
//! interactive prompt — the CLI is used non-interactively under agents/CI, so the
//! gate is a flag, matching the security-scan write gate's "explicit opt-in"
//! posture). `governance::forget` removes the store rows (events + the
//! `agent_sessions` row, whose actions/transcripts cascade) and, for the by-id
//! case, the session's redacted transcript files and any
//! `<out_dir>/sessions/<id>/` directory (the `--reversible` encrypted-preimage
//! location).

use std::path::PathBuf;

use clap::Args;

use logbook_core::MicrosTimestamp;
use logbook_inventory::governance::{self, ForgetTarget};
use logbook_store::Store;

/// `logbook forget <session-id | --before <duration>> --yes [opts]`.
#[derive(Debug, Args)]
pub struct ForgetArgs {
    /// The recorded session id to forget. Mutually exclusive with `--before`;
    /// exactly one target must be given.
    #[arg(conflicts_with = "before")]
    pub session_id: Option<String>,

    /// Forget everything older than this duration ago (e.g. `7d`, `24h`, `30m`,
    /// `90s`, or a bare integer = seconds). Mutually exclusive with a session id.
    #[arg(long)]
    pub before: Option<String>,

    /// Out-dir holding the logbook store + on-disk transcripts/preimages.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Required confirmation. `forget` irreversibly deletes data, so it refuses
    /// to run without this flag (no interactive prompt — the gate is explicit).
    #[arg(long)]
    pub yes: bool,
}

/// Dispatch a `forget` invocation.
///
/// # Errors
/// Returns an error if neither/both targets were given, `--yes` is absent, a
/// `--before` duration cannot be parsed, the store cannot be opened, or a delete
/// fails.
pub fn run(args: ForgetArgs) -> anyhow::Result<i32> {
    let target = resolve_target(&args)?;

    if !args.yes {
        anyhow::bail!(
            "forget irreversibly deletes recorded data; re-run with --yes to confirm \
             (e.g. `logbook forget {} --yes`).",
            describe_target(&target)
        );
    }

    let store = Store::open_in_dir(&args.out_dir)?;
    let report = governance::forget(&store, target, &args.out_dir)?;
    println!(
        "forget complete: {} event(s), {} session(s), {} file(s), {} dir(s) removed.",
        report.events, report.agent_sessions, report.files_removed, report.dirs_removed
    );
    Ok(0)
}

/// Resolve the parsed args into exactly one [`ForgetTarget`], rejecting the
/// neither / both cases (clap's `conflicts_with` covers "both", but a missing
/// target still needs a clear error).
fn resolve_target(args: &ForgetArgs) -> anyhow::Result<ForgetTarget> {
    match (&args.session_id, &args.before) {
        (Some(_), Some(_)) => {
            anyhow::bail!("give either a <session-id> or --before <duration>, not both")
        }
        (None, None) => {
            anyhow::bail!("nothing to forget: pass a <session-id> or --before <duration>")
        }
        (Some(id), None) => Ok(ForgetTarget::Session(id.clone())),
        (None, Some(dur)) => {
            let cutoff = cutoff_micros_from_duration(dur, MicrosTimestamp::now().as_micros())?;
            Ok(ForgetTarget::Before(cutoff))
        }
    }
}

/// A short human label for a target, used in the `--yes` confirmation hint.
fn describe_target(target: &ForgetTarget) -> String {
    match target {
        ForgetTarget::Session(id) => id.clone(),
        ForgetTarget::Before(_) => "--before <duration>".to_string(),
    }
}

/// Compute the absolute microsecond cut-off for `--before <duration>`: events
/// older than `now - duration` are forgotten. Returns the resulting timestamp,
/// clamped at `0` so a duration longer than the current clock never underflows.
///
/// Accepts a single `<int><unit>` token (`d`/`h`/`m`/`s`) or a bare integer
/// (seconds). Whitespace around the token is tolerated.
///
/// # Errors
/// Returns an error if the duration is empty, not a positive integer + optional
/// unit, or uses an unknown unit.
fn cutoff_micros_from_duration(spec: &str, now_micros: i64) -> anyhow::Result<i64> {
    let secs = duration_to_secs(spec)?;
    let span_micros = secs.saturating_mul(1_000_000);
    Ok(now_micros.saturating_sub(span_micros).max(0))
}

/// Parse a `<int><unit>` duration into whole seconds. `d`=days, `h`=hours,
/// `m`=minutes, `s`=seconds; a bare integer is seconds.
fn duration_to_secs(spec: &str) -> anyhow::Result<i64> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("--before requires a duration (e.g. 7d, 24h, 30m, 90s)");
    }
    let (digits, unit) = match spec.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((idx, _)) => (&spec[..idx], &spec[idx..]),
        None => (spec, ""),
    };
    if digits.is_empty() {
        anyhow::bail!("invalid --before duration {spec:?}: expected a leading integer (e.g. 7d)");
    }
    let n: i64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --before duration {spec:?}: {digits:?} is not an integer"))?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        other => anyhow::bail!(
            "invalid --before duration unit {other:?}: use d (days), h (hours), m (minutes), or s (seconds)"
        ),
    };
    Ok(n.saturating_mul(mult))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Forget(ForgetArgs),
    }

    fn parse(argv: &[&str]) -> Result<ForgetArgs, clap::Error> {
        TestCli::try_parse_from(argv).map(|c| match c.cmd {
            TestCmd::Forget(a) => a,
        })
    }

    #[test]
    fn parses_session_id_with_yes() {
        let a = parse(&["x", "forget", "sess-1", "--yes"]).unwrap();
        assert_eq!(a.session_id.as_deref(), Some("sess-1"));
        assert!(a.yes);
        assert!(a.before.is_none());
        assert_eq!(a.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
    }

    #[test]
    fn parses_before_duration() {
        let a = parse(&["x", "forget", "--before", "7d", "--yes"]).unwrap();
        assert_eq!(a.before.as_deref(), Some("7d"));
        assert!(a.session_id.is_none());
    }

    #[test]
    fn session_id_and_before_conflict() {
        // clap's conflicts_with rejects passing both at parse time.
        assert!(parse(&["x", "forget", "sess-1", "--before", "7d", "--yes"]).is_err());
    }

    #[test]
    fn forget_requires_yes() {
        // Parses fine without --yes, but the dispatcher refuses to act.
        let a = parse(&["x", "forget", "sess-1"]).unwrap();
        assert!(!a.yes);
        let err = run(a).unwrap_err();
        assert!(
            err.to_string().contains("--yes"),
            "expected a --yes confirmation error, got: {err}"
        );
    }

    #[test]
    fn missing_target_is_an_error() {
        let a = parse(&["x", "forget", "--yes"]).unwrap();
        let err = run(a).unwrap_err();
        assert!(err.to_string().contains("session-id") || err.to_string().contains("--before"));
    }

    #[test]
    fn resolve_target_session_and_before() {
        let s = resolve_target(&ForgetArgs {
            session_id: Some("s".into()),
            before: None,
            out_dir: PathBuf::from("."),
            yes: true,
        })
        .unwrap();
        assert_eq!(s, ForgetTarget::Session("s".into()));

        let b = resolve_target(&ForgetArgs {
            session_id: None,
            before: Some("1s".into()),
            out_dir: PathBuf::from("."),
            yes: true,
        })
        .unwrap();
        assert!(matches!(b, ForgetTarget::Before(_)));
    }

    #[test]
    fn duration_units_parse() {
        assert_eq!(duration_to_secs("90").unwrap(), 90);
        assert_eq!(duration_to_secs("90s").unwrap(), 90);
        assert_eq!(duration_to_secs("30m").unwrap(), 1_800);
        assert_eq!(duration_to_secs("24h").unwrap(), 86_400);
        assert_eq!(duration_to_secs("7d").unwrap(), 604_800);
    }

    #[test]
    fn duration_rejects_garbage() {
        assert!(duration_to_secs("").is_err());
        assert!(duration_to_secs("abc").is_err());
        assert!(duration_to_secs("7y").is_err());
        assert!(duration_to_secs("d").is_err());
    }

    #[test]
    fn cutoff_subtracts_from_now_and_clamps() {
        // 1 day before a fixed "now".
        let now = 10 * 24 * 60 * 60 * 1_000_000i64; // day 10, in micros
        let cutoff = cutoff_micros_from_duration("1d", now).unwrap();
        assert_eq!(cutoff, 9 * 24 * 60 * 60 * 1_000_000);
        // A span longer than the clock clamps at 0, never underflows.
        assert_eq!(cutoff_micros_from_duration("365d", 1_000).unwrap(), 0);
    }
}
