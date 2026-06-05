//! `logbook guard -- <agent...> [--halt-on <severity>]` — run an agent under
//! capture (like `logbook agent`), then evaluate the Phase-3 risk rules over the
//! recorded session and **exit non-zero** if any finding is at or above
//! `--halt-on` (plan §Phase 3 "Orbit additions" → live guard / kill-switch),
//! wired to `logbook-inventory` (capture) + `logbook-detect` (rules) +
//! `logbook-store` (persistence).
//!
//! ## This is run-then-detect, not pre-execution blocking
//! Real-time blocking *before* a risky action executes is a follow-up (it needs
//! the streaming guard hook); `guard` today **records the whole session, then
//! detects, then fails the exit code**. The agent has already run by the time a
//! finding is raised — the value is a CI/wrapper gate that turns a risky session
//! into a non-zero exit (and persisted findings), not interdiction. The `--help`
//! text says so explicitly.
//!
//! ## Redaction-before-persistence is sacred (plan §9)
//! Capture goes through the same fail-closed [`CapturePolicy::resolve`] +
//! secrets-floor redactor as `logbook agent` (the secrets floor always runs;
//! `--no-redact` only drops the general layer and never exposes a secret), and
//! detection runs **after** redaction over the already-redacted stored events.
//! The findings persisted here are `Kind::Finding` events; no raw payload leaves.

use std::io::Write;
use std::path::PathBuf;

use clap::Args;

use logbook_core::{
    CapturePolicy, CliOverlay, Event, LogbookConfig, Redactor, SensitivityClass, Severity,
};
use logbook_detect::{builtin_rules, detect, DetectConfig};
use logbook_inventory::config::InventoryConfig;
use logbook_inventory::endpoint::local_endpoint;
use logbook_inventory::model::SessionTranscriptRecord;
use logbook_inventory::store_ext;
use logbook_inventory::wrapper::{self, LogbookOptions};
use logbook_store::Store;
#[cfg(test)]
use logbook_store::Query;

/// `logbook guard [opts] -- <agent...>`.
#[derive(Debug, Args)]
pub struct GuardArgs {
    /// Out-dir holding the logbook store + transcript files.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Severity at or above which a finding fails the guard (the exit becomes
    /// non-zero). One of `info`, `low`, `medium`, `high`, `critical`. Default:
    /// `high`.
    #[arg(long, default_value_t = Severity::High)]
    pub halt_on: Severity,

    /// Disable the **general** (non-secret) redactor for this session. The
    /// secrets floor (cloud keys, JWT, bearer, PEM, …) is **never** disabled —
    /// `--no-redact` only drops the general / `deny`-pattern layer; the
    /// `file_diffs` class is force-redacted regardless.
    #[arg(long)]
    pub no_redact: bool,

    /// The agent command line to run (e.g. `claude --resume`). Everything after
    /// the flags — or after a literal `--` — is the wrapped agent command.
    #[arg(trailing_var_arg = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// The exit code returned when a finding at or above `--halt-on` was raised. A
/// dedicated code (distinct from `1`, a hard `Err`) lets CI tell "the guard
/// tripped on a risky session" apart from a wrapper failure, mirroring
/// `commands/security.rs`'s `SCAN_INCOMPLETE_EXIT`.
const GUARD_TRIPPED_EXIT: i32 = 3;

/// Dispatch a `guard` invocation: capture the session, detect, then map the
/// worst finding to an exit code.
///
/// # Errors
/// Returns an error if the agent cannot be launched, capture fails, or the
/// session/findings cannot be persisted. A tripped guard is **not** an error —
/// it returns `Ok(GUARD_TRIPPED_EXIT)` so the message + persisted findings still
/// surface cleanly.
pub fn run(args: GuardArgs) -> anyhow::Result<i32> {
    if args.command.is_empty() {
        anyhow::bail!("no agent command given (expected `guard -- <agent> [args...]`)");
    }
    let project = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut err = std::io::stderr();
    run_in(args, project, &mut err)
}

/// Like [`run`] but with an explicit project/cwd root and status sink (the seam
/// tests use). The agent runs and is diffed in `project`, which is also the root
/// the capture policy + `[redaction]` config load from.
fn run_in(args: GuardArgs, project: PathBuf, status: &mut impl Write) -> anyhow::Result<i32> {
    // 1) Capture the session exactly like `logbook agent` (fail-closed policy +
    //    secrets-floor redactor), capturing the LogbookOutcome so we have the
    //    session_id to detect over — no racy "latest session" lookup.
    let outcome = capture_session(&args, &project, status)?;
    let session_id = outcome.session.session_id.clone();
    let exit_code = outcome.session.exit_code;

    // 2) Detect over the recorded session's (already-redacted) events. Route
    //    through the SAME gather as `logbook detect` so the session's
    //    `agent_actions` diffs are folded in as synthetic diff events — otherwise
    //    `secret_in_diff` never fires on a guarded session's file diffs (they
    //    live in `agent_actions`, not the `events` table).
    let store = Store::open_in_dir(&args.out_dir)?;
    let events = super::detect::gather_session_events(&store, &session_id)?;
    let cfg = detect_config(&project);
    let rules = builtin_rules(&cfg);
    let findings = detect(&events, &rules);

    // 3) Persist the findings (Kind::Finding events on the same session).
    if !findings.is_empty() {
        store.insert_batch(findings.clone())?;
    }

    // 4) Report + decide the exit code: trip iff any finding >= --halt-on.
    let worst = worst_severity(&findings);
    report(status, &session_id, &findings, worst, args.halt_on);

    let tripped = worst.is_some_and(|s| s >= args.halt_on);
    if tripped {
        return Ok(GUARD_TRIPPED_EXIT);
    }
    // Clean guard: propagate the agent's own exit code (a failing agent still
    // fails the guard), defaulting to 0 when unknown.
    Ok(exit_code.unwrap_or(0))
}

/// Run the agent under capture, mirroring `logbook agent`'s wiring: resolve the
/// capture policy fail-closed, build the secrets-floor (or general) redactor,
/// drive [`wrapper::run_agent`] on a current-thread runtime, then persist the
/// session, actions, and transcript pointer via the public `store_ext` helpers.
/// Returns the [`wrapper::LogbookOutcome`] so the caller has the session id.
fn capture_session(
    args: &GuardArgs,
    project: &std::path::Path,
    status: &mut impl Write,
) -> anyhow::Result<wrapper::LogbookOutcome> {
    let inv_cfg = InventoryConfig::load_from_dir(project);
    let general_redaction_enabled = inv_cfg.redaction.enabled && !args.no_redact;

    // Same shared, fail-closed resolution as the agent wrapper (defaults →
    // strict logbook.toml → <out_dir>/capture-state.json narrow-only → CLI). The
    // only CLI knob guard carries is --no-redact; diff capture stays at the
    // policy default (recorder-on), which is what `logbook agent` does too.
    let overlay = CliOverlay {
        no_redact: args.no_redact,
        ..Default::default()
    };
    let policy = CapturePolicy::resolve(project, &args.out_dir, overlay);

    let redactor = if general_redaction_enabled {
        logbook_core::redact::from_config(true, &inv_cfg.redaction.deny, &inv_cfg.redaction.allow)
            .unwrap_or_else(|_| {
                tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
                Redactor::new().with_process_env()
            })
    } else {
        Redactor::secrets_floor_with_process_env()
    };
    if args.no_redact {
        let _ = writeln!(
            status,
            "logbook: WARNING --no-redact is set; the secrets floor still applies, but \
             non-secret content in diffs/transcript may be persisted to {}.",
            args.out_dir.display()
        );
    }

    let endpoint = local_endpoint();
    let opts = LogbookOptions {
        cwd: project.to_path_buf(),
        out_dir: args.out_dir.clone(),
        endpoint_id: Some(endpoint.id.clone()),
        spawn: true,
        policy,
        redaction_enabled: general_redaction_enabled,
        reversible: false,
    };

    let store = Store::open_in_dir(&args.out_dir)?;
    store_ext::upsert_endpoint(&store, &endpoint)?;

    // Current-thread runtime (like `commands/run.rs` / the agent wrapper); the
    // PTY forwards interactive stdin.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let outcome = rt.block_on(wrapper::run_agent(&args.command, &opts, &redactor))?;

    // Persist the session + actions + transcript pointer (same as
    // `run_agent_wrapper_in`).
    store_ext::insert_agent_session(&store, &outcome.session)?;
    store_ext::insert_agent_actions(&store, &outcome.session.session_id, &outcome.actions)?;
    if let Some(t) = &outcome.transcript {
        if t.terminal_log_path.is_some() || t.text_path.is_some() {
            let rec = SessionTranscriptRecord {
                session_id: outcome.session.session_id.clone(),
                trace_id: outcome.session.trace_id.clone(),
                terminal_log_path: t.terminal_log_path.as_ref().map(|p| p.display().to_string()),
                text_path: t.text_path.as_ref().map(|p| p.display().to_string()),
                line_count: Some(t.line_count as i64),
                byte_size: Some(t.byte_size as i64),
                max_sensitivity: SensitivityClass::Transcript.as_str().to_string(),
            };
            store_ext::insert_session_transcript(&store, &rec)?;
        }
    }

    Ok(outcome)
}

/// Build the [`DetectConfig`] for the guard pass (egress allowlist from
/// `logbook.toml`, default thresholds otherwise) — identical to `logbook
/// detect`'s config.
fn detect_config(root: &std::path::Path) -> DetectConfig {
    let allowed_domains = LogbookConfig::load_from_root(root)
        .map(|c| c.permissions.allowed_domains)
        .unwrap_or_default();
    DetectConfig {
        allowed_domains,
        ..DetectConfig::default()
    }
}

/// The maximum severity across a set of findings, or `None` when there are none.
fn worst_severity(findings: &[Event]) -> Option<Severity> {
    findings
        .iter()
        .filter_map(|f| f.blocks.finding.as_ref().and_then(|b| b.severity))
        .max()
}

/// Print the guard outcome to the status sink: each finding, then the verdict.
fn report(
    status: &mut impl Write,
    session_id: &str,
    findings: &[Event],
    worst: Option<Severity>,
    halt_on: Severity,
) {
    for f in findings {
        let block = f.blocks.finding.as_ref();
        let rule = block.and_then(|b| b.rule_id.as_deref()).unwrap_or(&f.operation);
        let sev = block.and_then(|b| b.severity).map(|s| s.as_str()).unwrap_or("?");
        let msg = block.and_then(|b| b.message.as_deref()).unwrap_or(&f.name);
        let _ = writeln!(status, "  guard finding [{sev}] {rule}: {msg}");
    }

    let tripped = worst.is_some_and(|s| s >= halt_on);
    if tripped {
        let _ = writeln!(
            status,
            "guard TRIPPED on session {session_id}: a finding at or above `{}` was raised \
             ({} finding(s) total). Exiting non-zero.",
            halt_on.as_str(),
            findings.len()
        );
    } else {
        let _ = writeln!(
            status,
            "guard clean on session {session_id}: {} finding(s), none at or above `{}`.",
            findings.len(),
            halt_on.as_str()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use logbook_core::{Category, FindingBlock, Kind, TraceId};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Guard(GuardArgs),
    }

    fn parse(argv: &[&str]) -> GuardArgs {
        match TestCli::try_parse_from(argv).expect("parse").cmd {
            TestCmd::Guard(a) => a,
        }
    }

    #[test]
    fn parses_command_after_double_dash_with_default_halt_on() {
        let a = parse(&["x", "guard", "--", "claude", "--resume"]);
        assert_eq!(a.command, vec!["claude", "--resume"]);
        assert_eq!(a.halt_on, Severity::High);
        assert_eq!(a.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert!(!a.no_redact);
    }

    #[test]
    fn parses_halt_on_and_out_dir() {
        let a = parse(&[
            "x", "guard", "--halt-on", "medium", "--out-dir", "/tmp/o", "--no-redact", "--", "sh",
            "-c", "true",
        ]);
        assert_eq!(a.halt_on, Severity::Medium);
        assert_eq!(a.out_dir, PathBuf::from("/tmp/o"));
        assert!(a.no_redact);
        assert_eq!(a.command, vec!["sh", "-c", "true"]);
    }

    #[test]
    fn command_can_lead_with_hyphen_flag() {
        // allow_hyphen_values lets the agent carry its own flags without a second --.
        let a = parse(&["x", "guard", "--", "ls", "-la"]);
        assert_eq!(a.command, vec!["ls", "-la"]);
    }

    #[test]
    fn command_is_required() {
        assert!(TestCli::try_parse_from(["x", "guard"]).is_err());
    }

    #[test]
    fn halt_on_value_is_validated() {
        assert!(TestCli::try_parse_from(["x", "guard", "--halt-on", "bogus", "--", "ls"]).is_err());
    }

    // --- exit-code mapping (the core guard contract) ---

    fn finding(severity: Severity) -> Event {
        Event::new(TraceId::new(), Kind::Finding, Category::Security, "dangerous_shell")
            .with_finding(FindingBlock {
                severity: Some(severity),
                rule_id: Some("dangerous_shell".into()),
                message: Some("rm -rf /".into()),
                ..Default::default()
            })
    }

    #[test]
    fn worst_severity_picks_the_max() {
        let findings = vec![finding(Severity::Low), finding(Severity::High), finding(Severity::Medium)];
        assert_eq!(worst_severity(&findings), Some(Severity::High));
        assert_eq!(worst_severity(&[]), None);
    }

    #[test]
    fn a_finding_at_or_above_halt_on_trips() {
        // High finding with --halt-on high => tripped.
        let worst = worst_severity(&[finding(Severity::High)]);
        assert!(worst.is_some_and(|s| s >= Severity::High));
        // Critical also trips a high gate.
        let worst = worst_severity(&[finding(Severity::Critical)]);
        assert!(worst.is_some_and(|s| s >= Severity::High));
    }

    #[test]
    fn a_finding_below_halt_on_does_not_trip() {
        // Medium finding with --halt-on high => clean.
        let worst = worst_severity(&[finding(Severity::Medium)]);
        assert!(!worst.is_some_and(|s| s >= Severity::High));
    }

    #[test]
    fn guard_tripped_exit_is_distinct_from_failure() {
        // Document the contract: the tripped code is not 0 and not the generic 1.
        assert_ne!(GUARD_TRIPPED_EXIT, 0);
        assert_ne!(GUARD_TRIPPED_EXIT, 1);
    }

    /// End-to-end seam: run a real `/bin/sh` agent whose command line itself is a
    /// dangerous shell (`rm -rf /`), then assert the guard trips with the
    /// dedicated exit code and persisted the finding. Uses `run_in` so it diffs
    /// in a temp dir without touching process cwd. POSIX-only (the binary is
    /// POSIX-only anyway).
    #[test]
    fn guard_run_trips_on_dangerous_session_and_persists_finding() {
        let out = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();

        // The agent argv contains the dangerous string, so the redacted command
        // line / transcript carries it and `dangerous_shell` (High) fires. We use
        // `echo` so nothing destructive actually runs.
        let args = GuardArgs {
            out_dir: out.path().to_path_buf(),
            halt_on: Severity::High,
            no_redact: false,
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo rm -rf /".into(),
            ],
        };

        let mut status = Vec::new();
        let code = run_in(args, project.path().to_path_buf(), &mut status).unwrap();
        assert_eq!(
            code,
            GUARD_TRIPPED_EXIT,
            "guard should trip on a High finding; status:\n{}",
            String::from_utf8_lossy(&status)
        );

        // A finding was persisted as a Kind::Finding / Security event.
        let store = Store::open_in_dir(out.path()).unwrap();
        let findings = store.query(&Query::new()).unwrap();
        assert!(
            findings
                .iter()
                .any(|e| e.kind == Kind::Finding && e.category == Category::Security),
            "expected a persisted Finding event"
        );
    }

    /// A benign session raises no halt-level finding, so the guard returns the
    /// agent's own (zero) exit code.
    #[test]
    fn guard_run_clean_on_benign_session() {
        let out = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let args = GuardArgs {
            out_dir: out.path().to_path_buf(),
            halt_on: Severity::High,
            no_redact: false,
            command: vec!["/bin/sh".into(), "-c".into(), "echo hello".into()],
        };
        let mut status = Vec::new();
        let code = run_in(args, project.path().to_path_buf(), &mut status).unwrap();
        assert_eq!(
            code,
            0,
            "benign session should not trip; status:\n{}",
            String::from_utf8_lossy(&status)
        );
    }
}
