//! `logbook revert <session-id> [--out-dir]` — reverse a recorded session's
//! file changes (plan §Phase 3 "Orbit additions" → `logbook revert <session>`),
//! wired to `logbook-inventory`'s `governance::revert`.
//!
//! Revert restores from the user's **own git HEAD**, not from any logbook-stored
//! diff body: only actions the wrapper marked `revert_safe = true` (clean tree at
//! session start, so HEAD *is* the preimage) are touched, and each is applied
//! only if the file still matches the recorded `post_hash`. Dirty-tree
//! (`revert_safe = false`) actions are **skipped** with a clear message — there is
//! no exact preimage to restore from, and a redacted diff cannot reconstruct
//! bytes. Files that diverged since the session, or that git could not restore,
//! are **refused**. The heavy lifting lives in `governance::revert`; this module
//! is the thin CLI adapter that prints the per-disposition tally.
//!
//! This is a **write** command (it mutates the working tree via git), but it only
//! ever restores from the user's own committed state — it persists nothing and
//! widens no capture — so, like `agent`/`inventory scan`, it is not behind a
//! `[permissions]` write gate.

use std::path::PathBuf;

use clap::Args;

use logbook_core::Redactor;
use logbook_inventory::config::InventoryConfig;
use logbook_inventory::governance::{self, RevertDisposition, RevertReport};
use logbook_store::Store;

/// `logbook revert <session-id> [opts]`.
#[derive(Debug, Args)]
pub struct RevertArgs {
    /// The recorded session id to reverse.
    pub session_id: String,

    /// Out-dir holding the logbook store the session was recorded in.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Repo root the session ran in — git's working directory for the restore
    /// and the dir post-state hashes are recomputed against. Defaults to the
    /// current directory (where `logbook agent` is typically launched). The
    /// session's `[redaction]` config (`logbook.toml`) is also loaded from here
    /// so revert recomputes the post-state hash with the **same** redactor the
    /// capture path used (see [`run`]).
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Set this when the session was captured under `logbook agent --no-redact`.
    /// Such a session recorded a **floor-only** post-state hash (general redactor
    /// disabled, secrets floor still applied), so revert must recompute with the
    /// secrets-floor redactor to match — otherwise every file is refused on a
    /// spurious hash mismatch. Has no effect on a normally-captured session.
    #[arg(long)]
    pub no_redact: bool,
}

/// Dispatch a `revert` invocation.
///
/// Returns `0` when every action was applied or cleanly skipped (not-safe), and
/// `1` when one or more actions were **refused** (hash mismatch / missing
/// post-hash / git error) — a refusal means the tree was left in a state the
/// caller asked to change but logbook would not touch, which CI/scripts should
/// be able to detect.
///
/// # Errors
/// Returns an error if the store cannot be opened or the session does not exist
/// (`governance::revert_with_redactor` returns `InventoryError::SessionNotFound`).
/// Per-file git failures are **not** errors — they surface as `refused` in the
/// report.
pub fn run(args: RevertArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;
    // Recompute the post-state hash with the **same** redactor the capture path
    // used (`cli.rs::run_agent_wrapper_in`): the general redactor seeded with the
    // user's `[redaction] deny`/`allow` when redaction was on, else the secrets
    // floor for a `--no-redact` session. The default `governance::revert` only
    // uses an empty `Redactor::new().with_process_env()`, so a session captured
    // with custom deny/allow patterns (or `--no-redact`) would recompute a
    // *different* hash and refuse every otherwise-valid file.
    let redactor = build_revert_redactor(&args.cwd, args.no_redact);
    let report =
        governance::revert_with_redactor(&store, &args.session_id, &args.cwd, &redactor)?;
    print_report(&report);
    Ok(exit_code(&report))
}

/// Build the redactor `revert` uses to recompute each action's post-state hash,
/// matching the one the capture path built for this session.
///
/// Mirrors `cli.rs::run_agent_wrapper_in` (and `commands/guard.rs`) exactly:
/// `general_redaction_enabled = [redaction].enabled && !--no-redact`. When the
/// general layer is on, the redactor honours the user's `[redaction] deny`/`allow`
/// patterns via [`logbook_core::redact::from_config`]; otherwise (config-off **or**
/// `--no-redact`) it is the secrets-floor redactor — the floor that still ran at
/// capture, so the recorded hash is reproduced. A bad deny pattern falls back to
/// the built-in general rules, identical to the capture path's fallback.
fn build_revert_redactor(cwd: &std::path::Path, no_redact: bool) -> Redactor {
    let inv_cfg = InventoryConfig::load_from_dir(cwd);
    let general_redaction_enabled = inv_cfg.redaction.enabled && !no_redact;
    if general_redaction_enabled {
        logbook_core::redact::from_config(true, &inv_cfg.redaction.deny, &inv_cfg.redaction.allow)
            .unwrap_or_else(|_| {
                tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
                Redactor::new().with_process_env()
            })
    } else {
        Redactor::secrets_floor_with_process_env()
    }
}

/// Map a revert report to a process exit code: non-zero iff anything was refused.
fn exit_code(report: &RevertReport) -> i32 {
    if report.refused() > 0 {
        1
    } else {
        0
    }
}

/// Print the per-file outcomes followed by the applied/skipped/refused tally.
fn print_report(report: &RevertReport) {
    for file in &report.files {
        let verb = match file.disposition {
            RevertDisposition::Applied => "reverted",
            RevertDisposition::SkippedNotSafe => "skipped (not revert-safe)",
            RevertDisposition::RefusedHashMismatch => "refused (file changed since the session)",
            RevertDisposition::RefusedNoPostHash => "refused (no recorded post-state hash)",
            RevertDisposition::RefusedGitError => "refused (git could not restore)",
        };
        match &file.detail {
            Some(detail) => println!("  {verb}: {} [{}] — {detail}", file.path, file.kind),
            None => println!("  {verb}: {} [{}]", file.path, file.kind),
        }
    }

    let (applied, skipped, refused) = (report.applied(), report.skipped(), report.refused());
    println!(
        "revert {}: {applied} applied, {skipped} skipped, {refused} refused.",
        report.session_id
    );
    if skipped > 0 {
        println!(
            "note: skipped actions were recorded on a dirty tree (not revert-safe); \
             logbook refuses to guess their pre-session content."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use logbook_inventory::governance::RevertOutcome;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCmd {
        Revert(RevertArgs),
    }

    fn parse(argv: &[&str]) -> RevertArgs {
        match TestCli::try_parse_from(argv).expect("parse").cmd {
            TestCmd::Revert(a) => a,
        }
    }

    #[test]
    fn parses_session_id_and_defaults() {
        let a = parse(&["x", "revert", "sess-1"]);
        assert_eq!(a.session_id, "sess-1");
        assert_eq!(a.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(a.cwd, PathBuf::from("."));
        assert!(!a.no_redact, "--no-redact defaults off");
    }

    #[test]
    fn parses_no_redact_flag() {
        let a = parse(&["x", "revert", "sess-1", "--no-redact"]);
        assert!(a.no_redact);
    }

    #[test]
    fn parses_explicit_out_dir_and_cwd() {
        let a = parse(&["x", "revert", "sess-9", "--out-dir", "/tmp/o", "--cwd", "/repo"]);
        assert_eq!(a.session_id, "sess-9");
        assert_eq!(a.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(a.cwd, PathBuf::from("/repo"));
    }

    #[test]
    fn session_id_is_required() {
        assert!(TestCli::try_parse_from(["x", "revert"]).is_err());
    }

    fn outcome(disposition: RevertDisposition) -> RevertOutcome {
        RevertOutcome {
            path: "f.txt".into(),
            kind: "file_modified".into(),
            disposition,
            detail: None,
        }
    }

    #[test]
    fn exit_code_zero_when_only_applied_or_skipped() {
        let report = RevertReport {
            session_id: "s".into(),
            files: vec![
                outcome(RevertDisposition::Applied),
                outcome(RevertDisposition::SkippedNotSafe),
            ],
        };
        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn exit_code_nonzero_when_any_refused() {
        let report = RevertReport {
            session_id: "s".into(),
            files: vec![
                outcome(RevertDisposition::Applied),
                outcome(RevertDisposition::RefusedHashMismatch),
            ],
        };
        assert_eq!(exit_code(&report), 1);
        assert_eq!(report.refused(), 1);
    }

    /// Regression for the redactor-parity defect: with a custom `[redaction] deny`
    /// pattern in `logbook.toml`, the revert redactor must be built **from that
    /// config** (so the post-state hash matches the one capture recorded), not the
    /// empty `Redactor::new().with_process_env()` the old default `revert` used.
    /// We prove it by checking the redactor actually applies the user's deny
    /// pattern — an empty redactor would leave the value untouched and thus
    /// recompute a different hash, refusing every otherwise-valid file.
    #[test]
    fn build_redactor_honours_config_deny_pattern() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("logbook.toml"),
            "[redaction]\nenabled = true\ndeny = [\"INTERNAL-[0-9]{6}\"]\n",
        )
        .expect("write config");

        let redactor = build_revert_redactor(dir.path(), false);
        assert!(redactor.is_enabled(), "general redactor should be enabled");
        assert!(
            !redactor.is_secrets_floor(),
            "config-on session must use the general redactor, not the floor"
        );
        let out = redactor.redact("ref INTERNAL-123456 ok");
        assert!(
            !out.contains("INTERNAL-123456"),
            "deny pattern from config not applied — redactor was not built from config: {out}"
        );
        assert!(out.contains("REDACTED:CUSTOM:"), "got: {out}");
    }

    /// A `--no-redact`-captured session recorded a floor-only hash, so revert must
    /// recompute with the secrets floor (which still scrubs secrets but passes
    /// non-secret bytes through) — never the general/deny redactor.
    #[test]
    fn build_redactor_no_redact_uses_secrets_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Even with redaction enabled + a deny pattern in config, --no-redact
        // drops the general layer down to the floor.
        std::fs::write(
            dir.path().join("logbook.toml"),
            "[redaction]\nenabled = true\ndeny = [\"INTERNAL-[0-9]{6}\"]\n",
        )
        .expect("write config");

        let redactor = build_revert_redactor(dir.path(), true);
        assert!(
            redactor.is_secrets_floor(),
            "--no-redact must recompute with the secrets-floor redactor"
        );
        // The floor ignores the general deny pattern (it is general-tier)…
        let out = redactor.redact("ref INTERNAL-123456 ok");
        assert!(
            out.contains("INTERNAL-123456"),
            "floor must not apply the general deny pattern: {out}"
        );
        // …but still scrubs an actual secret (the floor can never be disabled).
        let secret = redactor.redact("key AKIAIOSFODNN7EXAMPLE end");
        assert!(
            secret.contains("REDACTED:CLOUD_KEY:"),
            "secrets floor must still redact a cloud key under --no-redact: {secret}"
        );
    }

    /// Config-off (redaction disabled, no `--no-redact`) also falls to the floor —
    /// matching the capture path, which builds the floor when the general layer is
    /// off for any reason.
    #[test]
    fn build_redactor_config_disabled_uses_secrets_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("logbook.toml"),
            "[redaction]\nenabled = false\n",
        )
        .expect("write config");

        let redactor = build_revert_redactor(dir.path(), false);
        assert!(
            redactor.is_secrets_floor(),
            "redaction-disabled session must recompute with the secrets-floor redactor"
        );
    }
}
