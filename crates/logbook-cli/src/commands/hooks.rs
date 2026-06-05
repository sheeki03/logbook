//! `logbook hooks` — run the collector's **harness hook receiver** and print how
//! to point a harness at it (plan "Phase 2", Ingest/OTLP row + "Consolidated
//! changes" CLI row: `logbook hooks`).
//!
//! This starts the same loopback [`logbook_collector`] axum server `logbook run`
//! uses, but as a **standalone, long-lived** endpoint dedicated to receiving a
//! coding harness's own records:
//! - **`POST /v1/hooks`** — Claude Code `PreToolUse`/`PostToolUse`/
//!   `UserPromptSubmit`/`Stop` hook JSON (or a session-log line), normalized via
//!   the [`logbook_harness`] adapters into **redacted** events and persisted;
//! - **`POST /v1/traces`** — a minimal OTLP-JSON spans envelope.
//!
//! Both routes are bearer-gated (the same per-run ingest token as `/ingest`,
//! unless `--no-token` drops the gate for a local single-user box) and honour the
//! resolved [`CapturePolicy`] (so a paused capture toggle drops prompt/tool
//! payloads). On startup the command prints the endpoint URL and a complete,
//! copy-pasteable Claude Code `settings.json` `hooks` recipe so a user can wire
//! their harness to it, then blocks until Ctrl-C / SIGTERM.
//!
//! ## Why the recipe goes through a shell
//! Claude Code execs a hook `command` **without** shell quote-processing, so an
//! inline `curl … -H 'Authorization: Bearer <tok>' …` is mis-parsed (the quoted
//! header arrives as a malformed argv token → the request is rejected → ZERO
//! events captured, silently). So the token-mode banner hands the user a tiny
//! hook **script** holding the curl and a `command` of `sh ~/.logbook-hook.sh`
//! (no quotes for the runner to mangle).
//!
//! Both recipes also forward a `x-logbook-trace: $LOGBOOK_TRACE` header so the
//! hooks **correlate** to the wrapped `logbook agent` session (which exports
//! `LOGBOOK_TRACE` into the agent's environment). Because the runner does no
//! shell processing, `$LOGBOOK_TRACE` only expands when the command runs through
//! a shell: the token recipe expands it inside the `sh` script; the `--no-token`
//! recipe — which has no Authorization header to quote — wraps its curl in
//! `sh -c '…'` for the same reason. Outside a `logbook agent` run the variable is
//! unset and the header is empty, which the receiver ignores.
//!
//! ## Redaction is sacred (plan §9)
//! Every prompt / tool arg / tool result is redacted **before** persistence
//! inside the collector's per-request [`HarnessContext`]; this command only
//! resolves the posture (fail-closed [`CapturePolicy::resolve`]) and hands it to
//! the collector. Ingesting a harness's own logs is **opt-in** — running this
//! receiver is the explicit opt-in (it is not started by `logbook run`/`agent`).

use std::path::PathBuf;

use clap::Args;

use logbook_collector::{CollectorConfig, RunningCollector, TokenMode};
use logbook_core::{CapturePolicy, CliOverlay};
use logbook_store::Store;

/// `logbook hooks [opts]`.
#[derive(Debug, Args)]
pub struct HooksArgs {
    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`) that ingested
    /// hook/OTLP events are written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the `[capture]` policy).
    /// Defaults to the current directory, matching how `logbook run`/`agent`
    /// resolve their config root.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Preferred port; auto-increments on conflict (matches `logbook run`'s
    /// collector default of 4318).
    #[arg(long, default_value_t = 4318)]
    pub port: u16,

    /// Origin allowed by CORS (scoped, never `*`). Only relevant if a browser
    /// page posts hooks; harness CLIs are unaffected.
    #[arg(long, default_value = "http://localhost:5173")]
    pub dev_origin: String,

    /// Disable the **general** (non-secret) redactor for ingested payloads. The
    /// secrets floor is **never** disabled — `--no-redact` only drops the
    /// general / `deny`-pattern layer; prompts/tool args/results are
    /// force-redacted regardless.
    #[arg(long)]
    pub no_redact: bool,

    /// Run the receiver with **no** ingest-token gate — **LOCAL SINGLE-USER /
    /// dev use only**. The receiver is always loopback-only, but on a **shared**
    /// host the token is what defends against OTHER local users: it stops any
    /// other process on the box from posting to `/v1/hooks` (and thereby
    /// injecting forged tool/prompt events into your recorder). With `--no-token`
    /// that defence is gone — *any* local process can hit the receiver — so it is
    /// strictly opt-in. The upside: the hook command becomes a quote-free
    /// `curl -X POST .../v1/hooks --data-binary @-` with **no** `Authorization`
    /// header, which Claude Code's hook runner (no shell quote-processing) execs
    /// reliably. When unset, the token is sourced from `LOGBOOK_INGEST_TOKEN` if
    /// present, else freshly generated at startup.
    #[arg(long, default_value_t = false)]
    pub no_token: bool,
}

/// Run the hook receiver until Ctrl-C / SIGTERM.
///
/// Resolves the capture policy fail-closed, starts the collector with that
/// policy, prints the endpoint + token + a harness-wiring snippet, and blocks on
/// the server task (which itself stops on SIGINT/SIGTERM).
///
/// # Errors
/// Returns an error if the store cannot be opened or no port in the
/// auto-increment range is free.
pub fn run(args: HooksArgs) -> anyhow::Result<i32> {
    // Resolve the capture policy through the shared fail-closed helper so the
    // cross-process pause toggle (`<out_dir>/capture-state.json`) silences hook
    // ingest too. Only `--no-redact` is carried on the overlay here.
    let overlay = CliOverlay {
        no_redact: args.no_redact,
        ..Default::default()
    };
    let policy = CapturePolicy::resolve(&args.root, &args.out_dir, overlay);

    let store = Store::open_in_dir(&args.out_dir)?;

    // Source the ingest token: `--no-token` wins (forces the gate OFF for a local
    // single-user box so the hook command needs no `Authorization` header), else
    // the established order — an explicit env token (`LOGBOOK_INGEST_TOKEN`) wins,
    // else mint one (same sourcing as `logbook run`'s collector). Factored into
    // `resolve_token_mode` so the precedence is unit-tested without binding a port.
    let token_mode = resolve_token_mode(
        args.no_token,
        std::env::var_os(logbook_collector::INGEST_TOKEN_ENV).is_some(),
    );

    let mut collector_cfg = CollectorConfig::new(args.out_dir.clone(), args.dev_origin.clone())
        .with_port(args.port)
        .with_token_mode(token_mode)
        .with_capture_policy(policy);
    if args.no_redact {
        collector_cfg = collector_cfg.without_redaction();
    }

    if args.no_redact {
        eprintln!(
            "logbook: WARNING --no-redact is set; the secrets floor still applies, but \
             non-secret hook payloads may be persisted to {}.",
            args.out_dir.display()
        );
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let collector = logbook_collector::start(collector_cfg, store).await?;
        print_instructions(&collector);
        // The collector's server task stops on its own SIGINT/SIGTERM handler;
        // awaiting `join` blocks here until then (or the parent-PID watchdog).
        collector.join().await;
        anyhow::Ok(())
    })?;

    Ok(0)
}

/// Resolve which [`TokenMode`] the hook receiver starts under, from the
/// `--no-token` flag and whether [`logbook_collector::INGEST_TOKEN_ENV`] is set.
///
/// `--no-token` is the **highest-precedence** input: when set it forces
/// [`TokenMode::Off`] (no gate — local single-user / dev only) regardless of the
/// env var, so a stray `LOGBOOK_INGEST_TOKEN` in the environment cannot silently
/// re-arm the gate the user explicitly asked to drop. Otherwise we keep the
/// established source order the rest of logbook uses: an explicit env var wins
/// ([`TokenMode::Env`], which hard-errors later if unset/empty), else mint a
/// fresh token at startup ([`TokenMode::Generated`]).
fn resolve_token_mode(no_token: bool, env_token_set: bool) -> TokenMode {
    if no_token {
        TokenMode::Off
    } else if env_token_set {
        TokenMode::Env
    } else {
        TokenMode::Generated
    }
}

/// Print the endpoint, bearer token, and a copy-pasteable Claude Code hooks
/// snippet to **stdout** so a user can point a harness at the receiver.
fn print_instructions(collector: &RunningCollector) {
    let addr = collector.addr();
    let base = format!("http://{addr}");
    // `base` already carries the bound port (the OS-assigned one after any
    // auto-increment), so the printed URLs are always the live, copy-pasteable
    // address.
    println!("logbook hooks: receiver listening on {base} (port {})", addr.port());
    println!("  POST {base}/v1/hooks   (Claude Code hook JSON: UserPromptSubmit/PreToolUse/PostToolUse/Stop)");
    println!("  POST {base}/v1/traces  (minimal OTLP-JSON spans)");
    match collector.token() {
        Some(token) => print_token_recipe(&base, token),
        None => print_no_token_recipe(&base),
    }
    println!();
    println!("Hooks fire in `claude -p` (headless) runs too, not just the interactive TUI.");
    println!("Press Ctrl-C to stop.");
}

/// Print the wiring recipe when the ingest token gate is **on** (the default).
///
/// Claude Code execs a hook `command` **without** shell quote-processing, so an
/// inline `curl … -H 'Authorization: Bearer <tok>' …` breaks (the quoted header
/// arrives as a malformed argv token, the request is rejected, and you silently
/// capture ZERO events). The reliable form is a hook **script** that holds the
/// curl — the settings `command` is then just `sh ~/.logbook-hook.sh`, which has
/// no quoting for the hook runner to mangle.
fn print_token_recipe(base: &str, token: &str) {
    println!();
    println!("Ingest token (the receiver is loopback-only AND token-gated):");
    println!("  {token}");
    println!();
    println!("IMPORTANT: Claude Code runs a hook `command` WITHOUT shell quote-processing, so an");
    println!("inline `curl -H 'Authorization: Bearer …'` is NOT parsed reliably (the quoted header");
    println!("becomes a malformed argument, the request is rejected, and you capture ZERO events).");
    println!("Use a hook SCRIPT instead — the settings `command` then carries no quotes to mangle.");
    println!();
    println!("1) Save this script (e.g. as ~/.logbook-hook.sh) and `chmod +x ~/.logbook-hook.sh`:");
    println!();
    println!("  #!/bin/sh");
    println!("  curl -sS -X POST {base}/v1/hooks \\");
    println!("    -H \"Content-Type: application/json\" \\");
    println!("    -H \"Authorization: Bearer {token}\" \\");
    println!("    -H \"x-logbook-trace: $LOGBOOK_TRACE\" \\");
    println!("    --data-binary @-");
    println!();
    println!("2) Add this `hooks` block to your settings.json (the `command` is quote-free):");
    println!();
    print_settings_block("sh ~/.logbook-hook.sh");
    println!();
    println!("Use it with `claude --settings <file>` or merge into ~/.claude/settings.json.");
    println!("(the hook's JSON payload is piped on stdin; the receiver redacts before storing.)");
    println!();
    println!("The `-H \"x-logbook-trace: $LOGBOOK_TRACE\"` line CORRELATES these hooks to the");
    println!("wrapped `logbook agent` session: that wrapper exports LOGBOOK_TRACE into the agent's");
    println!("environment, the hook script (run by /bin/sh) expands it at fire time, and the");
    println!("receiver records the hook events under that SAME trace — so the agent transcript,");
    println!("the LLM-proxy calls, and these tool/prompt events form one correlated session.");
    println!("(Outside a `logbook agent` run LOGBOOK_TRACE is unset and the header is empty, which");
    println!("the receiver ignores — each hook batch then gets its own trace, as before.)");
}

/// Print the wiring recipe when `--no-token` dropped the gate (local
/// single-user / dev). With no `Authorization` header to quote, the hook
/// `command` is a quote-free one-liner Claude Code's hook runner execs reliably,
/// so no wrapper script is needed.
fn print_no_token_recipe(base: &str) {
    println!();
    println!("(token gate disabled via --no-token — LOCAL SINGLE-USER / dev only; every request is");
    println!("accepted. On a shared host, drop --no-token so the token blocks other local users.)");
    println!();
    println!("There is no Authorization header to quote, but the command still forwards the");
    println!("correlation header `x-logbook-trace: $LOGBOOK_TRACE`. Claude Code execs a hook");
    println!("`command` WITHOUT shell quote-processing, so `$LOGBOOK_TRACE` would NOT expand in a");
    println!("bare inline curl — the command is therefore wrapped in `sh -c '...'` so a shell");
    println!("expands the variable at fire time. Add this `hooks` block to your settings.json:");
    println!();
    print_settings_block(&no_token_hook_command(base));
    println!();
    println!("Use it with `claude --settings <file>` or merge into ~/.claude/settings.json.");
    println!();
    println!("The `-H \"x-logbook-trace: $LOGBOOK_TRACE\"` CORRELATES these hooks to the wrapped");
    println!("`logbook agent` session: that wrapper exports LOGBOOK_TRACE into the agent's");
    println!("environment, the `sh -c` shell expands it at fire time, and the receiver records the");
    println!("hook events under that SAME trace — so the agent transcript, the LLM-proxy calls, and");
    println!("these tool/prompt events form one correlated session. (Outside a `logbook agent` run");
    println!("LOGBOOK_TRACE is unset and the header is empty, which the receiver ignores — each hook");
    println!("batch then gets its own trace, as before.)");
}

/// Print a copy-pasteable Claude Code `settings.json` `hooks` block wiring all
/// four capture-relevant lifecycle events (UserPromptSubmit, PreToolUse,
/// PostToolUse, Stop) — each with a `"*"` matcher — to run `command` on stdin.
///
/// The shape matches Claude Code 2.x: each event maps to a list of matcher
/// groups, each group a `matcher` plus a `hooks` list of `{type:"command",
/// command}` entries that receive the event JSON on stdin.
fn print_settings_block(command: &str) {
    print!("{}", settings_block(command));
}

/// Build the copy-pasteable Claude Code `settings.json` `hooks` block as a
/// string (so it is testable as valid JSON), wiring the four capture-relevant
/// lifecycle events to run `command` on stdin.
///
/// The `command` may contain double-quotes (the `--no-token` recipe wraps the
/// curl in `sh -c '... -H "x-logbook-trace: $LOGBOOK_TRACE" ...'`), so it is
/// JSON-escaped before being embedded as a string value — otherwise the printed
/// settings.json is malformed and silently fails to parse.
fn settings_block(command: &str) -> String {
    use std::fmt::Write as _;
    let command = json_escape(command);
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"hooks\": {{");
    // The four events we care about. UserPromptSubmit + Stop bracket a turn;
    // Pre/PostToolUse capture each tool call.
    let events = ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"];
    for (i, event) in events.iter().enumerate() {
        let comma = if i + 1 < events.len() { "," } else { "" };
        let _ = writeln!(out, "    \"{event}\": [");
        let _ = writeln!(out, "      {{");
        let _ = writeln!(out, "        \"matcher\": \"*\",");
        let _ = writeln!(out, "        \"hooks\": [");
        let _ = writeln!(out, "          {{ \"type\": \"command\", \"command\": \"{command}\" }}");
        let _ = writeln!(out, "        ]");
        let _ = writeln!(out, "      }}");
        let _ = writeln!(out, "    ]{comma}");
    }
    let _ = writeln!(out, "  }}");
    let _ = writeln!(out, "}}");
    out
}

/// The hook `command` the `--no-token` recipe prints: a `sh -c` wrapper so the
/// shell expands `$LOGBOOK_TRACE` at fire time (Claude Code execs the hook
/// `command` without shell quote-processing, so a bare inline curl would not
/// expand it). Factored out so the forwarded correlation header is unit-tested.
fn no_token_hook_command(base: &str) -> String {
    format!(
        "sh -c 'curl -sS -X POST {base}/v1/hooks -H \"Content-Type: application/json\" -H \"x-logbook-trace: $LOGBOOK_TRACE\" --data-binary @-'"
    )
}

/// Minimal JSON string-body escaper for the hook `command` embedded in the
/// printed settings.json. Escapes the two characters that would otherwise break
/// the surrounding `"..."` string: backslash and double-quote. (The commands we
/// print never contain control characters, so this is sufficient and keeps the
/// snippet human-readable — a full `serde_json::to_string` would also work but
/// would escape nothing else here anyway.)
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
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
        Hooks(HooksArgs),
    }

    fn parse(argv: &[&str]) -> HooksArgs {
        let cli = TestCli::try_parse_from(argv).expect("parse");
        match cli.cmd {
            TestCmd::Hooks(h) => h,
        }
    }

    #[test]
    fn parses_hooks_defaults() {
        let h = parse(&["x", "hooks"]);
        assert_eq!(h.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(h.root, PathBuf::from("."));
        assert_eq!(h.port, 4318);
        assert_eq!(h.dev_origin, "http://localhost:5173");
        assert!(!h.no_redact);
        assert!(!h.no_token);
    }

    #[test]
    fn parses_hooks_opts() {
        let h = parse(&[
            "x", "hooks", "--out-dir", "/tmp/o", "--root", "/repo", "--port", "9000",
            "--dev-origin", "http://localhost:3000", "--no-redact", "--no-token",
        ]);
        assert_eq!(h.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(h.root, PathBuf::from("/repo"));
        assert_eq!(h.port, 9000);
        assert_eq!(h.dev_origin, "http://localhost:3000");
        assert!(h.no_redact);
        assert!(h.no_token);
    }

    /// Token-mode resolution (`resolve_token_mode`), the exact decision `run`
    /// makes from `--no-token` and whether `LOGBOOK_INGEST_TOKEN` is set. Tested
    /// against the pure helper so no env mutation or port bind is needed (mirrors
    /// the `proxy llm` precedence test).
    ///
    /// - `--no-token` ⇒ [`TokenMode::Off`], and it WINS even when the env var is
    ///   set (the user explicitly dropped the gate; a stray env token must not
    ///   silently re-arm it).
    /// - not set + env unset ⇒ [`TokenMode::Generated`] (mint a fresh token).
    /// - not set + env set ⇒ [`TokenMode::Env`] (the established source order).
    #[test]
    fn resolve_token_mode_precedence() {
        assert_eq!(resolve_token_mode(true, false), TokenMode::Off);
        assert_eq!(
            resolve_token_mode(true, true),
            TokenMode::Off,
            "--no-token must win over a set LOGBOOK_INGEST_TOKEN"
        );
        assert_eq!(
            resolve_token_mode(false, false),
            TokenMode::Generated,
            "no flag and no env var ⇒ mint a fresh token"
        );
        assert_eq!(resolve_token_mode(false, true), TokenMode::Env);
    }

    /// `json_escape` escapes exactly the two characters that would break the
    /// surrounding `"..."` JSON string value (backslash, double-quote).
    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape(r#"a "b" c"#), r#"a \"b\" c"#);
        assert_eq!(json_escape(r"a\b"), r"a\\b");
    }

    /// The `--no-token` recipe's hook command forwards the correlation header so
    /// the wrapped `logbook agent` session's `LOGBOOK_TRACE` is propagated, and it
    /// goes through a shell (`sh -c '...'`) so the variable expands at fire time
    /// (Claude Code execs the `command` without shell quote-processing).
    #[test]
    fn no_token_command_forwards_correlation_header_via_shell() {
        let cmd = no_token_hook_command("http://127.0.0.1:4318");
        assert!(cmd.starts_with("sh -c '"), "must run through a shell: {cmd}");
        assert!(
            cmd.contains("-H \"x-logbook-trace: $LOGBOOK_TRACE\""),
            "must forward the correlation header: {cmd}"
        );
        assert!(cmd.contains("http://127.0.0.1:4318/v1/hooks"), "posts to the receiver: {cmd}");
        assert!(cmd.contains("--data-binary @-"), "still pipes the payload on stdin: {cmd}");
    }

    /// Both recipe `command` shapes embed as VALID JSON in the printed settings
    /// block (a malformed block would silently fail to parse in Claude Code), and
    /// the `command` round-trips byte-for-byte through the JSON escaping.
    #[test]
    fn settings_block_is_valid_json_for_both_recipes() {
        // --no-token: the `sh -c '...'` form contains inner double-quotes.
        let no_tok_cmd = no_token_hook_command("http://127.0.0.1:4318");
        let block = settings_block(&no_tok_cmd);
        let parsed: serde_json::Value =
            serde_json::from_str(&block).expect("no-token settings block must be valid JSON");
        let got = parsed["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .expect("command string");
        assert_eq!(got, no_tok_cmd, "command must round-trip through the JSON escaping");
        assert!(
            got.contains("x-logbook-trace: $LOGBOOK_TRACE"),
            "forwarded correlation header survives into the JSON: {got}"
        );
        // All four lifecycle events are wired.
        for ev in ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"] {
            assert!(parsed["hooks"].get(ev).is_some(), "missing event {ev}");
        }

        // token mode: the `command` is the quote-free `sh ~/.logbook-hook.sh`.
        let tok_block = settings_block("sh ~/.logbook-hook.sh");
        let tok_parsed: serde_json::Value =
            serde_json::from_str(&tok_block).expect("token settings block must be valid JSON");
        assert_eq!(
            tok_parsed["hooks"]["Stop"][0]["hooks"][0]["command"].as_str(),
            Some("sh ~/.logbook-hook.sh")
        );
    }
}
