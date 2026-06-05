//! `logbook proxy mcp -- <real-mcp-server...>` — run `logbook` as an **MCP
//! proxy in the middle** (plan "Phase 2", MCP proxy row + "Consolidated changes"
//! CLI row: `logbook proxy mcp`).
//!
//! An agent is pointed at `logbook` instead of its real MCP server. `logbook`
//! spawns the real server, forwards the agent's JSON-RPC (read from **stdin**,
//! written back to **stdout**) through a [`LoggingMcpTransport`], and records a
//! redacted `Kind::Tool` event for every `tools/call` — relaying responses
//! verbatim. The agent sees the real server; logbook sees (and records) every
//! tool call in between. The heavy lifting lives in
//! [`logbook_collector::run_mcp_proxy`]; this module is the thin CLI adapter.
//!
//! ## stdout is the protocol channel
//! Exactly like `logbook mcp`, the agent talks JSON-RPC over **stdout**, so this
//! command must never print anything else there. The process-wide `tracing`
//! subscriber already writes to **stderr only** (see `main.rs`), and the only
//! stdout writer here is the proxy's frame relay. Human status (the resolved
//! trace/session, the tool-event count) is printed to **stderr**.
//!
//! ## Redaction is sacred (plan §9)
//! Every recorded tool payload is redacted **before** persistence by the
//! [`HarnessContext`] inside [`LoggingMcpTransport`]. The capture posture is
//! resolved through the shared, fail-closed [`CapturePolicy::resolve`]
//! (recorder-on defaults → strict `<root>/logbook.toml [capture]` →
//! `<out_dir>/capture-state.json` narrow-only → CLI flags), so the cross-process
//! UI pause toggle silences proxy recording here too. The handler never builds
//! an event holding a raw secret.

use std::io::{BufReader, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand};

use logbook_collector::{run_mcp_proxy, McpProxyConfig};
use logbook_core::{CapturePolicy, CliOverlay, Redactor, SessionId, TraceId};
use logbook_harness::harness_context;
use logbook_store::Store;

/// `logbook proxy <kind>` — recording man-in-the-middle proxies.
#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// The proxy kind.
    #[command(subcommand)]
    pub command: ProxyCommand,
}

/// The `proxy` subcommands. Only `mcp` ships in Phase 2; `llm` (the Phase-4
/// provider proxy) is deliberately not wired here yet.
#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Run the MCP proxy-in-the-middle: spawn the real MCP server given after
    /// `--`, relay the agent's stdio JSON-RPC through it, and record a redacted
    /// tool event per `tools/call`.
    Mcp(McpProxyArgs),
}

/// `logbook proxy mcp [opts] -- <program> [args...]`.
#[derive(Debug, Args)]
pub struct McpProxyArgs {
    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`) that recorded
    /// tool events are written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the `[capture]` policy + the
    /// `[redaction]` patterns). Defaults to the current directory, matching how
    /// `logbook run`/`agent` resolve their config root.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Tie recorded tool events to an existing 32-hex `trace_id` (e.g. the trace
    /// of an active `logbook agent` session) instead of minting a fresh one.
    #[arg(long)]
    pub trace: Option<String>,

    /// Tie recorded tool events to a specific `session_id` instead of a fresh
    /// generated one.
    #[arg(long)]
    pub session: Option<String>,

    /// Harness label stamped on recorded events (default
    /// `mcp-proxy`).
    #[arg(long)]
    pub harness: Option<String>,

    /// Disable the **general** (non-secret) redactor for recorded tool payloads.
    /// The secrets floor (cloud keys, JWT, bearer, PEM, …) is **never** disabled
    /// — `--no-redact` only drops the general / `deny`-pattern layer, and the
    /// `tool_args`/`tool_results` classes are force-redacted regardless.
    #[arg(long)]
    pub no_redact: bool,

    /// The real MCP server to spawn: the program followed by its arguments.
    /// Everything after the flags — or after a literal `--` — is the server
    /// command (e.g. `-- node dist/server.js`).
    #[arg(trailing_var_arg = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Dispatch a `proxy` subcommand.
///
/// # Errors
/// Propagates the underlying proxy/store error as an `anyhow` error.
pub fn run(args: ProxyArgs) -> anyhow::Result<i32> {
    match args.command {
        ProxyCommand::Mcp(mcp_args) => run_mcp(mcp_args),
    }
}

/// Run the MCP proxy-in-the-middle to completion (until the agent closes stdin).
///
/// Resolves the capture policy fail-closed, builds a [`HarnessContext`], spawns
/// the real server behind a [`LoggingMcpTransport`], and pumps the agent's
/// stdin/stdout through it on a current-thread runtime (`run_mcp_proxy` has an
/// async signature but a synchronous blocking body, so it does not yield).
///
/// # Errors
/// Returns an error if the store cannot be opened, the real server cannot be
/// spawned, or a fatal I/O error occurs on the agent pipes. A non-zero result is
/// reserved for fatal failures; a clean agent disconnect returns `Ok(0)`.
fn run_mcp(args: McpProxyArgs) -> anyhow::Result<i32> {
    if args.command.is_empty() {
        anyhow::bail!("no MCP server command given (expected `proxy mcp -- <program> [args...]`)");
    }

    // Resolve the capture policy through the shared fail-closed helper so the
    // cross-process pause toggle (`<out_dir>/capture-state.json`) is honoured. We
    // only carry `--no-redact` on the overlay; diff flags do not apply to the
    // proxy lane.
    let overlay = CliOverlay {
        no_redact: args.no_redact,
        ..Default::default()
    };
    let policy = CapturePolicy::resolve(&args.root, &args.out_dir, overlay);

    // The general-redaction switch from `[redaction].enabled` AND `--no-redact`.
    // Build the general redactor (honouring the user's `[redaction] deny`/`allow`
    // patterns) when on, else the disabled passthrough — the `HarnessContext`
    // always layers the mandatory secrets floor on top regardless, so a secret
    // can never reach an event even under `--no-redact`, and `tool_args`/
    // `tool_results` are force-redacted (`RedactionMode::Always`).
    let cfg = logbook_core::LogbookConfig::load_from_root_or_default(&args.root);
    let general_enabled = cfg.redaction.enabled && !args.no_redact;
    let redactor = if general_enabled {
        logbook_core::redact::from_config(true, &cfg.redaction.deny, &cfg.redaction.allow)
            .unwrap_or_else(|_| {
                tracing::warn!("invalid redaction deny pattern in config; using built-in rules");
                Redactor::new().with_process_env()
            })
    } else {
        Redactor::disabled()
    };
    let ctx = harness_context(redactor, policy, general_enabled);

    // Trace/session: tie to an explicit id (e.g. an active session) or mint.
    let trace = match args.trace.as_deref() {
        Some(hex) => parse_trace_hex(hex)
            .ok_or_else(|| anyhow::anyhow!("--trace must be 32 hex chars (a logbook trace id)"))?,
        None => TraceId::new(),
    };
    let session = args
        .session
        .as_deref()
        .map(SessionId::new)
        .unwrap_or_else(SessionId::generate);

    let (program, server_args) = args.command.split_first().expect("non-empty (checked above)");
    let mut proxy_cfg = McpProxyConfig::new(program.clone(), server_args.to_vec())
        .with_cwd(args.root.clone())
        .with_trace(trace)
        .with_session(session.clone());
    if let Some(harness) = args.harness.clone() {
        proxy_cfg.harness = Some(harness);
    }

    let store = Store::open_in_dir(&args.out_dir)?;

    // Status to STDERR only — stdout is the JSON-RPC channel to the agent.
    eprintln!(
        "logbook proxy mcp: recording `{}` (trace {}, session {}); relaying agent stdio…",
        args.command.join(" "),
        trace.to_hex(),
        session.as_str()
    );
    if args.no_redact {
        eprintln!(
            "logbook: WARNING --no-redact is set; the secrets floor still applies, but \
             non-secret tool payloads may be persisted to {}.",
            args.out_dir.display()
        );
    }

    // Drive the proxy on a current-thread runtime (like `commands/mcp.rs` /
    // `commands/run.rs`). `run_mcp_proxy`'s body is synchronous blocking stdio
    // despite the async signature — it does not yield — so a single-threaded
    // runtime on this thread is sufficient and keeps the agent's stdin/stdout the
    // process pipes. Lock stdout so the relay owns the JSON-RPC protocol channel.
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let agent_in = BufReader::new(stdin.lock());
    let agent_out = stdout.lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let outcome = rt.block_on(run_mcp_proxy(
        proxy_cfg,
        std::sync::Arc::new(store),
        ctx,
        agent_in,
        agent_out,
    ))?;

    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "logbook proxy mcp: done — {} request(s), {} notification(s), {} tool event(s) recorded.",
        outcome.requests, outcome.notifications, outcome.tool_events
    );
    Ok(0)
}

/// Parse a 32-hex-char trace id into a [`TraceId`] (the `--trace` flag).
fn parse_trace_hex(hex: &str) -> Option<TraceId> {
    let hex = hex.trim();
    if hex.len() != TraceId::HEX_LEN {
        return None;
    }
    let mut bytes = [0u8; TraceId::LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        let s = hex.get(i * 2..i * 2 + 2)?;
        *b = u8::from_str_radix(s, 16).ok()?;
    }
    if bytes == [0u8; TraceId::LEN] {
        return None;
    }
    Some(TraceId::from_bytes(bytes))
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

    #[derive(Debug, Subcommand)]
    enum TestCmd {
        Proxy(ProxyArgs),
    }

    fn parse_mcp(argv: &[&str]) -> McpProxyArgs {
        let cli = TestCli::try_parse_from(argv).expect("parse");
        match cli.cmd {
            TestCmd::Proxy(p) => match p.command {
                ProxyCommand::Mcp(m) => m,
            },
        }
    }

    #[test]
    fn parses_proxy_mcp_server_command_after_double_dash() {
        let m = parse_mcp(&["x", "proxy", "mcp", "--", "node", "server.js", "--flag"]);
        assert_eq!(m.command, vec!["node", "server.js", "--flag"]);
        // Defaults.
        assert_eq!(m.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(m.root, PathBuf::from("."));
        assert!(m.trace.is_none() && m.session.is_none() && m.harness.is_none());
        assert!(!m.no_redact);
    }

    #[test]
    fn parses_proxy_mcp_opts_then_command() {
        let m = parse_mcp(&[
            "x", "proxy", "mcp", "--out-dir", "/tmp/o", "--root", "/repo", "--trace",
            "a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8", "--session", "sess-1", "--harness", "claude-code",
            "--no-redact", "--", "python", "-m", "srv",
        ]);
        assert_eq!(m.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(m.root, PathBuf::from("/repo"));
        assert_eq!(m.trace.as_deref(), Some("a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8"));
        assert_eq!(m.session.as_deref(), Some("sess-1"));
        assert_eq!(m.harness.as_deref(), Some("claude-code"));
        assert!(m.no_redact);
        assert_eq!(m.command, vec!["python", "-m", "srv"]);
    }

    #[test]
    fn mcp_server_command_can_lead_with_hyphen_flag() {
        // `allow_hyphen_values` lets the spawned server carry its own flags
        // without a second `--` confusing clap.
        let m = parse_mcp(&["x", "proxy", "mcp", "--", "mcp-server", "-v", "--port", "0"]);
        assert_eq!(m.command, vec!["mcp-server", "-v", "--port", "0"]);
    }

    #[test]
    fn parse_trace_hex_roundtrips_and_rejects_bad_input() {
        let hex = "a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8";
        let t = parse_trace_hex(hex).expect("valid 32-hex");
        assert_eq!(t.to_hex(), hex);
        // Wrong length / non-hex / all-zero are rejected.
        assert!(parse_trace_hex("abcd").is_none());
        assert!(parse_trace_hex("zz2a3a4a5a6a7a8b1b2b3b4b5b6b7b8x").is_none());
        assert!(parse_trace_hex(&"0".repeat(32)).is_none());
    }
}
