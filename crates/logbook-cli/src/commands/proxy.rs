//! `logbook proxy <kind>` — recording man-in-the-middle proxies (plan
//! "Consolidated changes" CLI row: `logbook proxy mcp` / `logbook proxy llm`).
//!
//! Two proxy lanes share this subcommand:
//!
//! - **`proxy mcp -- <real-mcp-server...>`** (Phase 2) — run `logbook` as an MCP
//!   proxy in the middle. An agent is pointed at `logbook` instead of its real
//!   MCP server. `logbook` spawns the real server, forwards the agent's JSON-RPC
//!   (read from **stdin**, written back to **stdout**) through a
//!   [`LoggingMcpTransport`], and records a redacted `Kind::Tool` event for every
//!   `tools/call` — relaying responses verbatim. The agent sees the real server;
//!   logbook sees (and records) every tool call in between. The heavy lifting
//!   lives in [`logbook_collector::run_mcp_proxy`].
//! - **`proxy llm [--provider …] [--upstream …] --yes`** (Phase 4) — run the
//!   **Complete-tier** LLM API proxy ([`logbook_llmproxy`]). A loopback-only,
//!   bearer-gated HTTP server an agent points `ANTHROPIC_BASE_URL` /
//!   `OPENAI_BASE_URL` at; it forwards each request upstream and records the call
//!   as a redacted `Kind::Llm` event. Because it captures **full provider
//!   traffic** (the most invasive tier), it **requires an explicit `--yes`**.
//!
//! This module is the thin CLI adapter over both crates.
//!
//! ## stdout is the protocol channel (mcp lane)
//! Exactly like `logbook mcp`, the agent talks JSON-RPC over **stdout** in the
//! `mcp` lane, so that command must never print anything else there. The
//! process-wide `tracing` subscriber already writes to **stderr only** (see
//! `main.rs`), and the only stdout writer is the proxy's frame relay. Human
//! status (the resolved trace/session, the tool-event count) is printed to
//! **stderr**. The `llm` lane is an HTTP server, not a stdio relay, so it prints
//! its banner (the `*_BASE_URL` to export, the proxy token to send on the
//! dedicated `x-logbook-proxy-token` header) to **stdout**.
//!
//! ## Redaction is sacred (plan §9)
//! Every recorded tool payload (mcp) / prompt+response body (llm) is redacted
//! **before** persistence by the [`HarnessContext`] the respective crate routes
//! payloads through. The capture posture is resolved through the shared,
//! fail-closed [`CapturePolicy::resolve`] (recorder-on defaults → strict
//! `<root>/logbook.toml [capture]` → `<out_dir>/capture-state.json` narrow-only →
//! CLI flags), so the cross-process UI pause toggle silences proxy recording
//! here too. Neither handler ever builds an event holding a raw secret. The LLM
//! proxy additionally reassembles streaming (SSE) responses **in full before
//! redaction** and force-redacts prompts/results regardless of `--no-redact`.

use std::io::{BufReader, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand};

use logbook_collector::{run_mcp_proxy, McpProxyConfig};
use logbook_core::{CapturePolicy, CliOverlay, Redactor, SessionId, TraceId};
use logbook_harness::harness_context;
use logbook_llmproxy::{run_llm_proxy, LlmProxyConfig, LlmProxyError, Provider, TokenMode};
use logbook_store::Store;

/// `logbook proxy <kind>` — recording man-in-the-middle proxies.
#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// The proxy kind.
    #[command(subcommand)]
    pub command: ProxyCommand,
}

/// The `proxy` subcommands: `mcp` (Phase 2, MCP-in-the-middle) and `llm`
/// (Phase 4, the Complete-tier provider proxy).
#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Run the MCP proxy-in-the-middle: spawn the real MCP server given after
    /// `--`, relay the agent's stdio JSON-RPC through it, and record a redacted
    /// tool event per `tools/call`.
    Mcp(McpProxyArgs),

    /// Run the Complete-tier LLM API proxy (Phase 4): forward an agent's provider
    /// traffic upstream and record each call as a redacted `Kind::Llm` event.
    /// Captures FULL provider payloads, so it **requires `--yes`** and enables
    /// the `complete` tier at runtime for this process only.
    Llm(LlmProxyArgs),
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
        ProxyCommand::Llm(llm_args) => run_llm(llm_args),
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

/// `logbook proxy llm [opts] --yes`.
///
/// The Complete-tier provider proxy. Because it captures the **full** provider
/// request/response (the most invasive tier), it carries a hard `--yes`
/// acknowledgement and enables the `complete` tier **at runtime for this process
/// only** — the config-file complete-enable is rejected by
/// `CapturePolicy::validate()`, so this CLI ack is the single sanctioned runtime
/// path (plan "Phase 4": "Default off; refuses to start unless `complete`
/// enabled").
#[derive(Debug, Args)]
pub struct LlmProxyArgs {
    /// Which provider to forward to (`anthropic` or `openai`). Selects the
    /// request/response shape, the routing prefix, and the default upstream base
    /// URL. Defaults to `anthropic`.
    #[arg(long, value_enum, default_value_t = ProviderArg::Anthropic)]
    pub provider: ProviderArg,

    /// Override the upstream provider base URL (e.g. a regional or gateway
    /// endpoint). Defaults to the provider's conventional public API root
    /// (`https://api.anthropic.com` / `https://api.openai.com`).
    #[arg(long)]
    pub upstream: Option<String>,

    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`) that recorded
    /// LLM events are written to.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the `[capture]` policy + the
    /// `[redaction]` patterns). Defaults to the current directory, matching how
    /// `logbook run`/`agent` resolve their config root.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Preferred port; auto-increments on conflict. `0` lets the OS choose.
    #[arg(long, default_value_t = 0)]
    pub port: u16,

    /// Acknowledge that this proxy captures FULL provider traffic (the Complete
    /// tier — the single most invasive capture mode). **Required**: without it
    /// the command refuses to start. Passing it enables the `complete` tier at
    /// runtime for this process only; it does **not** write `logbook.toml`.
    #[arg(long, default_value_t = false)]
    pub yes: bool,

    /// Disable the **general** (non-secret) redactor for recorded payloads. The
    /// secrets floor (cloud keys, JWT, bearer, PEM, …) is **never** disabled —
    /// `--no-redact` only drops the general / `deny`-pattern layer, and the
    /// `prompts` / `tool_results` classes are force-redacted regardless.
    #[arg(long)]
    pub no_redact: bool,

    /// Additionally extend the tamper-evident audit hash chain over each recorded
    /// (already-redacted) event.
    #[arg(long, default_value_t = false)]
    pub audit: bool,
}

/// `--provider` choices (a CLI mirror of [`Provider`] so clap can derive
/// `ValueEnum` without touching the library type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProviderArg {
    /// Anthropic Messages API.
    Anthropic,
    /// OpenAI Chat Completions API.
    Openai,
}

impl ProviderArg {
    /// Map to the library [`Provider`].
    fn as_provider(self) -> Provider {
        match self {
            ProviderArg::Anthropic => Provider::Anthropic,
            ProviderArg::Openai => Provider::OpenAi,
        }
    }
}

/// Run the Complete-tier LLM API proxy until Ctrl-C / SIGTERM.
///
/// ## The `--yes` gate (the most invasive tier)
/// The LLM proxy is the **only** component that sees raw provider payloads, so it
/// is the most gated. Without `--yes` we refuse up front with a clear
/// explanation and a non-zero exit — *before* opening the store or binding a
/// port. With `--yes`, we resolve the normal fail-closed capture policy
/// (`complete` still off there — `validate()` rejects a config-file enable) and
/// then flip `tiers.complete = true` **at runtime for this process only**. This
/// CLI acknowledgement is the sanctioned runtime path the underlying
/// `run_llm_proxy` gate ([`LlmProxyError::CompleteTierDisabled`]) expects.
///
/// ## Redaction is sacred (plan §9)
/// We pass the resolved policy and the `--no-redact` flag straight into
/// [`LlmProxyConfig`]; the crate force-redacts prompts/results and reassembles
/// SSE before redaction. Nothing here ever holds a raw payload.
///
/// # Errors
/// Returns an error if the store cannot be opened, the upstream client cannot be
/// built, or no port in the auto-increment range is free. Refusal for a missing
/// `--yes` is surfaced as `Ok(2)` (a clean, explained decline — not a crash).
fn run_llm(args: LlmProxyArgs) -> anyhow::Result<i32> {
    let provider = args.provider.as_provider();

    // GATE: full provider traffic ⇒ require the explicit acknowledgement. Refuse
    // loudly to STDERR and decline (exit 2) before touching the store or network.
    if !args.yes {
        eprintln!(
            "logbook proxy llm: refusing to start without `--yes`.\n\
             \n\
             This proxy captures FULL provider request/response traffic (the\n\
             Complete tier — the single most invasive capture mode in logbook).\n\
             It is OFF by default and the config-file enable is rejected on load;\n\
             passing `--yes` is the only sanctioned way to turn it on, and it does\n\
             so at RUNTIME for this process only (it never writes logbook.toml).\n\
             \n\
             Prompts and responses are always force-redacted before persistence\n\
             (the secrets floor applies even with --no-redact, and streaming\n\
             responses are reassembled in full before redaction), but you are\n\
             still routing real provider traffic through logbook.\n\
             \n\
             Re-run with `--yes` to acknowledge and start:\n  \
             logbook proxy llm --provider {} --yes",
            provider.as_str()
        );
        return Ok(2);
    }

    // Resolve the capture policy (shared fail-closed helper) and apply the
    // sanctioned RUNTIME complete-tier enable that `--yes` acknowledges.
    let policy = resolve_llm_policy(&args.root, &args.out_dir, args.no_redact);

    // If the cross-process pause toggle (or a `[capture]` master-off) has disabled
    // capture, the proxy still forwards traffic but records nothing — warn loudly
    // (the user explicitly opted into recording with `--yes`) and continue, rather
    // than silently no-op. Re-enabling capture restores recording without a
    // restart, since the policy is consulted per request at the persistence
    // boundary inside the crate.
    if !policy.enabled {
        eprintln!(
            "logbook proxy llm: WARNING capture is currently paused (master switch off via \
             logbook.toml or {}/capture-state.json); the proxy will forward provider traffic \
             but record NOTHING until capture is re-enabled.",
            args.out_dir.display()
        );
    }

    let base_url = args
        .upstream
        .clone()
        .unwrap_or_else(|| provider.default_base_url().to_string());

    // Source the bearer token like the other servers: an explicit env var wins,
    // else mint a fresh one at startup.
    let token_mode = if std::env::var_os(logbook_llmproxy::ENV_TOKEN_VAR).is_some() {
        TokenMode::Env
    } else {
        TokenMode::Generated
    };

    let mut config = LlmProxyConfig::single(provider, base_url.clone())
        .with_port(args.port)
        .with_token_mode(token_mode)
        .with_capture_policy(policy);
    if args.no_redact {
        config = config.without_redaction();
    }
    if args.audit {
        config = config.with_audit();
    }

    let store = Store::open_in_dir(&args.out_dir)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let proxy = match run_llm_proxy(config, store).await {
            Ok(p) => p,
            // Map the tier gate to a friendly message (should not trigger — we
            // enabled `complete` above — but keep the contract explicit).
            Err(LlmProxyError::CompleteTierDisabled) => {
                eprintln!(
                    "logbook proxy llm: the Complete tier is not enabled; pass `--yes` to \
                     acknowledge and enable it."
                );
                return Ok(2);
            }
            Err(e) => return Err(anyhow::Error::new(e)),
        };

        print_llm_instructions(&proxy, provider, &base_url, args.no_redact);

        // Neither `RunningProxy` nor the hub install their own signal handler
        // (unlike the collector), so the CLI owns the shutdown wait here: block
        // until Ctrl-C / SIGTERM, then drain the server task.
        wait_for_shutdown().await;
        eprintln!("logbook proxy llm: shutting down…");
        proxy.shutdown().await;
        anyhow::Ok(0)
    })
}

/// Resolve the LLM-proxy capture policy and apply the `--yes` runtime tier enable.
///
/// Resolves the policy through the SAME shared fail-closed helper every producer
/// uses (recorder-on defaults → strict `<root>/logbook.toml [capture]` →
/// `<out_dir>/capture-state.json` narrow-only; `complete` is OFF there — the
/// config path can never enable it). Only `--no-redact` rides the overlay; the
/// diff flags do not apply to the proxy lane.
///
/// Then it performs the sanctioned RUNTIME complete-tier enable that `--yes`
/// acknowledges (the config-file path's `validate()` refuses to honour it). Tiers
/// are CUMULATIVE (universal ⊆ structured ⊆ complete), so all three lower-or-equal
/// switches are raised together: prompt/result capture is gated on the STRUCTURED
/// tier (`tier_allows` routes Prompts/ToolArgs/ToolResults → `tiers.structured`),
/// not on `complete`, so enabling `complete` alone would leave a `logbook.toml`
/// that turned `structured` off recording NOTHING from this complete-tier proxy.
fn resolve_llm_policy(root: &std::path::Path, out_dir: &std::path::Path, no_redact: bool) -> CapturePolicy {
    let overlay = CliOverlay {
        no_redact,
        ..Default::default()
    };
    let mut policy = CapturePolicy::resolve(root, out_dir, overlay);

    // Cumulative enable: raise universal + structured alongside complete so the
    // complete-tier proxy actually captures the prompts/results it exists to
    // record (see the doc comment above). Setting these here — not in
    // `logbook.toml` — is exactly what the plan calls "the CLI ack is the
    // sanctioned runtime path".
    policy.tiers.universal = true;
    policy.tiers.structured = true;
    policy.tiers.complete = true;
    policy
}

/// Print the `*_BASE_URL` to export, the proxy token (sent on the dedicated
/// `x-logbook-proxy-token` header — NOT `Authorization`, which carries the real
/// provider key), and how to point an agent at the proxy. Goes to **stdout** (the
/// `llm` lane is an HTTP server, not a stdio JSON-RPC relay, so stdout is free for
/// the human banner).
fn print_llm_instructions(
    proxy: &logbook_llmproxy::RunningProxy,
    provider: Provider,
    upstream: &str,
    no_redact: bool,
) {
    let addr = proxy.addr();
    let base = format!("http://{addr}");
    let env_var = match provider {
        Provider::Anthropic => "ANTHROPIC_BASE_URL",
        Provider::OpenAi => "OPENAI_BASE_URL",
    };
    println!("logbook proxy llm: Complete-tier {} proxy listening on {base}", provider.as_str());
    println!("  forwarding upstream -> {upstream}");
    println!();
    println!("Point your agent at it by exporting:");
    println!("  export {env_var}={base}");
    match proxy.token() {
        Some(token) => {
            // The proxy authenticates the agent → proxy hop on its OWN dedicated
            // header (`x-logbook-proxy-token`), carrying the raw token with NO
            // `Bearer` prefix. `Authorization` is deliberately left free to carry
            // the real provider key (see `logbook_llmproxy::server::PROXY_TOKEN_HEADER`
            // — a shared contract with this CLI).
            let provider_key_header = match provider {
                Provider::Anthropic => "x-api-key: <your Anthropic key>",
                Provider::OpenAi => "Authorization: Bearer <your OpenAI key>",
            };
            println!();
            println!("Proxy token (the proxy is loopback-only AND token-gated):");
            println!("  {token}");
            println!();
            println!("Send it on the proxy's dedicated request header (raw token, no `Bearer`):");
            println!("  {}: {token}", logbook_llmproxy::server::PROXY_TOKEN_HEADER);
            println!();
            println!(
                "Your agent's REAL provider key stays on its usual header and is forwarded\n\
                 upstream verbatim — the proxy never reads it for auth:\n  \
                 {provider_key_header}\n\
                 (the {env_var} env var above only points the agent at logbook; the proxy\n\
                 authenticates on {} and leaves the provider key untouched.)",
                logbook_llmproxy::server::PROXY_TOKEN_HEADER
            );
        }
        None => {
            println!();
            println!("(token disabled — dev/test only; every request is accepted.)");
        }
    }
    if no_redact {
        println!();
        println!(
            "WARNING --no-redact is set; the secrets floor still applies and prompts/results\n\
             are force-redacted regardless, but non-secret payload text may be persisted."
        );
    }
    println!();
    println!("Press Ctrl-C to stop.");
}

/// Block until a termination signal (Ctrl-C, or SIGTERM on Unix) arrives.
///
/// `RunningProxy`/`RunningHub` expose `shutdown()`/`join()` but do not install
/// their own signal handlers, so the CLI waits here and then calls `shutdown()`.
/// On non-Unix POSIX targets without `SIGTERM` wiring we fall back to Ctrl-C
/// only; the binary is POSIX-only regardless (see `main.rs`).
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // If SIGTERM can't be registered, degrade to Ctrl-C only rather than fail.
        let mut term = signal(SignalKind::terminate()).ok();
        match term.as_mut() {
            Some(term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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
                ProxyCommand::Llm(_) => panic!("expected proxy mcp"),
            },
        }
    }

    fn parse_llm(argv: &[&str]) -> LlmProxyArgs {
        let cli = TestCli::try_parse_from(argv).expect("parse");
        match cli.cmd {
            TestCmd::Proxy(p) => match p.command {
                ProxyCommand::Llm(l) => l,
                ProxyCommand::Mcp(_) => panic!("expected proxy llm"),
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

    // --- proxy llm (Phase 4) ---

    #[test]
    fn parses_proxy_llm_defaults() {
        let l = parse_llm(&["x", "proxy", "llm"]);
        assert_eq!(l.provider, ProviderArg::Anthropic);
        assert!(l.upstream.is_none());
        assert_eq!(l.out_dir, PathBuf::from(super::super::DEFAULT_OUT_DIR));
        assert_eq!(l.root, PathBuf::from("."));
        assert_eq!(l.port, 0);
        // The acknowledgement and the redaction/audit knobs all default off.
        assert!(!l.yes);
        assert!(!l.no_redact);
        assert!(!l.audit);
    }

    #[test]
    fn parses_proxy_llm_opts() {
        let l = parse_llm(&[
            "x", "proxy", "llm", "--provider", "openai", "--upstream",
            "https://gateway.example/v1", "--out-dir", "/tmp/o", "--root", "/repo", "--port",
            "9100", "--yes", "--no-redact", "--audit",
        ]);
        assert_eq!(l.provider, ProviderArg::Openai);
        assert_eq!(l.upstream.as_deref(), Some("https://gateway.example/v1"));
        assert_eq!(l.out_dir, PathBuf::from("/tmp/o"));
        assert_eq!(l.root, PathBuf::from("/repo"));
        assert_eq!(l.port, 9100);
        assert!(l.yes);
        assert!(l.no_redact);
        assert!(l.audit);
        assert_eq!(l.provider.as_provider(), Provider::OpenAi);
    }

    #[test]
    fn proxy_llm_rejects_unknown_provider() {
        // clap's ValueEnum rejects anything but anthropic/openai.
        let cli = TestCli::try_parse_from(["x", "proxy", "llm", "--provider", "gemini"]);
        assert!(cli.is_err(), "unknown --provider must be rejected at parse time");
    }

    /// The headline Phase-4 safety gate: `proxy llm` WITHOUT `--yes` must refuse.
    /// It declines cleanly (exit 2) **before** opening the store, building the
    /// upstream client, or binding a port — so the refusal path makes no network
    /// call and needs no real provider. Pointing at empty temp dirs proves no
    /// store work happens (a non-existent `<out_dir>/logbook.db` is never created).
    #[test]
    fn proxy_llm_without_yes_refuses() {
        let out = tempfile::tempdir().expect("out_dir");
        let root = tempfile::tempdir().expect("root");
        let args = LlmProxyArgs {
            provider: ProviderArg::Anthropic,
            upstream: None,
            out_dir: out.path().to_path_buf(),
            root: root.path().to_path_buf(),
            port: 0,
            yes: false,
            no_redact: false,
            audit: false,
        };
        let code = run_llm(args).expect("refusal is a clean decline, not an error");
        assert_eq!(code, 2, "missing --yes must decline with exit code 2");
        // Refusal happens before any store work: no db file was created.
        assert!(
            !out.path().join("logbook.db").exists(),
            "the refusal path must not open/create the store"
        );
    }

    #[test]
    fn provider_arg_maps_to_library_provider() {
        assert_eq!(ProviderArg::Anthropic.as_provider(), Provider::Anthropic);
        assert_eq!(ProviderArg::Openai.as_provider(), Provider::OpenAi);
    }

    /// The `--yes` runtime enable must raise the tiers CUMULATIVELY: with no
    /// `logbook.toml`, the resolved policy starts recorder-on (universal +
    /// structured already true) and the ack adds `complete`. All three end on, so
    /// the complete-tier proxy's prompt/result capture (gated on STRUCTURED) is
    /// actually open. `resolve_llm_policy` is the exact path `run_llm` takes after
    /// the `--yes` gate, minus the port bind — so this needs no network/store.
    #[test]
    fn proxy_llm_yes_enables_cumulative_tiers() {
        let out = tempfile::tempdir().expect("out_dir");
        let root = tempfile::tempdir().expect("root");
        let policy = resolve_llm_policy(root.path(), out.path(), false);
        assert!(policy.tiers.complete, "--yes must enable the complete tier");
        assert!(
            policy.tiers.structured,
            "structured must be on (prompts/results are gated on it, not on complete)"
        );
        assert!(policy.tiers.universal, "tiers are cumulative: universal must be on too");
    }

    /// The cumulativity fix's whole point: even when `logbook.toml [capture.tiers]`
    /// explicitly turns `structured` OFF (a VALID config — only `complete=true` is
    /// rejected by `validate()`), the `--yes` runtime ack must raise it back on, or
    /// the complete-tier proxy would record NO prompts/results. This guards the
    /// regression where enabling `complete` alone left `structured` off.
    #[test]
    fn proxy_llm_yes_overrides_structured_off_in_config() {
        let out = tempfile::tempdir().expect("out_dir");
        let root = tempfile::tempdir().expect("root");
        // Valid logbook.toml that disables the structured tier (complete stays off
        // in-config — enabling it there is what validate() rejects).
        std::fs::write(
            root.path().join("logbook.toml"),
            "[capture.tiers]\nstructured = false\n",
        )
        .expect("write logbook.toml");

        // Sanity: without the runtime ack, the config genuinely turns structured
        // off (so this proves the override below is doing real work).
        let base = CapturePolicy::resolve(root.path(), out.path(), CliOverlay::default());
        assert!(!base.tiers.structured, "config should turn structured off pre-ack");

        // The --yes path raises structured (and universal) back on alongside
        // complete, so prompt/result capture is open again.
        let policy = resolve_llm_policy(root.path(), out.path(), false);
        assert!(policy.tiers.structured, "the --yes ack must override structured=false");
        assert!(policy.tiers.complete, "--yes still enables complete");
        assert!(policy.tiers.universal, "cumulative: universal on too");
    }

    /// Prompt + result capture must actually be permitted under the post-`--yes`
    /// policy (the user-facing symptom the fix targets): `should_capture` returns
    /// true for the `Prompts` and `ToolResults` classes once the cumulative enable
    /// has run, even starting from a config that disabled the structured tier.
    #[test]
    fn proxy_llm_yes_permits_prompt_and_result_capture() {
        use logbook_core::SensitivityClass;
        let out = tempfile::tempdir().expect("out_dir");
        let root = tempfile::tempdir().expect("root");
        std::fs::write(
            root.path().join("logbook.toml"),
            "[capture.tiers]\nstructured = false\n",
        )
        .expect("write logbook.toml");

        let policy = resolve_llm_policy(root.path(), out.path(), false);
        assert!(
            policy.should_capture(SensitivityClass::Prompts),
            "complete-tier proxy must capture prompts after --yes"
        );
        assert!(
            policy.should_capture(SensitivityClass::ToolResults),
            "complete-tier proxy must capture results after --yes"
        );
    }
}
