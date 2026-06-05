//! `logbook ui` — serve the embedded web UI over loopback (plan §1, §7b),
//! wired to `logbook-ui`.
//!
//! A loopback-only axum server (port auto-increment, optional parent-PID
//! watchdog) that renders the Timeline plus the five Endpoint Inventory tabs
//! over read-only JSON APIs and an SSE live tail. It reads the same store the
//! capture pipeline / collector write to.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use clap::Args;

use logbook_store::Store;
use logbook_ui::{serve_with_state, AppState, EventBus, UiConfig, DEFAULT_PORT};

/// `logbook ui [opts]`.
#[derive(Debug, Args)]
pub struct UiArgs {
    /// Out-dir holding the logbook store to visualize.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (the durable `[capture]` write
    /// target, gated behind `--allow-config-write`). Defaults to the current
    /// directory, matching how capturing producers (`logbook run`/`agent`)
    /// resolve their config root, so the UI writes `logbook.toml` to the same
    /// place producers read it from.
    #[arg(long, alias = "project")]
    pub root: Option<PathBuf>,

    /// Preferred port; auto-increments on conflict.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// Allow the Capture panel to persist the durable default into
    /// `<root>/logbook.toml [capture]` (plan §1.4). Off by default — without it
    /// the toggle still works but writes only the cross-process, narrow-only
    /// `<out_dir>/capture-state.json` runtime override, never the config file.
    #[arg(long, default_value_t = false)]
    pub allow_config_write: bool,
}

/// Open the store and serve the UI until Ctrl-C / SIGTERM.
///
/// # Errors
/// Returns an error if the store cannot be opened or no port in the
/// auto-increment range is free.
pub fn run(args: UiArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;
    let bus = EventBus::new();
    let cfg = UiConfig {
        host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: args.port,
        parent_pid: None,
    };

    // The capture root (where `logbook.toml` lives) defaults to the current
    // directory — the same root capturing producers (`logbook run`/`agent`)
    // resolve via `std::env::current_dir()` — so the UI and producers agree on
    // which `logbook.toml` to read/write.
    let capture_root = args
        .root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Enforce retention on startup (plan §3 / Phase 3: "run at `ui`/`agent`
    // startup"). Best-effort: a prune failure must never stop the UI from
    // serving, so it is logged and we continue.
    super::prune_retention(&store, &capture_root, &args.out_dir);

    // Wire the Capture panel's write surface (plan §1.4): the runtime override
    // lands in `<out_dir>/capture-state.json` (narrow-only, cross-process), and
    // the durable `logbook.toml [capture]` write is gated behind
    // `--allow-config-write`.
    let state = AppState::new(store, bus).with_capture(
        args.out_dir.clone(),
        capture_root,
        args.allow_config_write,
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        serve_with_state(&cfg, state).await?;
        anyhow::Ok(())
    })?;
    Ok(0)
}
