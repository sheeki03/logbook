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
use logbook_ui::{serve, EventBus, UiConfig, DEFAULT_PORT};

/// `logbook ui [opts]`.
#[derive(Debug, Args)]
pub struct UiArgs {
    /// Out-dir holding the logbook store to visualize.
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Preferred port; auto-increments on conflict.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        serve(&cfg, store, bus).await?;
        anyhow::Ok(())
    })?;
    Ok(0)
}
