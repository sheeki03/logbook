//! `logbook mcp` — serve the MCP tool surface over stdio (plan §5),
//! wired to `logbook-mcp`.
//!
//! Read-only by default: write tools stay hidden unless enabled in
//! `logbook.toml` (`[permissions].enabled_writes` + matching `allow_*`). The
//! permission file is loaded relative to `--root` (the workspace root),
//! matching [`logbook_mcp::server_from_root`].

use std::path::PathBuf;

use clap::Args;

use logbook_mcp::server_from_root;
use logbook_store::Store;

/// `logbook mcp [opts]`.
#[derive(Debug, Args)]
pub struct McpArgs {
    /// Out-dir holding the logbook store (`<out_dir>/logbook.db`).
    #[arg(long, default_value = super::DEFAULT_OUT_DIR)]
    pub out_dir: PathBuf,

    /// Workspace root that holds `logbook.toml` (for the permission model).
    /// Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
}

/// Open the store, load permissions from `<root>/logbook.toml`, and serve the
/// MCP surface over stdio until the peer disconnects.
///
/// # Errors
/// Returns an error if the store cannot be opened, `logbook.toml` exists but
/// cannot be parsed, or the stdio transport fails.
pub fn run(args: McpArgs) -> anyhow::Result<i32> {
    let store = Store::open_in_dir(&args.out_dir)?;
    let server = server_from_root(store, &args.root)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        server.serve_stdio().await?;
        anyhow::Ok(())
    })?;
    Ok(0)
}
