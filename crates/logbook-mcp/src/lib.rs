//! `logbook-mcp` — the MCP tool surface (rmcp over stdio).
//!
//! This crate exposes the logbook observability store to coding agents via the
//! Model Context Protocol, using the official Rust SDK ([`rmcp`]) over stdio.
//!
//! # Read-only by default (plan §5, §9)
//! The surface is **read-only by default**. The READ tools — advertised
//! unconditionally — answer questions against [`logbook_store`]:
//!
//! - **Logs:** `list_log_files`, `tail_log`, `search_logs`, `get_errors`,
//!   `get_run_status`, `watch_log`.
//! - **Browser:** `browser_console`, `browser_network`, `browser_get_request`,
//!   `browser_dom`.
//! - **Timeline:** `query_timeline`, `get_trace`, `correlate`.
//! - **Findings:** `list_findings`, `get_finding`.
//! - **Debug:** `debug_fetch_evidence`.
//! - **Inventory:** `inventory_list_agents`, `inventory_list_mcp`,
//!   `inventory_list_sessions`, `inventory_report`, `inventory_findings`.
//!
//! The WRITE tools (browser navigate/record/replay/screenshot/start_session;
//! DAP set_logpoint/enable_trace/start/end_session; `security_scan`,
//! `scan_agent_diff`; `inventory_scan`, `inventory_watch`; `export_otel`) are
//! **hidden** — invisible to `tools/list` *and* rejected by `tools/call` —
//! unless their category is enabled in `logbook.toml`
//! (`[permissions].enabled_writes`, loaded from the workspace root). See
//! [`config`] for the schema and [`server`] for the enforcement.
//!
//! # Architecture
//! - [`config`] — the permission model + write-tool catalog (no `rmcp` types).
//! - [`params`] — tool parameter/output structs (`Deserialize` + `JsonSchema`).
//! - [`tools`] — the tool *logic* as plain `fn(&Store, params) -> Value`
//!   (no `rmcp` types, so it is unit-testable directly).
//! - [`server`] — the only module that touches `rmcp`: it adapts each
//!   `tools::*` function into an rmcp tool and applies the permission gate.
//!
//! # Quick start
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use logbook_mcp::server_from_root;
//! use logbook_store::Store;
//!
//! // Open the store in the project out-dir, load permissions from
//! // `<root>/logbook.toml`, and serve over stdio.
//! let store = Store::open_in_dir(".logbook")?;
//! let server = server_from_root(store, ".")?;
//! server.serve_stdio().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod params;
pub mod server;
pub mod tools;

pub use config::{
    all_write_tools, ConfigError, McpConfig, Permissions, WriteCategory, CONFIG_FILENAME,
};
pub use server::{server_from_root, LogbookServer, Server};
