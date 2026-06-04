//! `logbook-inventory` — Endpoint Inventory Lite (plan §7b).
//!
//! Answers, for the **local endpoint only**: which coding agents are installed
//! here? which MCP servers are configured? which `logbook agent <cmd>`
//! sessions ran? what files changed during them? what looks
//! unsanctioned / risky / untracked?
//!
//! Design constraints (plan §7b, §9, §13):
//! - **Local-only, read-only, observe-not-modify.** Discovery never executes a
//!   discovered agent as part of a plain scan and never alters any process,
//!   config, or MCP server. The one continuous surface (`inventory watch`) is
//!   opt-in via `[permissions].enabled_writes += "inventory_watch"`; `scan` and
//!   `report` are always allowed.
//! - **Redaction on by default.** Any secret found while scanning MCP configs,
//!   process command lines, or agent diffs is redacted via
//!   [`logbook_core::Redactor`] **before** it is surfaced or persisted.
//!
//! # Module map
//! - [`config`] — read the inventory-relevant parts of `logbook.toml`.
//! - [`endpoint`] — local machine identity.
//! - [`agents`] — discover agent CLIs on `PATH`.
//! - [`mcp`] — parse + redact MCP server configs from known locations.
//! - [`processes`] — best-effort running-agent process listing.
//! - [`tools`] — detect schrute / security-suite / scanner availability.
//! - [`wrapper`] — the `logbook agent <cli>` session + git/file-diff recorder.
//! - [`scan`] — orchestrate discovery, derive risk findings, persist + emit events.
//! - [`store_ext`] — SQL upserts/reads for the inventory tables.
//! - [`report`] — human + JSON rendering.
//! - [`cli`] — the `inventory` / `agent` clap command surface.
//!
//! # Quick tour
//! ```
//! use logbook_inventory::scan::{scan, ScanContext};
//! # let home = std::env::temp_dir();
//! # let project = std::env::temp_dir();
//! let ctx = ScanContext::discover(&home, &project);
//! let report = scan(&ctx);
//! // The report organizes into the five UI tabs: Endpoint, Agents, MCP
//! // Servers, Sessions/Processes, Risk/Shadow.
//! println!("{}", logbook_inventory::report::to_human(&report));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod agents;
pub mod cli;
pub mod config;
pub mod endpoint;
pub mod error;
pub mod mcp;
pub mod model;
pub mod processes;
pub mod report;
pub mod scan;
pub mod store_ext;
pub mod tools;
pub mod wrapper;

// Common surface re-exports.
pub use error::{InventoryError, Result};
pub use model::{
    finding_kind, AgentInstall, Endpoint, InventoryFinding, McpServer, McpTransport,
    RunningProcess, ToolPresence,
};
pub use scan::{scan, scan_and_persist, ScanContext, ScanReport};
pub use wrapper::{run_agent, AgentAction, LogbookOptions, LogbookOutcome, AgentSessionRecord};
