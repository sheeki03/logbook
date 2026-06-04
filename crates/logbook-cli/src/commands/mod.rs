//! Per-subcommand handlers for the `logbook` CLI.
//!
//! Each module owns one subcommand's argument struct (where it isn't already
//! provided by the owning crate, as inventory is) and the glue that turns those
//! arguments into a call into the relevant crate. Keeping the wiring here, not
//! in `main.rs`, keeps the top-level dispatch readable.

pub mod debug;
pub mod export;
pub mod inventory;
pub mod mcp;
pub mod run;
pub mod security;
pub mod ui;

/// The default out-dir, shared by every subcommand (plan §1: `.logbook`).
pub const DEFAULT_OUT_DIR: &str = ".logbook";
