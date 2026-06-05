//! Per-subcommand handlers for the `logbook` CLI.
//!
//! Each module owns one subcommand's argument struct (where it isn't already
//! provided by the owning crate, as inventory is) and the glue that turns those
//! arguments into a call into the relevant crate. Keeping the wiring here, not
//! in `main.rs`, keeps the top-level dispatch readable.

use std::path::Path;

use logbook_core::{CapturePolicy, CliOverlay, LogbookConfig, MicrosTimestamp};
use logbook_store::Store;

pub mod debug;
pub mod detect;
pub mod export;
pub mod forget;
pub mod guard;
pub mod hooks;
pub mod inventory;
pub mod mcp;
pub mod proxy;
pub mod revert;
pub mod run;
pub mod security;
pub mod session;
pub mod ui;

/// The default out-dir, shared by every subcommand (plan §1: `.logbook`).
pub const DEFAULT_OUT_DIR: &str = ".logbook";

/// Enforce retention against the event store on a long-lived producer's startup
/// (plan §3 / Phase 3: `Store::prune` "run at `ui`/`agent` startup"). Both the
/// `ui` and `agent` handlers call this so retention is actually enforced — until
/// now `Store::prune` existed but nothing invoked it.
///
/// The policy is resolved through the **same** shared fail-closed helper every
/// producer uses ([`CapturePolicy::resolve`]: recorder-on defaults → strict
/// `<root>/logbook.toml [capture]` → `<out_dir>/capture-state.json` narrow-only),
/// and the retention caps come from the loaded [`LogbookConfig::retention`]
/// (`[retention] max_age_days`/`max_db_mb`, default 14 days / 512 MB) so the
/// per-class age sweep honours each class's `max_age_days`.
///
/// **Best-effort:** retention is a maintenance sweep, never the point of the
/// command, so a failure is logged via `tracing::warn!` and we continue — a prune
/// error must not stop `ui` from serving or `agent` from recording.
pub(crate) fn prune_retention(store: &Store, root: &Path, out_dir: &Path) {
    // The UI/agent startup sweep carries no CLI redaction knobs; the default
    // overlay leaves the layered (config + defaults) policy untouched.
    let policy = CapturePolicy::resolve(root, out_dir, CliOverlay::default());
    let retention = LogbookConfig::load_from_root(root)
        .map(|c| c.retention)
        .unwrap_or_default();
    let now = MicrosTimestamp::now().as_micros();
    match store.prune(&policy, &retention, now) {
        Ok(stats) => {
            if stats.total() > 0 {
                tracing::info!(
                    by_age = stats.events_by_age,
                    by_size = stats.events_by_size,
                    "retention prune removed {} event(s)",
                    stats.total()
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "retention prune failed on startup; continuing");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{Category, Event, Kind, MicrosTimestamp, TraceId};

    const MICROS_PER_DAY: i64 = 86_400 * 1_000_000;

    fn log_event(trace: TraceId, ts: i64) -> Event {
        let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("line");
        ev.timestamp = MicrosTimestamp(ts);
        ev
    }

    /// The shared startup sweep that both the `ui` and `agent` handlers call must
    /// actually invoke `Store::prune`, threading the `[retention]` caps loaded
    /// from `<root>/logbook.toml`. Regression for "retention prune is never
    /// invoked": before the fix nothing called `prune`, so an over-age row would
    /// linger forever. Here a tight `max_age_days = 1` config must drop a 5-day-old
    /// row while keeping a fresh one.
    #[test]
    fn prune_retention_enforces_config_age_cap() {
        let root = tempfile::tempdir().expect("root");
        let out = tempfile::tempdir().expect("out_dir");
        std::fs::write(
            root.path().join("logbook.toml"),
            "[retention]\nmax_age_days = 1\nmax_db_mb = 4096\n",
        )
        .expect("write config");

        let store = Store::open_in_dir(out.path()).expect("open store");
        // Use a NON-`now()` clock baseline so the test is deterministic: a big
        // "now" keeps the cut-offs positive, and prune is called against that same
        // clock would require injecting it — instead we seed rows relative to the
        // real wall clock the helper reads, well outside the 1-day window.
        let now = MicrosTimestamp::now().as_micros();
        store.insert(&log_event(TraceId::new(), now - 5 * MICROS_PER_DAY)).expect("old");
        store.insert(&log_event(TraceId::new(), now - MICROS_PER_DAY / 4)).expect("fresh");
        assert_eq!(store.count().expect("count"), 2);

        prune_retention(&store, root.path(), out.path());

        // The 5-day-old row is gone (older than the 1-day cap); the fresh one
        // survives — proving the helper both ran prune and used the config cap.
        assert_eq!(
            store.count().expect("count"),
            1,
            "prune_retention must drop the over-age row using the config's max_age_days"
        );
    }

    /// With the default 14-day retention (no `logbook.toml`), a recent row is
    /// retained — the sweep runs but deletes nothing, confirming the helper is a
    /// no-op when nothing is over-age (and that a missing config falls back to the
    /// default caps, not capture-OFF for retention purposes).
    #[test]
    fn prune_retention_keeps_recent_rows_under_default_caps() {
        let root = tempfile::tempdir().expect("root"); // no logbook.toml
        let out = tempfile::tempdir().expect("out_dir");
        let store = Store::open_in_dir(out.path()).expect("open store");

        let now = MicrosTimestamp::now().as_micros();
        store.insert(&log_event(TraceId::new(), now - MICROS_PER_DAY)).expect("recent");

        prune_retention(&store, root.path(), out.path());

        assert_eq!(
            store.count().expect("count"),
            1,
            "a 1-day-old row must survive the default 14-day retention"
        );
    }
}
