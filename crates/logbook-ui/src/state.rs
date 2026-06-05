//! Shared application state handed to every axum handler.

use std::path::PathBuf;

use logbook_store::Store;

use crate::bus::EventBus;

/// State shared across all UI request handlers, cloned per request by axum.
///
/// The store/bus are cheap to clone (`Store` is `Arc`-backed; [`EventBus`] wraps
/// an `Arc<broadcast::Sender>`), and the capture-toggle fields are small owned
/// values, so deriving `Clone` is the intended usage.
#[derive(Clone)]
pub struct AppState {
    /// Read access to the event + inventory store.
    pub store: Store,
    /// The live-tail broadcast bus the SSE endpoint subscribes to.
    pub bus: EventBus,
    /// Out-dir holding the store + the `<out_dir>/capture-state.json` runtime
    /// overlay the capture toggle writes (plan §1.4).
    pub out_dir: PathBuf,
    /// Root holding `logbook.toml` (the durable `[capture]` write target). Set
    /// alongside `out_dir`; defaults to the out-dir's parent.
    pub capture_root: PathBuf,
    /// Whether `logbook ui --allow-config-write` was passed — gates the durable
    /// `logbook.toml` write target (off by default).
    pub allow_config_write: bool,
    /// Per-process CSRF token the capture-toggle `POST` must echo. Minted once at
    /// state construction from OS entropy.
    pub csrf_token: String,
}

impl AppState {
    /// Build state from a store and a bus, with the capture-toggle write surface
    /// defaulted (out-dir `.logbook`, config writes disabled, a fresh CSRF
    /// token). Use [`Self::with_capture`] to point the toggle at a real out-dir.
    #[must_use]
    pub fn new(store: Store, bus: EventBus) -> Self {
        let out_dir = PathBuf::from(".logbook");
        let capture_root = crate::capture::default_capture_root(&out_dir);
        Self {
            store,
            bus,
            out_dir,
            capture_root,
            allow_config_write: false,
            csrf_token: crate::capture::new_csrf_token(),
        }
    }

    /// Configure the capture-toggle write surface: the `out_dir` (where
    /// `capture-state.json` is written), the `capture_root` (where `logbook.toml`
    /// lives), and whether durable config writes are allowed.
    #[must_use]
    pub fn with_capture(
        mut self,
        out_dir: impl Into<PathBuf>,
        capture_root: impl Into<PathBuf>,
        allow_config_write: bool,
    ) -> Self {
        self.out_dir = out_dir.into();
        self.capture_root = capture_root.into();
        self.allow_config_write = allow_config_write;
        self
    }
}
