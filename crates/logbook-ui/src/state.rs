//! Shared application state handed to every axum handler.

use logbook_store::Store;

use crate::bus::EventBus;

/// State shared across all UI request handlers, cloned per request by axum.
///
/// Both fields are cheap to clone (`Store` is `Arc`-backed; [`EventBus`] wraps
/// an `Arc<broadcast::Sender>`), so deriving `Clone` is the intended usage.
#[derive(Clone)]
pub struct AppState {
    /// Read access to the event + inventory store.
    pub store: Store,
    /// The live-tail broadcast bus the SSE endpoint subscribes to.
    pub bus: EventBus,
}

impl AppState {
    /// Build state from a store and a bus.
    #[must_use]
    pub fn new(store: Store, bus: EventBus) -> Self {
        Self { store, bus }
    }
}
