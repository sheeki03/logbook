//! The live-tail event bus.
//!
//! The UI server streams freshly captured [`Event`]s to connected browsers over
//! SSE (plan §1, §2: "live tail via a tokio broadcast channel"). Producers — the
//! collector, capture pipeline, inventory scanner, etc. — clone a [`Store`] and
//! publish into a shared [`EventBus`]; every connected SSE client holds a
//! [`broadcast::Receiver`] and forwards what it sees.
//!
//! A broadcast channel is the right primitive here: it is multi-producer,
//! multi-consumer, and lossy-by-design — a slow browser tab that falls behind
//! drops the oldest buffered frames (surfaced as
//! [`broadcast::error::RecvError::Lagged`]) instead of applying backpressure to
//! the capture hot path. The initial page load is served from the durable store
//! via the JSON APIs, so a dropped live frame is only ever a transient gap that
//! the next snapshot/refresh reconciles.

use std::sync::Arc;

use tokio::sync::broadcast;

use logbook_core::Event;

/// Default broadcast buffer depth. Large enough to absorb a burst of capture
/// events between SSE poll wakeups, small enough to bound memory.
pub const DEFAULT_CAPACITY: usize = 1024;

/// A cheaply-cloneable handle to the live event broadcast channel.
///
/// Clone freely: every clone shares the same underlying channel. Drop all
/// senders and subscribers shut down naturally.
#[derive(Clone)]
pub struct EventBus {
    tx: Arc<broadcast::Sender<Event>>,
}

impl EventBus {
    /// Create a bus with the [`DEFAULT_CAPACITY`] buffer depth.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a bus with an explicit buffer depth.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx: Arc::new(tx) }
    }

    /// Publish an event to all current subscribers.
    ///
    /// Returns the number of receivers the event was delivered to. `0` is not an
    /// error — it just means no browser is currently tailing — so the result is
    /// safe to ignore on the capture hot path.
    pub fn publish(&self, event: Event) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

    /// Subscribe to the live tail. Each subscriber receives every event
    /// published after it subscribed (subject to the lossy lag semantics
    /// described on the type).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Number of currently-attached subscribers (connected SSE clients).
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{Category, Kind, TraceId};

    fn sample() -> Event {
        Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout")
    }

    #[tokio::test]
    async fn subscriber_receives_published_event() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let ev = sample();
        assert_eq!(bus.publish(ev.clone()), 1);
        let got = rx.recv().await.expect("recv");
        assert_eq!(got.id, ev.id);
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_not_an_error() {
        let bus = EventBus::new();
        assert_eq!(bus.publish(sample()), 0);
    }

    #[tokio::test]
    async fn clones_share_one_channel() {
        let bus = EventBus::new();
        let bus2 = bus.clone();
        let mut rx = bus.subscribe();
        assert_eq!(bus2.subscriber_count(), 1);
        bus2.publish(sample());
        assert!(rx.recv().await.is_ok());
    }

    // Exercises the lossy-broadcast contract documented on the type (a slow
    // receiver drops the oldest frames as `Lagged` rather than killing the
    // channel) and, crucially, that the receiver *recovers* and keeps receiving.
    #[tokio::test]
    async fn lagged_receiver_recovers_and_keeps_receiving() {
        use tokio::sync::broadcast::error::RecvError;

        // Capacity 2, then overflow it before consuming.
        let bus = EventBus::with_capacity(2);
        let mut rx = bus.subscribe();
        bus.publish(sample());
        bus.publish(sample());
        bus.publish(sample()); // overflows: oldest is now unrecoverable

        // The first recv reports how many were skipped, but does NOT close the
        // channel.
        match rx.recv().await {
            Err(RecvError::Lagged(skipped)) => assert!(skipped >= 1, "should report drops"),
            other => panic!("expected Lagged after overflow, got {other:?}"),
        }

        // Recovery: the still-buffered frames remain receivable, and a freshly
        // published event is delivered too — the receiver is not dead.
        assert!(rx.recv().await.is_ok(), "buffered frame still receivable after lag");
        let fresh = sample();
        bus.publish(fresh.clone());
        // Drain until we observe the fresh event (one more buffered frame may precede it).
        loop {
            match rx.recv().await {
                Ok(ev) if ev.id == fresh.id => break,
                Ok(_) => continue,
                other => panic!("receiver should keep delivering after lag, got {other:?}"),
            }
        }
    }
}
