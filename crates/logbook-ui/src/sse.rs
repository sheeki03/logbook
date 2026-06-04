//! The live-tail SSE endpoint: `GET /api/stream` (plan §1).
//!
//! Each connected browser subscribes to the [`EventBus`](crate::bus::EventBus)
//! broadcast channel and receives every captured [`Event`] as a Server-Sent
//! Events `message` frame carrying the event's canonical JSON. A periodic
//! keep-alive comment holds the connection open through idle gaps and proxies.
//!
//! Lag handling: if a browser falls behind and the broadcast channel drops
//! frames for it, [`BroadcastStream`] yields a `Lagged` error. We log and skip
//! it rather than tearing down the stream — the next durable snapshot the client
//! fetches reconciles any gap (the store, not the live tail, is the source of
//! truth).

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::IntoResponse;
use futures::stream::Stream;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tokio_stream::StreamExt;

use crate::state::AppState;

/// `GET /api/stream` — subscribe to the live event tail over SSE.
pub async fn stream(State(state): State<AppState>) -> impl IntoResponse {
    let rx = state.bus.subscribe();
    let stream = event_stream(rx);
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// Adapt a broadcast receiver into a stream of SSE frames, serializing each
/// event to JSON and dropping lag/serialization errors instead of ending the
/// stream.
fn event_stream(
    rx: tokio::sync::broadcast::Receiver<logbook_core::Event>,
) -> impl Stream<Item = Result<SseEvent, Infallible>> {
    BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(event) => match serde_json::to_string(&event) {
            Ok(json) => Some(Ok(SseEvent::default().data(json))),
            Err(err) => {
                tracing::warn!(error = %err, "failed to serialize event for SSE");
                None
            }
        },
        Err(BroadcastStreamRecvError::Lagged(skipped)) => {
            tracing::warn!(skipped, "SSE client lagged; dropped buffered events");
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;

    use http_body_util::BodyExt;
    use logbook_core::{Category, Event, Kind, TraceId};

    fn sample(name: &str) -> Event {
        Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout").with_name(name)
    }

    /// Render an `event_stream` to its raw SSE wire text. The bus must already be
    /// dropped (sender closed) so the broadcast stream terminates and the body
    /// completes; no keep-alive is attached, so the body is purely data frames.
    async fn render_stream(
        rx: tokio::sync::broadcast::Receiver<Event>,
    ) -> String {
        let body = Sse::new(event_stream(rx)).into_response().into_body();
        let bytes = body.collect().await.expect("collect sse body").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("sse frames are utf8")
    }

    /// Extract the JSON object carried by each `data:` line of an SSE payload.
    fn data_payloads(wire: &str) -> Vec<serde_json::Value> {
        wire.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .map(|json| serde_json::from_str(json).expect("each data line is json"))
            .collect()
    }

    #[tokio::test]
    async fn stream_yields_serialized_event_data() {
        let bus = EventBus::new();
        let rx = bus.subscribe();
        bus.publish(sample("hello"));
        drop(bus); // close the sender so the stream terminates

        // Assert on the actual SSE `data` field parsed as JSON, not a Debug string.
        let payloads = data_payloads(&render_stream(rx).await);
        assert_eq!(payloads.len(), 1, "exactly one data frame");
        assert_eq!(
            payloads[0]["name"], "hello",
            "the data payload must be the event's canonical json"
        );
    }

    // Drives the documented lag contract (module docs lines 8-12): a receiver that
    // overflows the channel must see `Lagged` *skipped* (not torn down) and keep
    // receiving subsequent events.
    #[tokio::test]
    async fn stream_skips_lag_and_keeps_delivering() {
        // Small channel so we can deterministically overflow it before consuming.
        let bus = EventBus::with_capacity(2);
        let rx = bus.subscribe();

        // Overflow capacity (2) so the receiver is forced into a Lagged state...
        bus.publish(sample("drop-1"));
        bus.publish(sample("drop-2"));
        bus.publish(sample("drop-3"));
        // ...then publish a sentinel that must still be delivered after the lag.
        bus.publish(sample("survivor"));
        drop(bus);

        let wire = render_stream(rx).await;
        let payloads = data_payloads(&wire);

        // The stream did NOT end on Lagged: the post-lag sentinel was delivered.
        let names: Vec<&str> = payloads
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert!(
            names.contains(&"survivor"),
            "post-lag event must still be delivered (stream must not tear down on Lagged), got {names:?}"
        );
        // The dropped frames are skipped, not emitted as malformed frames; every
        // emitted frame parsed as valid event JSON above.
        assert!(
            !names.is_empty(),
            "at least the surviving event should be emitted"
        );
    }
}
