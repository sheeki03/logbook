//! End-to-end DAP logpoint ingestion (plan §6, Tier 2 alpha):
//! connect to a (mock) running-process debug adapter, set a logpoint, and
//! assert the emitted values are ingested as logbook events — into both a
//! channel sink and the store-backed sink used by a real session.

#[path = "support/mock_adapter.rs"]
mod mock_adapter;

use std::sync::Arc;
use std::time::Duration;

use logbook_core::{Kind, Redactor, SessionId, TraceId};
use logbook_debug::dap::{ChannelSink, DapClient};
use logbook_debug::{DebugMode, DebugSession, EvidenceFilter, Logpoint};
use logbook_store::{Query, Store};

#[tokio::test]
async fn logpoint_output_is_ingested_via_channel_sink() {
    let addr = mock_adapter::spawn().await;
    let trace = TraceId::new();
    let session = SessionId::new("ingest-test");

    let (sink, mut rx) = ChannelSink::new();
    let client = DapClient::connect_tcp(
        addr,
        trace,
        session.clone(),
        Arc::new(sink),
        Arc::new(Redactor::new()),
    )
    .await
    .expect("connect");

    client.initialize("t").await.expect("initialize");
    client
        .set_logpoints(&[Logpoint::expr("/virtual/main", 7, "x", "x")])
        .await
        .expect("set logpoint");

    // The mock emits two `output` events on logpoint install.
    let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("first event in time")
        .expect("event present");
    let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("second event in time")
        .expect("event present");

    for ev in [&first, &second] {
        assert_eq!(ev.kind, Kind::Log);
        assert_eq!(ev.type_, "dap.logpoint.output");
        assert_eq!(ev.session_id.as_ref().unwrap(), &session);
        assert_eq!(ev.trace_id, trace);
    }
    let msg1 = first.blocks.console.as_ref().unwrap().message.as_deref().unwrap();
    let msg2 = second.blocks.console.as_ref().unwrap().message.as_deref().unwrap();
    assert_eq!(msg1, "x=41");
    assert_eq!(msg2, "x=42");

    client.disconnect().await;
}

#[tokio::test]
async fn logpoint_output_lands_in_store_through_session_sink() {
    let store = Store::open_in_memory().unwrap();
    let addr = mock_adapter::spawn().await;

    let mut session = DebugSession::start_session(&store, DebugMode::Dap, None).unwrap();
    let trace = session.trace_id();

    let client = DapClient::connect_tcp(
        addr,
        trace,
        session.id().clone(),
        session.store_sink(),
        session.redactor(),
    )
    .await
    .expect("connect");
    let client = session.attach_dap(client).unwrap();

    client.initialize("t").await.expect("initialize");
    client
        .set_logpoints(&[Logpoint::expr("/virtual/main", 7, "x", "x")])
        .await
        .expect("set logpoint");

    // Wait until both ingested events are durable in the store.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let n = store
            .query(&Query::new().trace(trace.to_hex()).limit(100))
            .unwrap()
            .len();
        if n >= 2 || std::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    session.end_session().await.expect("end");

    // Fetch evidence the way an agent would: Tier-1 passive query over the
    // session's trace. The DAP-ingested logpoint output shows up as console
    // (the mapped category) and/or log evidence.
    let evidence =
        logbook_debug::collect_evidence(&store, &EvidenceFilter::new().trace(trace.to_hex()))
            .unwrap();
    assert!(
        evidence.total() >= 2,
        "expected >=2 ingested events, got {} ({:?})",
        evidence.total(),
        evidence
    );
    // The logpoint outputs were classified as app-log console events.
    let logpoint_events: usize = evidence
        .logs
        .iter()
        .chain(evidence.console.iter())
        .filter(|e| e.type_ == "dap.logpoint.output")
        .count();
    assert_eq!(logpoint_events, 2, "both logpoint hits should be ingested");
}

#[tokio::test]
async fn passive_tier_queries_prior_captured_signals_by_window_and_session() {
    // Tier-1 is the default and works with NO adapter at all: it just reads
    // back already-captured signals scoped to a time window + session.
    let store = Store::open_in_memory().unwrap();
    let mut session = DebugSession::start_session(&store, DebugMode::Passive, None).unwrap();
    let sid = session.id().clone();
    let trace = session.trace_id();

    // Mark the repro point, then "capture" some app logs after it.
    session.request_repro(Some("reproduced bug")).unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;

    use logbook_core::{Category, Event};
    store
        .insert(
            &Event::new(trace, Kind::Log, Category::AppLog, "stdout")
                .with_name("GET /widgets 500")
                .with_session(sid.clone()),
        )
        .unwrap();
    store
        .insert(
            &Event::new(trace, Kind::Network, Category::Browser, "fetch")
                .with_name("xhr /widgets")
                .with_session(sid.clone())
                .with_network(logbook_core::NetworkBlock {
                    method: Some("GET".into()),
                    url: Some("https://app.test/widgets".into()),
                    status_code: Some(500),
                    ..Default::default()
                }),
        )
        .unwrap();

    // Default fetch scopes to "this session, since repro". The window includes
    // the repro marker (a control event on the timeline) plus the two captured
    // signals.
    let ev = session.fetch_evidence(None).unwrap();
    assert!(
        ev.logs.iter().any(|e| e.name == "GET /widgets 500"),
        "the app log captured after repro should be present: {:?}",
        ev.logs
    );
    assert_eq!(ev.network.len(), 1, "the browser network event after repro");
    assert_eq!(
        ev.network[0].blocks.network.as_ref().unwrap().status_code,
        Some(500)
    );
    // The repro marker is in-window too, so we see at least 3 events total.
    assert!(ev.total() >= 3, "expected >=3 events, got {}", ev.total());
    assert!(
        ev.logs.iter().any(|e| e.type_ == "debug.repro_requested"),
        "repro marker should be in the window"
    );
    assert_eq!(
        session.record().status,
        logbook_debug::DebugStatus::Fetched
    );
}
