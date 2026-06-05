//! Integration tests for the logbook hub — the fleet receiver + governance plane
//! (plan "Phase 4 — Complete Tier & Fleet", "P4 tests").
//!
//! Coverage (the task's required scenarios):
//! - a posted batch is **received (idempotent)** + **audited** — `verify_chain`
//!   passes, and re-posting the same batch grows neither the rows nor the chain;
//! - tampering with a received row is **detected** by `GET /hub/verify`;
//! - a **Viewer** read returns the sanitized export projection while an
//!   **Auditor** sees the payload;
//! - the **roll-up** aggregates two endpoints;
//! - bearer auth: `/hub/ingest` is 401 without the token, persists nothing.

use std::net::{IpAddr, Ipv4Addr};

use logbook_core::{Category, Event, Kind, LlmBlock, MicrosTimestamp, TraceId};
use logbook_hub::{run_hub, HubConfig, RunningHub, TokenMode};
use logbook_store::Store;

const ORIGIN: &str = "http://localhost:5173";

#[allow(dead_code)]
fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Start a hub on an OS-chosen port with the periodic prune disabled (tests own
/// the lifecycle). Returns the running handle + the store + the temp dir.
async fn start_test_hub() -> (RunningHub, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(dir.path()).unwrap();
    let config = HubConfig::new(dir.path(), ORIGIN)
        .with_port(0)
        .with_token_mode(TokenMode::Generated)
        .with_prune_interval(None);
    let running = run_hub(config, store.clone()).await.unwrap();
    (running, store, dir)
}

/// A simple log event with a fixed id-bearing timestamp.
fn log_event(trace: TraceId, name: &str, ts: i64) -> Event {
    let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name(name);
    ev.timestamp = MicrosTimestamp(ts);
    ev
}

#[tokio::test]
async fn ingest_401_without_token_and_persists_nothing() {
    let (hub, store, _dir) = start_test_hub().await;
    let url = format!("http://127.0.0.1:{}/hub/ingest", hub.port());
    let trace = TraceId::new();
    let batch = serde_json::json!({
        "endpoint_id": "endpoint-a",
        "events": [log_event(trace, "one", 1)],
    });

    // No Authorization header -> 401.
    let unauth = reqwest::Client::new()
        .post(&url)
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401, "missing token must be unauthorized");
    assert_eq!(store.count().unwrap(), 0, "rejected post must not persist");

    hub.shutdown().await;
}

#[tokio::test]
async fn posted_batch_is_received_idempotently_and_audited() {
    let (hub, store, _dir) = start_test_hub().await;
    let ingest = format!("http://127.0.0.1:{}/hub/ingest", hub.port());
    let verify = format!("http://127.0.0.1:{}/hub/verify", hub.port());
    let token = hub.token().unwrap().to_string();
    let client = reqwest::Client::new();

    let trace = TraceId::new();
    let events = vec![
        log_event(trace, "r0", 1),
        log_event(trace, "r1", 2),
        log_event(trace, "r2", 3),
    ];
    let batch = serde_json::json!({ "endpoint_id": "endpoint-a", "events": events });

    // First POST: all three received and audited.
    let resp = client
        .post(&ingest)
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["received"], serde_json::json!(3), "all three newly inserted");
    assert_eq!(body["audited"], serde_json::json!(3), "all three appended to the chain");
    assert_eq!(store.count().unwrap(), 3);

    // The chain verifies clean.
    let v: serde_json::Value = client
        .get(&verify)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["ok"], serde_json::json!(true), "intact chain verifies: {v}");
    assert_eq!(v["checked"], serde_json::json!(3));

    // Re-POST the SAME batch: idempotent — nothing new received or audited.
    let resp2 = client
        .post(&ingest)
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap();
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(body2["received"], serde_json::json!(0), "duplicate ids inserted nothing");
    assert_eq!(body2["audited"], serde_json::json!(0), "duplicate ids not re-audited");
    assert_eq!(store.count().unwrap(), 3, "row count unchanged after re-receive");

    // Chain still clean and still length 3 (no double-audit).
    let v2: serde_json::Value = client
        .get(&verify)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v2["ok"], serde_json::json!(true));
    assert_eq!(v2["checked"], serde_json::json!(3), "chain not grown by re-receive");

    hub.shutdown().await;
}

#[tokio::test]
async fn verify_detects_a_tampered_row() {
    let (hub, store, _dir) = start_test_hub().await;
    let ingest = format!("http://127.0.0.1:{}/hub/ingest", hub.port());
    let verify = format!("http://127.0.0.1:{}/hub/verify", hub.port());
    let token = hub.token().unwrap().to_string();
    let client = reqwest::Client::new();

    let trace = TraceId::new();
    let events = vec![log_event(trace, "a", 1), log_event(trace, "b", 2)];
    let target_id = events[1].id.as_str().to_string();
    let batch = serde_json::json!({ "endpoint_id": "endpoint-a", "events": events });

    client
        .post(&ingest)
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap();

    // Clean before tampering.
    let v: serde_json::Value = client
        .get(&verify)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["ok"], serde_json::json!(true));

    // Tamper directly with a received event's stored body (bypassing the normal
    // write path), simulating an after-the-fact edit of an audited row.
    store
        .write({
            let id = target_id.clone();
            move |conn| {
                conn.execute(
                    "UPDATE events SET name = 'TAMPERED', body = replace(body, '\"b\"', '\"TAMPERED\"') WHERE id = ?1",
                    rusqlite::params![id],
                )?;
                Ok(())
            }
        })
        .unwrap();

    // Verify now reports a break at the tampered row.
    let v2: serde_json::Value = client
        .get(&verify)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v2["ok"], serde_json::json!(false), "tamper must break verification: {v2}");
    let brk = &v2["first_break"];
    assert_eq!(brk["event_id"], serde_json::json!(target_id), "break points at the tampered row");
    assert_eq!(brk["reason"]["kind"], serde_json::json!("row_hash_mismatch"));

    hub.shutdown().await;
}

#[tokio::test]
async fn viewer_sees_sanitized_projection_auditor_sees_payload() {
    let (hub, store, _dir) = start_test_hub().await;
    let ingest = format!("http://127.0.0.1:{}/hub/ingest", hub.port());
    let events_url = format!("http://127.0.0.1:{}/hub/events", hub.port());
    let token = hub.token().unwrap().to_string();
    let client = reqwest::Client::new();

    // An LLM event carrying a PROMPT payload (a `prompts`-class body) + model
    // metadata. The Viewer projection must drop the prompt; the Auditor keeps it.
    let trace = TraceId::new();
    let mut llm = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
        .with_op("chat.completion")
        .with_llm(LlmBlock {
            model: Some("claude-3-5-sonnet".into()),
            ..Default::default()
        });
    llm.timestamp = MicrosTimestamp(10);
    llm.input = Some(serde_json::json!("PLEASE-SUMMARIZE-THIS-SECRET-PROMPT"));

    let batch = serde_json::json!({ "endpoint_id": "endpoint-a", "events": [llm] });
    let resp = client
        .post(&ingest)
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(store.count().unwrap(), 1);

    let trace_hex = trace.to_hex();

    // ---- Auditor: full row, prompt visible ----
    let auditor: serde_json::Value = client
        .get(&events_url)
        .query(&[("trace", trace_hex.as_str())])
        .bearer_auth(&token)
        .header("X-Logbook-Role", "auditor")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(auditor["role"], serde_json::json!("auditor"));
    assert_eq!(auditor["count"], serde_json::json!(1));
    let auditor_dump = serde_json::to_string(&auditor).unwrap();
    assert!(
        auditor_dump.contains("PLEASE-SUMMARIZE-THIS-SECRET-PROMPT"),
        "auditor must see the prompt payload: {auditor_dump}"
    );

    // ---- Viewer (default + explicit): prompt dropped, metadata kept ----
    for role in [None, Some("viewer")] {
        let mut req = client.get(&events_url).query(&[("trace", trace_hex.as_str())]).bearer_auth(&token);
        if let Some(r) = role {
            req = req.header("X-Logbook-Role", r);
        }
        let viewer: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
        assert_eq!(viewer["role"], serde_json::json!("viewer"), "absent/viewer role ⇒ viewer");
        assert_eq!(viewer["count"], serde_json::json!(1));
        let viewer_dump = serde_json::to_string(&viewer).unwrap();
        assert!(
            !viewer_dump.contains("PLEASE-SUMMARIZE-THIS-SECRET-PROMPT"),
            "viewer must NOT see the prompt payload: {viewer_dump}"
        );
        // The model metadata (the one exporting class) survives for the viewer.
        assert!(
            viewer_dump.contains("claude-3-5-sonnet"),
            "viewer should still see model metadata: {viewer_dump}"
        );
    }

    hub.shutdown().await;
}

#[tokio::test]
async fn inventory_rollup_aggregates_two_endpoints() {
    use logbook_inventory::model::{AgentInstall, Endpoint, McpServer, McpTransport};
    use logbook_inventory::store_ext::{
        insert_agent_session, upsert_agent_installs, upsert_endpoint, upsert_mcp_servers,
    };
    use logbook_inventory::wrapper::AgentSessionRecord;

    let (hub, store, _dir) = start_test_hub().await;
    let inv_url = format!("http://127.0.0.1:{}/hub/inventory", hub.port());
    let token = hub.token().unwrap().to_string();

    let endpoint = |id: &str, host: &str| Endpoint {
        id: id.into(),
        hostname: host.into(),
        os: "linux".into(),
        arch: "x86_64".into(),
    };
    let agent = |id: &str, name: &str| AgentInstall {
        id: id.into(),
        name: name.into(),
        version: None,
        path: format!("/usr/bin/{name}"),
        sanctioned: true,
    };
    let mcp = |id: &str, name: &str| McpServer {
        id: id.into(),
        name: name.into(),
        source_config: "/tmp/.mcp.json".into(),
        command: Some("x".into()),
        transport: McpTransport::Stdio,
        sanctioned: true,
        has_secret: false,
    };
    let session = |id: &str, ep: &str| AgentSessionRecord {
        session_id: id.into(),
        endpoint_id: Some(ep.into()),
        agent: "claude".into(),
        command: "claude --help".into(),
        trace_id: TraceId::new().to_hex(),
        started_at: 1,
        ended_at: Some(2),
        exit_code: Some(0),
    };

    // Endpoint A: 2 agents, 1 MCP, 1 session. Endpoint B: 1 agent, 2 MCP, 2 sessions.
    upsert_endpoint(&store, &endpoint("endpoint-a", "alpha")).unwrap();
    upsert_agent_installs(&store, "endpoint-a", &[agent("a-c", "claude"), agent("a-x", "codex")]).unwrap();
    upsert_mcp_servers(&store, "endpoint-a", &[mcp("a-fs", "filesystem")]).unwrap();
    insert_agent_session(&store, &session("sess-a1", "endpoint-a")).unwrap();

    upsert_endpoint(&store, &endpoint("endpoint-b", "bravo")).unwrap();
    upsert_agent_installs(&store, "endpoint-b", &[agent("b-a", "aider")]).unwrap();
    upsert_mcp_servers(&store, "endpoint-b", &[mcp("b-fs", "filesystem"), mcp("b-gh", "github")]).unwrap();
    insert_agent_session(&store, &session("sess-b1", "endpoint-b")).unwrap();
    insert_agent_session(&store, &session("sess-b2", "endpoint-b")).unwrap();

    let roll: serde_json::Value = reqwest::Client::new()
        .get(&inv_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(roll["endpoints"], serde_json::json!(2), "two distinct endpoints");
    assert_eq!(roll["total_agents"], serde_json::json!(3), "2 + 1 agents");
    assert_eq!(roll["total_mcp_servers"], serde_json::json!(3), "1 + 2 MCP servers");
    assert_eq!(roll["total_sessions"], serde_json::json!(3), "1 + 2 sessions");
    let per = roll["per_endpoint"].as_array().unwrap();
    assert_eq!(per.len(), 2);
    // Ordered by endpoint id: A then B.
    assert_eq!(per[0]["endpoint_id"], serde_json::json!("endpoint-a"));
    assert_eq!(per[0]["agents"], serde_json::json!(2));
    assert_eq!(per[1]["endpoint_id"], serde_json::json!("endpoint-b"));
    assert_eq!(per[1]["mcp_servers"], serde_json::json!(2));

    hub.shutdown().await;
}

#[tokio::test]
async fn prune_route_runs_a_sweep() {
    // The endpoint-triggered retention sweep responds with stats (an empty store
    // prunes nothing, but the route must work and return the shape).
    let (hub, _store, _dir) = start_test_hub().await;
    let prune = format!("http://127.0.0.1:{}/hub/prune", hub.port());
    let token = hub.token().unwrap().to_string();

    let resp = reqwest::Client::new()
        .post(&prune)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(body["events_by_age"], serde_json::json!(0));

    hub.shutdown().await;
}
