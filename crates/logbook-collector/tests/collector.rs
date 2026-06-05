//! Integration tests for the logbook collector (plan §4, §11, §15).
//!
//! Coverage:
//! - `/ingest` returns **401** without the bearer token and **204** with it;
//! - both `/ingest` payload shapes (`{events:[]}` and a bare array) persist;
//! - port **auto-increment** when the preferred port is busy;
//! - the parent-PID **watchdog** shuts the collector down when the launching
//!   process dies;
//! - `collector.token` is **0600** (token only) and `collector.json` carries
//!   **no secret**;
//! - `GET /health` is public and secret-free.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use logbook_collector::{
    collector, start, CollectorConfig, IngestToken, RunningCollector, TokenMode, COLLECTOR_JSON,
    COLLECTOR_TOKEN,
};
use logbook_store::{Query, Store};

const ORIGIN: &str = "http://localhost:5173";

fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Start a collector on an OS-chosen port with the watchdog disabled (tests own
/// the lifecycle). Returns the running handle + the store + the temp dir.
async fn start_test_collector() -> (RunningCollector, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(dir.path()).unwrap();
    let config = CollectorConfig::new(dir.path(), ORIGIN)
        .with_port(0)
        .with_token_mode(TokenMode::Generated)
        .with_parent_pid(None);
    let running = start(config, store.clone()).await.unwrap();
    (running, store, dir)
}

#[tokio::test]
async fn health_is_public_and_has_no_secret() {
    let (running, _store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/health", running.port());

    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], serde_json::json!(true));
    assert!(body.get("token").is_none(), "/health must not leak a token");
    assert!(body.get("secret").is_none());
    assert!(body["port"].as_u64().is_some());

    running.shutdown().await;
}

#[tokio::test]
async fn ingest_401_without_token_and_204_with_it() {
    let (running, store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/ingest", running.port());
    let token = running.token().unwrap().to_string();
    let client = reqwest::Client::new();

    // No Authorization header -> 401.
    let unauth = client
        .post(&url)
        .json(&serde_json::json!({"events": [{"message": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401, "missing token must be unauthorized");

    // Wrong token -> 401.
    let wrong = client
        .post(&url)
        .bearer_auth("not-the-token")
        .json(&serde_json::json!({"events": [{"message": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401, "wrong token must be unauthorized");

    // Nothing should have been persisted by the rejected requests.
    assert_eq!(store.count().unwrap(), 0, "unauthorized posts must not persist");

    // Correct token -> 204.
    let ok = client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({"events": [{"message": "console says hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 204, "valid token must be accepted");

    // The event was persisted into the browser lane.
    let events = store
        .query(&Query::new().category(logbook_core::Category::Browser))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].category, logbook_core::Category::Browser);

    running.shutdown().await;
}

#[tokio::test]
async fn ingest_accepts_both_payload_shapes() {
    let (running, store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/ingest", running.port());
    let token = running.token().unwrap().to_string();
    let client = reqwest::Client::new();

    // Shape 1: wrapped {events:[...]}.
    let wrapped = client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({"events": [{"message": "wrapped one"}, {"message": "wrapped two"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrapped.status(), 204);

    // Shape 2: bare array.
    let bare = client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!([{"message": "bare one"}]))
        .send()
        .await
        .unwrap();
    assert_eq!(bare.status(), 204);

    let events = store
        .query(&Query::new().category(logbook_core::Category::Browser).limit(100))
        .unwrap();
    assert_eq!(events.len(), 3, "both shapes should persist their events");

    running.shutdown().await;
}

#[tokio::test]
async fn ingest_redacts_secrets_before_persisting() {
    let (running, store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/ingest", running.port());
    let token = running.token().unwrap().to_string();

    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({"events": [{
            "level": "error",
            "message": "leak AKIAIOSFODNN7EXAMPLE here",
            "url": "https://user:hunter2pw@example.com/x"
        }]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let events = store
        .query(&Query::new().category(logbook_core::Category::Browser))
        .unwrap();
    assert_eq!(events.len(), 1);
    let console = events[0].blocks.console.as_ref().unwrap();
    let msg = console.message.as_ref().unwrap();
    assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into store: {msg}");
    let stored_url = console.url.as_ref().unwrap();
    assert!(!stored_url.contains("hunter2pw"), "url password leaked: {stored_url}");

    running.shutdown().await;
}

#[tokio::test]
async fn collector_token_is_0600_and_json_has_no_secret() {
    let (running, _store, dir) = start_test_collector().await;
    let token = running.token().unwrap().to_string();

    // collector.json exists, parses, and carries NO secret.
    let json_path = dir.path().join(COLLECTOR_JSON);
    let raw = std::fs::read_to_string(&json_path).unwrap();
    assert!(!raw.contains(&token), "collector.json must not contain the token");
    let record: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(record.get("token").is_none());
    assert!(record.get("secret").is_none());
    assert_eq!(record["pid"].as_u64().unwrap(), std::process::id() as u64);

    // collector.token exists, equals the token, and is 0600.
    let token_path = dir.path().join(COLLECTOR_TOKEN);
    let token_contents = std::fs::read_to_string(&token_path).unwrap();
    assert_eq!(token_contents, token, "collector.token holds the token only");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "collector.token must be 0600, got {:o}", mode & 0o777);
    }

    running.shutdown().await;

    // After shutdown the files are removed (pid matched).
    assert!(!json_path.exists(), "collector.json should be removed on shutdown");
    assert!(!token_path.exists(), "collector.token should be removed on shutdown");
}

#[tokio::test]
async fn port_auto_increments_when_preferred_is_busy() {
    // Bind one collector on an OS-chosen port, then ask a second to start on the
    // SAME port; it must auto-increment to a different, working port.
    let dir_a = tempfile::tempdir().unwrap();
    let store_a = Store::open_in_dir(dir_a.path()).unwrap();
    let cfg_a = CollectorConfig::new(dir_a.path(), ORIGIN)
        .with_port(0)
        .with_parent_pid(None);
    let a = start(cfg_a, store_a).await.unwrap();
    let shared_port = a.port();

    let dir_b = tempfile::tempdir().unwrap();
    let store_b = Store::open_in_dir(dir_b.path()).unwrap();
    let cfg_b = CollectorConfig::new(dir_b.path(), ORIGIN)
        .with_port(shared_port)
        .with_parent_pid(None);
    let b = start(cfg_b, store_b).await.unwrap();

    assert_ne!(b.port(), shared_port, "second collector must not reuse the busy port");
    assert!(b.port() > shared_port, "auto-increment should pick a higher port");

    // Both are independently reachable.
    let client = reqwest::Client::new();
    for port in [a.port(), b.port()] {
        let resp = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "collector on {port} should be healthy");
    }

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn bind_auto_increment_helper_skips_busy_port() {
    // Directly exercise the bind helper: hold a listener, then bind starting at
    // its port and confirm we land elsewhere.
    let first = collector::bind_with_auto_increment(loopback(), 0).await.unwrap();
    let busy_port = first.local_addr().unwrap().port();

    let second = collector::bind_with_auto_increment(loopback(), busy_port)
        .await
        .unwrap();
    let got = second.local_addr().unwrap().port();
    assert_ne!(got, busy_port);
    assert!(got > busy_port);
}

#[tokio::test]
async fn watchdog_shuts_collector_down_when_parent_dies() {
    // Spawn a real child process to act as the "launching parent", point the
    // collector's watchdog at it, then kill the child. The collector's server
    // task must complete (graceful shutdown) on its own.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(dir.path()).unwrap();

    // A child that simply sleeps until killed.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let child_pid = child.id() as i32;

    let config = CollectorConfig::new(dir.path(), ORIGIN)
        .with_port(0)
        .with_parent_pid(Some(child_pid));
    let running = start(config, store).await.unwrap();
    let port = running.port();

    // Confirm it's up.
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Kill the "parent". The watchdog (500ms poll) should trip shortly after.
    child.kill().expect("kill child");
    let _ = child.wait();

    // join() awaits the server task; it must finish without us calling shutdown.
    let joined = tokio::time::timeout(Duration::from_secs(10), running.join()).await;
    assert!(joined.is_ok(), "watchdog did not shut the collector down after parent death");

    // Port should be free again (collector released it). Best-effort: a fresh
    // bind on that exact port should now succeed.
    let rebind = collector::bind_with_auto_increment(loopback(), port).await;
    assert!(rebind.is_ok(), "port not released after watchdog shutdown");

    // Files cleaned up (pid matched).
    assert!(!dir.path().join(COLLECTOR_JSON).exists());
    assert!(!dir.path().join(COLLECTOR_TOKEN).exists());
}

#[tokio::test]
async fn generated_token_is_present_and_well_formed() {
    // In the default (generated) mode the handle exposes a 256-bit hex token
    // and the matching collector.token file is written.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(dir.path()).unwrap();
    let config = CollectorConfig::new(dir.path(), ORIGIN)
        .with_port(0)
        .with_parent_pid(None);
    let running = start(config, store).await.unwrap();
    let token = running.token().unwrap().to_string();
    assert_eq!(token.len(), 64, "generated token is 64 hex chars");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(
        std::fs::read_to_string(dir.path().join(COLLECTOR_TOKEN)).unwrap(),
        token
    );
    running.shutdown().await;
}

#[tokio::test]
async fn off_token_mode_allows_unauthenticated_ingest() {
    // token_mode=off is dev/test-only: no token file, and /ingest accepts posts
    // without an Authorization header.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(dir.path()).unwrap();
    let config = CollectorConfig::new(dir.path(), ORIGIN)
        .with_port(0)
        .with_token_mode(TokenMode::Off)
        .with_parent_pid(None);
    let running = start(config, store.clone()).await.unwrap();
    assert!(running.token().is_none(), "off mode has no token");
    // No collector.token file is written in off mode.
    assert!(!dir.path().join(COLLECTOR_TOKEN).exists());

    let url = format!("http://127.0.0.1:{}/ingest", running.port());
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!([{"message": "no auth needed in off mode"}]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "off mode accepts unauthenticated ingest");
    assert_eq!(store.count().unwrap(), 1);

    running.shutdown().await;
}

#[tokio::test]
async fn hooks_401_without_token_and_normalizes_a_sample_hook() {
    // `/v1/hooks` is bearer-gated exactly like `/ingest`, and a valid PostToolUse
    // hook normalizes into a redacted Kind::Tool event, persisted in the Agent
    // lane under the supplied trace.
    let (running, store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/v1/hooks", running.port());
    let token = running.token().unwrap().to_string();
    let client = reqwest::Client::new();

    // A planted secret in the tool result must NOT survive into the store.
    let hook = serde_json::json!({
        "trace": "aabbccddeeff00112233445566778899",
        "session": "sess-hook-1",
        "harness_version": "1.9.9",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "toolu_7",
        "tool_input": { "command": "deploy", "token": "AKIAIOSFODNN7EXAMPLE" },
        "tool_response": { "stdout": "deployed with AKIAIOSFODNN7EXAMPLE", "stderr": "" }
    });

    // Wrong bearer -> 401, nothing persisted.
    let bad = client
        .post(&url)
        .bearer_auth("not-the-token")
        .json(&hook)
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401, "bad bearer must be rejected");
    assert_eq!(store.count().unwrap(), 0, "rejected hook must not persist");

    // Correct bearer -> 204 + one redacted tool event.
    let ok = client.post(&url).bearer_auth(&token).json(&hook).send().await.unwrap();
    assert_eq!(ok.status(), 204, "valid hook accepted");

    let events = store
        .query(&Query::new().category(logbook_core::Category::Agent).limit(100))
        .unwrap();
    assert_eq!(events.len(), 1, "PostToolUse hook → one tool event");
    let ev = &events[0];
    assert_eq!(ev.kind, logbook_core::Kind::Tool);
    // Correlated to the supplied trace + session.
    assert_eq!(ev.trace_id.to_hex(), "aabbccddeeff00112233445566778899");
    assert_eq!(
        ev.session_id.as_ref().map(logbook_core::SessionId::as_str),
        Some("sess-hook-1")
    );
    let tb = ev.blocks.tool.as_ref().expect("tool block");
    assert_eq!(tb.tool_name.as_deref(), Some("Bash"));
    // Arguments + result redacted before persistence (plan §9).
    let args_s = serde_json::to_string(tb.arguments.as_ref().unwrap()).unwrap();
    assert!(!args_s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in args: {args_s}");
    assert!(args_s.contains("deploy"), "non-secret arg lost: {args_s}");
    if let Some(out) = ev.output.as_ref().and_then(|o| o.as_str()) {
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in result: {out}");
    }
    // harness_version stamped.
    assert_eq!(
        ev.attributes.get("harness_version").and_then(|v| v.as_str()),
        Some("1.9.9")
    );

    running.shutdown().await;
}

#[tokio::test]
async fn hooks_skip_unknown_records_with_no_persist() {
    // An unrecognized hook record normalizes to zero events → 204, nothing stored
    // (the adapter is tolerant).
    let (running, store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/v1/hooks", running.port());
    let token = running.token().unwrap().to_string();

    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "totally": "unknown", "shape": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(store.count().unwrap(), 0, "unknown record persists nothing");

    running.shutdown().await;
}

#[tokio::test]
async fn ingest_drops_when_browser_data_class_off() {
    // The new browser_data capture gate: with the class off, /ingest accepts the
    // request (204) but persists NOTHING. With it on (default), it persists.
    use logbook_core::CapturePolicy;

    // ---- class OFF: dropped ----
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(dir.path()).unwrap();
    let mut policy = CapturePolicy::default();
    policy.classes.browser_data.capture = false;
    let config = CollectorConfig::new(dir.path(), ORIGIN)
        .with_port(0)
        .with_parent_pid(None)
        .with_capture_policy(policy);
    let running = start(config, store.clone()).await.unwrap();
    let url = format!("http://127.0.0.1:{}/ingest", running.port());
    let token = running.token().unwrap().to_string();

    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({"events": [{"message": "should be dropped"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "request still accepted when class off");
    assert_eq!(store.count().unwrap(), 0, "browser_data off ⇒ nothing persisted");
    running.shutdown().await;

    // ---- class ON (default): persisted ----
    let (running2, store2, _dir2) = start_test_collector().await;
    let url2 = format!("http://127.0.0.1:{}/ingest", running2.port());
    let token2 = running2.token().unwrap().to_string();
    let resp2 = reqwest::Client::new()
        .post(&url2)
        .bearer_auth(&token2)
        .json(&serde_json::json!({"events": [{"message": "kept"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 204);
    assert_eq!(store2.count().unwrap(), 1, "default policy persists browser events");
    running2.shutdown().await;
}

#[tokio::test]
async fn hooks_drop_when_capture_paused() {
    // Regression: `/v1/hooks` must honor the capture policy. Today only `/ingest`
    // is class-gated, so a master-pause or structured-tier-off does NOT stop hook
    // ingest. With either off, a valid PostToolUse hook (which would otherwise
    // persist a redacted Kind::Tool event) must persist NOTHING — accepted (204)
    // but dropped — mirroring the `/ingest` browser_data gate.
    use logbook_core::CapturePolicy;

    // A well-formed hook that the adapter WOULD normalize into one tool event.
    let hook = serde_json::json!({
        "trace": "aabbccddeeff00112233445566778899",
        "session": "sess-hook-paused",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "toolu_9",
        "tool_input": { "command": "deploy" },
        "tool_response": { "stdout": "ok", "stderr": "" }
    });

    // ---- master switch OFF: dropped ----
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let policy = CapturePolicy {
            enabled: false, // master pause (UI toggle / capture-state overlay)
            ..Default::default()
        };
        let config = CollectorConfig::new(dir.path(), ORIGIN)
            .with_port(0)
            .with_parent_pid(None)
            .with_capture_policy(policy);
        let running = start(config, store.clone()).await.unwrap();
        let url = format!("http://127.0.0.1:{}/v1/hooks", running.port());
        let token = running.token().unwrap().to_string();

        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&token)
            .json(&hook)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204, "request still accepted when capture paused");
        assert_eq!(store.count().unwrap(), 0, "master off ⇒ no hook events persisted");
        running.shutdown().await;
    }

    // ---- structured tier OFF: dropped ----
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let mut policy = CapturePolicy::default();
        policy.tiers.structured = false; // structured-tier off (no prompts/tool_*/metadata)
        let config = CollectorConfig::new(dir.path(), ORIGIN)
            .with_port(0)
            .with_parent_pid(None)
            .with_capture_policy(policy);
        let running = start(config, store.clone()).await.unwrap();
        let url = format!("http://127.0.0.1:{}/v1/hooks", running.port());
        let token = running.token().unwrap().to_string();

        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&token)
            .json(&hook)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204, "request still accepted when structured tier off");
        assert_eq!(store.count().unwrap(), 0, "structured off ⇒ no hook events persisted");
        running.shutdown().await;
    }

    // ---- default policy (structured on): persisted ----
    {
        let (running, store, _dir) = start_test_collector().await;
        let url = format!("http://127.0.0.1:{}/v1/hooks", running.port());
        let token = running.token().unwrap().to_string();
        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&token)
            .json(&hook)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
        assert_eq!(store.count().unwrap(), 1, "default policy persists the hook event");
        running.shutdown().await;
    }
}

#[tokio::test]
async fn traces_drop_when_capture_paused() {
    // Regression: `/v1/traces` must honor the capture policy. OTLP spans persist
    // with name + attributes under the `tool_args` class; a master-pause or
    // structured-tier-off must stop them (accepted 204, persisted nothing),
    // mirroring the `/ingest` browser_data gate.
    use logbook_core::CapturePolicy;

    let otlp = serde_json::json!({
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [{
                    "traceId": "112233445566778899aabbccddeeff00",
                    "spanId": "1122334455667788",
                    "name": "llm.call",
                    "startTimeUnixNano": "1700000000000000000",
                    "status": { "code": 1 },
                    "attributes": [
                        { "key": "model", "value": { "stringValue": "claude-3-5-sonnet" } }
                    ]
                }]
            }]
        }]
    });

    // ---- master switch OFF: dropped ----
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let policy = CapturePolicy {
            enabled: false,
            ..Default::default()
        };
        let config = CollectorConfig::new(dir.path(), ORIGIN)
            .with_port(0)
            .with_parent_pid(None)
            .with_capture_policy(policy);
        let running = start(config, store.clone()).await.unwrap();
        let url = format!("http://127.0.0.1:{}/v1/traces", running.port());
        let token = running.token().unwrap().to_string();

        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&token)
            .json(&otlp)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204, "request still accepted when capture paused");
        assert_eq!(store.count().unwrap(), 0, "master off ⇒ no spans persisted");
        running.shutdown().await;
    }

    // ---- structured tier OFF: dropped ----
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_dir(dir.path()).unwrap();
        let mut policy = CapturePolicy::default();
        policy.tiers.structured = false;
        let config = CollectorConfig::new(dir.path(), ORIGIN)
            .with_port(0)
            .with_parent_pid(None)
            .with_capture_policy(policy);
        let running = start(config, store.clone()).await.unwrap();
        let url = format!("http://127.0.0.1:{}/v1/traces", running.port());
        let token = running.token().unwrap().to_string();

        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&token)
            .json(&otlp)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204, "request still accepted when structured tier off");
        assert_eq!(store.count().unwrap(), 0, "structured off ⇒ no spans persisted");
        running.shutdown().await;
    }

    // ---- default policy (structured on): persisted ----
    {
        let (running, store, _dir) = start_test_collector().await;
        let url = format!("http://127.0.0.1:{}/v1/traces", running.port());
        let token = running.token().unwrap().to_string();
        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&token)
            .json(&otlp)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
        assert_eq!(store.count().unwrap(), 1, "default policy persists the span");
        running.shutdown().await;
    }
}

#[tokio::test]
async fn traces_401_without_token_and_maps_otlp_span() {
    // `/v1/traces` is bearer-gated and maps a minimal OTLP-JSON span to a
    // Kind::Span event with redacted attributes.
    let (running, store, _dir) = start_test_collector().await;
    let url = format!("http://127.0.0.1:{}/v1/traces", running.port());
    let token = running.token().unwrap().to_string();
    let client = reqwest::Client::new();

    let otlp = serde_json::json!({
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [{
                    "traceId": "112233445566778899aabbccddeeff00",
                    "spanId": "1122334455667788",
                    "name": "llm.call",
                    "startTimeUnixNano": "1700000000000000000",
                    "status": { "code": 1 },
                    "attributes": [
                        { "key": "model", "value": { "stringValue": "claude-3-5-sonnet" } },
                        { "key": "api_key", "value": { "stringValue": "AKIAIOSFODNN7EXAMPLE" } },
                        { "key": "tokens", "value": { "intValue": 128 } }
                    ]
                }]
            }]
        }]
    });

    // Bad bearer -> 401.
    let bad = client.post(&url).bearer_auth("nope").json(&otlp).send().await.unwrap();
    assert_eq!(bad.status(), 401);
    assert_eq!(store.count().unwrap(), 0);

    // Good bearer -> 204 + one span event.
    let ok = client.post(&url).bearer_auth(&token).json(&otlp).send().await.unwrap();
    assert_eq!(ok.status(), 204);

    let events = store
        .query(&Query::new().trace("112233445566778899aabbccddeeff00").limit(10))
        .unwrap();
    assert_eq!(events.len(), 1, "one OTLP span → one event");
    let ev = &events[0];
    assert_eq!(ev.kind, logbook_core::Kind::Span);
    assert_eq!(ev.attributes.get("model").and_then(|v| v.as_str()), Some("claude-3-5-sonnet"));
    // The secret-looking attribute value is redacted before persistence.
    let key_attr = ev.attributes.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
    assert!(!key_attr.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked in OTLP attr: {key_attr}");
    assert_eq!(ev.attributes.get("tokens").and_then(|v| v.as_u64()), Some(128));

    running.shutdown().await;
}

#[tokio::test]
async fn cleanup_does_not_remove_files_owned_by_another_pid() {
    // Simulate a relaunched collector adopting the out-dir: write a record with
    // a different pid, then call cleanup with our pid — it must NOT delete it.
    let dir = tempfile::tempdir().unwrap();
    let foreign = collector::CollectorRecord {
        host: "127.0.0.1".into(),
        port: 9999,
        out_dir: dir.path().to_string_lossy().into_owned(),
        pid: std::process::id() + 1, // not us
        started_at: "0us".into(),
    };
    collector::write_collector_json(dir.path(), &foreign).unwrap();
    let token = IngestToken::from_secret("abc");
    collector::write_collector_token(dir.path(), &token).unwrap();

    collector::cleanup_files(dir.path(), std::process::id());

    assert!(
        dir.path().join(COLLECTOR_JSON).exists(),
        "must not delete a record owned by another pid"
    );
}
