//! `logbook-ui` — the embedded web UI server (plan §1, §7b).
//!
//! A small [`axum`] server, separate from the collector, that:
//!
//! - serves the built React/Vite bundle embedded from `ui/dist` via
//!   [`rust_embed`], with a single-page-app fallback ([`embed`]);
//! - exposes read-only JSON APIs over [`logbook_store`] — `/api/events`,
//!   `/api/timeline`, `/api/inventory` ([`api`], [`inventory`]);
//! - streams a live event tail over Server-Sent Events at `/api/stream`, backed
//!   by a [`tokio::sync::broadcast`] channel ([`bus`], [`sse`]).
//!
//! The front-end renders a **Timeline** across all event categories plus five
//! **Endpoint Inventory** tabs (Endpoint · Agents · MCP Servers · Sessions ·
//! Risk/Shadow).
//!
//! # Wiring it up
//! ```no_run
//! use logbook_ui::{serve, EventBus, UiConfig};
//! use logbook_store::Store;
//!
//! # async fn run() -> std::io::Result<()> {
//! let store = Store::open_in_dir(".logbook").expect("open store");
//! let bus = EventBus::new();
//!
//! // Capture/collector code clones `bus` and `store` and publishes events:
//! //   bus.publish(event);  store.insert(&event)?;
//!
//! serve(&UiConfig::default(), store, bus).await
//! # }
//! ```
//!
//! Binding is loopback-only with port auto-increment and an optional parent-PID
//! watchdog, mirroring the OpenLogs collector contract (plan §4).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod bus;
pub mod capture;
pub mod embed;
pub mod inventory;
pub mod server;
pub mod sessions;
pub mod sse;
pub mod state;

pub use bus::EventBus;
pub use capture::{CapturePolicyUpdate, CapturePolicyView, WriteTarget, CSRF_HEADER};
pub use inventory::{
    AgentInstall, AgentSession, Endpoint, InventoryFinding, InventorySnapshot, McpServer,
};
pub use server::{app, bind, serve, serve_with_state, UiConfig, UiServer, DEFAULT_PORT};
pub use sessions::{
    list_sessions, load_session, SessionAction, SessionDetail, SessionSummary, SessionTranscript,
    SessionTreeView, TurnGroupView,
};
pub use state::AppState;

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `oneshot`

    use logbook_core::{
        Category, ConsoleBlock, Event, FindingBlock, Kind, Severity, Status, TraceId,
    };
    use logbook_store::Store;

    fn seed_store() -> (Store, TraceId) {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        // An app-log line.
        let mut log = Event::new(trace, Kind::Log, Category::AppLog, "stdout")
            .with_name("server started")
            .with_status(Status::Ok);
        log.timestamp = logbook_core::MicrosTimestamp(1_000);
        store.insert(&log).unwrap();

        // A browser console error.
        let mut console = Event::new(trace, Kind::Browser, Category::Browser, "console")
            .with_console(ConsoleBlock {
                level: Some("error".into()),
                message: Some("ReferenceError: x is not defined".into()),
                ..Default::default()
            })
            .with_error("ReferenceError: x is not defined");
        console.timestamp = logbook_core::MicrosTimestamp(2_000);
        store.insert(&console).unwrap();

        // A security finding.
        let mut finding = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("cargo-audit".into()),
                rule_id: Some("RUSTSEC-2024-0003".into()),
                severity: Some(Severity::High),
                message: Some("vulnerable dependency".into()),
                ..Default::default()
            });
        finding.timestamp = logbook_core::MicrosTimestamp(3_000);
        store.insert(&finding).unwrap();

        (store, trace)
    }

    fn router() -> (axum::Router, TraceId) {
        let (store, trace) = seed_store();
        let state = AppState::new(store, EventBus::new());
        (app(state), trace)
    }

    async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn events_endpoint_returns_newest_first() {
        let (app, _trace) = router();
        let (status, json) = get_json(&app, "/api/events").await;
        assert_eq!(status, StatusCode::OK);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        // Newest first: the security finding (ts=3000) leads.
        assert_eq!(events[0]["category"], "security");
        assert_eq!(events[2]["category"], "app_log");
    }

    #[tokio::test]
    async fn timeline_endpoint_returns_oldest_first() {
        let (app, _trace) = router();
        let (status, json) = get_json(&app, "/api/timeline").await;
        assert_eq!(status, StatusCode::OK);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        // Oldest first: the app log (ts=1000) leads.
        assert_eq!(events[0]["category"], "app_log");
        assert_eq!(events[2]["category"], "security");
    }

    #[tokio::test]
    async fn events_endpoint_filters_by_category() {
        let (app, _trace) = router();
        let (status, json) = get_json(&app, "/api/events?category=security").await;
        assert_eq!(status, StatusCode::OK);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["category"], "security");
        assert_eq!(events[0]["finding"]["severity"], "high");
    }

    #[tokio::test]
    async fn events_endpoint_rejects_unknown_category() {
        let (app, _trace) = router();
        // A typo'd category must be a 400, not a silent widening to all lanes.
        let (status, json) = get_json(&app, "/api/events?category=securty").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            json["error"].as_str().unwrap_or_default().contains("securty"),
            "error body should name the bad category, got {json}"
        );
    }

    #[tokio::test]
    async fn timeline_endpoint_rejects_unknown_category() {
        let (app, _trace) = router();
        let (status, _json) = get_json(&app, "/api/timeline?category=bogus").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn events_endpoint_filters_by_trace() {
        let (app, trace) = router();
        let uri = format!("/api/events?trace_id={}", trace.to_hex());
        let (status, json) = get_json(&app, &uri).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["events"].as_array().unwrap().len(), 3);

        // A different trace id matches nothing.
        let other = TraceId::new().to_hex();
        let (_s, none) = get_json(&app, &format!("/api/events?trace_id={other}")).await;
        assert!(none["events"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn events_endpoint_full_text_search() {
        let (app, _trace) = router();
        let (status, json) = get_json(&app, "/api/events?q=ReferenceError").await;
        assert_eq!(status, StatusCode::OK);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "FTS should match the console error");
        assert_eq!(events[0]["category"], "browser");
    }

    #[tokio::test]
    async fn inventory_endpoint_returns_empty_shape_when_unpopulated() {
        let (app, _trace) = router();
        let (status, json) = get_json(&app, "/api/inventory").await;
        assert_eq!(status, StatusCode::OK);
        // All five tabs present as arrays, even with no inventory rows.
        for key in ["endpoints", "agents", "mcp_servers", "sessions", "findings"] {
            assert!(json[key].is_array(), "{key} should be an array");
            assert_eq!(json[key].as_array().unwrap().len(), 0);
        }
    }

    #[tokio::test]
    async fn inventory_endpoint_reads_planted_rows() {
        let (store, _trace) = seed_store();
        // Plant an endpoint, a shadow agent, and a risk finding directly.
        store
            .write(|conn| {
                conn.execute_batch(
                    "INSERT INTO endpoints (id, hostname, os, arch, first_seen, last_seen) \
                       VALUES ('ep1', 'devbox', 'macos', 'arm64', 10, 20);
                     INSERT INTO agent_installs \
                       (id, endpoint_id, name, version, path, sanctioned, discovered_at) \
                       VALUES ('a1', 'ep1', 'claude', '1.0', '/usr/local/bin/claude', 1, 11),
                              ('a2', 'ep1', 'rogue-agent', NULL, '/tmp/rogue', 0, 12);
                     INSERT INTO mcp_servers \
                       (id, endpoint_id, name, source_config, command, transport, sanctioned, has_secret, discovered_at) \
                       VALUES ('m1', 'ep1', 'filesystem', '.mcp.json', 'npx fs', 'stdio', 1, 0, 13),
                              ('m2', 'ep1', 'shady', '.cursor/mcp.json', 'curl evil', 'stdio', 0, 1, 14);
                     INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                       VALUES ('s1', 'ep1', 'claude', 'claude --help', NULL, 15, 16, 0);
                     INSERT INTO inventory_findings \
                       (id, endpoint_id, kind, severity, subject, message, created_at) \
                       VALUES ('f1', 'ep1', 'unsanctioned_agent', 'high', 'rogue-agent', 'shadow agent on PATH', 17);",
                )
                .map_err(logbook_store::StoreError::from)
            })
            .unwrap();

        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/inventory").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["endpoints"].as_array().unwrap().len(), 1);
        assert_eq!(json["endpoints"][0]["hostname"], "devbox");
        assert_eq!(json["agents"].as_array().unwrap().len(), 2);
        assert_eq!(json["mcp_servers"].as_array().unwrap().len(), 2);
        assert_eq!(json["sessions"].as_array().unwrap().len(), 1);

        // Risk/shadow surfacing: the shadow agent finding is present and the
        // unsanctioned rows are flagged.
        let findings = json["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["kind"], "unsanctioned_agent");
        assert_eq!(findings[0]["severity"], "high");

        let shadow_agent = json["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["name"] == "rogue-agent")
            .unwrap();
        assert_eq!(shadow_agent["sanctioned"], false);

        let shady_mcp = json["mcp_servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == "shady")
            .unwrap();
        assert_eq!(shady_mcp["sanctioned"], false);
        assert_eq!(shady_mcp["has_secret"], true);
    }

    #[tokio::test]
    async fn static_handler_serves_embedded_index() {
        let (app, _trace) = router();
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(ct.contains("text/html"), "index should be html, got {ct}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty(), "index.html should have content");
    }

    #[tokio::test]
    async fn unknown_route_falls_back_to_spa_index() {
        let (app, _trace) = router();
        // A client-side route that is not a real asset returns the app shell.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/inventory/agents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "SPA fallback should return 200");
    }

    // ───────────────── sessions endpoints (Orbit §1.4) ─────────────────

    /// Plant one full session (header + transcript + actions + a trace event).
    fn seed_session(store: &Store) -> TraceId {
        let trace = TraceId::new();
        let trace_hex = trace.to_hex();
        store
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                     VALUES ('s1', NULL, 'claude', 'claude -- build', ?1, 100, 200, 0)",
                    [&trace_hex],
                )?;
                conn.execute_batch(
                    "INSERT INTO session_transcripts \
                       (session_id, trace_id, terminal_log_path, text_path, line_count, byte_size, max_sensitivity, created_at) \
                       VALUES ('s1', 'tr', '/o/s.terminal.log', '/o/s.txt', 7, 999, 'transcript', 150);
                     INSERT INTO agent_actions \
                       (id, session_id, kind, path, detail, observed_at, diff, diff_bytes, post_hash, revert_safe, max_sensitivity) \
                       VALUES ('a1', 's1', 'file_modified', 'f.txt', NULL, 160, '@@ -1 +1 @@\n-x\n+y', 17, 'h', 1, 'file_diffs');",
                )?;
                Ok(())
            })
            .unwrap();
        let mut ev = Event::new(trace, Kind::Log, Category::Agent, "run")
            .with_name("echo hi")
            .with_status(Status::Ok)
            .with_session(logbook_core::SessionId::new("s1"));
        ev.timestamp = logbook_core::MicrosTimestamp(155);
        store.insert(&ev).unwrap();
        trace
    }

    #[tokio::test]
    async fn sessions_endpoint_lists_with_counts() {
        let store = Store::open_in_memory().unwrap();
        seed_session(&store);
        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/sessions").await;
        assert_eq!(status, StatusCode::OK);
        let sessions = json["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["session_id"], "s1");
        assert_eq!(sessions[0]["action_count"], 1);
        assert_eq!(sessions[0]["has_transcript"], true);
        assert_eq!(sessions[0]["exit_code"], 0);
    }

    #[tokio::test]
    async fn session_detail_endpoint_replays_transcript_actions_events() {
        let store = Store::open_in_memory().unwrap();
        seed_session(&store);
        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/sessions/s1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["session"]["session_id"], "s1");
        assert_eq!(json["transcript"]["terminal_log_path"], "/o/s.terminal.log");
        assert_eq!(json["transcript"]["line_count"], 7);
        let actions = json["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "file_modified");
        assert_eq!(actions[0]["revert_safe"], true);
        assert_eq!(actions[0]["diff_bytes"], 17);
        // The ordered trace stream carries the planted command event.
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["name"], "echo hi");
    }

    #[tokio::test]
    async fn session_detail_missing_is_404() {
        let store = Store::open_in_memory().unwrap();
        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/sessions/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["error"].as_str().unwrap_or_default().contains("nope"));
    }

    // ───────────────── findings feed (Phase 3 Risk) ─────────────────

    /// Plant three security findings (a detect-style secret-in-diff at High, a
    /// medium risky-git finding, and an info advisory) so the severity filter
    /// has something to discriminate. Returns the store.
    fn seed_findings() -> Store {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        let mut info = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("detect".into()),
                rule_id: Some("tool_call_rate".into()),
                severity: Some(Severity::Info),
                message: Some("informational rate note".into()),
                ..Default::default()
            });
        info.timestamp = logbook_core::MicrosTimestamp(1_000);
        store.insert(&info).unwrap();

        let mut medium = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("detect".into()),
                rule_id: Some("risky_git".into()),
                severity: Some(Severity::Medium),
                file: Some("scripts/deploy.sh".into()),
                message: Some("history rewrite (git rebase)".into()),
                ..Default::default()
            });
        medium.timestamp = logbook_core::MicrosTimestamp(2_000);
        store.insert(&medium).unwrap();

        let mut high = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("detect".into()),
                rule_id: Some("secret_in_diff".into()),
                severity: Some(Severity::High),
                file: Some("src/config.rs".into()),
                line: Some(42),
                message: Some("a secret was present in a code change".into()),
            });
        high.timestamp = logbook_core::MicrosTimestamp(3_000);
        store.insert(&high).unwrap();

        store
    }

    #[tokio::test]
    async fn findings_endpoint_returns_security_findings_newest_first() {
        let app = app(AppState::new(seed_findings(), EventBus::new()));
        let (status, json) = get_json(&app, "/api/findings").await;
        assert_eq!(status, StatusCode::OK);
        let findings = json["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 3);
        // Newest-first: the High secret-in-diff (ts=3000) leads, the Info note last.
        assert_eq!(findings[0]["finding"]["rule_id"], "secret_in_diff");
        assert_eq!(findings[0]["finding"]["severity"], "high");
        assert_eq!(findings[0]["finding"]["line"], 42);
        assert_eq!(findings[2]["finding"]["severity"], "info");
    }

    #[tokio::test]
    async fn findings_endpoint_filters_by_min_severity() {
        let app = app(AppState::new(seed_findings(), EventBus::new()));
        // severity=medium drops the Info finding, keeps Medium + High.
        let (status, json) = get_json(&app, "/api/findings?severity=medium").await;
        assert_eq!(status, StatusCode::OK);
        let findings = json["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|f| f["finding"]["severity"] != "info"));

        // severity=critical drops everything (nothing is that severe here).
        let (_s, none) = get_json(&app, "/api/findings?severity=critical").await;
        assert!(none["findings"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn findings_endpoint_severity_floor_survives_limit_of_low_findings() {
        // Regression: the severity floor is a Rust post-filter, so it must run
        // against a candidate set large enough to *reach* the severe findings.
        // Seed MANY low (Info) findings that are all NEWER than a single High
        // finding, then more of them than the request `limit`. With the old
        // "fetch `limit` newest, then filter" logic, the High finding sits just
        // past the newest-`limit` window and `?severity=high` returns ZERO — a
        // false negative on the Risk feed. The fix fetches a larger candidate
        // set, applies the floor, then truncates, so the High finding survives.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();

        // The lone High finding is the OLDEST event (ts=1), so a naive
        // newest-first store LIMIT would exclude it once enough newer Info
        // findings exist.
        let mut high = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("detect".into()),
                rule_id: Some("secret_in_diff".into()),
                severity: Some(Severity::High),
                file: Some("src/config.rs".into()),
                line: Some(7),
                message: Some("a secret was present in a code change".into()),
            });
        high.timestamp = logbook_core::MicrosTimestamp(1);
        store.insert(&high).unwrap();

        // Plant far more newer Info findings than the `limit` we will request,
        // so they would fully occupy a newest-`limit` candidate window.
        let request_limit = 5_u32;
        let low_count = (request_limit as i64) * 4; // 20 Info findings, all newer.
        for i in 0..low_count {
            let mut info = Event::new(trace, Kind::Finding, Category::Security, "advisory")
                .with_finding(FindingBlock {
                    source: Some("detect".into()),
                    rule_id: Some("tool_call_rate".into()),
                    severity: Some(Severity::Info),
                    message: Some("informational rate note".into()),
                    ..Default::default()
                });
            // ts strictly greater than the High finding's ts=1.
            info.timestamp = logbook_core::MicrosTimestamp(1_000 + i);
            store.insert(&info).unwrap();
        }

        let app = app(AppState::new(store, EventBus::new()));
        // Request a small limit so the newest Info findings alone would exhaust
        // it; `?severity=high` must STILL surface the older High finding.
        let uri = format!("/api/findings?severity=high&limit={request_limit}");
        let (status, json) = get_json(&app, &uri).await;
        assert_eq!(status, StatusCode::OK);
        let findings = json["findings"].as_array().unwrap();
        assert_eq!(
            findings.len(),
            1,
            "the single High finding must survive the floor despite {low_count} newer Info findings and limit={request_limit}, got {json}"
        );
        assert_eq!(findings[0]["finding"]["severity"], "high");
        assert_eq!(findings[0]["finding"]["rule_id"], "secret_in_diff");

        // And it must not over-return: the Info findings stay filtered out.
        assert!(
            findings
                .iter()
                .all(|f| f["finding"]["severity"] == "high"),
            "only High findings should pass the floor, got {json}"
        );
    }

    #[tokio::test]
    async fn findings_endpoint_rejects_unknown_severity() {
        let app = app(AppState::new(seed_findings(), EventBus::new()));
        let (status, json) = get_json(&app, "/api/findings?severity=spicy").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            json["error"].as_str().unwrap_or_default().contains("spicy"),
            "error body should name the bad severity, got {json}"
        );
    }

    #[tokio::test]
    async fn findings_endpoint_empty_when_no_security_events() {
        // A store with only an app-log line has no security findings.
        let store = Store::open_in_memory().unwrap();
        let mut log = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout")
            .with_name("nothing risky here");
        log.timestamp = logbook_core::MicrosTimestamp(10);
        store.insert(&log).unwrap();
        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/findings").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["findings"].as_array().unwrap().is_empty());
    }

    // ───────────────── session tree (Phase 3 correlation) ─────────────────

    /// Plant one session whose events span two turns plus a turn-less finding,
    /// so the correlation tree groups them: turn 0 (an agent step + a tool
    /// call), turn 1 (an llm call), and a turn-less security finding.
    fn seed_tree_session(store: &Store) {
        let trace = TraceId::new();
        let trace_hex = trace.to_hex();
        store
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO agent_sessions \
                       (id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code) \
                     VALUES ('tree-1', NULL, 'claude', 'claude -- build', ?1, 100, 400, 0)",
                    [&trace_hex],
                )?;
                Ok(())
            })
            .unwrap();

        let sess = logbook_core::SessionId::new("tree-1");
        let turn = |t: u64| logbook_core::AgentBlock {
            turn: Some(t),
            ..Default::default()
        };

        // Turn 0: an agent step.
        let mut step = Event::new(trace, Kind::Agent, Category::Agent, "turn")
            .with_name("plan the change")
            .with_session(sess.clone())
            .with_agent(turn(0));
        step.timestamp = logbook_core::MicrosTimestamp(150);
        store.insert(&step).unwrap();

        // Turn 0: a tool call under the same turn.
        let mut tool = Event::new(trace, Kind::Tool, Category::Agent, "tools/call")
            .with_name("edit_file")
            .with_session(sess.clone())
            .with_agent(turn(0));
        tool.timestamp = logbook_core::MicrosTimestamp(160);
        store.insert(&tool).unwrap();

        // Turn 1: an llm call.
        let mut llm = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_name("anthropic claude-3")
            .with_session(sess.clone())
            .with_agent(turn(1));
        llm.timestamp = logbook_core::MicrosTimestamp(200);
        store.insert(&llm).unwrap();

        // A turn-less security finding correlated by session (no stamped turn).
        let mut finding = Event::new(trace, Kind::Finding, Category::Security, "advisory")
            .with_finding(FindingBlock {
                source: Some("detect".into()),
                rule_id: Some("secret_in_diff".into()),
                severity: Some(Severity::High),
                message: Some("a secret was present in a code change".into()),
                ..Default::default()
            })
            .with_session(sess);
        finding.timestamp = logbook_core::MicrosTimestamp(300);
        store.insert(&finding).unwrap();
    }

    #[tokio::test]
    async fn session_tree_endpoint_groups_events_by_turn() {
        let store = Store::open_in_memory().unwrap();
        seed_tree_session(&store);
        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/sessions/tree-1/tree").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["session_id"], "tree-1");
        assert_eq!(json["event_count"], 4);

        let turns = json["turns"].as_array().unwrap();
        // Three groups: turn 0, turn 1, and the turn-less (null) catch-all last.
        assert_eq!(turns.len(), 3);
        assert_eq!(turns[0]["turn"], 0);
        assert_eq!(turns[0]["events"].as_array().unwrap().len(), 2);
        // Turn 0 children are oldest-first: the agent step then the tool call.
        assert_eq!(turns[0]["events"][0]["kind"], "agent");
        assert_eq!(turns[0]["events"][1]["kind"], "tool");
        assert_eq!(turns[1]["turn"], 1);
        assert_eq!(turns[1]["events"][0]["kind"], "llm");
        // The turn-less group sorts last and carries the security finding.
        assert!(turns[2]["turn"].is_null());
        assert_eq!(turns[2]["events"][0]["category"], "security");
        assert_eq!(turns[2]["events"][0]["finding"]["rule_id"], "secret_in_diff");
    }

    #[tokio::test]
    async fn session_tree_endpoint_unknown_session_is_empty_ok() {
        // An unknown session is a 200 with an empty tree (nothing to correlate),
        // not a 404 — the correlation view of "no events" is "no turns".
        let store = Store::open_in_memory().unwrap();
        let app = app(AppState::new(store, EventBus::new()));
        let (status, json) = get_json(&app, "/api/sessions/ghost/tree").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["session_id"], "ghost");
        assert_eq!(json["event_count"], 0);
        assert!(json["turns"].as_array().unwrap().is_empty());
    }

    // ───────────────── capture-policy endpoint (Orbit §1.4) ─────────────────

    /// A state pointed at a temp out-dir, with the given config-write capability.
    fn capture_state(out_dir: &std::path::Path, allow_config_write: bool) -> AppState {
        AppState::new(Store::open_in_memory().unwrap(), EventBus::new())
            .with_capture(out_dir.to_path_buf(), out_dir.to_path_buf(), allow_config_write)
    }

    async fn post_json(
        app: &axum::Router,
        uri: &str,
        csrf: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = csrf {
            req = req.header(crate::capture::CSRF_HEADER, token);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn capture_policy_get_exposes_token_and_locked_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(capture_state(tmp.path(), false));
        let (status, json) = get_json(&app, "/api/capture-policy").await;
        assert_eq!(status, StatusCode::OK);
        // Recorder-on defaults (no logbook.toml present).
        assert_eq!(json["enabled"], true);
        assert_eq!(json["classes"]["file_diffs"], true);
        assert_eq!(json["secrets_locked"], true);
        assert_eq!(json["allow_config_write"], false);
        assert!(json["csrf_token"].as_str().unwrap().len() >= 16);
        assert_eq!(json["version"], "absent");
    }

    #[tokio::test]
    async fn capture_policy_post_without_csrf_is_forbidden() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(capture_state(tmp.path(), false));
        let (status, _json) =
            post_json(&app, "/api/capture-policy", None, serde_json::json!({ "enabled": false }))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // No capture-state.json should have been written.
        assert!(!tmp.path().join("capture-state.json").exists());
    }

    #[tokio::test]
    async fn capture_policy_post_runtime_writes_overlay_cross_process() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(capture_state(tmp.path(), false));
        // Read the CSRF token first.
        let (_s, view) = get_json(&app, "/api/capture-policy").await;
        let token = view["csrf_token"].as_str().unwrap();

        // Pause capture via the runtime overlay.
        let (status, json) = post_json(
            &app,
            "/api/capture-policy",
            Some(token),
            serde_json::json!({ "target": "runtime", "enabled": false }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["enabled"], false, "resolved policy reflects the pause");

        // The cross-process file is written, and a fresh resolve sees master-off.
        let state_path = tmp.path().join("capture-state.json");
        assert!(state_path.exists(), "capture-state.json must be written");
        let resolved = logbook_core::CapturePolicy::resolve(
            tmp.path(),
            tmp.path(),
            logbook_core::CliOverlay::default(),
        );
        assert!(!resolved.enabled, "subsequent producers see the pause");
    }

    #[tokio::test]
    async fn capture_policy_post_config_target_is_gated() {
        let tmp = tempfile::tempdir().unwrap();
        // allow_config_write = false -> config target rejected.
        let app = app(capture_state(tmp.path(), false));
        let (_s, view) = get_json(&app, "/api/capture-policy").await;
        let token = view["csrf_token"].as_str().unwrap();
        let (status, _json) = post_json(
            &app,
            "/api/capture-policy",
            Some(token),
            serde_json::json!({ "target": "config", "enabled": false }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "config write needs --allow-config-write");
        assert!(!tmp.path().join("logbook.toml").exists());
    }

    #[tokio::test]
    async fn capture_policy_post_config_target_when_allowed_writes_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(capture_state(tmp.path(), true));
        let (_s, view) = get_json(&app, "/api/capture-policy").await;
        let token = view["csrf_token"].as_str().unwrap();
        let (status, _json) = post_json(
            &app,
            "/api/capture-policy",
            Some(token),
            serde_json::json!({ "target": "config", "classes": { "file_diffs": false } }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let toml_path = tmp.path().join("logbook.toml");
        assert!(toml_path.exists(), "logbook.toml must be written");
        // The durable config disables file_diffs but keeps the secrets floor.
        let cfg = logbook_core::LogbookConfig::load_from_root(tmp.path()).unwrap();
        assert!(!cfg.capture.classes.file_diffs.capture);
        assert!(cfg.capture.classes.secrets.capture, "floor preserved");
        assert!(cfg.capture.validate().is_ok());
    }

    #[tokio::test]
    async fn capture_policy_post_detects_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(capture_state(tmp.path(), false));
        let (_s, view) = get_json(&app, "/api/capture-policy").await;
        let token = view["csrf_token"].as_str().unwrap().to_string();

        // A stale expected_version (file is currently absent) -> 409.
        let (status, _json) = post_json(
            &app,
            "/api/capture-policy",
            Some(&token),
            serde_json::json!({ "enabled": false, "expected_version": "stale:1:abc" }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn capture_policy_cross_site_fetch_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(capture_state(tmp.path(), false));
        let (_s, view) = get_json(&app, "/api/capture-policy").await;
        let token = view["csrf_token"].as_str().unwrap().to_string();
        // Even with a valid token, an explicit cross-site fetch is rejected.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/capture-policy")
                    .header("content-type", "application/json")
                    .header(crate::capture::CSRF_HEADER, token)
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::from(
                        serde_json::json!({ "enabled": false }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
