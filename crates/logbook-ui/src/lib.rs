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
pub mod embed;
pub mod inventory;
pub mod server;
pub mod sse;
pub mod state;

pub use bus::EventBus;
pub use inventory::{
    AgentInstall, AgentSession, Endpoint, InventoryFinding, InventorySnapshot, McpServer,
};
pub use server::{app, bind, serve, UiConfig, UiServer, DEFAULT_PORT};
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
}
