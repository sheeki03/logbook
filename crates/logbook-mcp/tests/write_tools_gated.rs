//! Integration test for the core security property (plan §5, §11, §15.3):
//!
//! > with default read-only permissions the advertised tool list contains NO
//! > write tools; enabling a write category advertises its tool.
//!
//! This drives the public surface exactly as the CLI would: load
//! `logbook.toml` from a project root and ask the built server which tools it
//! advertises (`tools/list`).

use std::fs;

use logbook_mcp::config::{all_write_tools, WriteCategory};
use logbook_mcp::{server_from_root, LogbookServer, McpConfig};
use logbook_store::Store;

/// The 21 read tools that must always be advertised.
const READ_TOOLS: &[&str] = &[
    "list_log_files",
    "tail_log",
    "search_logs",
    "get_errors",
    "get_run_status",
    "watch_log",
    "browser_console",
    "browser_network",
    "browser_get_request",
    "browser_dom",
    "query_timeline",
    "get_trace",
    "correlate",
    "list_findings",
    "get_finding",
    "debug_fetch_evidence",
    "inventory_list_agents",
    "inventory_list_mcp",
    "inventory_list_sessions",
    "inventory_report",
    "inventory_findings",
];

fn server_for(cfg_text: Option<&str>) -> LogbookServer {
    let store = Store::open_in_memory().unwrap();
    let perms = match cfg_text {
        Some(t) => McpConfig::parse(t).unwrap(),
        None => McpConfig::default(),
    };
    LogbookServer::new(store, perms.permissions())
}

#[test]
fn default_is_read_only_no_write_tools_visible() {
    let server = server_for(None);
    let names = server.advertised_tool_names();

    // Every read tool present...
    for t in READ_TOOLS {
        assert!(names.contains(&t.to_string()), "read tool {t} should be advertised");
    }
    // ...and not a single write tool.
    for w in all_write_tools() {
        assert!(
            !names.contains(&w.to_string()),
            "write tool {w} must NOT be advertised by default"
        );
    }
    assert_eq!(names.len(), READ_TOOLS.len(), "default surface = read tools only");
}

#[test]
fn enabling_a_category_advertises_exactly_its_tools() {
    // Security needs both the list entry and the allow flag.
    let server = server_for(Some(
        r#"
        [permissions]
        enabled_writes = ["security"]
        allow_security_scans = true
        "#,
    ));
    let names = server.advertised_tool_names();

    for t in WriteCategory::Security.tools() {
        assert!(names.contains(&t.to_string()), "security tool {t} should be advertised");
    }
    // No other write category leaked in.
    for other in [
        WriteCategory::Browser,
        WriteCategory::Dap,
        WriteCategory::Export,
        WriteCategory::InventoryWatch,
    ] {
        for t in other.tools() {
            assert!(!names.contains(&t.to_string()), "tool {t} from a disabled category leaked");
        }
    }
    assert_eq!(names.len(), READ_TOOLS.len() + WriteCategory::Security.tools().len());
}

#[test]
fn loads_permissions_from_root_logbook_toml() {
    // Write a real logbook.toml in a temp "workspace root" and load it.
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("logbook.toml"),
        r#"
        [permissions]
        enabled_writes = ["export"]

        [redaction]
        enabled = true
        "#,
    )
    .unwrap();

    let store = Store::open_in_memory().unwrap();
    let server = server_from_root(store, dir.path()).unwrap();
    let names = server.advertised_tool_names();
    assert!(names.contains(&"export_otel".to_string()), "export_otel should be advertised");
    // Still no browser/security/dap/inventory writes.
    assert!(!names.contains(&"security_scan".to_string()));
    assert!(!names.contains(&"browser_navigate".to_string()));
}

#[test]
fn missing_root_config_is_read_only() {
    // An empty dir (no logbook.toml) → strict read-only default.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_memory().unwrap();
    let server = server_from_root(store, dir.path()).unwrap();
    let names = server.advertised_tool_names();
    for w in all_write_tools() {
        assert!(!names.contains(&w.to_string()), "missing config must hide write tool {w}");
    }
    assert_eq!(names.len(), READ_TOOLS.len());
}

// ===========================================================================
// End-to-end `tools/call` enforcement (not just `tools/list` visibility).
//
// The security contract (lib.rs / server.rs docs) is that a disabled write
// tool is BOTH invisible to `tools/list` AND *rejected on `tools/call`*. The
// tests above only pin the visibility half via `advertised_tool_names()`. The
// two tests below drive a real rmcp client over an in-process duplex pipe and
// invoke the actual `tools/call` path, so a future rmcp upgrade (or a tool
// accidentally wired outside the gated router) that hid-but-still-dispatched a
// disabled tool would fail here instead of silently leaving it callable.
// ===========================================================================

use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};

/// Stand up `server` and a bare rmcp client connected to it over an in-memory
/// duplex pipe, completing the MCP initialize handshake. Returns the running
/// client service; its `peer()` drives `tools/call` against the real server.
async fn connect_client(server: LogbookServer) -> RunningService<RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(8192);
    // Serve the logbook server on its half in the background.
    tokio::spawn(async move {
        // Ignore the result: when the client disconnects at end of test the
        // server task simply ends.
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    // Drive the client on the other half (this performs the handshake).
    ().serve(client_io)
        .await
        .expect("client should connect and initialize")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_write_tool_is_rejected_on_tools_call() {
    // Read-only default: `security_scan` is in a disabled category.
    let store = Store::open_in_memory().unwrap();
    let server = LogbookServer::new(store, McpConfig::default().permissions());

    // Sanity: it is not even advertised.
    assert!(
        !server.advertised_tool_names().contains(&"security_scan".to_string()),
        "precondition: security_scan must be hidden under the read-only default"
    );

    let client = connect_client(server).await;
    let result = client
        .peer()
        .call_tool(CallToolRequestParams::new("security_scan"))
        .await;

    // The call MUST be rejected at the protocol layer (not executed and not
    // returned as a successful tool result).
    let err = result.expect_err("calling a disabled write tool must be rejected, not executed");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("not found"),
        "expected a not-found/rejection error for a disabled tool, got: {msg}"
    );

    let _ = client.cancel().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_write_tool_is_callable_on_tools_call() {
    // Enable the security category (list + companion flag).
    let store = Store::open_in_memory().unwrap();
    let cfg = McpConfig::parse(
        r#"
        [permissions]
        enabled_writes = ["security"]
        allow_security_scans = true
        "#,
    )
    .unwrap();
    let server = LogbookServer::new(store, cfg.permissions());

    // Sanity: it is advertised once enabled.
    assert!(
        server.advertised_tool_names().contains(&"security_scan".to_string()),
        "precondition: security_scan must be visible once enabled"
    );

    let client = connect_client(server).await;
    // `scanner` is required by the params schema.
    let args = serde_json::json!({ "scanner": "semgrep" })
        .as_object()
        .cloned()
        .expect("object literal");
    let result = client
        .peer()
        .call_tool(CallToolRequestParams::new("security_scan").with_arguments(args))
        .await
        .expect("an enabled write tool must be callable through tools/call");

    // The v1 body is a permitted-but-not-implemented stub; the point is the
    // call was *dispatched* (reached the handler) rather than rejected by the
    // gate. The handler reports a tool-level (not protocol-level) outcome.
    assert_ne!(
        result.is_error,
        Some(true),
        "enabled tool should return a successful tool result, not an error"
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default();
    assert!(
        text.contains("permitted_but_not_implemented"),
        "enabled security_scan stub should report it was permitted; got: {text}"
    );

    let _ = client.cancel().await;
}
