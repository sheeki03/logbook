//! Integration test for Endpoint Inventory Lite (plan §7b, §11, §15.7–§15.8).
//!
//! The plan's headline acceptance: a planted fake agent CLI on PATH + a temp
//! `.mcp.json` are detected and surfaced; a secret placed in that `.mcp.json` is
//! redacted in report output. This exercises the crate end-to-end through its
//! public API (discovery -> findings -> persistence -> rendered report).

use std::io::Write;
use std::path::Path;

use logbook_core::Redactor;
use logbook_inventory::agents::AgentScanOptions;
use logbook_inventory::model::finding_kind;
use logbook_inventory::scan::{scan_and_persist, ScanContext};
use logbook_inventory::store_ext::{self, InventoryTable};
use logbook_inventory::{report, ScanReport};
use logbook_store::{Query, Store};

/// Write a fake executable agent CLI into `dir`.
fn plant_agent(dir: &Path, name: &str) {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    writeln!(f, "#!/bin/sh\necho fake-{name}").unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Build a scan context whose agent discovery is scoped to `bindir` (no global
/// env mutation), with the project dir holding the planted `.mcp.json`.
fn ctx_with_planted(bindir: &Path, home: &Path, project: &Path) -> ScanContext {
    let mut ctx = ScanContext::discover(home, project);
    ctx.agents = AgentScanOptions::with_path(bindir.to_string_lossy());
    // Hermetic: scope conversation-store discovery to the test's (store-free)
    // home tempdir so `scan` never walks the real machine's data dirs — which
    // would make these tests slow, non-deterministic, and dependent on whatever
    // Cursor/Gemini/Continue history the developer happens to have on disk.
    ctx.session_roots = Some(logbook_import::discovery::from_path(home.to_path_buf()));
    ctx
}

#[test]
fn planted_agent_and_mcp_secret_detected_and_redacted_in_report() {
    const SECRET: &str = "sk-ant-INTEGRATIONSECRET0123456789";

    let bindir = tempfile::tempdir().unwrap();
    // An unsanctioned agent CLI on the (scoped) PATH.
    plant_agent(bindir.path(), "aider");

    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    // A project-local .mcp.json with an inline secret in an env value.
    std::fs::write(
        project.path().join(".mcp.json"),
        format!(
            r#"{{ "mcpServers": {{ "ghost": {{ "command": "node", "args": ["s.js"],
                 "env": {{ "API_KEY": "{SECRET}" }} }} }} }}"#
        ),
    )
    .unwrap();

    let ctx = ctx_with_planted(bindir.path(), home.path(), project.path());
    let store = Store::open_in_memory().unwrap();
    let report: ScanReport = scan_and_persist(&ctx, &store).unwrap();

    // --- Detection ---
    assert!(
        report
            .agents
            .iter()
            .any(|a| a.name == "aider" && !a.sanctioned),
        "planted unsanctioned agent should be detected: {:?}",
        report.agents
    );
    let ghost = report
        .mcp_servers
        .iter()
        .find(|s| s.name == "ghost")
        .expect("planted MCP server detected");
    assert!(ghost.has_secret, "the inline secret should be flagged");
    assert!(!ghost.sanctioned, "ghost is shadow/untracked");

    // --- Risk surfacing ---
    assert!(report.has_risk());
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == finding_kind::UNSANCTIONED_AGENT));
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == finding_kind::SHADOW_MCP));
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == finding_kind::MCP_SECRET));

    // --- Redaction in BOTH report renderings ---
    let human = report::to_human(&report);
    let json = report::to_json(&report).unwrap();
    assert!(
        !human.contains(SECRET),
        "secret leaked in human report:\n{human}"
    );
    assert!(
        !json.contains(SECRET),
        "secret leaked in JSON report:\n{json}"
    );
    // The report still communicates that a secret was present (redacted).
    assert!(
        human.contains("SECRET REDACTED"),
        "human report should flag the redacted secret"
    );
    assert!(
        json.contains("\"has_secret\": true"),
        "JSON should flag has_secret"
    );
    // The planted items are visible in the report.
    assert!(human.contains("aider"));
    assert!(human.contains("ghost"));

    // --- Persistence: inventory tables populated, timeline carries events ---
    assert!(store_ext::count_rows(&store, InventoryTable::AgentInstalls).unwrap() >= 1);
    assert_eq!(
        store_ext::count_rows(&store, InventoryTable::McpServers).unwrap(),
        1
    );
    let findings = store_ext::load_inventory_findings(&store, &report.endpoint.id).unwrap();
    assert!(findings.iter().any(|f| f.kind == finding_kind::MCP_SECRET));

    // The persisted timeline events (category=inventory) must not leak either.
    let inv_events = store
        .query(&Query::new().category(logbook_core::Category::Inventory))
        .unwrap();
    assert!(
        !inv_events.is_empty(),
        "scan should emit inventory timeline events"
    );
    let ev_json = serde_json::to_string(&inv_events).unwrap();
    assert!(
        !ev_json.contains("INTEGRATIONSECRET"),
        "timeline leaked secret: {ev_json}"
    );

    // And nothing in the persisted findings rows leaks the secret.
    let findings_text = serde_json::to_string(&findings).unwrap();
    assert!(
        !findings_text.contains("INTEGRATIONSECRET"),
        "stored findings leaked: {findings_text}"
    );
}

#[test]
fn rescan_refreshes_findings_without_accumulating() {
    // Contract (scan::persist): re-scanning the same store must *refresh*
    // inventory_findings, not pile up stale rows. Each scan mints fresh,
    // randomized finding ids, so without the clear-then-insert in persist() a
    // second scan would double the row count. Guard that here.
    let bindir = tempfile::tempdir().unwrap();
    plant_agent(bindir.path(), "aider"); // unsanctioned → at least one finding
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".mcp.json"),
        r#"{ "mcpServers": { "ghost": { "command": "node",
             "env": { "API_KEY": "sk-ant-RESCANSECRET0123456789" } } } }"#,
    )
    .unwrap();

    let ctx = ctx_with_planted(bindir.path(), home.path(), project.path());
    let store = Store::open_in_memory().unwrap();

    let first = scan_and_persist(&ctx, &store).unwrap();
    assert!(
        !first.findings.is_empty(),
        "fixture should surface at least one finding"
    );
    let after_first =
        store_ext::count_rows(&store, InventoryTable::InventoryFindings).unwrap();
    assert_eq!(
        after_first,
        first.findings.len() as i64,
        "first scan persists exactly its findings"
    );

    // A second identical scan must leave the persisted finding count unchanged.
    let second = scan_and_persist(&ctx, &store).unwrap();
    let after_second =
        store_ext::count_rows(&store, InventoryTable::InventoryFindings).unwrap();
    assert_eq!(
        after_second, after_first,
        "re-scan must refresh findings, not accumulate (got {after_second}, expected {after_first})"
    );
    assert_eq!(
        second.findings.len(),
        first.findings.len(),
        "same inputs should yield the same finding set across scans"
    );

    // The persisted rows reflect a single scan's worth, keyed by endpoint.
    let loaded = store_ext::load_inventory_findings(&store, &second.endpoint.id).unwrap();
    assert_eq!(loaded.len(), second.findings.len());
}

#[test]
fn clean_endpoint_has_no_risk_findings() {
    // A scoped PATH with only a sanctioned agent and no MCP configs → no risk.
    let bindir = tempfile::tempdir().unwrap();
    plant_agent(bindir.path(), "claude"); // sanctioned by default
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();

    let ctx = ctx_with_planted(bindir.path(), home.path(), project.path());
    let store = Store::open_in_memory().unwrap();
    let report = scan_and_persist(&ctx, &store).unwrap();

    assert!(report
        .agents
        .iter()
        .any(|a| a.name == "claude" && a.sanctioned));
    assert!(
        !report.has_risk(),
        "a sanctioned-only endpoint has no risk: {:?}",
        report.findings
    );

    // A scan with no risk emits an Ok summary event.
    let inv = store
        .query(&Query::new().category(logbook_core::Category::Inventory))
        .unwrap();
    assert_eq!(inv.len(), 1, "exactly the summary event, no finding events");
    assert_eq!(inv[0].status, logbook_core::Status::Ok);
}

#[test]
fn secret_redacted_with_aws_key_in_codex_toml() {
    // Secrets also surface from Codex-style TOML env tables.
    const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    let bindir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join(".codex")).unwrap();
    std::fs::write(
        project.path().join(".codex").join("config.toml"),
        format!(
            "[mcp_servers.leaky]\ncommand = \"/bin/srv\"\n\n[mcp_servers.leaky.env]\nAWS_SECRET = \"{AWS}\"\n"
        ),
    )
    .unwrap();

    let ctx = ctx_with_planted(bindir.path(), home.path(), project.path());
    let report = logbook_inventory::scan::scan(&ctx);
    let leaky = report
        .mcp_servers
        .iter()
        .find(|s| s.name == "leaky")
        .expect("codex mcp detected");
    assert!(leaky.has_secret);

    let json = report::to_json(&report).unwrap();
    assert!(!json.contains(AWS), "codex secret leaked: {json}");
}

#[test]
fn report_is_self_contained_and_redaction_default_on() {
    // Sanity: even with no config file present, redaction is on (the secret in a
    // discovered config is scrubbed). This guards the plan's "redaction on by
    // default" requirement at the inventory layer.
    let r = Redactor::new();
    let scrubbed = r.redact("API_KEY=AKIAIOSFODNN7EXAMPLE");
    assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
}
