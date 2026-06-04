//! Tool *logic* — plain functions over an [`logbook_store::Store`].
//!
//! None of these functions know about `rmcp`: each takes a `&Store` plus typed
//! params and returns `anyhow::Result<serde_json::Value>`. The server
//! (`server.rs`) is the only place that adapts these into `rmcp` tool handlers.
//! Keeping the boundary here means the read-tool behaviour is unit-testable
//! against an in-memory store with no MCP plumbing.
//!
//! ## Read vs write
//! The READ tools (advertised by default) query the store. The WRITE tools are
//! gated by `logbook.toml` (`[permissions]`); their *visibility* is enforced in
//! the server, and their *bodies* are intentionally minimal stubs in v1 — the
//! real browser/DAP/security/export machinery lands in the sibling crates. The
//! stub still refuses to run unless the permission gate let it through, so it
//! returns a structured "not yet implemented (but permitted)" marker rather than
//! pretending to act.

use logbook_core::{Category, Event, Severity};
use logbook_store::{Query, Store};
use anyhow::{anyhow, Context};
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::params::*;

/// Serialize a slice of events to JSON values (the canonical `Event` shape).
fn events_to_values(events: &[Event]) -> Vec<Value> {
    events
        .iter()
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect()
}

/// Prepare `sql`, run it with `params`, and collect every mapped row into a
/// `Vec`, surfacing the first row error.
///
/// This factors out the `prepare → query_map → for row { push(row?) }` block
/// that every table-reading tool here would otherwise repeat. `map_fn` receives
/// each [`rusqlite::Row`] and returns the value to collect (typically a
/// `serde_json::Value`).
fn read_rows<T, P, F>(conn: &Connection, sql: &str, params: P, map_fn: F) -> rusqlite::Result<Vec<T>>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut stmt = conn.prepare(sql)?;
    let mapped = stmt.query_map(params, map_fn)?;
    let mut out = Vec::new();
    for row in mapped {
        out.push(row?);
    }
    Ok(out)
}

/// Parse a category token into the store enum, erroring on an unknown value.
fn parse_category(token: &str) -> anyhow::Result<Category> {
    match token {
        "agent" => Ok(Category::Agent),
        "browser" => Ok(Category::Browser),
        "app_log" => Ok(Category::AppLog),
        "code_test" => Ok(Category::CodeTest),
        "security" => Ok(Category::Security),
        "inventory" => Ok(Category::Inventory),
        other => Err(anyhow!("unknown category: {other}")),
    }
}


// ===========================================================================
// Logs lane
// ===========================================================================

/// `list_log_files` — the OpenLogs-style run index (one row per captured run).
/// Backed by the `runs` SQL table.
pub fn list_log_files(store: &Store) -> anyhow::Result<Value> {
    let rows = store.read(|conn: &Connection| {
        read_rows(
            conn,
            "SELECT key, command, name, out_dir, terminal_log_path, text_path, \
                    started_at, ended_at, exit_code \
             FROM runs ORDER BY started_at DESC",
            [],
            |r| {
                Ok(json!({
                    "key": r.get::<_, String>(0)?,
                    "command": r.get::<_, String>(1)?,
                    "name": r.get::<_, Option<String>>(2)?,
                    "out_dir": r.get::<_, String>(3)?,
                    "terminal_log_path": r.get::<_, Option<String>>(4)?,
                    "text_path": r.get::<_, Option<String>>(5)?,
                    "started_at": r.get::<_, i64>(6)?,
                    "ended_at": r.get::<_, Option<i64>>(7)?,
                    "exit_code": r.get::<_, Option<i64>>(8)?,
                }))
            },
        )
        .map_err(logbook_store::StoreError::from)
    })?;
    Ok(json!({ "count": rows.len(), "runs": rows }))
}

/// Resolve a run key (or the latest) to its `trace_id`/`session_id` hint, if the
/// run row carries one in its body-less columns. Runs don't store a trace id
/// column, so log lines are matched by session/run via events; here we just
/// return the run record for `get_run_status`.
fn run_record(conn: &Connection, run: Option<&str>) -> rusqlite::Result<Option<Value>> {
    let sql_latest = "SELECT key, command, name, started_at, ended_at, exit_code \
                      FROM runs ORDER BY started_at DESC LIMIT 1";
    let sql_keyed = "SELECT key, command, name, started_at, ended_at, exit_code \
                     FROM runs WHERE key = ?1 LIMIT 1";
    let map = |r: &rusqlite::Row| {
        Ok(json!({
            "key": r.get::<_, String>(0)?,
            "command": r.get::<_, String>(1)?,
            "name": r.get::<_, Option<String>>(2)?,
            "started_at": r.get::<_, i64>(3)?,
            "ended_at": r.get::<_, Option<i64>>(4)?,
            "exit_code": r.get::<_, Option<i64>>(5)?,
        }))
    };
    let row = match run {
        Some(key) => conn.query_row(sql_keyed, [key], map).ok(),
        None => conn.query_row(sql_latest, [], map).ok(),
    };
    Ok(row)
}

/// `tail_log` — the most recent application-log events, newest-first. Optionally
/// scoped to a run key (matched by session id == run key, the convention used by
/// the capture pipeline).
pub fn tail_log(store: &Store, params: &TailLogParams) -> anyhow::Result<Value> {
    let mut q = Query::new().category(Category::AppLog).limit(params.limit);
    if let Some(run) = &params.run {
        q = q.session(run.clone());
    }
    let events = store.query(&q)?;
    Ok(ListResult::new(events_to_values(&events)).into_value())
}

/// `search_logs` — full-text search over captured text (FTS5 MATCH).
pub fn search_logs(store: &Store, params: &SearchLogsParams) -> anyhow::Result<Value> {
    let q = Query::new().search(params.query.clone()).limit(params.limit);
    let events = store.query(&q)?;
    Ok(ListResult::new(events_to_values(&events)).into_value())
}

/// `get_errors` — recent events whose status is `error`, optionally for one
/// trace.
pub fn get_errors(store: &Store, params: &GetErrorsParams) -> anyhow::Result<Value> {
    // Pull a window newest-first, then keep the error-status ones. (Status is a
    // denormalized column but the public Query API filters by category/trace/
    // session/text/time; we post-filter on the reconstructed events.)
    let mut q = Query::new().limit(params.limit.saturating_mul(4).max(params.limit));
    if let Some(trace) = &params.trace_id {
        q = q.trace(trace.clone());
    }
    let events = store.query(&q)?;
    let errors: Vec<Value> = events
        .iter()
        .filter(|e| e.status == logbook_core::Status::Error || e.error.is_some())
        .take(params.limit as usize)
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();
    Ok(ListResult::new(errors).into_value())
}

/// `get_run_status` — the run-index record for a run key (or the latest run).
pub fn get_run_status(store: &Store, params: &GetRunStatusParams) -> anyhow::Result<Value> {
    let run = params.run.clone();
    let record = store.read(move |conn: &Connection| {
        run_record(conn, run.as_deref())
            .map_err(logbook_store::StoreError::from)
    })?;
    match record {
        Some(rec) => {
            // Derive a coarse status from the columns.
            let status = if rec.get("ended_at").map(Value::is_null).unwrap_or(true) {
                "running"
            } else if rec.get("exit_code") == Some(&json!(0)) {
                "ok"
            } else {
                "error"
            };
            Ok(json!({ "found": true, "status": status, "run": rec }))
        }
        None => Ok(json!({ "found": false })),
    }
}

/// `watch_log` — pull-based: app-log events newer than a microsecond cursor.
pub fn watch_log(store: &Store, params: &WatchLogParams) -> anyhow::Result<Value> {
    let mut q = Query::new().category(Category::AppLog).limit(params.limit);
    if let Some(since) = params.since_micros {
        // Half-open (strictly newer): query is inclusive, so bump by 1µs.
        q = q.time_range(since.saturating_add(1), i64::MAX);
        q = q.oldest_first();
    }
    let events = store.query(&q)?;
    // The next cursor is the max timestamp we returned (so the client can poll
    // forward).
    let next_cursor = events.iter().map(|e| e.timestamp.as_micros()).max();
    Ok(json!({
        "count": events.len(),
        "next_cursor_micros": next_cursor,
        "items": events_to_values(&events),
    }))
}

// ===========================================================================
// Browser lane
// ===========================================================================

/// Build a browser-category query from the common session/trace/limit filters.
fn browser_query(session_id: &Option<String>, trace_id: &Option<String>, limit: u32) -> Query {
    let mut q = Query::new().category(Category::Browser).limit(limit);
    if let Some(s) = session_id {
        q = q.session(s.clone());
    }
    if let Some(t) = trace_id {
        q = q.trace(t.clone());
    }
    q
}

/// `browser_console` — captured browser console events.
pub fn browser_console(store: &Store, params: &BrowserConsoleParams) -> anyhow::Result<Value> {
    let q = browser_query(&params.session_id, &params.trace_id, params.limit);
    let events: Vec<Value> = store
        .query(&q)?
        .iter()
        .filter(|e| e.blocks.console.is_some() || e.type_ == "console")
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();
    Ok(ListResult::new(events).into_value())
}

/// `browser_network` — captured browser network events.
pub fn browser_network(store: &Store, params: &BrowserNetworkParams) -> anyhow::Result<Value> {
    let q = browser_query(&params.session_id, &params.trace_id, params.limit);
    let events: Vec<Value> = store
        .query(&q)?
        .iter()
        .filter(|e| e.blocks.network.is_some() || e.type_.contains("network") || e.type_ == "fetch")
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();
    Ok(ListResult::new(events).into_value())
}

/// `browser_get_request` — one captured network event by id.
pub fn browser_get_request(store: &Store, params: &BrowserGetRequestParams) -> anyhow::Result<Value> {
    let event = find_event_by_id(store, &params.event_id)?;
    match event {
        Some(e) => Ok(json!({ "found": true, "event": serde_json::to_value(&e)? })),
        None => Ok(json!({ "found": false })),
    }
}

/// `browser_dom` — the most recent DOM-snapshot event for a session/trace.
pub fn browser_dom(store: &Store, params: &BrowserDomParams) -> anyhow::Result<Value> {
    // DOM snapshots are browser-category events with type `dom` (newest-first
    // gives us the latest).
    let q = browser_query(&params.session_id, &params.trace_id, 50);
    let latest = store
        .query(&q)?
        .into_iter()
        .find(|e| e.type_ == "dom" || e.operation == "dom_snapshot");
    match latest {
        Some(e) => Ok(json!({ "found": true, "event": serde_json::to_value(&e)? })),
        None => Ok(json!({ "found": false })),
    }
}

// ===========================================================================
// Timeline lane
// ===========================================================================

/// `query_timeline` — the unified timeline with category/time/session/text
/// filters.
pub fn query_timeline(store: &Store, params: &QueryTimelineParams) -> anyhow::Result<Value> {
    let mut q = Query::new().limit(params.limit);
    if let Some(cat) = &params.category {
        q = q.category(parse_category(cat)?);
    }
    if let (Some(since), Some(until)) = (params.since_micros, params.until_micros) {
        q = q.time_range(since, until);
    } else if let Some(since) = params.since_micros {
        q = q.time_range(since, i64::MAX);
    } else if let Some(until) = params.until_micros {
        q = q.time_range(i64::MIN, until);
    }
    if let Some(s) = &params.session_id {
        q = q.session(s.clone());
    }
    if let Some(text) = &params.query {
        q = q.search(text.clone());
    }
    let events = store.query(&q)?;
    Ok(ListResult::new(events_to_values(&events)).into_value())
}

/// `get_trace` — every event on a trace, oldest-first.
pub fn get_trace(store: &Store, params: &GetTraceParams) -> anyhow::Result<Value> {
    let events = store.trace(&params.trace_id)?;
    Ok(ListResult::new(events_to_values(&events)).into_value())
}

/// `correlate` — resolve an event id to its trace, then return the full trace.
pub fn correlate(store: &Store, params: &CorrelateParams) -> anyhow::Result<Value> {
    let event = find_event_by_id(store, &params.event_id)?
        .ok_or_else(|| anyhow!("event not found: {}", params.event_id))?;
    let trace_hex = event.trace_id.to_hex();
    let events = store.trace(&trace_hex)?;
    Ok(json!({
        "trace_id": trace_hex,
        "count": events.len(),
        "items": events_to_values(&events),
    }))
}

/// Look up a single event by its id (the SQLite primary key) via the body
/// column, reconstructing the full `Event`.
fn find_event_by_id(store: &Store, id: &str) -> anyhow::Result<Option<Event>> {
    let id = id.to_string();
    let body: Option<String> = store.read(move |conn: &Connection| {
        conn.query_row(
            "SELECT body FROM events WHERE id = ?1 LIMIT 1",
            [&id],
            |r| r.get::<_, String>(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(logbook_store::StoreError::from(other)),
        })
    })?;
    match body {
        Some(b) => Ok(Some(serde_json::from_str(&b).context("decode event body")?)),
        None => Ok(None),
    }
}

// ===========================================================================
// Findings lane (backed by the `findings` SQL table)
// ===========================================================================

/// `list_findings` — security findings newest-first, with optional source and
/// minimum-severity filters.
pub fn list_findings(store: &Store, params: &ListFindingsParams) -> anyhow::Result<Value> {
    let source = params.source.clone();
    // Parse the minimum severity once via the canonical core enum; comparisons
    // below use its derived `Ord` (Info < Low < … < Critical).
    let min_severity: Option<Severity> = match &params.min_severity {
        Some(s) => Some(Severity::from_wire(s).ok_or_else(|| anyhow!("unknown severity: {s}"))?),
        None => None,
    };
    let limit = params.limit;
    let rows = store.read(move |conn: &Connection| {
        let mut sql = String::from(
            "SELECT id, event_id, trace_id, source, rule_id, severity, file, line, message, created_at \
             FROM findings",
        );
        let mut wheres: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        if let Some(src) = &source {
            wheres.push("source = ?".to_string());
            binds.push(src.clone());
        }
        if !wheres.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&wheres.join(" AND "));
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT ");
        sql.push_str(&limit.to_string());

        let binds_ref: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        read_rows(conn, &sql, binds_ref.as_slice(), |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "event_id": r.get::<_, Option<String>>(1)?,
                "trace_id": r.get::<_, Option<String>>(2)?,
                "source": r.get::<_, String>(3)?,
                "rule_id": r.get::<_, Option<String>>(4)?,
                "severity": r.get::<_, Option<String>>(5)?,
                "file": r.get::<_, Option<String>>(6)?,
                "line": r.get::<_, Option<i64>>(7)?,
                "message": r.get::<_, Option<String>>(8)?,
                "created_at": r.get::<_, i64>(9)?,
            }))
        })
        .map_err(logbook_store::StoreError::from)
    })?;

    // Apply the min-severity post-filter (severity is a text column; ranking in
    // Rust keeps the SQL simple and the ordering stable). Comparison uses the
    // core `Severity` ordering rather than a bespoke rank map.
    let filtered: Vec<Value> = rows
        .into_iter()
        .filter(|f| match min_severity {
            None => true,
            Some(min) => f
                .get("severity")
                .and_then(Value::as_str)
                .and_then(Severity::from_wire)
                .map(|sev| sev >= min)
                .unwrap_or(false),
        })
        .collect();
    Ok(ListResult::new(filtered).into_value())
}

/// `get_finding` — a single finding by id.
pub fn get_finding(store: &Store, params: &GetFindingParams) -> anyhow::Result<Value> {
    let id = params.id.clone();
    let row = store.read(move |conn: &Connection| {
        conn.query_row(
            "SELECT id, event_id, trace_id, source, rule_id, severity, file, line, message, created_at \
             FROM findings WHERE id = ?1 LIMIT 1",
            [&id],
            |r| {
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "event_id": r.get::<_, Option<String>>(1)?,
                    "trace_id": r.get::<_, Option<String>>(2)?,
                    "source": r.get::<_, String>(3)?,
                    "rule_id": r.get::<_, Option<String>>(4)?,
                    "severity": r.get::<_, Option<String>>(5)?,
                    "file": r.get::<_, Option<String>>(6)?,
                    "line": r.get::<_, Option<i64>>(7)?,
                    "message": r.get::<_, Option<String>>(8)?,
                    "created_at": r.get::<_, i64>(9)?,
                }))
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(logbook_store::StoreError::from(other)),
        })
    })?;
    match row {
        Some(f) => Ok(json!({ "found": true, "finding": f })),
        None => Ok(json!({ "found": false })),
    }
}

// ===========================================================================
// Debug lane
// ===========================================================================

/// `debug_fetch_evidence` — the captured events correlated to a debug session.
///
/// Looks the session up in `debug_sessions` for its trace id, then returns that
/// trace's events (the passive Tier-1 evidence). If the session has no trace
/// yet, returns the events tagged with the session id directly.
pub fn debug_fetch_evidence(store: &Store, params: &DebugFetchEvidenceParams) -> anyhow::Result<Value> {
    let session = params.session_id.clone();
    let trace_id: Option<String> = store.read(move |conn: &Connection| {
        conn.query_row(
            "SELECT trace_id FROM debug_sessions WHERE id = ?1 LIMIT 1",
            [&session],
            |r| r.get::<_, Option<String>>(0),
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(logbook_store::StoreError::from(other)),
        })
    })?;

    let events = match trace_id {
        Some(t) if !t.is_empty() => store.trace(&t)?,
        _ => store.query(&Query::new().session(params.session_id.clone()).limit(params.limit))?,
    };
    let items: Vec<Value> = events
        .iter()
        .take(params.limit as usize)
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();
    Ok(json!({
        "session_id": params.session_id,
        "count": items.len(),
        "items": items,
    }))
}

// ===========================================================================
// Inventory lane (read) — backed by inventory SQL tables
// ===========================================================================

/// `inventory_list_agents` — coding-agent CLIs discovered on this endpoint.
pub fn inventory_list_agents(store: &Store) -> anyhow::Result<Value> {
    let rows = store.read(|conn: &Connection| {
        read_rows(
            conn,
            "SELECT id, endpoint_id, name, version, path, sanctioned, discovered_at \
             FROM agent_installs ORDER BY name ASC",
            [],
            |r| {
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "endpoint_id": r.get::<_, String>(1)?,
                    "name": r.get::<_, String>(2)?,
                    "version": r.get::<_, Option<String>>(3)?,
                    "path": r.get::<_, Option<String>>(4)?,
                    "sanctioned": r.get::<_, i64>(5)? != 0,
                    "discovered_at": r.get::<_, i64>(6)?,
                }))
            },
        )
        .map_err(logbook_store::StoreError::from)
    })?;
    Ok(ListResult::new(rows).into_value())
}

/// `inventory_list_mcp` — MCP servers found in known config locations.
pub fn inventory_list_mcp(store: &Store) -> anyhow::Result<Value> {
    let rows = store.read(|conn: &Connection| {
        read_rows(
            conn,
            "SELECT id, endpoint_id, name, source_config, command, transport, sanctioned, has_secret, discovered_at \
             FROM mcp_servers ORDER BY name ASC",
            [],
            |r| {
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "endpoint_id": r.get::<_, String>(1)?,
                    "name": r.get::<_, String>(2)?,
                    "source_config": r.get::<_, Option<String>>(3)?,
                    "command": r.get::<_, Option<String>>(4)?,
                    "transport": r.get::<_, Option<String>>(5)?,
                    "sanctioned": r.get::<_, i64>(6)? != 0,
                    "has_secret": r.get::<_, i64>(7)? != 0,
                    "discovered_at": r.get::<_, i64>(8)?,
                }))
            },
        )
        .map_err(logbook_store::StoreError::from)
    })?;
    Ok(ListResult::new(rows).into_value())
}

/// `inventory_list_sessions` — recorded `logbook agent <cli>` sessions.
pub fn inventory_list_sessions(store: &Store, params: &InventoryListSessionsParams) -> anyhow::Result<Value> {
    let agent = params.agent.clone();
    let limit = params.limit;
    let rows = store.read(move |conn: &Connection| {
        let mut sql = String::from(
            "SELECT id, endpoint_id, agent, command, trace_id, started_at, ended_at, exit_code \
             FROM agent_sessions",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(a) = &agent {
            sql.push_str(" WHERE agent = ?");
            binds.push(a.clone());
        }
        sql.push_str(" ORDER BY started_at DESC LIMIT ");
        sql.push_str(&limit.to_string());
        let binds_ref: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        read_rows(conn, &sql, binds_ref.as_slice(), |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "endpoint_id": r.get::<_, Option<String>>(1)?,
                "agent": r.get::<_, String>(2)?,
                "command": r.get::<_, String>(3)?,
                "trace_id": r.get::<_, Option<String>>(4)?,
                "started_at": r.get::<_, i64>(5)?,
                "ended_at": r.get::<_, Option<i64>>(6)?,
                "exit_code": r.get::<_, Option<i64>>(7)?,
            }))
        })
        .map_err(logbook_store::StoreError::from)
    })?;
    Ok(ListResult::new(rows).into_value())
}

/// `inventory_findings` — risk/shadow findings (advisory, local-only).
pub fn inventory_findings(store: &Store, params: &InventoryFindingsParams) -> anyhow::Result<Value> {
    let kind = params.kind.clone();
    let limit = params.limit;
    let rows = store.read(move |conn: &Connection| {
        let mut sql = String::from(
            "SELECT id, endpoint_id, kind, severity, subject, message, created_at \
             FROM inventory_findings",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(k) = &kind {
            sql.push_str(" WHERE kind = ?");
            binds.push(k.clone());
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT ");
        sql.push_str(&limit.to_string());
        let binds_ref: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        read_rows(conn, &sql, binds_ref.as_slice(), |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "endpoint_id": r.get::<_, Option<String>>(1)?,
                "kind": r.get::<_, String>(2)?,
                "severity": r.get::<_, Option<String>>(3)?,
                "subject": r.get::<_, Option<String>>(4)?,
                "message": r.get::<_, Option<String>>(5)?,
                "created_at": r.get::<_, i64>(6)?,
            }))
        })
        .map_err(logbook_store::StoreError::from)
    })?;
    Ok(ListResult::new(rows).into_value())
}

/// `inventory_report` — a combined endpoint/agents/mcp/sessions/risk snapshot
/// (the human/JSON report; the UI renders the same data as tabs).
pub fn inventory_report(store: &Store) -> anyhow::Result<Value> {
    let endpoints = store.read(|conn: &Connection| {
        read_rows(
            conn,
            "SELECT id, hostname, os, arch, first_seen, last_seen FROM endpoints ORDER BY last_seen DESC",
            [],
            |r| {
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "hostname": r.get::<_, String>(1)?,
                    "os": r.get::<_, Option<String>>(2)?,
                    "arch": r.get::<_, Option<String>>(3)?,
                    "first_seen": r.get::<_, i64>(4)?,
                    "last_seen": r.get::<_, i64>(5)?,
                }))
            },
        )
        .map_err(logbook_store::StoreError::from)
    })?;

    let agents = inventory_list_agents(store)?;
    let mcp = inventory_list_mcp(store)?;
    let sessions = inventory_list_sessions(store, &InventoryListSessionsParams::default())?;
    let risk = inventory_findings(store, &InventoryFindingsParams::default())?;

    Ok(json!({
        "endpoints": endpoints,
        "agents": agents,
        "mcp_servers": mcp,
        "sessions": sessions,
        "risk": risk,
    }))
}

// ===========================================================================
// Write tools — v1 stubs (only reachable when the permission gate allows them)
// ===========================================================================

/// A uniform response for the v1 write-tool stubs: the call was *permitted*
/// (it passed the gate, or this function wouldn't run), but the underlying
/// machinery lives in a sibling crate not wired in this phase.
fn write_stub(tool: &str, detail: Value) -> Value {
    json!({
        "ok": false,
        "tool": tool,
        "status": "permitted_but_not_implemented",
        "message": format!(
            "`{tool}` is enabled by your logbook.toml permissions, but its action \
             is implemented in a sibling crate not wired into this MCP build yet."
        ),
        "echo": detail,
    })
}

/// `browser_navigate` (gated). v1 stub.
pub fn browser_navigate(_store: &Store, params: &BrowserNavigateParams) -> anyhow::Result<Value> {
    Ok(write_stub(
        "browser_navigate",
        json!({ "url": params.url, "session_id": params.session_id }),
    ))
}

/// `browser_record` (gated). v1 stub.
pub fn browser_record(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("browser_record", json!({})))
}

/// `browser_replay` (gated). v1 stub.
pub fn browser_replay(_store: &Store, params: &BrowserReplayParams) -> anyhow::Result<Value> {
    Ok(write_stub("browser_replay", json!({ "session_id": params.session_id })))
}

/// `browser_screenshot` (gated). v1 stub.
pub fn browser_screenshot(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("browser_screenshot", json!({})))
}

/// `browser_start_session` (gated). v1 stub.
pub fn browser_start_session(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("browser_start_session", json!({})))
}

/// `debug_set_logpoint` (gated, alpha). v1 stub.
pub fn debug_set_logpoint(_store: &Store, params: &DebugSetLogpointParams) -> anyhow::Result<Value> {
    Ok(write_stub(
        "debug_set_logpoint",
        json!({ "file": params.file, "line": params.line, "expression": params.expression }),
    ))
}

/// `debug_enable_trace` (gated). v1 stub.
pub fn debug_enable_trace(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("debug_enable_trace", json!({})))
}

/// `debug_start_session` (gated). v1 stub.
pub fn debug_start_session(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("debug_start_session", json!({})))
}

/// `debug_end_session` (gated). v1 stub.
pub fn debug_end_session(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("debug_end_session", json!({})))
}

/// `security_scan` (gated). v1 stub.
pub fn security_scan(_store: &Store, params: &SecurityScanParams) -> anyhow::Result<Value> {
    Ok(write_stub(
        "security_scan",
        json!({ "scanner": params.scanner, "path": params.path }),
    ))
}

/// `scan_agent_diff` (gated). v1 stub.
pub fn scan_agent_diff(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("scan_agent_diff", json!({})))
}

/// `inventory_scan` (gated). v1 stub.
pub fn inventory_scan(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("inventory_scan", json!({})))
}

/// `inventory_watch` (gated). v1 stub.
pub fn inventory_watch(_store: &Store) -> anyhow::Result<Value> {
    Ok(write_stub("inventory_watch", json!({})))
}

/// `export_otel` (gated). v1 stub.
pub fn export_otel(_store: &Store, params: &ExportOtelParams) -> anyhow::Result<Value> {
    Ok(write_stub("export_otel", json!({ "trace_id": params.trace_id })))
}

// ---------------------------------------------------------------------------

impl ListResult {
    /// Serialize this envelope to a JSON value (infallible — the fields are
    /// plain).
    fn into_value(self) -> Value {
        json!({ "count": self.count, "items": self.items })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{
        Category, ConsoleBlock, Event, Kind, MicrosTimestamp, NetworkBlock, SessionId, TraceId,
    };

    fn store_with_some_events() -> (Store, TraceId) {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        // Two app logs, one of them an error.
        store
            .insert(&Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("hello world"))
            .unwrap();
        store
            .insert(
                &Event::new(trace, Kind::Log, Category::AppLog, "stderr")
                    .with_name("connection refused on port 8080")
                    .with_error("connection refused"),
            )
            .unwrap();
        // A browser console + network event.
        store
            .insert(
                &Event::new(trace, Kind::Browser, Category::Browser, "console")
                    .with_console(ConsoleBlock {
                        level: Some("error".into()),
                        message: Some("ReferenceError: x is not defined".into()),
                        ..Default::default()
                    }),
            )
            .unwrap();
        store
            .insert(
                &Event::new(trace, Kind::Network, Category::Browser, "fetch")
                    .with_network(NetworkBlock {
                        method: Some("GET".into()),
                        url: Some("https://example.test/api".into()),
                        status_code: Some(500),
                        ..Default::default()
                    }),
            )
            .unwrap();
        (store, trace)
    }

    #[test]
    fn tail_returns_app_logs() {
        let (store, _t) = store_with_some_events();
        let out = tail_log(&store, &TailLogParams::default()).unwrap();
        assert_eq!(out["count"], json!(2), "two app-log events");
    }

    #[test]
    fn search_finds_text() {
        let (store, _t) = store_with_some_events();
        let out = search_logs(
            &store,
            &SearchLogsParams { query: "refused".into(), limit: 50 },
        )
        .unwrap();
        assert_eq!(out["count"], json!(1));
    }

    #[test]
    fn get_errors_filters_to_errors() {
        let (store, _t) = store_with_some_events();
        let out = get_errors(&store, &GetErrorsParams::default()).unwrap();
        assert_eq!(out["count"], json!(1), "only the errored event");
    }

    #[test]
    fn browser_console_and_network_split() {
        let (store, _t) = store_with_some_events();
        let console = browser_console(&store, &BrowserConsoleParams::default()).unwrap();
        assert_eq!(console["count"], json!(1));
        let network = browser_network(&store, &BrowserNetworkParams::default()).unwrap();
        assert_eq!(network["count"], json!(1));
    }

    #[test]
    fn get_trace_and_correlate_roundtrip() {
        let (store, trace) = store_with_some_events();
        let hex = trace.to_hex();
        let out = get_trace(&store, &GetTraceParams { trace_id: hex.clone() }).unwrap();
        assert_eq!(out["count"], json!(4), "all four events on the trace");

        // Grab one event id from the trace and correlate back.
        let first_id = out["items"][0]["id"].as_str().unwrap().to_string();
        let corr = correlate(&store, &CorrelateParams { event_id: first_id }).unwrap();
        assert_eq!(corr["trace_id"], json!(hex));
        assert_eq!(corr["count"], json!(4));
    }

    #[test]
    fn correlate_unknown_event_errors() {
        let (store, _t) = store_with_some_events();
        let err = correlate(&store, &CorrelateParams { event_id: "deadbeef".into() });
        assert!(err.is_err());
    }

    #[test]
    fn query_timeline_by_category() {
        let (store, _t) = store_with_some_events();
        let out = query_timeline(
            &store,
            &QueryTimelineParams {
                category: Some("browser".into()),
                limit: 50,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(out["count"], json!(2), "two browser-category events");
    }

    #[test]
    fn query_timeline_unknown_category_errors() {
        let (store, _t) = store_with_some_events();
        let err = query_timeline(
            &store,
            &QueryTimelineParams { category: Some("nope".into()), ..Default::default() },
        );
        assert!(err.is_err());
    }

    #[test]
    fn watch_log_advances_cursor() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let mut a = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("a");
        a.timestamp = MicrosTimestamp(100);
        let mut b = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("b");
        b.timestamp = MicrosTimestamp(200);
        store.insert(&a).unwrap();
        store.insert(&b).unwrap();

        // Watch since 100 → should only see b (strictly newer).
        let out = watch_log(&store, &WatchLogParams { since_micros: Some(100), limit: 50 }).unwrap();
        assert_eq!(out["count"], json!(1));
        assert_eq!(out["next_cursor_micros"], json!(200));
    }

    #[test]
    fn list_log_files_reads_runs_table() {
        let store = Store::open_in_memory().unwrap();
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO runs (key, command, name, out_dir, started_at) \
                     VALUES ('latest', 'cargo test', 'tests', '.logbook', 1000)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let out = list_log_files(&store).unwrap();
        assert_eq!(out["count"], json!(1));
        assert_eq!(out["runs"][0]["command"], json!("cargo test"));
    }

    #[test]
    fn get_run_status_running_vs_done() {
        let store = Store::open_in_memory().unwrap();
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO runs (key, command, out_dir, started_at, ended_at, exit_code) \
                     VALUES ('done', 'c', '.logbook', 1, 2, 0)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO runs (key, command, out_dir, started_at) \
                     VALUES ('live', 'c', '.logbook', 3)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let done = get_run_status(&store, &GetRunStatusParams { run: Some("done".into()) }).unwrap();
        assert_eq!(done["status"], json!("ok"));
        let live = get_run_status(&store, &GetRunStatusParams { run: Some("live".into()) }).unwrap();
        assert_eq!(live["status"], json!("running"));
        let missing = get_run_status(&store, &GetRunStatusParams { run: Some("ghost".into()) }).unwrap();
        assert_eq!(missing["found"], json!(false));
    }

    #[test]
    fn findings_list_and_get_and_severity_filter() {
        let store = Store::open_in_memory().unwrap();
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO findings (id, source, severity, message, created_at) \
                     VALUES ('f1', 'semgrep', 'high', 'sqli', 10)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO findings (id, source, severity, message, created_at) \
                     VALUES ('f2', 'trivy', 'low', 'old dep', 20)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

        let all = list_findings(&store, &ListFindingsParams::default()).unwrap();
        assert_eq!(all["count"], json!(2));

        let high = list_findings(
            &store,
            &ListFindingsParams { min_severity: Some("high".into()), ..Default::default() },
        )
        .unwrap();
        assert_eq!(high["count"], json!(1));

        let by_source = list_findings(
            &store,
            &ListFindingsParams { source: Some("trivy".into()), ..Default::default() },
        )
        .unwrap();
        assert_eq!(by_source["count"], json!(1));

        let one = get_finding(&store, &GetFindingParams { id: "f1".into() }).unwrap();
        assert_eq!(one["found"], json!(true));
        assert_eq!(one["finding"]["source"], json!("semgrep"));

        let none = get_finding(&store, &GetFindingParams { id: "nope".into() }).unwrap();
        assert_eq!(none["found"], json!(false));
    }

    #[test]
    fn inventory_read_tools_query_tables() {
        let store = Store::open_in_memory().unwrap();
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO endpoints (id, hostname, first_seen, last_seen) \
                     VALUES ('ep1', 'laptop', 1, 2)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO agent_installs (id, endpoint_id, name, sanctioned, discovered_at) \
                     VALUES ('a1', 'ep1', 'claude', 1, 5)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO mcp_servers (id, endpoint_id, name, sanctioned, has_secret, discovered_at) \
                     VALUES ('m1', 'ep1', 'shady-mcp', 0, 1, 6)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO agent_sessions (id, agent, command, started_at) \
                     VALUES ('s1', 'claude', 'claude --help', 7)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO inventory_findings (id, kind, severity, subject, message, created_at) \
                     VALUES ('if1', 'shadow_mcp', 'medium', 'shady-mcp', 'untracked MCP server', 8)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

        assert_eq!(inventory_list_agents(&store).unwrap()["count"], json!(1));
        let mcp = inventory_list_mcp(&store).unwrap();
        assert_eq!(mcp["count"], json!(1));
        assert_eq!(mcp["items"][0]["sanctioned"], json!(false));
        assert_eq!(mcp["items"][0]["has_secret"], json!(true));

        let sessions =
            inventory_list_sessions(&store, &InventoryListSessionsParams::default()).unwrap();
        assert_eq!(sessions["count"], json!(1));

        let risk = inventory_findings(&store, &InventoryFindingsParams::default()).unwrap();
        assert_eq!(risk["count"], json!(1));
        assert_eq!(risk["items"][0]["kind"], json!("shadow_mcp"));

        let report = inventory_report(&store).unwrap();
        assert_eq!(report["endpoints"][0]["hostname"], json!("laptop"));
        assert_eq!(report["agents"]["count"], json!(1));
        assert_eq!(report["risk"]["count"], json!(1));
    }

    #[test]
    fn debug_fetch_evidence_uses_session_trace() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let sess = SessionId::new("dbg-1");
        // Two events on the trace.
        store
            .insert(&Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_session(sess.clone()))
            .unwrap();
        store
            .write({
                let t = trace.to_hex();
                move |conn| {
                    conn.execute(
                        "INSERT INTO debug_sessions (id, trace_id, status, mode, started_at) \
                         VALUES ('dbg-1', ?1, 'active', 'passive', 1)",
                        [&t],
                    )?;
                    Ok(())
                }
            })
            .unwrap();

        let out = debug_fetch_evidence(
            &store,
            &DebugFetchEvidenceParams { session_id: "dbg-1".into(), limit: 50 },
        )
        .unwrap();
        assert_eq!(out["session_id"], json!("dbg-1"));
        assert_eq!(out["count"], json!(1));
    }

    #[test]
    fn write_stub_marks_not_implemented() {
        let store = Store::open_in_memory().unwrap();
        let out = security_scan(
            &store,
            &SecurityScanParams { scanner: "semgrep".into(), path: None },
        )
        .unwrap();
        assert_eq!(out["status"], json!("permitted_but_not_implemented"));
        assert_eq!(out["tool"], json!("security_scan"));
    }
}
