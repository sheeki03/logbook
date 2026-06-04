-- logbook store schema, migration V1.
--
-- One wide `events` table is the spine (export-shaped, plan §2), mirrored into
-- an FTS5 virtual table for full-text search. Alongside it live the OpenLogs
-- `runs` index, security `findings`, `debug_sessions`, and the Endpoint
-- Inventory Lite tables. All timestamps are INTEGER microseconds since the
-- UNIX epoch. Secret content is redacted before insertion (plan §9).

-- ---------------------------------------------------------------------------
-- events — the unified event spine
-- ---------------------------------------------------------------------------
CREATE TABLE events (
    id          TEXT PRIMARY KEY,            -- EventId (idempotent upsert key)
    trace_id    TEXT NOT NULL,               -- W3C 128-bit trace id (hex)
    parent_id   TEXT,                         -- W3C 64-bit span id (hex), nullable
    timestamp   INTEGER NOT NULL,            -- microseconds since UNIX epoch
    duration_ms REAL,
    kind        TEXT NOT NULL,
    type        TEXT NOT NULL,
    category    TEXT NOT NULL,               -- agent|browser|app_log|code_test|security|inventory
    operation   TEXT NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'unset',
    error       TEXT,
    session_id  TEXT,
    -- Full event payload as canonical JSON (already redacted). The scalar
    -- columns above are denormalized projections for fast filtering/indexing.
    body        TEXT NOT NULL
);

CREATE INDEX idx_events_timestamp ON events (timestamp);
CREATE INDEX idx_events_trace     ON events (trace_id, timestamp);
CREATE INDEX idx_events_session   ON events (session_id, timestamp);
CREATE INDEX idx_events_category  ON events (category, timestamp);
CREATE INDEX idx_events_kind      ON events (kind, timestamp);

-- Full-text search over the human-meaningful text of each event. Kept in sync
-- by the triggers below. `content_rowid` ties FTS rows to events.rowid.
CREATE VIRTUAL TABLE events_fts USING fts5 (
    name,
    operation,
    error,
    body,
    content = 'events',
    content_rowid = 'rowid'
);

CREATE TRIGGER events_fts_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts (rowid, name, operation, error, body)
    VALUES (new.rowid, new.name, new.operation, new.error, new.body);
END;

CREATE TRIGGER events_fts_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts (events_fts, rowid, name, operation, error, body)
    VALUES ('delete', old.rowid, old.name, old.operation, old.error, old.body);
END;

CREATE TRIGGER events_fts_au AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts (events_fts, rowid, name, operation, error, body)
    VALUES ('delete', old.rowid, old.name, old.operation, old.error, old.body);
    INSERT INTO events_fts (rowid, name, operation, error, body)
    VALUES (new.rowid, new.name, new.operation, new.error, new.body);
END;

-- ---------------------------------------------------------------------------
-- runs — OpenLogs-style run index (one row per `logbook <cmd>` invocation)
-- ---------------------------------------------------------------------------
CREATE TABLE runs (
    key         TEXT PRIMARY KEY,            -- slug/name key (latest, my-cmd, ...)
    command     TEXT NOT NULL,
    name        TEXT,
    out_dir     TEXT NOT NULL,
    terminal_log_path TEXT,                  -- *.terminal.log (redacted transcript)
    text_path   TEXT,                         -- *.txt (ANSI-stripped)
    started_at  INTEGER NOT NULL,            -- microseconds
    ended_at    INTEGER,
    exit_code   INTEGER
);

CREATE INDEX idx_runs_started ON runs (started_at);

-- ---------------------------------------------------------------------------
-- findings — security findings (Semgrep/Trivy/cargo-audit + SARIF/JSON import)
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
    id          TEXT PRIMARY KEY,
    event_id    TEXT,                         -- correlated events.id, if any
    trace_id    TEXT,
    source      TEXT NOT NULL,               -- semgrep|trivy|cargo-audit|sarif|...
    rule_id     TEXT,
    severity    TEXT,                         -- info|low|medium|high|critical
    file        TEXT,
    line        INTEGER,
    message     TEXT,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE SET NULL
);

CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_source   ON findings (source);
CREATE INDEX idx_findings_trace    ON findings (trace_id);

-- ---------------------------------------------------------------------------
-- debug_sessions — passive + DAP-logpoint debug sessions (plan §6)
-- ---------------------------------------------------------------------------
CREATE TABLE debug_sessions (
    id          TEXT PRIMARY KEY,            -- SessionId
    trace_id    TEXT,
    status      TEXT NOT NULL,               -- active|fetched|ended
    mode        TEXT NOT NULL DEFAULT 'passive', -- passive|dap
    target      TEXT,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER
);

CREATE INDEX idx_debug_sessions_status ON debug_sessions (status);

-- ===========================================================================
-- Endpoint Inventory Lite tables (plan §7b)
-- ===========================================================================

-- endpoints — the local machine(s) this store has seen (v1: just this one)
CREATE TABLE endpoints (
    id          TEXT PRIMARY KEY,            -- stable endpoint id (e.g. host fingerprint)
    hostname    TEXT NOT NULL,
    os          TEXT,
    arch        TEXT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

-- agent_installs — coding-agent CLIs discovered on this endpoint
CREATE TABLE agent_installs (
    id          TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    name        TEXT NOT NULL,               -- claude|cursor|codex|gemini|aider|...
    version     TEXT,
    path        TEXT,                         -- resolved binary path on PATH
    sanctioned  INTEGER NOT NULL DEFAULT 1,  -- 0 = flagged as unsanctioned/shadow
    discovered_at INTEGER NOT NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE CASCADE
);

CREATE INDEX idx_agent_installs_endpoint ON agent_installs (endpoint_id);
CREATE INDEX idx_agent_installs_name     ON agent_installs (name);

-- mcp_servers — MCP servers configured in known config locations
CREATE TABLE mcp_servers (
    id          TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    source_config TEXT,                       -- which config file declared it
    command     TEXT,
    transport   TEXT,                         -- stdio|sse|http|ws
    sanctioned  INTEGER NOT NULL DEFAULT 1,  -- 0 = flagged as shadow/untracked
    has_secret  INTEGER NOT NULL DEFAULT 0,  -- 1 = config carried a (redacted) secret
    discovered_at INTEGER NOT NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE CASCADE
);

CREATE INDEX idx_mcp_servers_endpoint ON mcp_servers (endpoint_id);
CREATE INDEX idx_mcp_servers_name     ON mcp_servers (name);

-- agent_sessions — `logbook agent <cli>` sessions (the v2 #4 capture)
CREATE TABLE agent_sessions (
    id          TEXT PRIMARY KEY,            -- SessionId
    endpoint_id TEXT,
    agent       TEXT NOT NULL,
    command     TEXT NOT NULL,
    trace_id    TEXT,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    exit_code   INTEGER,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE SET NULL
);

CREATE INDEX idx_agent_sessions_agent   ON agent_sessions (agent);
CREATE INDEX idx_agent_sessions_started ON agent_sessions (started_at);

-- agent_actions — git/file diffs observed during an agent_session
CREATE TABLE agent_actions (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,               -- file_modified|file_added|file_deleted|git_commit|...
    path        TEXT,
    detail      TEXT,
    observed_at INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES agent_sessions (id) ON DELETE CASCADE
);

CREATE INDEX idx_agent_actions_session ON agent_actions (session_id);

-- inventory_findings — risk/shadow surfacing (advisory, local-only)
CREATE TABLE inventory_findings (
    id          TEXT PRIMARY KEY,
    endpoint_id TEXT,
    kind        TEXT NOT NULL,               -- unsanctioned_agent|shadow_mcp|mcp_secret|...
    severity    TEXT,
    subject     TEXT,                         -- the agent/mcp/path the finding is about
    message     TEXT,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE SET NULL
);

CREATE INDEX idx_inventory_findings_kind     ON inventory_findings (kind);
CREATE INDEX idx_inventory_findings_severity ON inventory_findings (severity);
