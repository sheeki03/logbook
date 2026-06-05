-- logbook store schema, migration V2 — Orbit capture policy (plan §1.2/§1.3,
-- "Retention & export").
--
-- Additive only: refinery applies this AFTER V1, so every column/table here is
-- new. Three changes:
--   1. events    += max_sensitivity (the most-sensitive class present in the
--      row, used by the per-class retention prune) + its covering index.
--   2. agent_actions += diff / diff_bytes / post_hash / revert_safe /
--      max_sensitivity — the Phase-1 session-accurate file-diff columns. WRITES
--      land in logbook-inventory (store_ext); this migration only adds storage.
--   3. session_transcripts — pointers + metadata for a captured agent session's
--      redacted transcript (the bulk bytes already live on disk).
--
-- The JSON `body` on `events` stays the source of truth on read; max_sensitivity
-- is a denormalized projection for fast retention filtering. SQLite only allows
-- one column per ALTER TABLE, so each add is its own statement.

-- ---------------------------------------------------------------------------
-- events — retention class projection
-- ---------------------------------------------------------------------------
-- Most-sensitive class present in the row (e.g. `transcript`, `tool_results`).
-- NULL on pre-V2 rows (unclassified — retained under the global default).
ALTER TABLE events ADD COLUMN max_sensitivity TEXT;

-- Covering index for the conservative per-class prune
-- (`DELETE … WHERE max_sensitivity=? AND timestamp<?`).
CREATE INDEX idx_events_max_sensitivity ON events (max_sensitivity, timestamp);

-- ---------------------------------------------------------------------------
-- agent_actions — Phase-1 session-accurate file diffs (redacted-only)
-- ---------------------------------------------------------------------------
-- Redacted, size-capped per-file diff (redacted start→end content). NULL when
-- diffs are off or the file exceeded the baseline caps (diff omitted).
ALTER TABLE agent_actions ADD COLUMN diff TEXT;
-- Original (pre-truncation) diff byte length; `diff_bytes > length(diff)` flags
-- a truncated body so the UI can render a "truncated" badge.
ALTER TABLE agent_actions ADD COLUMN diff_bytes INTEGER;
-- Post-state content hash of the file after the session change. `logbook revert`
-- (Phase 3) only applies if the file still matches this hash.
ALTER TABLE agent_actions ADD COLUMN post_hash TEXT;
-- Whether this action can be safely reverted (clean tree at start, or an opt-in
-- encrypted preimage was stored). 0 by default (dirty-tree, redacted-diff-only).
ALTER TABLE agent_actions ADD COLUMN revert_safe INTEGER NOT NULL DEFAULT 0;
-- Most-sensitive class present in the action (typically `file_diffs`).
ALTER TABLE agent_actions ADD COLUMN max_sensitivity TEXT;

-- ---------------------------------------------------------------------------
-- session_transcripts — transcript pointers + metadata, not bulk bytes
-- ---------------------------------------------------------------------------
-- The redacted transcript files already live on disk; this row points at them
-- (written by the wrapper from CaptureOutcome) so replay can stream the file or
-- render structured per-line events (already in `events` under the shared trace).
CREATE TABLE session_transcripts (
    session_id        TEXT PRIMARY KEY,        -- SessionId (== agent_sessions.id)
    trace_id          TEXT NOT NULL,           -- shared trace across all artifacts
    terminal_log_path TEXT,                    -- *.terminal.log (redacted transcript)
    text_path         TEXT,                    -- *.txt (ANSI-stripped)
    line_count        INTEGER,
    byte_size         INTEGER,
    max_sensitivity   TEXT NOT NULL DEFAULT 'transcript',
    created_at        INTEGER NOT NULL,        -- microseconds since UNIX epoch
    FOREIGN KEY (session_id) REFERENCES agent_sessions (id) ON DELETE CASCADE
);
