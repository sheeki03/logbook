-- logbook store schema, migration V3 — Orbit Phase 2 "Structured Agent Capture"
-- (plan: "Event-schema enrichment" + "Consolidated changes").
--
-- Additive only: refinery applies this AFTER V1 and V2, so the column/index here
-- are new. NEVER edit V1/V2 — refinery records applied migrations by version and
-- a checksum, and any edit to an already-applied file breaks the upgrade.
--
-- One change: an optional `events.turn` column for fast grouping of agent
-- steps by turn (the coarse user/assistant exchange index). The JSON `body`
-- stays the source of truth on read; this column is a denormalized projection
-- of the event's `AgentBlock.turn` (NULL when the event carries no agent block
-- or no turn). Pre-V3 rows read `turn = NULL` (unclassified), exactly like the
-- V2 `max_sensitivity` add.

-- ---------------------------------------------------------------------------
-- events — turn projection (fast turn-grouping for the turn/step tree)
-- ---------------------------------------------------------------------------
-- Zero-based turn index mirrored from `AgentBlock.turn`. NULL on pre-V3 rows
-- and on any event without an agent turn.
ALTER TABLE events ADD COLUMN turn INTEGER;

-- Covering index for per-session turn grouping/filtering
-- (`WHERE session_id = ? AND turn = ?`, and turn-ordered reads within a session).
CREATE INDEX idx_events_turn ON events (session_id, turn);
