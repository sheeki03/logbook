-- logbook store schema, migration V4 — Orbit Phase 4 "Complete Tier & Fleet"
-- (plan: "Phase 4 — Complete Tier & Fleet" → hash-chain audit; plan "Consolidated
-- changes" lists `audit_log` under V3/Phase 4 — it lands here as its own V4 so
-- the V3 `events.turn` upgrade and this governance table version independently).
--
-- Additive only: refinery applies this AFTER V1, V2 and V3, so the table/index
-- here are new. NEVER edit V1–V3 — refinery records applied migrations by version
-- and a checksum, and any edit to an already-applied file breaks the upgrade.
--
-- ---------------------------------------------------------------------------
-- audit_log — tamper-EVIDENT hash chain over already-redacted stored records
-- ---------------------------------------------------------------------------
-- One append-only row per audited event. Each row's `row_hash` is
--   hex(sha256(prev_hash_bytes || canonical_json(event)))
-- where `prev_hash` is the previous row's `row_hash` (the genesis link is 64
-- hex zeros) and `canonical_json(event)` is the deterministic, key-sorted JSON
-- of the *stored, already-redacted* event body. The `seq` AUTOINCREMENT column
-- fixes the chain order independently of timestamps.
--
-- This proves stored rows were not altered/deleted AFTER they were recorded
-- (tamper-evidence over the redacted archive). It does NOT prove that raw
-- secrets were never captured before redaction — redaction happens upstream at
-- capture, and the `secrets` marker only records that redaction occurred, never
-- the value (plan "Top risks & mitigations" #2).
--
-- AUTOINCREMENT (not a bare INTEGER PRIMARY KEY) is deliberate: it guarantees
-- `seq` is strictly monotonic and never reuses a rowid even after deletes, so a
-- deleted-then-reinserted audit row cannot silently reclaim an earlier seq.
CREATE TABLE audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT, -- strictly monotonic chain index
    event_id   TEXT NOT NULL,                     -- the audited events.id
    prev_hash  TEXT NOT NULL,                     -- previous row_hash (genesis = 64 zeros)
    row_hash   TEXT NOT NULL,                     -- hex sha256(prev_hash || canonical_json)
    created_at INTEGER NOT NULL                   -- microseconds since UNIX epoch
);

-- Lookup of a stored event's audit links by the event it covers.
CREATE INDEX idx_audit_log_event_id ON audit_log (event_id);
