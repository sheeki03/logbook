//! Phase-4 hash-chain audit + fleet receive (plan "Phase 4 — Complete Tier &
//! Fleet").
//!
//! Two governance capabilities live here, both built on the existing `events`
//! spine plus the V4 `audit_log` table:
//!
//! - [`append_audit`] / [`verify_chain`] — a **tamper-evident hash chain** over
//!   the *already-redacted* stored event records. Each appended row links to the
//!   previous via `row_hash = hex(sha256(prev_hash_bytes || canonical_json(event)))`
//!   (genesis link = 64 hex zeros). [`verify_chain`] recomputes the whole chain
//!   from the current stored event bodies in `seq` order and reports the first
//!   break, so mutating or deleting a stored event's body becomes detectable.
//! - [`hub_receive`] — the **fleet receiver** insert path: an idempotent
//!   upsert-by-id (`INSERT OR IGNORE` on the `events.id` primary key) for events
//!   forwarded from a local plane, returning how many were newly inserted.
//!
//! # What the chain proves (and what it does NOT)
//!
//! The chain is **tamper-evidence over stored, already-redacted rows**: it shows
//! that a row was not altered or removed *after* it was recorded. It does **not**
//! prove that raw secrets were never captured before redaction — redaction runs
//! upstream at capture (`logbook-core`), before anything reaches this store, and
//! the `secrets` marker records only that redaction *occurred*, never the value
//! (plan "Top risks & mitigations" #2). By the time an [`Event`] is audited here
//! it is already safe to persist; the chain attests to the integrity of that
//! redacted archive, nothing more.
//!
//! # Canonicalization
//!
//! [`canonical_json`] serializes an event to a **deterministic, key-sorted**
//! JSON string so the hash is stable across runs and independent of map/struct
//! field ordering (and of whether `serde_json`'s `preserve_order` feature is
//! enabled by some other crate in the build). Object keys are recursively sorted;
//! arrays keep their order (semantically meaningful); scalars are emitted
//! verbatim. This is the exact byte string fed into SHA-256.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use logbook_core::Event;

use crate::error::Result;
use crate::schema::{event_from_body, event_to_row};

/// The genesis `prev_hash`: 64 hex zeros (the all-zero 32-byte SHA-256 width).
/// The very first appended row links against this, so an empty chain has a
/// well-defined, constant root.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ===========================================================================
// canonical JSON
// ===========================================================================

/// Serialize `event` to a **canonical**, key-sorted JSON string — the exact
/// bytes hashed into the audit chain.
///
/// Determinism is load-bearing for a hash chain, so this does not rely on the
/// incidental ordering of [`serde_json::to_string`] (which depends on the
/// `serde_json/preserve_order` feature flag, something an unrelated dependency
/// could flip). Instead the event is lowered to a [`serde_json::Value`] and
/// re-emitted with every object's keys sorted recursively. Array order is
/// preserved (it is semantically meaningful); scalar values are unchanged.
///
/// # Persistence-stable normalization
///
/// The event is first round-tripped through its **stored body representation**
/// (`Event -> JSON body string -> Event`) before canonicalizing, so
/// [`append_audit`] (which hashes a possibly in-memory event) and
/// [`verify_chain`] (which hashes the body read back from `events`) always
/// agree by construction. This matters for fields whose in-memory and
/// round-tripped forms differ — e.g. a non-finite `f64` (`NaN`/`±inf`)
/// serializes to JSON `null`, then deserializes to `None`, which is then
/// *omitted* by `skip_serializing_if`. Normalizing through the body first means
/// the hash is computed over exactly what is (or will be) persisted and later
/// re-read, so a faithfully-stored row never falsely reports a chain break.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if the event fails to serialize
/// or the normalization round-trip fails to deserialize.
pub fn canonical_json(event: &Event) -> Result<String> {
    // Normalize through the stored-body form so in-memory and read-back events
    // canonicalize to identical bytes (see the "Persistence-stable" note above).
    let body = serde_json::to_string(event)?;
    let normalized: Event = serde_json::from_str(&body)?;
    let value = serde_json::to_value(&normalized)?;
    let mut out = String::new();
    write_canonical(&value, &mut out);
    Ok(out)
}

/// Recursively write `value` into `out` as compact JSON with object keys sorted
/// lexicographically (by Unicode scalar / UTF-8 byte order, which agree for the
/// ASCII field names the event model uses). Arrays keep their element order.
fn write_canonical(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            out.push('{');
            // Collect and sort keys; `serde_json::Map` may be insertion-ordered
            // (preserve_order) or already sorted (BTreeMap) depending on the
            // build, so sort explicitly to be order-independent either way.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // A key is a JSON string; reuse serde's string escaping so any
                // special characters are encoded canonically.
                write_json_string(key, out);
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        // Scalars (null/bool/number/string) have a single canonical compact
        // serde rendering; emit it directly. (`to_string` on a scalar Value is
        // infallible in practice; fall back to `null` to stay total.)
        other => out.push_str(&serde_json::to_string(other).unwrap_or_else(|_| "null".to_string())),
    }
}

/// Append `s` to `out` as a JSON string literal (quotes + serde escaping).
fn write_json_string(s: &str, out: &mut String) {
    // Delegate to serde for correct, canonical escaping of control/Unicode chars.
    match serde_json::to_string(s) {
        Ok(encoded) => out.push_str(&encoded),
        // `to_string` on a `&str` does not fail; keep total just in case.
        Err(_) => {
            out.push('"');
            out.push('"');
        }
    }
}

/// Compute `hex(sha256(prev_hash_bytes || canonical_bytes))`.
///
/// `prev_hash` is the previous row's `row_hash` (the genesis link is
/// [`GENESIS_HASH`]); its **UTF-8 bytes** are the chain link — the hex string is
/// hashed as-is, so the stored `audit_log.prev_hash`/`row_hash` text columns are
/// exactly the bytes that bind one row to the next. `canonical` is the
/// [`canonical_json`] of the event.
fn row_hash(prev_hash: &str, canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    hex_lower(digest.as_slice())
}

/// Lowercase-hex encode a byte slice (a 32-byte SHA-256 digest → 64 hex chars).
/// Inlined to avoid pulling in the `hex` crate for one trivial encoding.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ===========================================================================
// append_audit — extend the chain
// ===========================================================================

/// Append one audit-log row for `event`, extending the hash chain, and return
/// the new `row_hash`.
///
/// The new row's `prev_hash` is the `row_hash` of the current tail row (the
/// highest `seq`), or [`GENESIS_HASH`] when the chain is empty. The `row_hash`
/// is `hex(sha256(prev_hash_bytes || canonical_json(event)))` over the event's
/// canonical, already-redacted JSON. Inserts the
/// `(event_id, prev_hash, row_hash, created_at)` row with bound parameters and
/// returns the computed `row_hash`.
///
/// `created_at` is taken from the event's own microsecond timestamp so an audit
/// row is reproducible from its event and carries no fresh wall-clock dependency.
///
/// This only records integrity metadata over an already-stored, already-redacted
/// event; it does not read or persist any raw payload.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if the canonicalization, the tail
/// lookup, or the insert fails.
pub fn append_audit(conn: &Connection, event: &Event) -> Result<String> {
    let prev_hash: String = conn
        .query_row(
            "SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_else(|| GENESIS_HASH.to_string());

    let canonical = canonical_json(event)?;
    let hash = row_hash(&prev_hash, &canonical);

    conn.execute(
        "INSERT INTO audit_log (event_id, prev_hash, row_hash, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            event.id.as_str(),
            prev_hash,
            hash,
            event.timestamp.as_micros(),
        ],
    )?;

    Ok(hash)
}

// ===========================================================================
// verify_chain — recompute + report the first break
// ===========================================================================

/// Why a [`verify_chain`] declared the chain broken at a given row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakReason {
    /// The recorded `prev_hash` did not equal the running hash carried forward
    /// from the previous verified row (the chain link itself was tampered with,
    /// or a row was inserted/removed mid-chain).
    PrevHashMismatch {
        /// The `prev_hash` stored on this row.
        stored_prev: String,
        /// The `row_hash` the previous verified row actually produced.
        expected_prev: String,
    },
    /// The `events` row this audit entry covers is gone — its body was deleted,
    /// so the chain can no longer be recomputed over it (a deletion is a tamper).
    MissingEvent {
        /// The `events.id` that no longer resolves to a stored body.
        event_id: String,
    },
    /// The event still exists but its stored body no longer hashes to the
    /// recorded `row_hash` — the row's content was mutated after it was audited.
    RowHashMismatch {
        /// The `row_hash` recorded in `audit_log` for this row.
        stored: String,
        /// The `row_hash` recomputed from the current stored event body.
        recomputed: String,
    },
}

/// The location + reason of the first detected chain break.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditBreak {
    /// The `audit_log.seq` of the row where verification first failed.
    pub seq: i64,
    /// The `event_id` recorded on that row.
    pub event_id: String,
    /// Why the row failed verification.
    pub reason: BreakReason,
}

/// The result of a [`verify_chain`] pass over the whole `audit_log`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditVerification {
    /// Whether the chain verified cleanly end-to-end (`first_break.is_none()`).
    pub ok: bool,
    /// How many audit rows were inspected (the full chain length, regardless of
    /// where a break was found — verification stops *reporting* at the first
    /// break but the count reflects the rows walked up to and including it).
    pub checked: u64,
    /// The first break encountered in `seq` order, or `None` if the chain is
    /// intact. Verification reports only the first break (a single break makes
    /// every downstream link's recomputation diverge, so later "breaks" would be
    /// noise).
    pub first_break: Option<AuditBreak>,
}

impl AuditVerification {
    /// A clean verification over `checked` rows (no break).
    fn clean(checked: u64) -> Self {
        Self {
            ok: true,
            checked,
            first_break: None,
        }
    }
}

/// Recompute the hash chain from the current stored event bodies and report the
/// first break.
///
/// Walks `audit_log` in ascending `seq` order, carrying a running `prev`
/// (starting at [`GENESIS_HASH`]). For each row it:
/// 1. checks the row's recorded `prev_hash` equals the running `prev` — a
///    mismatch is a [`BreakReason::PrevHashMismatch`] (a tampered link, or an
///    inserted/removed row);
/// 2. loads the covered `events` body; if it is gone, that is a
///    [`BreakReason::MissingEvent`] (a deleted row);
/// 3. recomputes `row_hash` over the event's [`canonical_json`] and the running
///    `prev`; if it differs from the recorded `row_hash`, that is a
///    [`BreakReason::RowHashMismatch`] (a mutated body).
///
/// On the first failure it returns immediately with `ok = false` and the
/// [`AuditBreak`]; otherwise the running hash advances to this row's `row_hash`
/// and the walk continues. An empty `audit_log` verifies cleanly
/// (`ok = true, checked = 0`).
///
/// Because a single break desynchronizes every later link, only the first break
/// is reported — that is the actionable one.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if the read or a body
/// deserialization fails. A *missing* covered event is **not** an error — it is
/// reported as a [`BreakReason::MissingEvent`] break.
pub fn verify_chain(conn: &Connection) -> Result<AuditVerification> {
    let mut stmt = conn.prepare(
        "SELECT seq, event_id, prev_hash, row_hash FROM audit_log ORDER BY seq ASC",
    )?;
    let mut rows = stmt.query([])?;

    let mut prev = GENESIS_HASH.to_string();
    let mut checked: u64 = 0;

    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let event_id: String = row.get(1)?;
        let stored_prev: String = row.get(2)?;
        let stored_row_hash: String = row.get(3)?;
        checked += 1;

        // (1) The recorded link must match the running hash.
        if stored_prev != prev {
            return Ok(AuditVerification {
                ok: false,
                checked,
                first_break: Some(AuditBreak {
                    seq,
                    event_id,
                    reason: BreakReason::PrevHashMismatch {
                        stored_prev,
                        expected_prev: prev,
                    },
                }),
            });
        }

        // (2) Load the covered event body (source of truth on read).
        let body: Option<String> = conn
            .query_row(
                "SELECT body FROM events WHERE id = ?1",
                params![event_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(body) = body else {
            return Ok(AuditVerification {
                ok: false,
                checked,
                first_break: Some(AuditBreak {
                    seq,
                    event_id: event_id.clone(),
                    reason: BreakReason::MissingEvent { event_id },
                }),
            });
        };

        // (3) Recompute row_hash over the canonical body + running prev.
        let event = event_from_body(&body)?;
        let canonical = canonical_json(&event)?;
        let recomputed = row_hash(&prev, &canonical);
        if recomputed != stored_row_hash {
            return Ok(AuditVerification {
                ok: false,
                checked,
                first_break: Some(AuditBreak {
                    seq,
                    event_id,
                    reason: BreakReason::RowHashMismatch {
                        stored: stored_row_hash,
                        recomputed,
                    },
                }),
            });
        }

        // Advance the running hash to this verified row.
        prev = stored_row_hash;
    }

    Ok(AuditVerification::clean(checked))
}

// ===========================================================================
// hub_receive — idempotent fleet-receiver insert path
// ===========================================================================

/// Idempotently insert a batch of forwarded `events` by id, returning how many
/// were **newly** inserted (the fleet receiver's upsert-by-id path, plan
/// "Phase 4 — Complete Tier & Fleet" → Hub fleet receiver).
///
/// Each event is inserted with `INSERT OR IGNORE` keyed on the `events.id`
/// primary key, so re-receiving an event already present is a no-op and does not
/// overwrite the local copy (the local plane stays the source of truth on
/// conflict — plan "logbook-hub" stub). All parameters are bound; the whole
/// batch runs in one transaction. Returns the count of rows that did not already
/// exist (the sum of per-statement change counts, which `INSERT OR IGNORE`
/// reports as 0 for an ignored conflict and 1 for a fresh insert).
///
/// Forwarded events are already-redacted records (redaction happened on the
/// origin plane before forwarding); this path persists them as-is and performs
/// no payload inspection.
///
/// # Errors
/// Returns a [`StoreError`](crate::StoreError) if a row fails to serialize or the
/// insert transaction fails (in which case the whole batch rolls back).
pub fn hub_receive(conn: &mut Connection, events: &[Event]) -> Result<usize> {
    // The `events` insert column layout mirrors `writer::INSERT_SQL`, but with
    // OR IGNORE (skip-on-conflict) instead of OR REPLACE so an already-present
    // id is preserved, not overwritten.
    const INSERT_OR_IGNORE_SQL: &str = "INSERT OR IGNORE INTO events \
        (id, trace_id, parent_id, timestamp, duration_ms, kind, type, category, \
         operation, name, status, error, session_id, turn, max_sensitivity, body) \
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";

    let mut inserted = 0usize;
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(INSERT_OR_IGNORE_SQL)?;
        for event in events {
            let r = event_to_row(event)?;
            let changed = stmt.execute(params![
                r.id,
                r.trace_id,
                r.parent_id,
                r.timestamp,
                r.duration_ms,
                r.kind,
                r.type_,
                r.category,
                r.operation,
                r.name,
                r.status,
                r.error,
                r.session_id,
                r.turn,
                r.max_sensitivity,
                r.body,
            ])?;
            // `INSERT OR IGNORE` reports 1 change for a fresh row, 0 for an
            // ignored conflict — exactly the "newly inserted" count we want.
            inserted += changed;
        }
    }
    tx.commit()?;
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{
        AgentBlock, Category, Event, Kind, LlmBlock, MicrosTimestamp, SessionId, TraceId,
    };

    use crate::Store;

    // ---- canonical_json --------------------------------------------------

    #[test]
    fn canonical_json_is_stable_and_key_sorted() {
        // Two events that are equal but built so their attribute maps were
        // populated in different insertion orders must canonicalize identically,
        // and the keys must come out sorted.
        let trace = TraceId::new();

        let mut a = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("x");
        a.attributes.insert("zebra".into(), serde_json::json!(1));
        a.attributes.insert("alpha".into(), serde_json::json!(2));
        a.attributes.insert("mango".into(), serde_json::json!(3));

        let mut b = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("x");
        // Same id/timestamp as `a` so the two are genuinely equal events.
        b.id = a.id.clone();
        b.timestamp = a.timestamp;
        b.attributes.insert("mango".into(), serde_json::json!(3));
        b.attributes.insert("alpha".into(), serde_json::json!(2));
        b.attributes.insert("zebra".into(), serde_json::json!(1));

        assert_eq!(a, b, "the two events are equal");
        let ca = canonical_json(&a).unwrap();
        let cb = canonical_json(&b).unwrap();
        assert_eq!(ca, cb, "equal events canonicalize to identical bytes");

        // Keys are sorted: alpha < mango < zebra in the emitted string.
        let i_alpha = ca.find("\"alpha\"").unwrap();
        let i_mango = ca.find("\"mango\"").unwrap();
        let i_zebra = ca.find("\"zebra\"").unwrap();
        assert!(i_alpha < i_mango && i_mango < i_zebra, "attribute keys sorted: {ca}");
    }

    #[test]
    fn canonical_json_changes_when_body_changes() {
        let trace = TraceId::new();
        let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("before");
        let c1 = canonical_json(&ev).unwrap();
        ev.name = "after".to_string();
        let c2 = canonical_json(&ev).unwrap();
        assert_ne!(c1, c2, "a mutated field changes the canonical bytes");
    }

    // ---- append_audit + verify_chain -------------------------------------

    /// Append a known event and a couple more to a store's audit_log over the
    /// same writer connection, returning the inserted events for later mutation.
    fn seed_events(store: &Store, trace: TraceId) -> Vec<Event> {
        let mut events = Vec::new();
        let mut e0 = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("one");
        e0.timestamp = MicrosTimestamp(1_000);
        let mut e1 = Event::new(trace, Kind::Llm, Category::Agent, "chat.completion")
            .with_llm(LlmBlock {
                model: Some("claude".into()),
                ..Default::default()
            });
        e1.timestamp = MicrosTimestamp(2_000);
        let mut e2 = Event::new(trace, Kind::Agent, Category::Agent, "step")
            .with_name("three")
            .with_session(SessionId::new("sess-1"))
            .with_agent(AgentBlock {
                turn: Some(0),
                ..Default::default()
            });
        e2.timestamp = MicrosTimestamp(3_000);
        for e in [&e0, &e1, &e2] {
            store.insert(e).unwrap();
            events.push(e.clone());
        }
        events
    }

    #[test]
    fn append_then_verify_passes_over_several_events() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let events = seed_events(&store, trace);

        // Append all three to the chain through the single writer connection.
        let hashes = store
            .write_returning(move |conn| {
                let mut hs = Vec::new();
                for e in &events {
                    hs.push(append_audit(conn, e)?);
                }
                Ok(hs)
            })
            .unwrap();
        assert_eq!(hashes.len(), 3);
        // Each row_hash is a 64-char lowercase hex string and they differ.
        for h in &hashes {
            assert_eq!(h.len(), 64);
            assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        assert_ne!(hashes[0], hashes[1]);
        assert_ne!(hashes[1], hashes[2]);

        let v = store.read(verify_chain).unwrap();
        assert!(v.ok, "intact chain verifies: {v:?}");
        assert_eq!(v.checked, 3);
        assert!(v.first_break.is_none());
    }

    #[test]
    fn first_appended_row_links_to_genesis() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let mut ev = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("g");
        ev.timestamp = MicrosTimestamp(10);
        store.insert(&ev).unwrap();
        store
            .write_returning(move |conn| append_audit(conn, &ev))
            .unwrap();

        let prev: String = store
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT prev_hash FROM audit_log ORDER BY seq ASC LIMIT 1",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(prev, GENESIS_HASH, "genesis link is 64 zeros");
    }

    #[test]
    fn mutating_a_stored_event_body_breaks_the_chain() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let events = seed_events(&store, trace);
        let target_id = events[1].id.as_str().to_string();

        store
            .write_returning({
                let events = events.clone();
                move |conn| {
                    for e in &events {
                        append_audit(conn, e)?;
                    }
                    Ok(())
                }
            })
            .unwrap();

        // Sanity: clean before tampering.
        assert!(store.read(verify_chain).unwrap().ok);

        // Tamper with the SECOND event's stored body directly in the events
        // table (bypassing the normal write path), simulating an after-the-fact
        // edit of an audited row. Rewrite the JSON body to a mutated event.
        let mut mutated = events[1].clone();
        mutated.name = "TAMPERED".to_string();
        let mutated_body = serde_json::to_string(&mutated).unwrap();
        store
            .write({
                let id = target_id.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE events SET body = ?1 WHERE id = ?2",
                        params![mutated_body, id],
                    )?;
                    Ok(())
                }
            })
            .unwrap();

        let v = store.read(verify_chain).unwrap();
        assert!(!v.ok, "a mutated stored body must break verification");
        let brk = v.first_break.expect("a break is reported");
        assert_eq!(brk.event_id, target_id, "break points at the tampered event");
        // It is the second appended row (seq 2) and a row-hash mismatch.
        assert_eq!(brk.seq, 2);
        assert!(
            matches!(brk.reason, BreakReason::RowHashMismatch { .. }),
            "expected a row-hash mismatch, got {:?}",
            brk.reason
        );
    }

    #[test]
    fn deleting_a_stored_event_body_breaks_the_chain() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let events = seed_events(&store, trace);
        let target_id = events[0].id.as_str().to_string();

        store
            .write_returning({
                let events = events.clone();
                move |conn| {
                    for e in &events {
                        append_audit(conn, e)?;
                    }
                    Ok(())
                }
            })
            .unwrap();

        // Delete the FIRST audited event's row outright.
        store
            .write({
                let id = target_id.clone();
                move |conn| {
                    conn.execute("DELETE FROM events WHERE id = ?1", params![id])?;
                    Ok(())
                }
            })
            .unwrap();

        let v = store.read(verify_chain).unwrap();
        assert!(!v.ok, "a deleted audited body must break verification");
        let brk = v.first_break.expect("a break is reported");
        assert_eq!(brk.seq, 1, "the first chain row is the broken one");
        assert!(
            matches!(brk.reason, BreakReason::MissingEvent { .. }),
            "expected a missing-event break, got {:?}",
            brk.reason
        );
    }

    #[test]
    fn empty_chain_verifies_clean() {
        let store = Store::open_in_memory().unwrap();
        let v = store.read(verify_chain).unwrap();
        assert!(v.ok);
        assert_eq!(v.checked, 0);
        assert!(v.first_break.is_none());
    }

    #[test]
    fn tampering_with_a_recorded_link_is_detected() {
        // Directly corrupt a stored prev_hash so the link no longer matches the
        // running hash — a PrevHashMismatch (an inserted/removed/edited link),
        // distinct from a body mutation.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let events = seed_events(&store, trace);
        store
            .write_returning({
                let events = events.clone();
                move |conn| {
                    for e in &events {
                        append_audit(conn, e)?;
                    }
                    Ok(())
                }
            })
            .unwrap();

        // Corrupt the prev_hash of seq 2.
        store
            .write(|conn| {
                conn.execute(
                    "UPDATE audit_log SET prev_hash = ?1 WHERE seq = 2",
                    params!["deadbeef".repeat(8)],
                )?;
                Ok(())
            })
            .unwrap();

        let v = store.read(verify_chain).unwrap();
        assert!(!v.ok);
        let brk = v.first_break.unwrap();
        assert_eq!(brk.seq, 2);
        assert!(matches!(brk.reason, BreakReason::PrevHashMismatch { .. }));
    }

    // ---- hub_receive -----------------------------------------------------

    #[test]
    fn hub_receive_is_idempotent_on_event_id() {
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let e0 = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("a");
        let e1 = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("b");
        let batch = vec![e0.clone(), e1.clone()];

        // First receive inserts both.
        let n1 = store
            .write_returning({
                let batch = batch.clone();
                move |conn| hub_receive(conn, &batch)
            })
            .unwrap();
        assert_eq!(n1, 2, "both events are newly inserted");
        assert_eq!(store.count().unwrap(), 2);

        // Re-receiving the SAME ids inserts nothing new (idempotent).
        let n2 = store
            .write_returning({
                let batch = batch.clone();
                move |conn| hub_receive(conn, &batch)
            })
            .unwrap();
        assert_eq!(n2, 0, "re-receiving the same ids inserts nothing");
        assert_eq!(store.count().unwrap(), 2, "row count unchanged");

        // A batch mixing one known + one new id inserts exactly the new one.
        let e2 = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("c");
        let mixed = vec![e0.clone(), e2.clone()];
        let n3 = store
            .write_returning(move |conn| hub_receive(conn, &mixed))
            .unwrap();
        assert_eq!(n3, 1, "only the genuinely new id is inserted");
        assert_eq!(store.count().unwrap(), 3);
    }

    #[test]
    fn hub_receive_does_not_overwrite_the_local_copy_on_conflict() {
        // INSERT OR IGNORE must preserve the existing row, not replace it — the
        // local plane stays source of truth on a conflicting id.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let local = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("local-wins");
        store.insert(&local).unwrap();

        // A forwarded event with the SAME id but a different name.
        let mut forwarded = local.clone();
        forwarded.name = "remote-loses".to_string();
        let n = store
            .write_returning(move |conn| hub_receive(conn, &[forwarded]))
            .unwrap();
        assert_eq!(n, 0, "the conflicting id is ignored");

        // The stored event is still the local one.
        let got = store.trace(&trace.to_hex()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "local-wins", "local copy preserved on conflict");
    }

    #[test]
    fn hub_receive_empty_batch_is_zero() {
        let store = Store::open_in_memory().unwrap();
        let n = store
            .write_returning(|conn| hub_receive(conn, &[]))
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn received_events_are_queryable_and_audited_together() {
        // End-to-end: receive a fleet batch, then audit those rows and verify —
        // the two Phase-4 paths compose over the same events table.
        let store = Store::open_in_memory().unwrap();
        let trace = TraceId::new();
        let mut e0 = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("r0");
        e0.timestamp = MicrosTimestamp(1);
        let mut e1 = Event::new(trace, Kind::Log, Category::AppLog, "stdout").with_name("r1");
        e1.timestamp = MicrosTimestamp(2);
        let batch = vec![e0, e1];

        let received = {
            let batch = batch.clone();
            store
                .write_returning(move |conn| hub_receive(conn, &batch))
                .unwrap()
        };
        assert_eq!(received, 2);

        store
            .write_returning(move |conn| {
                for e in &batch {
                    append_audit(conn, e)?;
                }
                Ok(())
            })
            .unwrap();

        let v = store.read(verify_chain).unwrap();
        assert!(v.ok, "received + audited events verify cleanly");
        assert_eq!(v.checked, 2);
    }
}
