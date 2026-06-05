# Orbit — turn `logbook` into an AI-Agent Black-Box Flight Recorder

> **Codename:** Orbit (the initiative). **Binary/repo stays `logbook`.** Default out-dir `.logbook` (configurable via `--out-dir`), config `logbook.toml`.
> This roadmap is also the deliverable: on execution it is written to **`docs/flight-recorder.md`** in the repo, then **Phase 1 is implemented**, then we pause for review before Phase 2.

## Context

`logbook` v1 (shipped at github.com/sheeki03/logbook; its full suite — **427 tests — was green at the last full run**) is strong at the *reverse* direction — feeding an app's runtime to an agent so it debugs from evidence. It is **thin at recording the agent itself**: `logbook agent` today spawns with *inherited stdio* (no transcript) and records only a session row + changed-file **paths** (a `len:mtime` fingerprint — no patch bodies, no prompts, no tool calls, no replay). For a true "black box," that pillar is underbuilt.

Orbit makes `logbook` record, replay, correlate, and (later) govern **what an agent/harness does**, on the same unified timeline, without changing the agent. The spine already exists — unified `Event` + trace tree, SQLite store (rusqlite+refinery), PTY capture engine, MCP server, embedded React timeline, redaction, inventory, export schema, hub stub. Orbit adds **capture sources + replay + correlation + governance**, not a rewrite.

**Recorder-on by default (user decision), scoped precisely:** capture is **ON out of the box** for every auto-capturable class (transcript, commands, diffs, tool args/results, prompts, model metadata) — but **"on" means within a session you explicitly start via `logbook agent`/`logbook run`, NOT passive background harvesting of pre-existing harness logs.** Ingesting a harness's own session logs / hooks / OTLP (Phase 2) is *separately opt-in*, preserving v1's "no always-on surveillance" promise. The guardrails are *secrets-redaction (locked on), retention caps, local-only, never-exported-by-default*, plus **per-class toggles in `logbook.toml` and a capture on/off button in the UI** so it's one click to pause or disable. The LLM API proxy (Phase 4) stays opt-in by *mechanism* (it reroutes provider traffic). **Scope is not reduced; it is sharpened into three fidelity tiers.**

## North star — three fidelity tiers

| Tier | Captures | Mechanism | Phase |
|---|---|---|---|
| **1 — Universal** | redacted terminal transcript + cleaned text, commands, exit codes, **session-accurate file diffs** | PTY capture path (exists) + redacted baseline-relative diff | **Phase 1** |
| **2 — Structured** | prompts, tool calls + args/results, model/token/cost metadata, turn/step tree | harness hooks + session-log tail (opt-in), **MCP proxy**, OTLP ingest | Phase 2 |
| **3 — Complete** | full prompt/response provider traffic, governance-grade audit | optional **LLM API proxy**, hash-chain, RBAC, retention enforcement, fleet | Phase 4 |

(Phase 3 sits between 2 and 4: correlation, attribution, anomaly/risk, live guard, revert/export/forget — built on the data tiers 1–2 produce.)

## Principles (inherited from the codebase — keep)

- **Redaction runs at capture, before persistence** (`logbook-core/src/redact.rs`; `pty.rs` fan-out — even the terminal transcript is redacted, `pty.rs:536`). The store is a dumb sink (`logbook-store/src/lib.rs`).
- **logbook never persists raw file preimages.** Session diffs are computed from an **ephemeral, in-memory per-file redacted-content** baseline and **only the redacted diff is stored**; reversible dirty-tree capture is an explicit opt-in with **encrypted, purgeable** preimages. (No `git stash create`, no raw `base/` dir by default — that would write unredacted content, incl. untracked `.env`-style files, into git/disk.)
- **Config is additive `#[serde(default)]`** — a new `[capture]` section can't break existing `logbook.toml`.
- **Local-first, no exfiltration**; `0600` token files; loopback binds; runtime/state files are **`<out_dir>`-relative**, not hardcoded.
- **Versioned migrations** (`refinery`, `logbook-store/src/migrations/`) — add `V2__*.sql`, `V3__*.sql`; never edit `V1`.

---

# Capture policy + sensitivity classes (the governance layer)

New module `crates/logbook-core/src/capture_policy.rs`, re-exported from `lib.rs`, added as one additive field on `LogbookConfig` (`config.rs`). A `[capture]` TOML section with **per-tier master switches** and **per-sensitivity-class rules**, plus a load-time `CapturePolicy::validate()`.

```rust
pub struct CapturePolicy { pub enabled: bool, pub tiers: Tiers, pub classes: ClassRules, pub reversible_dirty: bool }  // enabled=true (UI-toggle target); reversible_dirty=false
pub struct Tiers { pub universal: bool, pub structured: bool, pub complete: bool }           // true, true, false
pub struct ClassRule { pub capture: bool, pub redaction: RedactionMode, pub max_age_days: Option<u32>, pub max_bytes: Option<u64>, pub export: bool }
pub enum RedactionMode { Always, Never, Default }                                            // Default = obey [redaction].enabled
pub enum SensitivityClass { Transcript, Prompts, ToolArgs, ToolResults, FileDiffs, Commands, Secrets, BrowserData, ModelMetadata }  // Copy, as_str()
```

**Sensitivity classes & recorder-on defaults** (the secrets floor applies to *every* row regardless):

| Class | `capture` default | `redaction` | `max_bytes` | `export` | Notes |
|---|---|---|---|---|---|
| `transcript` | **on** | default | — | off | The Universal tier; already redacted in `pty.rs`. |
| `commands` | **on** | default | — | off | Command + exit code; already redacted (`paths.rs` run records, regression-tested). |
| `file_diffs` | **on** | **always** | 256 KiB | off | Phase-1 headline; redacted diff only, capped per file. |
| `tool_args` | **on** | **always** | 64 KiB | off | Phase 2; force-redact. |
| `tool_results` | **on** | **always** | 64 KiB | off | Phase 2; largest leak surface → force-redact + cap. |
| `prompts` | **on** | **always** | 128 KiB | off | Phase 2; governance-sensitive → force-redact, on-box. |
| `model_metadata` | **on** | default | — | **on** | provider/model/tokens/cost — the one class exported by default (no payload). |
| `browser_data` | **on** | default | — | off | **active browser *control* gated by `allow_browser_sessions`; passive `/ingest` browser events gated by `[capture].classes.browser_data`** — a *new* collector-side gate (today `/ingest` is not class-gated). |
| `secrets` | **locked on** | **always (locked)** | — | off | Not a content toggle — the redaction *floor*. `capture=false`/`redaction=never` for this class is **rejected at load**. Records only a "secret redacted" marker (count+class), never the value. |

### Guardrails (each one closes a concrete gap)

- **Secrets floor is independent of the global switch.** Redaction is two layers: a **mandatory secrets redactor** (cloud keys, JWT, bearer, PEM, …) that **always** runs, and a **general redactor** gated by `[redaction].enabled` / `--no-redact`. `RedactionMode::Always` classes always get at least the secrets floor. **`--no-redact` is redefined to disable only `Default`-mode (non-secret) redaction** — it can never expose a secret. (Today `pty.rs` builds a single *disabled* redactor under `--no-redact` (`pty.rs:104`, `:236`) — split it into floor + general.)
- **Fail-closed loading (no silent widening).** Security-bearing producers (capture, agent wrapper, MCP proxy) load with **`LogbookConfig::load_from_root` (strict) + `CapturePolicy::validate()`**, and on parse/validate error **degrade to capture-OFF** (logged loudly) — *not* the soft `load_from_root_or_default` path (`config.rs:239`), which would silently fall back to **recorder-on** defaults and widen capture. Recorder-on defaults apply only to a **validly absent** `[capture]` section, never a malformed one.
- **`validate()` rejects** `secrets.capture=false` / `secrets.redaction=Never`, and a `complete`-tier enable without explicit confirmation.

### Config resolution (one shared helper, all producers identical)

`CapturePolicy::resolve(root, out_dir, cli) ->` policy, layering: **built-in recorder-on defaults → `<root>/logbook.toml [capture]` (strict, fail-closed) → `<out_dir>/capture-state.json` runtime overlay → CLI flags.** The overlay path is **`<out_dir>`-relative** (default `.logbook/capture-state.json`) so a custom `--out-dir` works. The overlay (written by the UI toggle, §1.4) **may only *narrow* capture (disable master/classes), never widen beyond config+defaults** — so a malformed/stale/hostile overlay can only restrict; on parse error it is ignored (not capture-off, since it cannot increase capture). `run`/`agent`/`collector`/`ui` all call `resolve`, so the cross-process pause switch behaves identically everywhere.

**Threading the policy** — consulted at each producer's *persistence boundary* (never inside `Store`), via:
```rust
impl CapturePolicy {
  pub fn should_capture(&self, c: SensitivityClass) -> bool;            // enabled && tier && class
  pub fn should_redact(&self, c: SensitivityClass, global_on: bool) -> bool;  // Always|Never|Default
  pub fn cap_body<'a>(&self, c: SensitivityClass, body: &'a str) -> (Cow<'a,str>, u64, bool);  // (capped, orig_bytes, truncated)
}
```
| Producer | File | Classes |
|---|---|---|
| Capture pipeline | `logbook-capture/src/pty.rs` `fan_out` | transcript, commands, secrets |
| Agent wrapper | `logbook-inventory/src/wrapper.rs` `diff_snapshots` | file_diffs, commands |
| MCP proxy (P2) | `logbook-collector/src/schrute_mcp.rs` → `LoggingMcpTransport` | tool_args, tool_results |
| Harness adapters (P2, opt-in) | new `logbook-harness` | prompts, tool_*, model_metadata |
| Ingest/OTLP (P2/3) | `logbook-collector/src/collector.rs` | browser_data, tool_args, model_metadata |
| LLM API proxy (P4) | new `logbook-llmproxy` | prompts, tool_results, model_metadata |

### Retention & export are NOT one coarse flag

An event's JSON body can mix classes (model metadata + prompt + tool args in one row, `event.rs` `Blocks`), so a single include/exclude bit is wrong on both axes:

- **Retention** uses a **`max_sensitivity TEXT`** column (the *most-sensitive* class present). V2 adds it to `events`/`agent_actions` + `CREATE INDEX idx_events_max_sensitivity`. Pruning deletes whole rows conservatively under the tightest per-class age: `DELETE … WHERE max_sensitivity=? AND timestamp<?`. Written via `schema.rs::event_to_row` + widened `INSERT_SQL` (`writer.rs`); JSON `body` stays source-of-truth on read.
- **Export** is a **per-class sanitizing projection**, not a whole-row filter. `logbook export` walks each event's blocks/fields and **drops or redacts any class whose `export=false`** (the default for every payload class; only `model_metadata` exports). A metadata+prompt row therefore exports the metadata and omits the prompt — no whole rows leak, and there is **no blanket `exportable DEFAULT 1`** column.

---

# Phase 1 — Real Local Flight Recorder

Goal: `logbook agent -- <cli>` produces a **fully replayable session** — redacted terminal transcript + cleaned text, structured line-events, session-accurate file diffs, exit status — all under **one `session_id`/`trace_id`**, viewable in a UI replay, with capture policy + the UI on/off toggle live.

### 1.1 Route `agent` through the capture pipeline (trace-id reconciliation)
**Problem:** `wrapper.rs::run_agent` uses inherited stdio (`Command::status`) and mints its own `TraceId`; `pty.rs::run` mints a *different* `TraceId` and returns only `Result<i32>`. A captured agent session would split across two traces.
**Fix — wrapper owns identity, capture accepts it:**
- Extend `CaptureConfig` (`pty.rs`) with `trace_id: Option<TraceId>`, `session_id: Option<SessionId>`, **and `cwd: Option<PathBuf>`** (all additive, default `None`); `pty.rs:287` becomes `config.trace_id.unwrap_or_else(TraceId::new)`; **the child runs in `cwd` (today hardcoded to `std::env::current_dir()`, `pty.rs:296`), and `cwd` also roots the strict config load** — `run_agent` already has `LogbookOptions.cwd` (`wrapper.rs:75`) to pass through. Line-events get `.with_session(...)`.
- Add `pub async fn run_with_outcome(CaptureConfig) -> Result<CaptureOutcome>` where **`CaptureOutcome = { exit_code, trace_id, session_id, transcript }`** and `transcript: TranscriptInfo { terminal_log_path, text_path, line_count, byte_size }` — surfaced from the `log_paths()` already computed at `pty.rs:221`, so the wrapper writes the `session_transcripts` row without re-deriving paths. Keep `run() -> Result<i32>` as a thin wrapper (zero churn for `commands/run.rs`).
- `run_agent` mints `trace`+`session`, builds a `CaptureConfig` with them (+ its `cwd`), calls `run_with_outcome` (small current-thread tokio runtime in `cli.rs::run_agent_wrapper`, like `commands/run.rs:105`). Interactive agents keep working (PTY forwards stdin) — strictly better than inherited stdio.

### 1.2 Full file diffs — *session-accurate*, redaction-safe, **never raw preimages**
Diffs must reflect **what THIS session changed** (not pre-existing dirt) **and** must not violate the core rule (redaction before persistence). **logbook never persists raw file preimages by default** — `git stash create` / a raw `base/` dir are dropped (they'd write unredacted content, incl. untracked `.env`-style files, into `.git/objects`/disk before the redactor runs). Today only `len:mtime` fingerprints exist (`wrapper.rs` `git_tracked_snapshot:197`).

**Mechanism (only redacted data is ever stored; baseline is per-file *content*, not hunks):**
- At session **start**, build an *ephemeral, in-memory* baseline: for each tracked + untracked-not-ignored file, hold its **redacted content** (run the redactor in memory) keyed by path, bounded by per-file (e.g. 1 MiB) + total-size caps. (`.gitignore`d trees like `node_modules`/`target` are excluded.) **Hunk-level set-difference over `git diff HEAD` is NOT used** — git hunks are unstable: a session edit *adjacent to* pre-existing dirt merges into one hunk, so any subtraction would leak the dirt or drop the real change.
- At **teardown**, for each file whose content hash changed, compute the diff **redacted-start-content → redacted-end-content** (a per-file text diff, e.g. `similar`/`imara-diff`, or `git diff --no-index` over the two redacted buffers). This isolates exactly the session's change vs pre-existing dirt, for **tracked and untracked-at-start files alike** (untracked files have a content baseline, not just a hash). `cap_body(FileDiffs,…)` (256 KiB, append `… [diff truncated N bytes]`). Persist **only** the redacted diff.
- Files exceeding the baseline caps (huge/binary) → a best-effort "changed, diff omitted (size)" marker, `revert_safe=false`, no body.

**Revert safety (`revert_safe` per action):**
- **Clean tree at start (recommended):** start diff empty → session diff = exactly end-vs-HEAD; `revert_safe=true` — revert needs *no logbook preimage* (`git checkout HEAD -- <path>` + remove added files; HEAD *is* the preimage, already the user's own git).
- **Dirty tree (default):** an **accurate session diff** is produced (per-file redacted start→end), but `revert_safe=false` (only a redacted diff is kept, which can't exactly restore content; the tree was already dirty). `logbook revert` refuses these.
- **Reversible dirty tree (opt-in `--reversible` / `[capture] reversible_dirty=true`):** additionally store **encrypted** preimages (local key) under **`<out_dir>/sessions/<id>/`**, with explicit retention + `forget`/`prune` deletion; documented as a sensitive store; sets `revert_safe=true`. The persisted diff stays redacted; the encrypted preimage is the only raw-bearing artifact, encrypted-at-rest + purgeable.
- Record a **post-state hash** per file; `revert` (Phase 3) applies only if the file still matches it.
- V2 columns on `agent_actions`: `diff TEXT, diff_bytes INTEGER, post_hash TEXT, revert_safe INTEGER NOT NULL DEFAULT 0, max_sensitivity TEXT`; widen `store_ext::insert_agent_actions`.

### 1.3 Transcript storage tied to session
New `session_transcripts` table (V2) — **pointers + metadata, not bulk bytes** (the redacted files already live on disk; don't overload `runs`, keyed by command-slug for OpenLogs `tail`):
```sql
CREATE TABLE session_transcripts (
  session_id TEXT PRIMARY KEY, trace_id TEXT NOT NULL,
  terminal_log_path TEXT, text_path TEXT, line_count INTEGER, byte_size INTEGER,
  max_sensitivity TEXT NOT NULL DEFAULT 'transcript', created_at INTEGER NOT NULL,
  FOREIGN KEY (session_id) REFERENCES agent_sessions(id) ON DELETE CASCADE);
```
The wrapper writes this row from `CaptureOutcome.transcript` after `run_with_outcome` returns. Structured per-line events are already in `events` under the shared trace, so replay can stream the **redacted transcript file** or render events (structured).

### 1.4 Session replay UI + capture toggle
- **Store reads** (new `logbook-ui/src/sessions.rs`): `list_sessions() -> Vec<SessionSummary>` and `load_session(id) -> SessionDetail` (joins `agent_sessions` + `session_transcripts` + `agent_actions`-with-diffs + ordered `store.trace(trace_id)`), via the existing `Store::read` escape hatch.
- **API routes** (`logbook-ui/src/server.rs` + `api.rs`, read-only like the existing three): `GET /api/sessions`, `GET /api/sessions/:id`.
- **React** (`ui/src/`): top-nav → `Timeline | Sessions | Inventory`; `views/Sessions.tsx` = master list (agent, command, started, exit, action-count, has-transcript) → detail with **Transcript/Prompt**, **Commands**, **Tool/LLM events**, **Diffs** (per-file patch, "truncated" badge when `diff_bytes>len`, `revert_safe` badge), **Exit**, and a per-session **timeline** (reuse the Timeline event-row scoped to `?session_id=`). Add `sessions()`/`session(id)` to `src/api.ts`, DTOs to `src/types.ts`.
- **Capture on/off button (user-requested) + its trust model.** A Capture panel with a master toggle + per-class switches (`secrets` locked). logbook-ui is read-only GET today (`server.rs:3,65`), so this is a deliberate, fenced boundary change with **two write targets at two trust levels:**
  - **Runtime override → `<out_dir>/capture-state.json` (default-allowed, cross-process).** The toggle writes a small dedicated runtime-state file (master on/off + per-class booleans; **narrow-only**, `secrets` locked). It's logbook's own state dir (not the user's config), so no launch flag — and **this is what makes the toggle work across processes**: every producer's `CapturePolicy::resolve` overlays it, so flipping it pauses capture for *subsequent* `logbook run`/`agent` invocations, not just the live UI/collector. (An in-memory-only toggle would silently fail to reach separate CLI processes — the real gap.)
  - **Durable default → `<root>/logbook.toml [capture]` (gated).** Persisting requires `logbook ui --allow-config-write` (off by default).
  - **Both writes** get: **same-origin + CSRF-token check** (loopback ≠ safe from a malicious page POST), **atomic write** (temp + rename), **conflict detection** (mtime/hash compare; read-modify-write, never blind-overwrite), and server-enforced `secrets` floor. Route: `POST /api/capture-policy`.

### 1.5 CLI surface (Phase 1)
On `AgentArgs` (`inventory/src/cli.rs`) and where sensible `RunArgs`: `--capture-diffs/--no-capture-diffs`, `--diff-max-bytes`, `--reversible` (opt-in encrypted preimages for dirty-tree revert; default off), `--no-redact` (parity — **redefined** per the secrets floor: disables only non-secret/`Default`-mode redaction). `--capture-prompts` and `--tier structured|complete` are **rejected in Phase 1** with "structured capture lands in Phase 2" — no misleading no-ops. Resolution uses the shared `CapturePolicy::resolve(root, out_dir, cli)` (§Config resolution).

### 1.6 Phase-1 acceptance tests
- `logbook agent -- /bin/sh -c "echo hi > f.txt"` ⇒ one `trace_id` shared by `*.terminal.log`, `*.txt`, line-events, `agent_sessions`, `agent_actions`, and a `session_transcripts` row whose paths/line_count/byte_size come from `CaptureOutcome` (extend `wrapper.rs` `run_agent_records_session_and_diff_in_real_repo`).
- **session-accuracy:** a repo with pre-existing dirty + staged changes ⇒ `agent_actions.diff` contains **only the session's changes** (per-file redacted start→end content diff), excluding pre-existing dirt — including the case where the session edits a line **adjacent to** pre-existing dirt (no hunk-merge leak) and the case where an **untracked-at-start** file is further modified; a planted secret in the change is redacted (extend `diff_paths_are_redacted`).
- **no raw preimage:** during a dirty-tree session, assert **no unredacted file content is written** to `.git/objects` or `<out_dir>` (baseline is in-memory; persisted diff is redacted).
- **revert_safe:** clean-tree session ⇒ actions `revert_safe=true`; dirty-tree without `--reversible` ⇒ `revert_safe=false`; `--reversible` ⇒ an **encrypted** preimage under `<out_dir>/sessions/<id>/` + `revert_safe=true`.
- **cwd:** `run_agent` with a non-cwd `LogbookOptions.cwd` runs the child and diffs in that dir.
- `--diff-max-bytes`/class cap truncates body + sets `diff_bytes>len` + marker. `--no-capture-diffs` ⇒ `diff=None`, behavior identical to pre-Orbit.
- **secrets floor:** with `--no-redact`, a planted AWS key in a diff/transcript is **still redacted**; a non-secret string is not.
- **fail-closed:** a malformed `[capture]` table makes a capturing producer **degrade to capture-OFF**, not recorder-on; a malformed `capture-state.json` is **ignored** (can only narrow); `[capture.classes.secrets] redaction="never"` rejected at load; `POST /api/capture-policy` cannot disable `secrets` and (without `--allow-config-write`) writes only `<out_dir>/capture-state.json`, never `logbook.toml`.
- **cross-process toggle:** writing `<out_dir>/capture-state.json` (master off) makes a subsequent `logbook agent` capture nothing.
- `GET /api/sessions/:id` replays transcript pointer + actions + ordered events.
- migration: V1→V2 idempotent; old rows read `max_sensitivity=NULL` (unclassified — retained under the global default, omitted from the export payload projection).

**Not in Phase 1 (honest):** prompts/tool-results have no capture *mechanism* yet (they arrive in P2 via hooks/proxy) — their recorder-on default takes effect when P2 lands; P1 rejects the flags rather than no-op them.

---

# Phase 2 — Structured Agent Capture

- **`logbook-harness` crate** — `trait HarnessAdapter { fn name(&self)->&str; fn parse_record(&self, raw:&Value)->Vec<Event>; }`. Adapters: **Claude Code** (hooks `PreToolUse`/`PostToolUse`/`UserPromptSubmit`/`Stop` POSTed to a collector route; **opt-in** session-log JSONL tail of `~/.claude/projects/**/*.jsonl` reusing `logbook-capture::tail` + `parse.rs::LineParser`); **Codex, Aider** (and Cursor where practical) — same trait, own formats, drift contained per-adapter + golden fixtures. Each record → `Kind::Agent|Tool|Llm`, tool calls `parent_id`-linked to their turn. **Tailing pre-existing logs is opt-in** (not recorder-on).
- **MCP proxy** — `LoggingMcpTransport<T: McpTransport>` decorates the existing transport (`schrute_mcp.rs`): emits a `Kind::Tool` event per `tools/call` (redacted `ToolBlock.arguments`=`tool_args`, result=`tool_results`), egress allowlist still in front. `logbook` can also run **as a proxy in the middle** (stdio passthrough) between an agent and its real MCP servers.
- **Ingest / OTLP receiver** — extend `collector.rs` (`/ingest` + bearer + loopback + watchdog) with `POST /v1/traces` (OTLP-JSON) + `POST /v1/hooks`, reusing `IngestToken` + redact-then-`insert_batch`, **and the new `browser_data`/class gate**. Reuse `logbook-export`'s OTel/OpenInference schemas inverted.
- **Event-schema enrichment** (additive): `AgentBlock { + turn, + tool_call_id }`, `ToolBlock { + result_summary }`, `LlmBlock { + finish_reason, + stream }`. Turn/step hierarchy via existing `parent_id`; optional `turn` column (V3) for fast grouping.
- **Cost/token accounting + FTS search** over sessions (extend `Query`).
- **Orbit addition — MCP read-back tools:** read-only `session_list`/`session_get`/`session_diff`/`session_search` so an **agent can query past sessions** ("what did the last run change?"). Closes the loop — the recorder feeds agents, not just humans.

**P2 tests:** golden-fixture per adapter (turn/tool tree); `LoggingMcpTransport` emits redacted tool events; `prompts` off ⇒ metadata-only, on ⇒ redacted+capped; `/v1/traces` rejects bad bearer; browser ingest honors `browser_data` gate.

---

# Phase 3 — Correlation, Risk & Governance

- **Correlation timeline (the killer view):** agent action → file diff → command → browser/runtime logs → security finding, woven by `trace_id`/time. Extend `Query` with `parent_id`/`turn`; add `Store::session_tree(session_id)`.
- **Attribution:** "which prompt/turn produced this line?" (diff ↔ turn span) and "which change caused this error?" (diff ↔ later error events).
- **Anomaly/risk detection** — new `logbook-detect` crate emitting `Kind::Finding`/`Category::Security` (reuse `FindingBlock`): secret-in-diff, dangerous shell (`rm -rf`, force-push), risky git ops, non-allowlisted egress, token/cost spikes, tool-call rate.
- **Orbit additions:** **live guard / kill-switch** (stream a running session; alert/halt on a risky action — pairs with the UI toggle); **`logbook revert <session>`** (reverse a session's changes — only for `revert_safe=true` actions, guarded by the post-state hash from §1.2); **`logbook session export <id>`** (self-contained, **per-class sanitized** bundle for bug reports/PRs); **`logbook forget <session|--before>` + panic-purge** + `Store::prune(policy, now)` enforcing per-class + global retention (run at `ui`/`agent` startup; also purges encrypted preimages); **workspace time-travel** (reconstruct repo state at turn N from the diff chain, where reversible).

**P3 tests:** planted secret-in-diff raises exactly one finding; non-allowlisted egress raises one; `prune` deletes only per-class-expired rows + their preimages; `revert` restores pre-session state, **refuses** `revert_safe=false` actions and when a file no longer matches its post-state hash; export bundle contains only the sanitized projection (no payload classes with `export=false`).

---

# Phase 4 — Complete Tier & Fleet

- **`logbook-llmproxy` crate** — opt-in local proxy (loopback, bearer-gated) the agent points `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` at; forwards to the provider, records request/response as `Kind::Llm` with full `LlmBlock`. **Default off** (`tiers.complete=false`); prompts/results only if those classes on; always force-redacted; SSE reassembled before redaction. The only component seeing raw provider payloads → most gated, last to ship.
- **Hub** (flesh out the `logbook-hub` stub): fleet receiver (collector's loopback+token model for many endpoints); **RBAC** keyed off `classes.<c>.export` (viewer sees the exportable projection; auditor sees all); server-side **retention** (`Store::prune`); **hash-chain audit** — `audit_log` with `prev_hash`/`row_hash` over each canonical **already-redacted** stored record. This gives **tamper-evidence that stored rows weren't later altered; it does NOT prove raw secrets were never captured before redaction.** The `secrets` marker records that redaction *occurred*, without the value. Plus the multi-endpoint roll-up of the existing inventory.

**P4 tests:** proxy round-trips one provider call → one `Kind::Llm` event with full metadata; refuses to start unless `complete` enabled; mutating an audited row breaks chain verification; RBAC viewer sees only the sanitized projection.

---

# Consolidated changes

**Schema (migrations):** `V2__capture_policy.sql` — `events += max_sensitivity` (+`idx_events_max_sensitivity`); `agent_actions += diff, diff_bytes, post_hash, revert_safe, max_sensitivity`; new `session_transcripts`. `V3__structured.sql` — optional `events.turn`; `audit_log` (Phase 4). **No blanket `exportable` column** — export is a per-class projection. Touch `schema.rs` (`EventRow`, `event_to_row`), `writer.rs` (`INSERT_SQL`), `store_ext.rs`.

**Config:** new `crates/logbook-core/src/capture_policy.rs` (`CapturePolicy` + `validate()` + `resolve(root, out_dir, cli)` reading `<out_dir>/capture-state.json`, narrow-only); `[capture]` field on `LogbookConfig` (`config.rs`); producers switch to `load_from_root` + validate + fail-closed.

**Redaction:** split the capture redactor into a **mandatory secrets-floor** + a **general** redactor (`pty.rs:104,236`; `redact.rs`); `--no-redact` redefined.

**Capture:** `CaptureConfig += {trace_id, session_id, cwd}`; new `run_with_outcome -> CaptureOutcome{exit_code,trace_id,session_id,transcript}` (`pty.rs`). Diffs computed from an ephemeral in-memory **per-file redacted-content** baseline (size-capped); only redacted diffs persisted; optional encrypted preimages under `<out_dir>/sessions/<id>/`.

**CLI:** `agent` flags (1.5, incl. `--reversible`); later subcommands — `logbook session list|show|diff|export|revert`, `logbook forget`, `logbook proxy mcp`, `logbook proxy llm`, `logbook hooks`. Slot into `logbook-cli/src/main.rs` + `commands/`.

**UI:** `Sessions/Replay` view + `/api/sessions[/:id]`; **Capture panel** (runtime toggle → `<out_dir>/capture-state.json`, cross-process; durable `logbook.toml` write only with `--allow-config-write`; both same-origin/CSRF/atomic/conflict-guarded; `secrets` server-locked).

**New crates:** `logbook-harness` (P2), `logbook-detect` (P3), `logbook-llmproxy` (P4).

# Privacy defaults & guardrails (recorder-on, with teeth)

Capture **on by default within an explicitly wrapped `logbook agent`/`run` session** (not passive harvesting of existing harness logs — that's opt-in). **Secrets always redacted (locked floor, independent of `--no-redact`)**; force-redaction on diffs/prompts/tool-args/results; **no raw file preimages persisted by default** (ephemeral in-memory baseline; reversible dirty = opt-in encrypted, purgeable preimages); **export is a per-class sanitizing projection — metadata-only by default, no whole rows leave**; retention caps (per-class + global) via `prune`; `forget`/panic-purge for deletion; everything **local-only**; **one UI button (→ cross-process `<out_dir>/capture-state.json`, narrow-only) + per-class `logbook.toml` toggles** to pause/disable; **malformed `[capture]` config fails closed to capture-OFF**, never to recorder-on. The LLM API proxy stays opt-in by mechanism.

# Top risks & mitigations

1. **Storage growth** → per-class `max_bytes`; diffs only for changed files; transcripts as file pointers; `prune`.
2. **Sensitive archive** → secrets-floor locked + independent of `--no-redact`; force-redaction; **no raw preimages by default**; export-projection (metadata-only); `0600` tokens; **hash-chain = tamper-evidence over stored *redacted* records (P4), not proof of pre-redaction safety**.
3. **Redaction completeness** → mandatory secrets-floor redactor + the general redactor; reuse the escape-split discipline (`pty.rs` regression); per-class golden/fuzz tests.
4. **Session-diff accuracy & privacy** → ephemeral in-memory **per-file redacted-content** baseline (not unstable hunk set-difference), per-file redacted start→end diff (covers untracked-at-start + edits adjacent to dirt); **no raw preimage persisted** by default; `revert_safe=false` on dirty trees; reversible dirty = opt-in **encrypted** preimage; clean-tree = exact + git-revertable.
5. **Trace-id reconciliation** → wrapper mints, capture accepts (+ `cwd`); acceptance test asserts one trace across all artifacts incl. the `session_transcripts` row.
6. **UI write surface + cross-process toggle** → runtime override → `<out_dir>/capture-state.json` (narrow-only, read by all producers via `resolve`); durable `logbook.toml` write behind `--allow-config-write`; both same-origin/CSRF + atomic + conflict-detect; secrets floor server-enforced.
7. **Fail-open config** → strict `load_from_root` + validate; malformed `[capture]` ⇒ capture-off; malformed overlay ⇒ ignored.
8. **Harness-format drift** → one adapter per harness + versioned golden fixtures + tolerant parse + `harness_version` attribute; harness-log tailing opt-in.
9. **Capture hot path** → diffs at teardown (not per chunk); policy lookups are field reads; store single-writer/batched; proxy/streaming off the terminal path.

# Verification (end-to-end, Phase 1)
`cargo build/test/clippy --workspace` green (new tests in §1.6) · `logbook agent -- claude` (or `/bin/sh`) → one trace across transcript+events+session+diff, with a `session_transcripts` row from `CaptureOutcome`; `GET /api/sessions/:id` replays it · a dirty repo yields a session-only **redacted** diff with **no raw preimage on disk** and `revert_safe=false`; `--reversible` writes an encrypted preimage · `--no-redact` still redacts a planted secret · UI toggle writes `<out_dir>/capture-state.json` and a subsequent `logbook agent` honors it; durable `logbook.toml` write only with `--allow-config-write` · malformed `[capture]` ⇒ capture-off · V1→V2 migration idempotent · `bun run build` for the UI.

# Critical files to modify
- `crates/logbook-core/src/capture_policy.rs` (new — `CapturePolicy`, `validate()`, `resolve(root, out_dir, cli)` reading `<out_dir>/capture-state.json`) + `config.rs` (`[capture]` field, strict-load helper) + `redact.rs` (secrets-floor split).
- `crates/logbook-capture/src/pty.rs` (`CaptureConfig += {trace_id,session_id,cwd}`; `run_with_outcome -> CaptureOutcome`; child runs in `cwd`; tier/secrets-floor gating).
- `crates/logbook-inventory/src/wrapper.rs` (drive `run_with_outcome`; per-file redacted-content baseline → session-accurate redacted diffs, redacted-only persistence, optional encrypted preimage; `AgentAction` diff/post_hash/revert_safe; write `session_transcripts`) + `cli.rs` (`run_agent_wrapper` runtime + `resolve` + fail-closed load).
- `crates/logbook-store/src/migrations/V2__capture_policy.sql` (new) + `schema.rs` + `writer.rs` + `store_ext.rs`.
- `crates/logbook-ui/src/{server.rs,api.rs,sessions.rs(new)}` (+ `POST /api/capture-policy` writer with guards) + `ui/src/{App.tsx,views/Sessions.tsx(new),api.ts,types.ts}`.

# Build order
Phase 1: capture_policy + `[capture]` + `resolve`/fail-closed load → V2 migration → secrets-floor redactor split → `CaptureConfig` ids/cwd + `run_with_outcome` + `agent`-through-capture → session-accurate redacted-only diffs (per-file in-memory redacted-content baseline; `--reversible` encrypted preimage) → `session_transcripts` (from `CaptureOutcome`) + session reads → `/api/sessions` + React Sessions view → capture toggle (`<out_dir>/capture-state.json`; `logbook.toml` behind `--allow-config-write`) → tests → **write `docs/flight-recorder.md`** → **pause for review.** Then P2 (`logbook-harness` + MCP proxy + OTLP + read-back), P3 (correlation + detect + revert/export/forget/time-travel), P4 (llmproxy + hub).
