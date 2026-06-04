# logbook

> A **local-first observability plane for agent-built software** — runtime evidence, browser state, agent actions, MCP/agent inventory, and security findings, correlated on one timeline.

`logbook` is **agent-agnostic** (works with any MCP-capable coding agent — Claude Code, Cursor, Codex, …), built in **Rust** (single binary) + an embedded **React/TS** UI, and reuses your own tools (`schrute`, `security-suite`) over clean boundaries.

**Status:** v1, `0.1.0` · POSIX only (macOS/Linux) · Apache-2.0 · `cargo build` clean, **362 tests passing / 0 failing**.

---

## Why

AI coding agents debug by *guessing*: read the code, form a theory, edit, hope. `logbook` gives the agent **real runtime evidence** instead, gives **you** visibility into **what the agent actually did**, and surfaces **which agents and MCP servers exist on this machine at all** — all on a single timeline.

logbook starts at the **developer workstation** and captures the evidence layer around coding agents — what they saw, what they changed, which MCP servers / tools they used, and what runtime and security signals resulted. v1 ships **local** endpoint inventory + agent/MCP discovery (the foundation for AI-usage visibility) — not fleet governance.

## What it captures

| Lane | How |
|------|-----|
| **Runtime logs** | Wraps your command in a PTY; mirrors output to a raw transcript, a cleaned text log, and structured events |
| **Browser state** | Injected-JS console/network collector for your own app + `schrute` (record→replay, stealth) over MCP |
| **Agent actions** | `logbook agent <cli>` wraps an agent's session and records it + the file diffs it produced |
| **MCP / agent inventory** | Discovers installed agent CLIs, configured MCP servers, running agent processes, and risk/shadow items |
| **Security findings** | Runs Semgrep / Trivy / cargo-audit on demand, or imports any SARIF/JSON, onto the same timeline |

## Safe by default

- **Read-only by default.** MCP write tools are hidden until per-session opt-in + allowlist + interactive confirm.
- **Redaction on by default.** Secrets are scrubbed *at capture, before anything is persisted* (`AKIA…` → `«REDACTED:CLOUD_KEY:20»`).
- **No external egress by default.** Browser navigation/replay needs a non-empty `allowed_domains`.
- **Local-only binds.** `/ingest` requires a per-run bearer token; the token lives in `collector.token` (`0600`), never in `collector.json`.
- **No always-on surveillance.** Inventory `scan`/`report` are user-triggered; continuous `watch` is opt-in.

---

## Use cases

- **Agent-assisted debugging** — your coding agent reads *real* logs (`tail_log`, `search_logs`, `query_timeline`, `get_errors`) and fixes from runtime evidence instead of guessing; no copy-pasting logs into chat.
- **Local full-stack dev observability** — one timeline for server stdout/stderr **and** browser console/network while you build.
- **"What did the agent do?" review** — wrap `claude` / `cursor` / `codex` with `logbook agent <cli>` to record the session and the exact file diffs it produced, before you merge.
- **Shadow-AI & MCP hygiene** — `logbook inventory report` shows which agent CLIs and MCP servers are configured on a machine, flags unsanctioned/untracked ones, and confirms no secrets sit unredacted in MCP configs.
- **Security-in-the-loop** — run Semgrep / Trivy / cargo-audit (or import CI SARIF) and see findings correlated with the code and runtime events on the same timeline.
- **Flaky-bug repro capture** — capture a run's full transcript + structured events to share or triage later.
- **Feed existing observability** — export the timeline to OpenTelemetry / OpenInference / Langfuse / MLflow.
- **Dev-machine forensics / onboarding** — quickly map a workstation's AI-tooling footprint.

## What you can do with it

Capture any command's output (PTY) into clean + raw + structured tiers · tail / search / follow past runs · expose a **read-only MCP** tool surface to any agent · pull **passive debug evidence** (non-invasive — never edits your source) · capture browser console/network (injected JS) and drive/replay flows (schrute) · record **agent sessions + diffs** · **inventory** agents / MCP servers / processes and surface shadow & risk · run or import **security scans** · **export** to OTel / OpenInference / Langfuse / MLflow · **auto-redact** secrets · browse it all in a local **web UI**.

## Install

Requires a Rust toolchain (1.80+). Node 18+ is only needed if you want to rebuild the web UI; the scanners (`semgrep`, `trivy`, `cargo-audit`) are optional and soft-degrade if absent.

```sh
# from the repo root
cargo install --path crates/logbook-cli      # installs `logbook` to ~/.cargo/bin
# …or just build and use the binary directly:
cargo build --release                         # → target/release/logbook
```

## Quick start

```sh
logbook run -- npm run dev        # capture your dev server (logs → .logbook/)
logbook tail -- -f                # follow the latest run (forwards args to `tail`)
logbook inventory report          # what agents / MCP servers / risks are on this machine
logbook ui                        # open the timeline → http://127.0.0.1:7878
logbook mcp                       # expose read-only tools to your coding agent over stdio
```

Everything lands under `./.logbook/` in the current project (override with `--out-dir`).

---

## Commands

All subcommands accept `--out-dir <path>` (default `.logbook`).

### `logbook run [OPTIONS] -- <command>…`
Run a command inside a capturing PTY (the OpenLogs `run` port). Forwards stdin, handles resize and Ctrl-C, preserves the child's exit code, and reaps the whole descendant process tree on exit.

| Flag | Meaning |
|------|---------|
| `--name <name>` | Explicit run name (else the slugified command) |
| `--no-history` | Skip timestamped history files (keep `latest`/named) |
| `--print-paths` | Print resolved log paths to stderr at startup |
| `--terminal-only` / `--text-only` | Keep only the transcript / only the cleaned text tier |
| `--no-redact` | Disable redaction (**dangerous** — prints a warning) |
| `--no-collector` | Don't start the browser collector (for non-web commands) |

```sh
logbook run --print-paths -- bun run dev
logbook run --name api -- cargo run -p api
```

### `logbook tail [OPTIONS] [QUERY] [-- <tail args>…]`
Replay a captured log. No query → latest run; a query → most-recent fuzzy match on name/command/timestamp.

```sh
logbook tail -- -n 200          # last 200 lines of the latest run
logbook tail api -- -f          # follow the most recent run matching "api"
logbook tail --terminal -- -n 50  # the raw transcript instead of cleaned text
```

### `logbook mcp [--root <dir>]`
Serve the MCP tool surface over stdio. **Read-only by default**; write tools appear only when enabled in `logbook.toml`. See [MCP integration](#mcp-integration).

### `logbook ui [--port 7878]`
Serve the embedded web UI (timeline + inventory tabs) on loopback; auto-increments the port on conflict.

### `logbook agent -- <agent-cli>…`
Wrap an agent's own session (e.g. `logbook agent -- claude`), recording an `agent_session` plus the git/file diffs it produced.

### `logbook inventory <scan|watch|report> [--project <dir>]`
Endpoint Inventory Lite. `scan` = one-shot discovery; `report` = human/JSON view; `watch` = continuous (opt-in via `enabled_writes`). See [Endpoint inventory](#endpoint-inventory).

### `logbook debug <fetch|sessions>`
Non-invasive debug. `fetch` opens a passive session, pulls correlated evidence, prints JSON, and ends it. `sessions` lists recorded sessions. DAP logpoints are **alpha** and not exposed as a one-shot CLI flow.

### `logbook security <import <file>|scan> [--root <dir>]`
`import` ingests a SARIF/JSON document as security findings (ungated). `scan` runs the configured scanners over a target (gated by `allow_security_scans`; soft-degrades when a scanner binary is missing).

### `logbook export [OPTIONS]`
Export captured events to a tracing schema. **v1 = schema only (stdout/file), no network export.**

| Flag | Meaning |
|------|---------|
| `--format otel\|openinference\|langfuse\|mlflow` | Target schema (default `otel` → OTLP `resourceSpans` document) |
| `--trace <hex>` | Only events on this correlated trace id |
| `--limit <n>` / `--output <file>` | Cap count / write to a file |

### `logbook hub`
Placeholder — prints `hub: v1.5 — not yet implemented` and exits 0.

---

## Output layout

```
.logbook/
  latest.txt                 # cleaned text of the most recent run (ANSI stripped)
  latest.terminal.log        # full transcript (ANSI/control bytes kept, secrets redacted)
  <slug>.txt / .terminal.log # command-specific "latest"
  <slug>.<ISO>.txt / …       # timestamped history (unless --no-history)
  runs.jsonl                 # one record per run (command, key, paths, startedAt)
  events.jsonl               # structured events (JSONL fallback / portable mirror)
  logbook.db                 # SQLite event store (the timeline + inventory + findings)
  collector.json             # {host, port, outDir, pid, startedAt} — NO secret
  collector.token            # per-run ingest token only, 0600 (when the collector runs)
```

**Three log tiers** — `*.terminal.log` (faithful transcript, redacted, *not* byte-exact), `*.txt` (cleaned), and structured `Event`s in `logbook.db` / `events.jsonl`.

---

## MCP integration

Register the stdio server with your agent (e.g. `.mcp.json` / `.cursor/mcp.json`):

```json
{ "mcpServers": { "logbook": { "command": "logbook", "args": ["mcp", "--out-dir", ".logbook"] } } }
```

**Read tools (always available):** `list_log_files`, `tail_log`, `search_logs`, `get_errors`, `get_run_status`, `watch_log`, `browser_console`, `browser_network`, `browser_get_request`, `browser_dom`, `query_timeline`, `get_trace`, `correlate`, `list_findings`, `get_finding`, `debug_fetch_evidence`, `inventory_list_agents`, `inventory_list_mcp`, `inventory_list_sessions`, `inventory_report`, `inventory_findings`.

**Write tools (hidden unless enabled in `logbook.toml`):** `browser_navigate`/`record`/`replay`/`screenshot`/`start_session`, `debug_set_logpoint`/`enable_trace`/`start_session`/`end_session`, `security_scan`, `scan_agent_diff`, `inventory_scan`, `inventory_watch`, `export_otel`.

---

## Configuration — `logbook.toml`

Loaded from the workspace root (`--root`, default cwd). Shipped defaults are conservative.

```toml
[permissions]
enabled_writes         = []      # subset of ["browser","dap","security","export","inventory_watch"]; [] = read-only
allowed_domains        = []      # egress allowlist for browser nav/replay; [] blocks all external navigation
allow_browser_sessions = false
allow_dap              = false   # DAP logpoints (alpha)
allow_security_scans   = false

[ingest]
token_mode = "generated"         # "generated" (collector.token, 0600) | "env" (LOGBOOK_INGEST_TOKEN) | "off" (DEV/TEST ONLY)

[redaction]
enabled = true                   # extra patterns via `deny`; false-positive exclusions via `allow`
deny    = []
allow   = []

[retention]
max_age_days = 14
max_db_mb    = 512

[scanners]                        # explicit paths; a missing binary soft-degrades (not an error)
semgrep = "semgrep"
trivy = "trivy"
cargo_audit = "cargo-audit"
```

---

## Security & redaction

Redaction runs at three choke points **before persistence**: PTY line assembly, the `/ingest` endpoint, and any MCP tool that returns log/console/network content (plus secrets found in scanned MCP configs). It catches cloud keys, JWTs, `Bearer` tokens, PEM blocks, `user:pass@` URLs, cookies, and env-derived secret values; placeholders preserve length-class (`«REDACTED:KIND:len»`) but not the secret. On by default; `--no-redact` warns.

The collector binds loopback only and requires the per-run bearer token on `/ingest` (401 otherwise). MCP is stdio (no network surface). Inventory is read-only and never modifies a discovered process.

> **Known gap (v1):** `runs.jsonl` stores the *wrapped command line verbatim* — a secret passed as a literal CLI argument is not redacted there, even though program **output** is. Fix tracked for `crates/logbook-capture/src/paths.rs`.

## Browser capture

Two interchangeable adapters behind one trait:

- **Injected-JS (default, for your own app):** a small snippet hooks `console.*`, `window.onerror`, `fetch`/XHR, and `PerformanceObserver`, batching to `/ingest` with the per-run token. Insert it via the provided Vite/Next dev-middleware, or paste the snippet `logbook` prints (the token is injected at runtime — the browser never reads `collector.token`).
- **schrute over MCP (rich):** record→replay, logged-in session reuse, network capture, and stealth (Playwright/patchright/Camoufox). schrute's own SSRF/domain gates are `PENDING` upstream, so logbook enforces its **own** egress allowlist until they're verified in adapter tests.

## Endpoint inventory

`logbook inventory scan` discovers, locally and read-only: installed agent CLIs (claude, cursor, codex, gemini, aider, opencode, …); configured MCP servers across Cursor/Claude/Codex/VS Code/Cline/Zed configs (with secrets redacted); running agent processes; and the presence of `schrute` / `security-suite`. It flags unsanctioned/untracked items as risk/shadow findings and renders five views — **Endpoint · Agents · MCP Servers · Sessions · Risk/Shadow** — in `report` and in the UI.

## Export

The unified `Event` maps to a canonical OpenTelemetry span, then re-keys for OpenInference span-kinds, Langfuse observations, and MLflow spans. v1 emits the document to stdout/file (golden-tested); the network/OTLP push wire lands in v1.5.

---

## Architecture

Single binary; a Cargo workspace where `agent` and `hub` modes share `core` + `store`, so the event model is defined once.

| Crate | Responsibility | Drawn from |
|-------|----------------|-----------|
| `logbook-core` | unified `Event` model, ids (W3C-width), redaction, errors | new |
| `logbook-store` | SQLite (rusqlite + refinery) single-writer + read pool; FTS; JSONL fallback | new / OpenLogs |
| `logbook-capture` | PTY capture, process-tree supervisor, ANSI cleaning, paths/run-index/tail | OpenLogs |
| `logbook-collector` | axum `/health` + token-gated `/ingest`; injected-JS + schrute adapters | OpenLogs + schrute |
| `logbook-mcp` | rmcp stdio server; read default, write gated | local-logs-mcp + new |
| `logbook-debug` | passive evidence + DAP logpoints (alpha) | Cursor (redesigned) + DAP |
| `logbook-inventory` | agent/MCP discovery, `agent` wrapper, diff watcher, risk findings | new |
| `logbook-security` | scanner runner + SARIF/JSON import | security-suite |
| `logbook-ui` | axum static + SSE; embeds `ui/dist` | new |
| `logbook-export` | OTel/OpenInference/Langfuse/MLflow mapping + golden tests | OTel/OpenInference |
| `logbook-hub` | v1.5 receiver/retention/audit/RBAC (stub) | new |
| `logbook-cli` | clap command tree, the `logbook` binary | new |

**Unified event schema:** `id`, `trace_id`, `parent_id?`, `timestamp`, `duration_ms?`, `kind` (span\|event\|log), `type`, `category` (agent\|browser\|app_log\|code_test\|security\|inventory), `operation`, `name`, `status`, `error?`, `attributes`, `input?`, `output?`, `session_id?`, plus optional typed blocks `llm`/`tool`/`agent`/`console`/`network`/`finding`.

---

## Roadmap (v1.5+)

- **Hub:** self-hosted receiver + dashboard, retention, audit log, RBAC; multi-endpoint inventory roll-up.
- **Security governance:** auto-scan the agent's diffs + gate/annotate; strix / pentagi / codeql / nuclei.
- **Export wire:** OTLP network push (currently schema-only).
- **Browser:** full Chrome DevTools / CDP performance-trace adapter.
- **Debug:** broader DAP runtime coverage; (optional, approval-gated) source-instrumentation fallback.

## Development

```sh
cargo build --workspace
cargo test  --workspace            # 362 tests, 0 failing
cargo clippy --workspace --all-targets
LOGBOOK_BLESS=1 cargo test -p logbook-export   # regenerate export golden fixtures
```

Edition 2021, resolver 2. The OpenLogs behavioral contract (Ctrl-C → 130, SIGINT grace, `setsid` descendant reaping, tail resolution) is ported as tests in `crates/logbook-capture/tests/`.

## Known limitations

- **POSIX only** (macOS/Linux); Windows is unsupported (errors out, like OpenLogs).
- `runs.jsonl` stores the command line unredacted (see [Security](#security--redaction)).
- DAP logpoints are **alpha**; the CLI exposes only the reliable passive debug tier.
- `debug fetch --query` uses FTS exact-match (no implicit substring/prefix).
- The collector token contract is unit-tested but not yet verified end-to-end via the CLI.
- `logbook ui` has no parent-PID watchdog — stop it with Ctrl-C.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
