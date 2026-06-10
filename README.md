# logbook

> **A local-first black-box flight recorder for AI coding agents.**
> It records what your agent actually did — every prompt, tool call, command, and file change — onto one redacted, replayable, local timeline. So you can review it, catch risky actions before they land, undo a bad run, and debug from real evidence.

When an AI coding agent works on your machine, you mostly see the *result*: some files changed, a summary in the chat. What it read, the commands it ran, the secrets it touched, the prompts and responses behind it all — gone the moment the session ends. `logbook` is the recorder for that session.

Point it at any agent — **Claude Code, Codex, Aider, or any CLI / SDK** — and it captures the session as structured, secret-redacted events in a local SQLite timeline you fully own. Nothing leaves your machine unless you explicitly export it.

```
$ logbook agent -- claude
… your normal Claude Code session …
agent session recorded: claude (7 file action(s), exit 0)

$ logbook detect <session>
[high] secret_in_diff: redacted secret (CLOUD_KEY) present in code change (config.ts)
[high] dangerous_shell: dangerous shell command: recursive force-remove (rm -rf)

$ logbook revert <session>      # undo exactly what the agent changed
$ logbook ui                    # replay the whole thing in a local web UI
```

- **Local-first & private** — one SQLite file, loopback-only servers, no telemetry. Secrets are scrubbed *at capture, before anything is written to disk*.
- **Agent-agnostic** — wrap any CLI; ingest Claude Code hooks; parse Codex's structured stream; proxy raw provider traffic; or **import** an IDE assistant's on-disk history after the fact.
- **Single static binary** — Rust core + an embedded web UI. Apache-2.0.

---

## What it records — three fidelity tiers

| Tier | What it captures | How |
|------|------------------|-----|
| **Universal** | Redacted terminal transcript, commands + exit codes, **session-accurate file diffs** | Wrap any command/agent in a capturing PTY |
| **Structured** | Prompts, tool calls with arguments & results, model / token / cost, turn-and-step tree | Claude Code hooks, an MCP proxy, Codex `--json`, or OTLP ingest |
| **Complete** | Full provider request/response traffic | An opt-in local LLM API proxy |

Higher tiers are additive — turn on as much fidelity as you want. Everything lands on **one correlated timeline**, keyed by trace and session, so the prompts, the tool calls, and the diffs from a single run read as one coherent story.

## Quick start

Requires a Rust toolchain (1.80+). The web UI ships prebuilt; the optional security scanners (`semgrep`, `trivy`, `cargo-audit`) soft-degrade if absent.

```sh
cargo install --path crates/logbook-cli     # installs `logbook` to ~/.cargo/bin
# …or build the binary directly:
cargo build --release                        # → target/release/logbook
```

```sh
logbook agent -- claude            # record a Claude Code session + its file diffs
logbook detect <session>           # scan it for secrets, dangerous commands, risky git, egress…
logbook ui                         # replay everything in a local web UI (http://127.0.0.1:7878)
logbook revert <session>           # undo exactly what the agent changed (clean-tree sessions)
```

Everything lands under `./.logbook/` in the current project (override with `--out-dir`). Capture is **on by default within a session you explicitly start** — never passive background harvesting.

## Capture your agent

You choose how deep to record, per agent. These compose.

### Claude Code

```sh
# Tier 1 — transcript + file diffs (no setup):
logbook agent -- claude

# Tier 3 — full prompts/responses + token usage. Start the proxy, point Claude at it:
logbook proxy llm --provider anthropic --yes --no-token
export ANTHROPIC_BASE_URL=http://127.0.0.1:<port>      # the proxy prints this
logbook agent -- claude

# Tier 2 — structured tool calls via Claude Code hooks:
logbook hooks                                          # prints a copy-paste settings.json recipe
claude --settings <that-file>
```

Run all three at once and they correlate into a single session.

### Codex

Codex emits a rich structured event stream, so logbook captures it natively — token usage, tool calls, file changes, and reasoning — with no hook wiring:

```sh
logbook codex -- "refactor the auth module and add tests"
# → codex session …: 4 llm turns, 9 tool calls, 3 file changes, 41k tokens
```

(`logbook agent -- codex exec …` also works for the transcript + diffs tier.)

### Anything else

Any CLI gets the Universal tier: `logbook agent -- <cli>`. Any agent or SDK that talks to a provider directly and honors a base-URL override (`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`) can be recorded by the LLM proxy. Any MCP-using agent can route its tools through `logbook proxy mcp -- <server>`. Tools that proxy LLM traffic through their own cloud backend can't be intercepted locally — for those, use the wrap or MCP tiers, or **import their on-disk history after the fact** (see [Import what already happened](#import-what-already-happened)).

## Import what already happened

Live capture covers the agents you launch through logbook. But GUI/IDE assistants that route their traffic through a private cloud backend — Cursor and others — leave nothing to intercept locally, even though their conversations sit on disk. `logbook import` reads those on-disk stores **retroactively** and lands each past session on the same redacted timeline:

```sh
logbook import cursor --dry-run     # list discovered conversations; writes nothing
logbook import cursor                # import them — redacted, deduplicated, replayable
logbook import gemini                # also supported: gemini (Gemini CLI), continue (Continue)
```

- **Opt-in and explicit** — you run it, per tool; never background harvesting.
- **Same redaction floor** — imported records flow through the identical secrets-floor pipeline before anything is written; the importer never persists a raw payload.
- **Idempotent** — every id and timestamp is derived from the source (namespaced per store), so re-importing an unchanged store changes nothing — no duplicates.
- **Read-only at the source** — stores are opened read-only; a locked store is skipped with a note, never modified.

Imported sessions appear in the web UI and answer to `detect`, `export`, and the rest, exactly like live captures. `logbook inventory scan` surfaces what's importable without touching it. Supported today: **Cursor** (chat / composer / agent `state.vscdb`), **Gemini CLI**, and **Continue**; Windsurf, Trae, and OpenCode are planned.

## What you can do with the recording

- **Review a run** — replay the transcript, browse the per-file diffs, the tool calls, and the prompts/responses in the web UI or over a read-only MCP surface (so the *agent itself* can query past sessions).
- **Catch risk** — `logbook detect` runs rules over a session: secret-in-diff, dangerous shell (`rm -rf`, fork bombs), risky git (force-push), non-allowlisted network egress, token/cost spikes, tool-call-rate bursts. `logbook guard -- <agent>` runs the agent and **fails (non-zero exit) if a finding crosses a severity threshold** — a CI gate for agent behavior.
- **Undo** — `logbook revert <session>` reverses exactly the files a clean-tree session changed, guarded by a recorded post-state hash so it refuses if you've since edited the file.
- **Share safely** — `logbook session export <id>` writes a self-contained, per-class **sanitized** bundle (metadata only by default; payload classes dropped) for a bug report or PR.
- **Forget** — `logbook forget <session | --before 7d>` irreversibly deletes a session from the store *and* disk; retention caps prune automatically.
- **Account for cost** — per-session, per-model token and cost roll-ups.
- **Export** — emit the timeline to OpenTelemetry / OpenInference / Langfuse / MLflow — or a **redacted chat dataset for fine-tuning** (`--format finetune`; message bodies stay out unless you pass `--include-payloads`).
- **Roll up a fleet** — `logbook hub serve` receives redacted records from many machines, with role-based visibility, server-side retention, and a tamper-evident hash-chain audit log.

## Privacy & safety

logbook is built so the recording can never become a liability.

- **Redaction before persistence — always.** A mandatory **secrets floor** (cloud keys, JWTs, bearer tokens, PEM blocks, `user:pass@` URLs, …) scrubs every record *before it is written*, independent of any setting — `--no-redact` only relaxes general/non-secret redaction, never the floor. Placeholders preserve a length class but not the value: `AKIA… → «REDACTED:CLOUD_KEY:20»`.
- **No raw file preimages.** Session diffs are computed from an in-memory, **redacted** content baseline; only the redacted diff is stored. The proxy reassembles streamed responses and redacts them before recording — it never persists a raw provider payload.
- **Local-only by default.** One SQLite file under `.logbook/`. Every server binds loopback; ingest endpoints are bearer-gated (token in `collector.token`, `0600`). No outbound network unless you export.
- **Fail-closed capture policy.** A `[capture]` section governs per-tier and per-sensitivity-class capture; a malformed policy degrades to capture-**off**, never silently to recording everything.
- **One switch to pause.** A capture toggle (UI button or `.logbook/capture-state.json`) pauses recording across every logbook process for the session.
- **Tamper-evidence at the fleet.** The hub keeps a SHA-256 hash-chain over already-redacted stored records, so a later edit to any row is detectable.

## Commands

All subcommands accept `--out-dir <path>` (default `.logbook`).

| Command | What it does |
|---------|--------------|
| `logbook run -- <cmd>` | Capture any command in a PTY → transcript + cleaned text + structured events |
| `logbook tail [query] [-- <tail args>]` | Replay/follow a captured run (latest, or fuzzy-matched) |
| `logbook agent -- <agent-cli>` | Wrap an agent session: transcript + session-accurate file diffs |
| `logbook codex -- <task>` | Run Codex under capture, recording its `--json` event stream as structured events |
| `logbook import <cursor\|gemini\|continue>` | Retroactively import an agent's on-disk conversation history onto the timeline — redacted, idempotent, read-only at the source (`--dry-run` to preview) |
| `logbook proxy llm --yes [--no-token]` | Opt-in local LLM API proxy — records full provider prompts/responses (Anthropic & OpenAI Chat/Responses) |
| `logbook proxy mcp -- <server>` | Relay an agent's MCP through logbook, recording redacted tool calls |
| `logbook hooks` | Receiver for Claude Code hooks / OTLP; prints a ready-to-paste settings recipe |
| `logbook detect [session]` | Run the risk rules over a session (or recent events); print + persist findings |
| `logbook guard -- <agent>` | Run an agent, then fail non-zero if a finding crosses `--halt-on` |
| `logbook revert <session>` | Reverse a clean-tree session's file changes (post-state-hash guarded) |
| `logbook session export <id>` | Write a per-class sanitized session bundle |
| `logbook forget <session \| --before <dur>>` | Irreversibly delete a session from store + disk (`--yes`) |
| `logbook inventory <scan\|watch\|report>` | Discover local agent CLIs, MCP servers, importable conversation stores, and risk/shadow items |
| `logbook security <scan\|import>` | Run scanners (Semgrep/Trivy/cargo-audit) or import any SARIF/JSON |
| `logbook export --format <otel\|openinference\|langfuse\|mlflow\|finetune>` | Export the timeline to a tracing schema, or a redacted fine-tuning chat dataset (`finetune`; bodies opt-in via `--include-payloads`) |
| `logbook ui` | Embedded web UI — timeline, session replay, inventory, risk feed |
| `logbook mcp` | Read-only MCP tool surface over stdio for your agent |
| `logbook hub serve` | Fleet receiver: RBAC, retention, hash-chain audit, multi-endpoint roll-up |

## Configuration — `logbook.toml`

Loaded from the workspace root (`--root`, default cwd). Shipped defaults are conservative; the file is fully optional.

```toml
[capture]                         # recorder-on by default, within explicitly-started sessions
enabled = true
[capture.tiers]
universal = true
structured = true
complete = false                  # the LLM-proxy tier is opt-in by mechanism

[capture.classes.secrets]         # the secrets floor is locked on; this cannot be disabled
redaction = "always"

[permissions]
enabled_writes  = []              # ["browser","security","inventory_watch", …]; [] = read-only
allowed_domains = []              # egress allowlist; [] blocks all external navigation

[redaction]
enabled = true                    # extra patterns via `deny`; false-positive exclusions via `allow`
deny = []
allow = []

[retention]
max_age_days = 14
max_db_mb    = 512
```

## How it's built

A single binary over a Cargo workspace; the event model is defined once and shared by every capture lane.

| Crate | Responsibility |
|-------|----------------|
| `logbook-core` | Unified `Event` model, ids, redaction, capture policy, trace correlation |
| `logbook-store` | SQLite store (rusqlite + refinery), FTS, retention/prune, hash-chain audit |
| `logbook-capture` | PTY capture, process-tree supervision, ANSI cleaning, transcript tiers |
| `logbook-inventory` | Agent/MCP discovery, the `agent` wrapper, session-accurate diffs, revert/export/forget |
| `logbook-harness` | Harness adapters — Claude Code hooks, Codex `--json`, Aider; Cursor / Gemini / Continue session adapters |
| `logbook-import` | Retroactive importers — discover & read on-disk agent stores into redacted events (CLI owns persistence; no store/inventory dep) |
| `logbook-collector` | Loopback ingest (`/v1/hooks`, `/v1/traces`, browser `/ingest`) + MCP proxy |
| `logbook-llmproxy` | Opt-in LLM API proxy (Anthropic + OpenAI Chat/Responses), SSE reassembly, force-redaction |
| `logbook-detect` | Anomaly/risk rule engine → `Finding` events |
| `logbook-mcp` | rmcp stdio server — read by default, write gated |
| `logbook-security` | Security scanner runner + SARIF/JSON import |
| `logbook-export` | OTel / OpenInference / Langfuse / MLflow mapping |
| `logbook-ui` | Embedded web UI (axum + SSE), serves the prebuilt React bundle |
| `logbook-hub` | Fleet receiver — RBAC, retention, hash-chain audit, roll-up |
| `logbook-cli` | The `logbook` binary (clap command tree) |

**The unified event** carries `id`, `trace_id`, `parent_id?`, `timestamp`, `kind`, `category`, `operation`, `name`, `status`, `attributes`, `input?`/`output?`, `session_id?`, plus optional typed blocks (`llm` / `tool` / `agent` / `console` / `network` / `finding`) — so a prompt, a shell command, a file diff, and a security finding all live on one timeline.

## Notes

- **macOS / Linux.** (Windows is not supported.)
- Reversing a session uses git as the preimage, so it applies to **clean-tree** sessions; reverting changes made on top of a dirty working tree is planned (it requires encrypted preimage storage).
- GUI / IDE assistants that route LLM traffic through their own cloud backend can't be captured *live* by the local proxy — use the wrap or MCP tiers, or **`logbook import`** to pull their on-disk history retroactively (Cursor / Gemini / Continue today; Windsurf / Trae / OpenCode planned).

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
