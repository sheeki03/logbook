// Wire types mirroring the Rust `logbook-core` Event model (plan §2) and the
// inventory DTOs returned by `logbook-ui`'s JSON API. Kept intentionally close
// to the serde representation: snake_case categories, flattened domain blocks,
// `type` (not `type_`) on the wire.

export type Category =
  | "agent"
  | "browser"
  | "app_log"
  | "code_test"
  | "security"
  | "inventory";

export type Kind =
  | "log"
  | "llm"
  | "tool"
  | "agent"
  | "browser"
  | "network"
  | "finding"
  | "test"
  | "span"
  | "other";

export type Status = "unset" | "ok" | "error";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface LlmBlock {
  provider?: string;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  temperature?: number;
  cost_usd?: number;
  finish_reason?: string;
  stream?: boolean;
}

export interface ToolBlock {
  tool_name?: string;
  is_write?: boolean;
  arguments?: unknown;
  result_summary?: string;
}

export interface AgentBlock {
  agent?: string;
  step?: number;
  role?: string;
  // Zero-based turn index (coarser than step); drives the correlation tree.
  turn?: number;
  tool_call_id?: string;
}

export interface ConsoleBlock {
  level?: string;
  message?: string;
  url?: string;
  stack?: string;
}

export interface NetworkBlock {
  method?: string;
  url?: string;
  status_code?: number;
  request_bytes?: number;
  response_bytes?: number;
}

export interface FindingBlock {
  source?: string;
  rule_id?: string;
  severity?: Severity;
  file?: string;
  line?: number;
  message?: string;
}

// The unified event. Domain blocks are flattened onto the parent object by
// serde (`#[serde(flatten)]`), so they appear as optional sibling keys.
export interface AgentEvent {
  id: string;
  trace_id: string;
  parent_id?: string;
  timestamp: number; // microseconds since UNIX epoch
  duration_ms?: number;
  kind: Kind;
  type: string;
  category: Category;
  operation: string;
  name: string;
  status: Status;
  error?: string;
  attributes?: Record<string, unknown>;
  input?: unknown;
  output?: unknown;
  session_id?: string;
  llm?: LlmBlock;
  tool?: ToolBlock;
  agent?: AgentBlock;
  console?: ConsoleBlock;
  network?: NetworkBlock;
  finding?: FindingBlock;
}

// ---- Inventory DTOs (plan §7b) ----

export interface Endpoint {
  id: string;
  hostname: string;
  os?: string;
  arch?: string;
  first_seen: number;
  last_seen: number;
}

export interface AgentInstall {
  id: string;
  endpoint_id: string;
  name: string;
  version?: string;
  path?: string;
  sanctioned: boolean;
  discovered_at: number;
}

export interface McpServer {
  id: string;
  endpoint_id: string;
  name: string;
  source_config?: string;
  command?: string;
  transport?: string;
  sanctioned: boolean;
  has_secret: boolean;
  discovered_at: number;
}

export interface AgentSession {
  id: string;
  endpoint_id?: string;
  agent: string;
  command: string;
  trace_id?: string;
  started_at: number;
  ended_at?: number;
  exit_code?: number;
}

export interface InventoryFinding {
  id: string;
  endpoint_id?: string;
  kind: string;
  severity?: Severity;
  subject?: string;
  message?: string;
  created_at: number;
}

export interface Inventory {
  endpoints: Endpoint[];
  agents: AgentInstall[];
  mcp_servers: McpServer[];
  sessions: AgentSession[];
  findings: InventoryFinding[];
}

export interface EventPage {
  events: AgentEvent[];
}

// ---- Session replay DTOs (Orbit plan §1.4) ----

// One row in the Sessions master list: the agent_sessions header plus the
// recorded action count and a has-transcript flag.
export interface SessionSummary {
  session_id: string;
  agent: string;
  command: string;
  started_at: number; // microseconds since UNIX epoch
  ended_at?: number;
  exit_code?: number;
  action_count: number;
  has_transcript: boolean;
}

// Transcript pointers + metadata (the redacted files live on disk).
export interface SessionTranscript {
  terminal_log_path?: string;
  text_path?: string;
  line_count?: number;
  byte_size?: number;
}

// One recorded file-diff action. `diff_bytes > len(diff)` flags a truncated
// body; `revert_safe` flags a clean-tree (git-revertable) change.
export interface SessionAction {
  kind: string;
  path?: string;
  diff?: string;
  diff_bytes?: number;
  post_hash?: string;
  revert_safe: boolean;
}

// The full per-session replay payload returned by GET /api/sessions/:id.
export interface SessionDetail {
  session: SessionSummary;
  transcript?: SessionTranscript;
  actions: SessionAction[];
  events: AgentEvent[];
}

export interface SessionPage {
  sessions: SessionSummary[];
}

// ---- Risk / findings DTOs (Phase 3) ----

// GET /api/findings: security findings (Kind::Finding + Category::Security
// events carrying a FindingBlock), newest-first, optionally severity-filtered.
export interface FindingPage {
  findings: AgentEvent[];
}

// ---- Correlation timeline DTOs (Phase 3) ----

// One turn of a SessionTree: the turn index (or null for the catch-all group
// of turn-less tool/log/finding events, which sorts last) and its child events
// oldest-first.
export interface TurnGroup {
  turn: number | null;
  events: AgentEvent[];
}

// GET /api/sessions/:id/tree: the session's events grouped by turn (turns
// ascending, the turn-less group last) — the agent action -> diff -> command
// -> runtime log -> finding correlation view.
export interface SessionTree {
  session_id: string;
  turns: TurnGroup[];
  event_count: number;
}

// ---- Capture policy DTOs (Orbit plan §1.4) ----

// Effective per-class capture booleans (secrets is the locked floor, not here).
export interface CaptureClassEnabled {
  transcript: boolean;
  prompts: boolean;
  tool_args: boolean;
  tool_results: boolean;
  file_diffs: boolean;
  commands: boolean;
  browser_data: boolean;
  model_metadata: boolean;
}

// The addressable per-class capture toggle keys (secrets excluded).
export type CaptureClass = keyof CaptureClassEnabled;

// GET /api/capture-policy: the effective policy + the CSRF token + the
// conflict-detection version + the config-write capability.
export interface CapturePolicyView {
  enabled: boolean;
  classes: CaptureClassEnabled;
  secrets_locked: boolean;
  allow_config_write: boolean;
  csrf_token: string;
  version: string;
}

// POST /api/capture-policy body. `target` chooses the runtime overlay
// (capture-state.json, default) or the durable logbook.toml (gated).
export interface CapturePolicyUpdate {
  target?: "runtime" | "config";
  enabled?: boolean;
  classes?: Partial<Record<CaptureClass, boolean>>;
  expected_version?: string;
}
