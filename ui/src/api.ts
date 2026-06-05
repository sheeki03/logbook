// Typed client for the logbook-ui JSON + SSE API. All paths are relative so
// the same bundle works whether it is served by the embedded axum server or
// proxied through `vite dev`.

import type {
  AgentEvent,
  Category,
  CapturePolicyUpdate,
  CapturePolicyView,
  EventPage,
  FindingPage,
  Inventory,
  SessionDetail,
  SessionPage,
  SessionSummary,
  SessionTree,
  Severity,
} from "./types";

// The header the capture-toggle POST must echo the per-process CSRF token in.
// Mirrors `logbook_ui::CSRF_HEADER`.
const CSRF_HEADER = "x-logbook-csrf";

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, {
    headers: { accept: "application/json" },
    signal,
  });
  if (!res.ok) {
    throw new Error(`GET ${path} failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

// Read a JSON error body's `error` field if present, for a useful message.
async function errorText(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    if (body && typeof body.error === "string") return body.error;
  } catch {
    // fall through to the status line
  }
  return `${res.status} ${res.statusText}`;
}

export interface EventQuery {
  category?: Category;
  trace_id?: string;
  session_id?: string;
  q?: string;
  limit?: number;
}

function eventQueryString(query: EventQuery): string {
  const params = new URLSearchParams();
  if (query.category) params.set("category", query.category);
  if (query.trace_id) params.set("trace_id", query.trace_id);
  if (query.session_id) params.set("session_id", query.session_id);
  if (query.q) params.set("q", query.q);
  if (query.limit != null) params.set("limit", String(query.limit));
  const s = params.toString();
  return s ? `?${s}` : "";
}

export const api = {
  // Flat event list, newest-first, optionally filtered.
  async events(query: EventQuery = {}, signal?: AbortSignal): Promise<AgentEvent[]> {
    const page = await getJson<EventPage>(
      `/api/events${eventQueryString(query)}`,
      signal,
    );
    return page.events;
  },

  // Timeline: events across all categories ordered oldest-first for reading.
  async timeline(query: EventQuery = {}, signal?: AbortSignal): Promise<AgentEvent[]> {
    const page = await getJson<EventPage>(
      `/api/timeline${eventQueryString(query)}`,
      signal,
    );
    return page.events;
  },

  // Endpoint inventory snapshot (all five tabs in one payload).
  async inventory(signal?: AbortSignal): Promise<Inventory> {
    return getJson<Inventory>("/api/inventory", signal);
  },

  // Recorded agent sessions, newest-first (master list).
  async sessions(signal?: AbortSignal): Promise<SessionSummary[]> {
    const page = await getJson<SessionPage>("/api/sessions", signal);
    return page.sessions;
  },

  // One session's full replay detail (header + transcript + diffs + events).
  async session(id: string, signal?: AbortSignal): Promise<SessionDetail> {
    return getJson<SessionDetail>(`/api/sessions/${encodeURIComponent(id)}`, signal);
  },

  // The session's correlation timeline: its events grouped by turn (Phase 3).
  async sessionTree(id: string, signal?: AbortSignal): Promise<SessionTree> {
    return getJson<SessionTree>(
      `/api/sessions/${encodeURIComponent(id)}/tree`,
      signal,
    );
  },

  // Security findings, newest-first (Phase 3 Risk feed). `minSeverity` drops
  // findings below the given rank (info < low < medium < high < critical).
  async findings(minSeverity?: Severity, signal?: AbortSignal): Promise<AgentEvent[]> {
    const qs = minSeverity ? `?severity=${encodeURIComponent(minSeverity)}` : "";
    const page = await getJson<FindingPage>(`/api/findings${qs}`, signal);
    return page.findings;
  },

  // The effective capture policy + the CSRF token + the conflict version.
  async getCapturePolicy(signal?: AbortSignal): Promise<CapturePolicyView> {
    return getJson<CapturePolicyView>("/api/capture-policy", signal);
  },

  // Narrow/widen the capture policy. `view` carries the CSRF token + version
  // from a prior `getCapturePolicy` so the write is authenticated and
  // conflict-checked. Returns the freshly-resolved policy view.
  async setCapturePolicy(
    view: CapturePolicyView,
    update: CapturePolicyUpdate,
    signal?: AbortSignal,
  ): Promise<CapturePolicyView> {
    const body: CapturePolicyUpdate = {
      ...update,
      expected_version: update.expected_version ?? view.version,
    };
    const res = await fetch("/api/capture-policy", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        [CSRF_HEADER]: view.csrf_token,
      },
      body: JSON.stringify(body),
      signal,
    });
    if (!res.ok) {
      throw new Error(`capture-policy update failed: ${await errorText(res)}`);
    }
    return (await res.json()) as CapturePolicyView;
  },
};

// Subscribe to the live event tail over SSE. Returns an unsubscribe function.
// Each `message` event carries one JSON-encoded `AgentEvent`.
export function subscribeEvents(
  onEvent: (event: AgentEvent) => void,
  onError?: (err: Event) => void,
): () => void {
  const source = new EventSource("/api/stream");
  source.addEventListener("message", (ev: MessageEvent<string>) => {
    try {
      onEvent(JSON.parse(ev.data) as AgentEvent);
    } catch (err) {
      // Keep-alive comments never reach here, so a parse failure means the
      // server emitted a genuinely malformed `message` frame. Drop it (the
      // live tail is non-fatal and the durable store reconciles gaps) but
      // leave a breadcrumb so a serialization regression is diagnosable.
      const snippet =
        typeof ev.data === "string" ? ev.data.slice(0, 200) : ev.data;
      console.warn("logbook: dropped malformed SSE frame", err, snippet);
    }
  });
  if (onError) {
    source.addEventListener("error", onError);
  }
  return () => source.close();
}
