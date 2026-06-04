// Typed client for the logbook-ui JSON + SSE API. All paths are relative so
// the same bundle works whether it is served by the embedded axum server or
// proxied through `vite dev`.

import type { AgentEvent, Category, EventPage, Inventory } from "./types";

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
