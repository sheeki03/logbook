import { useEffect, useMemo, useRef, useState } from "react";

import { api, subscribeEvents } from "../api";
import type { AgentEvent, Category } from "../types";
import {
  ALL_CATEGORIES,
  categoryLabel,
  eventSummary,
  formatDuration,
  formatTime,
} from "../format";
import { CategoryBadge, SeverityBadge, StatusBadge } from "../components/Badge";

const MAX_ROWS = 1000;

// Merge a freshly streamed event into the list, de-duplicating on id and
// keeping the list bounded + oldest-first.
function mergeEvent(list: AgentEvent[], ev: AgentEvent): AgentEvent[] {
  if (list.some((e) => e.id === ev.id)) return list;
  const next = [...list, ev];
  next.sort((a, b) => a.timestamp - b.timestamp);
  return next.length > MAX_ROWS ? next.slice(next.length - MAX_ROWS) : next;
}

export function Timeline() {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [active, setActive] = useState<Set<Category>>(new Set(ALL_CATEGORIES));
  const [live, setLive] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AgentEvent | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  // Initial load.
  useEffect(() => {
    const ctrl = new AbortController();
    api
      .timeline({ limit: MAX_ROWS }, ctrl.signal)
      .then(setEvents)
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) setError(String(e));
      });
    return () => ctrl.abort();
  }, []);

  // Live tail over SSE.
  useEffect(() => {
    if (!live) return;
    const unsub = subscribeEvents(
      (ev) => setEvents((prev) => mergeEvent(prev, ev)),
      () => setError("Live stream disconnected"),
    );
    return unsub;
  }, [live]);

  const visible = useMemo(
    () => events.filter((e) => active.has(e.category)),
    [events, active],
  );

  useEffect(() => {
    if (live) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [visible.length, live]);

  function toggle(cat: Category) {
    setActive((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }

  return (
    <div className="timeline">
      <div className="toolbar">
        <div className="filters">
          {ALL_CATEGORIES.map((cat) => (
            <button
              key={cat}
              className={`chip ${active.has(cat) ? "on" : "off"} cat-${cat}`}
              onClick={() => toggle(cat)}
              type="button"
            >
              {categoryLabel(cat)}
            </button>
          ))}
        </div>
        <label className="live-toggle">
          <input
            type="checkbox"
            checked={live}
            onChange={(e) => setLive(e.target.checked)}
          />
          Live
        </label>
        <span className="count">{visible.length} events</span>
      </div>

      {error && <div className="error-bar">{error}</div>}

      <div className="event-list">
        {visible.length === 0 && (
          <div className="empty">No events yet. Run a command to populate the timeline.</div>
        )}
        {visible.map((ev) => (
          <button
            key={ev.id}
            className={`event-row cat-${ev.category} ${ev.status === "error" ? "is-error" : ""}`}
            onClick={() => setSelected(ev)}
            type="button"
          >
            <span className="ts">{formatTime(ev.timestamp)}</span>
            <CategoryBadge category={ev.category} />
            <span className="op">{ev.operation}</span>
            <span className="summary">{eventSummary(ev)}</span>
            <SeverityBadge severity={ev.finding?.severity} />
            <StatusBadge status={ev.status} />
            <span className="dur">{formatDuration(ev.duration_ms)}</span>
          </button>
        ))}
        <div ref={bottomRef} />
      </div>

      {selected && (
        <EventDetail event={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function EventDetail({ event, onClose }: { event: AgentEvent; onClose: () => void }) {
  return (
    <aside className="detail-panel">
      <div className="detail-head">
        <strong>{event.name}</strong>
        <button className="close" onClick={onClose} type="button">
          ×
        </button>
      </div>
      <dl className="detail-grid">
        <dt>kind</dt>
        <dd>{event.kind}</dd>
        <dt>type</dt>
        <dd>{event.type}</dd>
        <dt>category</dt>
        <dd>{categoryLabel(event.category)}</dd>
        <dt>trace</dt>
        <dd className="mono">{event.trace_id}</dd>
        {event.session_id && (
          <>
            <dt>session</dt>
            <dd className="mono">{event.session_id}</dd>
          </>
        )}
        {event.error && (
          <>
            <dt>error</dt>
            <dd className="err">{event.error}</dd>
          </>
        )}
      </dl>
      <pre className="detail-json">{JSON.stringify(event, null, 2)}</pre>
    </aside>
  );
}
