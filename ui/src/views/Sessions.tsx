import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import type {
  AgentEvent,
  SessionAction,
  SessionDetail,
  SessionSummary,
} from "../types";
import { eventSummary, formatTime } from "../format";
import { CategoryBadge, StatusBadge } from "../components/Badge";
import { CapturePanel } from "./CapturePanel";

// Session replay (Orbit plan §1.4): a master list of recorded `logbook agent`
// sessions -> a detail view with the redacted transcript pointer, commands,
// tool/LLM events, session-accurate file diffs (truncated + revert_safe
// badges), exit status, and a per-session timeline (the event-row reused,
// scoped to this session's trace).

export function Sessions() {
  const [list, setList] = useState<SessionSummary[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function reload(signal?: AbortSignal) {
    api
      .sessions(signal)
      .then((s) => {
        setList(s);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!signal?.aborted) setError(String(e));
      });
  }

  useEffect(() => {
    const ctrl = new AbortController();
    reload(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  return (
    <div className="sessions">
      <CapturePanel />

      <div className="tabbar">
        <span className="section-title">Sessions</span>
        <span className="count">{list ? `${list.length} recorded` : "…"}</span>
        <button className="refresh" onClick={() => reload()} type="button">
          Refresh
        </button>
      </div>

      {error && <div className="error-bar">{error}</div>}
      {!list && !error && <div className="empty">Loading sessions…</div>}

      {list && list.length === 0 && (
        <div className="empty">
          No sessions recorded. Run <span className="mono">logbook agent -- &lt;cli&gt;</span> to
          capture one.
        </div>
      )}

      {list && list.length > 0 && (
        <SessionTable
          sessions={list}
          selected={selected}
          onSelect={(id) => setSelected(id)}
        />
      )}

      {selected && (
        <SessionReplay sessionId={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function SessionTable({
  sessions,
  selected,
  onSelect,
}: {
  sessions: SessionSummary[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="session-list">
      <table className="grid">
        <thead>
          <tr>
            <th>Agent</th>
            <th>Command</th>
            <th>Started</th>
            <th>Actions</th>
            <th>Transcript</th>
            <th>Exit</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => {
            const failed = s.exit_code != null && s.exit_code !== 0;
            return (
              <tr
                key={s.session_id}
                className={`${failed ? "is-error" : ""} ${selected === s.session_id ? "row-selected" : ""}`}
                onClick={() => onSelect(s.session_id)}
              >
                <td>{s.agent}</td>
                <td className="mono ellipsis">{s.command}</td>
                <td>{formatTime(s.started_at)}</td>
                <td className="num">{s.action_count}</td>
                <td>{s.has_transcript ? <span className="badge ok-pill">yes</span> : "—"}</td>
                <td className="num">{s.exit_code ?? (s.ended_at ? "—" : "running")}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Detail slide-over: replays one session.
function SessionReplay({
  sessionId,
  onClose,
}: {
  sessionId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setDetail(null);
    setError(null);
    api
      .session(sessionId, ctrl.signal)
      .then(setDetail)
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) setError(String(e));
      });
    return () => ctrl.abort();
  }, [sessionId]);

  return (
    <aside className="detail-panel wide">
      <div className="detail-head">
        <strong>session replay</strong>
        <button className="close" onClick={onClose} type="button">
          ×
        </button>
      </div>

      {error && <div className="error-bar">{error}</div>}
      {!detail && !error && <div className="empty">Loading session…</div>}

      {detail && <ReplayBody detail={detail} />}
    </aside>
  );
}

function ReplayBody({ detail }: { detail: SessionDetail }) {
  const { session, transcript, actions, events } = detail;

  // Partition the trace stream into the panels the plan calls for.
  const { commands, toolLlm } = useMemo(() => partitionEvents(events), [events]);

  return (
    <div className="replay">
      {/* Session header + exit */}
      <dl className="detail-grid">
        <dt>agent</dt>
        <dd>{session.agent}</dd>
        <dt>command</dt>
        <dd className="mono">{session.command}</dd>
        <dt>started</dt>
        <dd>{formatTime(session.started_at)}</dd>
        <dt>ended</dt>
        <dd>{session.ended_at ? formatTime(session.ended_at) : "running"}</dd>
        <dt>exit</dt>
        <dd className={session.exit_code ? "err" : ""}>
          {session.exit_code ?? "—"}
        </dd>
      </dl>

      {/* Transcript / Prompt */}
      <Section title="Transcript">
        {transcript ? (
          <dl className="kv">
            <dt>terminal</dt>
            <dd className="mono ellipsis">{transcript.terminal_log_path ?? "—"}</dd>
            <dt>text</dt>
            <dd className="mono ellipsis">{transcript.text_path ?? "—"}</dd>
            <dt>lines</dt>
            <dd className="num">{transcript.line_count ?? "—"}</dd>
            <dt>bytes</dt>
            <dd className="num">{transcript.byte_size ?? "—"}</dd>
          </dl>
        ) : (
          <div className="empty small">No transcript captured for this session.</div>
        )}
      </Section>

      {/* Commands */}
      <Section title={`Commands (${commands.length})`}>
        {commands.length === 0 ? (
          <div className="empty small">No commands recorded.</div>
        ) : (
          <ul className="event-mini-list">
            {commands.map((ev) => (
              <li key={ev.id} className={ev.status === "error" ? "is-error" : ""}>
                <span className="ts">{formatTime(ev.timestamp)}</span>
                <span className="mono">{eventSummary(ev)}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* Tool / LLM events */}
      <Section title={`Tool / LLM (${toolLlm.length})`}>
        {toolLlm.length === 0 ? (
          <div className="empty small">No tool or LLM events (Phase 2 mechanism).</div>
        ) : (
          <ul className="event-mini-list">
            {toolLlm.map((ev) => (
              <li key={ev.id}>
                <span className="ts">{formatTime(ev.timestamp)}</span>
                <span className="kind-tag">{ev.kind}</span>
                <span className="mono">{eventSummary(ev)}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* Diffs */}
      <Section title={`Diffs (${actions.length})`}>
        {actions.length === 0 ? (
          <div className="empty small">No file diffs recorded.</div>
        ) : (
          actions.map((a, i) => <DiffCard key={`${a.path ?? "diff"}-${i}`} action={a} />)
        )}
      </Section>

      {/* Per-session timeline — the event-row reused, scoped to this trace */}
      <Section title={`Timeline (${events.length})`}>
        {events.length === 0 ? (
          <div className="empty small">No correlated events for this session.</div>
        ) : (
          <div className="session-timeline">
            {events.map((ev) => (
              <div
                key={ev.id}
                className={`event-row cat-${ev.category} ${ev.status === "error" ? "is-error" : ""}`}
              >
                <span className="ts">{formatTime(ev.timestamp)}</span>
                <CategoryBadge category={ev.category} />
                <span className="op">{ev.operation}</span>
                <span className="summary">{eventSummary(ev)}</span>
                <StatusBadge status={ev.status} />
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function DiffCard({ action }: { action: SessionAction }) {
  // diff_bytes is the original pre-truncation length, so diff_bytes > rendered
  // length flags a truncated body (the cap_body convention).
  const truncated =
    action.diff != null &&
    action.diff_bytes != null &&
    action.diff_bytes > action.diff.length;

  return (
    <div className="diff-card">
      <div className="diff-head">
        <span className="diff-kind">{action.kind}</span>
        <span className="mono ellipsis diff-path">{action.path ?? "—"}</span>
        <span className="diff-badges">
          {truncated && <span className="badge sev-medium">truncated</span>}
          <span className={`badge ${action.revert_safe ? "sanction ok" : "sanction shadow"}`}>
            {action.revert_safe ? "revert-safe" : "no-revert"}
          </span>
        </span>
      </div>
      {action.diff != null ? (
        <pre className="diff-body">{action.diff}</pre>
      ) : (
        <div className="empty small">Diff omitted (size cap or diffs off).</div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="replay-section">
      <h4 className="replay-section-title">{title}</h4>
      {children}
    </section>
  );
}

// Split the ordered trace into command vs tool/LLM panels. Everything else
// (transcript line-events, spans, etc.) still appears in the timeline panel.
function partitionEvents(events: AgentEvent[]): {
  commands: AgentEvent[];
  toolLlm: AgentEvent[];
} {
  const commands: AgentEvent[] = [];
  const toolLlm: AgentEvent[] = [];
  for (const ev of events) {
    if (ev.kind === "tool" || ev.kind === "llm") {
      toolLlm.push(ev);
    } else if (
      ev.kind === "test" ||
      ev.operation === "run" ||
      ev.operation === "command" ||
      ev.operation === "exec"
    ) {
      commands.push(ev);
    }
  }
  return { commands, toolLlm };
}
