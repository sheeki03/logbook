import { useEffect, useMemo, useState } from "react";

import { api, subscribeEvents } from "../api";
import type { AgentEvent, Severity } from "../types";
import { formatTime, SEVERITY_ORDER } from "../format";
import { SeverityBadge } from "../components/Badge";

// Risk view (Phase 3): the security-findings feed. Findings are
// Kind::Finding + Category::Security events carrying a FindingBlock, emitted by
// the detect engine (secret-in-diff, dangerous shell, risky git, egress, …).
// Listed newest-first, filterable to a minimum severity, with severity badges
// reusing the dark design system's category/severity hues (index.css).

// The severity filter chips, most-severe first (matches SEVERITY_ORDER).
const SEVERITIES: Severity[] = SEVERITY_ORDER;

export function Risk() {
  const [findings, setFindings] = useState<AgentEvent[] | null>(null);
  const [minSeverity, setMinSeverity] = useState<Severity | null>(null);
  const [error, setError] = useState<string | null>(null);

  function reload(signal?: AbortSignal) {
    api
      .findings(minSeverity ?? undefined, signal)
      .then((f) => {
        setFindings(f);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!signal?.aborted) setError(String(e));
      });
  }

  // Refetch whenever the severity floor changes.
  useEffect(() => {
    const ctrl = new AbortController();
    reload(ctrl.signal);
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [minSeverity]);

  // Live-refresh when a security event streams in (e.g. a fresh detection),
  // debounced so a burst of findings coalesces into one reload.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const unsub = subscribeEvents((ev) => {
      if (ev.category === "security") {
        clearTimeout(timer);
        timer = setTimeout(() => reload(), 250);
      }
    });
    return () => {
      clearTimeout(timer);
      unsub();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [minSeverity]);

  // Defensive client-side sort: the API already returns newest-first, but sort
  // by severity (desc) then recency so the worst findings lead the list.
  const sorted = useMemo(() => {
    if (!findings) return null;
    const rank = (ev: AgentEvent) => {
      const i = SEVERITY_ORDER.indexOf((ev.finding?.severity ?? "info") as never);
      return i < 0 ? SEVERITY_ORDER.length : i;
    };
    return [...findings].sort(
      (a, b) => rank(a) - rank(b) || b.timestamp - a.timestamp,
    );
  }, [findings]);

  return (
    <div className="risk">
      <div className="tabbar">
        <span className="section-title">Risk</span>
        <span className="count">
          {sorted ? `${sorted.length} finding${sorted.length === 1 ? "" : "s"}` : "…"}
        </span>
        <div className="filters sev-filters">
          <button
            className={`chip ${minSeverity == null ? "on" : "off"}`}
            onClick={() => setMinSeverity(null)}
            type="button"
          >
            all
          </button>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              className={`chip sev-chip sev-${s} ${minSeverity === s ? "on" : "off"}`}
              onClick={() => setMinSeverity(s)}
              type="button"
              title={`severity ≥ ${s}`}
            >
              {s}
            </button>
          ))}
        </div>
        <button className="refresh" onClick={() => reload()} type="button">
          Refresh
        </button>
      </div>

      {error && <div className="error-bar">{error}</div>}
      {!sorted && !error && <div className="empty">Loading findings…</div>}

      {sorted && sorted.length === 0 && (
        <div className="empty">
          No security findings{minSeverity ? ` at severity ≥ ${minSeverity}` : ""}.
          Detection runs over recorded sessions (secret-in-diff, dangerous shell,
          risky git, non-allowlisted egress, cost/rate spikes).
        </div>
      )}

      {sorted && sorted.length > 0 && (
        <div className="finding-list">
          {sorted.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding }: { finding: AgentEvent }) {
  const fb = finding.finding;
  // Tint the card's left rail by severity by mirroring the badge class.
  const sev = fb?.severity;
  const location =
    fb?.file != null
      ? `${fb.file}${fb.line != null ? `:${fb.line}` : ""}`
      : null;

  return (
    <div className={`finding sev-rail-${sev ?? "info"}`}>
      <div className="finding-head">
        <SeverityBadge severity={sev} />
        <span className="finding-kind">{fb?.rule_id ?? finding.name}</span>
        {fb?.source && <span className="finding-source">{fb.source}</span>}
        {location && <span className="finding-subject mono">{location}</span>}
      </div>
      {fb?.message && <p className="finding-msg">{fb.message}</p>}
      <div className="finding-foot">
        <span className="finding-time">{formatTime(finding.timestamp)}</span>
        <span className="finding-trace mono" title={finding.trace_id}>
          trace {finding.trace_id.slice(0, 8)}
        </span>
      </div>
    </div>
  );
}
