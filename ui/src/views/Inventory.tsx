import { useEffect, useMemo, useState } from "react";

import { api, subscribeEvents } from "../api";
import type { Inventory as InventoryData } from "../types";
import { formatTime, SEVERITY_ORDER } from "../format";
import { SanctionBadge, SeverityBadge } from "../components/Badge";

type InventoryTab = "endpoint" | "agents" | "mcp" | "sessions" | "risk";

const TABS: { id: InventoryTab; label: string }[] = [
  { id: "endpoint", label: "Endpoint" },
  { id: "agents", label: "Agents" },
  { id: "mcp", label: "MCP Servers" },
  { id: "sessions", label: "Sessions" },
  { id: "risk", label: "Risk / Shadow" },
];

export function Inventory() {
  const [data, setData] = useState<InventoryData | null>(null);
  const [tab, setTab] = useState<InventoryTab>("endpoint");
  const [error, setError] = useState<string | null>(null);

  function reload(signal?: AbortSignal) {
    api
      .inventory(signal)
      .then(setData)
      .catch((e: unknown) => {
        if (!signal?.aborted) setError(String(e));
      });
  }

  useEffect(() => {
    const ctrl = new AbortController();
    reload(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  // Refresh the inventory snapshot when an inventory-category event streams in
  // (e.g. a fresh `inventory scan`), debounced via a short timer.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const unsub = subscribeEvents((ev) => {
      if (ev.category === "inventory") {
        clearTimeout(timer);
        timer = setTimeout(() => reload(), 250);
      }
    });
    return () => {
      clearTimeout(timer);
      unsub();
    };
  }, []);

  return (
    <div className="inventory">
      <div className="tabbar">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`tab ${tab === t.id ? "active" : ""}`}
            onClick={() => setTab(t.id)}
            type="button"
          >
            {t.label}
            {t.id === "risk" && data && data.findings.length > 0 && (
              <span className="tab-badge">{data.findings.length}</span>
            )}
          </button>
        ))}
        <button className="refresh" onClick={() => reload()} type="button">
          Refresh
        </button>
      </div>

      {error && <div className="error-bar">{error}</div>}
      {!data && !error && <div className="empty">Loading inventory…</div>}

      {data && tab === "endpoint" && <EndpointTab data={data} />}
      {data && tab === "agents" && <AgentsTab data={data} />}
      {data && tab === "mcp" && <McpTab data={data} />}
      {data && tab === "sessions" && <SessionsTab data={data} />}
      {data && tab === "risk" && <RiskTab data={data} />}
    </div>
  );
}

function EndpointTab({ data }: { data: InventoryData }) {
  if (data.endpoints.length === 0) {
    return <div className="empty">No endpoint recorded. Run `logbook inventory scan`.</div>;
  }
  return (
    <div className="cards">
      {data.endpoints.map((e) => {
        const agents = data.agents.filter((a) => a.endpoint_id === e.id).length;
        const servers = data.mcp_servers.filter((m) => m.endpoint_id === e.id).length;
        return (
          <div className="card" key={e.id}>
            <h3>{e.hostname}</h3>
            <dl className="kv">
              <dt>OS</dt>
              <dd>{e.os ?? "—"}</dd>
              <dt>Arch</dt>
              <dd>{e.arch ?? "—"}</dd>
              <dt>Agents</dt>
              <dd>{agents}</dd>
              <dt>MCP servers</dt>
              <dd>{servers}</dd>
              <dt>First seen</dt>
              <dd>{formatTime(e.first_seen)}</dd>
              <dt>Last seen</dt>
              <dd>{formatTime(e.last_seen)}</dd>
            </dl>
          </div>
        );
      })}
    </div>
  );
}

function AgentsTab({ data }: { data: InventoryData }) {
  if (data.agents.length === 0) {
    return <div className="empty">No agent CLIs discovered.</div>;
  }
  return (
    <table className="grid">
      <thead>
        <tr>
          <th>Agent</th>
          <th>Version</th>
          <th>Path</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {data.agents.map((a) => (
          <tr key={a.id} className={a.sanctioned ? "" : "row-shadow"}>
            <td>{a.name}</td>
            <td>{a.version ?? "—"}</td>
            <td className="mono ellipsis">{a.path ?? "—"}</td>
            <td>
              <SanctionBadge sanctioned={a.sanctioned} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function McpTab({ data }: { data: InventoryData }) {
  if (data.mcp_servers.length === 0) {
    return <div className="empty">No MCP servers configured.</div>;
  }
  return (
    <table className="grid">
      <thead>
        <tr>
          <th>Name</th>
          <th>Transport</th>
          <th>Command</th>
          <th>Source</th>
          <th>Flags</th>
        </tr>
      </thead>
      <tbody>
        {data.mcp_servers.map((m) => (
          <tr key={m.id} className={m.sanctioned ? "" : "row-shadow"}>
            <td>{m.name}</td>
            <td>{m.transport ?? "—"}</td>
            <td className="mono ellipsis">{m.command ?? "—"}</td>
            <td className="mono ellipsis">{m.source_config ?? "—"}</td>
            <td className="flags">
              <SanctionBadge sanctioned={m.sanctioned} />
              {m.has_secret && <span className="badge sev sev-medium">secret</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SessionsTab({ data }: { data: InventoryData }) {
  if (data.sessions.length === 0) {
    return <div className="empty">No `logbook agent` sessions recorded.</div>;
  }
  return (
    <table className="grid">
      <thead>
        <tr>
          <th>Agent</th>
          <th>Command</th>
          <th>Started</th>
          <th>Ended</th>
          <th>Exit</th>
        </tr>
      </thead>
      <tbody>
        {data.sessions.map((s) => (
          <tr key={s.id} className={s.exit_code && s.exit_code !== 0 ? "is-error" : ""}>
            <td>{s.agent}</td>
            <td className="mono ellipsis">{s.command}</td>
            <td>{formatTime(s.started_at)}</td>
            <td>{s.ended_at ? formatTime(s.ended_at) : "running"}</td>
            <td>{s.exit_code ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RiskTab({ data }: { data: InventoryData }) {
  const sorted = useMemo(() => {
    const rank = (sev?: string) => {
      const i = SEVERITY_ORDER.indexOf((sev ?? "info") as never);
      return i < 0 ? SEVERITY_ORDER.length : i;
    };
    return [...data.findings].sort((a, b) => rank(a.severity) - rank(b.severity));
  }, [data.findings]);

  if (sorted.length === 0) {
    return <div className="empty">No risk or shadow findings. Nothing unsanctioned detected.</div>;
  }
  return (
    <div className="finding-list">
      {sorted.map((f) => (
        <div key={f.id} className="finding">
          <div className="finding-head">
            <SeverityBadge severity={f.severity} />
            <span className="finding-kind">{f.kind}</span>
            {f.subject && <span className="finding-subject mono">{f.subject}</span>}
          </div>
          {f.message && <p className="finding-msg">{f.message}</p>}
          <span className="finding-time">{formatTime(f.created_at)}</span>
        </div>
      ))}
    </div>
  );
}
