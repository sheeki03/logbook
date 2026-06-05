import { useEffect, useState } from "react";

import { api } from "../api";
import type { CaptureClass, CapturePolicyView } from "../types";

// The capture on/off panel (Orbit plan §1.4). A master toggle + per-class
// switches that POST to /api/capture-policy. `secrets` is the locked redaction
// floor — rendered disabled, never togglable. Writes go to the cross-process
// runtime overlay (<out_dir>/capture-state.json) by default; the durable
// logbook.toml target is only offered when the server was launched with
// --allow-config-write.

const CLASS_LABELS: { id: CaptureClass; label: string }[] = [
  { id: "transcript", label: "Transcript" },
  { id: "commands", label: "Commands" },
  { id: "file_diffs", label: "File diffs" },
  { id: "tool_args", label: "Tool args" },
  { id: "tool_results", label: "Tool results" },
  { id: "prompts", label: "Prompts" },
  { id: "model_metadata", label: "Model metadata" },
  { id: "browser_data", label: "Browser data" },
];

export function CapturePanel() {
  const [view, setView] = useState<CapturePolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [target, setTarget] = useState<"runtime" | "config">("runtime");

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .getCapturePolicy(ctrl.signal)
      .then((v) => {
        setView(v);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) setError(String(e));
      });
    return () => ctrl.abort();
  }, []);

  // Apply an update, then reconcile with the server's freshly-resolved view so
  // the rendered state is always the effective (resolved) policy.
  async function apply(update: {
    enabled?: boolean;
    classes?: Partial<Record<CaptureClass, boolean>>;
  }) {
    if (!view || busy) return;
    setBusy(true);
    try {
      const next = await api.setCapturePolicy(view, { ...update, target });
      setView(next);
      setError(null);
    } catch (e: unknown) {
      setError(String(e));
      // Re-read so a conflict/version error leaves the UI showing live state.
      try {
        setView(await api.getCapturePolicy());
      } catch {
        // keep the error already surfaced
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="capture-panel">
      <div className="capture-head">
        <span className="section-title">Capture</span>
        {view && (
          <span className={`capture-state ${view.enabled ? "on" : "off"}`}>
            {view.enabled ? "recording" : "paused"}
          </span>
        )}
        {view?.allow_config_write && (
          <label className="capture-target" title="where the toggle is persisted">
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value as "runtime" | "config")}
              disabled={busy}
            >
              <option value="runtime">runtime (capture-state.json)</option>
              <option value="config">durable (logbook.toml)</option>
            </select>
          </label>
        )}
        <label className={`master-toggle ${busy ? "busy" : ""}`}>
          <input
            type="checkbox"
            checked={view?.enabled ?? false}
            disabled={!view || busy}
            onChange={(e) => apply({ enabled: e.target.checked })}
          />
          Capture on
        </label>
      </div>

      {error && <div className="error-bar">{error}</div>}

      {view && (
        <div className="capture-classes">
          {CLASS_LABELS.map((c) => (
            <label
              key={c.id}
              className={`class-toggle ${view.enabled ? "" : "dim"}`}
            >
              <input
                type="checkbox"
                checked={view.classes[c.id]}
                disabled={!view.enabled || busy}
                onChange={(e) => apply({ classes: { [c.id]: e.target.checked } })}
              />
              {c.label}
            </label>
          ))}
          {/* secrets — the locked redaction floor; never togglable. */}
          <label className="class-toggle locked" title="the redaction floor is always on">
            <input type="checkbox" checked readOnly disabled />
            Secrets
            <span className="lock-pill">locked</span>
          </label>
        </div>
      )}
    </div>
  );
}
