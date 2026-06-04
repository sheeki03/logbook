// Small presentation helpers shared by the views.

import type { AgentEvent, Category, Severity } from "./types";

// Microsecond UNIX timestamp -> local HH:MM:SS.mmm
export function formatTime(micros: number): string {
  const ms = Math.floor(micros / 1000);
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const millis = String(ms % 1000).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${millis}`;
}

export function formatDuration(ms?: number): string {
  if (ms == null) return "";
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

const CATEGORY_LABEL: Record<Category, string> = {
  agent: "Agent",
  browser: "Browser",
  app_log: "App Log",
  code_test: "Code/Test",
  security: "Security",
  inventory: "Inventory",
};

export function categoryLabel(c: Category): string {
  return CATEGORY_LABEL[c] ?? c;
}

export const ALL_CATEGORIES: Category[] = [
  "agent",
  "browser",
  "app_log",
  "code_test",
  "security",
  "inventory",
];

// Compact one-line summary of an event for the timeline row.
export function eventSummary(ev: AgentEvent): string {
  if (ev.error) return ev.error;
  if (ev.console?.message) return ev.console.message;
  if (ev.network?.url) {
    const code = ev.network.status_code ? ` ${ev.network.status_code}` : "";
    return `${ev.network.method ?? "GET"} ${ev.network.url}${code}`;
  }
  if (ev.finding?.message) return ev.finding.message;
  if (ev.llm?.model) return `${ev.llm.provider ?? ""} ${ev.llm.model}`.trim();
  if (ev.tool?.tool_name) return ev.tool.tool_name;
  return ev.name;
}

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];
