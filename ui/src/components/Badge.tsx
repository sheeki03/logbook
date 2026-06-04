import type { Category, Severity, Status } from "../types";
import { categoryLabel } from "../format";

export function CategoryBadge({ category }: { category: Category }) {
  return (
    <span className={`badge cat cat-${category}`}>{categoryLabel(category)}</span>
  );
}

export function StatusBadge({ status }: { status: Status }) {
  if (status === "unset") return null;
  return <span className={`badge status status-${status}`}>{status}</span>;
}

export function SeverityBadge({ severity }: { severity?: Severity }) {
  if (!severity) return null;
  return <span className={`badge sev sev-${severity}`}>{severity}</span>;
}

export function SanctionBadge({ sanctioned }: { sanctioned: boolean }) {
  return (
    <span className={`badge sanction ${sanctioned ? "ok" : "shadow"}`}>
      {sanctioned ? "sanctioned" : "shadow"}
    </span>
  );
}
