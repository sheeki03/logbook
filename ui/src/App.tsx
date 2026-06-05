import { useState } from "react";

import { Timeline } from "./views/Timeline";
import { Inventory } from "./views/Inventory";
import { Sessions } from "./views/Sessions";
import { Risk } from "./views/Risk";

type View = "timeline" | "sessions" | "risk" | "inventory";

const NAV: { id: View; label: string }[] = [
  { id: "timeline", label: "Timeline" },
  { id: "sessions", label: "Sessions" },
  { id: "risk", label: "Risk" },
  { id: "inventory", label: "Inventory" },
];

export default function App() {
  const [view, setView] = useState<View>("timeline");

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="logo">logbook</span>
          <span className="tagline">local observability for agent-built software</span>
        </div>
        <nav className="main-nav">
          {NAV.map((n) => (
            <button
              key={n.id}
              className={view === n.id ? "active" : ""}
              onClick={() => setView(n.id)}
              type="button"
            >
              {n.label}
            </button>
          ))}
        </nav>
      </header>
      <main className="app-main">
        {view === "timeline" && <Timeline />}
        {view === "sessions" && <Sessions />}
        {view === "risk" && <Risk />}
        {view === "inventory" && <Inventory />}
      </main>
    </div>
  );
}
