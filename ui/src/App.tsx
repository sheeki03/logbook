import { useState } from "react";

import { Timeline } from "./views/Timeline";
import { Inventory } from "./views/Inventory";

type View = "timeline" | "inventory";

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
          <button
            className={view === "timeline" ? "active" : ""}
            onClick={() => setView("timeline")}
            type="button"
          >
            Timeline
          </button>
          <button
            className={view === "inventory" ? "active" : ""}
            onClick={() => setView("inventory")}
            type="button"
          >
            Inventory
          </button>
        </nav>
      </header>
      <main className="app-main">
        {view === "timeline" ? <Timeline /> : <Inventory />}
      </main>
    </div>
  );
}
