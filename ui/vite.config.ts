import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Rust `logbook-ui` crate embeds `dist/` via `rust-embed` and serves it
// from an axum server. During `vite dev` we proxy the JSON + SSE APIs to the
// running UI server (default 127.0.0.1:7878) so the React app talks to a real
// backend without CORS gymnastics.
const API_TARGET = process.env.LOGBOOK_UI_API ?? "http://127.0.0.1:7878";

export default defineConfig({
  plugins: [react()],
  build: {
    // Emit a self-contained build that rust-embed picks up verbatim.
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": {
        target: API_TARGET,
        changeOrigin: true,
        // SSE needs the connection kept open and unbuffered.
        ws: false,
      },
    },
  },
});
