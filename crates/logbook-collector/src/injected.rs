//! `InjectedJsAdapter` — the injected-JS browser console collector (plan §4).
//!
//! The adapter does not run a browser itself; it **produces the insertion
//! material** that a developer (or a dev-server middleware) drops into the page
//! under test. That material is a small JS shim that hooks `console.*`,
//! `window.onerror`/`unhandledrejection`, `fetch`, `XMLHttpRequest`, and a
//! `PerformanceObserver`, then **batches** the captured events to
//! `POST /ingest` with an `Authorization: Bearer <token>` header.
//!
//! ## Token is injected at RUNTIME (review #v3.2)
//! The browser must **never** read `collector.token`. There are two supported
//! insertion paths, both of which inject the token from the server side at
//! request time:
//! 1. **Vite/Next dev-server middleware** ([`InjectedJsAdapter::vite_middleware`]):
//!    a Node module the dev server imports; it reads the token from the
//!    collector process environment / a handle it was given and serves the shim
//!    with the token already baked into a non-persisted response.
//! 2. **Printed snippet** ([`InjectedJsAdapter::printed_snippet`]): `logbook`
//!    prints a ready-to-paste `<script>` containing the token for the developer
//!    to drop into their page during a session.
//!
//! In both cases the token travels server→page at runtime, never via a file the
//! browser can read.

use crate::browser::{BrowserCapture, CaptureKind};

/// Produces injected-JS insertion material (shim, snippet, dev middleware).
#[derive(Clone, Debug)]
pub struct InjectedJsAdapter {
    /// The collector base URL the shim should post to (e.g.
    /// `http://127.0.0.1:7070`).
    collector_url: String,
    /// Logical source label attached to every event (drives per-source log
    /// grouping).
    source: String,
    /// Batch flush interval in milliseconds.
    flush_ms: u32,
    /// Max events buffered before an early flush.
    max_batch: u32,
}

impl InjectedJsAdapter {
    /// New adapter posting to `collector_url`, tagging events with `source`.
    #[must_use]
    pub fn new(collector_url: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            collector_url: collector_url.into(),
            source: source.into(),
            flush_ms: 1000,
            max_batch: 50,
        }
    }

    /// Override the batch flush interval (ms).
    #[must_use]
    pub fn with_flush_ms(mut self, ms: u32) -> Self {
        self.flush_ms = ms;
        self
    }

    /// Override the max buffered events before an early flush.
    #[must_use]
    pub fn with_max_batch(mut self, n: u32) -> Self {
        self.max_batch = n;
        self
    }

    /// The collector base URL.
    #[must_use]
    pub fn collector_url(&self) -> &str {
        &self.collector_url
    }

    /// The core JS shim, parameterized by a `__LOGBOOK_TOKEN__` global that the
    /// insertion layer sets at runtime. This body alone contains **no token** —
    /// it reads `window.__LOGBOOK_TOKEN__`, which the middleware/snippet
    /// defines just before loading the shim.
    ///
    /// Returned as a string so the CLI can print it or a middleware can serve
    /// it; it is intentionally framework-agnostic and CSP-friendly enough to be
    /// inlined.
    #[must_use]
    pub fn shim_js(&self) -> String {
        // Note: kept dependency-free and ES5-ish so it runs anywhere. The token
        // is read from a global the host page sets at runtime.
        format!(
            r#"(function () {{
  var ENDPOINT = {endpoint};
  var SOURCE = {source};
  var FLUSH_MS = {flush_ms};
  var MAX_BATCH = {max_batch};
  var token = (typeof window !== "undefined" && window.__LOGBOOK_TOKEN__) || null;
  if (!token) {{
    // No runtime token injected — do nothing rather than post unauthenticated.
    return;
  }}
  var queue = [];
  var timer = null;

  function nowIso() {{ try {{ return new Date().toISOString(); }} catch (e) {{ return null; }} }}

  function enqueue(ev) {{
    ev.source = SOURCE;
    ev.ts = ev.ts || nowIso();
    queue.push(ev);
    if (queue.length >= MAX_BATCH) {{ flush(); }}
    else if (!timer) {{ timer = setTimeout(flush, FLUSH_MS); }}
  }}

  function flush() {{
    if (timer) {{ clearTimeout(timer); timer = null; }}
    if (!queue.length) {{ return; }}
    var batch = queue.splice(0, queue.length);
    try {{
      fetch(ENDPOINT + "/ingest", {{
        method: "POST",
        headers: {{
          "content-type": "application/json",
          "authorization": "Bearer " + token
        }},
        body: JSON.stringify({{ events: batch }}),
        keepalive: true
      }}).catch(function () {{}});
    }} catch (e) {{}}
  }}

  // ---- console.* ----
  ["log", "info", "warn", "error", "debug"].forEach(function (level) {{
    var orig = console[level] ? console[level].bind(console) : null;
    console[level] = function () {{
      try {{
        var args = Array.prototype.slice.call(arguments);
        enqueue({{ kind: "console", level: level, args: args, url: location.href }});
      }} catch (e) {{}}
      if (orig) {{ orig.apply(null, arguments); }}
    }};
  }});

  // ---- window.onerror / unhandledrejection ----
  if (typeof window !== "undefined") {{
    window.addEventListener("error", function (e) {{
      enqueue({{
        kind: "error", level: "error",
        message: e && e.message ? String(e.message) : "error",
        stack: e && e.error && e.error.stack ? String(e.error.stack) : undefined,
        url: location.href
      }});
    }});
    window.addEventListener("unhandledrejection", function (e) {{
      var reason = e && e.reason;
      enqueue({{
        kind: "error", level: "error",
        message: "unhandledrejection: " + (reason && reason.message ? reason.message : String(reason)),
        stack: reason && reason.stack ? String(reason.stack) : undefined,
        url: location.href
      }});
    }});
  }}

  // ---- fetch ----
  if (typeof window !== "undefined" && window.fetch) {{
    var origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {{
      var url = (typeof input === "string") ? input : (input && input.url) || "";
      var method = (init && init.method) || (input && input.method) || "GET";
      // Never capture our own ingest posts (avoid feedback loops).
      if (url && url.indexOf(ENDPOINT) === 0) {{ return origFetch(input, init); }}
      var started = Date.now();
      return origFetch(input, init).then(function (res) {{
        enqueue({{
          kind: "network", level: res.ok ? "info" : "error",
          message: method + " " + url + " -> " + res.status,
          meta: {{ method: method, url: url, status: res.status, ms: Date.now() - started }},
          url: location.href
        }});
        return res;
      }}).catch(function (err) {{
        enqueue({{
          kind: "network", level: "error",
          message: method + " " + url + " failed",
          meta: {{ method: method, url: url, error: String(err) }},
          url: location.href
        }});
        throw err;
      }});
    }};
  }}

  // ---- XMLHttpRequest ----
  if (typeof XMLHttpRequest !== "undefined") {{
    var OrigXhrOpen = XMLHttpRequest.prototype.open;
    var OrigXhrSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {{
      this.__ar_method = method; this.__ar_url = url;
      return OrigXhrOpen.apply(this, arguments);
    }};
    XMLHttpRequest.prototype.send = function () {{
      var self = this; var started = Date.now();
      var url = self.__ar_url || "";
      if (url && url.indexOf(ENDPOINT) === 0) {{ return OrigXhrSend.apply(self, arguments); }}
      self.addEventListener("loadend", function () {{
        enqueue({{
          kind: "network", level: (self.status >= 400 || self.status === 0) ? "error" : "info",
          message: (self.__ar_method || "GET") + " " + url + " -> " + self.status,
          meta: {{ method: self.__ar_method, url: url, status: self.status, ms: Date.now() - started }},
          url: location.href
        }});
      }});
      return OrigXhrSend.apply(self, arguments);
    }};
  }}

  // ---- PerformanceObserver ----
  if (typeof PerformanceObserver !== "undefined") {{
    try {{
      var po = new PerformanceObserver(function (list) {{
        list.getEntries().forEach(function (entry) {{
          enqueue({{
            kind: "performance", level: "info",
            message: "perf " + entry.entryType + " " + (entry.name || "") + " " + Math.round(entry.duration) + "ms",
            meta: {{ entryType: entry.entryType, name: entry.name, duration: entry.duration, startTime: entry.startTime }},
            url: location.href
          }});
        }});
      }});
      po.observe({{ entryTypes: ["navigation", "resource", "longtask", "paint"] }});
    }} catch (e) {{}}
  }}

  // Flush any buffered events when the page is hidden / unloaded.
  if (typeof window !== "undefined") {{
    window.addEventListener("visibilitychange", function () {{
      if (document.visibilityState === "hidden") {{ flush(); }}
    }});
    window.addEventListener("pagehide", flush);
  }}
}})();
"#,
            endpoint = js_string(&self.collector_url),
            source = js_string(&self.source),
            flush_ms = self.flush_ms,
            max_batch = self.max_batch,
        )
    }

    /// A ready-to-paste `<script>` block carrying the **actual token** for the
    /// current run, printed by `logbook` for the developer to drop into the
    /// page. The token is set on `window.__LOGBOOK_TOKEN__` immediately before
    /// the shim runs.
    ///
    /// This is the only path where the token appears in adapter output, and it
    /// is produced server-side at runtime — the browser still never reads
    /// `collector.token`.
    #[must_use]
    pub fn printed_snippet(&self, token: &str) -> String {
        format!(
            "<script>\nwindow.__LOGBOOK_TOKEN__ = {token};\n</script>\n<script>\n{shim}</script>\n",
            token = js_string(token),
            shim = self.shim_js(),
        )
    }

    /// A Vite dev-server middleware module (ESM) that injects the shim with the
    /// token at request time. The token is passed in by the collector launcher
    /// (e.g. via `process.env.LOGBOOK_INGEST_TOKEN`) — **not** read from
    /// `collector.token` by the browser.
    ///
    /// Usage in `vite.config.ts`:
    /// ```js
    /// import logbook from "./logbook-vite-middleware.mjs";
    /// export default { plugins: [logbook()] };
    /// ```
    #[must_use]
    pub fn vite_middleware(&self) -> String {
        format!(
            r#"// logbook Vite dev-middleware — injects the browser-capture shim with the
// per-run ingest token at request time. The token is read from the server-side
// environment (LOGBOOK_INGEST_TOKEN); the browser never reads the token file.
//
// Generated by logbook-collector InjectedJsAdapter.
const SHIM = {shim_literal};

export default function logbookPlugin(opts = {{}}) {{
  const token = opts.token || process.env.LOGBOOK_INGEST_TOKEN || "";
  return {{
    name: "logbook-capture",
    apply: "serve",
    transformIndexHtml(html) {{
      if (!token) return html; // no token -> inject nothing (fail closed)
      const inject =
        '<script>window.__LOGBOOK_TOKEN__=' + JSON.stringify(token) + ';</script>\n' +
        '<script>' + SHIM + '</script>';
      // Insert just before </head> (or prepend if no head).
      if (html.includes("</head>")) {{
        return html.replace("</head>", inject + "\n</head>");
      }}
      return inject + "\n" + html;
    }},
  }};
}}
"#,
            shim_literal = js_string(&self.shim_js()),
        )
    }
}

impl BrowserCapture for InjectedJsAdapter {
    fn name(&self) -> &str {
        "injected-js"
    }

    fn capture_kind(&self) -> CaptureKind {
        CaptureKind::Injected
    }
}

/// JSON-encode a Rust string into a JS string literal (handles quotes, control
/// chars, `</script>` breakouts). We route through `serde_json` for correctness
/// and additionally escape `/` in `</` so an embedded `</script>` can't close
/// the host page's script tag.
fn js_string(s: &str) -> String {
    let mut out = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    if out.contains("</") {
        out = out.replace("</", "<\\/");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> InjectedJsAdapter {
        InjectedJsAdapter::new("http://127.0.0.1:7070", "browser")
    }

    #[test]
    fn shim_has_no_token_baked_in() {
        let shim = adapter().shim_js();
        // The bare shim must read the token from a runtime global, not embed it.
        assert!(shim.contains("window.__LOGBOOK_TOKEN__"));
        assert!(shim.contains("/ingest"));
        assert!(shim.contains("Bearer "));
        // Hooks present.
        for needle in ["console[level]", "window.fetch", "XMLHttpRequest", "PerformanceObserver", "unhandledrejection"] {
            assert!(shim.contains(needle), "shim missing hook: {needle}");
        }
    }

    #[test]
    fn printed_snippet_injects_token_at_runtime() {
        let snip = adapter().printed_snippet("deadbeefcafef00d");
        assert!(snip.contains("window.__LOGBOOK_TOKEN__ = \"deadbeefcafef00d\""));
        assert!(snip.contains("/ingest"));
    }

    #[test]
    fn snippet_escapes_script_breakout() {
        // A token containing a script close should be neutralized.
        let snip = adapter().printed_snippet("</script><script>evil()</script>");
        assert!(!snip.contains("</script><script>evil"), "breakout not escaped: {snip}");
        assert!(snip.contains("<\\/script>"));
    }

    #[test]
    fn vite_middleware_reads_env_token_not_file() {
        let mw = adapter().vite_middleware();
        assert!(mw.contains("process.env.LOGBOOK_INGEST_TOKEN"));
        assert!(mw.contains("transformIndexHtml"));
        // Must not reference the token file at all.
        assert!(!mw.contains("collector.token"));
        assert!(mw.contains("window.__LOGBOOK_TOKEN__"));
    }

    #[test]
    fn capture_kind_is_injected() {
        assert_eq!(adapter().capture_kind(), CaptureKind::Injected);
        assert_eq!(adapter().name(), "injected-js");
    }
}
