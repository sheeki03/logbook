//! Internal helpers for reading risk-relevant material out of an [`Event`]
//! without coupling to any one producer's exact field layout.
//!
//! An `Event`'s human/command text can live in several places depending on who
//! produced it — `name`, `error`, string `attributes` (e.g. `command`, `cmd`,
//! `diff`, `argv`), the `input`/`output` JSON payloads, and the typed blocks
//! (`console.message`, `tool.arguments`, …). Rather than guess one location,
//! these helpers gather the relevant text into a single searchable haystack and
//! expose the structured fields (LLM cost/tokens, network host) the rules need.
//!
//! All extraction is read-only and allocation-light where it can be; the
//! haystack builders return owned `String`s because they concatenate several
//! borrowed sources.

use logbook_core::Event;

/// Append a string value from a JSON `Value` (recursing into objects/arrays) to
/// `buf`. Only string leaves contribute text; keys are ignored (a redaction
/// marker or command lives in a *value*, per `redact_json`).
fn collect_json_strings(value: &serde_json::Value, buf: &mut String) {
    match value {
        serde_json::Value::String(s) => {
            buf.push_str(s);
            buf.push('\n');
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, buf);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_json_strings(v, buf);
            }
        }
        _ => {}
    }
}

/// Build a single searchable text haystack for an event, concatenating every
/// place free-form / command / diff text can appear:
/// `name`, `operation`, `type`, `error`, all string `attributes` values, the
/// `input`/`output` JSON string leaves, and the text-bearing block fields
/// (`console.message`/`stack`, `tool.tool_name` + `tool.arguments`,
/// `network.url`).
///
/// Newline-separated so multi-line patterns (e.g. a fork-bomb on its own line)
/// are matchable but distinct sources don't accidentally fuse into a false
/// match across a boundary.
#[must_use]
pub(crate) fn haystack(ev: &Event) -> String {
    let mut buf = String::new();
    buf.push_str(&ev.name);
    buf.push('\n');
    buf.push_str(&ev.operation);
    buf.push('\n');
    buf.push_str(&ev.type_);
    buf.push('\n');
    if let Some(err) = &ev.error {
        buf.push_str(err);
        buf.push('\n');
    }
    for v in ev.attributes.values() {
        collect_json_strings(v, &mut buf);
    }
    if let Some(input) = &ev.input {
        collect_json_strings(input, &mut buf);
    }
    if let Some(output) = &ev.output {
        collect_json_strings(output, &mut buf);
    }
    if let Some(console) = &ev.blocks.console {
        if let Some(m) = &console.message {
            buf.push_str(m);
            buf.push('\n');
        }
        if let Some(s) = &console.stack {
            buf.push_str(s);
            buf.push('\n');
        }
        if let Some(u) = &console.url {
            buf.push_str(u);
            buf.push('\n');
        }
    }
    if let Some(tool) = &ev.blocks.tool {
        if let Some(n) = &tool.tool_name {
            buf.push_str(n);
            buf.push('\n');
        }
        if let Some(args) = &tool.arguments {
            collect_json_strings(args, &mut buf);
        }
        if let Some(rs) = &tool.result_summary {
            buf.push_str(rs);
            buf.push('\n');
        }
    }
    if let Some(net) = &ev.blocks.network {
        if let Some(u) = &net.url {
            buf.push_str(u);
            buf.push('\n');
        }
    }
    buf
}

/// The best-effort affected file path for a finding locator: the event's
/// `file`/`path` string attribute if present.
#[must_use]
pub(crate) fn file_hint(ev: &Event) -> Option<String> {
    for key in ["file", "path", "filename"] {
        if let Some(serde_json::Value::String(s)) = ev.attributes.get(key) {
            if !s.is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

/// Extract the host component of a URL string without a URL-parsing dependency.
///
/// Handles `scheme://[user[:pass]@]host[:port][/path…]` and bare
/// `host[:port][/path]`. Returns the lowercased host (no port, no auth, no
/// brackets for IPv6) or `None` if nothing host-like is present.
#[must_use]
pub(crate) fn url_host(url: &str) -> Option<String> {
    let s = url.trim();
    if s.is_empty() {
        return None;
    }
    // Strip scheme.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    // Authority ends at the first '/', '?', or '#'.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Drop userinfo.
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if hostport.is_empty() {
        return None;
    }
    // IPv6 literal in brackets: keep what's inside the brackets.
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.find(']') {
            Some(end) => &stripped[..end],
            None => stripped,
        }
    } else {
        // host[:port] — split off a numeric-looking port.
        match hostport.rfind(':') {
            Some(i) if hostport[i + 1..].chars().all(|c| c.is_ascii_digit())
                && !hostport[i + 1..].is_empty() =>
            {
                &hostport[..i]
            }
            _ => hostport,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Whether `host` is allowed by `allowed`: an exact (case-insensitive) match or
/// a subdomain of an allowed domain (`api.example.com` is allowed by
/// `example.com`). An empty `allowed` list allows **nothing**.
#[must_use]
pub(crate) fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    allowed.iter().any(|d| {
        let d = d.trim().trim_start_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return false;
        }
        host == d || host.ends_with(&format!(".{d}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use logbook_core::{Category, ConsoleBlock, Event, Kind, NetworkBlock, TraceId};

    #[test]
    fn haystack_gathers_name_attrs_and_blocks() {
        let ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "stdout")
            .with_name("the-name")
            .with_attr("command", "rm -rf /")
            .with_attr("nested", serde_json::json!({"k": "deep-value"}))
            .with_console(ConsoleBlock {
                message: Some("console-msg".into()),
                ..Default::default()
            });
        let h = haystack(&ev);
        assert!(h.contains("the-name"));
        assert!(h.contains("rm -rf /"));
        assert!(h.contains("deep-value"));
        assert!(h.contains("console-msg"));
    }

    #[test]
    fn haystack_reads_input_output_json() {
        let mut ev = Event::new(TraceId::new(), Kind::Log, Category::AppLog, "x");
        ev.input = Some(serde_json::json!({"diff": "+ AKIA«REDACTED:CLOUD_KEY:20»"}));
        ev.output = Some(serde_json::json!(["line-one", "git push --force"]));
        let h = haystack(&ev);
        assert!(h.contains("REDACTED:CLOUD_KEY"));
        assert!(h.contains("git push --force"));
    }

    #[test]
    fn url_host_parses_variants() {
        assert_eq!(url_host("https://evil.example.com/x?y=1").as_deref(), Some("evil.example.com"));
        assert_eq!(url_host("http://user:pass@host.test:8080/p").as_deref(), Some("host.test"));
        assert_eq!(url_host("bare.host.com").as_deref(), Some("bare.host.com"));
        assert_eq!(url_host("http://[2001:db8::1]:443/").as_deref(), Some("2001:db8::1"));
        assert_eq!(url_host("localhost:3000").as_deref(), Some("localhost"));
        assert_eq!(url_host("   ").as_deref(), None);
    }

    #[test]
    fn host_allowed_matches_exact_and_subdomain() {
        let allow = vec!["example.com".to_string(), "anthropic.com".to_string()];
        assert!(host_allowed("example.com", &allow));
        assert!(host_allowed("api.example.com", &allow));
        assert!(host_allowed("API.Example.Com", &allow));
        assert!(!host_allowed("evil.com", &allow));
        assert!(!host_allowed("notexample.com", &allow));
        // Empty allowlist allows nothing.
        assert!(!host_allowed("example.com", &[]));
    }

    #[test]
    fn network_block_url_is_in_haystack() {
        let ev = Event::new(TraceId::new(), Kind::Network, Category::Browser, "fetch")
            .with_network(NetworkBlock {
                url: Some("https://exfil.bad/data".into()),
                ..Default::default()
            });
        assert!(haystack(&ev).contains("exfil.bad"));
    }
}
