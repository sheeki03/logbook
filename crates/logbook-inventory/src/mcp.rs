//! Discovery of configured MCP servers from known locations + local project
//! files (plan §7b).
//!
//! Sources (local, read-only, best-effort):
//! - **Cursor**: `~/.cursor/mcp.json` and project `.cursor/mcp.json`
//! - **Claude**: `~/.claude.json`, the Claude Desktop config, project Claude config
//! - **Codex**: `~/.codex/config.toml` and project `.codex/config.toml`
//! - **VS Code / Cline**: user `settings.json` (`mcp.servers` / `cline.mcpServers`)
//! - **Zed**: `~/.config/zed/settings.json` (`context_servers`)
//! - Local: `.mcp.json`, `.cursor/mcp.json`, `.codex/config.toml`
//!
//! All formats reduce to: a map of server name -> launch spec. We extract the
//! command/URL and transport, **detect whether the entry carries a secret**
//! (inline `env`/`headers`/`*_token*` values), and **redact every string** via
//! [`logbook_core::Redactor`] before any value is surfaced or persisted (plan
//! §9 — keys in `.mcp.json` / `config.toml` are redacted).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use logbook_core::Redactor;

use crate::model::{McpServer, McpTransport};

/// The default sanctioned MCP server names. Anything else discovered is flagged
/// as a shadow / untracked MCP server. Intentionally small; operators widen it.
pub const DEFAULT_SANCTIONED_MCP: &[&str] = &["schrute", "logbook", "playwright"];

/// A discovered MCP config source: a file plus the dialect to parse it with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpConfigSource {
    /// Absolute path to the config file.
    pub path: PathBuf,
    /// How to parse it.
    pub dialect: ConfigDialect,
}

/// The on-disk config dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigDialect {
    /// JSON object containing an `mcpServers` (or similar) map.
    Json,
    /// TOML with `[mcp_servers.<name>]` tables (Codex).
    Toml,
}

/// Options for MCP discovery.
#[derive(Clone, Debug)]
pub struct McpScanOptions {
    /// Explicit list of config sources to read. When empty, [`scan_mcp`] uses
    /// [`default_sources`] (the real known locations under `$HOME` + the given
    /// project dir).
    pub sources: Vec<McpConfigSource>,
    /// Sanctioned server names.
    pub sanctioned: Vec<String>,
}

impl Default for McpScanOptions {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            sanctioned: DEFAULT_SANCTIONED_MCP
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl McpScanOptions {
    /// Whether `name` is sanctioned under these options.
    #[must_use]
    pub fn is_sanctioned(&self, name: &str) -> bool {
        self.sanctioned.iter().any(|s| s == name)
    }
}

/// Build the default set of config sources for the given home dir and project
/// dir. Non-existent files are filtered out by [`scan_mcp`]; this only lists
/// *candidate* locations so it is deterministic and testable.
#[must_use]
pub fn default_sources(home: &Path, project: &Path) -> Vec<McpConfigSource> {
    let json = |p: PathBuf| McpConfigSource {
        path: p,
        dialect: ConfigDialect::Json,
    };
    let toml = |p: PathBuf| McpConfigSource {
        path: p,
        dialect: ConfigDialect::Toml,
    };
    vec![
        // Cursor
        json(home.join(".cursor").join("mcp.json")),
        json(project.join(".cursor").join("mcp.json")),
        // Claude
        json(home.join(".claude.json")),
        json(
            home.join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
        ),
        json(
            home.join(".config")
                .join("claude")
                .join("claude_desktop_config.json"),
        ),
        json(project.join(".claude.json")),
        // Codex
        toml(home.join(".codex").join("config.toml")),
        toml(project.join(".codex").join("config.toml")),
        // VS Code (user settings) — macOS + Linux
        json(
            home.join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("settings.json"),
        ),
        json(
            home.join(".config")
                .join("Code")
                .join("User")
                .join("settings.json"),
        ),
        // Zed
        json(home.join(".config").join("zed").join("settings.json")),
        // Generic project-local
        json(project.join(".mcp.json")),
    ]
}

/// Scan the configured (or default) sources for MCP servers. Every returned
/// [`McpServer`] has already had its strings redacted.
///
/// `home` and `project` are only used when `opts.sources` is empty.
#[must_use]
pub fn scan_mcp(
    endpoint_id: &str,
    home: &Path,
    project: &Path,
    opts: &McpScanOptions,
    redactor: &Redactor,
) -> Vec<McpServer> {
    let sources = if opts.sources.is_empty() {
        default_sources(home, project)
    } else {
        opts.sources.clone()
    };

    let mut out: Vec<McpServer> = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    for source in &sources {
        let text = match std::fs::read_to_string(&source.path) {
            Ok(t) => t,
            // A genuinely absent config is the common, legitimate skip.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // Present-but-unreadable (permissions, I/O): a shadow MCP server in
            // this file would be invisible, so surface it rather than skip
            // silently. (This is a discovery/security signal — see module docs.)
            Err(e) => {
                tracing::warn!(
                    path = %source.path.display(),
                    error = %e,
                    "could not read MCP config; any servers it declares are not inventoried"
                );
                continue;
            }
        };
        let source_label = source.path.to_string_lossy().to_string();
        let servers = match source.dialect {
            ConfigDialect::Json => parse_json_servers(&text),
            ConfigDialect::Toml => parse_toml_servers(&text),
        };
        let servers = match servers {
            Ok(s) => s,
            // Present-but-malformed config: a corrupt file conflated with "not
            // an MCP config" would hide a shadow server. Warn, naming the file.
            Err(e) => {
                tracing::warn!(
                    path = %source.path.display(),
                    error = %e,
                    "malformed MCP config; any servers it declares are not inventoried"
                );
                continue;
            }
        };
        for raw in servers {
            // Dedupe identical (source, name) pairs.
            if !seen.insert((source_label.clone(), raw.name.clone())) {
                continue;
            }
            out.push(finalize_server(
                endpoint_id,
                &source_label,
                raw,
                opts,
                redactor,
            ));
        }
    }
    out
}

/// A raw, pre-redaction server spec extracted from a config file.
#[derive(Clone, Debug, Default)]
struct RawServer {
    name: String,
    command: Option<String>,
    url: Option<String>,
    transport: McpTransport,
    /// Whether a secret was detected anywhere in this entry.
    has_secret: bool,
}

/// Turn a [`RawServer`] into a redacted [`McpServer`].
fn finalize_server(
    endpoint_id: &str,
    source_label: &str,
    raw: RawServer,
    opts: &McpScanOptions,
    redactor: &Redactor,
) -> McpServer {
    // Redact the command/url defensively — a `user:pass@` URL or a command that
    // embeds a token must not be persisted in the clear.
    let command = raw
        .command
        .or(raw.url)
        .map(|c| redactor.redact(&c).into_owned());
    McpServer {
        id: server_id(endpoint_id, source_label, &raw.name),
        name: raw.name.clone(),
        source_config: source_label.to_string(),
        command,
        transport: raw.transport,
        sanctioned: opts.is_sanctioned(&raw.name),
        has_secret: raw.has_secret,
    }
}

fn server_id(endpoint_id: &str, source_label: &str, name: &str) -> String {
    // Stable across re-scans for the same (endpoint, file, server).
    let src_slug: String = source_label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("mcp-{endpoint_id}-{src_slug}-{name}")
}

/// Parse the `mcpServers` (Cursor/Claude) — or the VS Code / Cline / Zed
/// equivalents — out of a JSON settings file.
///
/// A valid-but-unknown shape (e.g. a `settings.json` with no MCP keys) yields
/// `Ok(vec![])`; only *malformed* JSON returns `Err`, so [`scan_mcp`] can warn
/// about a corrupt config that might hide a shadow server rather than silently
/// treating it as empty.
fn parse_json_servers(text: &str) -> std::result::Result<Vec<RawServer>, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| e.to_string())?;
    // Known container keys across products.
    const KEYS: &[&str] = &[
        "mcpServers",
        "context_servers", // Zed
        "mcp",             // VS Code: { "mcp": { "servers": {...} } }
    ];
    let mut maps: Vec<&serde_json::Map<String, serde_json::Value>> = Vec::new();
    if let Some(obj) = value.as_object() {
        for key in KEYS {
            if let Some(inner) = obj.get(*key) {
                // VS Code nests under `mcp.servers`.
                if *key == "mcp" {
                    if let Some(servers) = inner.get("servers").and_then(|s| s.as_object()) {
                        maps.push(servers);
                    }
                } else if let Some(m) = inner.as_object() {
                    maps.push(m);
                }
            }
        }
        // Cline stores under `cline.mcpServers` inside settings; also accept a
        // bare top-level object that *looks* like a server map is avoided to
        // prevent false positives.
        if let Some(cline) = obj.get("cline.mcpServers").and_then(|v| v.as_object()) {
            maps.push(cline);
        }
    }

    let mut out = Vec::new();
    for map in maps {
        for (name, spec) in map {
            out.push(parse_json_server_spec(name, spec));
        }
    }
    Ok(out)
}

/// Extract one server from a JSON spec object.
fn parse_json_server_spec(name: &str, spec: &serde_json::Value) -> RawServer {
    let obj = spec.as_object();
    let command = obj
        .and_then(|o| o.get("command"))
        .and_then(|c| c.as_str())
        .map(str::to_string);
    let url = obj
        .and_then(|o| o.get("url"))
        .and_then(|u| u.as_str())
        .map(str::to_string);
    let transport = infer_transport(
        command.as_deref(),
        url.as_deref(),
        obj.and_then(|o| o.get("type")).and_then(|t| t.as_str()),
    );
    let has_secret = obj.map(json_spec_has_secret).unwrap_or(false);
    RawServer {
        name: name.to_string(),
        command,
        url,
        transport,
        has_secret,
    }
}

/// Heuristically decide whether a JSON server spec carries a secret: an `env`
/// map with a secret-looking key, a `headers` map with an `Authorization` /
/// secret-looking value, or any top-level `*token*` / `*key*` field with a
/// non-placeholder string value.
fn json_spec_has_secret(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    // env: { SOME_SECRET: "..." }
    if let Some(env) = obj.get("env").and_then(|e| e.as_object()) {
        for (k, v) in env {
            if logbook_core::redact::name_looks_secret(k) && value_is_real_secret(v) {
                return true;
            }
        }
    }
    // headers: { Authorization: "Bearer ..." }
    if let Some(headers) = obj.get("headers").and_then(|h| h.as_object()) {
        for (k, v) in headers {
            let kl = k.to_ascii_lowercase();
            if (kl.contains("authorization")
                || kl.contains("token")
                || kl.contains("api-key")
                || kl.contains("cookie"))
                && value_is_real_secret(v)
            {
                return true;
            }
        }
    }
    // Top-level *token*/*key* fields (e.g. bearer_token, apiKey).
    for (k, v) in obj {
        if logbook_core::redact::name_looks_secret(k) && value_is_real_secret(v) {
            return true;
        }
    }
    false
}

/// Whether a JSON value looks like a *real* inline secret (a non-empty string
/// that is not an obvious `${env:...}` / `$VAR` indirection placeholder).
fn value_is_real_secret(v: &serde_json::Value) -> bool {
    match v.as_str() {
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                return false;
            }
            // Pure indirection placeholders are not themselves secrets.
            let is_placeholder = (t.starts_with("${") && t.ends_with('}'))
                || (t.starts_with('$') && !t.contains(' '))
                || t.eq_ignore_ascii_case("changeme");
            if is_placeholder {
                return false;
            }
            // A bare "Bearer ${env:X}" header still references indirection.
            if t.to_ascii_lowercase().starts_with("bearer ${") {
                return false;
            }
            true
        }
        None => false,
    }
}

/// Parse `[mcp_servers.<name>]` tables out of a Codex-style TOML config.
///
/// A valid TOML file with no `mcp_servers` table yields `Ok(vec![])`; only
/// *malformed* TOML returns `Err`, so [`scan_mcp`] can warn about a corrupt
/// config that might hide a shadow server rather than silently treating it as
/// empty.
fn parse_toml_servers(text: &str) -> std::result::Result<Vec<RawServer>, String> {
    let value: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let table = match value.get("mcp_servers").and_then(|t| t.as_table()) {
        Some(t) => t,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (name, spec) in table {
        out.push(parse_toml_server_spec(name, spec));
    }
    Ok(out)
}

/// Extract one server from a TOML spec table.
fn parse_toml_server_spec(name: &str, spec: &toml::Value) -> RawServer {
    let tbl = spec.as_table();
    let command = tbl
        .and_then(|t| t.get("command"))
        .and_then(|c| c.as_str())
        .map(str::to_string);
    let url = tbl
        .and_then(|t| t.get("url"))
        .and_then(|u| u.as_str())
        .map(str::to_string);
    let transport = infer_transport(command.as_deref(), url.as_deref(), None);
    let has_secret = tbl.map(toml_spec_has_secret).unwrap_or(false);
    RawServer {
        name: name.to_string(),
        command,
        url,
        transport,
        has_secret,
    }
}

/// Whether a Codex TOML server table carries a secret. Codex uses
/// `bearer_token_env_var` (indirection — *not* a secret) but may also carry an
/// inline `[mcp_servers.<name>.env]` table with secret-looking keys.
fn toml_spec_has_secret(tbl: &toml::Table) -> bool {
    if let Some(env) = tbl.get("env").and_then(|e| e.as_table()) {
        for (k, v) in env {
            if logbook_core::redact::name_looks_secret(k) && toml_value_is_real_secret(v) {
                return true;
            }
        }
    }
    // Any inline secret-looking scalar (but `bearer_token_env_var` is an env
    // *name*, i.e. indirection, so exclude it explicitly).
    for (k, v) in tbl {
        if k == "bearer_token_env_var" {
            continue;
        }
        if logbook_core::redact::name_looks_secret(k) && toml_value_is_real_secret(v) {
            return true;
        }
    }
    false
}

fn toml_value_is_real_secret(v: &toml::Value) -> bool {
    match v.as_str() {
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                return false;
            }
            let env_brace = t.starts_with("${") && t.ends_with('}');
            let env_var = t.starts_with('$') && !t.contains(' ');
            !env_brace && !env_var
        }
        None => false,
    }
}

/// Infer the transport from command/url presence and an optional explicit type.
fn infer_transport(
    command: Option<&str>,
    url: Option<&str>,
    explicit: Option<&str>,
) -> McpTransport {
    if let Some(t) = explicit {
        match t.to_ascii_lowercase().as_str() {
            "stdio" => return McpTransport::Stdio,
            "sse" => return McpTransport::Sse,
            "http" | "streamable-http" | "streamablehttp" => return McpTransport::Http,
            "ws" | "websocket" => return McpTransport::Ws,
            _ => {}
        }
    }
    if command.is_some() {
        return McpTransport::Stdio;
    }
    if let Some(u) = url {
        let ul = u.to_ascii_lowercase();
        if ul.starts_with("ws://") || ul.starts_with("wss://") {
            return McpTransport::Ws;
        }
        if ul.contains("/sse") {
            return McpTransport::Sse;
        }
        return McpTransport::Http;
    }
    McpTransport::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red() -> Redactor {
        Redactor::new()
    }

    #[test]
    fn parses_cursor_style_json() {
        let json = r#"{
          "mcpServers": {
            "uidotsh": { "url": "https://ui.sh/mcp?agent=cursor",
              "headers": { "Authorization": "Bearer ${env:UIDOTSH_TOKEN}" } }
          }
        }"#;
        let servers = parse_json_servers(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "uidotsh");
        assert_eq!(servers[0].transport, McpTransport::Http);
        // Authorization references ${env:...} → indirection, not an inline secret.
        assert!(!servers[0].has_secret, "env-indirection is not a secret");
    }

    #[test]
    fn detects_inline_secret_in_json_env() {
        let json = r#"{
          "mcpServers": {
            "leaky": { "command": "node", "args": ["server.js"],
              "env": { "API_KEY": "sk-ant-REALSECRET0123456789" } }
          }
        }"#;
        let servers = parse_json_servers(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].has_secret, "inline env secret must be detected");
        assert_eq!(servers[0].transport, McpTransport::Stdio);
    }

    #[test]
    fn detects_inline_secret_in_authorization_header() {
        let json = r#"{
          "mcpServers": {
            "remote": { "url": "https://api.example.com/mcp",
              "headers": { "Authorization": "Bearer abcdef0123456789ghij" } }
          }
        }"#;
        let servers = parse_json_servers(json).unwrap();
        assert!(servers[0].has_secret, "literal bearer token is a secret");
    }

    #[test]
    fn parses_codex_toml() {
        let toml = r#"
[mcp_servers.linear]
url = "https://mcp.linear.app/mcp"

[mcp_servers.playwright]
command = "npx"
args = ["@playwright/mcp@latest"]

[mcp_servers.uidotsh]
bearer_token_env_var = "UIDOTSH_TOKEN"
url = "https://ui.sh/mcp?agent=codex"
"#;
        let mut servers = parse_toml_servers(toml).unwrap();
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(servers.len(), 3);
        let by = |n: &str| servers.iter().find(|s| s.name == n).unwrap();
        assert_eq!(by("playwright").transport, McpTransport::Stdio);
        assert_eq!(by("linear").transport, McpTransport::Http);
        // bearer_token_env_var is indirection, NOT an inline secret.
        assert!(!by("uidotsh").has_secret);
    }

    #[test]
    fn detects_inline_secret_in_codex_env_table() {
        let toml = r#"
[mcp_servers.leaky]
command = "/bin/server"

[mcp_servers.leaky.env]
SERVICE_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
"#;
        let servers = parse_toml_servers(toml).unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].has_secret);
    }

    #[test]
    fn malformed_config_is_distinguished_from_no_servers() {
        // Malformed JSON/TOML must Err (so scan_mcp can warn) rather than be
        // silently conflated with a valid config that simply has no MCP servers.
        assert!(parse_json_servers("{ not valid json").is_err());
        assert!(parse_toml_servers("this is = = not toml").is_err());
        // A syntactically valid config with no MCP keys is Ok(empty), not Err.
        assert_eq!(parse_json_servers(r#"{ "other": 1 }"#).unwrap().len(), 0);
        assert_eq!(parse_toml_servers("[other]\nk = 1\n").unwrap().len(), 0);
    }

    #[test]
    fn scan_mcp_skips_malformed_config_without_panicking() {
        // A present-but-corrupt .mcp.json must not crash the scan or surface a
        // bogus server; it is skipped (with a warn, not asserted here) and the
        // scan returns the servers from the remaining valid sources.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(project.join(".mcp.json"), "{ this is not valid json").unwrap();
        let servers = scan_mcp("e", &home, &project, &McpScanOptions::default(), &red());
        assert!(
            servers.is_empty(),
            "a corrupt config yields no servers (and does not panic): {servers:?}"
        );
    }

    #[test]
    fn finalize_redacts_command_and_flags_shadow() {
        let raw = RawServer {
            name: "leaky".into(),
            command: Some("server --token sk-ant-REALSECRET0123456789".into()),
            url: None,
            transport: McpTransport::Stdio,
            has_secret: true,
        };
        let opts = McpScanOptions::default();
        let s = finalize_server("e", "/tmp/.mcp.json", raw, &opts, &red());
        assert!(s.has_secret);
        assert!(!s.sanctioned, "leaky is not in the default allowlist");
        let cmd = s.command.unwrap();
        assert!(
            !cmd.contains("sk-ant-REALSECRET0123456789"),
            "command leaked secret: {cmd}"
        );
        assert!(
            cmd.contains("REDACTED"),
            "command should be redacted: {cmd}"
        );
    }

    #[test]
    fn sanctioned_server_not_flagged() {
        let raw = RawServer {
            name: "schrute".into(),
            command: Some("node dist/index.js".into()),
            url: None,
            transport: McpTransport::Stdio,
            has_secret: false,
        };
        let opts = McpScanOptions::default();
        let s = finalize_server("e", "/tmp/.mcp.json", raw, &opts, &red());
        assert!(s.sanctioned, "schrute is in the default allowlist");
    }

    #[test]
    fn scan_mcp_reads_local_mcp_json_and_redacts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        // Plant a project-local .mcp.json with an inline secret.
        std::fs::write(
            project.join(".mcp.json"),
            r#"{ "mcpServers": { "evil": { "command": "x",
                 "env": { "PASSWORD": "AKIAIOSFODNN7EXAMPLE" } } } }"#,
        )
        .unwrap();
        let servers = scan_mcp("e", &home, &project, &McpScanOptions::default(), &red());
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "evil");
        assert!(servers[0].has_secret);
        assert!(!servers[0].sanctioned);
        // The whole struct, once serialized, must not leak the secret.
        let json = serde_json::to_string(&servers[0]).unwrap();
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"), "leaked: {json}");
    }

    #[test]
    fn default_sources_lists_known_locations() {
        let home = Path::new("/home/u");
        let project = Path::new("/proj");
        let sources = default_sources(home, project);
        let paths: Vec<String> = sources
            .iter()
            .map(|s| s.path.to_string_lossy().to_string())
            .collect();
        assert!(paths.iter().any(|p| p.ends_with(".cursor/mcp.json")));
        assert!(paths.iter().any(|p| p.ends_with(".codex/config.toml")));
        assert!(paths.iter().any(|p| p.ends_with("/proj/.mcp.json")));
        // Codex is parsed as TOML; ensure the dialect is right.
        let codex = sources
            .iter()
            .find(|s| s.path.to_string_lossy().ends_with(".codex/config.toml"))
            .unwrap();
        assert_eq!(codex.dialect, ConfigDialect::Toml);
    }
}
