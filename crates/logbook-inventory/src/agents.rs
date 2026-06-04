//! Discovery of coding-agent CLIs installed on `PATH` (plan §7b).
//!
//! Local, read-only, best-effort: we walk the directories on `PATH` looking for
//! executables whose file name matches a known agent CLI. We never execute a
//! discovered binary as part of a plain `PATH` walk; an optional version probe
//! (`--version`) is opt-in via [`probe_version`] and used by the scan only when
//! enabled (it is a benign, widely-supported, read-only invocation).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::model::AgentInstall;

/// The set of agent CLIs we look for, by canonical name. Mirrors plan §7b
/// (`claude`, `cursor`, `codex`, `gemini`, `aider`, `opencode`, …).
pub const KNOWN_AGENTS: &[&str] = &[
    "claude", "cursor", "codex", "gemini", "aider", "opencode", "cody", "continue", "goose", "amp",
    "windsurf", "cline", "qodo", "tabby",
];

/// The default sanctioned allowlist (agents considered approved on this
/// endpoint). Anything discovered that is *not* here is flagged as a shadow /
/// unsanctioned agent. Kept conservative on purpose; the operator can widen it.
pub const DEFAULT_SANCTIONED_AGENTS: &[&str] = &["claude", "codex", "cursor", "gemini"];

/// Options controlling agent discovery.
#[derive(Clone, Debug)]
pub struct AgentScanOptions {
    /// The `PATH` string to scan (colon-separated). Defaults to the process
    /// `PATH`; overridable for tests.
    pub path_var: String,
    /// The names considered sanctioned/approved.
    pub sanctioned: Vec<String>,
    /// Whether to probe `<bin> --version` for a version string. Off by default
    /// (a pure discovery scan does not execute discovered binaries).
    pub probe_versions: bool,
}

impl Default for AgentScanOptions {
    fn default() -> Self {
        Self {
            path_var: std::env::var("PATH").unwrap_or_default(),
            sanctioned: DEFAULT_SANCTIONED_AGENTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            probe_versions: false,
        }
    }
}

impl AgentScanOptions {
    /// Construct with an explicit `PATH` (useful for tests that plant a fake
    /// agent in a temp dir).
    #[must_use]
    pub fn with_path(path_var: impl Into<String>) -> Self {
        Self {
            path_var: path_var.into(),
            ..Default::default()
        }
    }

    /// Whether `name` is sanctioned under these options.
    #[must_use]
    pub fn is_sanctioned(&self, name: &str) -> bool {
        self.sanctioned.iter().any(|s| s == name)
    }
}

/// Scan `PATH` for known agent CLIs, returning one [`AgentInstall`] per agent
/// name (the first match on `PATH` wins, mirroring shell resolution order).
#[must_use]
pub fn scan_agents(endpoint_id: &str, opts: &AgentScanOptions) -> Vec<AgentInstall> {
    // Preserve PATH order but dedupe by agent name (first hit wins).
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();

    // Cross-platform PATH split (`:` on Unix, `;` on Windows) via the std lib.
    for dir in std::env::split_paths(&opts.path_var).filter(|p| !p.as_os_str().is_empty()) {
        for name in KNOWN_AGENTS {
            if found.contains_key(*name) {
                continue;
            }
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                found.insert((*name).to_string(), candidate);
                order.push((*name).to_string());
            }
        }
    }

    order
        .into_iter()
        .map(|name| {
            let path = found.remove(&name).expect("name was inserted");
            let version = if opts.probe_versions {
                probe_version(&path)
            } else {
                None
            };
            let sanctioned = opts.is_sanctioned(&name);
            AgentInstall {
                id: install_id(endpoint_id, &name, &path),
                name,
                version,
                path: path.to_string_lossy().to_string(),
                sanctioned,
            }
        })
        .collect()
}

/// Whether `path` is a regular file with an executable bit set (Unix) or simply
/// exists as a file (non-Unix fallback).
#[must_use]
pub fn is_executable_file(path: &Path) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Probe `<bin> --version`, returning a trimmed single-line version string if
/// the binary exits successfully and prints something. Best-effort: any failure
/// (spawn error, non-zero exit, empty output) yields `None`. A short timeout is
/// *not* enforced here; callers that worry about hangs should keep
/// `probe_versions = false` (the default).
#[must_use]
pub fn probe_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next().unwrap_or_default().trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

/// A stable id for an install: `agent-<endpoint>-<name>` (path is intentionally
/// excluded so a re-scan after an upgrade upserts the same row).
fn install_id(endpoint_id: &str, name: &str, _path: &Path) -> String {
    format!("agent-{endpoint_id}-{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_fake_bin(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh\necho fake {name}").unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    #[test]
    fn detects_planted_agent_on_path() {
        let tmp = tempfile::tempdir().unwrap();
        write_fake_bin(tmp.path(), "claude");
        // A non-agent executable should be ignored.
        write_fake_bin(tmp.path(), "totally-not-an-agent");

        let opts = AgentScanOptions::with_path(tmp.path().to_string_lossy());
        let installs = scan_agents("endpoint-test", &opts);
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].name, "claude");
        assert!(installs[0].sanctioned, "claude is in the default allowlist");
        assert!(installs[0].path.ends_with("claude"));
    }

    #[test]
    fn flags_unsanctioned_agent() {
        let tmp = tempfile::tempdir().unwrap();
        write_fake_bin(tmp.path(), "aider"); // not in the default allowlist
        let opts = AgentScanOptions::with_path(tmp.path().to_string_lossy());
        let installs = scan_agents("endpoint-test", &opts);
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].name, "aider");
        assert!(
            !installs[0].sanctioned,
            "aider is not sanctioned by default"
        );
    }

    #[test]
    fn non_executable_file_is_not_detected() {
        let tmp = tempfile::tempdir().unwrap();
        // A file named like an agent but with no executable bit.
        let p = tmp.path().join("codex");
        std::fs::write(&p, "not executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            let opts = AgentScanOptions::with_path(tmp.path().to_string_lossy());
            assert!(scan_agents("e", &opts).is_empty());
        }
    }

    #[test]
    fn first_hit_on_path_wins() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write_fake_bin(a.path(), "codex");
        write_fake_bin(b.path(), "codex");
        let path = format!("{}:{}", a.path().display(), b.path().display());
        let opts = AgentScanOptions::with_path(path);
        let installs = scan_agents("e", &opts);
        assert_eq!(installs.len(), 1);
        assert!(
            installs[0]
                .path
                .starts_with(a.path().to_string_lossy().as_ref()),
            "earlier PATH entry should win: {}",
            installs[0].path
        );
    }

    #[test]
    fn install_id_is_stable_across_path_changes() {
        let id1 = install_id("e", "claude", Path::new("/usr/bin/claude"));
        let id2 = install_id("e", "claude", Path::new("/opt/claude"));
        assert_eq!(id1, id2, "id must not depend on path so upgrades upsert");
    }
}
