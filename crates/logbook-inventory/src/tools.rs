//! Detection of external tools logbook can reuse: schrute and security-suite
//! (plan §7b discovery sources), plus security-suite scanner availability.
//!
//! Local, read-only, best-effort. We look for the tools in their canonical
//! locations and on `PATH`, and (for security-suite) report which of the v1
//! scanners (Semgrep / Trivy / cargo-audit) resolve.

use std::path::Path;

use crate::agents::is_executable_file;
use crate::config::Scanners;
use crate::model::ToolPresence;

/// Options for tool detection (paths are injectable for tests).
#[derive(Clone, Debug, Default)]
pub struct ToolScanOptions {
    /// Candidate directories that may contain a schrute checkout (each is
    /// checked for a `package.json` naming `schrute` or a `.mcp.json`).
    pub schrute_dirs: Vec<std::path::PathBuf>,
    /// Candidate security-suite root directories.
    pub security_suite_dirs: Vec<std::path::PathBuf>,
    /// `PATH` to consult for scanner binaries.
    pub path_var: String,
    /// Scanner command names/paths from config.
    pub scanners: Scanners,
}

impl ToolScanOptions {
    /// Build with the conventional real locations under `$HOME`.
    #[must_use]
    pub fn with_home(home: &Path) -> Self {
        Self {
            schrute_dirs: vec![
                home.join("browser agent").join("oneagent"),
                home.join("schrute"),
                home.join("oneagent"),
            ],
            security_suite_dirs: vec![home.join("security-suite")],
            path_var: std::env::var("PATH").unwrap_or_default(),
            scanners: Scanners::default(),
        }
    }
}

/// Detect schrute, security-suite, and the v1 scanners. Returns one
/// [`ToolPresence`] per tool, always (present or not), so the report can show a
/// complete checklist.
#[must_use]
pub fn scan_tools(opts: &ToolScanOptions) -> Vec<ToolPresence> {
    vec![
        detect_schrute(&opts.schrute_dirs),
        detect_security_suite(&opts.security_suite_dirs),
        // Scanner availability (part of "security-suite scanner availability").
        detect_on_path("semgrep", &opts.scanners.semgrep, &opts.path_var),
        detect_on_path("trivy", &opts.scanners.trivy, &opts.path_var),
        detect_on_path("cargo-audit", &opts.scanners.cargo_audit, &opts.path_var),
    ]
}

/// schrute is present if any candidate dir contains a `package.json` whose name
/// is `schrute`, or (looser) a `.mcp.json` declaring a `schrute` server.
fn detect_schrute(dirs: &[std::path::PathBuf]) -> ToolPresence {
    for dir in dirs {
        let pkg = dir.join("package.json");
        if let Ok(text) = std::fs::read_to_string(&pkg) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if v.get("name").and_then(|n| n.as_str()) == Some("schrute") {
                    return present("schrute", dir.display().to_string());
                }
            }
        }
        let mcp = dir.join(".mcp.json");
        if let Ok(text) = std::fs::read_to_string(&mcp) {
            if text.contains("\"schrute\"") {
                return present("schrute", mcp.display().to_string());
            }
        }
    }
    absent("schrute")
}

/// security-suite is present if a candidate root exists and contains at least
/// one of the expected scanner subdirectories.
fn detect_security_suite(dirs: &[std::path::PathBuf]) -> ToolPresence {
    for dir in dirs {
        if dir.is_dir() {
            let has_marker = ["semgrep", "trivy", "cargo-audit", "strix"]
                .iter()
                .any(|m| dir.join(m).exists());
            if has_marker {
                return present("security-suite", dir.display().to_string());
            }
            // Directory exists but no recognizable marker — still report it as
            // present at that path (best-effort), but note it.
            return present("security-suite", dir.display().to_string());
        }
    }
    absent("security-suite")
}

/// Resolve a scanner binary either as an absolute path or by walking `PATH`.
fn detect_on_path(label: &str, command: &str, path_var: &str) -> ToolPresence {
    // Absolute / relative path with separators: check directly.
    if command.contains('/') {
        let p = Path::new(command);
        if is_executable_file(p) {
            return present(label, p.display().to_string());
        }
        return absent(label);
    }
    // Cross-platform PATH split (`:` on Unix, `;` on Windows) via the std lib.
    for dir in std::env::split_paths(path_var).filter(|p| !p.as_os_str().is_empty()) {
        let candidate = dir.join(command);
        if is_executable_file(&candidate) {
            return present(label, candidate.display().to_string());
        }
    }
    absent(label)
}

fn present(name: &str, detail: String) -> ToolPresence {
    ToolPresence {
        name: name.to_string(),
        present: true,
        detail: Some(detail),
    }
}

fn absent(name: &str) -> ToolPresence {
    ToolPresence {
        name: name.to_string(),
        present: false,
        detail: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_schrute_by_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{ "name": "schrute", "version": "1.0.0" }"#,
        )
        .unwrap();
        let p = detect_schrute(&[tmp.path().to_path_buf()]);
        assert!(p.present);
        assert!(p
            .detail
            .unwrap()
            .contains(tmp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn detects_schrute_by_mcp_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".mcp.json"),
            r#"{ "mcpServers": { "schrute": { "command": "node" } } }"#,
        )
        .unwrap();
        let p = detect_schrute(&[tmp.path().to_path_buf()]);
        assert!(p.present);
    }

    #[test]
    fn absent_schrute_when_no_markers() {
        let tmp = tempfile::tempdir().unwrap();
        let p = detect_schrute(&[tmp.path().to_path_buf()]);
        assert!(!p.present);
    }

    #[test]
    fn detects_security_suite_with_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("semgrep")).unwrap();
        let p = detect_security_suite(&[tmp.path().to_path_buf()]);
        assert!(p.present);
    }

    #[test]
    fn detects_scanner_on_synthetic_path() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("semgrep");
        let mut f = std::fs::File::create(&bin).unwrap();
        writeln!(f, "#!/bin/sh\ntrue").unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            let p = detect_on_path("semgrep", "semgrep", &tmp.path().to_string_lossy());
            assert!(p.present, "should find semgrep on synthetic PATH");
        }
    }

    #[test]
    fn scanner_absent_when_not_on_path() {
        let p = detect_on_path(
            "semgrep",
            "definitely-not-a-real-binary-xyz",
            "/nonexistent",
        );
        assert!(!p.present);
    }
}
