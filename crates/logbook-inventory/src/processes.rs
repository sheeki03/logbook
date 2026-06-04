//! Best-effort listing of running agent-related processes (plan §7b).
//!
//! Local-only and **observe-not-modify**: we shell out to `ps` (the same
//! mechanism the OpenLogs supervisor uses to walk descendants) and match the
//! command line against the known agent names. We never signal or alter any
//! process. Command lines are redacted before they leave this module.

use logbook_core::Redactor;

use crate::agents::KNOWN_AGENTS;
use crate::model::RunningProcess;

/// List running processes whose command line references a known agent CLI.
///
/// On non-Unix or when `ps` is unavailable this returns an empty list (the
/// feature is explicitly best-effort).
#[must_use]
pub fn scan_processes(redactor: &Redactor) -> Vec<RunningProcess> {
    let output = match run_ps() {
        Some(o) => o,
        None => return Vec::new(),
    };
    parse_ps(&output, redactor)
}

/// Run `ps -axo pid=,comm=,args=` and return stdout, or `None` on failure.
fn run_ps() -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-axo", "pid=,comm=,args="])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Parse `ps` output lines of the form `<pid> <comm> <args...>` and keep the
/// ones whose basename (comm) or args reference a known agent. Exposed for unit
/// testing with synthetic `ps` output.
#[must_use]
pub fn parse_ps(ps_output: &str, redactor: &Redactor) -> Vec<RunningProcess> {
    let mut out = Vec::new();
    for line in ps_output.lines() {
        let line = line.trim_start();
        if line.is_empty() {
            continue;
        }
        // pid is the first whitespace-delimited token; comm is the second; the
        // remainder is the full args string.
        let mut it = line
            .splitn(3, char::is_whitespace)
            .filter(|s| !s.is_empty());
        let pid_str = match it.next() {
            Some(p) => p,
            None => continue,
        };
        let comm = it.next().unwrap_or("");
        let args = it.next().unwrap_or("");
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Some(agent) = match_agent(comm, args) {
            // Skip our own scan process and obvious self-references would need a
            // pid compare; for a best-effort lister we keep it simple.
            let command = redactor.redact(args).into_owned();
            out.push(RunningProcess {
                pid,
                agent,
                command,
            });
        }
    }
    out
}

/// Return the known-agent name a process matches, if any. Matches on the binary
/// basename (`comm`) being exactly an agent name, or the agent name appearing
/// as a path segment / whole word in the args.
fn match_agent(comm: &str, args: &str) -> Option<String> {
    let comm_base = comm.rsplit('/').next().unwrap_or(comm);
    for name in KNOWN_AGENTS {
        if comm_base == *name {
            return Some((*name).to_string());
        }
    }
    // Args match: require the agent name as a `/<name>` path segment or a
    // space-delimited token so we don't match substrings like "continuee".
    let first = args.split_whitespace().next().unwrap_or("");
    let first_base = first.rsplit('/').next().unwrap_or(first);
    for name in KNOWN_AGENTS {
        if first_base == *name {
            return Some((*name).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red() -> Redactor {
        Redactor::new()
    }

    #[test]
    fn matches_agent_by_comm() {
        let ps = "  4321 claude /Users/me/.local/bin/claude --resume\n\
                   1000 zsh -zsh\n\
                   5678 node /usr/local/bin/codex serve\n";
        // Note: comm column for codex is "node" so it should match via args.
        let procs = parse_ps(ps, &red());
        let names: Vec<&str> = procs.iter().map(|p| p.agent.as_str()).collect();
        assert!(names.contains(&"claude"), "claude not matched: {names:?}");
        assert!(
            names.contains(&"codex"),
            "codex not matched via args: {names:?}"
        );
        assert!(!names.contains(&"zsh"));
    }

    #[test]
    fn does_not_match_substrings() {
        let ps = "100 continuee /opt/continuee run\n200 mycodexthing /opt/mycodexthing\n";
        let procs = parse_ps(ps, &red());
        assert!(procs.is_empty(), "should not match substrings: {procs:?}");
    }

    #[test]
    fn redacts_command_line() {
        let ps = "9999 claude /bin/claude --token AKIAIOSFODNN7EXAMPLE\n";
        let procs = parse_ps(ps, &red());
        assert_eq!(procs.len(), 1);
        assert!(
            !procs[0].command.contains("AKIAIOSFODNN7EXAMPLE"),
            "leaked: {}",
            procs[0].command
        );
    }

    #[test]
    fn skips_malformed_lines() {
        let ps = "\n   \nnotanumber comm args\n42 claude /bin/claude\n";
        let procs = parse_ps(ps, &red());
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 42);
    }
}
