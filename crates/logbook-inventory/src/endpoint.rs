//! Local endpoint identity (plan §7b: "the local machine(s) this store has
//! seen — v1: just this one").
//!
//! Strictly local and read-only: hostname + OS + arch, with a stable id derived
//! from the hostname so repeated scans upsert the same `endpoints` row.

use crate::model::Endpoint;

/// Discover the local endpoint. Never fails: unknown fields fall back to
/// `"unknown"`.
#[must_use]
pub fn local_endpoint() -> Endpoint {
    let hostname = hostname();
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let id = endpoint_id(&hostname);
    Endpoint {
        id,
        hostname,
        os,
        arch,
    }
}

/// Best-effort hostname. Reads `HOSTNAME`, then `HOST`, then the `hostname`
/// command, then falls back to `"localhost"`. (We avoid pulling a libc/`uname`
/// dependency for what is a display-only field in a local tool.)
fn hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = std::env::var("HOST") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(out) = std::process::Command::new("hostname").output() {
        if out.status.success() {
            let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !h.is_empty() {
                return h;
            }
        }
    }
    "localhost".to_string()
}

/// A stable, non-secret id for an endpoint: `endpoint-<hostname-slug>`.
fn endpoint_id(hostname: &str) -> String {
    let slug: String = hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "endpoint-local".to_string()
    } else {
        format!("endpoint-{slug}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_endpoint_is_populated() {
        let ep = local_endpoint();
        assert!(!ep.id.is_empty());
        assert!(ep.id.starts_with("endpoint-"));
        assert!(!ep.hostname.is_empty());
        assert!(!ep.os.is_empty());
        assert!(!ep.arch.is_empty());
    }

    #[test]
    fn endpoint_id_is_stable_and_slugged() {
        assert_eq!(endpoint_id("My.Laptop.local"), "endpoint-my-laptop-local");
        assert_eq!(endpoint_id(""), "endpoint-local");
        // Stable across calls.
        assert_eq!(endpoint_id("box"), endpoint_id("box"));
    }
}
