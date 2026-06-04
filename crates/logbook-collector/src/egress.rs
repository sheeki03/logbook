//! logbook's **own** egress allowlist (plan §4, §13).
//!
//! schrute's security gates (SSRF blocking, domain allowlist, redirect
//! behavior) are marked `PENDING VERIFICATION` in its parity doc
//! (`agent-browser-parity.md:3`). Per the plan we **do not assume them**;
//! [`crate::schrute_mcp::SchruteAdapter`] runs every navigation/replay target
//! through this allowlist first. Until a target both parses as a URL and matches
//! the configured allowlist (and is not a private/loopback/link-local host), the
//! request is refused locally — schrute is never asked to fetch it.
//!
//! The allowlist is **deny-by-default**: an empty allowlist blocks all external
//! navigation (matching `logbook.toml [permissions] allowed_domains = []`).

/// Reasons a target can be rejected by the egress policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressDenied {
    /// The string did not parse as an absolute `http(s)` URL.
    NotAUrl(String),
    /// The scheme was not `http`/`https`.
    BadScheme(String),
    /// The URL had no host component.
    NoHost(String),
    /// The host is a private, loopback, or link-local address (SSRF guard).
    PrivateHost(String),
    /// The host did not match any allowlist entry.
    NotAllowlisted(String),
}

impl std::fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressDenied::NotAUrl(s) => write!(f, "not an absolute URL: {s}"),
            EgressDenied::BadScheme(s) => write!(f, "scheme not allowed (need http/https): {s}"),
            EgressDenied::NoHost(s) => write!(f, "URL has no host: {s}"),
            EgressDenied::PrivateHost(h) => write!(f, "private/loopback host blocked: {h}"),
            EgressDenied::NotAllowlisted(h) => write!(f, "host not in egress allowlist: {h}"),
        }
    }
}

impl std::error::Error for EgressDenied {}

/// A deny-by-default egress allowlist of domain suffixes.
#[derive(Clone, Debug, Default)]
pub struct EgressAllowlist {
    /// Lowercased domain entries; a host matches if it equals an entry or is a
    /// subdomain of one (`example.com` matches `app.example.com`).
    domains: Vec<String>,
    /// When true, loopback/private hosts are permitted (dev-only escape hatch,
    /// off by default).
    allow_private: bool,
}

impl EgressAllowlist {
    /// An empty allowlist that blocks everything.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Build from an iterator of allowed domains.
    #[must_use]
    pub fn from_domains<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let domains = domains
            .into_iter()
            .map(|d| d.as_ref().trim().trim_start_matches("*.").to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        Self {
            domains,
            allow_private: false,
        }
    }

    /// Permit loopback/private hosts (dev-only). Off by default.
    #[must_use]
    pub fn allowing_private(mut self) -> Self {
        self.allow_private = true;
        self
    }

    /// Whether the allowlist is empty (blocks everything external).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Check a target URL. Returns the normalized host on success.
    ///
    /// # Errors
    /// Returns an [`EgressDenied`] describing why the target is refused.
    pub fn check(&self, target: &str) -> Result<String, EgressDenied> {
        let (scheme, rest) = split_scheme(target)
            .ok_or_else(|| EgressDenied::NotAUrl(target.to_string()))?;
        if scheme != "http" && scheme != "https" {
            return Err(EgressDenied::BadScheme(target.to_string()));
        }
        let host = extract_host(rest).ok_or_else(|| EgressDenied::NoHost(target.to_string()))?;
        let host = host.to_ascii_lowercase();
        if host.is_empty() {
            return Err(EgressDenied::NoHost(target.to_string()));
        }

        if !self.allow_private && is_private_host(&host) {
            return Err(EgressDenied::PrivateHost(host));
        }

        if self.host_allowed(&host) {
            Ok(host)
        } else {
            Err(EgressDenied::NotAllowlisted(host))
        }
    }

    /// Whether `host` matches any allowlist entry (exact or subdomain).
    fn host_allowed(&self, host: &str) -> bool {
        self.domains.iter().any(|d| {
            host == d || host.ends_with(&format!(".{d}"))
        })
    }
}

/// Split `scheme://rest` into `(scheme, rest)`, lowercasing the scheme. Returns
/// `None` if there is no `://`.
fn split_scheme(url: &str) -> Option<(String, &str)> {
    let idx = url.find("://")?;
    let scheme = url[..idx].to_ascii_lowercase();
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return None;
    }
    Some((scheme, &url[idx + 3..]))
}

/// Extract the host from the authority portion of a URL (everything up to the
/// first `/`, `?`, or `#`), stripping userinfo and the port. Bracketed IPv6
/// literals are returned without brackets.
fn extract_host(rest: &str) -> Option<&str> {
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // Strip userinfo.
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if authority.is_empty() {
        return None;
    }
    // IPv6 literal: [::1]:port
    if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')?;
        return Some(&stripped[..end]);
    }
    // Strip :port for host:port.
    let host = match authority.find(':') {
        Some(i) => &authority[..i],
        None => authority,
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Whether a host string is a private, loopback, or link-local address, or a
/// non-routable name like `localhost`. Conservative SSRF guard.
fn is_private_host(host: &str) -> bool {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host == "localhost.localdomain"
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip_is_private(ip);
    }
    false
}

/// Whether an IP address is loopback, private, link-local, unspecified, or
/// otherwise non-public.
fn ip_is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // Carrier-grade NAT 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: re-check the embedded v4.
                || v6.to_ipv4_mapped().map(|m| ip_is_private(std::net::IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_blocks_everything() {
        let a = EgressAllowlist::deny_all();
        assert!(a.is_empty());
        assert!(matches!(
            a.check("https://example.com/"),
            Err(EgressDenied::NotAllowlisted(_))
        ));
    }

    #[test]
    fn allows_exact_and_subdomain() {
        let a = EgressAllowlist::from_domains(["example.com"]);
        assert_eq!(a.check("https://example.com/x").unwrap(), "example.com");
        assert_eq!(a.check("https://app.example.com/").unwrap(), "app.example.com");
        // A different registrable domain is rejected.
        assert!(matches!(
            a.check("https://evil.com/"),
            Err(EgressDenied::NotAllowlisted(_))
        ));
        // Suffix-confusion guard: notexample.com must NOT match example.com.
        assert!(matches!(
            a.check("https://notexample.com/"),
            Err(EgressDenied::NotAllowlisted(_))
        ));
    }

    #[test]
    fn blocks_private_and_loopback_even_if_allowlisted() {
        let a = EgressAllowlist::from_domains(["localhost", "example.com"]);
        assert!(matches!(a.check("http://localhost:3000/"), Err(EgressDenied::PrivateHost(_))));
        assert!(matches!(a.check("http://127.0.0.1/"), Err(EgressDenied::PrivateHost(_))));
        assert!(matches!(a.check("http://10.0.0.5/"), Err(EgressDenied::PrivateHost(_))));
        assert!(matches!(a.check("http://192.168.1.1/"), Err(EgressDenied::PrivateHost(_))));
        assert!(matches!(a.check("http://169.254.1.1/"), Err(EgressDenied::PrivateHost(_))));
        assert!(matches!(a.check("http://[::1]/"), Err(EgressDenied::PrivateHost(_))));
        // CGNAT.
        assert!(matches!(a.check("http://100.64.0.1/"), Err(EgressDenied::PrivateHost(_))));
    }

    #[test]
    fn private_allowed_only_with_escape_hatch() {
        let a = EgressAllowlist::from_domains(["localhost"]).allowing_private();
        assert_eq!(a.check("http://localhost:3000/").unwrap(), "localhost");
    }

    #[test]
    fn rejects_non_http_schemes_and_garbage() {
        let a = EgressAllowlist::from_domains(["example.com"]);
        assert!(matches!(a.check("ftp://example.com/"), Err(EgressDenied::BadScheme(_))));
        assert!(matches!(a.check("file:///etc/passwd"), Err(EgressDenied::BadScheme(_))));
        assert!(matches!(a.check("javascript:alert(1)"), Err(EgressDenied::NotAUrl(_))));
        assert!(matches!(a.check("not a url"), Err(EgressDenied::NotAUrl(_))));
    }

    #[test]
    fn strips_userinfo_and_port_for_host_match() {
        let a = EgressAllowlist::from_domains(["example.com"]);
        assert_eq!(a.check("https://user:pw@app.example.com:8443/p").unwrap(), "app.example.com");
    }

    #[test]
    fn ipv4_mapped_ipv6_loopback_blocked() {
        let a = EgressAllowlist::from_domains(["example.com"]).allowing_private();
        // Even with the escape hatch off for public, ensure mapping logic works.
        let b = EgressAllowlist::from_domains(["example.com"]);
        assert!(matches!(b.check("http://[::ffff:127.0.0.1]/"), Err(EgressDenied::PrivateHost(_))));
        let _ = a;
    }
}
