//! The `logbook.toml` permission model (plan §9.1) and the write-tool catalog.
//!
//! The MCP surface is **read-only by default**. Write tools are advertised
//! (and callable) only when their *category* is listed in
//! `[permissions].enabled_writes` in `logbook.toml`, loaded from the workspace
//! root (`<root>/logbook.toml`). A missing config file means the strictest,
//! read-only posture — never a fail-open.
//!
//! This module is deliberately free of any `rmcp` types: it parses the config,
//! classifies tools, and answers "is this write category enabled?". The server
//! (`server.rs`) consumes [`Permissions`] to decide which write tools to keep
//! visible; everything else (the tool functions) lives in [`crate::tools`].
//!
//! ## Schema lives in `logbook-core`
//! The `logbook.toml` *schema* (the `[permissions]` table, the
//! [`CONFIG_FILENAME`] const, the parse/load semantics, and the
//! [`ConfigError`]) is owned by [`logbook_core::config`] so every crate parses
//! the same document. This module no longer re-declares those structs: it wraps
//! the core [`LogbookConfig`](logbook_core::config::LogbookConfig) /
//! [`Permissions`](logbook_core::config::Permissions) in thin newtypes that
//! attach the MCP-only write-tool catalog logic
//! ([`WriteCategory`], [`Permissions::category_enabled`], …). The newtypes exist
//! purely to host those inherent methods on data the core crate owns.

use std::collections::BTreeSet;
use std::ops::Deref;

use serde::Deserialize;

// Re-export the canonical schema pieces so downstream code can keep using
// `logbook_mcp::{CONFIG_FILENAME, ConfigError}` unchanged.
pub use logbook_core::config::{ConfigError, CONFIG_FILENAME};

/// A category of *write* tools, gated behind `[permissions].enabled_writes`.
///
/// Each variant maps to a set of concrete write tools (see
/// [`WriteCategory::tools`]). A category is advertised iff it appears in
/// `enabled_writes` (and, where applicable, the matching `allow_*` flag is set —
/// see [`Permissions::category_enabled`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WriteCategory {
    /// `browser` — `browser_navigate`/`record`/`replay`/`screenshot`/`start_session`.
    Browser,
    /// `dap` — `debug_set_logpoint` (alpha)/`enable_trace`/`start_session`/`end_session`.
    Dap,
    /// `security` — `security_scan`, `scan_agent_diff`.
    Security,
    /// `export` — `export_otel`.
    Export,
    /// `inventory_watch` — `inventory_scan`, `inventory_watch`.
    InventoryWatch,
}

impl WriteCategory {
    /// Every category, in a stable order.
    pub const ALL: [WriteCategory; 5] = [
        WriteCategory::Browser,
        WriteCategory::Dap,
        WriteCategory::Security,
        WriteCategory::Export,
        WriteCategory::InventoryWatch,
    ];

    /// The wire token used in `enabled_writes` (matches the plan §9.1 schema).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WriteCategory::Browser => "browser",
            WriteCategory::Dap => "dap",
            WriteCategory::Security => "security",
            WriteCategory::Export => "export",
            WriteCategory::InventoryWatch => "inventory_watch",
        }
    }

    /// Parse a category token from `enabled_writes`. Unknown tokens return
    /// `None` (and are ignored with a warning by the loader).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        WriteCategory::ALL
            .into_iter()
            .find(|c| c.as_str() == token)
    }

    /// The concrete write-tool names belonging to this category. This is the
    /// authoritative catalog the server uses to decide which routes to disable.
    #[must_use]
    pub const fn tools(self) -> &'static [&'static str] {
        match self {
            WriteCategory::Browser => &[
                "browser_navigate",
                "browser_record",
                "browser_replay",
                "browser_screenshot",
                "browser_start_session",
            ],
            WriteCategory::Dap => &[
                "debug_set_logpoint",
                "debug_enable_trace",
                "debug_start_session",
                "debug_end_session",
            ],
            WriteCategory::Security => &["security_scan", "scan_agent_diff"],
            WriteCategory::Export => &["export_otel"],
            WriteCategory::InventoryWatch => &["inventory_scan", "inventory_watch"],
        }
    }
}

/// Every write tool advertised by the surface, regardless of category. Used by
/// the server to know the full set to consider disabling, and by tests to assert
/// the read-only default hides all of them.
#[must_use]
pub fn all_write_tools() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = WriteCategory::ALL
        .into_iter()
        .flat_map(|c| c.tools().iter().copied())
        .collect();
    v.sort_unstable();
    v
}

/// The `[permissions]` table (plan §9.1), wrapping the canonical
/// [`logbook_core::config::Permissions`].
///
/// This is a thin newtype: the *schema* (fields, defaults, serde shape) lives in
/// `logbook-core`; this wrapper exists only to attach the MCP-specific write-tool
/// catalog logic ([`Self::category_enabled`], [`Self::enabled_write_tools`],
/// [`Self::disabled_write_tools`]) as inherent methods. Field reads
/// (`enabled_writes`, `allowed_domains`, the `allow_*` gates) are available
/// transparently via [`Deref`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Permissions(pub logbook_core::config::Permissions);

impl Deref for Permissions {
    type Target = logbook_core::config::Permissions;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<logbook_core::config::Permissions> for Permissions {
    fn from(inner: logbook_core::config::Permissions) -> Self {
        Self(inner)
    }
}

impl Permissions {
    /// The set of categories named in `enabled_writes`, with unknown tokens
    /// dropped (and logged).
    fn enabled_categories(&self) -> BTreeSet<WriteCategory> {
        self.enabled_writes
            .iter()
            .filter_map(|tok| {
                let parsed = WriteCategory::from_token(tok);
                if parsed.is_none() {
                    tracing::warn!(token = %tok, "ignoring unknown enabled_writes category");
                }
                parsed
            })
            .collect()
    }

    /// Whether a write *category* is fully enabled. A category is enabled only
    /// when it is listed in `enabled_writes` **and** its companion `allow_*`
    /// flag (if any) is set. `export` and `inventory_watch` have no companion
    /// flag, so listing them suffices.
    #[must_use]
    pub fn category_enabled(&self, category: WriteCategory) -> bool {
        if !self.enabled_categories().contains(&category) {
            return false;
        }
        match category {
            WriteCategory::Browser => self.allow_browser_sessions,
            WriteCategory::Dap => self.allow_dap,
            WriteCategory::Security => self.allow_security_scans,
            WriteCategory::Export | WriteCategory::InventoryWatch => true,
        }
    }

    /// The concrete set of write tools that should be **advertised/callable**
    /// given these permissions (sorted, deduplicated).
    #[must_use]
    pub fn enabled_write_tools(&self) -> BTreeSet<&'static str> {
        let mut set = BTreeSet::new();
        for category in WriteCategory::ALL {
            if self.category_enabled(category) {
                set.extend(category.tools().iter().copied());
            }
        }
        set
    }

    /// The write tools that should be **hidden** (disabled in the router) given
    /// these permissions: every write tool minus the enabled ones.
    #[must_use]
    pub fn disabled_write_tools(&self) -> Vec<&'static str> {
        let enabled = self.enabled_write_tools();
        all_write_tools()
            .into_iter()
            .filter(|t| !enabled.contains(t))
            .collect()
    }
}

/// The MCP view of `logbook.toml`. The full schema is parsed by
/// [`logbook_core::config::LogbookConfig`]; this crate only needs
/// `[permissions]`, so it keeps a single [`Permissions`] (wrapping the core
/// permission model). The load/parse semantics — including
/// **missing-file-is-read-only-default** — are inherited from core.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpConfig {
    /// The permission model. Absent table = read-only default.
    pub permissions: Permissions,
}

impl McpConfig {
    /// Build the MCP view from an already-parsed core config.
    fn from_core(cfg: logbook_core::config::LogbookConfig) -> Self {
        Self {
            permissions: Permissions(cfg.permissions),
        }
    }

    /// Resolve the config path inside a workspace root.
    #[must_use]
    pub fn path_in_root(root: impl AsRef<std::path::Path>) -> std::path::PathBuf {
        logbook_core::config::LogbookConfig::path_in_root(root)
    }

    /// Load `[permissions]` from `<root>/logbook.toml`.
    ///
    /// A **missing file is not an error** — it yields the read-only default
    /// (the secure posture). A present-but-malformed file *is* an error, so a
    /// typo can't silently fail open into broader permissions… except that, by
    /// construction, a parse error can only ever *reduce* the surface here
    /// because the caller treats `Err` as fatal at startup.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file exists but cannot be read or parsed.
    pub fn load_from_root(root: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        logbook_core::config::LogbookConfig::load_from_root(root).map(Self::from_core)
    }

    /// Load from an explicit file path (missing file = read-only default).
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file exists but cannot be read or parsed.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        logbook_core::config::LogbookConfig::load_from_file(path).map(Self::from_core)
    }

    /// Parse config from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] on malformed TOML.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        logbook_core::config::LogbookConfig::parse(text).map(Self::from_core)
    }

    /// Borrow the permission model.
    #[must_use]
    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_read_only() {
        let cfg = McpConfig::default();
        let perms = cfg.permissions();
        assert!(perms.enabled_write_tools().is_empty(), "default must enable no writes");
        // Every write tool is therefore hidden.
        assert_eq!(perms.disabled_write_tools(), all_write_tools());
    }

    #[test]
    fn missing_file_yields_read_only() {
        let dir = tempfile::tempdir().unwrap();
        // No logbook.toml written.
        let cfg = McpConfig::load_from_root(dir.path()).unwrap();
        assert!(cfg.permissions().enabled_write_tools().is_empty());
    }

    #[test]
    fn empty_permissions_table_is_read_only() {
        let cfg = McpConfig::parse("[permissions]\n").unwrap();
        assert!(cfg.permissions().enabled_write_tools().is_empty());
    }

    #[test]
    fn enabling_security_requires_both_list_and_flag() {
        // Listed but no allow flag → still disabled.
        let only_listed = McpConfig::parse(
            r#"
            [permissions]
            enabled_writes = ["security"]
            "#,
        )
        .unwrap();
        assert!(!only_listed.permissions().category_enabled(WriteCategory::Security));
        assert!(only_listed.permissions().enabled_write_tools().is_empty());

        // Listed AND allow flag → enabled.
        let both = McpConfig::parse(
            r#"
            [permissions]
            enabled_writes = ["security"]
            allow_security_scans = true
            "#,
        )
        .unwrap();
        assert!(both.permissions().category_enabled(WriteCategory::Security));
        let enabled = both.permissions().enabled_write_tools();
        assert!(enabled.contains("security_scan"));
        assert!(enabled.contains("scan_agent_diff"));
        // Only the security tools, nothing else.
        assert_eq!(enabled.len(), 2);
    }

    #[test]
    fn export_needs_no_companion_flag() {
        let cfg = McpConfig::parse(
            r#"
            [permissions]
            enabled_writes = ["export"]
            "#,
        )
        .unwrap();
        assert!(cfg.permissions().category_enabled(WriteCategory::Export));
        assert!(cfg.permissions().enabled_write_tools().contains("export_otel"));
    }

    #[test]
    fn inventory_watch_needs_no_companion_flag() {
        let cfg = McpConfig::parse(
            r#"
            [permissions]
            enabled_writes = ["inventory_watch"]
            "#,
        )
        .unwrap();
        let enabled = cfg.permissions().enabled_write_tools();
        assert!(enabled.contains("inventory_scan"));
        assert!(enabled.contains("inventory_watch"));
    }

    #[test]
    fn unknown_category_is_ignored() {
        let cfg = McpConfig::parse(
            r#"
            [permissions]
            enabled_writes = ["nonsense", "export"]
            "#,
        )
        .unwrap();
        // Only the valid `export` survives.
        assert_eq!(cfg.permissions().enabled_write_tools(), {
            let mut s = BTreeSet::new();
            s.insert("export_otel");
            s
        });
    }

    #[test]
    fn full_schema_from_plan_parses() {
        // The exact §9.1 example. The full document is parsed by
        // `logbook_core::config::LogbookConfig`; this crate keeps only
        // `[permissions]`, but the other tables must still parse cleanly.
        let text = r#"
            [permissions]
            enabled_writes        = ["security", "export"]
            allowed_domains       = ["example.test"]
            allow_browser_sessions = false
            allow_dap             = false
            allow_security_scans  = true

            [ingest]
            token_mode = "generated"

            [redaction]
            enabled = true
            deny    = []
            allow   = []

            [retention]
            max_age_days = 14
            max_db_mb    = 512

            [scanners]
            semgrep     = "semgrep"
            trivy       = "trivy"
            cargo_audit = "cargo-audit"
        "#;
        let cfg = McpConfig::parse(text).unwrap();
        let perms = cfg.permissions();
        // security enabled (listed + flag), export enabled (listed), browser/dap not.
        assert!(perms.category_enabled(WriteCategory::Security));
        assert!(perms.category_enabled(WriteCategory::Export));
        assert!(!perms.category_enabled(WriteCategory::Browser));
        assert!(!perms.category_enabled(WriteCategory::Dap));
        assert_eq!(perms.allowed_domains, vec!["example.test".to_string()]);
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(McpConfig::parse("this is = = not toml").is_err());
    }

    #[test]
    fn catalog_has_no_overlap_and_known_size() {
        // Sanity: every write tool belongs to exactly one category.
        let mut seen = BTreeSet::new();
        for c in WriteCategory::ALL {
            for t in c.tools() {
                assert!(seen.insert(*t), "tool {t} listed in two categories");
            }
        }
        // 5 browser + 4 dap + 2 security + 1 export + 2 inventory = 14.
        assert_eq!(all_write_tools().len(), 14);
    }
}
