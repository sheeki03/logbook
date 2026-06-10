//! Data-root resolution for source-store discovery.
//!
//! GUI/IDE agents keep their conversation stores under per-OS application-data
//! directories (`~/Library/Application Support` on macOS, `%APPDATA%` on
//! Windows, `$XDG_DATA_HOME`/`$XDG_CONFIG_HOME` on Linux). [`DataRoots`] is the
//! neutral set of base directories a [`SessionSource`](crate::SessionSource)
//! walks; each source knows the tool-specific sub-path beneath a root.
//!
//! Resolution is **tolerant**: a root that does not exist on this machine is
//! still returned (the source simply finds nothing under it), and a missing
//! per-OS directory is skipped rather than erroring. Discovery problems surface
//! later as [`Diag`](crate::Diag)s from the source, never as a hard failure
//! here.

use std::path::PathBuf;

/// The set of base directories under which sources look for conversation stores.
///
/// Construct via [`resolve`] (per-OS defaults, honouring `$XDG_*`) for normal
/// use, or [`from_path`] to point discovery at a single explicit directory
/// (fixtures, non-standard installs, a store copied off another machine).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataRoots {
    /// Candidate base directories, most-specific first. May include paths that
    /// do not exist on this machine; sources tolerate absent roots.
    pub roots: Vec<PathBuf>,
}

impl DataRoots {
    /// Whether there are no roots to walk.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Resolve the per-OS data/config/home roots, honouring `$XDG_*` overrides.
///
/// Returns every plausible base directory for this platform (deduplicated):
/// the user data dir, the config dir, and the home dir. Tolerant by design —
/// any directory the platform cannot resolve is simply omitted, and the result
/// may legitimately be empty on a headless/locked-down environment. The
/// `$XDG_DATA_HOME` / `$XDG_CONFIG_HOME` environment overrides are honoured
/// directly (and are also what [`dirs`] consults on Linux), so a non-standard
/// XDG layout is respected on every OS.
#[must_use]
pub fn resolve() -> DataRoots {
    let mut roots: Vec<PathBuf> = Vec::new();

    // Honour explicit XDG overrides first (cheap, cross-platform, and the most
    // specific signal a user can give). Empty values are ignored.
    push_env_path(&mut roots, "XDG_DATA_HOME");
    push_env_path(&mut roots, "XDG_CONFIG_HOME");

    // Then the per-OS defaults. On Linux these already fold in $XDG_* (so the
    // explicit pushes above are belt-and-suspenders); on macOS/Windows they are
    // the platform application-data / config directories.
    if let Some(p) = dirs::data_dir() {
        push_unique(&mut roots, p);
    }
    if let Some(p) = dirs::config_dir() {
        push_unique(&mut roots, p);
    }
    // Home last: a coarse fallback for tools that keep a dotdir directly under
    // it (e.g. `~/.continue`).
    if let Some(p) = dirs::home_dir() {
        push_unique(&mut roots, p);
    }

    DataRoots { roots }
}

/// Build a [`DataRoots`] pointing at a single explicit `path`.
///
/// Used by `--path` overrides and tests: discovery walks exactly this directory
/// (or treats it as a single store, per the source) instead of the per-OS
/// defaults.
#[must_use]
pub fn from_path(path: PathBuf) -> DataRoots {
    DataRoots { roots: vec![path] }
}

/// Push the directory named by environment variable `var` if it is set and
/// non-empty, deduplicating.
fn push_env_path(roots: &mut Vec<PathBuf>, var: &str) {
    if let Some(val) = std::env::var_os(var) {
        if !val.is_empty() {
            push_unique(roots, PathBuf::from(val));
        }
    }
}

/// Push `path` unless an equal path is already present.
fn push_unique(roots: &mut Vec<PathBuf>, path: PathBuf) {
    if !roots.contains(&path) {
        roots.push(path);
    }
}

/// Build a [`DataRoots`] rooted at a single base directory, for tests that seed a
/// per-OS-style layout (e.g. `{base}/Cursor/User/…`) under a tempdir instead of
/// the real data dirs. Equivalent to [`from_path`] but named to read as a
/// discovery root rather than a single-store override.
#[doc(hidden)]
#[must_use]
pub fn resolve_for_test(base: &std::path::Path) -> DataRoots {
    DataRoots {
        roots: vec![base.to_path_buf()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_path_holds_exactly_that_path() {
        let roots = from_path(PathBuf::from("/tmp/fixture/Cursor"));
        assert_eq!(roots.roots, vec![PathBuf::from("/tmp/fixture/Cursor")]);
        assert!(!roots.is_empty());
    }

    #[test]
    fn resolve_is_tolerant_and_deduplicates() {
        // Must not panic regardless of environment, and must not contain
        // duplicate roots.
        let roots = resolve();
        let mut sorted = roots.roots.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            roots.roots.len(),
            "resolve() returned duplicate roots: {:?}",
            roots.roots
        );
    }

    #[test]
    fn default_is_empty() {
        assert!(DataRoots::default().is_empty());
    }
}
