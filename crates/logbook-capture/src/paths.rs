//! Log-file path layout, the run index, and fuzzy run lookup (plan §3, ported
//! from OpenLogs `shared.ts`).
//!
//! ## File tiers (plan §3, review #v3.1)
//! For a run whose key is `K`:
//! * `latest.terminal.log`, `K.terminal.log` (and, with history,
//!   `K.<timestamp>.terminal.log`) — the **redacted full terminal transcript**
//!   (ANSI/control bytes preserved, secrets removed). Renamed from OpenLogs'
//!   `.raw.log` to drop the "raw = byte-exact" implication.
//! * `latest.txt`, `K.txt` (and, with history, `K.<timestamp>.txt`) — the
//!   ANSI-stripped cleaned text.
//! * `.K.<timestamp>.capture.tmp` — a hidden, short-lived **redacted** capture
//!   buffer used only to drive the teardown rewrite of both the `.terminal.log`
//!   and `.txt` tiers (a whole-transcript re-redaction that also closes secrets
//!   split across chunk boundaries); deleted when the run ends. A fully
//!   un-redacted byte stream is never persisted.
//! * `runs.jsonl` — append-only run index (one JSON record per run).

use std::path::{Path, PathBuf};

use logbook_core::Redactor;
use serde::{Deserialize, Serialize};

/// Default out-dir (plan: `.logbook`).
pub const DEFAULT_OUT_DIR: &str = ".logbook";

/// Filename of the append-only run index.
pub const RUN_INDEX_FILENAME: &str = "runs.jsonl";

/// Suffix for the redacted full-transcript tier.
pub const TERMINAL_SUFFIX: &str = ".terminal.log";

/// Suffix for the ANSI-stripped cleaned-text tier.
pub const TEXT_SUFFIX: &str = ".txt";

/// The set of files a single run writes, plus the slugified run `key`.
///
/// Mirrors OpenLogs `LogPaths`, with `.raw.log` → `.terminal.log` and a
/// `.capture.tmp` scratch file instead of `.raw.log`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogPaths {
    /// Hidden, short-lived redacted capture buffer feeding the teardown rewrite
    /// of both the `.terminal.log` and `.txt` tiers.
    pub capture_path: PathBuf,
    /// Slugified run key (`name` or a slug of the command).
    pub key: String,
    /// The canonical (non-history) transcript path, `<out>/<key>.terminal.log`.
    pub terminal_path: PathBuf,
    /// All transcript files to fan output into (latest + named + optional history).
    pub terminal_paths: Vec<PathBuf>,
    /// The canonical (non-history) cleaned-text path, `<out>/<key>.txt`.
    pub text_path: PathBuf,
    /// All cleaned-text files to write (latest + named + optional history).
    pub text_paths: Vec<PathBuf>,
}

/// Options controlling how a run's paths are laid out — the subset of the CLI
/// options that path computation needs.
#[derive(Clone, Debug)]
pub struct PathOptions {
    /// The wrapped command (used to derive the default key when unnamed).
    pub command: Vec<String>,
    /// Whether to also write timestamped history files.
    pub history: bool,
    /// Explicit run name (`--name`), overriding the command-derived key.
    pub name: Option<String>,
    /// Output directory.
    pub out_dir: PathBuf,
    /// Whether to write the transcript (`.terminal.log`) tier.
    pub write_terminal: bool,
    /// Whether to write the cleaned-text (`.txt`) tier.
    pub write_text: bool,
}

impl PathOptions {
    /// Sensible defaults: out-dir [`DEFAULT_OUT_DIR`], history on, both tiers on.
    #[must_use]
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            history: true,
            name: None,
            out_dir: PathBuf::from(DEFAULT_OUT_DIR),
            write_terminal: true,
            write_text: true,
        }
    }
}

/// One record in `runs.jsonl`. Field names match the OpenLogs `RunRecord`
/// JSON shape so an existing index remains readable, except `rawPath` is renamed
/// to `terminalPath` to track the file rename.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    /// The full command line, space-joined.
    pub command: String,
    /// Slugified run key.
    pub key: String,
    /// Optional explicit name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The out-dir this run wrote to.
    #[serde(rename = "outDir")]
    pub out_dir: String,
    /// Canonical transcript path.
    #[serde(rename = "terminalPath")]
    pub terminal_path: String,
    /// RFC3339-ish start timestamp (the run-id form, `:`→`-`).
    #[serde(rename = "startedAt")]
    pub started_at: String,
    /// Canonical cleaned-text path.
    #[serde(rename = "textPath")]
    pub text_path: String,
}

/// Slugify a value: lowercase, runs of non-alphanumerics → `-`, trim leading and
/// trailing `-`, truncate to 48 bytes. Faithful port of OpenLogs `slugify`.
#[must_use]
pub fn slugify(value: &str) -> String {
    let lower = value.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    // Truncate to 48 bytes on a char boundary (slugs are ASCII so this is byte 48).
    let end = trimmed
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(trimmed.len()))
        .take_while(|&i| i <= 48)
        .last()
        .unwrap_or(0);
    trimmed[..end].to_string()
}

/// Derive the log key: explicit `name`, else a slug of the joined command, else
/// `"latest"`. Faithful port of OpenLogs `getLogKey`.
#[must_use]
pub fn log_key(command: &[String], name: Option<&str>) -> String {
    if let Some(name) = name {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    let slug = slugify(&command.join("-"));
    if slug.is_empty() {
        "latest".to_string()
    } else {
        slug
    }
}

/// Format a [`std::time::SystemTime`] as the run-id string used in history file
/// names and `startedAt`: an RFC3339 UTC timestamp with `:` replaced by `-` and
/// the trailing `.NNN` milliseconds stripped (so it ends in `Z`).
///
/// Example: `2026-03-08T10-45-12Z`. Faithful port of OpenLogs `getRunId`
/// (`now.toISOString().replaceAll(":","-").replace(/\.\d{3}Z$/, "Z")`).
#[must_use]
pub fn run_id(time: std::time::SystemTime) -> String {
    let iso = rfc3339_utc(time);
    let dashed = iso.replace(':', "-");
    // Strip a trailing `.NNN` (milliseconds) before the final `Z`, if present.
    strip_millis(&dashed)
}

/// The full `startedAt` ISO timestamp (with `:` intact and milliseconds kept),
/// matching `now.toISOString()`.
#[must_use]
pub fn started_at(time: std::time::SystemTime) -> String {
    rfc3339_utc(time)
}

/// Compute all log paths for a run (faithful port of OpenLogs `getLogPaths`),
/// using `now` for the history timestamp so it is testable.
#[must_use]
pub fn log_paths(options: &PathOptions, now: std::time::SystemTime) -> LogPaths {
    let key = log_key(&options.command, options.name.as_deref());
    let rid = run_id(now);
    let out = &options.out_dir;

    let capture_path = out.join(format!(".{key}.{rid}.capture.tmp"));
    let history_prefix = out.join(format!("{key}.{rid}"));
    let latest_prefix = out.join("latest");
    let named_prefix = out.join(&key);

    let terminal_path = path_with_suffix(&named_prefix, TERMINAL_SUFFIX);
    let text_path = path_with_suffix(&named_prefix, TEXT_SUFFIX);

    let terminal_paths = visible_paths(
        &[&latest_prefix, &named_prefix],
        &history_prefix,
        options.history,
        options.write_terminal,
        TERMINAL_SUFFIX,
    );
    let text_paths = visible_paths(
        &[&latest_prefix, &named_prefix],
        &history_prefix,
        options.history,
        options.write_text,
        TEXT_SUFFIX,
    );

    LogPaths {
        capture_path,
        key,
        terminal_path,
        terminal_paths,
        text_path,
        text_paths,
    }
}

/// Build a [`RunRecord`] for a run (port of OpenLogs `getRunRecord`).
///
/// The joined command line is run through `redactor` before it is stored, so a
/// secret passed as a literal CLI argument (e.g. `--api-key sk-…`) is scrubbed
/// from `runs.jsonl` too, mirroring the redaction applied to the captured
/// output and to `inventory`'s recorded command line.
#[must_use]
pub fn run_record(
    options: &PathOptions,
    paths: &LogPaths,
    now: std::time::SystemTime,
    redactor: &Redactor,
) -> RunRecord {
    RunRecord {
        command: redactor.redact(&options.command.join(" ")).into_owned(),
        key: paths.key.clone(),
        name: options.name.clone(),
        out_dir: options.out_dir.to_string_lossy().into_owned(),
        terminal_path: paths.terminal_path.to_string_lossy().into_owned(),
        started_at: started_at(now),
        text_path: paths.text_path.to_string_lossy().into_owned(),
    }
}

/// Path to the run index within `out_dir`.
#[must_use]
pub fn run_index_path(out_dir: &Path) -> PathBuf {
    out_dir.join(RUN_INDEX_FILENAME)
}

/// Append a run record to `runs.jsonl` (creating it if needed).
///
/// # Errors
/// Returns any I/O error from creating the directory, opening the file, or
/// writing the line.
pub fn append_run_record(out_dir: &Path, record: &RunRecord) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(out_dir)?;
    let line = serde_json::to_string(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_index_path(out_dir))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

/// Load all run records from `runs.jsonl`, tolerating blank/malformed lines.
/// A missing index yields an empty vector. Port of OpenLogs `loadRunRecords`.
#[must_use]
pub fn load_run_records(out_dir: &Path) -> Vec<RunRecord> {
    let path = run_index_path(out_dir);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<RunRecord>(l).ok())
        .collect()
}

/// The "latest" tail target for a `tail` invocation (port of OpenLogs
/// `getLatestLogPath`): `<out>/<query|latest><suffix>`.
#[must_use]
pub fn latest_log_path(out_dir: &Path, query: Option<&str>, terminal: bool) -> PathBuf {
    let stem = query.unwrap_or("latest");
    let suffix = if terminal { TERMINAL_SUFFIX } else { TEXT_SUFFIX };
    out_dir.join(format!("{stem}{suffix}"))
}

/// Find the most recent run matching `query` (reverse-chronological fuzzy
/// substring over `name`, `command`, `key`). With no query, the last record is
/// returned. Faithful port of OpenLogs `findMatchingRun`.
#[must_use]
pub fn find_matching_run<'a>(
    records: &'a [RunRecord],
    query: Option<&str>,
) -> Option<&'a RunRecord> {
    let Some(query) = query else {
        return records.last();
    };
    let normalized = query.to_lowercase();
    records.iter().rev().find(|record| {
        let name_hit = record
            .name
            .as_deref()
            .is_some_and(|n| n.to_lowercase().contains(&normalized));
        name_hit
            || record.command.to_lowercase().contains(&normalized)
            || record.key.to_lowercase().contains(&normalized)
    })
}

/// Resolve which file a `tail` should read: if a query matches a run, the run's
/// terminal/text path; otherwise the `latest` file. Port of OpenLogs
/// `resolveTailPath`.
#[must_use]
pub fn resolve_tail_path(
    out_dir: &Path,
    query: Option<&str>,
    terminal: bool,
) -> PathBuf {
    if query.is_none() {
        return latest_log_path(out_dir, None, terminal);
    }
    let records = load_run_records(out_dir);
    match find_matching_run(&records, query) {
        Some(rec) => {
            let p = if terminal { &rec.terminal_path } else { &rec.text_path };
            PathBuf::from(p)
        }
        None => latest_log_path(out_dir, query, terminal),
    }
}

// ---- internal helpers ----

fn path_with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    // `prefix` is `<dir>/<stem>`; appending a suffix means extending the file
    // name, not adding a path component.
    let mut s = prefix.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Port of OpenLogs `getVisiblePaths`: latest + named prefixes plus an optional
/// history prefix, each with `suffix`, de-duplicated while preserving order.
fn visible_paths(
    latest_prefixes: &[&Path],
    history_prefix: &Path,
    history: bool,
    enabled: bool,
    suffix: &str,
) -> Vec<PathBuf> {
    if !enabled {
        return Vec::new();
    }
    let mut out: Vec<PathBuf> = Vec::new();
    let push_unique = |p: PathBuf, out: &mut Vec<PathBuf>| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for prefix in latest_prefixes {
        push_unique(path_with_suffix(prefix, suffix), &mut out);
    }
    if history {
        push_unique(path_with_suffix(history_prefix, suffix), &mut out);
    }
    out
}

/// Format a `SystemTime` as an RFC3339 UTC string with millisecond precision,
/// e.g. `2026-03-08T10:45:12.000Z` — matching JavaScript's `Date#toISOString`.
///
/// Delegates to the shared [`logbook_core::format_rfc3339_millis`] so the date
/// math and formatter live in one place across the workspace (no local copy of
/// Howard Hinnant's `civil_from_days`).
fn rfc3339_utc(time: std::time::SystemTime) -> String {
    let dur = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Milliseconds since the epoch (the run timestamps are always >= 1970, so an
    // unsigned-to-signed cast is safe for any representable SystemTime here).
    let unix_millis = dur.as_millis() as i64;
    logbook_core::format_rfc3339_millis(unix_millis)
}

/// Strip a trailing `.NNN` (milliseconds, three digits) immediately before a
/// final `Z`, leaving the `Z`. Mirrors `/\.\d{3}Z$/ → "Z"`.
fn strip_millis(s: &str) -> String {
    if let Some(stripped) = s.strip_suffix('Z') {
        if let Some(dot) = stripped.rfind('.') {
            let frac = &stripped[dot + 1..];
            if frac.len() == 3 && frac.bytes().all(|b| b.is_ascii_digit()) {
                return format!("{}Z", &stripped[..dot]);
            }
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn opts(command: &[&str]) -> PathOptions {
        PathOptions {
            command: command.iter().map(|s| s.to_string()).collect(),
            history: true,
            name: None,
            out_dir: PathBuf::from(".logbook"),
            write_terminal: true,
            write_text: true,
        }
    }

    #[test]
    fn run_record_redacts_secret_in_command_line() {
        // A secret passed as a literal CLI argument must be scrubbed from the run
        // record (and thus from runs.jsonl), not stored verbatim.
        let o = opts(&["mytool", "--token", "AKIAIOSFODNN7EXAMPLE"]);
        let log_paths = log_paths(&o, UNIX_EPOCH);
        let rec = run_record(&o, &log_paths, UNIX_EPOCH, &Redactor::new());
        assert!(
            !rec.command.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked into run record command: {}",
            rec.command
        );
        assert!(rec.command.starts_with("mytool --token "));
    }

    #[test]
    fn run_record_disabled_redactor_keeps_command_verbatim() {
        // With --no-redact (a disabled redactor) the command is stored as-is.
        let o = opts(&["mytool", "--flag", "value"]);
        let log_paths = log_paths(&o, UNIX_EPOCH);
        let rec = run_record(&o, &log_paths, UNIX_EPOCH, &Redactor::disabled());
        assert_eq!(rec.command, "mytool --flag value");
    }

    #[test]
    fn slugify_matches_openlogs_rules() {
        assert_eq!(slugify("npm run dev"), "npm-run-dev");
        assert_eq!(slugify("  Hello, World!  "), "hello-world");
        assert_eq!(slugify("---a---b---"), "a-b");
        assert_eq!(slugify("UPPER_case"), "upper-case");
        // Truncated to 48 chars.
        let long = "a".repeat(60);
        assert_eq!(slugify(&long).len(), 48);
    }

    #[test]
    fn log_key_prefers_name_then_slug_then_latest() {
        assert_eq!(log_key(&["npm".into(), "dev".into()], Some("myname")), "myname");
        assert_eq!(log_key(&["npm".into(), "dev".into()], None), "npm-dev");
        // A command that slugs to empty falls back to "latest".
        assert_eq!(log_key(&["!!!".into()], None), "latest");
    }

    #[test]
    fn run_id_replaces_colons_and_strips_millis() {
        // 2026-03-08T10:45:12.000Z  (a known epoch second)
        let t = UNIX_EPOCH + Duration::from_secs(1_772_966_712);
        assert_eq!(started_at(t), "2026-03-08T10:45:12.000Z");
        assert_eq!(run_id(t), "2026-03-08T10-45-12Z");
    }

    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_000_000_000_123);
        assert_eq!(rfc3339_utc(t), "2001-09-09T01:46:40.123Z");
    }

    #[test]
    fn log_paths_latest_named_and_history() {
        let t = UNIX_EPOCH + Duration::from_secs(1_772_966_712);
        let p = log_paths(&opts(&["npm", "run", "dev"]), t);
        assert_eq!(p.key, "npm-run-dev");

        // latest + named + history for each tier.
        let term: Vec<String> = p
            .terminal_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(term.contains(&".logbook/latest.terminal.log".to_string()), "{term:?}");
        assert!(term.contains(&".logbook/npm-run-dev.terminal.log".to_string()), "{term:?}");
        assert!(
            term.iter()
                .any(|s| s.starts_with(".logbook/npm-run-dev.2026-03-08T10-45-12Z")
                    && s.ends_with(".terminal.log")),
            "history terminal missing: {term:?}"
        );

        let text: Vec<String> = p
            .text_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(text.contains(&".logbook/latest.txt".to_string()), "{text:?}");
        assert!(text.contains(&".logbook/npm-run-dev.txt".to_string()), "{text:?}");

        // Capture temp is a hidden dotfile.
        let cap = p.capture_path.to_string_lossy();
        assert!(cap.starts_with(".logbook/.npm-run-dev."), "{cap}");
        assert!(cap.ends_with(".capture.tmp"), "{cap}");
    }

    #[test]
    fn no_history_omits_timestamped_files() {
        let mut o = opts(&["sleep", "0"]);
        o.history = false;
        let t = UNIX_EPOCH + Duration::from_secs(1_772_966_712);
        let p = log_paths(&o, t);
        // Only latest + named (2 each), no history file.
        assert_eq!(p.terminal_paths.len(), 2, "{:?}", p.terminal_paths);
        assert_eq!(p.text_paths.len(), 2, "{:?}", p.text_paths);
    }

    #[test]
    fn tier_toggles_disable_outputs() {
        let mut o = opts(&["x"]);
        o.write_text = false;
        let p = log_paths(&o, UNIX_EPOCH);
        assert!(p.text_paths.is_empty());
        assert!(!p.terminal_paths.is_empty());
    }

    #[test]
    fn run_index_roundtrip_and_fuzzy_match() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path();

        let mk = |cmd: &str, key: &str, started: &str| RunRecord {
            command: cmd.to_string(),
            key: key.to_string(),
            name: None,
            out_dir: out.to_string_lossy().into_owned(),
            terminal_path: out.join(format!("{key}.terminal.log")).to_string_lossy().into_owned(),
            started_at: started.to_string(),
            text_path: out.join(format!("{key}.txt")).to_string_lossy().into_owned(),
        };
        append_run_record(out, &mk("npm run dev", "dev", "2026-03-08T10:45:12.000Z")).unwrap();
        append_run_record(out, &mk("npm run dev:server", "dev-server", "2026-03-08T10:50:12.000Z")).unwrap();

        let records = load_run_records(out);
        assert_eq!(records.len(), 2);

        // Fuzzy "server" → the dev-server run (reverse-chronological).
        let m = find_matching_run(&records, Some("server")).unwrap();
        assert_eq!(m.key, "dev-server");

        // No query → last record.
        assert_eq!(find_matching_run(&records, None).unwrap().key, "dev-server");

        // No match → None.
        assert!(find_matching_run(&records, Some("zzz")).is_none());
    }

    #[test]
    fn load_run_records_tolerates_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path();
        std::fs::create_dir_all(out).unwrap();
        let good = RunRecord {
            command: "x".into(),
            key: "x".into(),
            name: None,
            out_dir: out.to_string_lossy().into_owned(),
            terminal_path: "x.terminal.log".into(),
            started_at: "2026-01-01T00:00:00.000Z".into(),
            text_path: "x.txt".into(),
        };
        let line = serde_json::to_string(&good).unwrap();
        std::fs::write(run_index_path(out), format!("\n{{bad json\n{line}\n\n")).unwrap();
        let recs = load_run_records(out);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].key, "x");
    }

    #[test]
    fn resolve_tail_path_prefers_match_else_latest() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path();
        // No index yet → latest.
        assert_eq!(
            resolve_tail_path(out, None, false),
            out.join("latest.txt")
        );
        // With a query but no index → query-named latest file.
        assert_eq!(
            resolve_tail_path(out, Some("server"), false),
            out.join("server.txt")
        );

        // With an index that matches → the run's text path.
        let rec = RunRecord {
            command: "npm run dev:server".into(),
            key: "dev-server".into(),
            name: None,
            out_dir: out.to_string_lossy().into_owned(),
            terminal_path: out.join("dev-server.terminal.log").to_string_lossy().into_owned(),
            started_at: "2026-03-08T10:50:12.000Z".into(),
            text_path: out.join("dev-server.txt").to_string_lossy().into_owned(),
        };
        append_run_record(out, &rec).unwrap();
        assert_eq!(
            resolve_tail_path(out, Some("server"), false),
            out.join("dev-server.txt")
        );
        assert_eq!(
            resolve_tail_path(out, Some("server"), true),
            out.join("dev-server.terminal.log")
        );
    }
}
