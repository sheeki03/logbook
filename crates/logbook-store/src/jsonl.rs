//! JSONL fallback writer / reader (`events.jsonl`, plan §2).
//!
//! When SQLite is unavailable (or as a durable append-only mirror), events are
//! written one canonical-JSON object per line. The reader tolerates blank lines
//! and—by default—skips malformed lines rather than aborting the whole read, so
//! a partially-written trailing line never loses the rest of the file.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use logbook_core::Event;

use crate::error::Result;

/// The conventional JSONL fallback filename within an out-dir.
pub const JSONL_FILENAME: &str = "events.jsonl";

/// Append-only JSONL writer. Each [`JsonlWriter::append`] writes one event as a
/// single line and flushes, so a crash never leaves a half-written line in the
/// middle of the file (only ever a truncated final line).
pub struct JsonlWriter {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl JsonlWriter {
    /// Open (creating if needed) the JSONL file at `path` for appending.
    ///
    /// # Errors
    /// Returns [`crate::error::StoreError::Io`] if the parent directory cannot
    /// be created or the file cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: BufWriter::new(file),
        })
    }

    /// Open the JSONL fallback inside an out-dir (`<out_dir>/events.jsonl`).
    ///
    /// # Errors
    /// See [`JsonlWriter::open`].
    pub fn in_dir(out_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open(out_dir.as_ref().join(JSONL_FILENAME))
    }

    /// Serialize one event and write it as a single line (no flush).
    fn write_line(&mut self, event: &Event) -> Result<()> {
        let line = serde_json::to_string(event)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    /// Append one event as a JSON line and flush.
    ///
    /// # Errors
    /// Returns an error if serialization or the underlying write fails.
    pub fn append(&mut self, event: &Event) -> Result<()> {
        self.write_line(event)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Append a batch of events, flushing once at the end.
    ///
    /// # Errors
    /// Returns an error if serialization or the underlying write fails.
    pub fn append_batch(&mut self, events: &[Event]) -> Result<()> {
        for event in events {
            self.write_line(event)?;
        }
        self.writer.flush()?;
        Ok(())
    }

    /// The path being written to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Read every event from a JSONL file. Blank lines are skipped; malformed lines
/// are skipped (and logged at `warn`) so one bad line doesn't lose the file.
///
/// # Errors
/// Returns [`crate::error::StoreError::Io`] only for I/O failures opening or
/// reading the file (a missing file yields an `Io` error — use
/// [`read_jsonl_opt`] to treat "missing" as empty).
pub fn read_jsonl(path: impl AsRef<Path>) -> Result<Vec<Event>> {
    let file = File::open(path.as_ref())?;
    read_events_from(BufReader::new(file))
}

/// Like [`read_jsonl`] but a missing file is treated as an empty log.
///
/// # Errors
/// Returns an error for I/O failures other than "not found".
pub fn read_jsonl_opt(path: impl AsRef<Path>) -> Result<Vec<Event>> {
    // Open exactly once and branch on the error, so there is no second open
    // (no redundant syscall) and no TOCTOU window where the file could vanish
    // between checking and reading.
    match File::open(path.as_ref()) {
        Ok(file) => read_events_from(BufReader::new(file)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// Read every event from an already-open reader, skipping blank lines and
/// (logging then) skipping malformed lines.
fn read_events_from<R: BufRead>(reader: R) -> Result<Vec<Event>> {
    let mut out = Vec::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(trimmed) {
            Ok(ev) => out.push(ev),
            Err(e) => {
                tracing::warn!(line = lineno + 1, error = %e, "skipping malformed JSONL line");
            }
        }
    }
    Ok(out)
}
