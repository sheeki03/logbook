//! The PTY capture driver (plan §3, ported from OpenLogs `cli.ts`).
//!
//! [`run`] spawns the user command inside a pseudo-terminal and fans every
//! output chunk to four sinks:
//!
//! 1. **stdout passthrough** — the user sees the program exactly as if it were
//!    run directly (colors, progress bars, prompts).
//! 2. **`*.terminal.log`** — the **redacted** full terminal transcript
//!    (ANSI/control bytes preserved, secrets scrubbed).
//! 3. **`*.txt`** — the ANSI-stripped, newline-normalized cleaned text.
//! 4. **structured `Event{kind:Log}`** rows into [`logbook_store`] (and the
//!    JSONL fallback), one per output line, with the level extracted and the
//!    text redacted.
//!
//! It also forwards **stdin** into the PTY, turns **Ctrl-C (byte `0x03`)** into a
//! `SIGINT` delivered to the process tree (the byte is *not* written to the
//! PTY), handles **`SIGWINCH`** by resizing the PTY, puts the controlling
//! terminal into **raw mode** while running, and tears the whole **descendant
//! tree** down via the native [`crate::supervisor::Supervisor`] (deepest-first,
//! graced, SIGKILL survivors) on interruption — reaping `setsid`/double-forked
//! orphans, not just the process group.
//!
//! Exit-code contract (matches the OpenLogs test suite):
//! * the wrapped command exits on its own → its exit code is preserved
//!   (a shell that traps `INT` and `exit 130` yields `130`; `exit 7` yields `7`);
//! * the wrapper itself receives `SIGINT`/`SIGTERM`/`SIGHUP` (or the user hits
//!   Ctrl-C) → the wrapper exits `128 + signum` (so `SIGTERM` → `143`,
//!   `SIGINT` → `130`).

use std::io::{Read, Write};
use std::path::PathBuf;

use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, PtySize};
use tokio::sync::mpsc;

use logbook_core::{Redactor, TraceId};
use logbook_store::{JsonlWriter, Store};

use crate::clean::{clean_log_bytes, StreamCleaner};
use crate::error::{CaptureError, Result};
use crate::parse::LineParser;
use crate::paths::{self, LogPaths, PathOptions};
use crate::supervisor::{grace_for, platform_proc_source, Supervisor};
use crate::term::RawModeGuard;

/// Configuration for a capture [`run`].
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// The command + args to run (must be non-empty).
    pub command: Vec<String>,
    /// Output directory (default `.logbook`).
    pub out_dir: PathBuf,
    /// Optional explicit run name (`--name`).
    pub name: Option<String>,
    /// Write timestamped history files in addition to `latest`/named.
    pub history: bool,
    /// Write the `*.terminal.log` transcript tier.
    pub write_terminal: bool,
    /// Write the `*.txt` cleaned-text tier.
    pub write_text: bool,
    /// Print the resolved log paths to stderr at startup (`--print-paths`).
    pub print_paths: bool,
    /// Whether secret redaction is enabled (default true).
    pub redact: bool,
}

impl CaptureConfig {
    /// A config running `command` with the default out-dir and both tiers on.
    #[must_use]
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            out_dir: PathBuf::from(paths::DEFAULT_OUT_DIR),
            name: None,
            history: true,
            write_terminal: true,
            write_text: true,
            print_paths: false,
            redact: true,
        }
    }

    fn path_options(&self) -> PathOptions {
        PathOptions {
            command: self.command.clone(),
            history: self.history,
            name: self.name.clone(),
            out_dir: self.out_dir.clone(),
            write_terminal: self.write_terminal,
            write_text: self.write_text,
        }
    }
}

/// Build the [`Redactor`] for a run: structural rules + process-env secrets plus
/// the user's configured `[redaction] deny`/`allow` patterns when enabled, or a
/// disabled redactor for `--no-redact` (callers should warn).
///
/// A `deny` pattern that fails to compile must not silently disable the rule the
/// user explicitly requested for secret protection nor drop redaction entirely:
/// a warning is emitted and the built-in rules are kept (mirroring the inventory
/// scanner's `redactor()`).
#[must_use]
pub fn build_redactor<S: AsRef<str>>(enabled: bool, deny: &[S], allow: &[S]) -> Redactor {
    logbook_core::redact::from_config(enabled, deny, allow).unwrap_or_else(|_| {
        eprintln!(
            "logbook: WARNING invalid [redaction] deny pattern in logbook.toml; using built-in rules only."
        );
        if enabled {
            Redactor::new().with_process_env()
        } else {
            Redactor::disabled()
        }
    })
}

/// The current terminal size from the real stdout, falling back to 80x24.
fn current_pty_size() -> PtySize {
    let (cols, rows) = crate::term::terminal_size().unwrap_or((80, 24));
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// A bundle of open output sinks for the four-way fan-out.
struct Sinks {
    /// Files receiving the redacted transcript (live, best-effort per chunk).
    terminal: Vec<std::fs::File>,
    /// Files receiving the cleaned text (live, best-effort per chunk).
    text: Vec<std::fs::File>,
    /// The redacted capture buffer used for the authoritative teardown rewrite.
    capture: std::fs::File,
}

impl Sinks {
    fn open(paths: &LogPaths) -> Result<Self> {
        // Truncate/create each target up front (matches OpenLogs `Bun.write("")`).
        let open = |p: &PathBuf| -> Result<std::fs::File> {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Ok(std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(p)?)
        };
        let terminal = paths
            .terminal_paths
            .iter()
            .map(open)
            .collect::<Result<Vec<_>>>()?;
        let text = paths
            .text_paths
            .iter()
            .map(open)
            .collect::<Result<Vec<_>>>()?;
        let capture = open(&paths.capture_path)?;
        Ok(Self {
            terminal,
            text,
            capture,
        })
    }

    fn write_terminal(&mut self, bytes: &[u8]) {
        let _ = self.capture.write_all(bytes);
        for f in &mut self.terminal {
            let _ = f.write_all(bytes);
        }
    }

    fn write_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        for f in &mut self.text {
            let _ = f.write_all(text.as_bytes());
        }
    }

    fn flush(&mut self) {
        let _ = self.capture.flush();
        for f in &mut self.terminal {
            let _ = f.flush();
        }
        for f in &mut self.text {
            let _ = f.flush();
        }
    }
}

/// Messages produced by the input watcher.
enum Input {
    /// Raw stdin bytes to forward into the PTY.
    Bytes(Vec<u8>),
    /// A Ctrl-C (`0x03`) was seen — interrupt the tree, don't forward the byte.
    Interrupt,
    /// stdin reached EOF.
    Eof,
}

/// Run the capture pipeline to completion, returning the wrapper exit code.
///
/// # Errors
/// Returns a [`CaptureError`] on Windows, for an empty command, or if the PTY /
/// store / filesystem cannot be initialized. Once the child is running, runtime
/// I/O errors on individual sinks are swallowed (best-effort logging) so a
/// single failing sink never aborts the user's command.
pub async fn run(config: CaptureConfig) -> Result<i32> {
    if cfg!(windows) {
        return Err(CaptureError::UnsupportedPlatform);
    }
    if config.command.is_empty() {
        return Err(CaptureError::EmptyCommand);
    }

    let path_opts = config.path_options();
    let now = std::time::SystemTime::now();
    let log_paths = paths::log_paths(&path_opts, now);

    // Honor the user's `[redaction] deny`/`allow` patterns from `logbook.toml`
    // (loaded from the workspace root = cwd, matching the rest of the workspace).
    // The CLI `--no-redact` flag (`config.redact == false`) and the config's own
    // `[redaction] enabled = false` both fully disable redaction; otherwise the
    // built-in rules + process-env secrets + the configured patterns all apply.
    // Built before the run record is written so the recorded command line is
    // redacted too (a secret passed as a literal CLI arg must not be persisted).
    let file_cfg = match std::env::current_dir() {
        Ok(root) => logbook_core::LogbookConfig::load_from_root_or_default(root),
        Err(_) => logbook_core::LogbookConfig::default(),
    };
    let redaction_enabled = config.redact && file_cfg.redaction.enabled;
    let redactor = build_redactor(
        redaction_enabled,
        &file_cfg.redaction.deny,
        &file_cfg.redaction.allow,
    );

    std::fs::create_dir_all(&config.out_dir)?;
    paths::append_run_record(
        &config.out_dir,
        &paths::run_record(&path_opts, &log_paths, now, &redactor),
    )?;

    if config.print_paths {
        for p in log_paths.terminal_paths.iter().chain(log_paths.text_paths.iter()) {
            eprintln!("logbook: {}", p.display());
        }
    }

    // Persistence: SQLite store + JSONL fallback. A store failure degrades to
    // JSONL-only rather than aborting the run; if BOTH the store and the JSONL
    // fallback fail to open (e.g. a read-only or full out-dir), warn loudly
    // because the run will otherwise look healthy while producing zero queryable
    // structured events.
    let store = match Store::open_in_dir(&config.out_dir) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "logbook: WARNING could not open the structured store in {} ({e}); falling back to JSONL only.",
                config.out_dir.display()
            );
            None
        }
    };
    let mut jsonl = match JsonlWriter::in_dir(&config.out_dir) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!(
                "logbook: WARNING could not open the JSONL fallback in {} ({e}).",
                config.out_dir.display()
            );
            None
        }
    };
    if store.is_none() && jsonl.is_none() {
        eprintln!(
            "logbook: WARNING no structured persistence is available in {}; this run's event timeline will NOT be recorded (terminal/text logs are unaffected).",
            config.out_dir.display()
        );
    }

    let trace_id = TraceId::new();
    let mut sinks = Sinks::open(&log_paths)?;

    // ---- Open the PTY and spawn the child. ----
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(current_pty_size())
        .map_err(|e| CaptureError::Pty(format!("openpty failed: {e}")))?;

    let mut cmd = CommandBuilder::new(&config.command[0]);
    cmd.args(&config.command[1..]);
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|source| CaptureError::Spawn {
            command: config.command.join(" "),
            source: std::io::Error::other(source.to_string()),
        })?;
    // Drop the slave handle so the only thing holding the slave open is the
    // child; this lets the master see EOF when the child exits.
    drop(pair.slave);

    let root_pid = child.process_id().map(|p| p as i32);
    let killer: Box<dyn ChildKiller + Send + Sync> = child.clone_killer();

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| CaptureError::Pty(format!("clone reader failed: {e}")))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| CaptureError::Pty(format!("take writer failed: {e}")))?;
    // The master is only used (for `resize`) from this task's select loop; it is
    // never sent to another thread, so it is held by value rather than in an Arc.
    let master = pair.master;

    // ---- Raw mode for the controlling terminal (restored on drop). ----
    let _raw_guard = RawModeGuard::enable();

    // ---- Signal listener (registered before any work; buffers everything). ----
    // SIGWINCH triggers a resize; SIGINT/SIGTERM/SIGHUP trigger teardown.
    let (sig_tx, mut sig_rx) = mpsc::unbounded_channel::<i32>();
    let signal_task = spawn_signal_listener(sig_tx);

    // ---- PTY output reader (blocking) → async channel. ----
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    let reader_task = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF: child closed the PTY
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // ---- stdin watcher (blocking) → async channel. ----
    let (in_tx, mut in_rx) = mpsc::channel::<Input>(64);
    let stdin_task = spawn_stdin_watcher(in_tx);

    // PTY writer lives in a dedicated blocking task fed by a channel so async
    // code never blocks on terminal writes.
    let (pty_in_tx, pty_in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let writer_task = spawn_pty_writer(writer, pty_in_rx);

    // ---- Supervisor + descendant tracking. ----
    let mut supervisor = root_pid.map(|pid| Supervisor::with_source(pid, platform_proc_source()));
    let mut snapshot_interval = tokio::time::interval(std::time::Duration::from_millis(50));
    snapshot_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Streaming text cleaner + line parser for the structured-event tier.
    let mut cleaner = StreamCleaner::new();
    let mut parser = LineParser::new(trace_id);

    // Latches the first runtime persistence failure so we warn exactly once
    // rather than silently dropping (or spamming) every failing batch.
    let mut persist_warned = false;

    // The signal we will exit `128 + signum` for, if any (None ⇒ child's own code).
    let mut received_signal: Option<i32> = None;

    // ---- Main select loop. ----
    loop {
        tokio::select! {
            biased;

            // A wrapper signal arrived.
            Some(signum) = sig_rx.recv() => {
                if signum == libc::SIGWINCH {
                    let _ = master.resize(current_pty_size());
                    continue;
                }
                received_signal = Some(signum);
                break;
            }

            // stdin activity.
            Some(input) = in_rx.recv() => {
                match input {
                    Input::Interrupt => {
                        // Ctrl-C: deliver SIGINT to the tree; treat as a received
                        // SIGINT for exit-code purposes; do NOT forward the byte.
                        received_signal = Some(libc::SIGINT);
                        break;
                    }
                    Input::Bytes(bytes) => {
                        let _ = pty_in_tx.send(bytes);
                    }
                    Input::Eof => {
                        // Close the PTY's stdin by dropping the writer feed.
                        // (Subsequent loop iterations simply won't forward input.)
                    }
                }
            }

            // PTY output chunk → fan-out.
            chunk = out_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        fan_out(
                            &bytes,
                            &redactor,
                            &mut cleaner,
                            &mut parser,
                            &mut sinks,
                            PersistSinks {
                                store: store.as_ref(),
                                jsonl: jsonl.as_mut(),
                                warned: &mut persist_warned,
                            },
                        );
                    }
                    None => {
                        // Output channel closed ⇒ child exited on its own.
                        break;
                    }
                }
            }

            // Periodic descendant snapshot (off-reactor `ps`).
            _ = snapshot_interval.tick() => {
                if let Some(sup) = supervisor.as_mut() {
                    if let Ok(Ok(pairs)) = tokio::task::spawn_blocking(|| platform_proc_source().snapshot()).await {
                        sup.observe(&pairs);
                    }
                }
            }
        }
    }

    // ---- Teardown. ----
    // 1. Flush the streaming cleaner's residual text to the live `.txt` sinks.
    let tail = cleaner.flush();
    sinks.write_text(&tail);
    if let Some(ev) = parser.finish(&redactor) {
        persist_event(store.as_ref(), jsonl.as_mut(), ev);
    }

    // 2. Cascade termination over the descendant tree.
    //    - If the wrapper received a signal, use it (and its grace).
    //    - Otherwise the child already exited; a SIGTERM sweep reaps stragglers
    //      (the `setsid` orphan reaping case).
    // Run on a blocking thread so this works on any runtime flavor.
    let teardown_signal = received_signal
        .and_then(|s| nix::sys::signal::Signal::try_from(s).ok())
        .unwrap_or(nix::sys::signal::Signal::SIGTERM);
    match supervisor.take() {
        Some(mut sup) => {
            let grace = grace_for(teardown_signal);
            let _ = tokio::task::spawn_blocking(move || {
                let _ = sup.terminate_with(teardown_signal, grace, std::thread::sleep);
            })
            .await;
        }
        None => {
            // No pid known; best-effort signal the immediate child via the killer.
            let mut k = killer;
            let _ = k.kill();
        }
    }

    // 3. Reap the child's exit status (now that the tree is down).
    let child_status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));

    // 4. Stop input/writer tasks and the signal listener.
    drop(pty_in_tx);
    signal_task.abort();
    stdin_task.abort();
    let _ = writer_task.await;
    let _ = reader_task.await;

    // 5. Flush sinks, then the authoritative whole-transcript rewrite from the
    //    (redacted) capture buffer: re-redact end-to-end (catches secrets split
    //    across chunk boundaries) and overwrite both tiers; then delete it.
    sinks.flush();
    drop(sinks);
    rewrite_from_capture(&log_paths, &redactor, config.write_terminal, config.write_text);
    let _ = std::fs::remove_file(&log_paths.capture_path);

    // 6. Persist a final flush of the store.
    if let Some(store) = store.as_ref() {
        let _ = store.shutdown();
    }
    drop(jsonl);

    // 7. Compute the wrapper exit code.
    Ok(exit_code(received_signal, child_status))
}

/// The persistence-tier destinations for structured events, plus the
/// "warned once" latch shared across them. Bundled so [`fan_out`] takes one
/// argument for the whole persistence concern instead of three.
struct PersistSinks<'a> {
    store: Option<&'a Store>,
    jsonl: Option<&'a mut JsonlWriter>,
    /// Latches the first runtime persistence failure (see [`warn_persist_once`]).
    warned: &'a mut bool,
}

/// Fan one PTY output chunk to all four sinks.
fn fan_out(
    bytes: &[u8],
    redactor: &Redactor,
    cleaner: &mut StreamCleaner,
    parser: &mut LineParser,
    sinks: &mut Sinks,
    persist: PersistSinks<'_>,
) {
    // 1. stdout passthrough — the user sees raw, un-redacted output live (it is
    //    never persisted; only the screen). This matches a normal terminal.
    {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bytes);
        let _ = out.flush();
    }

    // 2. Redact the decoded chunk; the redacted text feeds every *persisted*
    //    sink. ANSI/control bytes are ASCII and survive lossy UTF-8 decoding.
    let decoded = String::from_utf8_lossy(bytes);
    let redacted = redactor.redact(&decoded);
    sinks.write_terminal(redacted.as_bytes());

    // 3. Cleaned text tier: strip ANSI + normalize newlines, then re-redact the
    //    cleaned stream before persisting. Redacting the ANSI-containing chunk in
    //    step 2 is not sufficient for the text tier because the structural rules
    //    (AWS key, JWT, bearer, …) need a contiguous run: a secret a program
    //    colorizes mid-token (`AKIA\x1b[0mIOSF…`) survives step-2 redaction but is
    //    reassembled into the bare secret once strip_ansi removes the escape. So
    //    the cleaned text is the single source for this tier and must be redacted
    //    *after* cleaning. Per-chunk best effort; the teardown rewrite is
    //    authoritative.
    let cleaned = redactor.redact(&cleaner.push(redacted.as_bytes())).into_owned();
    sinks.write_text(&cleaned);

    // 4. Structured events, one per completed line (already-redacted input).
    let events = parser.push(redactor, &cleaned);
    if !events.is_empty() {
        let PersistSinks { store, jsonl, warned } = persist;
        match (store, jsonl) {
            (Some(store), Some(jsonl)) => {
                if let Err(e) = jsonl.append_batch(&events) {
                    warn_persist_once(warned, "JSONL append", &e);
                }
                if let Err(e) = store.insert_batch(events) {
                    warn_persist_once(warned, "store insert", &e);
                }
            }
            (Some(store), None) => {
                if let Err(e) = store.insert_batch(events) {
                    warn_persist_once(warned, "store insert", &e);
                }
            }
            (None, Some(jsonl)) => {
                if let Err(e) = jsonl.append_batch(&events) {
                    warn_persist_once(warned, "JSONL append", &e);
                }
            }
            (None, None) => {}
        }
    }
}

/// Emit a single warning on the first runtime persistence failure, then stay
/// quiet so a persistently-failing sink doesn't flood stderr while leaving the
/// user with no signal that events are being dropped.
fn warn_persist_once(warned: &mut bool, what: &str, err: &dyn std::fmt::Display) {
    if !*warned {
        *warned = true;
        eprintln!("logbook: WARNING {what} failed ({err}); some structured events may be lost.");
    }
}

fn persist_event(store: Option<&Store>, jsonl: Option<&mut JsonlWriter>, event: logbook_core::Event) {
    if let Some(jsonl) = jsonl {
        let _ = jsonl.append(&event);
    }
    if let Some(store) = store {
        let _ = store.insert(&event);
    }
}

/// Authoritative teardown rewrite: read the redacted capture buffer, re-redact
/// the whole transcript (closing any per-chunk boundary gaps), and overwrite the
/// `.terminal.log` and `.txt` tiers. Mirrors OpenLogs `rewriteTextLogs`, extended
/// to also harden the transcript tier per plan §9.
fn rewrite_from_capture(
    paths: &LogPaths,
    redactor: &Redactor,
    write_terminal: bool,
    write_text: bool,
) {
    let Ok(raw) = std::fs::read(&paths.capture_path) else {
        return;
    };
    // Whole-transcript redaction (idempotent over already-redacted placeholders).
    let decoded = String::from_utf8_lossy(&raw);
    let transcript = redactor.redact(&decoded).into_owned();

    if write_terminal {
        for p in &paths.terminal_paths {
            let _ = std::fs::write(p, transcript.as_bytes());
        }
    }
    if write_text {
        // Re-redact after cleaning: stripping ANSI from the transcript can
        // reassemble an escape-split secret into a contiguous run that only now
        // matches the structural rules (see `fan_out` step 3), so the cleaned
        // text must be redacted before it is persisted to the `.txt` tier.
        let cleaned = redactor
            .redact(&clean_log_bytes(transcript.as_bytes()))
            .into_owned();
        for p in &paths.text_paths {
            let _ = std::fs::write(p, cleaned.as_bytes());
        }
    }
}

/// Compute the wrapper exit code from the optional received signal and the
/// child's reaped status.
fn exit_code(received_signal: Option<i32>, child_status: std::io::Result<portable_pty::ExitStatus>) -> i32 {
    if let Some(signum) = received_signal {
        // The wrapper itself was interrupted (or Ctrl-C'd) → 128 + signum.
        return 128 + signum;
    }
    match child_status {
        Ok(status) => status.exit_code() as i32,
        Err(_) => 1,
    }
}

/// Spawn the signal listener task. Registers SIGINT/SIGTERM/SIGHUP/SIGWINCH and
/// forwards each received signal number on `tx`. Registration happens inside the
/// task immediately, before the child produces output, so an early Ctrl-C is
/// still observed (buffered in the channel).
fn spawn_signal_listener(tx: mpsc::UnboundedSender<i32>) -> tokio::task::JoinHandle<()> {
    use futures::stream::StreamExt;
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};
    use signal_hook_tokio::Signals;

    tokio::spawn(async move {
        let mut signals = match Signals::new([SIGINT, SIGTERM, SIGHUP, SIGWINCH]) {
            Ok(s) => s,
            Err(_) => return,
        };
        while let Some(signum) = signals.next().await {
            if tx.send(signum).is_err() {
                break;
            }
        }
    })
}

/// Spawn the stdin watcher. Reads the real stdin and emits [`Input`] messages,
/// flagging a Ctrl-C (`0x03`) as [`Input::Interrupt`] (the byte is consumed, not
/// forwarded), matching OpenLogs `hasInterruptByte`.
fn spawn_stdin_watcher(tx: mpsc::Sender<Input>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.blocking_send(Input::Eof);
                    break;
                }
                Ok(n) => {
                    let data = &buf[..n];
                    if data.contains(&0x03) {
                        if tx.blocking_send(Input::Interrupt).is_err() {
                            break;
                        }
                    } else if tx.blocking_send(Input::Bytes(data.to_vec())).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

/// Spawn the PTY writer task: drains forwarded stdin bytes from `rx` and writes
/// them into the PTY master.
fn spawn_pty_writer(
    mut writer: Box<dyn Write + Send>,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        while let Ok(bytes) = rx.recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use portable_pty::ExitStatus;

    #[test]
    fn exit_code_prefers_received_signal() {
        // SIGTERM (15) → 143 regardless of child status.
        let st = Ok(ExitStatus::with_exit_code(0));
        assert_eq!(exit_code(Some(libc::SIGTERM), st), 143);
        // SIGINT (2) → 130.
        let st = Ok(ExitStatus::with_exit_code(0));
        assert_eq!(exit_code(Some(libc::SIGINT), st), 130);
        // SIGHUP (1) → 129.
        let st = Ok(ExitStatus::with_exit_code(0));
        assert_eq!(exit_code(Some(libc::SIGHUP), st), 129);
    }

    #[test]
    fn exit_code_preserves_child_code_without_signal() {
        assert_eq!(exit_code(None, Ok(ExitStatus::with_exit_code(7))), 7);
        assert_eq!(exit_code(None, Ok(ExitStatus::with_exit_code(0))), 0);
        // A child that trapped INT and exited 130 surfaces as a normal exit 130.
        assert_eq!(exit_code(None, Ok(ExitStatus::with_exit_code(130))), 130);
    }

    #[test]
    fn build_redactor_honors_flag() {
        let empty: &[&str] = &[];
        assert!(build_redactor(true, empty, empty).is_enabled());
        assert!(!build_redactor(false, empty, empty).is_enabled());
    }

    #[test]
    fn build_redactor_applies_configured_deny_pattern() {
        // A custom deny pattern from `[redaction] deny` must take effect on the
        // capture path (regression for the ignored-config finding).
        let deny = ["PROJSECRET-[0-9]+"];
        let allow: &[&str] = &[];
        let r = build_redactor(true, &deny, allow);
        let out = r.redact("token PROJSECRET-12345 end");
        assert!(!out.contains("PROJSECRET-12345"), "custom deny not applied: {out}");
    }

    #[test]
    fn build_redactor_invalid_deny_falls_back_to_builtins() {
        // An invalid deny regex must not disable redaction entirely; built-in
        // rules (e.g. AWS keys) must still apply.
        let deny = ["("]; // invalid regex
        let allow: &[&str] = &[];
        let r = build_redactor(true, &deny, allow);
        assert!(r.is_enabled());
        let out = r.redact("AKIAIOSFODNN7EXAMPLE");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "built-in rule lost: {out}");
    }

    /// Regression for the escape-split-secret leak: a secret a program colorizes
    /// mid-token (`AKIA` + reset + the rest) is NOT matched by the structural
    /// redactor while the ANSI escape splits it, but is reassembled into the bare
    /// secret once ANSI is stripped. The cleaned `.txt` tier must therefore be
    /// redacted *after* cleaning, so the reassembled secret never lands on disk.
    #[test]
    fn fan_out_redacts_escape_split_secret_in_text_tier() {
        use std::io::Read as _;

        let dir = tempfile::tempdir().unwrap();
        let opts = PathOptions {
            command: vec!["echo".into()],
            history: false,
            name: Some("escsplit".into()),
            out_dir: dir.path().to_path_buf(),
            write_terminal: true,
            write_text: true,
        };
        let log_paths = paths::log_paths(&opts, std::time::SystemTime::UNIX_EPOCH);
        let mut sinks = Sinks::open(&log_paths).unwrap();

        let redactor = build_redactor(true, &[] as &[&str], &[] as &[&str]);
        let mut cleaner = StreamCleaner::new();
        let mut parser = LineParser::new(TraceId::new());
        let mut warned = false;

        // `AKIA` then a colour reset (`ESC[0m`) then the rest of the AWS key.
        let chunk = b"AKIA\x1b[0mIOSFODNN7EXAMPLE\n";
        fan_out(
            chunk,
            &redactor,
            &mut cleaner,
            &mut parser,
            &mut sinks,
            PersistSinks {
                store: None,
                jsonl: None,
                warned: &mut warned,
            },
        );
        sinks.write_text(&cleaner.flush());
        sinks.flush();
        drop(sinks);

        // After the per-chunk pass, the cleaned `.txt` tier must not contain the
        // reassembled bare secret.
        let mut txt = String::new();
        std::fs::File::open(&log_paths.text_path)
            .unwrap()
            .read_to_string(&mut txt)
            .unwrap();
        assert!(
            !txt.contains("AKIAIOSFODNN7EXAMPLE"),
            "escape-split secret leaked into .txt tier: {txt:?}"
        );

        // And the authoritative teardown rewrite (reads the capture buffer back,
        // strips ANSI, re-redacts) must also be clean.
        rewrite_from_capture(&log_paths, &redactor, true, true);
        let mut rewritten = String::new();
        std::fs::File::open(&log_paths.text_path)
            .unwrap()
            .read_to_string(&mut rewritten)
            .unwrap();
        assert!(
            !rewritten.contains("AKIAIOSFODNN7EXAMPLE"),
            "escape-split secret leaked into rewritten .txt tier: {rewritten:?}"
        );
    }
}
