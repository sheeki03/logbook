//! Integration tests porting the OpenLogs `cli.test.ts` contract to the Rust
//! capture pipeline (plan §3, §11).
//!
//! These spawn the `capture_runner` example binary as a subprocess (with piped
//! stdin/stdout), exactly the way `cli.test.ts` spawns the `ol` CLI, and assert
//! the same observable behaviours:
//!
//! * raw transcript + cleaned text files are written;
//! * `--no-history` / `--print-paths`;
//! * stdin is forwarded to the wrapped command;
//! * Ctrl-C (byte `0x03`) becomes a `SIGINT` to the tree and is NOT forwarded as
//!   a literal byte (exit `130`);
//! * the `SIGINT` grace gives a trap handler time to run (≥ ~1800 ms);
//! * the wrapped command's exit code is preserved;
//! * a `setsid` / orphaned descendant is reaped before exit;
//! * a wrapper `SIGTERM` tears the tree down and exits `143`;
//! * `tail` reads latest / raw / fuzzy-matched logs and shows a friendly error.
//!
//! All of these require a POSIX host with `python3`, `sh`, and `tail` available.

#![cfg(unix)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Resolve the built `capture_runner` example binary next to the test binary.
fn runner_bin() -> PathBuf {
    // current_exe = target/debug/deps/<testbin>; example = target/debug/examples/capture_runner
    let mut p = std::env::current_exe().expect("current exe");
    p.pop(); // deps
    p.pop(); // debug
    p.push("examples");
    p.push("capture_runner");
    assert!(
        p.exists(),
        "capture_runner example not built at {} (run `cargo test -p logbook-capture`)",
        p.display()
    );
    p
}

fn tmp_out() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// Spawn the runner wrapping `command`, with piped stdin/stdout/stderr.
fn spawn(out_dir: &std::path::Path, command: &[&str]) -> std::process::Child {
    Command::new(runner_bin())
        .arg("--out-dir")
        .arg(out_dir)
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runner")
}

fn read_file(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn wait_until<F: FnMut() -> bool>(mut cond: F, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if cond() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn pid_alive(pid: i32) -> bool {
    // signal 0 probe via `kill -0`.
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn writes_transcript_and_cleaned_log_files() {
    let dir = tmp_out();
    let out = dir.path();
    // Emit green "hello" then reset + newline.
    let child = spawn(
        out,
        &["sh", "-lc", "printf '\\033[32mhello\\033[0m\\n'"],
    );
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let txt = read_file(&out.join("latest.txt"));
    assert_eq!(txt, "hello\n", "cleaned text should strip ANSI; got {txt:?}");

    let term = read_file(&out.join("latest.terminal.log"));
    assert!(term.contains("hello"), "transcript should contain text; got {term:?}");

    // A timestamped history transcript exists.
    let entries: Vec<String> = std::fs::read_dir(out)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|n| n.contains("T") && n.ends_with(".terminal.log") && n != "latest.terminal.log"),
        "expected a history transcript file, saw {entries:?}"
    );
}

#[test]
fn skips_history_and_prints_paths() {
    let dir = tmp_out();
    let out = dir.path();
    let child = Command::new(runner_bin())
        .arg("--out-dir")
        .arg(out)
        .arg("--no-history")
        .arg("--print-paths")
        .args(["sh", "-lc", "printf 'hi\\n'"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(read_file(&out.join("latest.txt")), "hi\n");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("logbook:"), "print-paths should log paths to stderr; got {stderr:?}");

    // With --no-history there should be exactly the latest + named transcripts.
    let term_files = std::fs::read_dir(out)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".terminal.log"))
        .count();
    assert_eq!(term_files, 2, "expected latest + named transcript only (no history)");
}

#[test]
fn forwards_stdin_to_wrapped_command() {
    let dir = tmp_out();
    let out = dir.path();
    let mut child = spawn(out, &["sh", "-lc", "read line; printf 'got:%s\\n' \"$line\""]);
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"hello\n").unwrap();
        // Drop stdin to signal EOF.
    }
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let txt = read_file(&out.join("latest.txt"));
    assert!(txt.contains("got:hello"), "stdin not forwarded; .txt = {txt:?}");
}

#[test]
fn ctrl_c_becomes_sigint_not_forwarded_byte_exit_130() {
    let dir = tmp_out();
    let out = dir.path();
    // Child traps INT and exits 130; produces no output.
    let mut child = spawn(
        out,
        &["sh", "-lc", "trap 'exit 130' INT; while :; do sleep 1; done"],
    );
    std::thread::sleep(Duration::from_millis(200));
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&[0x03]).unwrap();
    }
    let output = child.wait_with_output().expect("wait");
    assert_eq!(
        output.status.code(),
        Some(130),
        "Ctrl-C should yield exit 130; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // No output was produced → both tiers empty (byte 3 was NOT echoed/forwarded).
    assert_eq!(read_file(&out.join("latest.txt")), "");
    assert_eq!(read_file(&out.join("latest.terminal.log")), "");
}

#[test]
fn sigint_grace_lets_trap_handler_finish() {
    let dir = tmp_out();
    let out = dir.path();
    // Trap sleeps 2s before exiting 130 — the wrapper must wait it out.
    let mut child = spawn(
        out,
        &["sh", "-lc", "trap 'sleep 2; exit 130' INT; while :; do sleep 1; done"],
    );
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&[0x03]).unwrap();
    }
    let status = child.wait().expect("wait");
    let elapsed = started.elapsed();
    assert_eq!(status.code(), Some(130), "should preserve trap's 130");
    assert!(
        elapsed >= Duration::from_millis(1800),
        "SIGINT grace too short: {elapsed:?} (< 1800ms)"
    );
}

#[test]
fn preserves_wrapped_command_exit_code() {
    let dir = tmp_out();
    let out = dir.path();
    let child = spawn(out, &["sh", "-lc", "exit 7"]);
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(7), "exit code not preserved");
}

#[test]
fn reaps_setsid_descendant_before_exit() {
    let dir = tmp_out();
    let out = dir.path();
    let pid_file = out.join("orphan.pid");
    std::fs::write(&pid_file, "").unwrap();

    // Parent forks a setsid child (new session → escapes the process group),
    // writes its pid, then the parent exits 0 after 0.2s. The supervisor must
    // have tracked the orphan before it reparented, and must reap it.
    let script = format!(
        "import os, time\n\
         pid = os.fork()\n\
         if pid == 0:\n\
         \x20   os.setsid()\n\
         \x20   open({:?}, 'w').write(str(os.getpid()))\n\
         \x20   while True: time.sleep(1)\n\
         time.sleep(0.2)\n",
        pid_file.to_string_lossy()
    );
    let child = spawn(out, &["python3", "-c", &script]);

    // Read the orphan pid.
    assert!(
        wait_until(|| !read_file(&pid_file).trim().is_empty(), Duration::from_secs(5)),
        "orphan never wrote its pid"
    );
    let orphan_pid: i32 = read_file(&pid_file).trim().parse().expect("orphan pid");

    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0), "parent should exit 0; stderr: {}", String::from_utf8_lossy(&output.stderr));

    // The orphan must be dead shortly after the wrapper exits.
    assert!(
        wait_until(|| !pid_alive(orphan_pid), Duration::from_secs(5)),
        "setsid orphan {orphan_pid} was not reaped"
    );
}

#[test]
fn wrapper_sigterm_tears_down_tree_exit_143() {
    let dir = tmp_out();
    let out = dir.path();
    let pid_file = out.join("child.pid");
    std::fs::write(&pid_file, "").unwrap();

    let cmd = format!(
        "printf %s $$ > {:?}; trap 'exit 0' TERM INT HUP; while :; do sleep 1; done",
        pid_file.to_string_lossy()
    );
    let mut child = spawn(out, &["sh", "-lc", &cmd]);
    assert!(
        wait_until(|| !read_file(&pid_file).trim().is_empty(), Duration::from_secs(5)),
        "child never wrote its pid"
    );
    let child_pid: i32 = read_file(&pid_file).trim().parse().expect("child pid");

    // Send SIGTERM to the wrapper itself.
    let runner_pid = child.id() as i32;
    assert!(
        Command::new("kill").arg("-TERM").arg(runner_pid.to_string()).status().unwrap().success(),
        "failed to SIGTERM the wrapper"
    );

    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(143), "wrapper SIGTERM should exit 128+15=143");

    assert!(
        wait_until(|| !pid_alive(child_pid), Duration::from_secs(5)),
        "wrapped child {child_pid} not terminated when wrapper was"
    );
}

// ---- tail ----

fn run_tail(out_dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(runner_bin())
        .arg("tail")
        .arg("--out-dir")
        .arg(out_dir)
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("tail output")
}

#[test]
fn tail_prints_latest_text_log() {
    let dir = tmp_out();
    let out = dir.path();
    std::fs::write(out.join("latest.txt"), "one\ntwo\nthree\n").unwrap();
    let output = run_tail(out, &["-n", "2"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "two\nthree\n");
}

#[test]
fn tail_reads_latest_raw_transcript() {
    let dir = tmp_out();
    let out = dir.path();
    std::fs::write(out.join("latest.terminal.log"), "raw-a\nraw-b\n").unwrap();
    let output = run_tail(out, &["--raw", "-n", "1"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "raw-b\n");
}

#[test]
fn tail_resolves_most_recent_matching_run() {
    let dir = tmp_out();
    let out = dir.path();
    std::fs::write(out.join("dev.txt"), "dev\n").unwrap();
    std::fs::write(out.join("dev-server.txt"), "server\n").unwrap();
    let runs = format!(
        "{}\n{}\n",
        serde_json::json!({
            "command": "npm run dev", "key": "dev",
            "outDir": out.to_string_lossy(),
            "terminalPath": out.join("dev.terminal.log").to_string_lossy(),
            "startedAt": "2026-03-08T10:45:12.000Z",
            "textPath": out.join("dev.txt").to_string_lossy(),
        }),
        serde_json::json!({
            "command": "npm run dev:server", "key": "dev-server",
            "outDir": out.to_string_lossy(),
            "terminalPath": out.join("dev-server.terminal.log").to_string_lossy(),
            "startedAt": "2026-03-08T10:50:12.000Z",
            "textPath": out.join("dev-server.txt").to_string_lossy(),
        }),
    );
    std::fs::write(out.join("runs.jsonl"), runs).unwrap();

    let output = run_tail(out, &["server", "-n", "1"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "server\n");
}

#[test]
fn tail_friendly_error_when_query_has_no_match() {
    let dir = tmp_out();
    let out = dir.path();
    std::fs::create_dir_all(out).unwrap();
    let output = run_tail(out, &["server", "-n", "10"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#"No log found for "server""#), "got stderr: {stderr:?}");
}

#[test]
fn tail_friendly_error_when_no_log_exists() {
    let dir = tmp_out();
    let out = dir.path();
    std::fs::create_dir_all(out).unwrap();
    let output = run_tail(out, &["-n", "10"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let expected = format!("No log found at {}.", out.join("latest.txt").display());
    assert!(stderr.contains(&expected), "got stderr: {stderr:?}");
}

// ---- structured events ----

#[test]
fn emits_structured_log_events_into_store() {
    use logbook_store::{Query, Store};

    let dir = tmp_out();
    let out = dir.path();
    let child = spawn(out, &["sh", "-lc", "printf 'line one\\nline two\\n'"]);
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));

    // The driver flushed the store on shutdown; reopen and query.
    let store = Store::open_in_dir(out).expect("open store");
    let events = store
        .query(&Query::new().category(logbook_core::Category::AppLog).limit(100))
        .expect("query");
    assert!(
        events.iter().any(|e| e
            .blocks
            .console
            .as_ref()
            .and_then(|c| c.message.as_deref())
            .is_some_and(|m| m.contains("line one"))),
        "expected a structured Log event for 'line one', got {} events",
        events.len()
    );
}

#[test]
fn redacts_secrets_in_all_persisted_tiers() {
    let dir = tmp_out();
    let out = dir.path();
    // The program prints an AWS-style key; it must be redacted everywhere it is
    // persisted (transcript, cleaned text, store) but the live stdout passthrough
    // is the program's own output (not asserted here).
    let child = spawn(out, &["sh", "-lc", "printf 'key=AKIAIOSFODNN7EXAMPLE done\\n'"]);
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));

    let txt = read_file(&out.join("latest.txt"));
    let term = read_file(&out.join("latest.terminal.log"));
    assert!(!txt.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into .txt: {txt:?}");
    assert!(!term.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked into transcript: {term:?}");
    assert!(txt.contains("REDACTED"), "expected a redaction placeholder in .txt: {txt:?}");
}
