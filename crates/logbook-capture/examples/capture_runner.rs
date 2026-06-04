//! Test/demo harness binary that drives the capture pipeline end-to-end the way
//! a real CLI would, so the integration tests can spawn it as a subprocess with
//! piped stdin/stdout (mirroring the OpenLogs `cli.test.ts` approach of spawning
//! the `ol` CLI).
//!
//! Usage:
//!   capture_runner [--out-dir DIR] [--name N] [--no-history] [--print-paths]
//!                  [--terminal-only|--text-only] [--no-redact] [--] CMD [ARGS...]
//!   capture_runner tail [--out-dir DIR] [--raw] [QUERY] [-- TAILARGS...]
//!
//! This binary lives under `examples/` so it is built by `cargo test` /
//! `cargo build --examples` and is otherwise not part of the public crate.

use std::path::PathBuf;
use std::process::exit;

use logbook_capture::{tail, CaptureConfig};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("tail") {
        exit(run_tail(&args[1..]));
    }
    exit(run_capture(&args));
}

fn run_capture(args: &[String]) -> i32 {
    let mut cfg = CaptureConfig::new(Vec::new());
    let mut i = 0;
    let mut command: Vec<String> = Vec::new();
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "--out-dir" => {
                cfg.out_dir = PathBuf::from(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--name" => {
                cfg.name = args.get(i + 1).cloned();
                i += 2;
            }
            "--no-history" => {
                cfg.history = false;
                i += 1;
            }
            "--print-paths" => {
                cfg.print_paths = true;
                i += 1;
            }
            "--terminal-only" => {
                cfg.write_text = false;
                i += 1;
            }
            "--text-only" => {
                cfg.write_terminal = false;
                i += 1;
            }
            "--no-redact" => {
                cfg.redact = false;
                i += 1;
            }
            other if other.starts_with('-') && other != "-" => {
                eprintln!("capture_runner: unknown option {other}");
                return 2;
            }
            _ => break,
        }
    }
    command.extend_from_slice(&args[i..]);
    if command.is_empty() {
        eprintln!("capture_runner: no command given");
        return 2;
    }
    cfg.command = command;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(logbook_capture::run(cfg)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("capture_runner: {e}");
            1
        }
    }
}

fn run_tail(args: &[String]) -> i32 {
    let mut out_dir = PathBuf::from(".logbook");
    let mut terminal = false;
    let mut query: Option<String> = None;
    let mut tail_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out-dir" => {
                out_dir = PathBuf::from(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--raw" => {
                terminal = true;
                i += 1;
            }
            "--" => {
                i += 1;
                break;
            }
            other if other.starts_with('-') && other != "-" => {
                // Unknown flag → treat the rest as tail args (matches OpenLogs).
                break;
            }
            _ => {
                if query.is_none() {
                    query = Some(args[i].clone());
                    i += 1;
                } else {
                    break;
                }
            }
        }
    }
    tail_args.extend_from_slice(&args[i..]);

    let opts = tail::TailOptions {
        out_dir,
        query,
        terminal,
        tail_args,
    };
    match tail::run(&opts) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("capture_runner: {e}");
            1
        }
    }
}
