//! Headline acceptance test (plan §11, §15.5):
//!
//! > Run a full debug session (start, set a logpoint, end) and assert that
//! > `git status --porcelain` is EMPTY afterward (zero source files modified).
//!
//! This proves the **non-invasiveness guarantee**: a debug session — including
//! the alpha DAP logpoint path — never writes to a source file. To scope the
//! assertion precisely (the surrounding workspace may have unrelated changes),
//! the test creates a throwaway git repo with one committed source file, runs
//! the entire session against a `file:line` in that repo, and asserts the
//! repo's working tree is pristine afterward.

#[path = "support/mock_adapter.rs"]
mod mock_adapter;

use std::process::Command;
use std::sync::Arc;

use logbook_core::Redactor;
use logbook_debug::dap::DapClient;
use logbook_debug::{DebugMode, DebugSession, Logpoint};
use logbook_store::Store;

/// Initialize a temp git repo containing one committed source file. Returns the
/// repo dir (kept alive by the returned `TempDir`) and the absolute path to the
/// source file.
fn init_repo_with_source() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let src = root.join("main.rs");
    std::fs::write(
        &src,
        "fn main() {\n    let mut x = 0;\n    for i in 0..43 {\n        x = i;\n    }\n    println!(\"done {x}\");\n}\n",
    )
    .unwrap();

    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("run git");
        assert!(
            status.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&status.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "seed"]);

    (dir, src)
}

/// `git status --porcelain` output for `root` (empty string == clean tree).
fn git_status_porcelain(root: &std::path::Path) -> String {
    let out = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .expect("run git status");
    assert!(out.status.success(), "git status failed");
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test]
async fn full_debug_session_with_logpoint_leaves_source_untouched() {
    let (repo, src) = init_repo_with_source();
    let repo_root = repo.path().to_path_buf();

    // Sanity: the freshly committed repo is clean to begin with.
    assert_eq!(
        git_status_porcelain(&repo_root),
        "",
        "precondition: repo should start clean"
    );

    // The store lives OUTSIDE the source repo (its own temp dir) so even the
    // store's own files can't possibly dirty the tree under test.
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_dir(store_dir.path()).unwrap();

    // Spawn the hermetic mock DAP adapter.
    let addr = mock_adapter::spawn().await;

    // 1. START a DAP-mode debug session targeting a file:line in the repo.
    let target = format!("{}:3", src.display());
    let mut session = DebugSession::start_session(&store, DebugMode::Dap, Some(target)).unwrap();
    let trace = session.trace_id();
    let sid = session.id().clone();

    // 2. SET A LOGPOINT at main.rs:3 — log `x` WITHOUT stopping, WITHOUT editing
    //    source. Connect the client (store-backed sink so hits are ingested).
    let client = DapClient::connect_tcp(
        addr,
        trace,
        sid.clone(),
        session.store_sink(),
        Arc::new(Redactor::new()),
    )
    .await
    .expect("connect to mock adapter");
    let client = session.attach_dap(client).unwrap();

    client.initialize("logbook-test").await.expect("initialize");
    let logpoint = Logpoint::expr(src.to_string_lossy(), 3, "x", "x");
    client.set_logpoints(&[logpoint]).await.expect("set logpoint");
    let _ = client.configuration_done().await; // best-effort

    // Give the adapter a beat to emit its simulated logpoint output, which the
    // store-backed sink ingests as events on the session.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 3. END the session — detaches ALL logpoints + disconnects.
    session.end_session().await.expect("end session");

    // THE ASSERTION: the source repo's working tree is still pristine. Zero
    // source files were modified by starting, logpointing, or ending the
    // session.
    let status = git_status_porcelain(&repo_root);
    assert_eq!(
        status, "",
        "debug session modified source files! git status --porcelain:\n{status}"
    );

    // The source file's bytes are byte-for-byte unchanged.
    let after = std::fs::read_to_string(&src).unwrap();
    assert!(after.contains("let mut x = 0;"), "source content changed");

    // And the session is recorded as ended.
    let rows = logbook_debug::list_sessions(&store).unwrap();
    let row = rows.iter().find(|r| r.id == sid).unwrap();
    assert_eq!(row.status, logbook_debug::DebugStatus::Ended);
    assert!(row.ended_at.is_some());
}
