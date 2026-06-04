//! Native process-tree supervisor (plan §3, replacing the OpenLogs Python
//! supervision script with in-process Rust + `nix`).
//!
//! When `logbook` wraps a command, the command (and everything it spawns) must
//! be torn down cleanly when the wrapper is interrupted — *including* processes
//! that escaped the original process group via `setsid` or a double-fork. A
//! `killpg` alone is therefore insufficient; this supervisor walks the full
//! descendant **process tree** instead.
//!
//! ## Strategy (ported from OpenLogs `supervisionScript`)
//! 1. **Continuously snapshot descendants** while the child runs, accumulating
//!    every PID ever seen below the root into a `tracked` set. This is what
//!    catches a `setsid` orphan: it is recorded *before* it reparents to
//!    `init`/`launchd`, so we can still signal it afterwards.
//! 2. On a termination signal, signal every still-living tracked PID
//!    **deepest-first** (children before parents) so a parent can't immediately
//!    respawn a just-killed child, and so shells forward signals correctly.
//! 3. Wait a **grace** period (~10 s for `SIGINT`, ~1 s otherwise) for the tree
//!    to exit, then `SIGKILL` any survivors.
//! 4. The wrapper preserves the child's disposition as exit code `128 + signum`
//!    when it was signalled (computed by the PTY driver, [`crate::pty`]).
//!
//! ## Platform support (POSIX only)
//! * **macOS / BSD** — descendants come from `ps -axo pid=,ppid=`.
//! * **Linux** — `/proc/<pid>/stat` is read directly (no `ps` dependency),
//!   falling back to `ps` if `/proc` is unavailable.
//! * **Windows** — unsupported; constructing a supervisor errors.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::error::CaptureError;

/// Default grace period for a `SIGINT` before escalating to `SIGKILL`.
pub const SIGINT_GRACE: Duration = Duration::from_secs(10);

/// Default grace period for non-`SIGINT` termination signals.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(1);

/// A source of `(pid, ppid)` pairs for the running process table. Abstracted so
/// the tree-walking logic can be unit-tested against a synthetic table.
pub trait ProcSource: Send + Sync {
    /// Snapshot the current process table as `(pid, parent_pid)` pairs.
    ///
    /// # Errors
    /// Returns a [`CaptureError`] if the underlying table cannot be read.
    fn snapshot(&self) -> Result<Vec<(i32, i32)>, CaptureError>;
}

/// Reads the process table via `ps -axo pid=,ppid=` (macOS / BSD; also works on
/// Linux as a fallback).
#[derive(Debug, Default, Clone, Copy)]
pub struct PsProcSource;

impl ProcSource for PsProcSource {
    fn snapshot(&self) -> Result<Vec<(i32, i32)>, CaptureError> {
        let output = std::process::Command::new("ps")
            .args(["-axo", "pid=,ppid="])
            .output()
            .map_err(|e| CaptureError::ProcTable(format!("spawning ps failed: {e}")))?;
        if !output.status.success() {
            return Err(CaptureError::ProcTable(format!(
                "ps exited with {:?}",
                output.status.code()
            )));
        }
        Ok(parse_pid_ppid(&String::from_utf8_lossy(&output.stdout)))
    }
}

/// Reads the process table from `/proc/<pid>/stat` (Linux). Falls back to `ps`
/// at the call site if `/proc` cannot be enumerated.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcFsProcSource;

impl ProcSource for ProcFsProcSource {
    fn snapshot(&self) -> Result<Vec<(i32, i32)>, CaptureError> {
        let dir = std::fs::read_dir("/proc")
            .map_err(|e| CaptureError::ProcTable(format!("reading /proc failed: {e}")))?;
        let mut pairs = Vec::new();
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<i32>() else {
                continue;
            };
            if let Some(ppid) = read_proc_ppid(pid) {
                pairs.push((pid, ppid));
            }
        }
        if pairs.is_empty() {
            return Err(CaptureError::ProcTable("/proc yielded no processes".into()));
        }
        Ok(pairs)
    }
}

/// Read the parent pid out of `/proc/<pid>/stat`. The fourth field is the ppid,
/// but the second field (`comm`) may contain spaces/parens, so we anchor on the
/// last `')'`.
fn read_proc_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_comm.split_whitespace();
    // Field order after comm: state(1) ppid(2) ...
    let _state = fields.next()?;
    fields.next()?.parse::<i32>().ok()
}

/// Pick the platform-appropriate process source. On Linux, `/proc` is preferred
/// with a `ps` fallback selected at snapshot time.
#[must_use]
pub fn platform_proc_source() -> Box<dyn ProcSource> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxProcSource::default())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(PsProcSource)
    }
}

/// Linux source that tries `/proc` first, then `ps`. Kept private; obtained via
/// [`platform_proc_source`].
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct LinuxProcSource {
    procfs: ProcFsProcSource,
    ps: PsProcSource,
}

#[cfg(target_os = "linux")]
impl ProcSource for LinuxProcSource {
    fn snapshot(&self) -> Result<Vec<(i32, i32)>, CaptureError> {
        match self.procfs.snapshot() {
            Ok(pairs) => Ok(pairs),
            Err(_) => self.ps.snapshot(),
        }
    }
}

/// Parse the whitespace-separated `pid ppid` lines emitted by `ps -axo
/// pid=,ppid=`. Malformed lines are skipped.
#[must_use]
pub fn parse_pid_ppid(text: &str) -> Vec<(i32, i32)> {
    text.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let pid = it.next()?.parse::<i32>().ok()?;
            let ppid = it.next()?.parse::<i32>().ok()?;
            Some((pid, ppid))
        })
        .collect()
}

/// Compute every descendant of `root` from a `(pid, ppid)` table, returned in
/// DFS discovery order (parents before their children). `root` itself is not
/// included. Self-parent / cyclic entries are guarded against.
#[must_use]
pub fn descendants(root: i32, pairs: &[(i32, i32)]) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for &(pid, ppid) in pairs {
        if pid != ppid {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut out = Vec::new();
    let mut seen: HashSet<i32> = HashSet::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if let Some(kids) = children.get(&current) {
            for &kid in kids {
                if seen.insert(kid) {
                    out.push(kid);
                    stack.push(kid);
                }
            }
        }
    }
    out
}

/// Compute the depth of each pid in `pids` relative to `root` (root = 0), using
/// the `(pid, ppid)` table. Pids not reachable from root get depth `0`.
fn depths(root: i32, pids: &[i32], pairs: &[(i32, i32)]) -> HashMap<i32, u32> {
    let parent: HashMap<i32, i32> = pairs
        .iter()
        .filter(|(pid, ppid)| pid != ppid)
        .map(|&(pid, ppid)| (pid, ppid))
        .collect();
    let mut out = HashMap::new();
    for &pid in pids {
        let mut depth = 0u32;
        let mut cur = pid;
        let mut guard = 0;
        while cur != root {
            let Some(&p) = parent.get(&cur) else { break };
            depth += 1;
            cur = p;
            guard += 1;
            if guard > 100_000 {
                break; // cycle guard
            }
        }
        out.insert(pid, depth);
    }
    out
}

/// Send `signal` to `pid`, treating "no such process" as success.
fn signal_pid(pid: i32, signal: Signal) -> Result<(), CaptureError> {
    match kill(Pid::from_raw(pid), signal) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()), // already gone
        Err(e) => Err(CaptureError::Signal {
            pid,
            signal: signal as i32,
            source: e,
        }),
    }
}

/// Whether `pid` is currently alive (signal 0 probe).
#[must_use]
pub fn is_alive(pid: i32) -> bool {
    matches!(kill(Pid::from_raw(pid), None), Ok(()))
}

/// Supervises a root process and its full descendant tree.
///
/// The async PTY driver (the only production caller) uses the off-reactor path:
/// construct with [`Supervisor::with_source`], feed externally-obtained
/// `(pid, ppid)` snapshots via [`Supervisor::observe`] (so the blocking `ps`
/// runs on a `spawn_blocking` thread, never on the Tokio reactor), and tear the
/// tree down with [`Supervisor::terminate_with`].
///
/// A simpler self-driving convenience path also exists for synchronous callers
/// and tests: construct with [`Supervisor::new`], poll [`Supervisor::track_descendants`]
/// (which shells out to `ps` itself, so it must not run on an async reactor),
/// and call [`Supervisor::terminate`] to cascade a signal and reap survivors.
pub struct Supervisor {
    root: i32,
    source: Box<dyn ProcSource>,
    /// Every descendant PID ever observed (so reparented `setsid` orphans stay
    /// reachable after they leave the root's subtree).
    tracked: HashSet<i32>,
    /// The most recent successful snapshot, used for depth-ordering at kill time.
    last_pairs: Vec<(i32, i32)>,
}

impl Supervisor {
    /// Create a supervisor for `root_pid` using the platform process source.
    ///
    /// # Errors
    /// Returns [`CaptureError::UnsupportedPlatform`] on Windows.
    pub fn new(root_pid: i32) -> Result<Self, CaptureError> {
        if cfg!(windows) {
            return Err(CaptureError::UnsupportedPlatform);
        }
        Ok(Self::with_source(root_pid, platform_proc_source()))
    }

    /// Create a supervisor with an explicit process source (used by tests).
    #[must_use]
    pub fn with_source(root_pid: i32, source: Box<dyn ProcSource>) -> Self {
        Self {
            root: root_pid,
            source,
            tracked: HashSet::new(),
            last_pairs: Vec::new(),
        }
    }

    /// The root PID being supervised.
    #[must_use]
    pub fn root(&self) -> i32 {
        self.root
    }

    /// Snapshot the process table and fold any newly-discovered descendants into
    /// the tracked set. Cheap to call in a poll loop. A snapshot failure is
    /// non-fatal (the previous tracked set is retained) but is returned so the
    /// caller can log it.
    ///
    /// # Errors
    /// Returns a [`CaptureError`] if the process table could not be read.
    pub fn track_descendants(&mut self) -> Result<(), CaptureError> {
        let pairs = self.source.snapshot()?;
        for pid in descendants(self.root, &pairs) {
            self.tracked.insert(pid);
        }
        self.last_pairs = pairs;
        Ok(())
    }

    /// Fold an externally-obtained `(pid, ppid)` snapshot into the tracked set
    /// and record it for depth-ordering. Lets the async PTY driver run the
    /// (blocking) `ps` snapshot off-reactor via `spawn_blocking` and feed the
    /// result back in, instead of having the supervisor shell out itself.
    pub fn observe(&mut self, pairs: &[(i32, i32)]) {
        for pid in descendants(self.root, pairs) {
            self.tracked.insert(pid);
        }
        self.last_pairs = pairs.to_vec();
    }

    /// The set of currently-living PIDs in the supervised tree (root first, then
    /// tracked descendants), in no particular order.
    #[must_use]
    pub fn living(&self) -> Vec<i32> {
        std::iter::once(self.root)
            .chain(self.tracked.iter().copied())
            .filter(|&pid| is_alive(pid))
            .collect()
    }

    /// Living PIDs ordered **deepest-first** (children before parents) using the
    /// last snapshot's parentage. The root sorts last.
    #[must_use]
    pub fn living_deepest_first(&self) -> Vec<i32> {
        let mut living = self.living();
        let depth = depths(self.root, &living, &self.last_pairs);
        living.sort_by(|a, b| {
            let da = if *a == self.root { 0 } else { *depth.get(a).unwrap_or(&0) };
            let db = if *b == self.root { 0 } else { *depth.get(b).unwrap_or(&0) };
            // Deeper first; tie-break by pid descending (newer pids tend deeper).
            db.cmp(&da).then(b.cmp(a))
        });
        living
    }

    /// Send `signal` to every living tracked PID, deepest-first. Refreshes the
    /// descendant set first so late spawns are included. Errors signalling an
    /// individual PID are returned for the first failure but do not stop the
    /// cascade.
    ///
    /// # Errors
    /// Returns the first per-PID [`CaptureError::Signal`] encountered (after
    /// attempting all of them).
    pub fn signal_tree(&mut self, signal: Signal) -> Result<(), CaptureError> {
        // Best-effort refresh; ignore a transient snapshot failure.
        let _ = self.track_descendants();
        let mut first_err = None;
        for pid in self.living_deepest_first() {
            if let Err(e) = signal_pid(pid, signal) {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Full termination cascade for a received `signal`:
    /// 1. signal the tree (deepest-first);
    /// 2. wait up to `grace` for the **root** to exit (matching OpenLogs, which
    ///    waits on the child first);
    /// 3. wait up to a further [`DEFAULT_GRACE`] for *all* descendants to die;
    /// 4. `SIGKILL` any survivors.
    ///
    /// `sleep` is a caller-supplied sleeper so this is testable without real
    /// time (use [`std::thread::sleep`] in production).
    ///
    /// # Errors
    /// Propagates the first signalling error, if any.
    pub fn terminate_with<S: FnMut(Duration)>(
        &mut self,
        signal: Signal,
        grace: Duration,
        mut sleep: S,
    ) -> Result<(), CaptureError> {
        self.signal_tree(signal)?;

        // Phase 1: wait for the root to exit, up to `grace`.
        let poll = Duration::from_millis(50);
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !is_alive(self.root) {
                break;
            }
            sleep(poll);
        }

        // Phase 2: wait for the whole tree to drain, up to DEFAULT_GRACE.
        let deadline = Instant::now() + DEFAULT_GRACE;
        while Instant::now() < deadline {
            if self.living().is_empty() {
                return Ok(());
            }
            sleep(poll);
        }

        // Phase 3: SIGKILL survivors, deepest-first.
        for pid in self.living_deepest_first() {
            signal_pid(pid, Signal::SIGKILL)?;
        }
        Ok(())
    }

    /// Convenience wrapper over [`Supervisor::terminate_with`] using real sleeps
    /// and the standard grace for `signal` (~10 s for `SIGINT`, ~1 s otherwise).
    ///
    /// # Errors
    /// Propagates the first signalling error, if any.
    pub fn terminate(&mut self, signal: Signal) -> Result<(), CaptureError> {
        let grace = grace_for(signal);
        self.terminate_with(signal, grace, std::thread::sleep)
    }
}

/// The grace period a given termination signal should be afforded.
#[must_use]
pub fn grace_for(signal: Signal) -> Duration {
    if signal == Signal::SIGINT {
        SIGINT_GRACE
    } else {
        DEFAULT_GRACE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A synthetic process source returning a fixed table.
    struct FakeSource(Mutex<Vec<(i32, i32)>>);
    impl FakeSource {
        fn new(pairs: Vec<(i32, i32)>) -> Self {
            Self(Mutex::new(pairs))
        }
    }
    impl ProcSource for FakeSource {
        fn snapshot(&self) -> Result<Vec<(i32, i32)>, CaptureError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    #[test]
    fn parses_ps_output() {
        let text = " 100 1\n 200 100\n 300 200\nbad line\n 400 100\n";
        let pairs = parse_pid_ppid(text);
        assert_eq!(pairs, vec![(100, 1), (200, 100), (300, 200), (400, 100)]);
    }

    #[test]
    fn descendants_walks_full_subtree() {
        // 100 ─┬─ 200 ── 300
        //      └─ 400
        // plus unrelated 999←1
        let pairs = vec![(100, 1), (200, 100), (300, 200), (400, 100), (999, 1)];
        let mut d = descendants(100, &pairs);
        d.sort_unstable();
        assert_eq!(d, vec![200, 300, 400]);
        // Parents discovered before children (DFS order).
        let order = descendants(100, &pairs);
        let pos = |p| order.iter().position(|&x| x == p).unwrap();
        assert!(pos(200) < pos(300), "parent before child: {order:?}");
    }

    #[test]
    fn descendants_guards_cycles_and_self_parent() {
        // A self-parent (50,50) and a cycle (10→20→10) must not loop forever.
        let pairs = vec![(50, 50), (10, 20), (20, 10), (5, 1), (6, 5)];
        let _ = descendants(5, &pairs); // should terminate
        let d = descendants(5, &pairs);
        assert_eq!(d, vec![6]);
    }

    #[test]
    fn depth_ordering_is_deepest_first() {
        // root=100; 200 child; 300 grandchild.
        let pairs = vec![(200, 100), (300, 200)];
        let map = depths(100, &[100, 200, 300], &pairs);
        assert_eq!(map[&100], 0);
        assert_eq!(map[&200], 1);
        assert_eq!(map[&300], 2);
    }

    #[test]
    fn track_descendants_accumulates_across_snapshots() {
        // Use this process's own pid as a never-dying "root" stand-in is risky;
        // instead test the accumulation logic with the fake source + a fake root
        // that won't be alive, then inspect `tracked` directly.
        let src = FakeSource::new(vec![(200, 42), (300, 200)]);
        let mut sup = Supervisor::with_source(42, Box::new(src));
        sup.track_descendants().unwrap();
        assert!(sup.tracked.contains(&200));
        assert!(sup.tracked.contains(&300));

        // A later snapshot where 300 has reparented to init (ppid 1): it must
        // STILL be tracked from the earlier observation.
        sup.source = Box::new(FakeSource::new(vec![(200, 42), (300, 1)]));
        sup.track_descendants().unwrap();
        assert!(sup.tracked.contains(&300), "orphaned descendant must stay tracked");
    }

    #[test]
    fn grace_for_signal() {
        assert_eq!(grace_for(Signal::SIGINT), SIGINT_GRACE);
        assert_eq!(grace_for(Signal::SIGTERM), DEFAULT_GRACE);
        assert_eq!(grace_for(Signal::SIGHUP), DEFAULT_GRACE);
    }

    #[test]
    fn new_supervisor_errors_on_windows_only() {
        // On this (non-Windows) host, construction must succeed.
        let sup = Supervisor::new(std::process::id() as i32);
        assert!(sup.is_ok(), "supervisor should construct on POSIX");
    }
}
