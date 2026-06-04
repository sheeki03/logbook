//! Parent-PID watchdog (plan §4, OpenLogs parity).
//!
//! A collector launched as a child of `logbook run` must not outlive its
//! launcher: a lingering collector would squat the port and block future runs
//! (notably across git worktrees). We poll the launching process and trip a
//! shutdown channel when it either re-parents (our `ppid` changes, meaning the
//! original parent died and we were re-parented to init) or is gone.

use std::time::Duration;

use tokio::sync::oneshot;

/// The current process's parent PID, if obtainable. `None` on platforms where
/// we can't query it (the watchdog is then disabled).
#[must_use]
pub fn parent_pid() -> Option<i32> {
    #[cfg(unix)]
    {
        // SAFETY: getppid() is always safe; it takes no args and cannot fail.
        let ppid = unsafe { libc::getppid() };
        if ppid > 1 {
            Some(ppid)
        } else {
            // ppid == 1 means we're already a child of init; nothing useful to
            // watch (and we'd fire immediately).
            None
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Whether `pid` is alive. On Unix this is `kill(pid, 0)`: `Ok`/`EPERM` means
/// alive, `ESRCH` means gone.
#[must_use]
pub fn is_process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        if pid <= 0 {
            return false;
        }
        // SAFETY: kill with signal 0 performs error checking without sending a
        // signal; it cannot corrupt memory.
        let rc = unsafe { libc::kill(pid, 0) };
        if rc == 0 {
            return true;
        }
        // errno EPERM (process exists, not permitted) still means "alive".
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Poll `parent_pid` every `interval`; send on `kill_tx` once the parent dies
/// or we are re-parented away from it. Returns when the trigger fires (or the
/// receiver is dropped).
pub async fn watch(parent_pid: i32, interval: Duration, kill_tx: oneshot::Sender<()>) {
    loop {
        tokio::time::sleep(interval).await;

        let reparented = {
            #[cfg(unix)]
            {
                // SAFETY: see parent_pid().
                let now = unsafe { libc::getppid() };
                now != parent_pid
            }
            #[cfg(not(unix))]
            {
                false
            }
        };

        if reparented || !is_process_alive(parent_pid) {
            let _ = kill_tx.send(());
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_is_alive() {
        let me = std::process::id() as i32;
        assert!(is_process_alive(me));
    }

    #[test]
    fn pid_one_or_zero_handling() {
        // pid 0 / negative are never "alive" in our predicate.
        assert!(!is_process_alive(0));
        assert!(!is_process_alive(-1));
    }

    #[tokio::test]
    async fn watch_fires_when_parent_unknown_pid_is_dead() {
        // A very high pid that is essentially certain not to exist; the watchdog
        // should fire on the first tick.
        let (tx, rx) = oneshot::channel();
        let dead_pid = 2_000_000_000;
        // Only meaningful on unix where we actually probe.
        if cfg!(unix) {
            tokio::spawn(watch(dead_pid, Duration::from_millis(5), tx));
            let fired = tokio::time::timeout(Duration::from_secs(2), rx).await;
            assert!(fired.is_ok() && fired.unwrap().is_ok(), "watchdog should fire for a dead pid");
        } else {
            drop((tx, rx));
        }
    }
}
