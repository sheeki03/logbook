//! Controlling-terminal helpers: raw mode and window size (plan §3).
//!
//! While the wrapped command runs, the parent terminal is switched to **raw
//! mode** so keystrokes (including Ctrl-C as a literal `0x03` byte we can detect
//! and translate to a signal) reach us un-cooked, exactly as OpenLogs does with
//! `process.stdin.setRawMode(true)`. The original terminal attributes are
//! restored when the [`RawModeGuard`] is dropped, even on a panic.
//!
//! When stdin is not a TTY (e.g. tests piping stdin, or output redirected),
//! raw-mode setup is skipped and the guard is inert.
//!
//! All terminal manipulation goes through the **safe** `rustix::termios` API, so
//! this crate keeps `#![forbid(unsafe_code)]`.

use std::io::{stdin, stdout};

use rustix::termios::{isatty, tcgetattr, tcgetwinsize, tcsetattr, OptionalActions, Termios};

/// RAII guard that puts stdin into raw mode on construction and restores the
/// previous attributes on drop. Inert when stdin is not a TTY.
pub struct RawModeGuard {
    original: Option<Termios>,
}

impl RawModeGuard {
    /// Enable raw mode on the controlling terminal (stdin), returning a guard
    /// that restores it on drop. If stdin is not a TTY (or attributes can't be
    /// read/set), returns an inert guard.
    #[must_use]
    pub fn enable() -> Self {
        let stdin = stdin();
        if !isatty(&stdin) {
            return Self { original: None };
        }
        let Ok(original) = tcgetattr(&stdin) else {
            return Self { original: None };
        };

        let mut raw = original.clone();
        raw.make_raw();
        // `make_raw` already sets VMIN=1 / VTIME=0 semantics; apply now.
        if tcsetattr(&stdin, OptionalActions::Now, &raw).is_err() {
            // stdin is a real TTY but raw mode could not be engaged; the terminal
            // stays cooked, so interactive keystroke forwarding (echo / line
            // buffering for REPLs/editors) is degraded. Surface it rather than
            // silently proceeding. (Ctrl-C still works via the SIGINT handler.)
            eprintln!(
                "logbook: WARNING could not enable raw mode; interactive keystroke handling may be degraded."
            );
            return Self { original: None };
        }
        Self {
            original: Some(original),
        }
    }

    /// Whether raw mode is actually active (stdin was a TTY).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.original.is_some()
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            // Restore the saved attributes; ignore errors during teardown.
            let _ = tcsetattr(stdin(), OptionalActions::Now, &original);
        }
    }
}

/// The controlling terminal's `(cols, rows)` from stdout, or `None` if stdout is
/// not a TTY (so the caller can fall back to a default).
#[must_use]
pub fn terminal_size() -> Option<(u16, u16)> {
    let stdout = stdout();
    if !isatty(&stdout) {
        return None;
    }
    let ws = tcgetwinsize(&stdout).ok()?;
    if ws.ws_col == 0 || ws.ws_row == 0 {
        return None;
    }
    Some((ws.ws_col, ws.ws_row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_guard_is_inert_when_not_a_tty() {
        // In the test harness stdin is generally not a TTY; the guard must not
        // panic and must be droppable.
        let g = RawModeGuard::enable();
        let _ = g.is_active();
        drop(g);
    }

    #[test]
    fn terminal_size_is_none_or_positive() {
        match terminal_size() {
            None => {}
            Some((c, r)) => assert!(c > 0 && r > 0),
        }
    }
}
