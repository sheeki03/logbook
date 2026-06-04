//! Terminal-output cleaning (plan §3, ported from OpenLogs `shared.ts`).
//!
//! Two cleaning tiers exist in the capture pipeline:
//!
//! * **Streaming clean** — applied to each PTY output chunk as it arrives, used
//!   to feed the live cleaned `.txt` stream. Because a chunk boundary can fall
//!   in the middle of a multi-byte UTF-8 sequence *or* in the middle of an ANSI
//!   escape sequence, the streaming path keeps a small carry buffer for the
//!   incomplete UTF-8 tail (mirroring JavaScript's `TextDecoder({stream:true})`)
//!   and strips ANSI per-chunk on a best-effort basis.
//! * **Whole-transcript clean** — applied once at teardown over the entire
//!   captured (redacted) byte stream. This *rewrites* the `.txt` file(s) so any
//!   escape sequence that was split across a chunk boundary during the streaming
//!   pass is cleaned correctly in the final artifact. This matches the OpenLogs
//!   `rewriteTextLogs` behavior.
//!
//! Both tiers perform the same normalization: strip ANSI escape sequences,
//! then fold `\r\n` and a lone `\r` to `\n`.
//!
//! ## What "strip ANSI" means here
//! OpenLogs uses Node's `stripVTControlCharacters`, which removes ANSI/VT
//! **escape sequences** (anything introduced by `ESC` — CSI `ESC[…`, OSC
//! `ESC]…`, DCS/SOS/PM/APC, single `ESC` two-byte sequences, plus the 8-bit C1
//! `0x9B` CSI introducer) but **preserves bare C0 control characters** such as
//! `\r`, `\n`, and `\t`. Preserving `\r` is essential: the newline-normalization
//! step folds it to `\n`, so it must survive the strip. This module therefore
//! strips with a faithful escape-sequence regex rather than a VT *parser* (which
//! would also swallow `\r` and partial bytes) so the behaviour matches OpenLogs.
//!
//! ## OpenLogs parity
//! - `cleanChunk(chunk, decoder)`  → [`StreamCleaner::push`]
//! - `flushCleanText(decoder)`     → [`StreamCleaner::flush`]
//! - `cleanLogText(text)`          → [`clean_log_text`]
//! - `normalizeLogText`            → [`normalize_newlines`]

use once_cell::sync::Lazy;
use regex::Regex;

/// ANSI / VT **escape-sequence** matcher (not bare control chars). Covers:
/// * CSI: `ESC [ … final` (and 8-bit `0x9B …`),
/// * OSC: `ESC ] … (BEL | ESC \\ | 0x9C)`,
/// * DCS/SOS/PM/APC: `ESC (P|X|^|_) … ST`,
/// * two-byte escapes: `ESC` followed by a single byte in `@`..`_` / intermediates.
///
/// Bare `\r`, `\n`, `\t` are intentionally NOT matched, so they pass through to
/// newline normalization. Mirrors the regex behaviour of Node's
/// `stripVTControlCharacters`.
static ANSI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        // 7-bit CSI `ESC[` or 8-bit CSI `\u{9b}`: params/intermediates then a
        // final byte 0x40–0x7E.
        r"[\x1b\u{9b}]\[[0-?]*[ -/]*[@-~]",
        // OSC `ESC]` (or 8-bit `\u{9d}`) up to BEL, ST (`ESC\`), or `\u{9c}`.
        r"|[\x1b\u{9d}]\][^\x07\x1b\u{9c}]*(?:\x07|\x1b\\|\u{9c})",
        // DCS/SOS/PM/APC introducers up to a String Terminator.
        r"|\x1b[PX^_][^\x1b\u{9c}]*(?:\x1b\\|\u{9c})",
        // Any other two-byte `ESC <byte>` sequence (e.g. `ESC(B`), including a
        // trailing lone ESC.
        r"|\x1b[ -/]*[0-~]?",
    ))
    .expect("valid ANSI escape regex")
});

/// Normalize line endings: `\r\n` → `\n`, then any remaining lone `\r` → `\n`.
///
/// Equivalent to OpenLogs `normalizeLogText`
/// (`text.replaceAll("\r\n","\n").replaceAll("\r","\n")`).
#[must_use]
pub fn normalize_newlines(text: &str) -> String {
    // Replace CRLF first so a CRLF doesn't become a double `\n`.
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Strip ANSI/VT escape **sequences** from `text`, preserving bare control
/// characters such as `\r` and `\t`. Mirrors `stripVTControlCharacters`.
#[must_use]
pub fn strip_ansi(text: &str) -> std::borrow::Cow<'_, str> {
    ANSI_RE.replace_all(text, "")
}

/// Clean an entire transcript string: strip ANSI escapes then normalize
/// newlines. This is the whole-transcript pass (`cleanLogText`).
#[must_use]
pub fn clean_log_text(text: &str) -> String {
    let stripped = strip_ansi(text);
    normalize_newlines(&stripped)
}

/// Clean an entire transcript given as raw bytes (used by the teardown rewrite
/// pass, which reads the captured byte file back in). Bytes are decoded lossily
/// first (the captured stream is text, possibly with stray non-UTF-8 bytes).
#[must_use]
pub fn clean_log_bytes(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    clean_log_text(&text)
}

/// A streaming cleaner that decodes incremental byte chunks into cleaned text.
///
/// It buffers an incomplete trailing UTF-8 sequence between chunks so a
/// multi-byte code point split across a read boundary is not corrupted — the
/// same guarantee `TextDecoder({stream:true})` gives in the OpenLogs source.
#[derive(Debug, Default)]
pub struct StreamCleaner {
    /// Bytes of an incomplete UTF-8 sequence carried over from the previous
    /// chunk. Never longer than 3 bytes (a UTF-8 sequence is at most 4 bytes).
    carry: Vec<u8>,
}

impl StreamCleaner {
    /// A fresh cleaner with an empty carry buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { carry: Vec::new() }
    }

    /// Push the next raw chunk of PTY output and return the cleaned text that
    /// can be decoded so far. Any trailing incomplete UTF-8 sequence is held
    /// back and re-emitted once completed by a later chunk (or on [`flush`]).
    ///
    /// [`flush`]: StreamCleaner::flush
    pub fn push(&mut self, chunk: &[u8]) -> String {
        // Prepend any carried-over incomplete sequence.
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);

        // Find the longest valid-UTF-8 prefix; stash the incomplete tail.
        let valid_up_to = match std::str::from_utf8(&buf) {
            Ok(_) => buf.len(),
            Err(e) => {
                // `error_len() == None` means the bytes at `valid_up_to()` are an
                // incomplete (but so-far-valid) sequence — carry them. A
                // `Some(_)` means a genuinely invalid byte, which we keep in the
                // decoded region and let `from_utf8_lossy` replace, matching the
                // lossy behavior of the streaming decoder.
                match e.error_len() {
                    None => e.valid_up_to(),
                    Some(_) => buf.len(),
                }
            }
        };

        if valid_up_to < buf.len() {
            self.carry = buf[valid_up_to..].to_vec();
        }
        let decodable = &buf[..valid_up_to];

        // Decode the complete prefix, strip ANSI escapes, then normalize.
        let text = String::from_utf8_lossy(decodable);
        let stripped = strip_ansi(&text);
        normalize_newlines(&stripped)
    }

    /// Flush any remaining carried bytes at end-of-stream, decoding them lossily
    /// (mirrors `decoder.decode()` with no `{stream:true}` in OpenLogs).
    pub fn flush(&mut self) -> String {
        if self.carry.is_empty() {
            return String::new();
        }
        let remaining = std::mem::take(&mut self.carry);
        let text = String::from_utf8_lossy(&remaining);
        let stripped = strip_ansi(&text);
        normalize_newlines(&stripped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_folds_crlf_and_lone_cr() {
        assert_eq!(normalize_newlines("a\r\nb"), "a\nb");
        assert_eq!(normalize_newlines("a\rb"), "a\nb");
        assert_eq!(normalize_newlines("a\r\n\rb\n"), "a\n\nb\n");
        // A CRLF must not become two newlines.
        assert_eq!(normalize_newlines("x\r\ny"), "x\ny");
    }

    #[test]
    fn strips_color_codes() {
        // The exact sequence the OpenLogs test uses: ESC[32m hello ESC[0m \n
        let input = b"\x1b[32mhello\x1b[0m\n";
        let cleaned = clean_log_bytes(input);
        assert_eq!(cleaned, "hello\n");
    }

    #[test]
    fn clean_log_text_strips_and_normalizes() {
        let input = "\x1b[1mbold\x1b[0m\r\nline2\r";
        assert_eq!(clean_log_text(input), "bold\nline2\n");
    }

    #[test]
    fn streaming_clean_matches_whole_clean_for_simple_input() {
        let input = b"\x1b[32mhello\x1b[0m\nworld\n";
        let mut sc = StreamCleaner::new();
        let mut out = sc.push(input);
        out.push_str(&sc.flush());
        assert_eq!(out, "hello\nworld\n");
    }

    #[test]
    fn streaming_clean_carries_split_multibyte_utf8() {
        // "é" is 0xC3 0xA9. Split across two chunks.
        let mut sc = StreamCleaner::new();
        let first = sc.push(&[b'a', 0xC3]); // incomplete tail 0xC3 carried
        assert_eq!(first, "a", "incomplete byte must be held back");
        let second = sc.push(&[0xA9, b'b']);
        assert_eq!(second, "éb");
        assert_eq!(sc.flush(), "");
    }

    #[test]
    fn streaming_clean_flushes_dangling_incomplete_sequence_lossily() {
        let mut sc = StreamCleaner::new();
        let pushed = sc.push(&[b'x', 0xE2, 0x82]); // start of a 3-byte seq, truncated
        assert_eq!(pushed, "x");
        let flushed = sc.flush();
        // Lossily decoded → replacement char, never a panic / data loss.
        assert!(flushed.contains('\u{FFFD}'), "got: {flushed:?}");
    }

    #[test]
    fn streaming_clean_normalizes_crlf_across_chunks_via_rewrite() {
        // The per-chunk pass may split a CRLF; the whole-transcript rewrite is
        // what guarantees correctness, so assert the rewrite path here.
        let whole = clean_log_bytes(b"line\r\nnext\r");
        assert_eq!(whole, "line\nnext\n");
    }
}
