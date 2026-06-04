//! Small UTF-8-safe string helpers shared across the workspace.
//!
//! Several crates independently reimplemented a stable-Rust substitute for the
//! still-unstable `str::floor_char_boundary` / `str::ceil_char_boundary`, plus a
//! "cap a display name at N bytes and append an ellipsis" idiom. They live here
//! once so the boundary logic and the truncation marker can't drift.

/// The ellipsis appended by [`truncate_with_ellipsis`] when input is shortened.
pub const ELLIPSIS: char = '…';

/// Largest byte index `<= i` that lands on a UTF-8 char boundary of `s`.
///
/// A stable-Rust substitute for the unstable `str::floor_char_boundary`.
/// `i` greater than `s.len()` is clamped to `s.len()`.
///
/// ```
/// use logbook_core::text::floor_char_boundary;
/// let s = "é"; // 2 bytes: 0xC3 0xA9
/// assert_eq!(floor_char_boundary(s, 1), 0);
/// assert_eq!(floor_char_boundary(s, 2), 2);
/// assert_eq!(floor_char_boundary(s, 99), 2);
/// ```
#[must_use]
pub fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Smallest byte index `>= i` that lands on a UTF-8 char boundary of `s`.
///
/// A stable-Rust substitute for the unstable `str::ceil_char_boundary`.
/// `i` greater than `s.len()` is clamped to `s.len()`.
///
/// ```
/// use logbook_core::text::ceil_char_boundary;
/// let s = "é"; // 2 bytes
/// assert_eq!(ceil_char_boundary(s, 1), 2);
/// assert_eq!(ceil_char_boundary(s, 0), 0);
/// ```
#[must_use]
pub fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Truncate `s` to at most `max_bytes` bytes (snapped down to a UTF-8 char
/// boundary) and, **only if** the input was longer, append an [`ELLIPSIS`].
///
/// If `s` already fits in `max_bytes` it is returned unchanged (no ellipsis).
/// The returned string is therefore at most `max_bytes` bytes plus the ellipsis
/// (3 bytes) — i.e. this caps the *kept prefix* in bytes, matching the existing
/// `truncate_name` / `short_name` call sites it replaces.
///
/// ```
/// use logbook_core::text::truncate_with_ellipsis;
/// assert_eq!(truncate_with_ellipsis("hello", 10), "hello");
/// assert_eq!(truncate_with_ellipsis("hello world", 5), "hello…");
/// ```
#[must_use]
pub fn truncate_with_ellipsis(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let end = floor_char_boundary(s, max_bytes);
    let mut out = String::with_capacity(end + ELLIPSIS.len_utf8());
    out.push_str(&s[..end]);
    out.push(ELLIPSIS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_snap() {
        let s = "aé"; // 'a'(1) + 'é'(2) = 3 bytes
        assert_eq!(floor_char_boundary(s, 2), 1);
        assert_eq!(ceil_char_boundary(s, 2), 3);
        assert_eq!(floor_char_boundary(s, 100), 3);
        assert_eq!(ceil_char_boundary(s, 100), 3);
    }

    #[test]
    fn no_ellipsis_when_short() {
        assert_eq!(truncate_with_ellipsis("hi", 10), "hi");
        assert_eq!(truncate_with_ellipsis("", 0), "");
    }

    #[test]
    fn appends_ellipsis_when_truncated() {
        assert_eq!(truncate_with_ellipsis("hello world", 5), "hello…");
    }

    #[test]
    fn never_splits_a_char() {
        // Cut at a byte that lands in the middle of a multibyte char.
        let s = "abcé"; // bytes: a b c 0xC3 0xA9 -> len 5
        let out = truncate_with_ellipsis(s, 4); // byte 4 is mid-'é' -> snap to 3
        assert_eq!(out, "abc…");
        assert!(out.is_char_boundary(out.len()));
    }
}
