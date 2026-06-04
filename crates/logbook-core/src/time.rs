//! Tiny, dependency-free date/time helpers shared across the workspace.
//!
//! logbook deliberately avoids a `chrono` dependency for the handful of places
//! that need a fixed, deterministic UTC timestamp string (run filenames, OTLP /
//! Langfuse observation timestamps). Those crates previously each carried their
//! own copy of Howard Hinnant's `civil_from_days` plus a near-identical RFC3339
//! formatter; this module is the single home for both so a fix to the date math
//! lands once.

/// Convert a count of days since the UNIX epoch (1970-01-01) to a
/// `(year, month, day)` proleptic-Gregorian date.
///
/// This is Howard Hinnant's branch-free `civil_from_days` algorithm. `z` may be
/// negative (dates before 1970). The returned `month` is `1..=12` and `day` is
/// `1..=31`.
///
/// ```
/// use logbook_core::time::civil_from_days;
/// assert_eq!(civil_from_days(0), (1970, 1, 1));
/// assert_eq!(civil_from_days(-1), (1969, 12, 31));
/// ```
#[must_use]
pub const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format a count of milliseconds since the UNIX epoch as a fixed-width UTC
/// RFC3339 / ISO-8601 timestamp with millisecond precision and a `Z` suffix,
/// e.g. `2023-11-14T22:13:20.000Z`.
///
/// Negative inputs (instants before 1970) are handled correctly via Euclidean
/// division. This is the single formatter the run-filename and export paths
/// share; it intentionally always emits exactly three fractional digits.
///
/// ```
/// use logbook_core::time::format_rfc3339_millis;
/// assert_eq!(format_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
/// assert_eq!(format_rfc3339_millis(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
/// ```
#[must_use]
pub fn format_rfc3339_millis(unix_millis: i64) -> String {
    let total_secs = unix_millis.div_euclid(1_000);
    let millis = unix_millis.rem_euclid(1_000);
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(format_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_instant_round_numbers() {
        // 1_700_000_000 s since epoch.
        assert_eq!(
            format_rfc3339_millis(1_700_000_000_000),
            "2023-11-14T22:13:20.000Z"
        );
    }

    #[test]
    fn millis_are_three_digits() {
        assert_eq!(format_rfc3339_millis(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(format_rfc3339_millis(5), "1970-01-01T00:00:00.005Z");
    }

    #[test]
    fn before_epoch() {
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        // -1 ms is 1969-12-31T23:59:59.999Z
        assert_eq!(format_rfc3339_millis(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn leap_day_2020() {
        // 2020-02-29 is day 18321 since epoch.
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    }
}
