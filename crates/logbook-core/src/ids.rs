//! W3C trace-context-width identifiers.
//!
//! - [`TraceId`] is 128-bit, rendered as 32 lowercase hex characters
//!   (matching the W3C `trace-id` field).
//! - [`SpanId`] is 64-bit, rendered as 16 lowercase hex characters
//!   (matching the W3C `parent-id` / span id field).
//!
//! Both are generated from OS entropy via [`getrandom`]. Per the W3C
//! trace-context spec the all-zero value is invalid, so generation retries
//! until a non-zero value is produced (astronomically rare to loop even once).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreError;

/// A 128-bit trace identifier (W3C width: 32 lowercase hex chars).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId([u8; 16]);

/// A 64-bit span identifier (W3C width: 16 lowercase hex chars).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId([u8; 8]);

impl TraceId {
    /// Number of bytes in a trace id (128 bits).
    pub const LEN: usize = 16;
    /// Number of hex characters in the rendered form.
    pub const HEX_LEN: usize = 32;

    /// Generate a fresh, non-zero random trace id from OS entropy.
    ///
    /// # Panics
    /// Panics only if the OS entropy source is unavailable. Use
    /// [`TraceId::try_new`] to handle that case explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("OS entropy source unavailable for TraceId")
    }

    /// Fallible variant of [`TraceId::new`].
    ///
    /// # Errors
    /// Returns [`CoreError::Entropy`] if the OS entropy source fails.
    pub fn try_new() -> Result<Self, CoreError> {
        loop {
            let mut bytes = [0u8; Self::LEN];
            fill(&mut bytes)?;
            if bytes != [0u8; Self::LEN] {
                return Ok(Self(bytes));
            }
        }
    }

    /// Construct from raw bytes (no validation beyond width, which is enforced
    /// by the array type).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Whether this id is the (invalid) all-zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; Self::LEN]
    }

    /// Render as 32 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl SpanId {
    /// Number of bytes in a span id (64 bits).
    pub const LEN: usize = 8;
    /// Number of hex characters in the rendered form.
    pub const HEX_LEN: usize = 16;

    /// Generate a fresh, non-zero random span id from OS entropy.
    ///
    /// # Panics
    /// Panics only if the OS entropy source is unavailable. Use
    /// [`SpanId::try_new`] to handle that case explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("OS entropy source unavailable for SpanId")
    }

    /// Fallible variant of [`SpanId::new`].
    ///
    /// # Errors
    /// Returns [`CoreError::Entropy`] if the OS entropy source fails.
    pub fn try_new() -> Result<Self, CoreError> {
        loop {
            let mut bytes = [0u8; Self::LEN];
            fill(&mut bytes)?;
            if bytes != [0u8; Self::LEN] {
                return Ok(Self(bytes));
            }
        }
    }

    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Whether this id is the (invalid) all-zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; Self::LEN]
    }

    /// Render as 16 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SpanId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceId({})", self.to_hex())
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpanId({})", self.to_hex())
    }
}

impl FromStr for TraceId {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::LEN];
        parse_hex(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl FromStr for SpanId {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::LEN];
        parse_hex(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

// Serialize/Deserialize as the lowercase-hex string form (interop-friendly,
// and what the export adapters and SQLite columns expect).
impl Serialize for TraceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl Serialize for SpanId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TraceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for SpanId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Fill a byte buffer with OS entropy.
fn fill(buf: &mut [u8]) -> Result<(), CoreError> {
    getrandom::fill(buf).map_err(|e| CoreError::Entropy(e.to_string()))
}

/// Lowercase-hex encode a byte slice without extra allocations per byte.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parse exactly `2 * out.len()` lowercase-or-uppercase hex chars into `out`.
fn parse_hex(s: &str, out: &mut [u8]) -> Result<(), CoreError> {
    let expected = out.len() * 2;
    if s.len() != expected {
        return Err(CoreError::InvalidId {
            expected,
            got: s.to_string(),
        });
    }
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[i * 2]).ok_or_else(|| CoreError::InvalidId {
            expected,
            got: s.to_string(),
        })?;
        let lo = hex_val(bytes[i * 2 + 1]).ok_or_else(|| CoreError::InvalidId {
            expected,
            got: s.to_string(),
        })?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

/// Map a single ASCII hex byte to its 0–15 value.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_id_is_32_lowercase_hex_chars() {
        let id = TraceId::new();
        let hex = id.to_hex();
        assert_eq!(hex.len(), TraceId::HEX_LEN, "trace id must be 32 hex chars");
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "trace id hex must be lowercase: {hex}"
        );
    }

    #[test]
    fn span_id_is_16_lowercase_hex_chars() {
        let id = SpanId::new();
        let hex = id.to_hex();
        assert_eq!(hex.len(), SpanId::HEX_LEN, "span id must be 16 hex chars");
        assert_eq!(hex.len(), 16);
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "span id hex must be lowercase: {hex}"
        );
    }

    #[test]
    fn generated_ids_are_never_zero() {
        for _ in 0..1000 {
            assert!(!TraceId::new().is_zero());
            assert!(!SpanId::new().is_zero());
        }
    }

    #[test]
    fn generated_ids_are_distinct() {
        // Collisions across 1000 128-bit ids would indicate a broken RNG.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(TraceId::new().to_hex()), "duplicate trace id");
        }
        let mut seen_spans = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen_spans.insert(SpanId::new().to_hex()), "duplicate span id");
        }
    }

    #[test]
    fn trace_id_roundtrips_through_hex() {
        let id = TraceId::new();
        let parsed: TraceId = id.to_hex().parse().unwrap();
        assert_eq!(id, parsed);
        assert_eq!(id.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn span_id_roundtrips_through_hex() {
        let id = SpanId::new();
        let parsed: SpanId = id.to_hex().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn parse_accepts_uppercase_but_renders_lowercase() {
        let id: TraceId = "ABCDEF0123456789ABCDEF0123456789".parse().unwrap();
        assert_eq!(id.to_hex(), "abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn parse_rejects_wrong_width() {
        assert!("abc".parse::<TraceId>().is_err());
        assert!("".parse::<SpanId>().is_err());
        // 16 chars is a span width, not a trace width.
        assert!("0123456789abcdef".parse::<TraceId>().is_err());
        // 32 chars is a trace width, not a span width.
        assert!("0123456789abcdef0123456789abcdef"
            .parse::<SpanId>()
            .is_err());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!("zz23456789abcdef0123456789abcdef".parse::<TraceId>().is_err());
        assert!("zzzzzzzzzzzzzzzz".parse::<SpanId>().is_err());
    }

    #[test]
    fn known_bytes_render_expected_hex() {
        let trace = TraceId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        assert_eq!(trace.to_hex(), "00112233445566778899aabbccddeeff");
        let span = SpanId::from_bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(span.to_hex(), "deadbeef00000001");
    }

    #[test]
    fn serde_roundtrip_is_the_hex_string() {
        let id = TraceId::new();
        let json = serde_json::to_string(&id).unwrap();
        // Should be a quoted hex string, not an array of bytes.
        assert_eq!(json, format!("\"{}\"", id.to_hex()));
        let back: TraceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
