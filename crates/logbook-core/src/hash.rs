//! Dependency-free FNV-1a 128-bit hashing.
//!
//! This is a tiny, non-cryptographic hash used by the deterministic id
//! derivations on the import path (and anywhere else a stable, well-specified
//! content hash is wanted). It is **not** a security primitive: FNV makes no
//! collision-resistance promises against an adversary, so it must never gate a
//! trust boundary. It is chosen here purely for being deterministic, fast, and
//! dependency-free — re-importing an unchanged store must reproduce
//! byte-identical ids, and FNV-1a's behaviour is fully pinned by its published
//! constants and test vectors.
//!
//! The algorithm (FNV-1a, 128-bit) is: start from the offset basis, then for
//! each input byte XOR it in **before** multiplying by the prime, all over a
//! wrapping `u128`. The 16-byte digest is emitted **big-endian**.
//!
//! ```
//! use logbook_core::fnv1a_128;
//!
//! // The empty input hashes to the offset basis itself.
//! assert_eq!(fnv1a_128(b""), 0x6c62272e07bb014262b821756295c58d_u128.to_be_bytes());
//! // Distinct inputs hash to distinct digests.
//! assert_ne!(fnv1a_128(b"a"), fnv1a_128(b"b"));
//! ```

/// FNV-1a 128-bit offset basis (the published constant).
const OFFSET_BASIS: u128 = 0x6c62272e07bb014262b821756295c58d;

/// FNV-1a 128-bit prime (the published constant, `2^88 + 2^8 + 0x3B`).
const PRIME: u128 = 0x0000000001000000000000000000013B;

/// Compute the FNV-1a 128-bit hash of `bytes`, returned as 16 big-endian bytes.
///
/// Deterministic and dependency-free: the same input always yields the same
/// digest, on every platform and every run. This is what makes it suitable for
/// the import path's reproducible id derivation (re-importing an unchanged store
/// must reproduce byte-identical ids).
///
/// Non-cryptographic — see the [module docs](self). Do not use it where
/// collision resistance against an adversary matters.
#[must_use]
pub fn fnv1a_128(bytes: &[u8]) -> [u8; 16] {
    let mut h = OFFSET_BASIS;
    for &b in bytes {
        h ^= u128::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_the_offset_basis() {
        // FNV-1a of the empty string is, by definition, the offset basis.
        assert_eq!(fnv1a_128(b""), OFFSET_BASIS.to_be_bytes());
    }

    #[test]
    fn canonical_vector_a() {
        // Canonical FNV-1a-128 test vector for the single byte "a".
        assert_eq!(
            fnv1a_128(b"a"),
            [
                0xd2, 0x28, 0xcb, 0x69, 0x6f, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a,
                0x89, 0x64,
            ]
        );
    }

    #[test]
    fn canonical_vector_foobar() {
        // Canonical FNV-1a-128 test vector for "foobar".
        assert_eq!(
            fnv1a_128(b"foobar"),
            [
                0x34, 0x3e, 0x16, 0x62, 0x79, 0x3c, 0x64, 0xbf, 0x6f, 0x0d, 0x35, 0x97, 0xba, 0x44,
                0x6f, 0x18,
            ]
        );
    }

    #[test]
    fn is_deterministic() {
        // The same input hashes identically every time.
        let a = fnv1a_128(b"logbook-import/cursor");
        let b = fnv1a_128(b"logbook-import/cursor");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_differ() {
        assert_ne!(fnv1a_128(b"a"), fnv1a_128(b"b"));
        assert_ne!(fnv1a_128(b"foo"), fnv1a_128(b"foobar"));
        // A trailing NUL is a different input from no NUL (matters for the
        // domain-separated id derivations that interleave `\0` separators).
        assert_ne!(fnv1a_128(b"foo"), fnv1a_128(b"foo\0"));
    }
}
