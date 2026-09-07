//! The integer and string encodings of NIST SP 800-185 Sec 2.3.
//!
//! These are shared by every SHA-3-derived function in the Recommendation: cSHAKE uses
//! `encode_string` and `bytepad` to bind its function-name and customization strings, and KMAC and
//! TupleHash add `right_encode` to bind the key and the requested output length.
//!
//! Lengths in the Recommendation are counted in **bits**, while this crate's API is byte-oriented,
//! so callers pass byte counts and the helpers multiply where the spec says `len(S)`.

/// The widest encoding these functions produce: a length byte plus up to eight value bytes.
///
/// SP 800-185 Sec 2.3.1 permits integers up to `2^2040 - 1`, which would need 255 value bytes. A
/// `u64` covers every length this library can be handed -- an input of `2^64` bits is 2 exabytes --
/// so the buffer is sized for that rather than for the spec's theoretical maximum.
pub(crate) const MAX_ENCODED_LEN: usize = 9;

/// `left_encode(x)`: SP 800-185 Sec 2.3.1.
///
/// Encodes `value` so that it can be parsed unambiguously *from the beginning*: the number of
/// value bytes comes first, then the value itself, big-endian. Returns the buffer and how much of
/// it is used.
///
/// The spec's example: `left_encode(0)` is `10000000 00000000`, which in this document's
/// low-order-bit-first notation is the bytes `01 00`.
pub(crate) fn left_encode(value: u64) -> ([u8; MAX_ENCODED_LEN], usize) {
    let mut buf = [0u8; MAX_ENCODED_LEN];
    // Step 1: n is the smallest positive integer with 2^(8n) > value. Zero still takes one byte,
    // which is why the count starts at 1 rather than 0.
    let n = value_bytes(value);
    buf[0] = n as u8;
    // Steps 2-4: the base-256 digits of value, most significant first.
    for i in 0..n {
        buf[1 + i] = (value >> (8 * (n - 1 - i))) as u8;
    }
    (buf, n + 1)
}

/// `right_encode(x)`: SP 800-185 Sec 2.3.1.
///
/// Unused until KMAC and TupleHash land, which bind the requested output length with it.
///
/// As [`left_encode`], but the length byte comes *last*, so the encoding can be parsed from the end
/// of a string. The spec's example: `right_encode(0)` is the bytes `00 01`.
#[allow(dead_code)] // used by KMAC and TupleHash
pub(crate) fn right_encode(value: u64) -> ([u8; MAX_ENCODED_LEN], usize) {
    let mut buf = [0u8; MAX_ENCODED_LEN];
    let n = value_bytes(value);
    for i in 0..n {
        buf[i] = (value >> (8 * (n - 1 - i))) as u8;
    }
    buf[n] = n as u8;
    (buf, n + 1)
}

/// The number of base-256 digits in `value`: the spec's `n`, the smallest positive integer with
/// `2^(8n) > value`. Positive, so zero encodes as one byte.
fn value_bytes(value: u64) -> usize {
    let mut n = 1;
    let mut v = value;
    while {
        v >>= 8;
        v != 0
    } {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two worked examples in SP 800-185 Sec 2.3.1, in the byte spelling of Sec 2
    /// ("bytes are written with the low-order bit first" in binary, high-order digit first in hex).
    #[test]
    fn spec_examples() {
        let (b, n) = right_encode(0);
        assert_eq!(&b[..n], &[0x00, 0x01], "right_encode(0) = 00000000 10000000");

        let (b, n) = left_encode(0);
        assert_eq!(&b[..n], &[0x01, 0x00], "left_encode(0) = 10000000 00000000");
    }

    /// The encodings that appear in the NIST cSHAKE sample file: `left_encode(168)` opens the
    /// bytepad block, and `left_encode(120)` prefixes the 15-character "Email Signature".
    #[test]
    fn cshake_sample_encodings() {
        let (b, n) = left_encode(168);
        assert_eq!(&b[..n], &[0x01, 0xA8], "left_encode(168), the cSHAKE128 rate");

        let (b, n) = left_encode(120);
        assert_eq!(&b[..n], &[0x01, 0x78], "left_encode(15 * 8), for \"Email Signature\"");
    }

    /// The length byte grows with the value, and the value is big-endian after it.
    #[test]
    fn multi_byte_values() {
        let (b, n) = left_encode(0x0100);
        assert_eq!(&b[..n], &[0x02, 0x01, 0x00]);
        let (b, n) = right_encode(0x0100);
        assert_eq!(&b[..n], &[0x01, 0x00, 0x02]);

        let (b, n) = left_encode(u64::MAX);
        assert_eq!(&b[..n], &[0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let (b, n) = right_encode(u64::MAX);
        assert_eq!(&b[..n], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x08]);
    }

    /// Every boundary where the number of value bytes increases.
    #[test]
    fn byte_count_boundaries() {
        for n in 1..=8u32 {
            let just_under = if n == 8 { u64::MAX } else { (1u64 << (8 * n)) - 1 };
            assert_eq!(left_encode(just_under).1, n as usize + 1, "2^{} - 1", 8 * n);
            assert_eq!(right_encode(just_under).1, n as usize + 1, "2^{} - 1", 8 * n);
            if n < 8 {
                assert_eq!(left_encode(1u64 << (8 * n)).1, n as usize + 2, "2^{}", 8 * n);
            }
        }
    }
}
