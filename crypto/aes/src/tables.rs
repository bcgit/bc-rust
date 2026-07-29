//! The AES substitution tables and key expansion round constants.
//!
//! * [`SBOX`] is FIPS 197 Table 4, used by SUBBYTES() (Section 5.1.1) and SUBWORD() (Eq 5.11).
//! * [`INVSBOX`] is FIPS 197 Table 6, used by INVSUBBYTES() (Section 5.3.2).
//! * [`RCON`] is FIPS 197 Table 5, used by KEYEXPANSION() (Section 5.2).
//!
//! # Why tables and not computed values?
//!
//! The S-box is mathematically defined (FIPS 197 Eq 5.2 and 5.3) as the multiplicative inverse in
//! GF(2^8) followed by an affine transformation. Computing that per byte would cost roughly 250
//! field multiplications, which is far too slow for a block cipher, so -- like every practical
//! implementation, and like the tabulated form the standard itself provides -- we store the 256
//! precomputed values.
//!
//! The unit tests at the bottom of this file re-derive the whole table from Eq (5.2) and (5.3) and
//! compare it against the stored bytes, so a transcription error in the table cannot survive
//! `cargo test`.
//!
//! # 🚨 Security 🚨
//!
//! Indexing a 256-byte table with a secret byte is not a constant-time operation on a CPU with a
//! data cache: which cache lines get touched depends on the value of the index. This is the
//! cache-timing exposure that FIPS 197 Section 6.4 calls out, and it is inherent to any
//! table-driven AES. See the crate-level "Security Considerations" docs for what this means in
//! practice and what the alternatives are.
//!
//! Note that we deliberately use only the 256-byte S-box, and *not* the common 4 KiB "T-tables"
//! that fold MIXCOLUMNS() into the substitution step. T-tables are faster but spread each lookup
//! over far more cache lines, which measurably widens exactly this side channel.

/// FIPS 197 Table 4: `SBOX()` substitution values for the byte `xy` in hexadecimal.
///
/// Indexed as `SBOX[0xXY]`, ie the table is stored row-major with `x` as the high nibble of the
/// index and `y` as the low nibble. The 16 rows below are therefore `x = 0x0 ..= 0xf` and the 16
/// columns are `y = 0x0 ..= 0xf`, so this reads exactly like Table 4 -- which is the point, and why
/// the grid is held to `rustfmt`'s `skip`: a reviewer has to be able to compare it against the
/// printed standard row by row.
#[rustfmt::skip]
pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// FIPS 197 Table 6: `INVSBOX()` substitution values for the byte `xy` in hexadecimal.
///
/// This is [`SBOX`] with the roles of input and output exchanged, laid out and indexed the same
/// way: 16 rows of `x = 0x0 ..= 0xf`, 16 columns of `y = 0x0 ..= 0xf`.
#[rustfmt::skip]
pub(crate) const INVSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// FIPS 197 Table 5: the round constants `Rcon[j]` for 1 <= j <= 10.
///
/// The spec indexes these from 1, so `Rcon[j]` is `RCON[j - 1]` here; [`crate::key_schedule`] is
/// the only caller and does that adjustment at the single point of use.
///
/// Each round constant is the word `[x^(j-1), {00}, {00}, {00}]`, held here as a big-endian `u32`
/// so it can be XOR-ed straight into a key schedule word. The leftmost byte therefore runs
/// {01}, {02}, {04} ... doubling in GF(2^8) each step, which is why the ninth and tenth entries
/// are {1b} and {36} rather than {100} and {200}.
pub(crate) const RCON: [u32; 10] = [
    0x0100_0000, // j=1  -> x^0 = {01}
    0x0200_0000, // j=2  -> x^1 = {02}
    0x0400_0000, // j=3  -> x^2 = {04}
    0x0800_0000, // j=4  -> x^3 = {08}
    0x1000_0000, // j=5  -> x^4 = {10}
    0x2000_0000, // j=6  -> x^5 = {20}
    0x4000_0000, // j=7  -> x^6 = {40}
    0x8000_0000, // j=8  -> x^7 = {80}
    0x1b00_0000, // j=9  -> x^8 = {1b} (x^8 reduced mod m(x))
    0x3600_0000, // j=10 -> x^9 = {36}
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf::{gf_mul, gf_pow, xtimes};

    /// Re-derives one S-box entry from its mathematical definition, FIPS 197 Section 5.1.1.
    fn sbox_from_definition(b: u8) -> u8 {
        // Step 1, Eq (5.2): b~ = {00} if b == {00}, otherwise the multiplicative inverse of b.
        // Eq (4.11) gives that inverse as b^254.
        let b_tilde = if b == 0x00 { 0x00 } else { gf_pow(b, 254) };

        // Step 2, Eq (5.3): b'_i = b~_i XOR b~_(i+4 mod 8) XOR b~_(i+5 mod 8)
        //                          XOR b~_(i+6 mod 8) XOR b~_(i+7 mod 8) XOR c_i
        // where c is the constant byte {01100011} = {63}.
        const C: u8 = 0x63;
        let bit = |value: u8, i: u32| (value >> (i % 8)) & 1;

        let mut result = 0u8;
        for i in 0..8u32 {
            let b_prime_i = bit(b_tilde, i)
                ^ bit(b_tilde, i + 4)
                ^ bit(b_tilde, i + 5)
                ^ bit(b_tilde, i + 6)
                ^ bit(b_tilde, i + 7)
                ^ bit(C, i);
            result |= b_prime_i << i;
        }
        result
    }

    /// Every entry of the stored [`SBOX`] must equal the value that FIPS 197 Eq (5.2) and (5.3)
    /// define, which makes a typo in the transcribed Table 4 impossible to miss.
    #[test]
    fn sbox_matches_its_mathematical_definition() {
        for b in 0..=u8::MAX {
            assert_eq!(SBOX[b as usize], sbox_from_definition(b), "SBOX[{b:#04x}]");
        }
    }

    /// Two spot checks straight out of the prose of FIPS 197.
    #[test]
    fn sbox_matches_documented_examples() {
        // Section 5.1.1: "if s_rc = {53} ... so that s'_rc = {ed}".
        assert_eq!(SBOX[0x53], 0xed);
        // Section 5.1.1: SBOX({00}) is the affine transform of {00}, ie the constant {63}.
        assert_eq!(SBOX[0x00], 0x63);
    }

    /// [`INVSBOX`] must be the exact inverse permutation of [`SBOX`] (Section 5.3.2), in both
    /// directions. Checking both directions also proves each table is a bijection.
    #[test]
    fn invsbox_inverts_sbox() {
        for b in 0..=u8::MAX {
            assert_eq!(INVSBOX[SBOX[b as usize] as usize], b, "INVSBOX(SBOX({b:#04x}))");
            assert_eq!(SBOX[INVSBOX[b as usize] as usize], b, "SBOX(INVSBOX({b:#04x}))");
        }
    }

    /// The S-box has no fixed points (SBOX(b) != b) and no "opposite" fixed points
    /// (SBOX(b) != !b). These are design properties of Rijndael's affine constant, so they are a
    /// cheap independent sanity check on the table.
    #[test]
    fn sbox_has_no_fixed_points() {
        for b in 0..=u8::MAX {
            assert_ne!(SBOX[b as usize], b, "SBOX has a fixed point at {b:#04x}");
            assert_ne!(SBOX[b as usize], !b, "SBOX has an opposite fixed point at {b:#04x}");
        }
    }

    /// FIPS 197 Section 5.2: "the value of the left-most byte of Rcon[j] in polynomial form is
    /// x^(j-1) ... these bytes may be generated by successively applying xTimes()".
    #[test]
    fn rcon_leftmost_bytes_are_successive_powers_of_x() {
        let mut power_of_x = 0x01u8; // x^0
        for (index, rcon) in RCON.iter().enumerate() {
            let expected = u32::from_be_bytes([power_of_x, 0x00, 0x00, 0x00]);
            assert_eq!(*rcon, expected, "RCON[{index}] (ie Rcon[{}])", index + 1);
            power_of_x = xtimes(power_of_x);
        }
    }

    /// Cross-check of the same property using the general field multiplication: Rcon[j] is
    /// {02}^(j-1).
    #[test]
    fn rcon_leftmost_bytes_are_powers_of_two_in_the_field() {
        for (index, rcon) in RCON.iter().enumerate() {
            let expected_byte = gf_pow(0x02, index as u32);
            assert_eq!((*rcon >> 24) as u8, expected_byte, "RCON[{index}]");
            // The other three bytes of every round constant are zero.
            assert_eq!(*rcon & 0x00ff_ffff, 0, "RCON[{index}] low bytes");
        }
    }

    /// {1b} and {36} are the reduced forms of x^8 and x^9, per Eq (4.3)'s modulus. Pinning this
    /// separately documents why the doubling sequence "wraps" where it does.
    #[test]
    fn rcon_wrap_values_are_reduced_powers() {
        assert_eq!(gf_mul(0x80, 0x02), 0x1b); // x^7 * x = x^8 = {1b} mod m(x)
        assert_eq!(gf_mul(0x1b, 0x02), 0x36); // x^8 * x = x^9 = {36} mod m(x)
    }
}
