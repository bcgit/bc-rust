//! MGF1 (RFC 8017 Appendix B.2.1): a mask generation function based on a hash function, used by
//! [`crate::emsa_pss`]. Specialized to PSS's own call shape (`MGF(H, maskLen)`, where `H` is
//! always the hash's own `hLen`-byte output) rather than MGF1's fully general arbitrary-length
//! seed: `mgfSeed` here is always exactly `H_LEN` bytes.

use bouncycastle_core::traits::Hash;

/// MGF1 (RFC 8017 Appendix B.2.1), with `mgfSeed` fixed at `H_LEN` bytes and `maskLen` fixed at
/// `MASK_LEN` (a compile-time constant here, since every call site in this crate knows its output
/// width in advance -- `emLen - hLen - 1` for a concrete modulus/hash pairing). Step 1's error
/// ("mask too long", `maskLen > 2^32 hLen`) cannot occur for any `MASK_LEN` this crate reaches
/// (at most a few KiB, for an 8192-bit modulus), so it is not checked. `SEED_LEN` is `H_LEN + 4`
/// (the seed plus the 4-octet counter `C`), a separate const parameter for the same reason
/// [`bouncycastle_ec::montgomery`]'s `L2 = 2 * L` is: stable Rust cannot compute one const
/// generic from another.
pub fn mgf1<H: Hash + Default, const H_LEN: usize, const SEED_LEN: usize, const MASK_LEN: usize>(
    seed: &[u8; H_LEN],
) -> [u8; MASK_LEN] {
    debug_assert_eq!(SEED_LEN, H_LEN + 4, "mgf1 needs SEED_LEN == H_LEN + 4");

    let mut mask = [0u8; MASK_LEN];
    let mut offset = 0;
    let mut counter: u32 = 0;
    while offset < MASK_LEN {
        let mut input = [0u8; SEED_LEN];
        input[..H_LEN].copy_from_slice(seed);
        input[H_LEN..].copy_from_slice(&counter.to_be_bytes());

        let mut block = [0u8; H_LEN];
        H::default().hash_out(&input, &mut block);

        let take = core::cmp::min(H_LEN, MASK_LEN - offset);
        mask[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter += 1;
    }
    mask
}

#[cfg(test)]
mod tests {
    //! `mgf1` is crate-private (only [`crate::emsa_pss`] needs it), so it is exercised here
    //! rather than from `tests/` -- the same "high-risk code that cannot be reached through the
    //! public API" exception `rsa_core`'s tests use. Every expected value below was computed with
    //! a direct Python transliteration of RFC 8017 Appendix B.2.1's own steps (not from recall),
    //! using `hashlib.sha256`.

    use super::*;
    use bouncycastle_sha2::SHA256;

    const SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// `MASK_LEN = 223`: the exact `DB_LEN` RSA-2048/SHA-256 PSS uses (`K_LEN - H_LEN - 1 = 256 -
    /// 32 - 1`), spanning seven full 32-byte hash blocks (`ceil(223/32) = 7`) plus a truncated one.
    #[test]
    fn mgf1_matches_python_for_pss_2048_sha256_mask_length() {
        let mask: [u8; 223] = mgf1::<SHA256, 32, 36, 223>(&SEED);
        let expected_prefix: [u8; 16] = [
            0x70, 0xf4, 0x00, 0x3d, 0x52, 0xb6, 0xeb, 0x03, 0xda, 0x85, 0x2e, 0x93, 0x25, 0x6b,
            0x59, 0x86,
        ];
        assert_eq!(&mask[..16], &expected_prefix);
        let expected_suffix: [u8; 8] = [0xff, 0x1f, 0x1e, 0x99, 0x50, 0x22, 0x99, 0x60];
        assert_eq!(&mask[215..223], expected_suffix);
    }

    /// `MASK_LEN = 10`, shorter than one hash block: exercises truncation of the very first block.
    #[test]
    fn mgf1_truncates_within_the_first_block() {
        let mask: [u8; 10] = mgf1::<SHA256, 32, 36, 10>(&SEED);
        let expected: [u8; 10] = [0x70, 0xf4, 0x00, 0x3d, 0x52, 0xb6, 0xeb, 0x03, 0xda, 0x85];
        assert_eq!(mask, expected);
        // Must agree with the longer mask's own prefix -- MGF1 is a genuine stream, not
        // recomputed independently per length.
        let longer: [u8; 223] = mgf1::<SHA256, 32, 36, 223>(&SEED);
        assert_eq!(mask, longer[..10]);
    }

    /// `MASK_LEN = 70`, spanning three counter blocks (`ceil(70/32) = 3`) with truncation of the
    /// last.
    #[test]
    fn mgf1_spans_multiple_counter_blocks() {
        let mask: [u8; 70] = mgf1::<SHA256, 32, 36, 70>(&SEED);
        let longer: [u8; 223] = mgf1::<SHA256, 32, 36, 223>(&SEED);
        assert_eq!(mask, longer[..70]);
    }
}
