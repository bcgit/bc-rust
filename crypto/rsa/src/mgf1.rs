//! MGF1 (RFC 8017 Appendix B.2.1): a mask generation function based on a hash function, used by
//! [`crate::emsa_pss`]. Specialized to PSS's own call shape (`MGF(H, maskLen)`, where `H` is
//! always the hash's own `hLen`-byte output) rather than MGF1's fully general arbitrary-length
//! seed: `mgfSeed` here is always exactly `H_LEN` bytes.

use bouncycastle_core::traits::{HashAlgParams, HashOneShot};
use bouncycastle_utils::secret::Secret;

/// MGF1 (RFC 8017 Appendix B.2.1), with `mgfSeed` fixed at `H_LEN` bytes and `maskLen` fixed at
/// `MASK_LEN` (a compile-time constant here, since every call site in this crate knows its output
/// width in advance -- `emLen - hLen - 1` for a concrete modulus/hash pairing). Step 1's error
/// ("mask too long", `maskLen > 2^32 hLen`) cannot occur for any `MASK_LEN` this crate reaches
/// (at most a few KiB, for an 8192-bit modulus), so it is not checked. `SEED_LEN` is `H_LEN + 4`
/// (the seed plus the 4-octet counter `C`), a separate const parameter for the same reason
/// [`bouncycastle_ec::montgomery`]'s `L2 = 2 * L` is: stable Rust cannot compute one const
/// generic from another.
/// The largest hash output MGF1 is used with here, SHA-512's.
pub(crate) const MAX_HASH_LEN: usize = 64;

/// MGF1 over `H` (RFC 8017 Appendix B.2.1): `mask` filled with `Hash(seed || C)` for the
/// counter `C` from 0, four big-endian bytes each, the last block truncated. `seed` is a hash
/// output here (`H::OUTPUT_LEN` bytes, EMSA-PSS's `H`).
pub fn mgf1<H: HashOneShot + HashAlgParams>(seed: &[u8], mask: &mut [u8]) {
    debug_assert!(seed.len() + 4 <= MAX_HASH_LEN + 4, "mgf1: seed longer than a hash output");
    let h_len = H::OUTPUT_LEN;
    let mut input = [0u8; MAX_HASH_LEN + 4];
    input[..seed.len()].copy_from_slice(seed);
    let mut block = [0u8; MAX_HASH_LEN];
    let mut offset = 0;
    let mut counter: u32 = 0;
    while offset < mask.len() {
        input[seed.len()..seed.len() + 4].copy_from_slice(&counter.to_be_bytes());
        H::hash_out(&input[..seed.len() + 4], &mut block[..h_len]);
        let take = core::cmp::min(h_len, mask.len() - offset);
        mask[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter += 1;
    }
}

/// MGF1 over `M` with a seed of any length, XORed into `target` (`target = target xor
/// MGF(seed, target.len())`), which is how EME-OAEP uses both of its masks (RFC 8017 §7.1.1
/// steps 2.e to 2.h): one of its seeds is `maskedDB`, most of a modulus long, which [`mgf1`]'s
/// fixed input buffer does not hold. The hash block is in a `Secret`, wiped on return, and
/// nothing here branches on the seed or the mask.
pub(crate) fn mgf1_xor<M: HashOneShot + HashAlgParams>(seed: &[u8], target: &mut [u8]) {
    let h_len = M::OUTPUT_LEN;
    let mut block = Secret::<[u8; MAX_HASH_LEN]>::new();
    // "For counter from 0 to ceil(maskLen / hLen) - 1": C = I2OSP(counter, 4),
    // T = T || Hash(mgfSeed || C). Each chunk of the target takes one block of T.
    for (counter, chunk) in target.chunks_mut(h_len).enumerate() {
        let mut hash = M::default();
        hash.do_update(seed);
        hash.do_update(&(counter as u32).to_be_bytes());
        hash.do_final_out(&mut block[..h_len]);
        for (t, m) in chunk.iter_mut().zip(block.iter()) {
            *t ^= m;
        }
    }
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

    const LONG_SEED_MASK: [u8; 40] = [
        0x21, 0x6a, 0xa5, 0xdf, 0x88, 0xa3, 0xda, 0x51, 0x8c, 0x77, 0x98, 0x7f, 0x93, 0xb1, 0xf8,
        0x71, 0x9f, 0xda, 0xb1, 0x64, 0x12, 0x57, 0x29, 0x86, 0x4b, 0xa8, 0x8b, 0x80, 0xc3, 0xa7,
        0x70, 0x84, 0x2b, 0xe7, 0xb5, 0x93, 0x92, 0x67, 0x71, 0x7c,
    ];

    /// `MASK_LEN = 223`: the exact `DB_LEN` RSA-2048/SHA-256 PSS uses (`K_LEN - H_LEN - 1 = 256 -
    /// 32 - 1`), spanning seven full 32-byte hash blocks (`ceil(223/32) = 7`) plus a truncated one.
    #[test]
    fn mgf1_matches_python_for_pss_2048_sha256_mask_length() {
        let mut mask = [0u8; 223];
        mgf1::<SHA256>(&SEED, &mut mask);
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
        let mut mask = [0u8; 10];
        mgf1::<SHA256>(&SEED, &mut mask);
        let expected: [u8; 10] = [0x70, 0xf4, 0x00, 0x3d, 0x52, 0xb6, 0xeb, 0x03, 0xda, 0x85];
        assert_eq!(mask, expected);
        // Must agree with the longer mask's own prefix -- MGF1 is a genuine stream, not
        // recomputed independently per length.
        let mut longer = [0u8; 223];
        mgf1::<SHA256>(&SEED, &mut longer);
        assert_eq!(mask, longer[..10]);
    }

    /// `MASK_LEN = 70`, spanning three counter blocks (`ceil(70/32) = 3`) with truncation of the
    /// last.
    #[test]
    fn mgf1_spans_multiple_counter_blocks() {
        let mut mask = [0u8; 70];
        mgf1::<SHA256>(&SEED, &mut mask);
        let mut longer = [0u8; 223];
        mgf1::<SHA256>(&SEED, &mut longer);
        assert_eq!(mask, longer[..70]);
    }

    /// `mgf1_xor` into zeros is the mask itself, and XORs into what is there.
    #[test]
    fn mgf1_xor_is_mgf1_xored_into_the_target() {
        let mut mask = [0u8; 223];
        mgf1::<SHA256>(&SEED, &mut mask);
        let mut target = [0u8; 223];
        mgf1_xor::<SHA256>(&SEED, &mut target);
        assert_eq!(target, mask);
        let mut target = [0xA5u8; 223];
        mgf1_xor::<SHA256>(&SEED, &mut target);
        assert!(target.iter().zip(mask).all(|(t, m)| *t == 0xA5 ^ m));
    }

    /// A seed longer than a hash output, as EME-OAEP's `maskedDB` is. The expected value was
    /// computed with a direct Python transliteration of RFC 8017 Appendix B.2.1 using
    /// `hashlib.sha256`, over the seed 0x00, 0x01, ..., 0xDE (223 bytes) and a 40-byte mask.
    #[test]
    fn mgf1_xor_takes_a_long_seed() {
        let seed: [u8; 223] = core::array::from_fn(|i| i as u8);
        let mut target = [0u8; 40];
        mgf1_xor::<SHA256>(&seed, &mut target);
        assert_eq!(target, LONG_SEED_MASK);
    }
}
