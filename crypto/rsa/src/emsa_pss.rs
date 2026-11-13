//! EMSA-PSS (RFC 8017 §9.1): probabilistic signature encoding, once over the hash `H` and the
//! parameters `P` ([`PssParams`]): the mask generation function (MGF1 over a hash, or a SHAKE
//! used natively per RFC 8702 §3.2.1, "the SHAKEs MUST be used natively as the MGF, instead of
//! the MGF1 algorithm") and the salt length.
//!
//! # The `8 * K_LEN - emBits == 1` simplification
//!
//! RFC 8017 encodes into `emLen = ceil(emBits / 8)` octets, where `emBits = modBits - 1`, and
//! steps 11/9 clear the leftmost `8 * emLen - emBits` bits of the encoded message's first octet
//! so that `OS2IP(EM) < 2^emBits <= n`. Every modulus size this crate offers is a whole number of
//! 64-bit limbs, so `modBits` (and therefore `emLen = K_LEN`) is always a multiple of 8; that
//! makes `8 * K_LEN - emBits = 8 * K_LEN - (8 * K_LEN - 1) = 1` for every concrete instantiation
//! here, so this module hard-codes "clear the top bit of the first octet" instead of threading a
//! generic bit-count parameter through for a case that cannot arise.

use crate::mgf1::MAX_HASH_LEN;
use crate::rsassa_pss::PssParams;
use bouncycastle_core::traits::{HashAlgParams, HashOneShot};

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) from step 3 onward, with `emBits` fixed to `8 * K_LEN - 1`
/// (see the module docs), steps 1-2's `mHash = Hash(M)` supplied by the caller (either
/// [`crate::rsassa_pss`] hashing a whole message in one call, or a streaming `Signer` that hashed
/// it incrementally -- this function itself never sees the message), and the salt supplied
/// rather than generated here -- [`crate::rsassa_pss`] draws it from an RNG; this function stays
/// deterministic so it can be tested directly against a known salt. Step 3's error ("encoding
/// error", `emLen < hLen + sLen + 2`) is a `debug_assert`, since every (hash, modulus size)
/// pairing this crate wires up has a modulus far wider than any hash-plus-salt combination it
/// offers.
/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) from the message hash `m_hash` (step 2's `mHash`,
/// `H::OUTPUT_LEN` bytes) and the salt (`sLen = P::SALT_LEN` bytes), with `P`'s mask, into the
/// `K_LEN`-byte `EM`. The lengths every other width derives from are `K_LEN` and the hash's:
/// `DB` is `K_LEN - hLen - 1` bytes, `M'` is `8 + hLen + sLen`.
pub fn emsa_pss_encode_from_hash<H, P, const K_LEN: usize>(
    m_hash: &[u8],
    salt: &[u8],
) -> [u8; K_LEN]
where
    H: HashOneShot + HashAlgParams,
    P: PssParams<H>,
{
    let h_len = H::OUTPUT_LEN;
    let s_len = P::SALT_LEN;
    debug_assert_eq!(m_hash.len(), h_len, "emsa_pss_encode: mHash is one hash output");
    debug_assert_eq!(salt.len(), s_len, "emsa_pss_encode: the salt is the parameters' length");
    debug_assert!(
        K_LEN >= h_len + s_len + 2,
        "emsa_pss_encode: modulus too short for this hash/salt"
    );
    let db_len = K_LEN - h_len - 1;

    // Steps 5-6: M' = 8 zero octets || mHash || salt; H = Hash(M').
    let mut m_prime = [0u8; 8 + 2 * MAX_HASH_LEN];
    m_prime[8..8 + h_len].copy_from_slice(m_hash);
    m_prime[8 + h_len..8 + h_len + s_len].copy_from_slice(salt);
    let mut h = [0u8; MAX_HASH_LEN];
    H::hash_out(&m_prime[..8 + h_len + s_len], &mut h[..h_len]);

    // Steps 7-8: DB = PS || 0x01 || salt (PS is all-zero, already the buffer's initial value).
    let mut db = [0u8; K_LEN];
    db[db_len - s_len - 1] = 0x01;
    db[db_len - s_len..db_len].copy_from_slice(salt);

    // Steps 9-11: maskedDB = DB xor MGF(H, DB_LEN), the parameters' mask, then clear the top
    // bit (see module docs).
    let mut db_mask = [0u8; K_LEN];
    P::mask(&h[..h_len], &mut db_mask[..db_len]);
    let mut em = [0u8; K_LEN];
    for i in 0..db_len {
        em[i] = db[i] ^ db_mask[i];
    }
    em[0] &= 0x7f;

    // Step 12: EM = maskedDB || H || 0xbc.
    em[db_len..db_len + h_len].copy_from_slice(&h[..h_len]);
    em[K_LEN - 1] = 0xbc;
    em
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) of the `K_LEN`-byte `em` against the message hash
/// `m_hash` (step 2's `mHash`), with `sLen = P::SALT_LEN` and `P`'s mask.
pub fn emsa_pss_verify_from_hash<H, P, const K_LEN: usize>(m_hash: &[u8], em: &[u8; K_LEN]) -> bool
where
    H: HashOneShot + HashAlgParams,
    P: PssParams<H>,
{
    let h_len = H::OUTPUT_LEN;
    let s_len = P::SALT_LEN;
    debug_assert_eq!(m_hash.len(), h_len, "emsa_pss_verify: mHash is one hash output");
    // Step 3: emLen < hLen + sLen + 2 is "inconsistent"; a constant of the pairing.
    if K_LEN < h_len + s_len + 2 {
        return false;
    }
    let db_len = K_LEN - h_len - 1;

    // Step 4.
    if em[K_LEN - 1] != 0xbc {
        return false;
    }
    // Step 6 (checked directly on `em[0]`, which is maskedDB's own leftmost octet).
    if em[0] & 0x80 != 0 {
        return false;
    }
    // Step 5.
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + h_len];

    // Steps 7-9.
    let mut db = [0u8; K_LEN];
    P::mask(h, &mut db[..db_len]);
    for i in 0..db_len {
        db[i] ^= masked_db[i];
    }
    db[0] &= 0x7f;

    // Step 10.
    let ps_len = db_len - s_len - 1;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return false;
    }
    // Step 11.
    let salt = &db[db_len - s_len..db_len];

    // Steps 12-14 (step 2's mHash is the caller's `m_hash`).
    let mut m_prime = [0u8; 8 + 2 * MAX_HASH_LEN];
    m_prime[8..8 + h_len].copy_from_slice(m_hash);
    m_prime[8 + h_len..8 + h_len + s_len].copy_from_slice(salt);
    let mut h_prime = [0u8; MAX_HASH_LEN];
    H::hash_out(&m_prime[..8 + h_len + s_len], &mut h_prime[..h_len]);
    h == &h_prime[..h_len]
}

#[cfg(test)]
mod tests {
    //! `emsa_pss_encode_from_hash`/`emsa_pss_verify_from_hash` are crate-private (only
    //! [`crate::rsassa_pss`] needs them), so they are exercised here rather than from `tests/` --
    //! the same "high-risk code that cannot be reached through the public API" exception
    //! `rsa_core`'s tests use. The KAT is a direct Python transliteration of RFC 8017 SS9.1.1's
    //! own steps (not from recall), reusing this crate's own `mgf1` reference values (`mgf1.rs`'s
    //! own tests) for the mask. The `encode`/`verify` helpers below add step 2's `mHash = Hash(M)`
    //! back on top, so the tests can speak in terms of messages.

    use super::*;
    use crate::rsassa_pss::Conventional;
    use bouncycastle_sha2::SHA256;
    use bouncycastle_sha3::SHAKE128;

    const SALT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const EXPECTED_EM: [u8; 256] = [
        0x62, 0x2c, 0x85, 0xcc, 0xb1, 0xe5, 0x9b, 0xb7, 0x46, 0x99, 0x27, 0xba, 0xab, 0xa2, 0x37,
        0x72, 0xd6, 0x77, 0xe5, 0xd9, 0x2d, 0x4c, 0x40, 0xc8, 0x08, 0x2c, 0x00, 0xbc, 0xed, 0x77,
        0x17, 0x75, 0x34, 0x88, 0x46, 0xd1, 0x8a, 0xa9, 0x77, 0x6e, 0xd8, 0x4e, 0xa4, 0x9f, 0x07,
        0x23, 0xd6, 0x60, 0xc7, 0xa3, 0x86, 0x1f, 0x24, 0x6b, 0x3a, 0x79, 0xec, 0x72, 0x9f, 0x33,
        0x4f, 0x8a, 0x10, 0x03, 0xdc, 0x56, 0x35, 0x4e, 0xef, 0x23, 0x05, 0xd7, 0x4b, 0x52, 0xde,
        0x1e, 0x26, 0x74, 0xaf, 0x4e, 0xd1, 0xdf, 0xd5, 0x75, 0x17, 0x18, 0x23, 0x4b, 0xd8, 0x67,
        0xd3, 0xc7, 0x3e, 0x57, 0xc7, 0xf1, 0xf7, 0xae, 0xa6, 0xf6, 0xa7, 0xa4, 0xb1, 0x87, 0xc0,
        0xde, 0x14, 0xa8, 0x5b, 0x64, 0x7c, 0x69, 0xe1, 0x3c, 0x81, 0xc1, 0x09, 0x23, 0xd3, 0x24,
        0xad, 0xbb, 0x71, 0xe5, 0xdf, 0x09, 0x93, 0x21, 0x4c, 0x0f, 0x7d, 0x0d, 0x1d, 0x4f, 0x54,
        0x27, 0xd3, 0xb9, 0x6e, 0xb6, 0x7d, 0x43, 0x11, 0x1c, 0x62, 0xd7, 0xa3, 0x2e, 0xcf, 0x8c,
        0x83, 0x4b, 0x2d, 0xe0, 0xe2, 0x65, 0x1f, 0x91, 0x71, 0x67, 0x6c, 0xab, 0xbb, 0x0b, 0x62,
        0x11, 0xe0, 0x43, 0xf6, 0xe6, 0xe7, 0xcc, 0xf9, 0x41, 0x85, 0xb5, 0xc1, 0x76, 0x55, 0xd1,
        0xe6, 0xd2, 0x87, 0xc5, 0x2a, 0xcf, 0x83, 0x90, 0x42, 0x5a, 0xe2, 0xf7, 0x9b, 0xca, 0x09,
        0x2c, 0x3f, 0x2a, 0xb6, 0x1d, 0x59, 0xce, 0xe0, 0x3b, 0x94, 0x9e, 0x81, 0x6d, 0xed, 0x08,
        0x88, 0xc4, 0xc2, 0xa2, 0xab, 0x47, 0x3b, 0x48, 0x1d, 0xea, 0xc1, 0xe0, 0x43, 0x09, 0x46,
        0xab, 0x31, 0x4e, 0x5e, 0x81, 0x09, 0x3b, 0x00, 0xda, 0xe0, 0xc4, 0x35, 0x58, 0x4e, 0xb8,
        0xf6, 0xc7, 0xda, 0x8c, 0xf2, 0xba, 0xb0, 0xb1, 0x04, 0xff, 0x46, 0xbb, 0x51, 0x84, 0xa3,
        0xbc,
    ];

    fn m_hash(message: &[u8]) -> [u8; 32] {
        let mut m_hash = [0u8; 32];
        SHA256::hash_out(message, &mut m_hash);
        m_hash
    }

    fn encode(message: &[u8], salt: &[u8; 32]) -> [u8; 256] {
        emsa_pss_encode_from_hash::<SHA256, Conventional, 256>(&m_hash(message), salt)
    }

    fn verify(message: &[u8], em: &[u8; 256]) -> bool {
        emsa_pss_verify_from_hash::<SHA256, Conventional, 256>(&m_hash(message), em)
    }

    #[test]
    fn encode_matches_python_kat() {
        assert_eq!(encode(b"hello", &SALT), EXPECTED_EM);
    }

    #[test]
    fn verify_accepts_the_kat() {
        assert!(verify(b"hello", &EXPECTED_EM));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        assert!(!verify(b"goodbye", &EXPECTED_EM));
    }

    #[test]
    fn different_salts_give_different_but_both_valid_encodings() {
        let salt_b: [u8; 32] = {
            let mut s = SALT;
            s[0] ^= 0xff;
            s
        };
        let em_a = encode(b"hello", &SALT);
        let em_b = encode(b"hello", &salt_b);
        assert_ne!(em_a, em_b, "PSS is randomized: different salts must give different EM");
        assert!(verify(b"hello", &em_a));
        assert!(verify(b"hello", &em_b));
    }

    /// RFC 8017 SS9.1.2 step 4: the trailer byte must be `0xbc`.
    #[test]
    fn verify_rejects_wrong_trailer_byte() {
        let mut em = EXPECTED_EM;
        em[255] = 0xbd;
        assert!(!verify(b"hello", &em));
    }

    /// RFC 8017 SS9.1.2 step 6: the leftmost bit of `maskedDB`'s first octet must already be 0
    /// (see the module docs on why this crate always needs exactly one bit clear).
    #[test]
    fn verify_rejects_top_bit_set() {
        let mut em = EXPECTED_EM;
        em[0] |= 0x80;
        assert!(!verify(b"hello", &em));
    }

    /// RFC 8017 SS9.1.2 step 10: every byte of `PS` must be zero.
    #[test]
    fn verify_rejects_nonzero_padding() {
        let mut em = EXPECTED_EM;
        // Corrupt a byte inside the (unmasked) PS region by flipping the corresponding bit of the
        // masked byte directly -- em[0] is PS's first (masked) byte after the top-bit clear.
        em[0] ^= 0x40;
        assert!(!verify(b"hello", &em));
    }

    /// RFC 8017 SS9.1.2 step 10: the octet right before the salt must be exactly `0x01`.
    #[test]
    fn verify_rejects_wrong_separator_byte() {
        // The byte at DB position (DB_LEN - S_LEN - 1) = 223 - 32 - 1 = 190, masked. Flipping its
        // least-significant bit changes the unmasked separator from 0x01 to 0x00.
        let mut em = EXPECTED_EM;
        em[190] ^= 0x01;
        assert!(!verify(b"hello", &em));
    }

    mod shake {

        //! The SHAKE parameters: the KAT is a direct Python transliteration of RFC 8017
        //! SS9.1.1's own steps with RFC 8702 SS3.2.1's native-SHAKE mask substituted for MGF1 (not from
        //! recall), using `hashlib.shake_128`. The `encode`/`verify` helpers below add step 2's
        //! `mHash = Hash(M)` back on top, so the tests can speak in terms of messages.

        use super::*;

        const SALT: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        fn m_hash(message: &[u8]) -> [u8; 32] {
            let mut m_hash = [0u8; 32];
            SHAKE128::hash_out(message, &mut m_hash);
            m_hash
        }

        fn encode(message: &[u8], salt: &[u8; 32]) -> [u8; 256] {
            emsa_pss_encode_from_hash::<SHAKE128, Conventional, 256>(&m_hash(message), salt)
        }

        fn verify(message: &[u8], em: &[u8; 256]) -> bool {
            emsa_pss_verify_from_hash::<SHAKE128, Conventional, 256>(&m_hash(message), em)
        }

        #[test]
        fn encode_matches_python_kat() {
            // hashlib.shake_128, following EMSA-PSS-ENCODE (RFC 8017 SS9.1.1) with the SHAKE-native
            // mask of RFC 8702 SS3.2.1 substituted for MGF1 -- not from recall.
            let expected_em: [u8; 256] = [
                0x44, 0x7f, 0x52, 0xb3, 0xea, 0xb3, 0x57, 0x7d, 0xe7, 0x42, 0xb3, 0x95, 0xf6, 0x85,
                0xc1, 0x72, 0x43, 0xf1, 0xe1, 0x00, 0xca, 0x98, 0x51, 0x95, 0x9b, 0x49, 0x94, 0x8c,
                0x34, 0xe8, 0x80, 0x43, 0xb3, 0x7a, 0xe6, 0xf9, 0x58, 0x55, 0x1c, 0x24, 0x67, 0x2c,
                0x5c, 0x67, 0x89, 0xd6, 0x70, 0xd9, 0x01, 0x5c, 0x21, 0x06, 0xdf, 0xdf, 0x2c, 0x99,
                0x36, 0x25, 0xb7, 0x42, 0x0e, 0xcb, 0x9d, 0x06, 0xac, 0xe7, 0x28, 0x81, 0x01, 0xe3,
                0x37, 0xb0, 0x20, 0x84, 0x01, 0x39, 0x2a, 0x9b, 0x5c, 0xf7, 0x05, 0xef, 0x4c, 0xb2,
                0x41, 0xc6, 0x33, 0x88, 0x2f, 0x45, 0x8a, 0x70, 0xfc, 0xe2, 0xb9, 0xd1, 0xcb, 0x0a,
                0xe7, 0x8d, 0x94, 0xfa, 0x99, 0xf6, 0x28, 0xbc, 0x25, 0x38, 0x11, 0xc9, 0xfa, 0xfd,
                0xd0, 0x3e, 0x51, 0x0f, 0xc9, 0xd1, 0x1f, 0x2a, 0x21, 0x08, 0x26, 0xe8, 0xb3, 0x5a,
                0xc7, 0x08, 0xbf, 0xfe, 0xd9, 0x88, 0xde, 0xad, 0x26, 0xec, 0x86, 0x9c, 0x76, 0xb9,
                0x0e, 0xca, 0x0d, 0xfe, 0xad, 0x99, 0x16, 0x57, 0x45, 0x7f, 0x9f, 0x94, 0x4b, 0x8e,
                0x3f, 0xfb, 0xff, 0x11, 0x95, 0xf7, 0x70, 0x1b, 0x2c, 0xbc, 0xb4, 0xbd, 0x6c, 0x2f,
                0xe7, 0x10, 0xad, 0x21, 0xaa, 0xfc, 0x72, 0xfa, 0xd1, 0x79, 0x98, 0xcc, 0x1c, 0xfc,
                0x7c, 0x57, 0xca, 0xf9, 0x28, 0x54, 0xd5, 0xbf, 0x9c, 0x19, 0x6e, 0xea, 0x48, 0x46,
                0xdb, 0x40, 0xcf, 0x69, 0x12, 0x19, 0xfe, 0xe9, 0x0c, 0x2b, 0x5e, 0xbc, 0xe1, 0x23,
                0x28, 0x6b, 0xe8, 0x99, 0x00, 0x35, 0x0a, 0x45, 0x48, 0x06, 0xcd, 0xe0, 0x56, 0xf8,
                0xe6, 0x24, 0x68, 0x9f, 0x87, 0x9b, 0x7a, 0xa5, 0x0e, 0x5c, 0x42, 0xd3, 0x29, 0xab,
                0xe0, 0xa3, 0x21, 0xc7, 0xe2, 0x11, 0xfb, 0x27, 0x45, 0xbc, 0x20, 0x21, 0x41, 0xa6,
                0xd6, 0xc1, 0xd0, 0xbc,
            ];
            assert_eq!(encode(b"hello", &SALT), expected_em);
        }

        #[test]
        fn round_trip_own_encoding() {
            let em = encode(b"hello", &SALT);
            assert!(verify(b"hello", &em));
        }

        #[test]
        fn verify_rejects_wrong_message() {
            let em = encode(b"hello", &SALT);
            assert!(!verify(b"goodbye", &em));
        }

        #[test]
        fn different_salts_give_different_but_both_valid_encodings() {
            let salt_b: [u8; 32] = {
                let mut s = SALT;
                s[0] ^= 0xff;
                s
            };
            let em_a = encode(b"hello", &SALT);
            let em_b = encode(b"hello", &salt_b);
            assert_ne!(em_a, em_b, "PSS is randomized: different salts must give different EM");
            assert!(verify(b"hello", &em_a));
            assert!(verify(b"hello", &em_b));
        }

        /// RFC 8017 §9.1.2 step 4: the trailer byte must be `0xbc`.
        #[test]
        fn verify_rejects_wrong_trailer_byte() {
            let mut em = encode(b"hello", &SALT);
            em[255] = 0xbd;
            assert!(!verify(b"hello", &em));
        }

        /// RFC 8017 §9.1.2 step 6: the leftmost bit of `maskedDB`'s first octet must already be 0.
        #[test]
        fn verify_rejects_top_bit_set() {
            let mut em = encode(b"hello", &SALT);
            em[0] |= 0x80;
            assert!(!verify(b"hello", &em));
        }

        /// RFC 8017 §9.1.2 step 10: every byte of `PS` must be zero.
        #[test]
        fn verify_rejects_nonzero_padding() {
            let mut em = encode(b"hello", &SALT);
            em[0] ^= 0x40;
            assert!(!verify(b"hello", &em));
        }

        /// RFC 8017 §9.1.2 step 10: the octet right before the salt must be exactly `0x01`.
        #[test]
        fn verify_rejects_wrong_separator_byte() {
            // The byte at DB position (DB_LEN - S_LEN - 1) = 223 - 32 - 1 = 190, masked. Flipping its
            // least-significant bit changes the unmasked separator from 0x01 to 0x00.
            let mut em = encode(b"hello", &SALT);
            em[190] ^= 0x01;
            assert!(!verify(b"hello", &em));
        }
    }
}
