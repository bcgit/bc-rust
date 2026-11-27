//! `LabeledExtract` and `LabeledExpand` of RFC 9180 Section 4, over HKDF (RFC 5869) on the hash
//! `H`, with the `suite_id` as an argument: the DHKEM's is `concat("KEM", I2OSP(kem_id, 2))`
//! (Section 4.1) and HPKE's is `concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2),
//! I2OSP(aead_id, 2))` (Section 5.1). Public for the key schedule of
//! `bouncycastle-hybrid`'s `hpke` module; see [`bouncycastle_core::hazmat`] for what the path
//! means.
//!
//! # 🚨 Security Considerations 🚨
//!
//! These are the KDF steps of a protocol, not a KDF to call: nothing checks that a label, a
//! suite id or an output length is one RFC 9180 defines, and an `L` past 255*Nh or 0xFFFF,
//! like an all-zero PRK (one HMAC output in 2^(8 * Nh)), is a panic.
//! Use HKDF (`bouncycastle_digest::hkdf`) for key derivation.

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
use bouncycastle_core::traits::HashAlgParams;
use bouncycastle_digest::hmac::hazmat as hmac_hazmat;
use bouncycastle_digest::hmac::{HMACParams, HmacKey};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::stack_wipe::in_wiped_frame_scaled;

/// The version label that RFC 9180 Section 4 puts in every labeled KDF input: at the front of
/// `labeled_ikm`, and after `I2OSP(L, 2)` in `labeled_info`.
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

/// The largest Nh among the KDFs of RFC 9180 Section 7.2 (HKDF-SHA512). The PRK and HKDF-Expand
/// block buffers are sized to it.
pub const MAX_NH: usize = 64;

/// What the stack wipe overwrites after each labeled step, in words: 512 bytes. Each runs in a
/// frame of its own, since the HMAC inner state it takes by value (`hmac::hazmat::inner_state`),
/// and in `labeled_expand` the HMAC key it makes from the PRK, are key-equivalents of the salt or
/// the PRK, and staged copies of them are otherwise left in the step's frame. A wipe of 64 bytes
/// misses them and one of 128 reaches them (x86-64, rustc 1.97 and 1.88,
/// `dev_scripts/ecdsa_stack_harness`); HMAC's own frames are wiped by HMAC.
const LABELED_STACK_WORDS: usize = 64;

/// What the stack wipe overwrites after [`salt_key`], in words: 2 KiB. A wipe of 512 bytes
/// misses the copies of the pad states and one of 1 KiB reaches them, over SHA-256, SHA-384 and
/// SHA-512 (x86-64, rustc 1.97 and 1.88, `dev_scripts/ecdsa_stack_harness`).
const SALT_KEY_STACK_WORDS: usize = 256;

/// The HMAC key that is the `salt` of a `LabeledExtract`; an empty salt is an empty HMAC key.
/// RFC 5869 Section 2.2 says an absent salt "is set to a string of HashLen zeros", which is the
/// same HMAC key, as HMAC zero-pads its key.
///
/// `salt` is at most [`MAX_NH`] bytes: it is empty, or a KEM shared secret of Nsecret bytes.
pub fn salt_key<H: HMACParams>(salt: &[u8]) -> HmacKey<H> {
    // In a wiped frame: the key is moved out of the `Result`s HMAC builds it in, and the copies
    // of its pad states left behind are as good as the salt, which in HPKE's key schedule is the
    // KEM's shared secret (SALT_KEY_STACK_WORDS).
    in_wiped_frame_scaled::<u64, 0, SALT_KEY_STACK_WORDS, _>(|| {
        // Cannot fail: the bytes fit, an all-zero or empty salt is typed Zeroized, which HMAC
        // accepts as a weak key, and the strength is not checked.
        let salt = KeyMaterial::<MAX_NH>::from_bytes_as_type(salt, KeyType::MACKey)
            .expect("a salt of at most MAX_NH bytes");
        HmacKey::<H>::from_key_material_allow_weak(&salt).expect("a MAC key or a zeroized one")
    })
}

/// `LabeledExtract(salt, label, ikm)` (RFC 9180 Section 4), where `Extract` is HKDF-Extract
/// (RFC 5869 Section 2.2) over `H`, with `ikm` given as the parts it is the concatenation of.
/// Writes the Nh bytes of the PRK to the front of `out`, the rest of which is left zero, and
/// returns Nh.
pub fn labeled_extract_out<H: HMACParams>(
    suite_id: &[u8],
    salt: &HmacKey<H>,
    label: &[u8],
    ikm: &[&[u8]],
    out: &mut [u8; MAX_NH],
) -> usize {
    out.fill(0);
    // In a wiped frame, for the copy of the inner state (LABELED_STACK_WORDS).
    in_wiped_frame_scaled::<u64, 0, LABELED_STACK_WORDS, _>(|| {
        // PRK = HMAC-Hash(salt, IKM)
        // HMAC through its hazmat halves, as HKDF's expand loop runs it: the role wants the tag
        // length as a const, which a hash-generic KDF does not have.
        let mut hmac = hmac_hazmat::inner_state(salt);
        // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        // Deviation from the RFC: the parts of labeled_ikm are absorbed by HMAC in order rather
        // than concatenated first.
        hmac.do_update(HPKE_VERSION_LABEL);
        hmac.do_update(suite_id);
        hmac.do_update(label);
        for part in ikm {
            hmac.do_update(part);
        }
        // The whole tag: the hash output length, at most MAX_NH (checked by each caller's const
        // assertions).
        let nh = <H as HashAlgParams>::OUTPUT_LEN;
        hmac_hazmat::finish_out(salt, &mut hmac, &mut out[..nh])
    })
}

/// [`labeled_extract_out`] into `prk` as a MAC key, ready for [`labeled_expand`]: into the
/// caller's buffer rather than returned, so that it is not moved.
pub fn labeled_extract_prk_into<H: HMACParams>(
    suite_id: &[u8],
    salt: &HmacKey<H>,
    label: &[u8],
    ikm: &[&[u8]],
    prk: &mut KeyMaterial<MAX_NH>,
) {
    let mut bytes = Secret::<[u8; MAX_NH]>::new();
    let nh = labeled_extract_out(suite_id, salt, label, ikm, &mut bytes);
    // nh <= MAX_NH bytes fit a KeyMaterial<MAX_NH>; the one way this fails is an all-zero
    // PRK (one HMAC output in 2^(8 * nh)), which the buffer types Zeroized and the expand's
    // HmacKey then refuses. Not reachable in practice; a panic is the right report for it.
    prk.set_bytes_as_type(&bytes[..nh], KeyType::MACKey)
        .expect("an all-zero PRK, one HMAC output in 2^(8 * nh)");
}

/// `LabeledExpand(prk, label, info, L)` (RFC 9180 Section 4), where `Expand` is HKDF-Expand (RFC
/// 5869 Section 2.3) over `H`, `L` is `out.len()`, and `info` is given as the parts it is the
/// concatenation of. Returns the number of bytes written, `L`.
///
/// # Panics
/// If `L` is more than 255*Nh or more than 0xFFFF.
pub fn labeled_expand<H: HMACParams>(
    suite_id: &[u8],
    prk: &KeyMaterial<MAX_NH>,
    label: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> usize {
    let nh = <H as HashAlgParams>::OUTPUT_LEN;
    // Past these, I2OSP(L, 2) and the one-byte block counter would wrap and the output would be
    // silently wrong. Every caller in the workspace is bounded at compile time.
    assert!(out.len() <= 255 * nh && out.len() <= 0xFFFF, "LabeledExpand: L is too long");
    let l = (out.len() as u16).to_be_bytes();
    // In a wiped frame, for the copies of the inner state (LABELED_STACK_WORDS).
    in_wiped_frame_scaled::<u64, 0, LABELED_STACK_WORDS, _>(|| {
        // T(0) = empty string (zero length)
        let mut t = Secret::<[u8; MAX_NH]>::new();
        let mut t_len = 0;
        // N = ceil(L/HashLen); T = T(1) | T(2) | ... | T(N); OKM = first L octets of T
        // The PRK keys one HmacKey for the whole expand, so that its pads are scheduled once
        // and not once per block. It refuses an
        // all-zero PRK, one HMAC output in 2^(8 * nh); see labeled_extract_prk_into.
        let key = HmacKey::<H>::from_key_material(prk)
            .expect("an all-zero PRK, one HMAC output in 2^(8 * nh)");
        // Each chunk of `out` is one T(i), the last one truncated.
        for (i, okm_chunk) in out.chunks_mut(nh).enumerate() {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i), with info = labeled_info
            let mut hmac = hmac_hazmat::inner_state(&key);
            hmac.do_update(&t[..t_len]);
            // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
            // Deviation from the RFC: absorbed in parts, as in labeled_extract_out.
            hmac.do_update(&l);
            hmac.do_update(HPKE_VERSION_LABEL);
            hmac.do_update(suite_id);
            hmac.do_update(label);
            for part in info {
                hmac.do_update(part);
            }
            // i <= N <= 255, since L <= 255*HashLen.
            hmac.do_update(&[(i + 1) as u8]);
            // The whole tag: the buffer is the hash output length.
            t_len = hmac_hazmat::finish_out(&key, &mut hmac, &mut t[..nh]);
            okm_chunk.copy_from_slice(&t[..okm_chunk.len()]);
        }
    });
    out.len()
}
