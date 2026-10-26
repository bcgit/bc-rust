//! Structural tests for KW and KWP, driven by a toy permutation: the key path and the bare
//! worker agree, the length rules of SP 800-38F Table 1, and the properties that tell the two
//! algorithms apart from each other and from a plain block encryption. The shared key-wrap
//! framework and the known-answer tests (RFC 3394, RFC 5649, ACVP) are in the `aes` crate,
//! `crypto/aes/tests/kw_*.rs`: the framework's tamper checks need a permutation with diffusion,
//! which the per-byte toy deliberately lacks, so a flipped register byte never reaches the ICV.

mod common;
#[path = "../common/toy_key.rs"]
mod toy_key;

use bouncycastle_cipher::modes::kw::{
    kw_ciphertext_len_is_valid, kw_plaintext_len_is_valid, kw_wrapped_len,
};
use bouncycastle_cipher::modes::kwp::{
    kwp_ciphertext_len_is_valid, kwp_plaintext_len_is_valid, kwp_wrapped_len,
};
use bouncycastle_cipher::modes::{KW, KWP, Kw, Kwp, ModeNames};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use common::{TOY_LEN, Toy, toy_key};
use toy_key::ToyKey;

type ToyKwKey = ToyKey<Toy, KW>;
type ToyKwpKey = ToyKey<Toy, KWP>;

fn kw_key() -> ToyKwKey {
    ToyKwKey::from_key_material(&toy_key()).expect("the toy KEK")
}

fn kwp_key() -> ToyKwpKey {
    ToyKwpKey::from_key_material(&toy_key()).expect("the toy KEK")
}

/// The construction suite -- key type, strength and `generate` -- for both modes.
#[test]
fn the_keys_enforce_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<TOY_LEN, ToyKwKey>(Toy::KW_ALG_NAME, SecurityStrength::_128bit);
    framework.test::<TOY_LEN, ToyKwpKey>(Toy::KWP_ALG_NAME, SecurityStrength::_128bit);
}

/// The key's one-shots and a worker built straight over the permutation agree.
#[test]
fn the_key_and_the_bare_worker_agree() {
    let perm = Toy::new(&toy_key()).unwrap();
    let data = [0x5Au8; 32];

    let key = kw_key();
    let from_key: [u8; 40] = key.wrap_key(&data).unwrap();
    let from_worker: [u8; 40] = Kw::from_perm(&perm).wrap_key(&data).unwrap();
    assert_eq!(from_key, from_worker);
    assert_eq!(*Kw::from_perm(&perm).unwrap_key::<32, 40>(&from_key).unwrap(), data);
    assert_eq!(*key.unwrap_key::<32, 40>(&from_worker).unwrap(), data);
    assert_eq!(*Kw::from_perm(key.state()).unwrap_key::<32, 40>(&from_key).unwrap(), data);

    let key = kwp_key();
    let short: [u8; 20] = data[..20].try_into().unwrap();
    let from_key: [u8; 32] = key.wrap_key(&short).unwrap();
    let from_worker: [u8; 32] = Kwp::from_perm(&perm).wrap_key(&short).unwrap();
    assert_eq!(from_key, from_worker);
    assert_eq!(*key.unwrap_key::<20, 32>(&from_worker).unwrap(), data[..20]);
}

// ---- properties specific to KW and KWP ------------------------------------------------------

/// The two integrity check values differ, so a ciphertext produced by one algorithm is rejected
/// by the other even though the lengths line up.
#[test]
fn kw_and_kwp_ciphertexts_are_not_interchangeable() {
    let kw = kw_key();
    let kwp = kwp_key();
    let data = [0x5Au8; 16];

    let kw_ct: [u8; 24] = kw.wrap_key(&data).unwrap();
    let kwp_ct: [u8; 24] = kwp.wrap_key(&data).unwrap();
    assert_ne!(kw_ct, kwp_ct);

    assert!(matches!(
        kwp.unwrap_key::<16, 24>(&kw_ct),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    assert!(matches!(
        kw.unwrap_key::<16, 24>(&kwp_ct),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
}

/// SP 800-38F Algorithm 5 step 5: for `len(P) <= 64` bits the ciphertext is `CIPH_K(S)` with
/// `S = ICV2 || [len]32 || P || PAD`, one raw block encryption and nothing else. Pinning that
/// against the permutation directly ties the single-block path to the spec.
#[test]
fn kwp_single_block_path_is_one_raw_block_encryption() {
    let key = kwp_key();
    let data = *b"12345";

    let ct: [u8; 16] = key.wrap_key(&data).unwrap();

    let mut s = [0u8; 16];
    s[..4].copy_from_slice(&[0xA6, 0x59, 0x59, 0xA6]);
    s[4..8].copy_from_slice(&(data.len() as u32).to_be_bytes());
    s[8..8 + data.len()].copy_from_slice(&data);
    Toy::new(&toy_key()).unwrap().encrypt_block(&mut s);
    assert_eq!(ct, s);
}

/// A KWP ciphertext length fixes the plaintext length only to within 7 bytes; the exact length is
/// the header field. So a 12-byte wrap unwraps fine as 12, and as any other length that shares
/// its ciphertext length is an authenticity failure, as the trait requires.
#[test]
fn kwp_unwrap_key_rejects_a_recovered_length_other_than_key_len() {
    let key = kwp_key();
    let ct: [u8; 24] = key.wrap_key(&[0x33u8; 12]).unwrap();

    assert_eq!(*key.unwrap_key::<12, 24>(&ct).unwrap(), [0x33u8; 12]);
    assert!(matches!(key.unwrap_key::<13, 24>(&ct), Err(SymmetricCipherError::DecryptionFailed)));
    assert!(matches!(key.unwrap_key::<9, 24>(&ct), Err(SymmetricCipherError::DecryptionFailed)));
    // ... and the run-time API reports the real length.
    let mut pt = [0u8; 16];
    assert_eq!(key.unwrap_out(&ct, &mut pt).unwrap(), 12);
    assert_eq!(pt[..12], [0x33u8; 12]);
    assert_eq!(pt[12..], [0u8; 4], "the padding is left as zeros");
}

/// Algorithm 6 step 8: padding must be zero. A ciphertext whose padding bytes were anything else
/// is a forgery. Constructed by wrapping through the raw block cipher with non-zero padding, since
/// the wrapper itself never produces one.
#[test]
fn kwp_rejects_non_zero_padding() {
    let key = kwp_key();
    let perm = Toy::new(&toy_key()).unwrap();

    let mut s = [0u8; 16];
    s[..4].copy_from_slice(&[0xA6, 0x59, 0x59, 0xA6]);
    s[4..8].copy_from_slice(&5u32.to_be_bytes());
    s[8..13].copy_from_slice(b"12345");
    s[15] = 0x01; // the last pad byte
    perm.encrypt_block(&mut s);

    assert!(matches!(key.unwrap_key::<5, 16>(&s), Err(SymmetricCipherError::DecryptionFailed)));
}

/// Algorithm 6 step 7: `padlen` must be 0 to 7, so a length field that does not fit the
/// ciphertext is a forgery even when the ICV and padding check out. Two cases: a length larger
/// than the padded data, and one that would leave 8 or more bytes of padding.
#[test]
fn kwp_rejects_a_length_field_that_does_not_fit() {
    let key = kwp_key();
    let perm = Toy::new(&toy_key()).unwrap();

    for bad_len in [9u32, 0u32, u32::MAX] {
        let mut s = [0u8; 16];
        s[..4].copy_from_slice(&[0xA6, 0x59, 0x59, 0xA6]);
        s[4..8].copy_from_slice(&bad_len.to_be_bytes());
        perm.encrypt_block(&mut s);

        let mut pt = [0xFFu8; 8];
        assert!(
            matches!(key.unwrap_out(&s, &mut pt), Err(SymmetricCipherError::DecryptionFailed)),
            "a length field of {bad_len} should not fit an 8-byte padded plaintext"
        );
        assert_eq!(pt, [0u8; 8], "the buffer is scrubbed on failure");
    }
}

/// The length predicates and helpers are SP 800-38F Table 1 exactly.
#[test]
fn the_length_helpers_match_table_1() {
    let kw = kw_key();
    let kwp = kwp_key();

    // KW: 2 to 2^54 - 1 semiblocks of plaintext, one more of ciphertext.
    assert!(!kw_plaintext_len_is_valid(0));
    assert!(!kw_plaintext_len_is_valid(8));
    assert!(!kw_plaintext_len_is_valid(12));
    assert!(kw_plaintext_len_is_valid(16));
    assert!(kw_plaintext_len_is_valid(24));
    assert!(!kw_ciphertext_len_is_valid(16));
    assert!(kw_ciphertext_len_is_valid(24));
    assert!(!kw_ciphertext_len_is_valid(25));
    assert_eq!(kw_wrapped_len(16), 24);
    assert_eq!(kw_wrapped_len(usize::MAX), usize::MAX, "saturates rather than overflowing");
    // The 2^54 upper bounds, reachable as lengths only on a 64-bit target: the last valid
    // plaintext is 2^54 - 1 semiblocks, the last valid ciphertext 2^54.
    #[cfg(target_pointer_width = "64")]
    {
        const MAX_PT: usize = ((1usize << 54) - 1) * 8;
        assert!(kw_plaintext_len_is_valid(MAX_PT));
        assert!(!kw_plaintext_len_is_valid(MAX_PT + 4));
        assert!(!kw_plaintext_len_is_valid(MAX_PT + 8));
        assert!(kw_ciphertext_len_is_valid(MAX_PT + 8));
        assert!(!kw_ciphertext_len_is_valid(MAX_PT + 16));
    }
    assert_eq!(kw.wrap_out_len(32), 40);
    assert_eq!(kw.unwrap_out_max_len(40), 32);
    assert_eq!(kw.unwrap_out_max_len(0), 0);

    // KWP: 1 to 2^32 - 1 octets of plaintext; 2 to 2^29 semiblocks of ciphertext.
    assert!(!kwp_plaintext_len_is_valid(0));
    assert!(kwp_plaintext_len_is_valid(1));
    assert!(kwp_plaintext_len_is_valid(u32::MAX as usize));
    assert!(!kwp_plaintext_len_is_valid(u32::MAX as usize + 1));
    assert!(!kwp_ciphertext_len_is_valid(8));
    assert!(kwp_ciphertext_len_is_valid(16));
    assert!(!kwp_ciphertext_len_is_valid(20));
    assert!(kwp_ciphertext_len_is_valid(8 << 29));
    assert!(!kwp_ciphertext_len_is_valid((8 << 29) + 8));
    assert_eq!(kwp_wrapped_len(1), 16);
    assert_eq!(kwp_wrapped_len(8), 16);
    assert_eq!(kwp_wrapped_len(9), 24);
    assert_eq!(kwp_wrapped_len(20), 32);
    assert_eq!(kwp_wrapped_len(usize::MAX), usize::MAX, "saturates rather than overflowing");
    assert_eq!(kwp.unwrap_out_max_len(32), 24);

    // ... and the run-time API enforces them.
    let mut buf = [0u8; 64];
    assert!(matches!(
        kw.wrap_out(&[0u8; 8], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        kw.wrap_out(&[0u8; 12], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        kw.unwrap_out(&[0u8; 16], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        kwp.unwrap_out(&[0u8; 20], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
}

/// KW and KWP wrap the same aligned data to different lengths only when it is short enough to
/// fit KWP's single block; otherwise KWP's ciphertext is KW's length, not longer, since the
/// header replaces ICV1 rather than adding to it.
#[test]
fn kwp_costs_nothing_extra_for_aligned_data() {
    let kw = kw_key();
    let kwp = kwp_key();
    assert_eq!(kw.wrap_out_len(16), kwp.wrap_out_len(16));
    assert_eq!(kw.wrap_out_len(32), kwp.wrap_out_len(32));
    assert_eq!(kwp.wrap_out_len(8), 16, "and 8 bytes need only one block");
}

/// The worker is the borrow and nothing else, and the key is the permutation and nothing else.
#[test]
fn sizes() {
    use core::mem::size_of;
    assert_eq!(size_of::<Kw<'_, Toy>>(), size_of::<&Toy>());
    assert_eq!(size_of::<Kwp<'_, Toy>>(), size_of::<&Toy>());
    assert_eq!(size_of::<ToyKwKey>(), size_of::<Toy>());
}
