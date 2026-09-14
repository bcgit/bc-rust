//! Shared plumbing for the ACVP AES-GCM and AES-GMAC known-answer test files
//! (`acvp_gcm_tests.rs`, `acvp_gmac_tests.rs`), whose request/response JSON shape is identical
//! between the two: GMAC is just the `payloadLen = 0` slice of the same ACVP AES-GCM protocol
//! (SP 800-38D Sec 5.2: GMAC is GCM restricted to `P = ""`).
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent, callers print a warning and skip,
//! matching the convention the other ACVP suites in this crate use.

#![allow(dead_code)]

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{SecurityStrength, SimpleCipherDecryptor, SimpleCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Encrypting, Gcm};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The nonce length these vectors use; every group in the ACVP AES-GCM/GMAC sets has `ivLen = 96`.
pub const GCM_NONCE_LEN: usize = 12;

/// Finds the directory holding `req_file` and `rsp_file` under either of the two candidate roots
/// this crate's other ACVP suites use, or `None` (with a printed warning) if neither has both.
pub fn test_data_dir(subdir: &str, req_file: &str, rsp_file: &str) -> Option<PathBuf> {
    let candidates = [
        format!("../../../bc-test-data/crypto/{subdir}"),
        format!("../bc-test-data/crypto/{subdir}"),
    ];
    for candidate in &candidates {
        let path = Path::new(candidate);
        if path.join(req_file).exists() && path.join(rsp_file).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {candidates:?}); \
         this suite will be skipped"
    );
    None
}

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys the set includes
/// deliberately: `KeyMaterial` tags an all-zero buffer as `KeyType::Zeroized` and will not promote
/// it outside a `do_hazardous_operations` closure, so this opts in explicitly.
pub fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("ACVP key bytes fit the buffer");
    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a NIST all-zero test key");
    }
    key
}

pub fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

/// Runs one ACVP AES-GCM/GMAC encrypt case: encrypts `pt` under `key`/`aad`, driving the nonce
/// through a `FixedSeedRNG` seeded with the vector's own `iv` and asserting it is reproduced
/// exactly (so a change that ignored the RNG could not pass silently), then compares the resulting
/// ciphertext and tag against the response file's `ct`/`tag`.
pub fn run_encrypt_case(
    key_bytes: &[u8],
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    tag_len: usize,
    expected_ct: &[u8],
    expected_tag: &[u8],
) {
    macro_rules! dispatch {
        ($p:ty, $klen:literal) => {{
            let key = cipher_key::<$klen>(key_bytes);
            let mut data = pt.to_vec();
            match tag_len {
                12 => run_encrypt::<$p, $klen, 12>(&key, iv, aad, &mut data, expected_tag),
                13 => run_encrypt::<$p, $klen, 13>(&key, iv, aad, &mut data, expected_tag),
                14 => run_encrypt::<$p, $klen, 14>(&key, iv, aad, &mut data, expected_tag),
                15 => run_encrypt::<$p, $klen, 15>(&key, iv, aad, &mut data, expected_tag),
                16 => run_encrypt::<$p, $klen, 16>(&key, iv, aad, &mut data, expected_tag),
                other => panic!("unsupported ACVP tagLen {other} bytes"),
            }
            assert_eq!(data, expected_ct);
        }};
    }
    match key_bytes.len() {
        16 => dispatch!(AES_128, 16),
        24 => dispatch!(AES_192, 24),
        32 => dispatch!(AES_256, 32),
        other => panic!("unexpected AES key length {other}"),
    }
}

fn run_encrypt<P, const KEY_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    expected_tag: &[u8],
) where
    P: bouncycastle_core::traits::ElectronicCodeBook<KEY_LEN, 16>,
{
    let (mut enc, got_iv) = Gcm::<P, Encrypting, KEY_LEN, TAG_LEN>::do_encrypt_init_rng(
        key,
        &mut FixedSeedRNG::<GCM_NONCE_LEN>::new(iv),
    )
    .expect("encrypt init");
    assert_eq!(got_iv, iv, "the pinned RNG should reproduce the vector's IV");
    enc.do_update_aad(aad).expect("aad");
    enc.do_encrypt(data).expect("encrypt");
    let tag = enc.finish();
    assert_eq!(&tag[..], expected_tag, "tag mismatch");
}

/// Runs one ACVP AES-GCM/GMAC decrypt case: decrypts `ct` under `key`/`aad`/`iv` and either
/// compares against `expected_pt` (a valid case) or asserts `AEADTagCheckFailed` (a forgery) from
/// both the detached one-shot and the inline `decrypt_out`, with the plaintext buffer left
/// untouched in both.
pub fn run_decrypt_case(
    key_bytes: &[u8],
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
    expected_pt: Option<&[u8]>,
) {
    macro_rules! dispatch {
        ($p:ty, $klen:literal) => {{
            let key = cipher_key::<$klen>(key_bytes);
            match tag.len() {
                12 => run_decrypt::<$p, $klen, 12>(&key, iv, aad, ct, tag, expected_pt),
                13 => run_decrypt::<$p, $klen, 13>(&key, iv, aad, ct, tag, expected_pt),
                14 => run_decrypt::<$p, $klen, 14>(&key, iv, aad, ct, tag, expected_pt),
                15 => run_decrypt::<$p, $klen, 15>(&key, iv, aad, ct, tag, expected_pt),
                16 => run_decrypt::<$p, $klen, 16>(&key, iv, aad, ct, tag, expected_pt),
                other => panic!("unsupported ACVP tagLen {other} bytes"),
            }
        }};
    }
    match key_bytes.len() {
        16 => dispatch!(AES_128, 16),
        24 => dispatch!(AES_192, 24),
        32 => dispatch!(AES_256, 32),
        other => panic!("unexpected AES key length {other}"),
    }
}

fn run_decrypt<P, const KEY_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
    expected_pt: Option<&[u8]>,
) where
    P: bouncycastle_core::traits::ElectronicCodeBook<KEY_LEN, 16>,
{
    let tag_arr: [u8; TAG_LEN] = tag.try_into().expect("tag length matches TAG_LEN");

    // The detached one-shot: AAD-capable, and never releases plaintext before the tag checks out.
    let mut data = ct.to_vec();
    let one_shot_result = Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::decrypt_detached(
        key, &iv, aad, &mut data, &tag_arr,
    );

    // The inline `SimpleCipherDecryptor` streaming view, `ciphertext || tag` through
    // `do_update_out`/`do_final`, with AAD fed via the inherent `do_update_aad` first. Note this is
    // *not* the AAD-less static `decrypt_out` one-shot (which has no AAD parameter at all and so
    // cannot be checked against these vectors, none of which have empty AAD): the streaming path
    // is where the inline layout meets AAD support, and unlike the one-shot it releases plaintext
    // before the tag is checked -- see `gcm_tests.rs` for that distinction pinned with empty AAD.
    let mut dec =
        Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::do_decrypt_init(key, &iv).expect("decrypt init");
    dec.do_update_aad(aad).expect("aad");
    let mut inline_ct = ct.to_vec();
    inline_ct.extend_from_slice(tag);
    let expect_written = dec.update_out_len(inline_ct.len());
    let mut inline_pt = vec![0u8; expect_written];
    let written = dec
        .do_update_out(&inline_ct, &mut inline_pt)
        .expect("do_update_out on a correctly sized buffer must not fail");
    assert_eq!(written, expect_written, "update_out_len must be exact");
    let inline_result = dec.do_final();

    match expected_pt {
        Some(pt) => {
            assert!(
                one_shot_result.is_ok(),
                "detached one-shot should have verified: {one_shot_result:?}"
            );
            assert_eq!(data, pt, "detached one-shot plaintext mismatch");

            assert!(inline_result.is_ok(), "inline stream should have verified: {inline_result:?}");
            assert_eq!(written, pt.len(), "inline stream released the wrong length");
            assert_eq!(&inline_pt[..written], pt, "inline stream plaintext mismatch");
        }
        None => {
            let before = ct.to_vec();
            assert!(
                matches!(one_shot_result, Err(SymmetricCipherError::AEADTagCheckFailed)),
                "expected AEADTagCheckFailed from the detached one-shot, got {one_shot_result:?}"
            );
            assert_eq!(data, before, "a forged tag must leave the one-shot buffer untouched");

            assert!(
                matches!(inline_result, Err(SymmetricCipherError::AEADTagCheckFailed)),
                "expected AEADTagCheckFailed from the inline stream's do_final, got {inline_result:?}"
            );
        }
    }
}
