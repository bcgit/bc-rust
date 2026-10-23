//! Shared plumbing for the ACVP AES-GCM and AES-GMAC known-answer test files
//! (`gcm_bc-test-data.rs`, `gmac_bc-test-data.rs`), whose request/response JSON shape is identical
//! between the two: GMAC is just the `payloadLen = 0` slice of the same ACVP AES-GCM protocol
//! (SP 800-38D Sec 5.2: GMAC is GCM restricted to `P = ""`).
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent, callers print a warning and skip,
//! matching the convention the other ACVP suites in this crate use.

#![allow(dead_code)]

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Gcm;
use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;

/// The nonce length these vectors use; every group in the ACVP AES-GCM/GMAC sets has `ivLen = 96`.
#[path = "acvp_helpers.rs"]
mod acvp_helpers;
pub use acvp_helpers::cipher_key;

pub const GCM_NONCE_LEN: usize = 12;

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
        16 => dispatch!(AES128Internal, 16),
        24 => dispatch!(AES192Internal, 24),
        32 => dispatch!(AES256Internal, 32),
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
    P: bouncycastle_core::hazmat::ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    let mut ct = vec![0u8; data.len()];
    let (got_iv, written, tag) = Gcm::<P, Encrypting, KEY_LEN, TAG_LEN>::encrypt_detached_rng_out(
        key,
        &mut FixedSeedRNG::<GCM_NONCE_LEN>::new(iv),
        aad,
        data,
        &mut ct,
    )
    .expect("encrypt");
    assert_eq!(got_iv, iv, "the pinned RNG should reproduce the vector's IV");
    assert_eq!(written, data.len(), "GCM ciphertext is as long as the plaintext");
    assert_eq!(&tag[..], expected_tag, "tag mismatch");
    data.copy_from_slice(&ct);
}

/// Runs one ACVP AES-GCM/GMAC decrypt case: decrypts `ct` under `key`/`aad`/`iv` and either
/// compares against `expected_pt` (a valid case) or asserts `AEADTagCheckFailed` (a forgery) from
/// both the detached one-shot and the inline stream, with the one-shot's plaintext buffer zeroized.
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
        16 => dispatch!(AES128Internal, 16),
        24 => dispatch!(AES192Internal, 24),
        32 => dispatch!(AES256Internal, 32),
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
    P: bouncycastle_core::hazmat::ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    let tag_arr: [u8; TAG_LEN] = tag.try_into().expect("tag length matches TAG_LEN");

    // The detached one-shot: AAD-capable, and never releases plaintext before the tag checks out.
    let mut data = vec![0xEEu8; ct.len()];
    let one_shot_result = Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::decrypt_detached_out(
        key, &iv, aad, ct, &tag_arr, &mut data,
    );

    // The inline `SymmetricCipherDecryptor` streaming view, `ciphertext || tag` through
    // `do_update_out`/`do_decrypt_final`, with AAD fed via `do_update_aad` first. Note this is
    // *not* the AAD-less static `decrypt_out` one-shot (which has no AAD parameter at all, so it
    // cannot run the cases that carry AAD, and most do): the streaming path is where the inline
    // layout meets AAD support, and unlike the one-shot it releases plaintext before the tag is
    // checked -- see `gcm_tests.rs` for that distinction pinned with empty AAD.
    let mut dec =
        Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::do_decrypt_init(key, &iv).expect("decrypt init");
    dec.do_update_aad(aad).expect("aad");
    let mut inline_ct = ct.to_vec();
    inline_ct.extend_from_slice(tag);
    let expect_written = dec.do_decrypt_out_len(inline_ct.len());
    let mut inline_pt = vec![0u8; expect_written];
    let written = dec
        .do_decrypt_out(&inline_ct, &mut inline_pt)
        .expect("do_update_out on a correctly sized buffer must not fail");
    assert_eq!(written, expect_written, "update_out_len must be exact");
    let inline_result = dec.do_decrypt_final();

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
            assert!(
                matches!(one_shot_result, Err(SymmetricCipherError::AEADTagCheckFailed)),
                "expected AEADTagCheckFailed from the detached one-shot, got {one_shot_result:?}"
            );
            assert!(
                data.iter().all(|&b| b == 0),
                "a forged tag must leave the one-shot buffer zeroized"
            );

            assert!(
                matches!(inline_result, Err(SymmetricCipherError::AEADTagCheckFailed)),
                "expected AEADTagCheckFailed from the inline stream's do_decrypt_final, got {inline_result:?}"
            );
        }
    }
}
