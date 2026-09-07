//! Known-answer tests from GB/T 32907-2016, as reproduced in draft-ribose-cfrg-sm4-10 Appendix A.1.
//!
//! Examples 1 and 2 are the standard's Example 1 in each direction; Example 3 is its Example 2,
//! the 1,000,000-fold iterated encryption. Examples 4 through 6 are the draft's own second key,
//! in the same three shapes. Every value here is transcribed from the downloaded text of the
//! draft.
//!
//! The per-round `rk_i` and `X_i` columns that Appendix A.1 also prints are **not** tested here:
//! the round keys are deliberately not public API (a `Secret` field) and the round outputs are
//! internal to the round loop, so both are pinned in the `#[cfg(test)]` modules of
//! `src/schedule.rs` and `src/sm4.rs`, where they can be reached. A round trip through the cipher
//! cannot check either -- a wrong `rk_i` is used by encryption and decryption alike.
//!
//! Key-handling behaviour (type, length, strength, `Debug` redaction) is tested here too.
//!
//! The two 1,000,000-iteration examples are ignored in unoptimised builds (see their attributes)
//! and run under `cargo test --release`.

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, SecurityStrength};
use bouncycastle_sm4::{BLOCK_LEN, SM4};

/// Examples 1-3 key (and plaintext): `0123456789ABCDEFFEDCBA9876543210`.
const KEY_1: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
];
/// Examples 1-3 plaintext, which happens to equal the key.
const PT_1: [u8; BLOCK_LEN] = KEY_1;
/// A.1.1 ciphertext.
const CT_1: [u8; BLOCK_LEN] = [
    0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46,
];
/// A.1.3 ciphertext after 1,000,000 encryptions.
const CT_1_ITERATED: [u8; BLOCK_LEN] = [
    0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F, 0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66,
];

/// Examples 4-6 key: `FEDCBA98765432100123456789ABCDEF`.
const KEY_4: [u8; 16] = [
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];
/// Examples 4-6 plaintext: `000102030405060708090A0B0C0D0E0F`.
const PT_4: [u8; BLOCK_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
/// A.1.4 ciphertext.
const CT_4: [u8; BLOCK_LEN] = [
    0xF7, 0x66, 0x67, 0x8F, 0x13, 0xF0, 0x1A, 0xDE, 0xAC, 0x1B, 0x3E, 0xA9, 0x55, 0xAD, 0xB5, 0x94,
];
/// A.1.6 ciphertext after 1,000,000 encryptions.
const CT_4_ITERATED: [u8; BLOCK_LEN] = [
    0x37, 0x9A, 0x96, 0xD0, 0xA6, 0xA5, 0xA5, 0x06, 0x0F, 0xB4, 0x60, 0xC7, 0x5D, 0x18, 0x79, 0xED,
];

fn key_material(bytes: &[u8; 16]) -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

#[test]
fn a_1_1_example_1_encrypt() {
    let sm4 = SM4::new(&key_material(&KEY_1)).unwrap();
    let mut block = PT_1;
    sm4.encrypt_block(&mut block);
    assert_eq!(block, CT_1);
}

#[test]
fn a_1_2_example_2_decrypt() {
    let sm4 = SM4::new(&key_material(&KEY_1)).unwrap();
    let mut block = CT_1;
    sm4.decrypt_block(&mut block);
    assert_eq!(block, PT_1);
}

/// A.1.3: "encryption of a plaintext 1,000,000 times repeatedly, using a fixed encryption key".
/// Gated to optimised builds: a million single-block calls through the four-lane circuit take
/// over a minute unoptimised. `cargo test --release -p bouncycastle-sm4` runs it.
#[cfg_attr(debug_assertions, ignore = "1,000,000 iterations; run with `cargo test --release`")]
#[test]
fn a_1_3_example_3_one_million_encryptions() {
    let sm4 = SM4::new(&key_material(&KEY_1)).unwrap();
    let mut block = PT_1;
    for _ in 0..1_000_000 {
        sm4.encrypt_block(&mut block);
    }
    assert_eq!(block, CT_1_ITERATED);
}

#[test]
fn a_1_4_example_4_encrypt() {
    let sm4 = SM4::new(&key_material(&KEY_4)).unwrap();
    let mut block = PT_4;
    sm4.encrypt_block(&mut block);
    assert_eq!(block, CT_4);
}

#[test]
fn a_1_5_example_5_decrypt() {
    let sm4 = SM4::new(&key_material(&KEY_4)).unwrap();
    let mut block = CT_4;
    sm4.decrypt_block(&mut block);
    assert_eq!(block, PT_4);
}

/// A.1.6: Example 4 iterated 1,000,000 times.
/// Gated to optimised builds: a million single-block calls through the four-lane circuit take
/// over a minute unoptimised. `cargo test --release -p bouncycastle-sm4` runs it.
#[cfg_attr(debug_assertions, ignore = "1,000,000 iterations; run with `cargo test --release`")]
#[test]
fn a_1_6_example_6_one_million_encryptions() {
    let sm4 = SM4::new(&key_material(&KEY_4)).unwrap();
    let mut block = PT_4;
    for _ in 0..1_000_000 {
        sm4.encrypt_block(&mut block);
    }
    assert_eq!(block, CT_4_ITERATED);
}

/// The two-block trait defaults must agree with the single-block known answers, in both slots.
#[test]
fn pair_methods_reproduce_the_appendix_ciphertexts() {
    let sm4 = SM4::new(&key_material(&KEY_1)).unwrap();

    let other = [0xAAu8; 16];
    let mut other_alone = other;
    sm4.encrypt_block(&mut other_alone);

    let mut pair = [PT_1, other];
    ElectronicCodeBook::encrypt_2blocks(&sm4, &mut pair);
    assert_eq!(pair, [CT_1, other_alone]);

    ElectronicCodeBook::decrypt_2blocks(&sm4, &mut pair);
    assert_eq!(pair, [PT_1, other]);
}

// ---- key handling -----------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    // KeyType::Seed is not a cipher key: a seed reused directly as an SM4 key is a real mistake
    // and the type system tracks enough to catch it.
    let key = KeyMaterial::<16>::from_bytes_as_type(&KEY_1, KeyType::Seed).unwrap();
    assert!(SM4::new(&key).is_err());

    let key = KeyMaterial::<16>::from_bytes_as_type(&KEY_1, KeyType::MACKey).unwrap();
    assert!(SM4::new(&key).is_err());
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    // The capacity is right but only part of it is populated, so `key_len()` disagrees with the
    // one SM4 key length. This is the one length error the const generic cannot catch by itself.
    let key =
        KeyMaterial::<16>::from_bytes_as_type(&KEY_1[..8], KeyType::SymmetricCipherKey).unwrap();
    assert!(SM4::new(&key).is_err());
}

#[test]
fn a_key_carrying_too_low_a_security_strength_is_rejected() {
    // A full-length key whose material was only ever derived at a lower security strength must
    // not be usable at the strength its length implies. `from_bytes_as_type` tags a 16-byte key
    // as 128-bit, so lower it deliberately -- lowering does not need a hazardous closure, only
    // raising does.
    let mut key = key_material(&KEY_1);
    assert_eq!(key.security_strength(), SecurityStrength::_128bit);

    key.set_security_strength(SecurityStrength::_112bit).unwrap();
    assert!(
        SM4::new(&key).is_err(),
        "SM4 must reject a 16-byte key only derived at the 112-bit strength"
    );

    // The same key at its full strength is fine, so the rejection is about the strength tag and
    // not about anything else having gone wrong with the key.
    assert!(SM4::new(&key_material(&KEY_1)).is_ok());
}

#[test]
fn an_all_zero_key_is_rejected_unless_explicitly_promoted() {
    // `KeyMaterial` tags an all-zero buffer `Zeroized`, and `SM4::new` refuses it as the wrong key
    // type. BC Java's `SM4Test` runs its generic `CipherTest` checks under `new byte[16]`; a caller
    // who really wants that key must opt in through `do_hazardous_operations`, as the CLI does.
    let key =
        KeyMaterial::<16>::from_bytes_as_type(&[0u8; 16], KeyType::SymmetricCipherKey).unwrap();
    assert_eq!(key.key_type(), KeyType::Zeroized);
    assert!(SM4::new(&key).is_err());
}

#[test]
fn debug_does_not_print_the_round_keys() {
    // The schedule is secret; `Debug` must not be a way to leak it.
    let sm4 = SM4::new(&key_material(&KEY_1)).unwrap();
    let rendered = format!("{sm4:?}");
    assert_eq!(rendered, "SM4");
}
