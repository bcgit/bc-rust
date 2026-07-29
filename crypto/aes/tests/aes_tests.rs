//! Known-answer tests for the AES block cipher engine.
//!
//! The vectors come from two places:
//!
//! * **FIPS 197 Appendix B** ("Cipher Example"), the single-block AES-128 worked example.
//! * The NIST **"AES Core" intermediate value files** for ECB-AES128, ECB-AES192 and ECB-AES256
//!   (the same four-block plaintext and keys that appear in NIST SP 800-38A Appendix F.1). Only the
//!   block-level inputs and outputs are checked here; the per-round intermediate values from those
//!   same files are checked against the individual transformations by the unit tests in
//!   `src/state.rs`, `src/key_schedule.rs` and `src/aes.rs`.
//!
//! Note that "ECB" in the names of those files simply means each block is enciphered independently
//! with no chaining, which is exactly the raw permutation this crate exposes. This crate does not
//! implement ECB (or any other) mode of operation -- see the crate docs.

use bouncycastle_aes::{
    AES, AES_BLOCK_LEN, AES128, AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS, AES128_NUM_ROUNDS,
    AES128Key, AES192, AES192_KEY_LEN, AES192_KEY_SCHEDULE_WORDS, AES192_NUM_ROUNDS, AES256,
    AES256_KEY_LEN, AES256_KEY_SCHEDULE_WORDS, AES256_NUM_ROUNDS, AES256Key, AESEngine,
};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_hex as hex;

/* *** Test vectors *** */

/// The AES-128 key of FIPS 197 Appendix A.1 and Appendix B, and of the ECB-AES128 vector file.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// The AES-192 key of FIPS 197 Appendix A.2 and of the ECB-AES192 vector file.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// The AES-256 key of FIPS 197 Appendix A.3 and of the ECB-AES256 vector file.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// The four plaintext blocks used by all three ECB-AES vector files.
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// The ciphertexts of [`PLAINTEXTS`] under [`KEY_128`].
const CIPHERTEXTS_128: [&str; 4] = [
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
];

/// The ciphertexts of [`PLAINTEXTS`] under [`KEY_192`].
const CIPHERTEXTS_192: [&str; 4] = [
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
];

/// The ciphertexts of [`PLAINTEXTS`] under [`KEY_256`].
const CIPHERTEXTS_256: [&str; 4] = [
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
];

/* *** Helpers *** */

/// Wraps a hex-encoded key as a [`KeyMaterial`] of the exact size the given AES variant takes.
fn key_from_hex<const KEY_LEN: usize>(key_hex: &str) -> KeyMaterial<KEY_LEN> {
    let bytes = hex::decode(key_hex).unwrap();
    assert_eq!(bytes.len(), KEY_LEN, "test key is the wrong length for this variant");
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// Decodes a hex-encoded block into a fixed-size array.
fn block_from_hex(block_hex: &str) -> [u8; AES_BLOCK_LEN] {
    hex::decode(block_hex).unwrap().try_into().expect("test block is not 16 bytes")
}

/// Runs a full known-answer test for one variant, in both directions, through every API the crate
/// offers: the streaming engine, the `_out` forms, and the one-shot statics.
///
/// Generic over the variant's parameters so that all three variants are exercised by identical
/// code; the `Algorithm` bound is what restricts this to the three parameter sets of FIPS 197
/// Table 3 (and incidentally proves that downstream crates can write such generic code).
fn check_known_answers<const KEY_LEN: usize, const NR: usize, const W_WORDS: usize>(
    key_hex: &str,
    expected_ciphertexts: [&str; 4],
) where
    AES<KEY_LEN, NR, W_WORDS>: Algorithm,
{
    let key = key_from_hex::<KEY_LEN>(key_hex);
    let engine = AES::<KEY_LEN, NR, W_WORDS>::new(&key).unwrap();

    for (plaintext_hex, ciphertext_hex) in PLAINTEXTS.iter().zip(expected_ciphertexts.iter()) {
        let plaintext = block_from_hex(plaintext_hex);
        let ciphertext = block_from_hex(ciphertext_hex);

        // CIPHER()
        assert_eq!(
            engine.encrypt_block(&plaintext),
            ciphertext,
            "{} encrypt of {plaintext_hex}",
            AES::<KEY_LEN, NR, W_WORDS>::ALG_NAME
        );

        // INVCIPHER()
        assert_eq!(
            engine.decrypt_block(&ciphertext),
            plaintext,
            "{} decrypt of {ciphertext_hex}",
            AES::<KEY_LEN, NR, W_WORDS>::ALG_NAME
        );

        // The _out forms must agree with the returning forms, byte for byte.
        let mut out = [0u8; AES_BLOCK_LEN];
        assert_eq!(engine.encrypt_block_out(&plaintext, &mut out), AES_BLOCK_LEN);
        assert_eq!(out, ciphertext);
        assert_eq!(engine.decrypt_block_out(&ciphertext, &mut out), AES_BLOCK_LEN);
        assert_eq!(out, plaintext);

        // ... and so must the one-shot statics, which re-expand the key each call.
        assert_eq!(
            AES::<KEY_LEN, NR, W_WORDS>::encrypt_single_block(&key, &plaintext).unwrap(),
            ciphertext
        );
        assert_eq!(
            AES::<KEY_LEN, NR, W_WORDS>::decrypt_single_block(&key, &ciphertext).unwrap(),
            plaintext
        );
    }
}

/* *** Known-answer tests *** */

/// FIPS 197 Appendix B, the step-by-step example: a 16-byte key and a 16-byte input, with the
/// expected output read out of the final state matrix.
#[test]
fn fips197_appendix_b_cipher_example() {
    let key = key_from_hex::<AES128_KEY_LEN>(KEY_128);
    let engine = AES128::new(&key).unwrap();

    let plaintext = block_from_hex("3243f6a8885a308d313198a2e0370734");
    let ciphertext = engine.encrypt_block(&plaintext);

    assert_eq!(hex::encode(ciphertext), "3925841d02dc09fbdc118597196a0b32");
    assert_eq!(engine.decrypt_block(&ciphertext), plaintext);
}

#[test]
fn aes128_known_answers() {
    check_known_answers::<AES128_KEY_LEN, AES128_NUM_ROUNDS, AES128_KEY_SCHEDULE_WORDS>(
        KEY_128, CIPHERTEXTS_128,
    );
}

#[test]
fn aes192_known_answers() {
    check_known_answers::<AES192_KEY_LEN, AES192_NUM_ROUNDS, AES192_KEY_SCHEDULE_WORDS>(
        KEY_192, CIPHERTEXTS_192,
    );
}

#[test]
fn aes256_known_answers() {
    check_known_answers::<AES256_KEY_LEN, AES256_NUM_ROUNDS, AES256_KEY_SCHEDULE_WORDS>(
        KEY_256, CIPHERTEXTS_256,
    );
}

/// The same plaintext under the three different key sizes must give three different ciphertexts.
/// This catches an engine that ignored part of the key, or that used the wrong round count.
#[test]
fn the_three_variants_are_distinct() {
    assert_ne!(CIPHERTEXTS_128[0], CIPHERTEXTS_192[0]);
    assert_ne!(CIPHERTEXTS_128[0], CIPHERTEXTS_256[0]);
    assert_ne!(CIPHERTEXTS_192[0], CIPHERTEXTS_256[0]);
}

/* *** Behavioural properties *** */

/// Encryption must be a permutation: every block must round-trip, including the degenerate
/// all-zero and all-ones blocks, and no two distinct blocks may encrypt to the same ciphertext.
#[test]
fn every_variant_round_trips_and_is_injective() {
    let key128 = key_from_hex::<AES128_KEY_LEN>(KEY_128);
    let key192 = key_from_hex::<AES192_KEY_LEN>(KEY_192);
    let key256 = key_from_hex::<AES256_KEY_LEN>(KEY_256);

    let aes128 = AES128::new(&key128).unwrap();
    let aes192 = AES192::new(&key192).unwrap();
    let aes256 = AES256::new(&key256).unwrap();

    // 258 blocks: all-zero, all-ones, and one block filled with each byte value.
    let mut blocks = Vec::new();
    blocks.push([0x00u8; AES_BLOCK_LEN]);
    blocks.push([0xFFu8; AES_BLOCK_LEN]);
    for filler in 0..=u8::MAX {
        let mut block = [filler; AES_BLOCK_LEN];
        // Vary within the block too, so a bug that only shows up on non-uniform blocks is caught.
        block[0] = filler.wrapping_mul(31);
        block[AES_BLOCK_LEN - 1] = !filler;
        blocks.push(block);
    }

    let mut ciphertexts_128 = Vec::with_capacity(blocks.len());
    for block in blocks.iter() {
        let ct128 = aes128.encrypt_block(block);
        let ct192 = aes192.encrypt_block(block);
        let ct256 = aes256.encrypt_block(block);

        assert_eq!(&aes128.decrypt_block(&ct128), block, "AES-128 round trip");
        assert_eq!(&aes192.decrypt_block(&ct192), block, "AES-192 round trip");
        assert_eq!(&aes256.decrypt_block(&ct256), block, "AES-256 round trip");

        // A block must never encrypt to itself, and the three variants must disagree.
        assert_ne!(&ct128, block);
        assert_ne!(ct128, ct192);
        assert_ne!(ct128, ct256);

        ciphertexts_128.push(ct128);
    }

    // Injectivity: distinct inputs give distinct outputs.
    let mut sorted = ciphertexts_128.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ciphertexts_128.len(), "two distinct blocks collided");
}

/// The engine is deterministic and stateless across calls: the same block encrypts to the same
/// ciphertext every time, and interleaving encryptions and decryptions changes nothing.
///
/// This is a property of the raw permutation, not a bug -- but it is also precisely why using the
/// engine directly on multi-block data (ie ECB) leaks plaintext structure, so it is worth pinning
/// as documented behaviour.
#[test]
fn the_engine_is_stateless_and_deterministic() {
    let key = key_from_hex::<AES128_KEY_LEN>(KEY_128);
    let engine = AES128::new(&key).unwrap();

    let a = block_from_hex(PLAINTEXTS[0]);
    let b = block_from_hex(PLAINTEXTS[1]);

    let first = engine.encrypt_block(&a);
    let _ = engine.encrypt_block(&b);
    let _ = engine.decrypt_block(&first);
    let second = engine.encrypt_block(&a);

    assert_eq!(first, second);
    assert_eq!(hex::encode(first), CIPHERTEXTS_128[0]);
}

/// Flipping a single bit of the plaintext must change roughly half the ciphertext bits, and must
/// never leave the ciphertext unchanged (the avalanche property). A cheap end-to-end check that all
/// the diffusion layers are actually wired in.
#[test]
fn flipping_one_plaintext_bit_avalanches() {
    let key = key_from_hex::<AES128_KEY_LEN>(KEY_128);
    let engine = AES128::new(&key).unwrap();

    let plaintext = block_from_hex(PLAINTEXTS[0]);
    let baseline = engine.encrypt_block(&plaintext);

    for bit in 0..(AES_BLOCK_LEN * 8) {
        let mut flipped = plaintext;
        flipped[bit / 8] ^= 1 << (bit % 8);
        let ciphertext = engine.encrypt_block(&flipped);

        assert_ne!(ciphertext, baseline, "flipping plaintext bit {bit} changed nothing");

        let differing_bits: u32 =
            ciphertext.iter().zip(baseline.iter()).map(|(a, b)| (a ^ b).count_ones()).sum();
        // Expect ~64 of 128 bits to change. A generous window: anything outside it means the
        // diffusion is broken, not that we got unlucky.
        assert!(
            (32..=96).contains(&differing_bits),
            "flipping plaintext bit {bit} changed {differing_bits} of 128 ciphertext bits"
        );
    }
}

/// The same avalanche property for a single-bit change in the *key*, which exercises the key
/// expansion rather than the round function.
#[test]
fn flipping_one_key_bit_avalanches() {
    let key_bytes = hex::decode(KEY_128).unwrap();
    let plaintext = block_from_hex(PLAINTEXTS[0]);

    let baseline = {
        let key = AES128Key::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey).unwrap();
        AES128::new(&key).unwrap().encrypt_block(&plaintext)
    };

    for bit in 0..(AES128_KEY_LEN * 8) {
        let mut flipped_bytes = key_bytes.clone();
        flipped_bytes[bit / 8] ^= 1 << (bit % 8);
        let key =
            AES128Key::from_bytes_as_type(&flipped_bytes, KeyType::SymmetricCipherKey).unwrap();
        let ciphertext = AES128::new(&key).unwrap().encrypt_block(&plaintext);

        assert_ne!(ciphertext, baseline, "flipping key bit {bit} changed nothing");

        let differing_bits: u32 =
            ciphertext.iter().zip(baseline.iter()).map(|(a, b)| (a ^ b).count_ones()).sum();
        assert!(
            (32..=96).contains(&differing_bits),
            "flipping key bit {bit} changed {differing_bits} of 128 ciphertext bits"
        );
    }
}

/* *** Key validation *** */

/// A key tagged for a different algorithm must be refused: key separation between primitives is a
/// security property.
#[test]
fn rejects_a_key_of_the_wrong_type() {
    let key_bytes = hex::decode(KEY_128).unwrap();

    for wrong_type in [KeyType::MACKey, KeyType::Seed, KeyType::Unknown] {
        let key = AES128Key::from_bytes_as_type(&key_bytes, wrong_type).unwrap();
        match AES128::new(&key) {
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {
                /* good */
            }
            other => panic!("expected InvalidKeyType for {wrong_type:?}, got {other:?}"),
        }
    }

    // The two accepted types must in fact be accepted.
    for right_type in [KeyType::SymmetricCipherKey, KeyType::CryptographicRandom] {
        let key = AES128Key::from_bytes_as_type(&key_bytes, right_type).unwrap();
        assert!(AES128::new(&key).is_ok(), "{right_type:?} should be accepted");
    }
}

/// An all-zero key arrives tagged [`KeyType::Zeroized`] and must be refused, so that a caller who
/// accidentally passes an uninitialized buffer gets an error rather than a working cipher under a
/// guessable key.
#[test]
fn rejects_an_all_zero_key() {
    // from_bytes_as_type() reports the all-zero input and tags the key Zeroized.
    let mut key = AES128Key::new();
    let flagged = key.set_bytes_as_type(&[0u8; AES128_KEY_LEN], KeyType::SymmetricCipherKey);
    assert!(flagged.is_err(), "KeyMaterial should flag an all-zero key");

    match AES128::new(&key) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {
            /* good */
        }
        other => panic!("expected InvalidKeyType for an all-zero key, got {other:?}"),
    }
}

/// A key holding fewer bytes than the variant needs must be refused rather than silently
/// zero-padded. (It cannot hold more: the [`KeyMaterial`] capacity is the key length.)
#[test]
fn rejects_a_short_key() {
    let short = AES256Key::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
    assert_eq!(short.key_len(), 16);

    match AES256::new(&short) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength)) => {
            /* good */
        }
        other => panic!("expected InvalidLength for a short key, got {other:?}"),
    }
}

/// A key tagged at a lower security strength than the variant provides must be refused: otherwise
/// an application could believe it had 256-bit security while keying AES-256 from 128 bits of
/// entropy.
#[test]
fn rejects_a_key_weaker_than_the_algorithm() {
    let mut key = key_from_hex::<AES256_KEY_LEN>(KEY_256);
    assert_eq!(key.security_strength(), SecurityStrength::_256bit);

    // Lowering the recorded strength does not need a hazardous-operations closure; only raising it
    // does. This models a 32-byte key that was derived from a weaker source.
    key.set_security_strength(SecurityStrength::_128bit).unwrap();

    match AES256::new(&key) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {
            /* good */
        }
        other => panic!("expected SecurityStrength for a weak key, got {other:?}"),
    }

    // The same key material is fine for AES-128, whose strength requirement it does meet.
    let mut key128 = key_from_hex::<AES128_KEY_LEN>(KEY_128);
    assert_eq!(key128.security_strength(), SecurityStrength::_128bit);
    assert!(AES128::new(&key128).is_ok());

    key128.set_security_strength(SecurityStrength::_112bit).unwrap();
    assert!(AES128::new(&key128).is_err(), "AES-128 must require 128-bit key strength");
}

/* *** Metadata, memory and hygiene *** */

/// The [`Algorithm`] and [`AESEngine`] constants must match FIPS 197 Table 3.
#[test]
fn algorithm_metadata_matches_fips197_table_3() {
    assert_eq!(AES128::ALG_NAME, "AES-128");
    assert_eq!(AES192::ALG_NAME, "AES-192");
    assert_eq!(AES256::ALG_NAME, "AES-256");

    assert_eq!(AES128::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(AES192::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(AES256::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);

    // Key lengths: Nk = 4, 6, 8 words.
    assert_eq!(<AES128 as AESEngine>::KEY_LEN, 16);
    assert_eq!(<AES192 as AESEngine>::KEY_LEN, 24);
    assert_eq!(<AES256 as AESEngine>::KEY_LEN, 32);

    // Round counts: Nr = 10, 12, 14.
    assert_eq!(<AES128 as AESEngine>::NUM_ROUNDS, 10);
    assert_eq!(<AES192 as AESEngine>::NUM_ROUNDS, 12);
    assert_eq!(<AES256 as AESEngine>::NUM_ROUNDS, 14);

    // Every variant has a 128-bit block.
    assert_eq!(AES_BLOCK_LEN, 16);
    assert_eq!(<AES128 as AESEngine>::BLOCK_LEN, AES_BLOCK_LEN);
    assert_eq!(<AES192 as AESEngine>::BLOCK_LEN, AES_BLOCK_LEN);
    assert_eq!(<AES256 as AESEngine>::BLOCK_LEN, AES_BLOCK_LEN);

    // The key schedule holds 4 * (Nr + 1) words.
    assert_eq!(AES128_KEY_SCHEDULE_WORDS, 44);
    assert_eq!(AES192_KEY_SCHEDULE_WORDS, 52);
    assert_eq!(AES256_KEY_SCHEDULE_WORDS, 60);
}

/// Pins the struct sizes quoted in the crate's "Memory Usage" documentation, so that the table
/// cannot silently go stale.
#[test]
fn struct_sizes_match_the_documented_memory_usage() {
    assert_eq!(size_of::<AES128>(), 176);
    assert_eq!(size_of::<AES192>(), 208);
    assert_eq!(size_of::<AES256>(), 240);

    // ie exactly the key schedule and nothing else.
    assert_eq!(size_of::<AES128>(), AES128_KEY_SCHEDULE_WORDS * size_of::<u32>());
    assert_eq!(size_of::<AES192>(), AES192_KEY_SCHEDULE_WORDS * size_of::<u32>());
    assert_eq!(size_of::<AES256>(), AES256_KEY_SCHEDULE_WORDS * size_of::<u32>());
}

/// Debug formatting must never expose the key schedule, which is recoverable back to the cipher
/// key. A regression here would leak keys into logs and panic messages.
#[test]
fn debug_output_does_not_leak_key_material() {
    let key = key_from_hex::<AES128_KEY_LEN>(KEY_128);
    let engine = AES128::new(&key).unwrap();

    let rendered = format!("{engine:?}");
    assert!(rendered.contains("redacted"), "Debug output should say it is redacted: {rendered}");

    // None of the key bytes, and no word of the first round key, may appear in any form.
    for byte_pair in ["2b7e", "28ae", "abf7", "09cf", "a0fa", "fe17"] {
        assert!(!rendered.contains(byte_pair), "Debug output leaked {byte_pair}: {rendered}");
    }
}

/// A cloned engine must behave identically to the original: cloning duplicates the key schedule and
/// nothing else.
#[test]
fn a_cloned_engine_encrypts_identically() {
    let key = key_from_hex::<AES192_KEY_LEN>(KEY_192);
    let engine = AES192::new(&key).unwrap();
    let clone = engine.clone();

    let plaintext = block_from_hex(PLAINTEXTS[2]);
    assert_eq!(engine.encrypt_block(&plaintext), clone.encrypt_block(&plaintext));
    assert_eq!(hex::encode(clone.encrypt_block(&plaintext)), CIPHERTEXTS_192[2]);
}
