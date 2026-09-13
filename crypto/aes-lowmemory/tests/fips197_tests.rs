//! Known-answer tests from NIST FIPS 197 itself.
//!
//! Appendix B -- the worked single-block AES-128 encryption -- plus its inverse, the two-block
//! path, and key-handling behaviour.
//!
//! The Appendix A key expansions are **not** tested here. The key schedule is deliberately not
//! public API (it is a `Secret` field), and a round-trip through the cipher cannot check it: a
//! wrong `w[i]` is used by encryption and decryption alike, so the round trip still succeeds.
//! Every word of all three expansions is instead checked against Appendix A inside
//! `src/schedule.rs`, where the stored schedule can be decompressed and compared directly.
//!
//! Known-answer coverage for AES-192 and AES-256, which Appendix B does not reach, is in
//! `sp800_38a_tests.rs` and `acvp_tests.rs`.
//!
//! All values here are transcribed from the published FIPS 197 (Update 1) PDF.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::SecurityStrength;

/// Appendix A.1 / Appendix B key: `2b7e151628aed2a6abf7158809cf4f3c`.
const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

/// Appendix A.2 key: `8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b`.
const KEY_192: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
];

/// Appendix A.3 key:
/// `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`.
const KEY_256: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

fn key_material<const N: usize>(bytes: &[u8; N]) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

#[test]
fn appendix_b_encrypts_the_documented_block() {
    // Appendix B: Input = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
    //             Key   = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    // The final state printed as "output" reads, column by column (Eq 3.7):
    //             39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
    let aes = Aes128::new(&key_material(&KEY_128)).unwrap();

    let mut block = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    aes.encrypt_block(&mut block);
    assert_eq!(
        block,
        [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32
        ]
    );
}

#[test]
fn appendix_b_decrypts_back_to_the_documented_input() {
    let aes = Aes128::new(&key_material(&KEY_128)).unwrap();

    let mut block = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b,
        0x32,
    ];
    aes.decrypt_block(&mut block);
    assert_eq!(
        block,
        [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34
        ]
    );
}

#[test]
fn appendix_b_two_block_path_agrees_with_the_single_block_path() {
    let aes = Aes128::new(&key_material(&KEY_128)).unwrap();
    let input = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    let expected = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b,
        0x32,
    ];

    // Pairing the Appendix B block with an unrelated one must not disturb either half.
    let other = [0xAAu8; 16];
    let mut other_alone = other;
    aes.encrypt_block(&mut other_alone);

    let mut pair = [input, other];
    aes.encrypt_blocks2(&mut pair);
    assert_eq!(pair[0], expected);
    assert_eq!(pair[1], other_alone);

    // ...and in the other slot, which is a different bit position in the interleave.
    let mut pair = [other, input];
    aes.encrypt_blocks2(&mut pair);
    assert_eq!(pair[0], other_alone);
    assert_eq!(pair[1], expected);
}

/// Encryption and decryption are inverses, under each Appendix A key.
///
/// This checks `decrypt_block` really inverts `encrypt_block` from the same stored schedule,
/// which is the load-bearing claim of following FIPS 197 Algorithm 3 rather than Sec 5.3.5. It
/// deliberately makes no claim about the schedule being *correct* -- see the module docs.
#[test]
fn encryption_and_decryption_are_inverses_for_all_three_key_lengths() {
    let aes128 = Aes128::new(&key_material(&KEY_128)).unwrap();
    let aes192 = Aes192::new(&key_material(&KEY_192)).unwrap();
    let aes256 = Aes256::new(&key_material(&KEY_256)).unwrap();

    for block in [[0u8; 16], [0xFFu8; 16], core::array::from_fn(|i| i as u8)] {
        let mut b = block;
        aes128.encrypt_block(&mut b);
        assert_ne!(b, block, "AES-128 must actually transform the block");
        aes128.decrypt_block(&mut b);
        assert_eq!(b, block, "AES-128 round trip with the Appendix A.1 key");

        let mut b = block;
        aes192.encrypt_block(&mut b);
        assert_ne!(b, block, "AES-192 must actually transform the block");
        aes192.decrypt_block(&mut b);
        assert_eq!(b, block, "AES-192 round trip with the Appendix A.2 key");

        let mut b = block;
        aes256.encrypt_block(&mut b);
        assert_ne!(b, block, "AES-256 must actually transform the block");
        aes256.decrypt_block(&mut b);
        assert_eq!(b, block, "AES-256 round trip with the Appendix A.3 key");
    }
}

/// The three key lengths must give different results for the same input.
///
/// Guards against a parameter set silently using another set's `Nr` or `Nk`.
#[test]
fn the_three_key_lengths_are_distinct_permutations() {
    // A key whose first 16 bytes are shared, so only Nk/Nr and the extra key bytes differ.
    let shared = [0x11u8; 32];
    let aes128 = Aes128::new(&key_material::<16>(&shared[..16].try_into().unwrap())).unwrap();
    let aes192 = Aes192::new(&key_material::<24>(&shared[..24].try_into().unwrap())).unwrap();
    let aes256 = Aes256::new(&key_material(&shared)).unwrap();

    let block = [0x42u8; 16];
    let mut b128 = block;
    let mut b192 = block;
    let mut b256 = block;
    aes128.encrypt_block(&mut b128);
    aes192.encrypt_block(&mut b192);
    aes256.encrypt_block(&mut b256);

    assert_ne!(b128, b192);
    assert_ne!(b192, b256);
    assert_ne!(b128, b256);
}

// ---- key handling -----------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    // KeyType::Seed is not a cipher key: a seed reused directly as an AES key is a real mistake
    // and the type system tracks enough to catch it.
    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x01; 16], KeyType::Seed).unwrap();
    assert!(Aes128::new(&key).is_err());

    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x01; 16], KeyType::MACKey).unwrap();
    assert!(Aes128::new(&key).is_err());
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    // The capacity is right but only part of it is populated, so `key_len()` disagrees with the
    // parameter set. This is the one length error the const generic cannot catch by itself.
    let key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x01; 16], KeyType::SymmetricCipherKey).unwrap();
    assert!(Aes256::new(&key).is_err());
}

#[test]
fn a_key_carrying_too_low_a_security_strength_is_rejected() {
    // A full-length key whose material was only ever derived at a lower security strength must
    // not be usable at the strength its length implies. `from_bytes_as_type` tags a 32-byte key
    // as 256-bit, so lower it deliberately -- lowering does not need a hazardous closure, only
    // raising does.
    let mut key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x01; 32], KeyType::SymmetricCipherKey).unwrap();
    assert_eq!(key.security_strength(), SecurityStrength::_256bit);

    key.set_security_strength(SecurityStrength::_128bit).unwrap();
    assert!(
        Aes256::new(&key).is_err(),
        "AES-256 must reject a 32-byte key only derived at the 128-bit strength"
    );

    // The same key at its full strength is fine, so the rejection is about the strength tag and
    // not about anything else having gone wrong with the key.
    let good =
        KeyMaterial::<32>::from_bytes_as_type(&[0x01; 32], KeyType::SymmetricCipherKey).unwrap();
    assert!(Aes256::new(&good).is_ok());
}

#[test]
fn a_correctly_typed_key_of_each_length_is_accepted() {
    assert!(Aes128::new(&key_material(&KEY_128)).is_ok());
    assert!(Aes192::new(&key_material(&KEY_192)).is_ok());
    assert!(Aes256::new(&key_material(&KEY_256)).is_ok());
}

#[test]
fn debug_does_not_print_the_key_schedule() {
    // The schedule is secret; `Debug` must not be a way to leak it.
    let aes = Aes128::new(&key_material(&KEY_128)).unwrap();
    let rendered = format!("{aes:?}");
    assert_eq!(rendered, "AES-128");
    // No byte of the key should appear as hex in the output.
    assert!(!rendered.contains("2b"));
    assert!(!rendered.contains("7e"));
}
