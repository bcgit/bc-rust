//! Known-answer tests from NIST SP 800-38A Appendix F.3, "CFB Example Vectors".
//!
//! Sections **F.3.7 through F.3.12**: CFB8-AES128, CFB8-AES192 and CFB8-AES256, Encrypt and
//! Decrypt. These are the `s = 8` subsections, the ones [`Cfb8`] implements. The `s = b`
//! subsections F.3.13-F.3.18 belong to [`Cfb`](bouncycastle_modes::Cfb) and are in
//! `sp800_38a_cfb_tests.rs`; F.3.1-F.3.6 are CFB1, which this crate does not provide.
//!
//! All six share the same IV. The plaintext is the **first 18 bytes** of the Appendix F plaintext:
//! the preamble notes that the CFB1 and CFB8 subsections truncate it, and each of these tabulates
//! 18 one-byte segments. Only the key and the resulting ciphertext differ between key lengths, and
//! the three keys are the same three used throughout Appendix F.
//!
//! Transcribed from the published SP 800-38A PDF (2001 edition).
//!
//! # The shift register is checked against the spec's own table
//!
//! Each F.3 subsection tabulates the **input block** and the **output block** for every segment.
//! For CFB8 those columns are the whole mechanism: the input block is the shift register, and the
//! output block is what `MSB_8` takes its byte from. `the_tabulated_blocks_are_the_shift_register`
//! transcribes all 18 of each for F.3.7 and checks them three ways -- that each input block is the
//! previous one shifted left by a byte with the ciphertext byte appended, that each output block is
//! the raw permutation applied to it, and that the ciphertext is the plaintext XOR its first byte.
//! A mode that produced the right ciphertext by some other route would still have to match them.
//! That check is key-independent, so it is done once rather than for all three key lengths.
//!
//! # Driving the IV
//!
//! There is no API for supplying an IV -- see the crate docs. Encryption is therefore driven
//! through [`StreamCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is
//! the vector's IV, and the test asserts the returned init data really is that IV before comparing
//! any ciphertext. Decryption takes the IV directly, as init data.

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cfb8, Decrypting, Encrypting};

const BLOCK_LEN: usize = 16;

/// The IV shared by every Appendix F.3 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The 18 one-byte plaintext segments shared by every CFB8 subsection: the first 18 bytes of the
/// Appendix F plaintext, which the CFB1 and CFB8 subsections truncate to.
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d";

/// F.3.7 / F.3.8 key.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// F.3.7 CFB8-AES128.Encrypt ciphertext segments.
const CIPHERTEXT_128: &str = "3b79424c9c0dd436bace9e0ed4586a4f32b9";

/// F.3.9 / F.3.10 key.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// F.3.9 CFB8-AES192.Encrypt ciphertext segments.
const CIPHERTEXT_192: &str = "cda2521ef0a905ca44cd057cbf0d47a0678a";

/// F.3.11 / F.3.12 key.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
/// F.3.11 CFB8-AES256.Encrypt ciphertext segments.
const CIPHERTEXT_256: &str = "dc1f1a8520a64db55fcc8ac554844e889700";

/// F.3.7 CFB8-AES128.Encrypt, the "Input Block" column: the shift register at each segment.
const INPUT_BLOCKS_128: [&str; 18] = [
    "000102030405060708090a0b0c0d0e0f",
    "0102030405060708090a0b0c0d0e0f3b",
    "02030405060708090a0b0c0d0e0f3b79",
    "030405060708090a0b0c0d0e0f3b7942",
    "0405060708090a0b0c0d0e0f3b79424c",
    "05060708090a0b0c0d0e0f3b79424c9c",
    "060708090a0b0c0d0e0f3b79424c9c0d",
    "0708090a0b0c0d0e0f3b79424c9c0dd4",
    "08090a0b0c0d0e0f3b79424c9c0dd436",
    "090a0b0c0d0e0f3b79424c9c0dd436ba",
    "0a0b0c0d0e0f3b79424c9c0dd436bace",
    "0b0c0d0e0f3b79424c9c0dd436bace9e",
    "0c0d0e0f3b79424c9c0dd436bace9e0e",
    "0d0e0f3b79424c9c0dd436bace9e0ed4",
    "0e0f3b79424c9c0dd436bace9e0ed458",
    "0f3b79424c9c0dd436bace9e0ed4586a",
    "3b79424c9c0dd436bace9e0ed4586a4f",
    "79424c9c0dd436bace9e0ed4586a4f32",
];

/// F.3.7 CFB8-AES128.Encrypt, the "Output Block" column: `Oj = CIPH_K(Ij)`, of which CFB8 uses
/// only the first byte.
const OUTPUT_BLOCKS_128: [&str; 18] = [
    "50fe67cc996d32b6da0937e99bafec60",
    "b8eb865a2b026381abb1d6560ed20f68",
    "fce6033b4edce64cbaed3f61ff5b927c",
    "ae4e5e7ffe805f7a4395b180004f8ca8",
    "b205eb89445b62116f1deb988a81e6dd",
    "4d21d456a5e239064fff4be0c0f85488",
    "4b2f5c3895b9efdc85ee0c5178c7fd33",
    "a0976d856da260a34104d1a80953db4c",
    "53674e5890a2c71b0f6a27a094e5808c",
    "f34cd32ffed495f8bc8adba194eccb7a",
    "e08cf2407d7ed676c9049586f1d48ba6",
    "1f5c88a19b6ca28e99c9aeb8982a6dd8",
    "a70e63df781cf395a208bd2365c8779b",
    "cbcfe8b3bcf9ac202ce18420013319ab",
    "7d9fac6604b3c8c5b1f8c5a00956cf56",
    "65c3fa64bf0343986825c636f4a1efd2",
    "9cff5e5ff4f554d56c924b9d6a6de21d",
    "946c3dc1584cc18400ecd8c6052c44b1",
];

fn block(hex_str: &str) -> [u8; BLOCK_LEN] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

fn bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let raw = hex::decode(hex_str).expect("valid hex");
    assert_eq!(raw.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&raw, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Chunk sizes that cut across the eight-byte batch and the 16-byte block: 1 is the single-byte
/// path only, 8 is exactly the batch, and the rest leave a different remainder each call.
const CHUNKINGS: [usize; 6] = [1, 3, 8, 9, 17, 18];

/// Runs one Appendix F.3 CFB8 encrypt subsection.
///
/// Checks the whole message in one call, then in every chunking above -- the vector should not care
/// how the calls are grouped.
fn check_encrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, expected_hex: &str)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let plaintext = bytes(PLAINTEXT);
    let expected = bytes(expected_hex);
    assert_eq!(plaintext.len(), 18, "{section}: the CFB8 subsections use 18 one-byte segments");

    for chunk in [plaintext.len()].into_iter().chain(CHUNKINGS) {
        let (mut enc, got_iv) = Cfb8::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
        )
        .unwrap();
        assert_eq!(got_iv, iv, "{section}: the pinned RNG should produce the vector's IV");

        let mut data = plaintext.clone();
        for piece in data.chunks_mut(chunk) {
            enc.do_encrypt(piece).unwrap();
        }
        assert_eq!(data, expected, "{section}: {chunk}-byte calls");
    }
}

/// Runs one Appendix F.3 CFB8 decrypt subsection.
fn check_decrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, ciphertext_hex: &str)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let plaintext = bytes(PLAINTEXT);
    let ciphertext = bytes(ciphertext_hex);

    for chunk in [ciphertext.len()].into_iter().chain(CHUNKINGS) {
        let mut dec =
            Cfb8::<P, Decrypting, KEY_LEN, BLOCK_LEN>::do_decrypt_init(&key, &iv).unwrap();
        let mut data = ciphertext.clone();
        for piece in data.chunks_mut(chunk) {
            dec.do_decrypt(piece).unwrap();
        }
        assert_eq!(data, plaintext, "{section}: {chunk}-byte calls");
    }

    // ...and the one-shot, where the IV is an input.
    let mut data = ciphertext.clone();
    Cfb8::<P, Decrypting, KEY_LEN, BLOCK_LEN>::decrypt(&key, &iv, &mut data).unwrap();
    assert_eq!(data, plaintext, "{section}: one-shot");
}

#[test]
fn f_3_7_cfb8_aes128_encrypt() {
    check_encrypt::<AES_128, 16>("F.3.7", KEY_128, CIPHERTEXT_128);
}

#[test]
fn f_3_8_cfb8_aes128_decrypt() {
    check_decrypt::<AES_128, 16>("F.3.8", KEY_128, CIPHERTEXT_128);
}

#[test]
fn f_3_9_cfb8_aes192_encrypt() {
    check_encrypt::<AES_192, 24>("F.3.9", KEY_192, CIPHERTEXT_192);
}

#[test]
fn f_3_10_cfb8_aes192_decrypt() {
    check_decrypt::<AES_192, 24>("F.3.10", KEY_192, CIPHERTEXT_192);
}

#[test]
fn f_3_11_cfb8_aes256_encrypt() {
    check_encrypt::<AES_256, 32>("F.3.11", KEY_256, CIPHERTEXT_256);
}

#[test]
fn f_3_12_cfb8_aes256_decrypt() {
    check_decrypt::<AES_256, 32>("F.3.12", KEY_256, CIPHERTEXT_256);
}

/// The spec's tabulated **Input Blocks** are the shift register and its **Output Blocks** are
/// `CIPH_K` of them. Both fall straight out of Sec 6.3 with `s = 8`:
///
/// ```text
/// I1 = IV;  Ij = LSB_{b-8}(I_{j-1}) | C_{j-1};  Oj = CIPH_K(Ij);  Cj = Pj XOR MSB_8(Oj)
/// ```
///
/// Checking all three relations against F.3.7's own table pins the mode's internals rather than
/// just its final output, and it confirms the transcription: the input, output, plaintext and
/// ciphertext columns are related by a shift, a cipher call and an XOR, none of which would survive
/// a typo in any of them.
#[test]
fn the_tabulated_blocks_are_the_shift_register() {
    let key = key_material::<16>(KEY_128);
    let perm = <AES_128 as ElectronicCodeBook<16, BLOCK_LEN>>::new(&key).expect("a valid key");
    let plaintext = bytes(PLAINTEXT);
    let ciphertext = bytes(CIPHERTEXT_128);

    for j in 0..18 {
        let input_block = block(INPUT_BLOCKS_128[j]);
        let output_block = block(OUTPUT_BLOCKS_128[j]);

        // I1 = IV, and Ij = LSB_{b-8}(I_{j-1}) | C_{j-1} thereafter.
        if j == 0 {
            assert_eq!(input_block, block(IV), "F.3.7: I1 must be the IV");
        } else {
            let previous = block(INPUT_BLOCKS_128[j - 1]);
            let mut expected = [0u8; BLOCK_LEN];
            expected[..BLOCK_LEN - 1].copy_from_slice(&previous[1..]);
            expected[BLOCK_LEN - 1] = ciphertext[j - 1];
            assert_eq!(
                input_block,
                expected,
                "F.3.7: I{} should be I{} shifted left one byte with C{} appended",
                j + 1,
                j,
                j
            );
        }

        // Oj = CIPH_K(Ij) -- the *forward* cipher function, which is all CFB ever uses.
        let mut computed = input_block;
        perm.encrypt_block(&mut computed);
        assert_eq!(
            computed,
            output_block,
            "F.3.7: tabulated output block #{} should be CIPH_K of input block #{}",
            j + 1,
            j + 1
        );

        // Cj = Pj XOR MSB_8(Oj): the first byte of the output block, the rest discarded.
        assert_eq!(
            ciphertext[j],
            plaintext[j] ^ output_block[0],
            "F.3.7: Cj = Pj XOR MSB_8(Oj) for segment #{}",
            j + 1
        );
    }
}

/// CFB8 and CFB128 agree on the **first** byte and on nothing after it.
///
/// Both set `I1 = IV` and `O1 = CIPH_K(IV)`, and both XOR the leading byte of `O1` into the first
/// plaintext byte, so `C1` is necessarily the same. They diverge immediately after, because CFB128
/// replaces the whole input block with the ciphertext block while CFB8 shifts one byte in.
///
/// The values below are quoted from **F.3.13 (CFB128-AES128.Encrypt)**, a different subsection from
/// the ones this file is testing, so agreement on byte 1 is an independent check that the F.3.7
/// transcription is right, and disagreement on byte 2 is a check that [`Cfb8`] is CFB8 and not
/// CFB128.
#[test]
fn cfb8_agrees_with_cfb128_on_the_first_byte_only() {
    /// F.3.13 CFB128-AES128.Encrypt, ciphertext segment #1 (16 bytes).
    const CFB128_C1: &str = "3b3fd92eb72dad20333449f8e83cfb4a";

    let cfb128_c1 = bytes(CFB128_C1);
    let cfb8_ct = bytes(CIPHERTEXT_128);

    assert_eq!(
        cfb8_ct[0], cfb128_c1[0],
        "F.3.7 and F.3.13 must agree on the first byte: both are P1 XOR MSB_8(CIPH_K(IV))"
    );
    assert_ne!(
        cfb8_ct[1], cfb128_c1[1],
        "the second byte must differ: CFB8 shifts the register, CFB128 replaces it"
    );
}
