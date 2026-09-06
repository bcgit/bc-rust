//! Known-answer tests from NIST SP 800-38A Appendix F.2, "CBC Example Vectors".
//!
//! Sections F.2.1 through F.2.6: CBC-AES128, CBC-AES192 and CBC-AES256, Encrypt and Decrypt. All
//! six share the same IV and the same four plaintext blocks (Appendix F preamble); only the key and
//! the resulting ciphertext differ. The three keys are the same three used by FIPS 197 Appendix A
//! and SP 800-38A F.1, so these vectors also re-check each AES key expansion through a second
//! construction.
//!
//! Transcribed from the published SP 800-38A PDF (2001 edition).
//!
//! # Driving the IV
//!
//! There is no API for supplying an IV -- see the crate docs. Encryption is therefore driven
//! through [`BlockCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is
//! the vector's IV, and the test asserts the returned init data really is that IV before comparing
//! any ciphertext. Decryption takes the IV directly, as init data.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};

const BLOCK_LEN: usize = 16;

/// The IV shared by every Appendix F.2 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four plaintext blocks shared by every Appendix F subsection (Appendix F preamble).
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// F.2.1 / F.2.2 key.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// F.2.1 CBC-AES128.Encrypt output blocks.
const CIPHERTEXTS_128: [&str; 4] = [
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
];

/// F.2.3 / F.2.4 key.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// F.2.3 CBC-AES192.Encrypt output blocks.
const CIPHERTEXTS_192: [&str; 4] = [
    "4f021db243bc633d7178183a9fa071e8",
    "b4d9ada9ad7dedf4e5e738763f69145a",
    "571b242012fb7ae07fa9baac3df102e0",
    "08b0e27988598881d920a9e64f5615cd",
];

/// F.2.5 / F.2.6 key.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
/// F.2.5 CBC-AES256.Encrypt output blocks.
const CIPHERTEXTS_256: [&str; 4] = [
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    "9cfc4e967edb808d679f777bc6702c7d",
    "39f23369a9d9bacfa530e26304231461",
    "b2eb05e2c39be9fcda6c19078c6a9d1b",
];

fn block(hex_str: &str) -> [u8; BLOCK_LEN] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

fn blocks(hex_strs: &[&str; 4]) -> [[u8; BLOCK_LEN]; 4] {
    core::array::from_fn(|i| block(hex_strs[i]))
}

/// The same four blocks as 64 contiguous bytes, for the flat streaming and one-shot methods.
fn flat(hex_strs: &[&str; 4]) -> [u8; 4 * BLOCK_LEN] {
    blocks(hex_strs).as_flattened().try_into().expect("4 blocks = 64 bytes")
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Runs one Appendix F.2 encrypt subsection.
///
/// Checks the whole message in one call, then again one block at a time, then again through the
/// implementor hook -- the vector should not care how the calls are grouped.
fn check_encrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, expected: &[&str; 4])
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(expected);

    // All four blocks in one call.
    let (mut enc, got_iv) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .unwrap();
    assert_eq!(got_iv, iv, "{section}: the pinned RNG should produce the vector's IV");
    let mut data = flat(&PLAINTEXTS);
    enc.do_encrypt(&mut data).unwrap();
    assert_eq!(data, flat(expected), "{section}: four blocks in one call");

    // One block at a time.
    let (mut enc, _) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .unwrap();
    for (i, (p, c)) in pt.iter().zip(ct.iter()).enumerate() {
        let mut got = *p;
        enc.do_encrypt(&mut got).unwrap();
        assert_eq!(&got, c, "{section}: block #{}", i + 1);
    }

    // Through the implementor hook, `do_*_blocks`.
    let (mut enc, _) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .unwrap();
    let mut blocks = pt;
    enc.do_encrypt_blocks(&mut blocks).unwrap();
    assert_eq!(blocks, ct, "{section}: implementor hook");
}

/// Runs one Appendix F.2 decrypt subsection.
///
/// Checks one call, one block at a time, and the odd grouping `3 + 1` -- which is the grouping that
/// leaves a one-block remainder after the pair loop in `do_decrypt_blocks`.
fn check_decrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, ciphertext: &[&str; 4])
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(ciphertext);

    type Dec<P, const K: usize> = Cbc<P, Decrypting, K, BLOCK_LEN>;

    // All four blocks in one call (two pairs, no remainder).
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    let mut data = flat(ciphertext);
    dec.do_decrypt(&mut data).unwrap();
    assert_eq!(data, flat(&PLAINTEXTS), "{section}: four blocks in one call");

    // One block at a time (never takes the pair path).
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    for (i, (c, p)) in ct.iter().zip(pt.iter()).enumerate() {
        let mut got = *c;
        dec.do_decrypt(&mut got).unwrap();
        assert_eq!(&got, p, "{section}: block #{}", i + 1);
    }

    // 3 + 1: one pair plus a remainder, then a lone block.
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    let mut three: [u8; 3 * BLOCK_LEN] = ct[..3].as_flattened().try_into().unwrap();
    dec.do_decrypt(&mut three).unwrap();
    let mut one = ct[3];
    dec.do_decrypt(&mut one).unwrap();
    assert_eq!(&three[..], pt[..3].as_flattened(), "{section}: blocks 1-3");
    assert_eq!(one, pt[3], "{section}: block 4");

    // Through the implementor hook, `do_*_blocks`.
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    let mut blocks = ct;
    dec.do_decrypt_blocks(&mut blocks).unwrap();
    assert_eq!(blocks, pt, "{section}: implementor hook");
}

#[test]
fn f_2_1_cbc_aes128_encrypt() {
    check_encrypt::<Aes128, 16>("F.2.1", KEY_128, &CIPHERTEXTS_128);
}

#[test]
fn f_2_2_cbc_aes128_decrypt() {
    check_decrypt::<Aes128, 16>("F.2.2", KEY_128, &CIPHERTEXTS_128);
}

#[test]
fn f_2_3_cbc_aes192_encrypt() {
    check_encrypt::<Aes192, 24>("F.2.3", KEY_192, &CIPHERTEXTS_192);
}

#[test]
fn f_2_4_cbc_aes192_decrypt() {
    check_decrypt::<Aes192, 24>("F.2.4", KEY_192, &CIPHERTEXTS_192);
}

#[test]
fn f_2_5_cbc_aes256_encrypt() {
    check_encrypt::<Aes256, 32>("F.2.5", KEY_256, &CIPHERTEXTS_256);
}

#[test]
fn f_2_6_cbc_aes256_decrypt() {
    check_decrypt::<Aes256, 32>("F.2.6", KEY_256, &CIPHERTEXTS_256);
}

/// The one-shot API must agree with the vectors too, on the decrypt side where the IV is an input.
/// The one-shots take flat arrays and work in place, so the four ciphertext blocks are presented
/// as 64 contiguous bytes and become the four plaintext blocks.
#[test]
fn the_one_shot_api_matches_the_vectors() {
    let iv = block(IV);
    let pt = flat(&PLAINTEXTS);

    let mut data = flat(&CIPHERTEXTS_128);
    Cbc::<Aes128, Decrypting, 16, 16>::decrypt(&key_material::<16>(KEY_128), &iv, &mut data)
        .unwrap();
    assert_eq!(data, pt);

    let mut data = flat(&CIPHERTEXTS_192);
    Cbc::<Aes192, Decrypting, 24, 16>::decrypt(&key_material::<24>(KEY_192), &iv, &mut data)
        .unwrap();
    assert_eq!(data, pt);

    let mut data = flat(&CIPHERTEXTS_256);
    Cbc::<Aes256, Decrypting, 32, 16>::decrypt(&key_material::<32>(KEY_256), &iv, &mut data)
        .unwrap();
    assert_eq!(data, pt);
}

/// The IV really is what distinguishes CBC from ECB here: the same key and plaintext under the
/// F.1 (ECB) conditions gives the F.1 ciphertext, and under F.2 gives a different one.
///
/// F.1.1 block #1 for this key is `3ad77bb40d7a3660a89ecaf32466ef97`; F.2.1 block #1 is
/// `7649abac8119b246cee98e9b12e9197d`. They differ solely because CBC XORs the IV in first.
#[test]
fn cbc_differs_from_ecb_by_the_iv() {
    let key = key_material::<16>(KEY_128);
    let iv = block(IV);

    // The raw permutation on P1 alone is the ECB answer from F.1.1.
    let mut ecb = block(PLAINTEXTS[0]);
    <Aes128 as BlockPermutation<16, 16>>::encrypt_block(
        &<Aes128 as BlockPermutation<16, 16>>::new(&key).unwrap(),
        &mut ecb,
    );
    assert_eq!(ecb, block("3ad77bb40d7a3660a89ecaf32466ef97"), "F.1.1 block #1");

    // CBC's C1 = CIPH_K(P1 XOR IV) is the F.2.1 answer, and differs.
    let (mut enc, _) = Cbc::<Aes128, Encrypting, 16, 16>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<16>::new(iv),
    )
    .unwrap();
    let mut cbc = block(PLAINTEXTS[0]);
    enc.do_encrypt(&mut cbc).unwrap();
    assert_eq!(cbc, block(CIPHERTEXTS_128[0]), "F.2.1 block #1");
    assert_ne!(cbc, ecb);
}
