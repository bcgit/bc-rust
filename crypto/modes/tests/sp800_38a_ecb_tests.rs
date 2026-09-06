//! Known-answer tests from NIST SP 800-38A Appendix F.1, "ECB Example Vectors".
//!
//! Sections **F.1.1 through F.1.6**: ECB-AES128, ECB-AES192 and ECB-AES256, Encrypt and Decrypt.
//! All six use the same four plaintext blocks (Appendix F preamble) and the same three keys as F.2
//! (CBC) and F.3 (CFB), so these vectors also re-check each AES key expansion through the plainest
//! possible construction. Transcribed from the published SP 800-38A PDF (2001 edition).
//!
//! # No IV to drive
//!
//! ECB has no initialization data, so -- unlike the CBC and CFB suites -- `encrypt` can be checked
//! against the published ciphertext directly, through the one-shot as well as the streaming API.
//!
//! # The mode is the permutation
//!
//! Sec 6.1 gives `Cj = CIPH_K(Pj)`, so each tabulated ciphertext block must equal the raw
//! permutation applied to the corresponding plaintext block. `each_block_is_the_raw_permutation`
//! checks that, which ties the mode to [`ElectronicCodeBook`] and confirms the transcription: a
//! typo in either column would break the equality.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook};
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Ecb, Encrypting};

const BLOCK_LEN: usize = 16;

/// The four plaintext blocks shared by every Appendix F subsection (Appendix F preamble).
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// F.1.1 / F.1.2 key.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// F.1.1 ECB-AES128.Encrypt ciphertext blocks.
const CIPHERTEXTS_128: [&str; 4] = [
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
];

/// F.1.3 / F.1.4 key.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// F.1.3 ECB-AES192.Encrypt ciphertext blocks.
const CIPHERTEXTS_192: [&str; 4] = [
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
];

/// F.1.5 / F.1.6 key.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
/// F.1.5 ECB-AES256.Encrypt ciphertext blocks.
const CIPHERTEXTS_256: [&str; 4] = [
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
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

/// Runs one Appendix F.1 encrypt subsection: the whole message in one call (two pairs), one block
/// at a time, the `3 + 1` grouping that leaves a remainder after the pair loop, the implementor
/// hook, and the one-shot.
fn check_encrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, expected: &[&str; 4])
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    type Enc<P, const K: usize> = Ecb<P, Encrypting, K, BLOCK_LEN>;
    let key = key_material::<KEY_LEN>(key_hex);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(expected);

    let (mut enc, init) = Enc::<P, KEY_LEN>::do_encrypt_init(&key).unwrap();
    assert_eq!(init, [], "{section}: ECB has no init data");
    let mut data = flat(&PLAINTEXTS);
    enc.do_encrypt(&mut data).unwrap();
    assert_eq!(data, flat(expected), "{section}: four blocks in one call");

    let (mut enc, _) = Enc::<P, KEY_LEN>::do_encrypt_init(&key).unwrap();
    for (i, (p, c)) in pt.iter().zip(ct.iter()).enumerate() {
        let mut got = *p;
        enc.do_encrypt(&mut got).unwrap();
        assert_eq!(&got, c, "{section}: block #{}", i + 1);
    }

    let (mut enc, _) = Enc::<P, KEY_LEN>::do_encrypt_init(&key).unwrap();
    let mut three: [u8; 3 * BLOCK_LEN] = pt[..3].as_flattened().try_into().unwrap();
    enc.do_encrypt(&mut three).unwrap();
    let mut one = pt[3];
    enc.do_encrypt(&mut one).unwrap();
    assert_eq!(&three[..], ct[..3].as_flattened(), "{section}: blocks 1-3");
    assert_eq!(one, ct[3], "{section}: block 4");

    let (mut enc, _) = Enc::<P, KEY_LEN>::do_encrypt_init(&key).unwrap();
    let mut hook = pt;
    enc.do_encrypt_blocks(&mut hook).unwrap();
    assert_eq!(hook, ct, "{section}: implementor hook");

    let mut data = flat(&PLAINTEXTS);
    let init = Enc::<P, KEY_LEN>::encrypt(&key, &mut data).unwrap();
    assert_eq!(init, []);
    assert_eq!(data, flat(expected), "{section}: one-shot");
}

/// Runs one Appendix F.1 decrypt subsection, in the same five groupings.
fn check_decrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, ciphertext: &[&str; 4])
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    type Dec<P, const K: usize> = Ecb<P, Decrypting, K, BLOCK_LEN>;
    let key = key_material::<KEY_LEN>(key_hex);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(ciphertext);

    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &[]).unwrap();
    let mut data = flat(ciphertext);
    dec.do_decrypt(&mut data).unwrap();
    assert_eq!(data, flat(&PLAINTEXTS), "{section}: four blocks in one call");

    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &[]).unwrap();
    for (i, (c, p)) in ct.iter().zip(pt.iter()).enumerate() {
        let mut got = *c;
        dec.do_decrypt(&mut got).unwrap();
        assert_eq!(&got, p, "{section}: block #{}", i + 1);
    }

    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &[]).unwrap();
    let mut three: [u8; 3 * BLOCK_LEN] = ct[..3].as_flattened().try_into().unwrap();
    dec.do_decrypt(&mut three).unwrap();
    let mut one = ct[3];
    dec.do_decrypt(&mut one).unwrap();
    assert_eq!(&three[..], pt[..3].as_flattened(), "{section}: blocks 1-3");
    assert_eq!(one, pt[3], "{section}: block 4");

    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &[]).unwrap();
    let mut hook = ct;
    dec.do_decrypt_blocks(&mut hook).unwrap();
    assert_eq!(hook, pt, "{section}: implementor hook");

    let mut data = flat(ciphertext);
    Dec::<P, KEY_LEN>::decrypt(&key, &[], &mut data).unwrap();
    assert_eq!(data, flat(&PLAINTEXTS), "{section}: one-shot");
}

#[test]
fn f_1_1_ecb_aes128_encrypt() {
    check_encrypt::<Aes128, 16>("F.1.1", KEY_128, &CIPHERTEXTS_128);
}

#[test]
fn f_1_2_ecb_aes128_decrypt() {
    check_decrypt::<Aes128, 16>("F.1.2", KEY_128, &CIPHERTEXTS_128);
}

#[test]
fn f_1_3_ecb_aes192_encrypt() {
    check_encrypt::<Aes192, 24>("F.1.3", KEY_192, &CIPHERTEXTS_192);
}

#[test]
fn f_1_4_ecb_aes192_decrypt() {
    check_decrypt::<Aes192, 24>("F.1.4", KEY_192, &CIPHERTEXTS_192);
}

#[test]
fn f_1_5_ecb_aes256_encrypt() {
    check_encrypt::<Aes256, 32>("F.1.5", KEY_256, &CIPHERTEXTS_256);
}

#[test]
fn f_1_6_ecb_aes256_decrypt() {
    check_decrypt::<Aes256, 32>("F.1.6", KEY_256, &CIPHERTEXTS_256);
}

/// Sec 6.1: `Cj = CIPH_K(Pj)`. Every tabulated ciphertext block is the raw permutation of the
/// corresponding plaintext block, for all three key lengths.
fn check_raw<P, const KEY_LEN: usize>(section: &str, key_hex: &str, ciphertexts: &[&str; 4])
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let perm = P::new(&key_material::<KEY_LEN>(key_hex)).expect("a valid key");
    for (j, (p, c)) in PLAINTEXTS.iter().zip(ciphertexts.iter()).enumerate() {
        let mut computed = block(p);
        perm.encrypt_block(&mut computed);
        assert_eq!(computed, block(c), "{section}: block #{} should be CIPH_K(P{})", j + 1, j + 1);
    }
}

#[test]
fn each_block_is_the_raw_permutation() {
    check_raw::<Aes128, 16>("F.1.1", KEY_128, &CIPHERTEXTS_128);
    check_raw::<Aes192, 24>("F.1.3", KEY_192, &CIPHERTEXTS_192);
    check_raw::<Aes256, 32>("F.1.5", KEY_256, &CIPHERTEXTS_256);
}
