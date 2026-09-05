//! Known-answer tests from draft-ribose-cfrg-sm4-10 Appendix A.2, "Examples For Various Modes Of
//! Operations": the SM4-ECB vectors (A.2.1) and the SM4-CBC vectors (A.2.2).
//!
//! ECB applies the raw permutation to each block independently (Sec 8.3), so an ECB example
//! vector *is* a block-permutation test vector, and the two-block plaintext exercises the trait's
//! pair methods against published answers. (That is the only reason ECB appears in this crate;
//! see the crate docs on why you must not use it to encrypt anything.)
//!
//! The CBC vectors go through [`SM4_CBC`], i.e. `bouncycastle-modes` over this permutation. There
//! is no API for supplying an IV, so encryption is driven through
//! [`BlockCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is the
//! vector's IV, and the test asserts the returned init data really is that IV before comparing
//! any ciphertext. Decryption takes the IV directly.
//!
//! The draft notes these vectors "can be verified using" Botan and OpenSSL. All values are
//! transcribed from the downloaded text of the draft.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Encrypting};
use bouncycastle_sm4::{BLOCK_LEN, Block, SM4, SM4_CBC};

/// The two plaintext blocks shared by every A.2 example.
const PLAINTEXT: &str = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";
/// The IV shared by every A.2 IV-based example.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// A.2.x Example 1 key.
const KEY_1: &str = "0123456789abcdeffedcba9876543210";
/// A.2.x Example 2 key.
const KEY_2: &str = "fedcba98765432100123456789abcdef";

/// A.2.1.1 SM4-ECB Example 1 ciphertext.
const ECB_CT_1: &str = "5ec8143de509cff7b5179f8f474b86192f1d305a7fb17df985f81c8482192304";
/// A.2.1.2 SM4-ECB Example 2 ciphertext.
const ECB_CT_2: &str = "c5876897e4a59bbba72a10c83872245b12dd90bc2d200692b529a4155ac9e600";
/// A.2.2.1 SM4-CBC Example 1 ciphertext.
const CBC_CT_1: &str = "78ebb11cc40b0a48312aaeb2040244cb4cb7016951909226979b0d15dc6a8f6d";
/// A.2.2.2 SM4-CBC Example 2 ciphertext.
const CBC_CT_2: &str = "0d3a6ddc2d21c698857215587b7bb59a91f2c147911a4144665e1fa1d40bae38";

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("expected length")
}

fn blocks(hex_str: &str) -> [Block; 2] {
    let flat: [u8; 32] = bytes(hex_str);
    let (chunks, _) = flat.as_chunks::<BLOCK_LEN>();
    [chunks[0], chunks[1]]
}

fn key_material(hex_str: &str) -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&bytes::<16>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

// ---- A.2.1  SM4-ECB ------------------------------------------------------------------------

fn check_ecb(section: &str, key: &str, expected: &str) {
    let sm4 = SM4::new(&key_material(key)).unwrap();
    let pt = blocks(PLAINTEXT);
    let ct = blocks(expected);

    // Block by block: Sec 8.3.1, C_i = SM4_Enc(K, P_i).
    for (i, (p, c)) in pt.iter().zip(ct.iter()).enumerate() {
        let mut b = *p;
        sm4.encrypt_block(&mut b);
        assert_eq!(&b, c, "{section} encrypt, block #{}", i + 1);

        let mut b = *c;
        sm4.decrypt_block(&mut b);
        assert_eq!(&b, p, "{section} decrypt, block #{}", i + 1);
    }

    // The pair methods, in one call each.
    let mut pair = pt;
    sm4.encrypt_2blocks(&mut pair);
    assert_eq!(pair, ct, "{section} encrypt_2blocks");
    sm4.decrypt_2blocks(&mut pair);
    assert_eq!(pair, pt, "{section} decrypt_2blocks");
}

#[test]
fn a_2_1_1_ecb_example_1() {
    check_ecb("A.2.1.1", KEY_1, ECB_CT_1);
}

#[test]
fn a_2_1_2_ecb_example_2() {
    check_ecb("A.2.1.2", KEY_2, ECB_CT_2);
}

// ---- A.2.2  SM4-CBC ------------------------------------------------------------------------

fn check_cbc(section: &str, key: &str, expected: &str) {
    let key = key_material(key);
    let iv: [u8; 16] = bytes(IV);
    let pt: [u8; 32] = bytes(PLAINTEXT);
    let ct: [u8; 32] = bytes(expected);

    // Encrypt, both blocks in one call, under the vector's IV.
    let (mut enc, got_iv) =
        SM4_CBC::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<16>::new(iv)).unwrap();
    assert_eq!(got_iv, iv, "{section}: the pinned RNG should produce the vector's IV");
    let mut data = pt;
    enc.do_encrypt(&mut data).unwrap();
    assert_eq!(data, ct, "{section} encrypt, two blocks in one call");

    // Encrypt one block at a time.
    let (mut enc, _) =
        SM4_CBC::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<16>::new(iv)).unwrap();
    let mut data = pt;
    let (chunks, _) = data.as_chunks_mut::<BLOCK_LEN>();
    for block in chunks.iter_mut() {
        enc.do_encrypt(block).unwrap();
    }
    assert_eq!(data, ct, "{section} encrypt, one block at a time");

    // Decrypt with the IV as init data: one shot, and streaming.
    let mut data = ct;
    SM4_CBC::<Decrypting>::decrypt(&key, &iv, &mut data).unwrap();
    assert_eq!(data, pt, "{section} decrypt, one shot");

    let mut dec = SM4_CBC::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let mut data = ct;
    let (chunks, _) = data.as_chunks_mut::<BLOCK_LEN>();
    for block in chunks.iter_mut() {
        dec.do_decrypt(block).unwrap();
    }
    assert_eq!(data, pt, "{section} decrypt, one block at a time");
}

#[test]
fn a_2_2_1_cbc_example_1() {
    check_cbc("A.2.2.1", KEY_1, CBC_CT_1);
}

#[test]
fn a_2_2_2_cbc_example_2() {
    check_cbc("A.2.2.2", KEY_2, CBC_CT_2);
}
