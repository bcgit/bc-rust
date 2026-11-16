//! Known-answer tests from NIST SP 800-38A Appendix F.4, "OFB Example Vectors": F.4.1 to F.4.6,
//! OFB-AES128, OFB-AES192 and OFB-AES256, Encrypt and Decrypt, transcribed from the published
//! SP 800-38A PDF (2001 edition).
//!
//! The Encrypt and Decrypt subsections of each key length tabulate the same blocks with `P` and
//! `C` exchanged (OFB encryption and decryption are the same operation, Sec 6.4), so each test
//! runs one table in both directions. The tables also give every output block `Oj`, the
//! keystream, which is checked by encrypting zeros; and each `Input Block` is the previous
//! `Output Block` (`Ij = Oj-1`), which `the_output_blocks_chain` checks against the raw
//! permutation.
//!
//! Encryption takes the vector's IV through the key's `create_encryptor_nonce`, and through
//! `create_encryptor` with an RNG that emits it; decryption takes it as init data.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::OFB;
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_hex as hex;
use bouncycastle_rng::FixedSeedRNG;

const BLOCK_LEN: usize = 16;

/// The IV shared by every Appendix F.4 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four plaintext blocks shared by every Appendix F subsection.
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// F.4.1 / F.4.2 key.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// F.4.1 OFB-AES128.Encrypt ciphertext blocks.
const CIPHERTEXTS_128: [&str; 4] = [
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "7789508d16918f03f53c52dac54ed825",
    "9740051e9c5fecf64344f7a82260edcc",
    "304c6528f659c77866a510d9c1d6ae5e",
];
/// F.4.1 OFB-AES128.Encrypt output blocks, the keystream `Oj`.
const OUTPUT_BLOCKS_128: [&str; 4] = [
    "50fe67cc996d32b6da0937e99bafec60",
    "d9a4dada0892239f6b8b3d7680e15674",
    "a78819583f0308e7a6bf36b1386abf23",
    "c6d3416d29165c6fcb8e51a227ba994e",
];

/// F.4.3 / F.4.4 key.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// F.4.3 OFB-AES192.Encrypt ciphertext blocks.
const CIPHERTEXTS_192: [&str; 4] = [
    "cdc80d6fddf18cab34c25909c99a4174",
    "fcc28b8d4c63837c09e81700c1100401",
    "8d9a9aeac0f6596f559c6d4daf59a5f2",
    "6d9f200857ca6c3e9cac524bd9acc92a",
];
/// F.4.3 OFB-AES192.Encrypt output blocks.
const OUTPUT_BLOCKS_192: [&str; 4] = [
    "a609b38df3b1133dddff2718ba09565e",
    "52ef01da52602fe0975f78ac84bf8a50",
    "bd5286ac63aabd7eb067ac54b553f71d",
    "9b00044d8885f729318713303fc0fe3a",
];

/// F.4.5 / F.4.6 key.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
/// F.4.5 OFB-AES256.Encrypt ciphertext blocks.
const CIPHERTEXTS_256: [&str; 4] = [
    "dc7e84bfda79164b7ecd8486985d3860",
    "4febdc6740d20b3ac88f6ad82a4fb08d",
    "71ab47a086e86eedf39d1c5bba97c408",
    "0126141d67f37be8538f5a8be740e484",
];
/// F.4.5 OFB-AES256.Encrypt output blocks.
const OUTPUT_BLOCKS_256: [&str; 4] = [
    "b7bf3a5df43989dd97f0fa97ebce2f4a",
    "e1c656305ed1a7a6563805746fe03edc",
    "41635be625b48afc1666dd42a09d96e7",
    "f7b93058b8bce0fffea41bf0012cd394",
];

fn block(hex_str: &str) -> [u8; BLOCK_LEN] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

/// Four blocks as 64 contiguous bytes.
fn flat(hex_strs: &[&str; 4]) -> Vec<u8> {
    hex_strs.iter().flat_map(|h| block(h)).collect()
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Runs one key length's table: encryption through both IV routes, decryption, the keystream,
/// each whole and in pieces that cut across the blocks.
fn check<K, const KEY_LEN: usize>(
    section: &str,
    key_hex: &str,
    ciphertexts: &[&str; 4],
    outputs: &[&str; 4],
) where
    K: 'static,
    K: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, 0>,
    for<'k> K::Encryptor<'k>: StreamCipherEncryptor<BLOCK_LEN>,
    for<'k> K::Decryptor<'k>: StreamCipherDecryptor<BLOCK_LEN>,
{
    let key = K::from_key_material(&key_material::<KEY_LEN>(key_hex)).expect("a valid key");
    let iv = block(IV);
    let pt = flat(&PLAINTEXTS);
    let ct = flat(ciphertexts);

    for chunk in [64, 16, 5, 23] {
        let mut data = pt.clone();
        let mut enc = key.create_encryptor_nonce(&iv);
        data.chunks_mut(chunk).for_each(|p| _ = enc.do_encrypt_inplace(p).unwrap());
        assert_eq!(data, ct, "{section} Encrypt, supplied IV, {chunk}-byte calls");

        let mut data = pt.clone();
        let (mut enc, drawn) = key.create_encryptor(&mut FixedSeedRNG::new(iv)).unwrap();
        assert_eq!(drawn, iv, "{section}: the RNG emits the vector's IV");
        data.chunks_mut(chunk).for_each(|p| _ = enc.do_encrypt_inplace(p).unwrap());
        assert_eq!(data, ct, "{section} Encrypt, drawn IV, {chunk}-byte calls");

        let mut data = ct.clone();
        let mut dec = key.create_decryptor(&iv);
        data.chunks_mut(chunk).for_each(|p| _ = dec.do_decrypt_inplace(p).unwrap());
        assert_eq!(data, pt, "{section} Decrypt, {chunk}-byte calls");
    }

    // With P = 0, C is the keystream O1 | O2 | O3 | O4.
    let mut zeros = vec![0u8; 4 * BLOCK_LEN];
    key.create_encryptor_nonce(&iv).do_encrypt_inplace(&mut zeros).unwrap();
    assert_eq!(zeros, flat(outputs), "{section}: the tabulated output blocks are the keystream");
}

#[test]
fn f_4_1_and_f_4_2_ofb_aes128() {
    check::<AES128Key<OFB>, 16>("F.4.1/F.4.2", KEY_128, &CIPHERTEXTS_128, &OUTPUT_BLOCKS_128);
}

#[test]
fn f_4_3_and_f_4_4_ofb_aes192() {
    check::<AES192Key<OFB>, 24>("F.4.3/F.4.4", KEY_192, &CIPHERTEXTS_192, &OUTPUT_BLOCKS_192);
}

#[test]
fn f_4_5_and_f_4_6_ofb_aes256() {
    check::<AES256Key<OFB>, 32>("F.4.5/F.4.6", KEY_256, &CIPHERTEXTS_256, &OUTPUT_BLOCKS_256);
}

/// Sec 6.4, `I1 = IV`, `Ij = Oj-1`, `Oj = CIPH_K(Ij)`: each tabulated output block is the raw
/// permutation of the one before, starting from the IV. Checks the transcription of the output
/// blocks independently of the mode.
#[test]
fn the_output_blocks_chain() {
    fn chain<P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>, const KEY_LEN: usize>(
        section: &str,
        key_hex: &str,
        outputs: &[&str; 4],
    ) {
        let perm = P::new(&key_material::<KEY_LEN>(key_hex)).unwrap();
        let mut o = block(IV);
        for (j, expected) in outputs.iter().enumerate() {
            perm.encrypt_block(&mut o);
            assert_eq!(o, block(expected), "{section}: Output Block #{}", j + 1);
        }
    }
    chain::<AES128Internal, 16>("F.4.1", KEY_128, &OUTPUT_BLOCKS_128);
    chain::<AES192Internal, 24>("F.4.3", KEY_192, &OUTPUT_BLOCKS_192);
    chain::<AES256Internal, 32>("F.4.5", KEY_256, &OUTPUT_BLOCKS_256);
}
