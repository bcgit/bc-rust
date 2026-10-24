//! The TDEA keys through the shared conformance suites: construction policy for every mode a key
//! can carry, then the block, symmetric and stream suites on the three-key key, and the one thing
//! a two-key key can do, decrypt.

use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::modes::{Blocks, CBC, CFB, CFB8, CTR, ModeNames};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::hazmat::{BlockPermutation, EcbDecryptionKey, ElectronicCodeBook, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    BlockDecryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
};
use bouncycastle_core::traits::{BlockCipherDecryptor, StreamCipherDecryptor};
use bouncycastle_core_test_framework::block_cipher::TestFrameworkBlockCipher;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_tdes::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_tdes::{BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN, KEY_LEN_2KEY, TDES2Key, TDES3Key};

/// The CTR mode at the alias's split: a 6-byte nonce on the 8-byte block.
type Ctr6 = CTR<CTR_NONCE_LEN, BLOCK_LEN>;

fn material<const N: usize>() -> KeyMaterial<N> {
    // Distinct, non-weak components at either bundle length.
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key3<M: Mode<TDESInternal>>() -> TDES3Key<M> {
    TDES3Key::from_key_material(&material::<KEY_LEN>()).expect("a valid key bundle")
}

fn key2<M: Mode<TDES2Internal>>() -> TDES2Key<M> {
    TDES2Key::from_key_material(&material::<KEY_LEN_2KEY>()).expect("a valid two-key bundle")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

fn construction_suite<M>(name: &'static str, name_2key: &'static str)
where
    M: Mode<TDESInternal> + Mode<TDES2Internal>,
{
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<KEY_LEN, TDES3Key<M>>(name, SecurityStrength::_112bit);
    framework.test::<KEY_LEN_2KEY, TDES2Key<M>>(name_2key, SecurityStrength::None);
}

#[test]
fn every_mode_key_enforces_the_material_policy() {
    construction_suite::<CBC<Blocks>>(TDESInternal::CBC_ALG_NAME, TDES2Internal::CBC_ALG_NAME);
    construction_suite::<CBC<PKCS7>>(TDESInternal::CBC_ALG_NAME, TDES2Internal::CBC_ALG_NAME);
    construction_suite::<CBC<NoPadding>>(TDESInternal::CBC_ALG_NAME, TDES2Internal::CBC_ALG_NAME);
    construction_suite::<ECB<Blocks>>(TDESInternal::ECB_ALG_NAME, TDES2Internal::ECB_ALG_NAME);
    construction_suite::<ECB<PKCS7>>(TDESInternal::ECB_ALG_NAME, TDES2Internal::ECB_ALG_NAME);
    construction_suite::<CFB>(TDESInternal::CFB_ALG_NAME, TDES2Internal::CFB_ALG_NAME);
    construction_suite::<CFB8>(TDESInternal::CFB8_ALG_NAME, TDES2Internal::CFB8_ALG_NAME);
    construction_suite::<Ctr6>(TDESInternal::CTR_ALG_NAME, TDES2Internal::CTR_ALG_NAME);
}

#[test]
fn cbc_blocks_key_passes_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new()
        .test_key::<KEY_LEN, BLOCK_LEN, BLOCK_LEN, _>(&key3::<CBC<Blocks>>(), &mut rng());
}

#[test]
fn ecb_blocks_key_passes_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new().test_ecb_key::<KEY_LEN, BLOCK_LEN, _>(&key3::<ECB<Blocks>>());
}

#[test]
fn padded_keys_pass_the_symmetric_cipher_framework() {
    let framework = TestFrameworkSymmetricCipher::new();
    framework.test_key::<KEY_LEN, BLOCK_LEN, BLOCK_LEN, _>(&key3::<CBC<PKCS7>>(), &mut rng());
    framework.test_key::<KEY_LEN, 0, BLOCK_LEN, _>(&key3::<ECB<PKCS7>>(), &mut rng());
}

#[test]
fn no_padding_keys_pass_the_symmetric_cipher_framework() {
    let mut framework = TestFrameworkSymmetricCipher::new();
    framework.required_alignment = BLOCK_LEN;
    framework.test_key::<KEY_LEN, BLOCK_LEN, BLOCK_LEN, _>(&key3::<CBC<NoPadding>>(), &mut rng());
    framework.test_key::<KEY_LEN, 0, BLOCK_LEN, _>(&key3::<ECB<NoPadding>>(), &mut rng());
}

#[test]
fn stream_mode_keys_pass_the_stream_cipher_framework() {
    let framework = TestFrameworkStreamCipher::new();
    framework.test_key::<KEY_LEN, BLOCK_LEN, _>(&key3::<CFB>(), &mut rng());
    framework.test_key::<KEY_LEN, BLOCK_LEN, _>(&key3::<CFB8>(), &mut rng());
    framework.test_key::<KEY_LEN, CTR_NONCE_LEN, _>(&key3::<Ctr6>(), &mut rng());
}

/// A two-key key hands out decryptors for every mode, and they decrypt what the raw two-key
/// permutation encrypted. (Its encryptors do not compile; see `TDES2Internal`.) The CAVP MMT2
/// vectors in `cavp_mmt_tests.rs` are the real check; this pins the wiring.
#[test]
fn two_key_keys_decrypt() {
    let perm = TDES2Internal::new(&material::<KEY_LEN_2KEY>()).unwrap();
    let plaintext = [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN]];

    // ECB: block by block.
    let mut ct = plaintext;
    for block in ct.iter_mut() {
        perm.encrypt_block(block);
    }
    let mut back = ct;
    key2::<ECB<Blocks>>().create_decryptor().do_decrypt_blocks_inplace(&mut back).unwrap();
    assert_eq!(back, plaintext);

    // CBC: `C_j = CIPH(P_j ^ C_{j-1})`, done by hand.
    let iv = [0xA5u8; BLOCK_LEN];
    let mut ct = plaintext;
    let mut prev = iv;
    for block in ct.iter_mut() {
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        perm.encrypt_block(block);
        prev = *block;
    }
    let mut back = ct;
    key2::<CBC<Blocks>>().create_decryptor(&iv).do_decrypt_blocks_inplace(&mut back).unwrap();
    assert_eq!(back, plaintext);

    // CFB64: `C_j = P_j ^ CIPH(C_{j-1})`, so decryption only needs the forward function.
    let mut ct = plaintext;
    let mut prev = iv;
    for block in ct.iter_mut() {
        let mut keystream = prev;
        perm.encrypt_block(&mut keystream);
        for (b, k) in block.iter_mut().zip(keystream) {
            *b ^= k;
        }
        prev = *block;
    }
    let mut back = ct.as_flattened().to_vec();
    key2::<CFB>().create_decryptor(&iv).do_decrypt_inplace(&mut back).unwrap();
    assert_eq!(back, plaintext.as_flattened());

    // CTR: `C_j = P_j ^ CIPH(nonce || j)`, counter from zero.
    let nonce = [1u8, 2, 3, 4, 5, 6];
    let mut ct = plaintext;
    for (j, block) in ct.iter_mut().enumerate() {
        let mut counter_block = [0u8; BLOCK_LEN];
        counter_block[..CTR_NONCE_LEN].copy_from_slice(&nonce);
        counter_block[CTR_NONCE_LEN..].copy_from_slice(&(j as u16).to_be_bytes());
        perm.encrypt_block(&mut counter_block);
        for (b, k) in block.iter_mut().zip(counter_block) {
            *b ^= k;
        }
    }
    let mut back = ct.as_flattened().to_vec();
    key2::<Ctr6>().create_decryptor(&nonce).do_decrypt_inplace(&mut back).unwrap();
    assert_eq!(back, plaintext.as_flattened());

    // ...and the symmetric one-shot on a padded two-key key opens a PKCS7-padded message.
    let padded = *b"hello\x03\x03\x03";
    let mut ct = padded;
    perm.encrypt_block(&mut ct);
    assert_eq!(key2::<ECB<PKCS7>>().decrypt(&[], &ct).unwrap(), b"hello");
}
