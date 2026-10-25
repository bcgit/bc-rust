//! The SM4 key through the shared conformance suites: construction policy for every mode a key
//! can carry, then the block, symmetric and stream suites.

use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::modes::{Blocks, CBC, CFB, CFB8, CTR, ModeNames};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::block_cipher::TestFrameworkBlockCipher;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sm4::hazmat::SM4Internal;
use bouncycastle_sm4::{KEY_LEN, SM4Key};

fn material() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key")
}

fn key<M: Mode<SM4Internal>>() -> SM4Key<M> {
    SM4Key::from_key_material(&material()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// The construction suite -- key type, strength and `generate` -- for the mode `M`, against the
/// name the permutation gives that mode.
fn construction_suite<M: Mode<SM4Internal>>(name: &'static str) {
    TestFrameworkFromKeyMaterial::new().test::<KEY_LEN, SM4Key<M>>(name, SecurityStrength::_128bit);
}

#[test]
fn every_mode_key_enforces_the_material_policy() {
    construction_suite::<CBC<Blocks>>(SM4Internal::CBC_ALG_NAME);
    construction_suite::<CBC<PKCS7>>(SM4Internal::CBC_ALG_NAME);
    construction_suite::<CBC<NoPadding>>(SM4Internal::CBC_ALG_NAME);
    construction_suite::<ECB<PKCS7>>(SM4Internal::ECB_ALG_NAME);
    construction_suite::<CFB>(SM4Internal::CFB_ALG_NAME);
    construction_suite::<CFB8>(SM4Internal::CFB8_ALG_NAME);
    construction_suite::<CTR>(SM4Internal::CTR_ALG_NAME);
}

#[test]
fn cbc_blocks_key_passes_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new().test_key::<16, 16, 16, _>(&key::<CBC<Blocks>>(), &mut rng());
}

#[test]
fn padded_keys_pass_the_symmetric_cipher_framework() {
    let framework = TestFrameworkSymmetricCipher::new();
    framework.test_key::<16, 16, 16, _>(&key::<CBC<PKCS7>>(), &mut rng());
    framework.test_key::<16, 0, 16, _>(&key::<ECB<PKCS7>>(), &mut rng());
}

/// `NoPadding` turns the adapters into an alignment check: the framework is told so, and asserts
/// that every other length is refused.
#[test]
fn no_padding_key_passes_the_symmetric_cipher_framework() {
    let mut framework = TestFrameworkSymmetricCipher::new();
    framework.required_alignment = 16;
    framework.test_key::<16, 16, 16, _>(&key::<CBC<NoPadding>>(), &mut rng());
}

#[test]
fn stream_mode_keys_pass_the_stream_cipher_framework() {
    let framework = TestFrameworkStreamCipher::new();
    framework.test_key::<16, 16, _>(&key::<CFB>(), &mut rng());
    framework.test_key::<16, 16, _>(&key::<CFB8>(), &mut rng());
    framework.test_key::<16, 12, _>(&key::<CTR>(), &mut rng());
}
