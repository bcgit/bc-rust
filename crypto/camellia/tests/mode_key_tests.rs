//! The Camellia keys through the shared conformance suites: construction policy for every mode a key
//! can carry, then the block, symmetric and stream suites at the 128- and 256-bit key
//! lengths (Camellia-192 sits between them in rounds and differs in nothing else the suites see).

use bouncycastle_camellia::hazmat::{Camellia128Internal, Camellia256Internal};
use bouncycastle_camellia::{Camellia128Key, Camellia256Key};
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

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key128<M: Mode<Camellia128Internal>>() -> Camellia128Key<M> {
    Camellia128Key::from_key_material(&material::<16>()).expect("a valid key")
}

fn key256<M: Mode<Camellia256Internal>>() -> Camellia256Key<M> {
    Camellia256Key::from_key_material(&material::<32>()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// The construction suite -- key type, strength and `generate` -- for the mode `M` at both key
/// lengths, against the name the permutation gives that mode.
fn construction_suite<M>(name_128: &'static str, name_256: &'static str)
where
    M: Mode<Camellia128Internal> + Mode<Camellia256Internal>,
{
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<16, Camellia128Key<M>>(name_128, SecurityStrength::_128bit);
    framework.test::<32, Camellia256Key<M>>(name_256, SecurityStrength::_256bit);
}

#[test]
fn every_mode_key_enforces_the_material_policy() {
    construction_suite::<CBC<Blocks>>(
        Camellia128Internal::CBC_ALG_NAME,
        Camellia256Internal::CBC_ALG_NAME,
    );
    construction_suite::<CBC<PKCS7>>(
        Camellia128Internal::CBC_ALG_NAME,
        Camellia256Internal::CBC_ALG_NAME,
    );
    construction_suite::<CBC<NoPadding>>(
        Camellia128Internal::CBC_ALG_NAME,
        Camellia256Internal::CBC_ALG_NAME,
    );
    construction_suite::<ECB<PKCS7>>(
        Camellia128Internal::ECB_ALG_NAME,
        Camellia256Internal::ECB_ALG_NAME,
    );
    construction_suite::<CFB>(Camellia128Internal::CFB_ALG_NAME, Camellia256Internal::CFB_ALG_NAME);
    construction_suite::<CFB8>(
        Camellia128Internal::CFB8_ALG_NAME,
        Camellia256Internal::CFB8_ALG_NAME,
    );
    construction_suite::<CTR>(Camellia128Internal::CTR_ALG_NAME, Camellia256Internal::CTR_ALG_NAME);
}

#[test]
fn cbc_blocks_keys_pass_the_block_cipher_framework() {
    let framework = TestFrameworkBlockCipher::new();
    framework.test_key::<16, 16, 16, _>(&key128::<CBC<Blocks>>(), &mut rng());
    framework.test_key::<32, 16, 16, _>(&key256::<CBC<Blocks>>(), &mut rng());
}

#[test]
fn padded_keys_pass_the_symmetric_cipher_framework() {
    let framework = TestFrameworkSymmetricCipher::new();
    framework.test_key::<16, 16, 16, _>(&key128::<CBC<PKCS7>>(), &mut rng());
    framework.test_key::<32, 16, 16, _>(&key256::<CBC<PKCS7>>(), &mut rng());
    framework.test_key::<16, 0, 16, _>(&key128::<ECB<PKCS7>>(), &mut rng());
    framework.test_key::<32, 0, 16, _>(&key256::<ECB<PKCS7>>(), &mut rng());
}

/// `NoPadding` turns the adapters into an alignment check: the framework is told so, and asserts
/// that every other length is refused.
#[test]
fn no_padding_keys_pass_the_symmetric_cipher_framework() {
    let mut framework = TestFrameworkSymmetricCipher::new();
    framework.required_alignment = 16;
    framework.test_key::<16, 16, 16, _>(&key128::<CBC<NoPadding>>(), &mut rng());
    framework.test_key::<32, 16, 16, _>(&key256::<CBC<NoPadding>>(), &mut rng());
}

#[test]
fn stream_mode_keys_pass_the_stream_cipher_framework() {
    let framework = TestFrameworkStreamCipher::new();
    framework.test_key::<16, 16, _>(&key128::<CFB>(), &mut rng());
    framework.test_key::<32, 16, _>(&key256::<CFB>(), &mut rng());
    framework.test_key::<16, 16, _>(&key128::<CFB8>(), &mut rng());
    framework.test_key::<32, 16, _>(&key256::<CFB8>(), &mut rng());
    framework.test_key::<16, 12, _>(&key128::<CTR>(), &mut rng());
    framework.test_key::<32, 12, _>(&key256::<CTR>(), &mut rng());
}
