//! The Camellia keys through the shared conformance suites: construction policy for every mode a
//! key can carry, then the block, symmetric, stream and AEAD suites at the 128- and 256-bit key
//! lengths (Camellia-192 sits between them in rounds and differs in nothing else the suites see),
//! and the MAC keys' round trips. The Wycheproof suites cover CCM and CMAC's answers; GCM has
//! no published Camellia vector, so its answers are bc-java's, in `gcm_bc_java_tests.rs`.

use bouncycastle_camellia::hazmat::{Camellia128Internal, Camellia256Internal};
use bouncycastle_camellia::{Camellia128Key, Camellia256Key};
use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::modes::{
    Blocks, CBC, CCM_Packet, CFB, CFB8, CMAC, CTR, GCM, GMAC, ModeNames,
};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{EcbEncryptionKey, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{BlockCipherEncryptor, MAC};
use bouncycastle_core_test_framework::aead::TestFrameworkAEADCipher;
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

/// A 32-byte frame for the fixed-frame CCM key, within the framework's seed buffer.
type Packet = CCM_Packet<12, 16, 64, 32>;

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
    construction_suite::<ECB<Blocks>>(
        Camellia128Internal::ECB_ALG_NAME,
        Camellia256Internal::ECB_ALG_NAME,
    );
    construction_suite::<GCM>(Camellia128Internal::GCM_ALG_NAME, Camellia256Internal::GCM_ALG_NAME);
    construction_suite::<Packet>(
        Camellia128Internal::CCM_ALG_NAME,
        Camellia256Internal::CCM_ALG_NAME,
    );
}

#[test]
fn ecb_blocks_keys_pass_the_block_cipher_framework() {
    let framework = TestFrameworkBlockCipher::new();
    framework.test_ecb_key::<16, 16, _>(&key128::<ECB<Blocks>>());
    framework.test_ecb_key::<32, 16, _>(&key256::<ECB<Blocks>>());
}

/// ECB has no init data, so the `ECB<Blocks>` key makes its workers with no RNG and nothing to
/// return; the one-shot and the worker are the same codebook.
#[test]
fn ecb_blocks_keys_take_no_init_data() {
    let key = key128::<ECB<Blocks>>();
    let mut block = *b"sixteen byte blk";
    let mut enc = key.create_encryptor();
    enc.do_encrypt_blocks_inplace(core::slice::from_mut(&mut block)).unwrap();
    let mut again = *b"sixteen byte blk";
    assert_eq!(key.encrypt_inplace(&mut again).unwrap(), 16);
    assert_eq!(again, block);
}

/// GCM and CCM are generic over any 16-byte-block permutation, so a Camellia key under them is
/// the same code as AES-GCM and AES-CCM over another engine; the AEAD suite checks the wiring.
#[test]
fn gcm_keys_pass_the_aead_framework() {
    let framework = TestFrameworkAEADCipher::new();
    framework.test_key::<16, 12, 16, 16, _>(&key128::<GCM>(), &mut rng());
    framework.test_key::<32, 12, 16, 16, _>(&key256::<GCM>(), &mut rng());
}

/// The fixed-frame key's workers and one-shots take exactly the frame, so the framework is told
/// the one length they accept.
#[test]
fn ccm_frame_keys_pass_the_aead_framework() {
    let mut framework = TestFrameworkAEADCipher::new();
    framework.fixed_message_len = Some(32);
    framework.test_key::<16, 12, 16, 16, _>(&key128::<Packet>(), &mut rng());
    framework.test_key::<32, 12, 16, 16, _>(&key256::<Packet>(), &mut rng());
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

/// `material::<N>()` with one bit of its last byte flipped.
fn material_flipped<const N: usize>() -> KeyMaterial<N> {
    let mut bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    bytes[N - 1] ^= 1;
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// Equality is over the expanded schedule, so it follows the material: the same bytes compare
/// equal, as does a clone, and a single flipped bit does not. Keys have no `Debug`, hence
/// `assert!` over `==`.
#[test]
fn keys_compare_equal_exactly_when_their_material_does() {
    let key = key128::<CTR>();
    assert!(key == key.clone());
    assert!(key == key128::<CTR>());
    assert!(key != Camellia128Key::<CTR>::from_key_material(&material_flipped::<16>()).unwrap());

    let key = key256::<CTR>();
    assert!(key == key256::<CTR>());
    assert!(key != Camellia256Key::<CTR>::from_key_material(&material_flipped::<32>()).unwrap());
}

fn mac_material<const N: usize>() -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[0x42; N], KeyType::MACKey).unwrap()
}

/// A MAC-mode key's `KEY_TYPE` is the `MACKey` the mode asks for: MAC material builds it and
/// cipher material is refused by type, at both key lengths and for both MAC modes.
#[test]
fn a_mac_mode_key_takes_mac_material_and_refuses_cipher_material() {
    fn refused<K>(r: Result<K, SymmetricCipherError>) {
        assert!(matches!(
            r,
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
        ));
    }
    assert_eq!(<Camellia128Key<CMAC> as FromKeyMaterial<16>>::KEY_TYPE, KeyType::MACKey);
    assert_eq!(<Camellia256Key<GMAC> as FromKeyMaterial<32>>::KEY_TYPE, KeyType::MACKey);
    assert!(Camellia128Key::<CMAC>::from_key_material(&mac_material::<16>()).is_ok());
    assert!(Camellia256Key::<CMAC>::from_key_material(&mac_material::<32>()).is_ok());
    assert!(Camellia128Key::<GMAC>::from_key_material(&mac_material::<16>()).is_ok());
    assert!(Camellia256Key::<GMAC>::from_key_material(&mac_material::<32>()).is_ok());
    refused(Camellia128Key::<CMAC>::from_key_material(&material::<16>()));
    refused(Camellia256Key::<CMAC>::from_key_material(&material::<32>()));
    refused(Camellia128Key::<GMAC>::from_key_material(&material::<16>()));
    refused(Camellia256Key::<GMAC>::from_key_material(&material::<32>()));
    assert!(Camellia128Key::<CMAC>::generate(&mut rng()).is_ok());
}

/// A CMAC key tags and verifies through the role pair, several workers from one key agree, and
/// the tag is bound to the message and the key; the Wycheproof suite holds the known answers.
#[test]
fn cmac_keys_tag_and_verify() {
    let key = Camellia128Key::<CMAC>::from_key_material(&mac_material::<16>()).unwrap();
    let mut generator = key.create_generator();
    generator.do_update(b"a message that arrives ");
    generator.do_update(b"in pieces");
    let tag = generator.do_final();
    assert_eq!(tag.len(), 16);
    assert_eq!(key.mac(b"a message that arrives in pieces"), tag);
    assert!(key.verify(b"a message that arrives in pieces", &tag));
    assert!(!key.verify(b"another message", &tag));
    let other = Camellia128Key::<CMAC>::from_key_material(
        &KeyMaterial::<16>::from_bytes_as_type(&[0x43; 16], KeyType::MACKey).unwrap(),
    )
    .unwrap();
    assert!(!other.verify(b"a message that arrives in pieces", &tag));
    let key256 = Camellia256Key::<CMAC>::from_key_material(&mac_material::<32>()).unwrap();
    assert!(key256.verify(b"x", &key256.mac(b"x")));
}

/// A GMAC key's generator draws a nonce, its verifier checks under it, and the tag is bound to
/// the nonce, the message and the key.
#[test]
fn gmac_keys_tag_and_verify_under_a_nonce() {
    let key = Camellia128Key::<GMAC>::from_key_material(&mac_material::<16>()).unwrap();
    let (mut generator, nonce) = key.create_generator(&mut rng()).unwrap();
    generator.do_update(b"a message that arrives ");
    generator.do_update(b"in pieces");
    let tag = generator.do_final();
    assert!(key.create_verifier(&nonce).verify(b"a message that arrives in pieces", &tag));
    assert!(!key.create_verifier(&nonce).verify(b"another message", &tag));
    let mut other_nonce = nonce;
    other_nonce[0] ^= 1;
    assert!(!key.create_verifier(&other_nonce).verify(b"a message that arrives in pieces", &tag));
    let mut again = key.create_generator_nonce(&nonce);
    again.do_update(b"a message that arrives in pieces");
    assert_eq!(again.do_final(), tag, "the same nonce and message give the same tag");
    let (_, second_nonce) = key.create_generator(&mut rng()).unwrap();
    assert_ne!(second_nonce, nonce, "each generator draws its own nonce");
    let key256 = Camellia256Key::<GMAC>::from_key_material(&mac_material::<32>()).unwrap();
    let (mut g, n) = key256.create_generator(&mut rng()).unwrap();
    g.do_update(b"x");
    let t = g.do_final();
    assert!(key256.create_verifier(&n).verify(b"x", &t));
}
