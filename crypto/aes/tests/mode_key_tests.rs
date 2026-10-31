//! The mode-bound AES keys for the block, padded, stream and fixed-frame modes: the construction
//! suite and the shared framework's key runner for each, and what tells the modes apart on the
//! key path -- an `ECB<Blocks>` key takes no RNG, a padded ECB key's init data is empty, and a
//! `CBC<Blocks>` key's in-place one-shot is the `CBC<NoPadding>` key's `encrypt_out`.
//!
//! The GCM, CCM, CMAC and GMAC keys have their own files.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_aes::{AES128Key, AES256Key};
use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::modes::{Blocks, CBC, CCM_Packet, CFB, CFB8, CTR, ModeNames};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::hazmat::{EcbEncryptionKey, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
    SymmetricEncryptionKey,
};
use bouncycastle_core::traits::BlockCipherEncryptor;
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::aead::TestFrameworkAEADCipher;
use bouncycastle_core_test_framework::block_cipher::TestFrameworkBlockCipher;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};
use bouncycastle_rng::HashDRBG_SHA512;

/// A 32-byte frame for the fixed-frame CCM key, within the framework's seed buffer.
type Packet = CCM_Packet<12, 16, 64, 32>;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key128<M: Mode<AES128Internal>>() -> AES128Key<M> {
    AES128Key::from_key_material(&material::<16>()).expect("a valid key")
}

fn key256<M: Mode<AES256Internal>>() -> AES256Key<M> {
    AES256Key::from_key_material(&material::<32>()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// The construction suite -- key type, binding, strength and `generate` -- for the mode `M` at
/// both key lengths, against the name the permutation gives that mode.
fn construction_suite<M>(name_128: &'static str, name_256: &'static str)
where
    M: Mode<AES128Internal> + Mode<AES256Internal>,
{
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<16, AES128Key<M>>(name_128, SecurityStrength::_128bit);
    framework.test::<32, AES256Key<M>>(name_256, SecurityStrength::_256bit);
}

#[test]
fn every_mode_key_enforces_the_material_policy() {
    construction_suite::<CBC<Blocks>>(AES128Internal::CBC_ALG_NAME, AES256Internal::CBC_ALG_NAME);
    construction_suite::<CBC<PKCS7>>(AES128Internal::CBC_ALG_NAME, AES256Internal::CBC_ALG_NAME);
    construction_suite::<CBC<NoPadding>>(
        AES128Internal::CBC_ALG_NAME,
        AES256Internal::CBC_ALG_NAME,
    );
    construction_suite::<ECB<Blocks>>(AES128Internal::ECB_ALG_NAME, AES256Internal::ECB_ALG_NAME);
    construction_suite::<ECB<PKCS7>>(AES128Internal::ECB_ALG_NAME, AES256Internal::ECB_ALG_NAME);
    construction_suite::<CFB>(AES128Internal::CFB_ALG_NAME, AES256Internal::CFB_ALG_NAME);
    construction_suite::<CFB8>(AES128Internal::CFB8_ALG_NAME, AES256Internal::CFB8_ALG_NAME);
    construction_suite::<CTR>(AES128Internal::CTR_ALG_NAME, AES256Internal::CTR_ALG_NAME);
    construction_suite::<Packet>(AES128Internal::CCM_ALG_NAME, AES256Internal::CCM_ALG_NAME);
}

#[test]
fn cbc_blocks_keys_pass_the_block_cipher_framework() {
    let framework = TestFrameworkBlockCipher::new();
    framework.test_key::<16, 16, 16, _>(&key128::<CBC<Blocks>>(), &mut rng());
    framework.test_key::<32, 16, 16, _>(&key256::<CBC<Blocks>>(), &mut rng());
}

#[test]
fn ecb_blocks_keys_pass_the_block_cipher_framework() {
    let framework = TestFrameworkBlockCipher::new();
    framework.test_ecb_key::<16, 16, _>(&key128::<ECB<Blocks>>());
    framework.test_ecb_key::<32, 16, _>(&key256::<ECB<Blocks>>());
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
    framework.test_key::<16, 0, 16, _>(&key128::<ECB<NoPadding>>(), &mut rng());
    framework.test_key::<32, 0, 16, _>(&key256::<ECB<NoPadding>>(), &mut rng());
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

/// The fixed-frame key's workers and one-shots take exactly the frame, so the framework is told
/// the one length they accept.
#[test]
fn ccm_frame_keys_pass_the_aead_framework() {
    let mut framework = TestFrameworkAEADCipher::new();
    framework.fixed_message_len = Some(32);
    framework.test_key::<16, 12, 16, 16, _>(&key128::<Packet>(), &mut rng());
    framework.test_key::<32, 12, 16, 16, _>(&key256::<Packet>(), &mut rng());
}

/// ECB has no init data, so the `ECB<Blocks>` key makes its workers with no RNG and nothing to
/// return, and the `ECB<PKCS7>` key, on the symmetric path, takes an RNG it never draws from and
/// returns `[u8; 0]`. The padded ciphertext is the block pair's encryption of the padded block.
#[test]
fn ecb_keys_take_no_init_data() {
    let key = key128::<ECB<Blocks>>();
    let mut padded_hello = *b"hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    let mut enc = key.create_encryptor();
    enc.do_encrypt_blocks_inplace(core::slice::from_mut(&mut padded_hello)).unwrap();
    let mut again = *b"hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    assert_eq!(key.encrypt_inplace(&mut again).unwrap(), 16);
    assert_eq!(again, padded_hello, "the worker and the one-shot are the same codebook");

    let padded_key = key128::<ECB<PKCS7>>();
    let mut out = [0u8; 16];
    // A seedless RNG panics on any draw, so finishing is the proof that none is made.
    let (written, init): (usize, [u8; 0]) =
        padded_key.encrypt_out(&mut FixedSeedRNG::<0>::new([]), b"hello", &mut out).unwrap();
    assert_eq!((written, init), (16, []));
    assert_eq!(out, padded_hello, "PKCS7 over ECB is ECB of the padded block");
    assert_eq!(padded_key.decrypt(&init, &out).unwrap(), b"hello");
}

/// Under a pinned IV, the `CBC<Blocks>` key's in-place one-shot and the `CBC<NoPadding>` key's
/// `encrypt_out` are the same bytes: `NoPadding` is an alignment check over the same mode.
#[test]
fn cbc_blocks_in_place_agrees_with_cbc_no_padding_out() {
    let iv = [0xA5u8; 16];
    let msg: [u8; 48] = core::array::from_fn(|i| (i * 7 + 3) as u8);

    let mut in_place = msg;
    let (n, iv_blocks) = key128::<CBC<Blocks>>()
        .encrypt_inplace(&mut FixedSeedRNG::<16>::new(iv), &mut in_place)
        .unwrap();
    assert_eq!((n, iv_blocks), (48, iv));

    let mut out = [0u8; 48];
    let (m, iv_np) = key128::<CBC<NoPadding>>()
        .encrypt_out(&mut FixedSeedRNG::<16>::new(iv), &msg, &mut out)
        .unwrap();
    assert_eq!((m, iv_np), (48, iv));
    assert_eq!(out, in_place);

    // ...and each key's decryptor opens the other's ciphertext.
    key128::<CBC<Blocks>>().decrypt_inplace(&iv, &mut out).unwrap();
    assert_eq!(out, msg);
    let mut back = [0u8; 64];
    let k = key128::<CBC<NoPadding>>().decrypt_out(&iv, &in_place, &mut back).unwrap();
    assert_eq!(&back[..k], &msg[..]);
}
