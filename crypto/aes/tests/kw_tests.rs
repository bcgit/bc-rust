//! `AES*Key<KW>` and `AES*Key<KWP>`: the published known answers, the shared key-wrap framework
//! at several payload lengths, and what the aliases resolve to.
//!
//! The known answers are RFC 3394 Sec 4 (all six KW vectors, covering every AES key length and
//! 128-, 192- and 256-bit key data) and RFC 5649 Sec 6 (both KWP examples, the second of which is
//! the 7-octet case that takes the single-block path of SP 800-38F Algorithm 5 step 5 and
//! Algorithm 6 step 3). SP 800-38F itself publishes no vectors; the NIST ACVP sets are in
//! `kw_bc-test-data.rs`. The structural tests of the two algorithms are toy-driven, in
//! `crypto/cipher/tests/modes/kw_tests.rs`; the framework runs here because its tamper checks
//! need a permutation with diffusion.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_aes::{
    AES_KW_128, AES_KW_192, AES_KW_256, AES_KWP_128, AES_KWP_192, AES_KWP_256, AES128Key,
    AES192Key, AES256Key,
};
use bouncycastle_cipher::modes::{KW, KWP, ModeNames};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::key_wrap::TestFrameworkKeyWrap;
use bouncycastle_hex as hex;

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("the expected length")
}

fn material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key")
}

fn key128<M: Mode<AES128Internal>>(hex_str: &str) -> AES128Key<M> {
    AES128Key::from_key_material(&material::<16>(hex_str)).expect("a valid key")
}

fn key192<M: Mode<AES192Internal>>(hex_str: &str) -> AES192Key<M> {
    AES192Key::from_key_material(&material::<24>(hex_str)).expect("a valid key")
}

fn key256<M: Mode<AES256Internal>>(hex_str: &str) -> AES256Key<M> {
    AES256Key::from_key_material(&material::<32>(hex_str)).expect("a valid key")
}

// ---- RFC 3394 Sec 4: the KW vectors --------------------------------------------------------

/// RFC 3394 Sec 4.1-4.6 all use the same KEK bytes, truncated to the key length, and the same
/// key data, truncated to the data length.
const RFC3394_KEK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const RFC3394_KEY_DATA: &str = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f";

/// Sec 4.1, "Wrap 128 bits of Key Data with a 128-bit KEK".
#[test]
fn rfc3394_4_1_wrap_128_bits_with_a_128_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<16, 16, 24, AES128Key<KW>>(
        &bytes(&RFC3394_KEK[..32]),
        &bytes(&RFC3394_KEY_DATA[..32]),
        &bytes("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
    );
}

/// Sec 4.2, "Wrap 128 bits of Key Data with a 192-bit KEK".
#[test]
fn rfc3394_4_2_wrap_128_bits_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 16, 24, AES192Key<KW>>(
        &bytes(&RFC3394_KEK[..48]),
        &bytes(&RFC3394_KEY_DATA[..32]),
        &bytes("96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"),
    );
}

/// Sec 4.3, "Wrap 128 bits of Key Data with a 256-bit KEK".
#[test]
fn rfc3394_4_3_wrap_128_bits_with_a_256_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<32, 16, 24, AES256Key<KW>>(
        &bytes(RFC3394_KEK),
        &bytes(&RFC3394_KEY_DATA[..32]),
        &bytes("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"),
    );
}

/// Sec 4.4, "Wrap 192 bits of Key Data with a 192-bit KEK".
#[test]
fn rfc3394_4_4_wrap_192_bits_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 24, 32, AES192Key<KW>>(
        &bytes(&RFC3394_KEK[..48]),
        &bytes(&RFC3394_KEY_DATA[..48]),
        &bytes("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"),
    );
}

/// Sec 4.5, "Wrap 192 bits of Key Data with a 256-bit KEK".
#[test]
fn rfc3394_4_5_wrap_192_bits_with_a_256_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<32, 24, 32, AES256Key<KW>>(
        &bytes(RFC3394_KEK),
        &bytes(&RFC3394_KEY_DATA[..48]),
        &bytes("a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"),
    );
}

/// Sec 4.6, "Wrap 256 bits of Key Data with a 256-bit KEK".
#[test]
fn rfc3394_4_6_wrap_256_bits_with_a_256_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<32, 32, 40, AES256Key<KW>>(
        &bytes(RFC3394_KEK),
        &bytes(RFC3394_KEY_DATA),
        &bytes("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"),
    );
}

// ---- RFC 5649 Sec 6: the KWP vectors -------------------------------------------------------

const RFC5649_KEK: &str = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";

/// "The first example wraps 20 octets of key data with a 192-bit KEK": 20 bytes pad to 24, and
/// the 32-byte result goes through the wrapping function proper.
#[test]
fn rfc5649_wrap_20_octets_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 20, 32, AES192Key<KWP>>(
        &bytes(RFC5649_KEK),
        &bytes("c37b7e6492584340bed12207808941155068f738"),
        &bytes("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"),
    );
}

/// "The second example wraps 7 octets of key data with a 192-bit KEK": header plus data fit one
/// block, so this is the single-block path (SP 800-38F Algorithm 5 step 5 / Algorithm 6 step 3).
#[test]
fn rfc5649_wrap_7_octets_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 7, 16, AES192Key<KWP>>(
        &bytes(RFC5649_KEK),
        &bytes("466f7250617369"),
        &bytes("afbeb0f07dfbf5419200f2ccb50bb24f"),
    );
}

// ---- the shared frameworks ------------------------------------------------------------------

/// The construction suite -- key type, strength and `generate` -- for both modes at every key
/// length.
#[test]
fn the_keys_enforce_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<16, AES128Key<KW>>(AES128Internal::KW_ALG_NAME, SecurityStrength::_128bit);
    framework.test::<24, AES192Key<KW>>(AES192Internal::KW_ALG_NAME, SecurityStrength::_192bit);
    framework.test::<32, AES256Key<KW>>(AES256Internal::KW_ALG_NAME, SecurityStrength::_256bit);
    framework.test::<16, AES128Key<KWP>>(AES128Internal::KWP_ALG_NAME, SecurityStrength::_128bit);
    framework.test::<24, AES192Key<KWP>>(AES192Internal::KWP_ALG_NAME, SecurityStrength::_192bit);
    framework.test::<32, AES256Key<KWP>>(AES256Internal::KWP_ALG_NAME, SecurityStrength::_256bit);
}

#[test]
fn kw_conforms_to_the_framework() {
    let tf = TestFrameworkKeyWrap::new();
    // AES-128 KEK: 128-, 192-, 256-bit keys and a 64-byte payload (n = 9 semiblocks).
    tf.test::<16, 16, 24, AES128Key<KW>>();
    tf.test::<16, 24, 32, AES128Key<KW>>();
    tf.test::<16, 32, 40, AES128Key<KW>>();
    tf.test::<16, 64, 72, AES128Key<KW>>();
    tf.test::<24, 16, 24, AES192Key<KW>>();
    tf.test::<24, 32, 40, AES192Key<KW>>();
    tf.test::<32, 16, 24, AES256Key<KW>>();
    tf.test::<32, 32, 40, AES256Key<KW>>();
}

#[test]
fn kwp_conforms_to_the_framework() {
    let tf = TestFrameworkKeyWrap::new();
    // Every padding length from 0 to 7 in the single-block case (1..=8 bytes -> 16), then the
    // boundary into the wrapping function (9 -> 24), unaligned and aligned longer inputs.
    tf.test::<16, 1, 16, AES128Key<KWP>>();
    tf.test::<16, 2, 16, AES128Key<KWP>>();
    tf.test::<16, 3, 16, AES128Key<KWP>>();
    tf.test::<16, 4, 16, AES128Key<KWP>>();
    tf.test::<16, 5, 16, AES128Key<KWP>>();
    tf.test::<16, 6, 16, AES128Key<KWP>>();
    tf.test::<16, 7, 16, AES128Key<KWP>>();
    tf.test::<16, 8, 16, AES128Key<KWP>>();
    tf.test::<16, 9, 24, AES128Key<KWP>>();
    tf.test::<16, 13, 24, AES128Key<KWP>>();
    tf.test::<16, 16, 24, AES128Key<KWP>>();
    tf.test::<16, 20, 32, AES128Key<KWP>>();
    tf.test::<16, 32, 40, AES128Key<KWP>>();
    tf.test::<16, 100, 112, AES128Key<KWP>>();
    tf.test::<24, 7, 16, AES192Key<KWP>>();
    tf.test::<24, 32, 40, AES192Key<KWP>>();
    tf.test::<32, 7, 16, AES256Key<KWP>>();
    tf.test::<32, 32, 40, AES256Key<KWP>>();
}

// ---- the keys and the aliases ---------------------------------------------------------------

/// The three key lengths are distinct algorithms: the same data under the "same" KEK bytes gives
/// three different ciphertexts.
#[test]
fn the_three_key_lengths_are_not_interchangeable() {
    let data = [0x5Au8; 16];
    let ct128: [u8; 24] = key128::<KW>(&RFC3394_KEK[..32]).wrap_key(&data).unwrap();
    let ct192: [u8; 24] = key192::<KW>(&RFC3394_KEK[..48]).wrap_key(&data).unwrap();
    let ct256: [u8; 24] = key256::<KW>(RFC3394_KEK).wrap_key(&data).unwrap();
    assert_ne!(ct128, ct192);
    assert_ne!(ct192, ct256);
    assert_ne!(ct128, ct256);
}

/// The keys hand out exactly the aliased workers (whose names are pinned in `alg_name_tests`).
#[test]
fn the_keys_hand_out_the_aliased_workers() {
    let kek = key128::<KW>(&RFC3394_KEK[..32]);
    let _: AES_KW_128<'_> = kek.create_wrapper();
    let _: AES_KW_128<'_> = kek.create_unwrapper();
    let kek = key192::<KW>(&RFC3394_KEK[..48]);
    let _: AES_KW_192<'_> = kek.create_wrapper();
    let kek = key256::<KW>(RFC3394_KEK);
    let _: AES_KW_256<'_> = kek.create_unwrapper();
    let kek = key128::<KWP>(&RFC3394_KEK[..32]);
    let _: AES_KWP_128<'_> = kek.create_wrapper();
    let kek = key192::<KWP>(&RFC3394_KEK[..48]);
    let _: AES_KWP_192<'_> = kek.create_unwrapper();
    let kek = key256::<KWP>(RFC3394_KEK);
    let _: AES_KWP_256<'_> = kek.create_wrapper();
}

/// The sizes the docs quote: the key is the schedule, the worker is the borrow.
#[test]
fn sizes() {
    use core::mem::size_of;
    assert_eq!(
        [size_of::<AES128Key<KW>>(), size_of::<AES192Key<KW>>(), size_of::<AES256Key<KW>>()],
        [size_of::<AES128Internal>(), size_of::<AES192Internal>(), size_of::<AES256Internal>()]
    );
    assert_eq!(size_of::<AES128Key<KWP>>(), size_of::<AES128Key<KW>>());
    assert_eq!(size_of::<AES_KW_128>(), size_of::<&AES128Internal>());
    assert_eq!(size_of::<AES_KWP_256>(), size_of::<&AES256Internal>());
}

/// Equality follows the material: the same bytes compare equal, as does a clone, and different
/// bytes do not.
#[test]
fn keys_compare_equal_exactly_when_their_material_does() {
    let kek = key128::<KW>(&RFC3394_KEK[..32]);
    assert!(kek == kek.clone());
    assert!(kek == key128::<KW>(&RFC3394_KEK[..32]));
    assert!(kek != key128::<KW>(&RFC3394_KEK[2..34]));
}
