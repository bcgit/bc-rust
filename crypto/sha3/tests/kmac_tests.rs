//! KMAC and KMACXOF behaviour tests. The SP 800-185 sample values are in `kmac_bc-test-data.rs`.

use bouncycastle_core::direction::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{Algorithm, Hash, MACGenerator, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromAnyKeyMaterial;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_sha3::kmac::{
    KMAC_MIN_OUTPUT_LEN, KMAC128, KMAC128Key, KMAC256, KMAC256Key, KMACXOF128, KMACXOF256,
};

/// A 32-byte MAC key carries a 256-bit strength, so it satisfies both KMAC128 and KMAC256 without
/// the weak-key escape hatch.
fn key_material(bytes: &[u8]) -> KeyMaterial<32> {
    assert_eq!(bytes.len(), 32, "the sample keys are all 32 bytes");
    KeyMaterial::<32>::from_bytes_as_type(bytes, KeyType::MACKey).expect("a valid MAC key")
}

/// The output length is absorbed, so a key type at a different length is a different function --
/// not a prefix. Sec 1: "any change in the requested output length completely changes the
/// function".
#[test]
fn output_length_changes_the_function() {
    let key = key_material(&[0x42u8; 32]);
    let short: [u8; 16] = KMAC128Key::<16>::with_params(&key, b"").unwrap().mac(b"abc");
    let long: [u8; 32] = KMAC128Key::<32>::with_params(&key, b"").unwrap().mac(b"abc");

    assert_ne!(&long[..16], &short[..], "a longer KMAC must not extend a shorter one");
}

/// The customization string separates one use of KMAC from another (Sec 4.2).
#[test]
fn customization_separates_the_functions() {
    let key = key_material(&[0x42u8; 32]);
    let plain = KMAC128Key::<32>::with_params(&key, b"").unwrap().mac(b"abc");
    let custom = KMAC128Key::<32>::with_params(&key, b"My Tagged Application").unwrap().mac(b"abc");
    assert_ne!(plain, custom, "a customization string must change the output");
}

/// Streaming input must equal the one-shot, and `verify` must accept only the right tag: the
/// shared MAC key suite, over both parameter sets and a non-default length.
#[test]
fn streaming_and_verification() {
    let key = key_material(&[0x11u8; 32]);
    let msg: Vec<u8> = (0..=255u8).collect();

    let key128 = KMAC128Key::<32>::with_params(&key, b"").unwrap();
    let one = key128.mac(&msg);
    let mut k = key128.create_generator();
    for chunk in msg.chunks(13) {
        k.do_update(chunk);
    }
    assert_eq!(k.do_final(), one, "chunked input must equal the one-shot");
    TestFrameworkMAC::new().test_mac_key(&key128, &msg, &one);

    let key256 = KMAC256Key::<64>::with_params(&key, b"S").unwrap();
    TestFrameworkMAC::new().test_mac_key(&key256, &msg, &key256.mac(&msg));

    let key16 = KMAC128Key::<16>::with_params(&key, b"").unwrap();
    TestFrameworkMAC::new().test_mac_key(&key16, &msg, &key16.mac(&msg));
}

/// Sec 8.4.1 wants the key at least as long as the security strength; the tag on the key material
/// is how that is enforced, so a key tagged too weak must be refused unless explicitly allowed.
#[test]
fn weak_keys_are_refused_unless_allowed() {
    let weak = KeyMaterial::<16>::from_bytes_as_type(&[0x01u8; 16], KeyType::MACKey)
        .expect("a valid 16-byte MAC key");
    assert!(
        weak.security_strength() < bouncycastle_core::security_strength::SecurityStrength::_256bit
    );

    assert!(
        KMAC256Key::<64>::from_key_material(&weak).is_err(),
        "a 128-bit key must not make a KMAC256 key"
    );
    assert!(
        KMAC256Key::<64>::from_key_material_allow_weak(&weak).is_ok(),
        "... unless explicitly allowed"
    );
    assert!(KMAC256Key::<16>::with_params(&weak, b"S").is_err());
    assert!(KMAC256Key::<16>::with_params_allow_weak(&weak, b"S").is_ok());
    assert!(KMAC128Key::<32>::from_key_material(&weak).is_ok(), "but it is enough for KMAC128");
}

/// The construction suite for both keys: a weak key accepted only through the `_allow_weak`
/// form, a no-strength key refused at any strength, generate at the key's strength.
#[test]
fn the_keys_enforce_the_material_policy() {
    let key = key_material(&[0x42u8; 32]);
    let framework = TestFrameworkFromAnyKeyMaterial::new();
    framework.test::<32, KMAC128Key>(&key);
    framework.test::<64, KMAC256Key>(&key);
    framework.test::<16, KMAC128Key<16>>(&key);
}

/// `from_key_material`: no customization string, at the key type's length.
#[test]
fn from_key_material_has_no_customization() {
    let key = key_material(&[0x42u8; 32]);
    let nominal: [u8; 32] = KMAC128Key::<32>::from_key_material(&key).unwrap().mac(b"abc");
    assert_eq!(nominal, KMAC128Key::<32>::with_params(&key, b"").unwrap().mac(b"abc"));
    let nominal: [u8; 64] = KMAC256Key::<64>::from_key_material(&key).unwrap().mac(b"abc");
    assert_eq!(nominal, KMAC256Key::<64>::with_params(&key, b"").unwrap().mac(b"abc"));
    let short: [u8; 8] = KMAC256Key::<8>::from_key_material(&key).unwrap().mac(b"abc");
    assert_eq!(short, KMAC256Key::<8>::with_params(&key, b"").unwrap().mac(b"abc"));
}

/// `generate` draws a key of the strength's length and tags it a MAC key, so the key it builds
/// is a full-strength one.
#[test]
fn generate_draws_a_key() {
    let mut rng = bouncycastle_rng::HashDRBG_SHA512::new_from_os();
    let key = KMAC256Key::<64>::generate(&mut rng).unwrap();
    let tag: [u8; 64] = key.mac(b"abc");
    assert_eq!(key.verify(b"abc", &tag), Ok(()));
    assert_ne!(
        KMAC256Key::<64>::generate(&mut rng).unwrap().mac(b"abc"),
        tag,
        "a fresh key each time"
    );
}

#[test]
fn algorithm_names() {
    assert_eq!(KMAC128::<Encrypting>::ALG_NAME, "KMAC128");
    assert_eq!(KMAC128::<Decrypting>::ALG_NAME, "KMAC128");
    assert_eq!(KMAC256::<Encrypting>::ALG_NAME, "KMAC256");
    assert_eq!(KMAC256::<Decrypting, 16>::ALG_NAME, "KMAC256");
}

/// The counterpart to `output_length_changes_the_function`: read as a stream, KMACXOF binds
/// `right_encode(0)` rather than the length, so output at one length *is* a prefix of output at a
/// longer one. The `Hash` view is not part of that stream -- it is a final read at the nominal
/// length, so it binds `L` and computes fixed-length KMAC128 instead.
#[test]
fn kmacxof_output_is_one_stream() {
    let key = key_material(&[0x42u8; 32]);
    let squeeze = |n| {
        let mut k = KMACXOF128::new(&key, b"", false).unwrap();
        k.do_update(b"abc");
        k.into_squeezer().do_output(n)
    };
    let long = squeeze(64);

    let short = squeeze(16);
    assert_eq!(&long[..16], &short[..], "KMACXOF at a shorter length must be a prefix");

    let mut k = KMACXOF128::new(&key, b"", false).unwrap();
    k.do_update(b"abc");
    let via_hash = k.do_final();
    assert_eq!(via_hash.len(), 32, "the nominal output length");
    assert_ne!(&long[..32], &via_hash[..], "the Hash view binds L, so it leaves the stream");
    assert_eq!(
        via_hash,
        KMAC128Key::<32>::from_key_material(&key).unwrap().mac(b"abc"),
        "... and lands on fixed-length KMAC128 at the nominal length"
    );
}

/// A partial final byte cannot be expressed: `right_encode(0)` has to follow the message, and the
/// sponge cannot absorb byte-aligned data after a partial byte.
#[test]
fn kmacxof_rejects_a_partial_final_byte() {
    let key = key_material(&[0x42u8; 32]);
    let mut k = KMACXOF128::new(&key, b"", false).unwrap();
    k.do_update(b"abc");
    assert!(matches!(
        k.into_squeezer_partial_bits(0xF0, 4),
        Err(bouncycastle_core::errors::HashError::InvalidLength(_))
    ));

    // ... but zero bits means the message ended on a byte boundary, which is fine.
    let mut k = KMACXOF128::new(&key, b"", false).unwrap();
    k.do_update(b"abc");
    assert!(k.into_squeezer_partial_bits(0, 0).is_ok());
}

#[test]
fn kmacxof_algorithm_names() {
    assert_eq!(KMACXOF128::ALG_NAME, "KMACXOF128");
    assert_eq!(KMACXOF256::ALG_NAME, "KMACXOF256");
}

/// `from_key_material_allow_weak` is `from_key_material` without the strength check: same
/// customization, same length, same tag.
#[test]
fn from_key_material_allow_weak_has_no_customization() {
    let key = key_material(&[0x42u8; 32]);

    let k = KMAC128Key::<32>::from_key_material_allow_weak(&key).unwrap();
    assert_eq!(k.mac(b"abc"), KMAC128Key::<32>::from_key_material(&key).unwrap().mac(b"abc"));

    let k = KMAC256Key::<64>::from_key_material_allow_weak(&key).unwrap();
    assert_eq!(k.mac(b"abc"), KMAC256Key::<64>::from_key_material(&key).unwrap().mac(b"abc"));
}

/// The same stance as HMAC: a key tagged `MACKey` or `Zeroized` is accepted, anything else is
/// refused as the wrong type. A zeroized key carries no security strength, so it also needs
/// `allow_weak_key`.
#[test]
fn key_type_is_checked() {
    let cipher_key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::SymmetricCipherKey).unwrap();
    assert!(matches!(
        KMAC128Key::<32>::from_key_material(&cipher_key),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        KMAC128Key::<32>::with_params_allow_weak(&cipher_key, b""),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        KMACXOF128::new(&cipher_key, b"", true),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    let zero = KeyMaterial::<32>::new();
    assert_eq!(zero.key_type(), KeyType::Zeroized);
    assert!(
        KMAC128Key::<32>::from_key_material(&zero).is_err(),
        "a zeroized key has no security strength"
    );
    assert!(
        KMAC128Key::<32>::with_params_allow_weak(&zero, b"").is_ok(),
        "... but is the right type"
    );
    assert!(KMAC128Key::<32>::from_key_material_allow_weak(&zero).is_ok());
    assert!(KMACXOF128::new(&zero, b"", true).is_ok());
}

/// The `Hash` view of the partial-byte entry points on KMACXOF: zero bits is the byte-aligned case
/// and yields the same bytes as `do_final`; anything else is refused. The test above only covers
/// the `XOF` entry point, `into_squeezer_partial_bits`.
#[test]
fn kmacxof_hash_view_partial_bits() {
    let key = key_material(&[0x42u8; 32]);
    let fresh = || {
        let mut k = KMACXOF128::new(&key, b"", false).unwrap();
        k.do_update(b"abc");
        k
    };
    let expected = fresh().do_final();
    assert_eq!(expected.len(), 32);

    assert_eq!(fresh().do_final_partial_bits(0, 0).unwrap(), expected);
    let mut out = vec![0u8; 32];
    assert_eq!(fresh().do_final_partial_bits_out(0, 0, &mut out).unwrap(), 32);
    assert_eq!(out, expected);

    assert!(matches!(
        fresh().do_final_partial_bits(0xF0, 4),
        Err(bouncycastle_core::errors::HashError::InvalidLength(_))
    ));
    assert!(matches!(
        fresh().do_final_partial_bits_out(0xF0, 4, &mut out),
        Err(bouncycastle_core::errors::HashError::InvalidLength(_))
    ));
}

/// SP 800-185 Sec 8.4.2's floor is the shortest key type that compiles (a shorter one is a
/// compile error, see the `KMACKeyInternal` docs), and a key at the floor works.
#[test]
fn the_shortest_output_length_works() {
    let key = key_material(&[0x42; 32]);
    assert_eq!(KMAC_MIN_OUTPUT_LEN, 4);
    let shortest = KMAC128Key::<KMAC_MIN_OUTPUT_LEN>::with_params(&key, b"").unwrap();
    let tag = shortest.mac(b"abc");
    assert_eq!(shortest.verify(b"abc", &tag), Ok(()));
    assert_eq!(shortest.verify(b"abd", &tag), Err(MACError::VerificationFailed));
}

/// KMACXOF's inherent one-shots are its `Hash` view in one call: a final read at the nominal
/// length, which is fixed-length KMAC at that length.
#[test]
fn kmacxof_one_shots_are_the_hash_view() {
    let key = key_material(&[0x42u8; 32]);
    let expected = KMAC128Key::<32>::from_key_material(&key).unwrap().mac(b"abc");
    assert_eq!(KMACXOF128::new(&key, b"", false).unwrap().hash(b"abc"), expected);
    let mut out = [0xFFu8; 40];
    assert_eq!(KMACXOF128::new(&key, b"", false).unwrap().hash_out(b"abc", &mut out), 32);
    assert_eq!(out[..32], expected);
    assert_eq!(out[32..], [0u8; 8]);
}

/// `generate` tags the drawn key at the RNG's strength when that is below what the length
/// carries, so a 128-bit DRBG makes a key KMAC256 refuses and KMAC128 accepts.
#[test]
fn generate_refuses_an_rng_below_the_kmac_strength() {
    let mut weak = bouncycastle_rng::FixedSeedRNG::new([0x5Au8; 32]);
    weak.set_security_strength(bouncycastle_core::security_strength::SecurityStrength::_128bit);
    assert!(matches!(
        KMAC256Key::<64>::generate(&mut weak),
        Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
    assert!(KMAC128Key::<32>::generate(&mut weak).is_ok());
}
