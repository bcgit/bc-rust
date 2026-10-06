//! KMAC and KMACXOF behaviour tests. The SP 800-185 sample values are in `kmac_bc-test-data.rs`.

use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, Hash, MAC, XOF, XOFSqueezer};
use bouncycastle_sha3::kmac::{KMAC128, KMAC256, KMACXOF128, KMACXOF256};

/// A 32-byte MAC key carries a 256-bit strength, so it satisfies both KMAC128 and KMAC256 without
/// the weak-key escape hatch.
fn key_material(bytes: &[u8]) -> KeyMaterial<32> {
    assert_eq!(bytes.len(), 32, "the sample keys are all 32 bytes");
    KeyMaterial::<32>::from_bytes_as_type(bytes, KeyType::MACKey).expect("a valid MAC key")
}

/// The output length is absorbed, so asking for a different length is a different function -- not
/// a prefix. Sec 1: "any change in the requested output length completely changes the function".
#[test]
fn output_length_changes_the_function() {
    let key = key_material(&[0x42u8; 32]);
    let short = KMAC128::new_with_params(&key, b"", 16, false).unwrap().mac(b"abc");
    let long = KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(b"abc");

    assert_eq!(short.len(), 16);
    assert_eq!(long.len(), 32);
    assert_ne!(&long[..16], &short[..], "a longer KMAC must not extend a shorter one");
}

/// The customization string separates one use of KMAC from another (Sec 4.2).
#[test]
fn customization_separates_the_functions() {
    let key = key_material(&[0x42u8; 32]);
    let plain = KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(b"abc");
    let custom =
        KMAC128::new_with_params(&key, b"My Tagged Application", 32, false).unwrap().mac(b"abc");
    assert_ne!(plain, custom, "a customization string must change the output");
}

/// Streaming input must equal the one-shot, and `verify` must accept only the right tag.
#[test]
fn streaming_and_verification() {
    let key = key_material(&[0x11u8; 32]);
    let msg: Vec<u8> = (0..=255u8).collect();

    let one = KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(&msg);

    let mut k = KMAC128::new_with_params(&key, b"", 32, false).unwrap();
    for chunk in msg.chunks(13) {
        k.do_update(chunk);
    }
    assert_eq!(k.do_final(), one, "chunked input must equal the one-shot");

    assert!(
        KMAC128::new_with_params(&key, b"", 32, false).unwrap().verify(&msg, &one),
        "the correct tag must verify"
    );

    let mut wrong = one.clone();
    wrong[0] ^= 1;
    assert!(
        !KMAC128::new_with_params(&key, b"", 32, false).unwrap().verify(&msg, &wrong),
        "a corrupted tag must not verify"
    );
    assert!(
        !KMAC128::new_with_params(&key, b"", 32, false).unwrap().verify(&msg, &one[..16]),
        "a truncated tag must not verify"
    );
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

    assert!(KMAC256::new(&weak).is_err(), "a 128-bit key must not instantiate KMAC256");
    assert!(KMAC256::new_allow_weak_key(&weak).is_ok(), "... unless explicitly allowed");
    assert!(KMAC128::new(&weak).is_ok(), "but it is enough for KMAC128");
}

/// The default constructor: no customization, nominal output length.
#[test]
fn default_constructor_uses_the_nominal_length() {
    let key = key_material(&[0x42u8; 32]);
    assert_eq!(KMAC128::new(&key).unwrap().output_len(), 32);
    assert_eq!(KMAC256::new(&key).unwrap().output_len(), 64);

    // ... and agrees with spelling the same thing out in full.
    assert_eq!(
        KMAC128::new(&key).unwrap().mac(b"abc"),
        KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(b"abc"),
    );
}

#[test]
fn algorithm_names() {
    assert_eq!(KMAC128::ALG_NAME, "KMAC128");
    assert_eq!(KMAC256::ALG_NAME, "KMAC256");
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
        KMAC128::new(&key).unwrap().mac(b"abc"),
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

/// `new_allow_weak_key` is `new` without the strength check: same customization, same nominal
/// length, same tag.
#[test]
fn new_allow_weak_key_uses_the_nominal_length() {
    let key = key_material(&[0x42u8; 32]);

    let k = KMAC128::new_allow_weak_key(&key).unwrap();
    assert_eq!(k.output_len(), 32);
    assert_eq!(k.mac(b"abc"), KMAC128::new(&key).unwrap().mac(b"abc"));

    let k = KMAC256::new_allow_weak_key(&key).unwrap();
    assert_eq!(k.output_len(), 64);
    assert_eq!(k.mac(b"abc"), KMAC256::new(&key).unwrap().mac(b"abc"));
}

/// The same stance as HMAC: a key tagged `MACKey` or `Zeroized` is accepted, anything else is
/// refused as the wrong type. A zeroized key carries no security strength, so it also needs
/// `allow_weak_key`.
#[test]
fn key_type_is_checked() {
    let cipher_key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::SymmetricCipherKey).unwrap();
    assert!(matches!(
        KMAC128::new(&cipher_key),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        KMAC128::new_with_params(&cipher_key, b"", 32, true),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        KMACXOF128::new(&cipher_key, b"", true),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    let zero = KeyMaterial::<32>::new();
    assert_eq!(zero.key_type(), KeyType::Zeroized);
    assert!(KMAC128::new(&zero).is_err(), "a zeroized key has no security strength");
    assert!(KMAC128::new_with_params(&zero, b"", 32, true).is_ok(), "... but is the right type");
    assert!(KMAC128::new_allow_weak_key(&zero).is_ok());
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
