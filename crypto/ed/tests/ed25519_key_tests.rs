//! The Ed25519 key objects: generation, `keygen_out` and the all-zero key it writes into,
//! encoding and decoding, and the full validation of a decoded public key.

use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, RNGError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{DeterministicOneShotSigningKey, OneShotVerifyingKey};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_core_test_framework::FailingRNG;
use bouncycastle_core_test_framework::signature::TestFrameworkSignatureKeys;
use bouncycastle_ed::ed25519::{
    Ed25519PrivateKey, Ed25519PublicKey, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, keygen, keygen_out,
    keypair_consistency_check,
};

const ZEROIZED: SignatureError =
    SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

/// 64 distinct octets, so that a second 32-octet draw differs from the first.
fn rng() -> FixedSeedRNG<[u8; 64]> {
    FixedSeedRNG::new(core::array::from_fn(|i| i as u8))
}

fn octets(hex: &str) -> [u8; 32] {
    bouncycastle_hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn key_encoding_framework() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<Ed25519PublicKey, Ed25519PrivateKey, PUBLIC_KEY_LEN, PRIVATE_KEY_LEN>(|| {
            keygen(&mut rng())
        });
}

/// The sizes the module's Memory Usage table gives.
#[test]
fn key_object_sizes() {
    assert_eq!((PRIVATE_KEY_LEN, PUBLIC_KEY_LEN), (32, 32));
    assert_eq!(core::mem::size_of::<Ed25519PublicKey>(), 80);
    assert_eq!(core::mem::size_of::<Ed25519PrivateKey>(), 128);
}

/// The private key is the 32 octets the RNG gave, and the public key is the one RFC 8032
/// derives from them.
#[test]
fn keygen_draws_the_private_key() {
    let (pk, sk) = keygen(&mut rng()).unwrap();
    let drawn: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(sk.encode(), drawn);
    assert!(sk == Ed25519PrivateKey::from_bytes(&drawn).unwrap());
    assert_eq!(pk, sk.pk().unwrap());
    keypair_consistency_check(&pk, &sk).unwrap();

    // The next draw is another key.
    let mut rng = rng();
    let (_, first) = keygen(&mut rng).unwrap();
    let (pk2, second) = keygen(&mut rng).unwrap();
    assert!(first == sk && second != sk);
    assert_ne!(pk2, pk);
    assert_eq!(keypair_consistency_check(&pk2, &sk), Err(SignatureError::ConsistencyCheckFailed));
    assert_eq!(
        keypair_consistency_check(&pk, &second),
        Err(SignatureError::ConsistencyCheckFailed)
    );
}

#[test]
fn keygen_out_matches_keygen_and_signs() {
    let (pk, sk) = keygen(&mut rng()).unwrap();
    let mut sk_out = Ed25519PrivateKey::zeroized();
    let pk_out = keygen_out(&mut rng(), &mut sk_out).unwrap();
    assert_eq!(pk_out, pk);
    assert!(sk_out == sk);
    assert_eq!(sk_out.encode(), sk.encode());

    let sig = sk_out.sign_deterministic(b"msg", None).unwrap();
    pk.verify(b"msg", None, &sig).unwrap();
    assert_eq!(sig, sk.sign_deterministic(b"msg", None).unwrap());
}

/// A key that already holds one key pair holds exactly the new one afterwards.
#[test]
fn refilling_replaces_the_key() {
    let mut rng = rng();
    let mut sk = Ed25519PrivateKey::zeroized();
    let pk1 = keygen_out(&mut rng, &mut sk).unwrap();
    let pk2 = keygen_out(&mut rng, &mut sk).unwrap();
    assert_ne!(pk1, pk2);
    assert_eq!(sk.pk().unwrap(), pk2);
    let second: [u8; 32] = core::array::from_fn(|i| 32 + i as u8);
    assert_eq!(sk.encode(), second);
    assert!(sk == Ed25519PrivateKey::from_bytes(&second).unwrap());
}

/// A failed generation leaves the key as `zeroized()` makes it, whatever it held before.
#[test]
fn a_failed_keygen_leaves_the_key_unfilled() {
    let mut weak = rng();
    weak.set_security_strength(SecurityStrength::_112bit);
    let insufficient = SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm);
    assert_eq!(keygen(&mut weak).err(), Some(insufficient));
    let mut exact = rng();
    exact.set_security_strength(SecurityStrength::_128bit);
    assert!(keygen(&mut exact).is_ok());

    /// Strong enough, and fails to deliver.
    struct Dry;
    impl bouncycastle_core::traits::RNG for Dry {
        fn add_seed_keymaterial(
            &mut self,
            _: &dyn bouncycastle_core::key_material::KeyMaterialTrait,
        ) -> Result<(), RNGError> {
            Ok(())
        }
        fn next_int(&mut self) -> Result<u32, RNGError> {
            Err(RNGError::GenericError("dry"))
        }
        fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
            // Leaves something behind, as a failing source might.
            out.fill(0xEE);
            Err(RNGError::GenericError("dry"))
        }
        fn fill_keymaterial_out(
            &mut self,
            _: &mut dyn bouncycastle_core::key_material::KeyMaterialTrait,
        ) -> Result<usize, RNGError> {
            Err(RNGError::GenericError("dry"))
        }
        fn security_strength(&self) -> SecurityStrength {
            SecurityStrength::_256bit
        }
    }

    let failing: [&mut dyn bouncycastle_core::traits::RNG; 3] =
        [&mut FailingRNG, &mut weak, &mut Dry];
    for rng_that_fails in failing {
        let (_, mut sk) = keygen(&mut rng()).unwrap();
        assert!(matches!(keygen_out(rng_that_fails, &mut sk), Err(SignatureError::RNGError(_))));
        assert!(sk == Ed25519PrivateKey::zeroized());
        assert_eq!(sk.encode(), [0u8; 32]);
        assert_eq!(sk.pk().err(), Some(ZEROIZED));
    }
}

/// The all-zero key has no public key, is part of no key pair, and is not the key decoded
/// from 32 zero octets, which is an ordinary key.
#[test]
fn the_unfilled_key() {
    let unfilled = Ed25519PrivateKey::zeroized();
    assert_eq!(unfilled.pk().err(), Some(ZEROIZED));
    assert!(unfilled == Ed25519PrivateKey::zeroized());
    assert!(unfilled == unfilled.clone());
    assert_eq!(unfilled.encode(), [0u8; 32]);

    let zeros = Ed25519PrivateKey::from_bytes(&[0u8; 32]).unwrap();
    assert_eq!(zeros.encode(), unfilled.encode());
    // Both directions, on purpose.
    #[allow(clippy::nonminimal_bool)]
    {
        assert!(zeros != unfilled && unfilled != zeros);
    }
    let pk = zeros.pk().unwrap();
    keypair_consistency_check(&pk, &zeros).unwrap();
    assert_eq!(keypair_consistency_check(&pk, &unfilled), Err(ZEROIZED));
}

/// `from_bytes_out` fills a key the caller holds as `from_bytes` would, replaces what the key
/// held, and leaves it as `zeroized()` makes it when the octets are refused.
#[test]
fn from_bytes_out_fills_a_held_key() {
    let (pk, sk) = keygen(&mut rng()).unwrap();
    let mut held = Ed25519PrivateKey::zeroized();
    Ed25519PrivateKey::from_bytes_out(&sk.encode(), &mut held).unwrap();
    assert!(held == sk);
    assert_eq!(held.pk().unwrap(), pk);
    assert_eq!(held.sign_deterministic(b"msg", None), sk.sign_deterministic(b"msg", None));

    Ed25519PrivateKey::from_bytes_out(&[7u8; 32], &mut held).unwrap();
    assert!(held == Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap() && held != sk);

    for wrong in [&[7u8; 31][..], &[7u8; 33], &[]] {
        Ed25519PrivateKey::from_bytes_out(&sk.encode(), &mut held).unwrap();
        assert_eq!(
            Ed25519PrivateKey::from_bytes_out(wrong, &mut held),
            Err(KeyDecodingError("An Ed25519 private key must be 32 bytes"))
        );
        assert!(held == Ed25519PrivateKey::zeroized());
        assert_eq!(held.encode(), [0u8; 32]);
        assert_eq!(held.pk().err(), Some(ZEROIZED));
    }
}

/// `clone` and `clone_from` give the same key, and `clone_from` replaces what the destination
/// held, an unfilled source included.
#[test]
fn clone_and_clone_from() {
    let (pk, sk) = keygen(&mut rng()).unwrap();
    assert!(sk.clone() == sk);
    assert_eq!(sk.clone().pk().unwrap(), pk);

    let mut held = Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    held.clone_from(&sk);
    assert!(held == sk);
    assert_eq!(held.encode(), sk.encode());
    assert_eq!(held.pk().unwrap(), pk);
    assert_eq!(held.sign_deterministic(b"msg", None), sk.sign_deterministic(b"msg", None));

    held.clone_from(&Ed25519PrivateKey::zeroized());
    assert!(held == Ed25519PrivateKey::zeroized());
    assert_eq!(held.pk().err(), Some(ZEROIZED));
}

#[test]
fn keys_round_trip_through_their_encodings() {
    let (pk, sk) = keygen(&mut rng()).unwrap();

    let sk_bytes = sk.encode();
    let mut out = [0xA5u8; PRIVATE_KEY_LEN];
    assert_eq!(sk.encode_out(&mut out), PRIVATE_KEY_LEN);
    assert_eq!(out, sk_bytes);
    let sk2 = Ed25519PrivateKey::from_bytes(&sk_bytes).unwrap();
    assert!(sk2 == sk && sk.clone() == sk);
    assert_eq!(sk2.pk().unwrap(), pk);

    let pk_bytes = pk.encode();
    let mut out = [0xA5u8; PUBLIC_KEY_LEN];
    assert_eq!(pk.encode_out(&mut out), PUBLIC_KEY_LEN);
    assert_eq!(out, pk_bytes);
    let pk2 = Ed25519PublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk2, pk);
    assert_eq!(pk2.encode(), pk_bytes);
    assert_eq!(pk.clone(), pk);

    // One octet of difference is another key.
    let mut other = sk_bytes;
    other[31] ^= 0x80;
    assert!(Ed25519PrivateKey::from_bytes(&other).unwrap() != sk);

    assert_eq!(
        Ed25519PrivateKey::from_bytes(&sk_bytes[..31]).err(),
        Some(KeyDecodingError("An Ed25519 private key must be 32 bytes"))
    );
    assert_eq!(
        Ed25519PublicKey::from_bytes(&pk_bytes[..31]),
        Err(KeyDecodingError("An Ed25519 public key must be 32 bytes"))
    );
}

/// `Display` and `Debug` show the encoding in hex.
#[test]
fn a_public_key_prints_its_encoding() {
    // RFC 8032 Section 7.1, TEST 1's public key.
    let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let pk = Ed25519PublicKey::from_bytes(&octets(hex)).unwrap();
    let expected = format!("Ed25519PublicKey {{ {hex} }}");
    assert_eq!(format!("{pk}"), expected);
    assert_eq!(format!("{pk:?}"), expected);
}

const NOT_A_KEY: Result<Ed25519PublicKey, KeyDecodingError> =
    Err(KeyDecodingError("Not the encoding of an Ed25519 public key in the prime-order subgroup"));

/// RFC 8032 Section 5.1.3: an encoding whose y is not below p, or whose x is zero with the
/// sign bit set, or whose y has no x, does not decode.
#[test]
fn non_canonical_and_off_curve_encodings_are_refused() {
    for (what, hex) in [
        ("y = p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("y = p + 1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("y = 2^255 - 1", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("y = p, sign set", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        (
            "x = 0, y = 1, sign set",
            "0100000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            "x = 0, y = -1, sign set",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        // (y^2 - 1) / (d y^2 + 1) is not a square for y = 2.
        ("y = 2", "0200000000000000000000000000000000000000000000000000000000000000"),
    ] {
        assert_eq!(Ed25519PublicKey::from_bytes(&octets(hex)), NOT_A_KEY, "{what}");
    }
}

/// Full validation: the eight points of small order, canonically encoded, and points of mixed
/// order (a point of order L plus one of small order) are on the curve and are refused.
#[test]
fn keys_outside_the_prime_order_subgroup_are_refused() {
    // The canonical encodings of the points of order 1, 2, 4, 4, 8, 8, 8 and 8.
    for hex in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ] {
        assert_eq!(Ed25519PublicKey::from_bytes(&octets(hex)), NOT_A_KEY, "small order {hex}");
    }
    // The mixed-order keys of "Taming the many EdDSAs", vectors 2 to 5, 8 and 9 (see
    // ed25519_taming_tests.rs).
    for hex in [
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
    ] {
        assert_eq!(Ed25519PublicKey::from_bytes(&octets(hex)), NOT_A_KEY, "mixed order {hex}");
    }
}
