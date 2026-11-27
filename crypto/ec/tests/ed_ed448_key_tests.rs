//! The Ed448 key objects: generation, `keygen_out` and the all-zero key it writes into,
//! encoding and decoding, and the full validation of a decoded public key.

use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, RNGError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{DeterministicOneShotSigningKey, OneShotVerifyingKey};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_core_test_framework::FailingRNG;
use bouncycastle_core_test_framework::ShortRNG;
use bouncycastle_core_test_framework::signature::TestFrameworkSignatureKeys;
use bouncycastle_ec::ed::ed448::{
    Ed448PrivateKey, Ed448PublicKey, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, keygen, keygen_out,
    keypair_consistency_check,
};
use bouncycastle_rng::DefaultRNG;

const ZEROIZED: SignatureError =
    SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

/// 128 distinct octets, so that a second 57-octet draw differs from the first.
fn rng() -> FixedSeedRNG<[u8; 128]> {
    FixedSeedRNG::new(core::array::from_fn(|i| i as u8))
}

fn octets(hex: &str) -> [u8; 57] {
    bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
}

// The encodings below were made with the Python library of RFC 8032 Appendix A, lifted from
// the text of the RFC by script.

/// Its public key.
const GENERATED_PK: &str = concat!(
    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c706",
    "1bd6783df1e50f6cd1fa1abeafe8256180",
);

// (what, encoding): refused by RFC 8032 Section 5.2.3
const NOT_DECODED: &[(&str, &str)] = &[
    (
        "y = p",
        concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff00",
        ),
    ),
    (
        "y = p + 1",
        concat!(
            "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff00",
        ),
    ),
    (
        "y = 2^448 - 1",
        concat!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff00",
        ),
    ),
    (
        "y = p, sign set",
        concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff80",
        ),
    ),
    (
        "y = 1 + 2^448",
        concat!(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000001",
        ),
    ),
    (
        "y = 1 + 2^454",
        concat!(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000040",
        ),
    ),
    (
        "x = 0, y = 1, sign set",
        concat!(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000080",
        ),
    ),
    (
        "x = 0, y = -1, sign set",
        concat!(
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff80",
        ),
    ),
    (
        "y = 2, which has no x",
        concat!(
            "02000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000",
        ),
    ),
];

// (what, canonical encoding): the four points of small order
const SMALL_ORDER: &[(&str, &str)] = &[
    (
        "order 1, (0, 1)",
        concat!(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000",
        ),
    ),
    (
        "order 2, (0, -1)",
        concat!(
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff00",
        ),
    ),
    (
        "order 4, (1, 0)",
        concat!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000080",
        ),
    ),
    (
        "order 4, (-1, 0)",
        concat!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000",
        ),
    ),
];

// (what, canonical encoding): on the curve and outside the prime-order subgroup
const MIXED_ORDER: &[(&str, &str)] = &[
    (
        "[5]B + the point of order 2, (0, -1)",
        concat!(
            "14ca0b8deb8c4bbcabdde077edaabfa7c34c2da6115b28d88efe674907ae9a2731704ec57d5ef3d9",
            "21f5a7021b63ef462c12e8dae58a025280",
        ),
    ),
    (
        "[5]B + the point of order 4, (1, 0)",
        concat!(
            "cbfffc6def62562faf06391073d2840f69c3f36d852a3f747fed776a169e28a958529d7a8d30347f",
            "10f24a12e19f58d4f134725bca6c608580",
        ),
    ),
    (
        "[5]B + the point of order 4, (-1, 0)",
        concat!(
            "34000392109da9d050f9c6ef8c2d7bf0963c0c927ad5c08b80128895e861d756a7ad628572cfcb80",
            "ef0db5ed1e60a72b0ecb8da435939f7a00",
        ),
    ),
];

/// [5]B, a key of the subgroup, beside the mixed-order keys made from it.
const FIVE_B: &str = concat!(
    "eb35f4721473b44354221f88125540583cb3d259eea4d727710198b6f75165d8ce8fb13a82a10c26",
    "de0a58fde49c10b9d3ed17251a75fdad00",
);

#[test]
fn key_encoding_framework() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<Ed448PublicKey, Ed448PrivateKey, PUBLIC_KEY_LEN, PRIVATE_KEY_LEN>(|| {
            keygen(&mut rng())
        });
}

/// The sizes the module's Memory Usage table gives.
#[test]
fn key_object_sizes() {
    assert_eq!((PRIVATE_KEY_LEN, PUBLIC_KEY_LEN), (57, 57));
    assert_eq!(core::mem::size_of::<Ed448PublicKey>(), 128);
    assert_eq!(core::mem::size_of::<Ed448PrivateKey>(), 228);
}

/// The private key is the 57 octets the RNG gave, and the public key is the one RFC 8032
/// derives from them.
#[test]
fn keygen_draws_the_private_key() {
    let (pk, sk) = keygen(&mut rng()).unwrap();
    let drawn: [u8; 57] = core::array::from_fn(|i| i as u8);
    assert_eq!(sk.encode(), drawn);
    assert!(sk == Ed448PrivateKey::from_bytes(&drawn).unwrap());
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
    let mut sk_out = Ed448PrivateKey::zeroized();
    keygen_out(&mut rng(), &mut sk_out).unwrap();
    assert_eq!(sk_out.pk().unwrap(), pk);
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
    let mut sk = Ed448PrivateKey::zeroized();
    keygen_out(&mut rng, &mut sk).unwrap();
    let pk1 = sk.pk().unwrap();
    keygen_out(&mut rng, &mut sk).unwrap();
    assert_ne!(sk.pk().unwrap(), pk1);
    let second: [u8; 57] = core::array::from_fn(|i| 57 + i as u8);
    assert_eq!(sk.encode(), second);
    assert!(sk == Ed448PrivateKey::from_bytes(&second).unwrap());
}

/// A failed generation leaves the key as `zeroized()` makes it, whatever it held before. The
/// RNG must offer the 192 bits Ed448 is classed at.
#[test]
fn a_failed_keygen_leaves_the_key_unfilled() {
    let mut weak = rng();
    weak.set_security_strength(SecurityStrength::_128bit);
    let insufficient = SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm);
    assert_eq!(keygen(&mut weak).err(), Some(insufficient));
    let mut exact = rng();
    exact.set_security_strength(SecurityStrength::_192bit);
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
        assert!(sk == Ed448PrivateKey::zeroized());
        assert_eq!(sk.encode(), [0u8; 57]);
        assert_eq!(sk.pk().err(), Some(ZEROIZED));
    }
}

/// The all-zero key has no public key, is part of no key pair, and is not the key decoded
/// from 57 zero octets, which is an ordinary key.
#[test]
fn the_unfilled_key() {
    let unfilled = Ed448PrivateKey::zeroized();
    assert_eq!(unfilled.pk().err(), Some(ZEROIZED));
    assert!(unfilled == Ed448PrivateKey::zeroized());
    assert!(unfilled == unfilled.clone());
    assert_eq!(unfilled.encode(), [0u8; 57]);

    let zeros = Ed448PrivateKey::from_bytes(&[0u8; 57]).unwrap();
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
    let mut held = Ed448PrivateKey::zeroized();
    Ed448PrivateKey::from_bytes_out(&sk.encode(), &mut held).unwrap();
    assert!(held == sk);
    assert_eq!(held.pk().unwrap(), pk);
    assert_eq!(held.sign_deterministic(b"msg", None), sk.sign_deterministic(b"msg", None));

    Ed448PrivateKey::from_bytes_out(&[7u8; 57], &mut held).unwrap();
    assert!(held == Ed448PrivateKey::from_bytes(&[7u8; 57]).unwrap() && held != sk);

    for wrong in [&[7u8; 56][..], &[7u8; 58], &[7u8; 32], &[]] {
        Ed448PrivateKey::from_bytes_out(&sk.encode(), &mut held).unwrap();
        assert_eq!(
            Ed448PrivateKey::from_bytes_out(wrong, &mut held),
            Err(KeyDecodingError("An Ed448 private key must be 57 bytes"))
        );
        assert!(held == Ed448PrivateKey::zeroized());
        assert_eq!(held.encode(), [0u8; 57]);
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

    let mut held = Ed448PrivateKey::from_bytes(&[7u8; 57]).unwrap();
    held.clone_from(&sk);
    assert!(held == sk);
    assert_eq!(held.encode(), sk.encode());
    assert_eq!(held.pk().unwrap(), pk);
    assert_eq!(held.sign_deterministic(b"msg", None), sk.sign_deterministic(b"msg", None));

    held.clone_from(&Ed448PrivateKey::zeroized());
    assert!(held == Ed448PrivateKey::zeroized());
    assert_eq!(held.pk().err(), Some(ZEROIZED));
}

#[test]
fn keys_round_trip_through_their_encodings() {
    let (pk, sk) = keygen(&mut rng()).unwrap();

    let sk_bytes = sk.encode();
    let mut out = [0xA5u8; PRIVATE_KEY_LEN];
    assert_eq!(sk.encode_out(&mut out), PRIVATE_KEY_LEN);
    assert_eq!(out, sk_bytes);
    let sk2 = Ed448PrivateKey::from_bytes(&sk_bytes).unwrap();
    assert!(sk2 == sk && sk.clone() == sk);
    assert_eq!(sk2.pk().unwrap(), pk);

    let pk_bytes = pk.encode();
    let mut out = [0xA5u8; PUBLIC_KEY_LEN];
    assert_eq!(pk.encode_out(&mut out), PUBLIC_KEY_LEN);
    assert_eq!(out, pk_bytes);
    let pk2 = Ed448PublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk2, pk);
    assert_eq!(pk2.encode(), pk_bytes);
    assert_eq!(pk.clone(), pk);

    // One bit of difference is another key, in the last octet too: all 57 octets are hashed.
    for octet in [0, 56] {
        let mut other = sk_bytes;
        other[octet] ^= 0x80;
        let other = Ed448PrivateKey::from_bytes(&other).unwrap();
        assert!(other != sk);
        assert_ne!(other.pk().unwrap(), pk);
    }

    assert_eq!(
        Ed448PrivateKey::from_bytes(&sk_bytes[..56]).err(),
        Some(KeyDecodingError("An Ed448 private key must be 57 bytes"))
    );
    assert_eq!(
        Ed448PublicKey::from_bytes(&pk_bytes[..56]),
        Err(KeyDecodingError("An Ed448 public key must be 57 bytes"))
    );
    assert_eq!(
        Ed448PublicKey::from_bytes(&[pk_bytes.as_slice(), &[0]].concat()),
        Err(KeyDecodingError("An Ed448 public key must be 57 bytes"))
    );
}

/// `Display` and `Debug` show the encoding in hex.
#[test]
fn a_public_key_prints_its_encoding() {
    // The public key of the first vector of RFC 8032 Section 7.4.
    let pk = Ed448PublicKey::from_bytes(&octets(GENERATED_PK)).unwrap();
    let expected = format!("Ed448PublicKey {{ {GENERATED_PK} }}");
    assert_eq!(format!("{pk}"), expected);
    assert_eq!(format!("{pk:?}"), expected);
}

const NOT_A_KEY: Result<Ed448PublicKey, KeyDecodingError> =
    Err(KeyDecodingError("Not the encoding of an Ed448 public key in the prime-order subgroup"));

/// RFC 8032 Section 5.2.3: an encoding whose y is not below p (anything in bits 448 to 454
/// included), or whose x is zero with the sign bit set, or whose y has no x, does not decode.
#[test]
fn non_canonical_and_off_curve_encodings_are_refused() {
    assert_eq!(NOT_DECODED.len(), 9);
    for (what, hex) in NOT_DECODED {
        assert_eq!(Ed448PublicKey::from_bytes(&octets(hex)), NOT_A_KEY, "{what}");
    }
}

/// Full validation: the four points of small order, canonically encoded, and points of mixed
/// order (a point of order L plus one of small order) are on the curve and are refused, while
/// the point of order L they were made from is a key.
#[test]
fn keys_outside_the_prime_order_subgroup_are_refused() {
    assert_eq!((SMALL_ORDER.len(), MIXED_ORDER.len()), (4, 3));
    for (what, hex) in SMALL_ORDER.iter().chain(MIXED_ORDER) {
        assert_eq!(Ed448PublicKey::from_bytes(&octets(hex)), NOT_A_KEY, "{what}");
    }
    let five_b = Ed448PublicKey::from_bytes(&octets(FIVE_B)).unwrap();
    assert_eq!(five_b.encode(), octets(FIVE_B));
}

/// A key that was never filled is refused as that whatever the context: the key is looked at
/// before the context, by Ed448 and by Ed448ph alike.
#[test]
fn the_unfilled_key_is_refused_before_a_bad_context() {
    // Both take a context of at most 255 octets.
    let (bad, bad_ph) = (Some(&[0u8; 256][..]), Some(&[0u8; 256][..]));
    let unfilled = Ed448PrivateKey::zeroized();
    assert_eq!(unfilled.sign_deterministic(b"msg", bad), Err(ZEROIZED));
    assert_eq!(unfilled.as_prehash().sign_deterministic(b"msg", bad_ph), Err(ZEROIZED));

    // A filled key gets the context's error.
    let (_, sk) = keygen(&mut rng()).unwrap();
    assert!(matches!(sk.sign_deterministic(b"msg", bad), Err(SignatureError::LengthError(_))));
    assert!(matches!(
        sk.as_prehash().sign_deterministic(b"msg", bad_ph),
        Err(SignatureError::LengthError(_))
    ));
}

/// A draw that comes back short is the RNG failing: refused rather than used as a key, and the
/// key is left unfilled.
#[test]
fn a_short_draw_is_refused_and_leaves_the_key_unfilled() {
    let short = |r: Result<(), SignatureError>| {
        matches!(r, Err(SignatureError::RNGError(RNGError::GenericError(_))))
    };
    assert!(short(keygen(&mut ShortRNG).map(|_| ())));
    let (_, mut sk) = keygen(&mut DefaultRNG::default()).unwrap();
    assert!(short(keygen_out(&mut ShortRNG, &mut sk)));
    assert!(sk == Ed448PrivateKey::zeroized());
}
