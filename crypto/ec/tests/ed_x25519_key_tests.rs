use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, KeyDecodingError, KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{AlgorithmOID, PrivateKey, PublicKey};
use bouncycastle_core_test_framework::ShortRNG;
use bouncycastle_core_test_framework::key_agreement::TestFrameworkKeyAgreementKeys;
use bouncycastle_ec::ed::x25519::{
    POINT_LEN, SCALAR_LEN, X25519, X25519PrivateKey, X25519PublicKey, keygen, keygen_from_seed,
    keygen_from_seed_out, keygen_out, keypair_consistency_check,
};
use bouncycastle_rng::DefaultRNG;

/// RFC 7748 Section 6.1: Alice's private key a and public key X25519(a, 9).
const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

fn seed(hex_str: &str, key_type: KeyType) -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&hex::decode(hex_str).unwrap(), key_type).unwrap()
}

/// What `pk()` gives for a key that was never filled.
const NO_PK: Result<X25519PublicKey, KeyAgreementError> =
    Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey));

fn keygen_default() -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
    keygen(&mut DefaultRNG::default())
}

#[test]
fn core_framework_tests() {
    TestFrameworkKeyAgreementKeys::new()
        .test_keys::<X25519PublicKey, X25519PrivateKey, POINT_LEN, SCALAR_LEN>(keygen_default);
}

/// id-X25519, RFC 8410 Section 3: `id-X25519 OBJECT IDENTIFIER ::= { 1 3 101 110 }`. The
/// encoding is the one in the subjectPublicKeyInfo of the certificate in its Section 10.2,
/// `06 03 2b 65 6e`.
#[test]
fn the_oid_is_id_x25519() {
    assert_eq!(<X25519 as AlgorithmOID>::OID, &[1, 3, 101, 110]);
    assert_eq!(<X25519 as AlgorithmOID>::OID_DER, &[0x06, 0x03, 0x2b, 0x65, 0x6e]);
}

#[test]
fn keygen_from_seed_takes_a_seed_or_random_material() {
    for key_type in [KeyType::Seed, KeyType::CryptographicRandom] {
        let (pk, sk) = keygen_from_seed(&seed(ALICE_SK, key_type)).unwrap();
        assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
        assert_eq!(sk.pk().unwrap(), pk);
    }
}

#[test]
fn keygen_from_seed_rejects_bad_seeds() {
    // Wrong key type.
    match keygen_from_seed(&seed(ALICE_SK, KeyType::MACKey)) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }

    // All zeros: KeyMaterial marks it KeyType::Zeroized, and the refusal says so.
    match keygen_from_seed(&seed(&"00".repeat(32), KeyType::Seed)) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey)) => {}
        other => panic!("expected ActingOnZeroizedKey, got {:?}", other.err()),
    }

    // Undersized.
    let short = seed(&ALICE_SK[..62], KeyType::Seed);
    assert_eq!(short.key_len(), 31);
    match keygen_from_seed(&short) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }

    // Security strength below the algorithm's, and exactly at it.
    let mut weak = seed(ALICE_SK, KeyType::Seed);
    weak.set_security_strength(SecurityStrength::_112bit).unwrap();
    match keygen_from_seed(&weak) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
        other => panic!("expected SecurityStrength, got {:?}", other.err()),
    }
    let mut just_right = seed(ALICE_SK, KeyType::Seed);
    just_right.set_security_strength(SecurityStrength::_128bit).unwrap();
    keygen_from_seed(&just_right).unwrap();
}

#[test]
fn keygen_uses_the_rng_output_as_the_key() {
    // The RNG output is used as the seed, so this must match keygen_from_seed.
    let seed_bytes: [u8; 32] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let mut rng = FixedSeedRNG::new(seed_bytes);
    let (pk, sk) = keygen(&mut rng).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk().unwrap(), pk);

    // RNG too weak.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_112bit);
    match keygen(&mut rng) {
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm)) => {}
        other => {
            panic!(
                "expected RNGError::SecurityStrengthInsufficientForAlgorithm, got {:?}",
                other.err()
            )
        }
    }

    // RNG just right.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_128bit);
    keygen(&mut rng).unwrap();
}

/// The out forms write into a key the caller holds: a stale key is overwritten with what the
/// by-value forms give for the same RNG output or seed, public key included, and a refused
/// RNG or seed leaves the key all zero.
#[test]
fn the_out_forms_fill_the_callers_key_and_zeroize_it_on_refusal() {
    let seed_bytes: [u8; 32] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let zero = X25519PrivateKey::zeroized();
    assert_eq!(zero.pk(), NO_PK);

    let (_, mut sk) = keygen_default().unwrap();
    keygen_out(&mut FixedSeedRNG::new(seed_bytes), &mut sk).unwrap();
    let (expected_pk, expected_sk) = keygen(&mut FixedSeedRNG::new(seed_bytes)).unwrap();
    assert_eq!(sk.pk().unwrap().as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk().unwrap(), expected_pk);
    assert!(sk == expected_sk);

    let mut weak = FixedSeedRNG::new(seed_bytes);
    weak.set_security_strength(SecurityStrength::_112bit);
    assert!(matches!(
        keygen_out(&mut weak, &mut sk),
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
    assert!(sk == zero);
    assert_eq!(sk.pk(), NO_PK);

    let (_, mut sk) = keygen_default().unwrap();
    keygen_from_seed_out(&seed(ALICE_SK, KeyType::Seed), &mut sk).unwrap();
    let (expected_pk, expected_sk) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    assert_eq!(sk.pk().unwrap().as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk().unwrap(), expected_pk);
    assert!(sk == expected_sk);

    assert!(matches!(
        keygen_from_seed_out(&seed(ALICE_SK, KeyType::Unknown), &mut sk),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(sk == zero);
    assert_eq!(sk.pk(), NO_PK);
}

#[test]
fn keygen_gives_fresh_pairs_whose_public_keys_belong_to_them() {
    let (pk1, sk1) = keygen_default().unwrap();
    let (pk2, sk2) = keygen_default().unwrap();
    assert_ne!(pk1, pk2);
    assert_eq!(sk1.pk().unwrap(), pk1);
    assert_eq!(sk2.pk().unwrap(), pk2);
    assert_ne!(sk1.pk().unwrap(), pk2);
    assert_ne!(sk2.pk().unwrap(), pk1);
}

#[test]
fn private_key_pk() {
    let (_, sk) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    assert_eq!(sk.pk().unwrap().as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());

    let (pk, sk) = keygen_default().unwrap();
    assert_eq!(sk.pk().unwrap(), pk);
}

#[test]
fn public_key_to_bytes() {
    let (pk, _) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    let expected = hex::decode(ALICE_PK).unwrap();

    let as_ref: &[u8] = pk.as_ref();
    assert_eq!(as_ref, expected);
}

fn decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// Clamps as `decodeScalar25519` does (RFC 7748 Section 5).
fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

#[test]
fn public_key_encoding() {
    let bytes = decode_32(ALICE_PK);
    let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.encode(), bytes);

    let mut out = [0xFF_u8; 32];
    assert_eq!(pk.encode_out(&mut out), 32);
    assert_eq!(out, bytes);

    // Decoding round-trips, and accepts any 32 bytes, including bit 255 set (RFC 7748 Section 5).
    let decoded = X25519PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, pk);
    let top_bit = [0xFF_u8; 32];
    let decoded = X25519PublicKey::from_bytes(&top_bit).unwrap();
    assert_eq!(decoded.encode(), top_bit);

    for len in [0, 31, 33] {
        match X25519PublicKey::from_bytes(&vec![1_u8; len]) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("expected DecodingError for {len} bytes"),
        }
    }
}

#[test]
fn private_key_encoding() {
    // The RFC 7748 Section 6.1 key is unclamped, so this exercises the clamping.
    let raw = decode_32(ALICE_SK);
    assert_ne!(raw, clamp(raw));

    let sk = X25519PrivateKey::from_bytes(&raw).unwrap();
    assert_eq!(sk.encode(), clamp(raw));
    assert_eq!(sk.pk().unwrap().as_bytes(), &decode_32(ALICE_PK));

    let mut out = [0xFF_u8; 32];
    assert_eq!(sk.encode_out(&mut out), 32);
    assert_eq!(out, clamp(raw));

    // A key built from the unclamped seed is the same key, with the same encoding, and it
    // round-trips through its encoding.
    let (_, from_seed) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    assert!(from_seed == sk);
    assert_eq!(from_seed.encode(), clamp(raw));
    let encoded = from_seed.encode();
    let decoded = X25519PrivateKey::from_bytes(&encoded).unwrap();
    assert!(decoded == from_seed);

    for len in [0, 31, 33] {
        match X25519PrivateKey::from_bytes(&vec![1_u8; len]) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("expected DecodingError for {len} bytes"),
        }
    }
}

/// `from_bytes_out` fills a key the caller holds as `from_bytes` would, replaces what the key
/// held, and leaves it as `zeroized()` makes it when the bytes are refused.
#[test]
fn from_bytes_out_fills_a_held_key() {
    let alice = X25519PrivateKey::from_bytes(&hex::decode(ALICE_SK).unwrap()).unwrap();
    let mut held = X25519PrivateKey::zeroized();
    X25519PrivateKey::from_bytes_out(&hex::decode(ALICE_SK).unwrap(), &mut held).unwrap();
    assert!(held == alice);
    assert_eq!(held.encode(), alice.encode());
    assert_eq!(held.pk().unwrap().as_bytes()[..], hex::decode(ALICE_PK).unwrap()[..]);

    X25519PrivateKey::from_bytes_out(&[7u8; 32], &mut held).unwrap();
    assert!(held == X25519PrivateKey::from_bytes(&[7u8; 32]).unwrap() && held != alice);

    for wrong in [&[7u8; 31][..], &[7u8; 33], &[]] {
        X25519PrivateKey::from_bytes_out(&hex::decode(ALICE_SK).unwrap(), &mut held).unwrap();
        assert_eq!(
            X25519PrivateKey::from_bytes_out(wrong, &mut held),
            Err(KeyDecodingError("An X25519 private key must be 32 bytes"))
        );
        assert_eq!(held.encode(), X25519PrivateKey::zeroized().encode());
        assert_eq!(held.pk(), NO_PK);
    }
}

/// `clone_from` replaces what the destination held with the source, an unfilled one included.
#[test]
fn clone_from_copies_into_a_held_key() {
    let alice = X25519PrivateKey::from_bytes(&hex::decode(ALICE_SK).unwrap()).unwrap();
    let mut held = X25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    held.clone_from(&alice);
    assert!(held == alice);
    assert_eq!(held.encode(), alice.encode());
    assert_eq!(held.pk().unwrap(), alice.pk().unwrap());

    // The copy of a filled key is filled: it makes the agreement the original makes.
    let (peer, _) = keygen_default().unwrap();
    assert!(held.agree(&peer, ()).unwrap().equals(&alice.agree(&peer, ()).unwrap()));

    // The copy of an unfilled key is unfilled, whatever the destination held.
    held.clone_from(&X25519PrivateKey::zeroized());
    assert_eq!(held.encode(), X25519PrivateKey::zeroized().encode());
    assert_eq!(held.pk(), NO_PK);
    assert!(matches!(
        held.agree(&peer, ()),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    ));
}

/// A clone is the same key, keeps its public key and its filled state.
#[test]
fn a_clone_is_the_same_key() {
    let (pk, sk) = keygen_default().unwrap();
    let copy = sk.clone();
    assert!(copy == sk);
    assert_eq!(copy.pk().unwrap(), pk);
    let (peer, _) = keygen_default().unwrap();
    assert!(copy.agree(&peer, ()).unwrap().equals(&sk.agree(&peer, ()).unwrap()));
    assert!(matches!(
        X25519PrivateKey::zeroized().clone().agree(&peer, ()),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    ));
}

/// `keypair_consistency_check` takes a private key with its own public key and no other, an
/// encoding of the same point that differs in its bytes included, and refuses a private key
/// that was never filled.
#[test]
fn keypair_consistency_check_takes_a_key_with_its_own_public_key() {
    let (pk, sk) = keygen_default().unwrap();
    assert_eq!(keypair_consistency_check(&pk, &sk), Ok(()));
    assert_eq!(keypair_consistency_check(&sk.pk().unwrap(), &sk.clone()), Ok(()));

    let (pk2, sk2) = keygen_default().unwrap();
    assert_eq!(
        keypair_consistency_check(&pk2, &sk),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );
    assert_eq!(
        keypair_consistency_check(&pk, &sk2),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );
    // One bit of the public key is enough, bit 255 included, which X25519 itself ignores (RFC
    // 7748 Section 5): the keys are compared as bytes.
    for (byte, bit) in [(16, 0x01), (31, 0x80)] {
        let mut bytes = pk.encode();
        bytes[byte] ^= bit;
        assert_eq!(
            keypair_consistency_check(&X25519PublicKey::from_bytes(&bytes).unwrap(), &sk),
            Err(KeyAgreementError::ConsistencyCheckFailed)
        );
    }

    // RFC 7748 Section 6's key pair.
    let alice = X25519PrivateKey::from_bytes(&hex::decode(ALICE_SK).unwrap()).unwrap();
    let alice_pk = X25519PublicKey::from_bytes(&hex::decode(ALICE_PK).unwrap()).unwrap();
    assert_eq!(keypair_consistency_check(&alice_pk, &alice), Ok(()));
    assert_eq!(
        keypair_consistency_check(&pk, &alice),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );

    // A key that was never filled is refused whatever the public key, the all-zero one its
    // field holds included.
    let unfilled = X25519PrivateKey::zeroized();
    let zero_pk = X25519PublicKey::from_bytes(&[0u8; 32]).unwrap();
    assert_eq!(keypair_consistency_check(&pk, &unfilled), NO_PK.map(|_| ()));
    assert_eq!(keypair_consistency_check(&zero_pk, &unfilled), NO_PK.map(|_| ()));
    assert_eq!(
        keypair_consistency_check(&zero_pk, &sk),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );
}

/// A key that was never filled equals only another such key: not the key decoded from 32 zero
/// bytes, which holds the same scalar and is an ordinary key.
#[test]
fn the_unfilled_key_equals_only_an_unfilled_key() {
    let unfilled = X25519PrivateKey::zeroized();
    assert!(unfilled == X25519PrivateKey::zeroized());
    assert!(unfilled == unfilled.clone());

    let zeros = X25519PrivateKey::from_bytes(&[0u8; 32]).unwrap();
    assert_eq!(zeros.encode(), unfilled.encode());
    assert!(zeros == zeros.clone());
    // Both directions, on purpose.
    #[allow(clippy::nonminimal_bool)]
    {
        assert!(zeros != unfilled && unfilled != zeros);
    }
}

/// A draw that comes back short is the RNG failing: refused rather than used as a key, and the
/// key is left unfilled.
#[test]
fn a_short_draw_is_refused_and_leaves_the_key_unfilled() {
    let short = |r: Result<(), KeyAgreementError>| {
        matches!(r, Err(KeyAgreementError::RNGError(RNGError::GenericError(_))))
    };
    assert!(short(keygen(&mut ShortRNG).map(|_| ())));
    let (_, mut sk) = keygen(&mut DefaultRNG::default()).unwrap();
    assert!(short(keygen_out(&mut ShortRNG, &mut sk)));
    assert!(sk == X25519PrivateKey::zeroized());
}
