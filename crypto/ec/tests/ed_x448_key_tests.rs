use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, KeyDecodingError, KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, PrivateKey, PublicKey};
use bouncycastle_core_test_framework::key_agreement::TestFrameworkKeyAgreementKeys;
use bouncycastle_ec::ed::x448::{
    POINT_LEN, SCALAR_LEN, X448, X448_HKDF_SHA512, X448_NAME, X448PrivateKey, X448PublicKey,
    keygen, keygen_from_seed, keygen_from_seed_out, keygen_out, keypair_consistency_check,
};
use bouncycastle_rng::DefaultRNG;

/// RFC 7748 Section 6.2: Alice's private key a and public key X448(a, 5), lifted from the text
/// of the RFC by a script, in the two lines of 56 hexadecimal digits the RFC prints.
const ALICE_SK: &str = concat!(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d",
    "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
);
const ALICE_PK: &str = concat!(
    "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c",
    "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
);

fn seed(hex_str: &str, key_type: KeyType) -> KeyMaterial<56> {
    KeyMaterial::<56>::from_bytes_as_type(&hex::decode(hex_str).unwrap(), key_type).unwrap()
}

/// What `pk()` gives for a key that was never filled.
const NO_PK: Result<X448PublicKey, KeyAgreementError> =
    Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey));

fn keygen_default() -> Result<(X448PublicKey, X448PrivateKey), KeyAgreementError> {
    keygen(&mut DefaultRNG::default())
}

#[test]
fn core_framework_tests() {
    TestFrameworkKeyAgreementKeys::new()
        .test_keys::<X448PublicKey, X448PrivateKey, POINT_LEN, SCALAR_LEN>(keygen_default);
}

/// The lengths are RFC 7748 Section 5's 56 bytes, and the algorithm and its HKDF-SHA512
/// pairing are named and classed at 192 bits.
#[test]
fn constants() {
    assert_eq!((POINT_LEN, SCALAR_LEN), (56, 56));
    assert_eq!(X448_NAME, "X448");
    assert_eq!(X448::ALG_NAME, "X448");
    assert_eq!(X448::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(X448_HKDF_SHA512::ALG_NAME, "X448-HKDF-SHA512");
    assert_eq!(X448_HKDF_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
}

/// id-X448, RFC 8410 Section 3: `id-X448 OBJECT IDENTIFIER ::= { 1 3 101 111 }`. The RFC prints
/// no encoding of it; this is the encoding of id-X25519 in the certificate of its Section 10.2,
/// `06 03 2b 65 6e`, with the last arc one higher.
#[test]
fn the_oid_is_id_x448() {
    assert_eq!(<X448 as AlgorithmOID>::OID, &[1, 3, 101, 111]);
    assert_eq!(<X448 as AlgorithmOID>::OID_DER, &[0x06, 0x03, 0x2b, 0x65, 0x6f]);
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
    match keygen_from_seed(&seed(&"00".repeat(56), KeyType::Seed)) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey)) => {}
        other => panic!("expected ActingOnZeroizedKey, got {:?}", other.err()),
    }

    // Undersized.
    let short = seed(&ALICE_SK[..110], KeyType::Seed);
    assert_eq!(short.key_len(), 55);
    match keygen_from_seed(&short) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }

    // Security strength below the algorithm's, and exactly at it.
    let mut weak = seed(ALICE_SK, KeyType::Seed);
    weak.set_security_strength(SecurityStrength::_128bit).unwrap();
    match keygen_from_seed(&weak) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
        other => panic!("expected SecurityStrength, got {:?}", other.err()),
    }
    let mut just_right = seed(ALICE_SK, KeyType::Seed);
    just_right.set_security_strength(SecurityStrength::_192bit).unwrap();
    keygen_from_seed(&just_right).unwrap();
}

#[test]
fn keygen_uses_the_rng_output_as_the_key() {
    // The RNG output is used as the seed, so this must match keygen_from_seed.
    let seed_bytes: [u8; 56] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let mut rng = FixedSeedRNG::new(seed_bytes);
    let (pk, sk) = keygen(&mut rng).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk().unwrap(), pk);

    // RNG too weak.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_128bit);
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
    rng.set_security_strength(SecurityStrength::_192bit);
    keygen(&mut rng).unwrap();
}

/// The out forms write into a key the caller holds: a stale key is overwritten with what the
/// by-value forms give for the same RNG output or seed, the returned public key is the key's
/// own, and a refused RNG or seed leaves the key all zero and unfilled.
#[test]
fn the_out_forms_fill_the_callers_key_and_zeroize_it_on_refusal() {
    use bouncycastle_core::agreement_key::AgreementKey;

    let seed_bytes: [u8; 56] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let zero = X448PrivateKey::zeroized();
    assert_eq!(zero.pk(), NO_PK);
    let unfilled = |sk: &X448PrivateKey| {
        matches!(
            sk.create_agreement(()),
            Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
        )
    };
    assert!(unfilled(&zero));

    let (_, mut sk) = keygen_default().unwrap();
    let pk = keygen_out(&mut FixedSeedRNG::new(seed_bytes), &mut sk).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk().unwrap(), pk);
    assert!(sk == keygen(&mut FixedSeedRNG::new(seed_bytes)).unwrap().1);
    assert!(!unfilled(&sk));

    let mut weak = FixedSeedRNG::new(seed_bytes);
    weak.set_security_strength(SecurityStrength::_128bit);
    assert!(matches!(
        keygen_out(&mut weak, &mut sk),
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
    assert!(sk == zero);
    assert_eq!(sk.pk(), NO_PK);
    assert!(unfilled(&sk));

    // An RNG that fails part-way through the key: what it wrote is wiped.
    let (_, mut sk) = keygen_default().unwrap();
    assert!(matches!(
        keygen_out(&mut HalfWrittenRNG, &mut sk),
        Err(KeyAgreementError::RNGError(_))
    ));
    assert!(sk == zero);
    assert_eq!(sk.encode(), zero.encode());
    assert_eq!(sk.pk(), NO_PK);
    assert!(unfilled(&sk));

    let (_, mut sk) = keygen_default().unwrap();
    let pk = keygen_from_seed_out(&seed(ALICE_SK, KeyType::Seed), &mut sk).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk().unwrap(), pk);
    assert!(sk == keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap().1);
    assert!(!unfilled(&sk));

    assert!(matches!(
        keygen_from_seed_out(&seed(ALICE_SK, KeyType::Unknown), &mut sk),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(sk == zero);
    assert_eq!(sk.pk(), NO_PK);
    assert!(unfilled(&sk));
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
    assert!(sk1 != sk2);
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
    assert_eq!(pk.to_string(), format!("X448PublicKey {{ {ALICE_PK} }}"));
}

fn decode_56(s: &str) -> [u8; 56] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// Clamps as `decodeScalar448` does (RFC 7748 Section 5).
fn clamp(mut k: [u8; 56]) -> [u8; 56] {
    k[0] &= 252;
    k[55] |= 128;
    k
}

#[test]
fn public_key_encoding() {
    let bytes = decode_56(ALICE_PK);
    let pk = X448PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.encode(), bytes);

    let mut out = [0xFF_u8; 56];
    assert_eq!(pk.encode_out(&mut out), 56);
    assert_eq!(out, bytes);

    // Decoding round-trips, and accepts any 56 bytes, the values at and above p included (RFC
    // 7748 Section 5).
    let decoded = X448PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, pk);
    let all_ones = [0xFF_u8; 56];
    let decoded = X448PublicKey::from_bytes(&all_ones).unwrap();
    assert_eq!(decoded.encode(), all_ones);

    for len in [0, 55, 57] {
        match X448PublicKey::from_bytes(&vec![1_u8; len]) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("expected DecodingError for {len} bytes"),
        }
    }
}

#[test]
fn private_key_encoding() {
    // A key with every clamped bit the wrong way round, so this exercises the clamping: the
    // RFC's key with its two low bits set and its top bit cleared.
    let mut raw = decode_56(ALICE_SK);
    raw[0] |= 3;
    raw[55] &= 0x7F;
    assert_ne!(raw[0], clamp(raw)[0]);
    assert_ne!(raw[55], clamp(raw)[55]);

    let sk = X448PrivateKey::from_bytes(&raw).unwrap();
    assert_eq!(sk.encode(), clamp(raw));
    // The clamped bits are no part of the key: it is the key of the RFC's bytes, clamped.
    let clamped_alice = X448PrivateKey::from_bytes(&clamp(decode_56(ALICE_SK))).unwrap();
    assert_eq!(clamp(raw), clamp(decode_56(ALICE_SK)));
    assert!(sk == clamped_alice);
    assert_eq!(sk.pk().unwrap().as_bytes(), &decode_56(ALICE_PK));

    let mut out = [0xFF_u8; 56];
    assert_eq!(sk.encode_out(&mut out), 56);
    assert_eq!(out, clamp(raw));

    // A key built from the unclamped seed is the same key, with the same encoding, and it
    // round-trips through its encoding.
    let unclamped = KeyMaterial::<56>::from_bytes_as_type(&raw, KeyType::Seed).unwrap();
    let (_, from_seed) = keygen_from_seed(&unclamped).unwrap();
    assert!(from_seed == sk);
    assert_eq!(from_seed.encode(), clamp(raw));
    let encoded = from_seed.encode();
    let decoded = X448PrivateKey::from_bytes(&encoded).unwrap();
    assert!(decoded == from_seed);
    assert_eq!(decoded.pk().unwrap(), from_seed.pk().unwrap());

    // Keys that differ in any other bit differ.
    for (byte, bit) in [(0, 0x04), (27, 0x01), (55, 0x40)] {
        let mut other = raw;
        other[byte] ^= bit;
        assert!(X448PrivateKey::from_bytes(&other).unwrap() != sk, "byte {byte}");
    }

    for len in [0, 55, 57] {
        match X448PrivateKey::from_bytes(&vec![1_u8; len]) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("expected DecodingError for {len} bytes"),
        }
    }
}

/// `from_bytes_out` fills a key the caller holds as `from_bytes` would, replaces what the key
/// held, and leaves it as `zeroized()` makes it when the bytes are refused.
#[test]
fn from_bytes_out_fills_a_held_key() {
    let alice = X448PrivateKey::from_bytes(&hex::decode(ALICE_SK).unwrap()).unwrap();
    let mut held = X448PrivateKey::zeroized();
    X448PrivateKey::from_bytes_out(&hex::decode(ALICE_SK).unwrap(), &mut held).unwrap();
    assert!(held == alice);
    assert_eq!(held.encode(), alice.encode());
    assert_eq!(held.pk().unwrap().as_bytes()[..], hex::decode(ALICE_PK).unwrap()[..]);

    X448PrivateKey::from_bytes_out(&[7u8; 56], &mut held).unwrap();
    assert!(held == X448PrivateKey::from_bytes(&[7u8; 56]).unwrap() && held != alice);

    for wrong in [&[7u8; 55][..], &[7u8; 57], &[]] {
        X448PrivateKey::from_bytes_out(&hex::decode(ALICE_SK).unwrap(), &mut held).unwrap();
        assert_eq!(
            X448PrivateKey::from_bytes_out(wrong, &mut held),
            Err(KeyDecodingError("An X448 private key must be 56 bytes"))
        );
        assert_eq!(held.encode(), X448PrivateKey::zeroized().encode());
        assert_eq!(held.pk(), NO_PK);
    }
}

/// `clone_from` replaces what the destination held with the source, an unfilled one included.
#[test]
fn clone_from_copies_into_a_held_key() {
    let alice = X448PrivateKey::from_bytes(&hex::decode(ALICE_SK).unwrap()).unwrap();
    let mut held = X448PrivateKey::from_bytes(&[7u8; 56]).unwrap();
    held.clone_from(&alice);
    assert!(held == alice);
    assert_eq!(held.encode(), alice.encode());
    assert_eq!(held.pk().unwrap(), alice.pk().unwrap());

    // The copy of a filled key is filled: it makes the agreement the original makes.
    let (peer, _) = keygen_default().unwrap();
    assert!(held.agree(&peer, ()).unwrap().equals(&alice.agree(&peer, ()).unwrap()));

    // The copy of an unfilled key is unfilled, whatever the destination held.
    held.clone_from(&X448PrivateKey::zeroized());
    assert_eq!(held.encode(), X448PrivateKey::zeroized().encode());
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
        X448PrivateKey::zeroized().clone().agree(&peer, ()),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    ));
}

/// An RNG that claims full strength, writes half of what is asked and then fails, as a DRBG
/// whose reseed fails might.
struct HalfWrittenRNG;

impl bouncycastle_core::traits::RNG for HalfWrittenRNG {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("HalfWrittenRNG"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("HalfWrittenRNG"))
    }
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        let half = out.len() / 2;
        out[..half].fill(0xA5);
        Err(RNGError::GenericError("HalfWrittenRNG"))
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("HalfWrittenRNG"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// `keypair_consistency_check` takes a private key with its own public key and no other, and
/// refuses a private key that was never filled.
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
    // One bit of the public key is enough.
    let mut bytes = pk.encode();
    bytes[28] ^= 1;
    assert_eq!(
        keypair_consistency_check(&X448PublicKey::from_bytes(&bytes).unwrap(), &sk),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );

    // RFC 7748 Section 6's key pair.
    let alice = X448PrivateKey::from_bytes(&hex::decode(ALICE_SK).unwrap()).unwrap();
    let alice_pk = X448PublicKey::from_bytes(&hex::decode(ALICE_PK).unwrap()).unwrap();
    assert_eq!(keypair_consistency_check(&alice_pk, &alice), Ok(()));
    assert_eq!(
        keypair_consistency_check(&pk, &alice),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );

    // A key that was never filled is refused whatever the public key, the all-zero one its
    // field holds included.
    let unfilled = X448PrivateKey::zeroized();
    let zero_pk = X448PublicKey::from_bytes(&[0u8; 56]).unwrap();
    assert_eq!(keypair_consistency_check(&pk, &unfilled), NO_PK.map(|_| ()));
    assert_eq!(keypair_consistency_check(&zero_pk, &unfilled), NO_PK.map(|_| ()));
    assert_eq!(
        keypair_consistency_check(&zero_pk, &sk),
        Err(KeyAgreementError::ConsistencyCheckFailed)
    );

    // The filled key `4 * order` has the all-zero public key: the filled state, not the public
    // key's bytes, is what refuses `unfilled` above.
    let four_times_order = X448PrivateKey::from_bytes(&decode_56(FOUR_TIMES_ORDER)).unwrap();
    assert_eq!(keypair_consistency_check(&zero_pk, &four_times_order), Ok(()));
}

/// Four times the order of the base point (RFC 7748 Section 4.2), as in `ed_x448_tests.rs`: a
/// clamped scalar whose public key is all zero.
const FOUR_TIMES_ORDER: &str = concat!(
    "cc1361ad4a0ae38d543d1637ca09b38540da58bb266d3b11a78f28f3",
    "fdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

/// A key that was never filled equals only another such key: not the key decoded from 56 zero
/// bytes, which holds the same scalar and is an ordinary key.
#[test]
fn the_unfilled_key_equals_only_an_unfilled_key() {
    let unfilled = X448PrivateKey::zeroized();
    assert!(unfilled == X448PrivateKey::zeroized());
    assert!(unfilled == unfilled.clone());

    let zeros = X448PrivateKey::from_bytes(&[0u8; 56]).unwrap();
    assert_eq!(zeros.encode(), unfilled.encode());
    assert!(zeros == zeros.clone());
    // Both directions, on purpose.
    #[allow(clippy::nonminimal_bool)]
    {
        assert!(zeros != unfilled && unfilled != zeros);
    }
}
