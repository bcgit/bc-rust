//! X25519 as a KEM: DHKEM(X25519, HKDF-SHA256) of RFC 9180 Section 4.1, against the RFC 9180
//! Appendix A.1 vectors and the core-test-framework KEM suites.

use bouncycastle_core::errors::{KEMError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::kem::{TestFrameworkKEM, TestFrameworkKEMKeys};
use bouncycastle_ed::x25519::{
    DHKEM_SS_LEN, POINT_SIZE, SCALAR_SIZE, X25519, X25519PrivateKey, X25519PublicKey,
};
use bouncycastle_hex as hex;
use bouncycastle_hpke::dhkem::DHKEM;

type X25519DHKEM = DHKEM<X25519, POINT_SIZE, SCALAR_SIZE, POINT_SIZE, DHKEM_SS_LEN>;

/// The DHKEM values of one RFC 9180 Appendix A.1 vector set.
struct Vector {
    ikm_e: &'static str,
    pk_em: &'static str,
    sk_em: &'static str,
    ikm_r: &'static str,
    pk_rm: &'static str,
    sk_rm: &'static str,
    enc: &'static str,
    shared_secret: &'static str,
}

/// RFC 9180 Appendix A.1.1 (Base mode) and A.1.2 (PSK mode). The PSK only enters the HPKE key
/// schedule, so for the KEM these are two independent sets.
const VECTORS: [Vector; 2] = [
    Vector {
        ikm_e: "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
        pk_em: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        sk_em: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        ikm_r: "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
        pk_rm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        sk_rm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        enc: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        shared_secret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    },
    Vector {
        ikm_e: "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b",
        pk_em: "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b",
        sk_em: "463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588",
        ikm_r: "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098",
        pk_rm: "9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366",
        sk_rm: "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd",
        enc: "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b",
        shared_secret: "727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd",
    },
];

fn decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn seed(s: &str) -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&decode_32(s), KeyType::Seed).unwrap()
}

/// Clamps as `decodeScalar25519` does (RFC 7748 Section 5).
fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// `X25519::keygen` with its error mapped, in the shape the KEM test framework takes.
fn keygen() -> Result<(X25519PublicKey, X25519PrivateKey), KEMError> {
    X25519::keygen().map_err(|_| KEMError::KeyGenError("X25519 keygen failed"))
}

/// `Encap` with the vector's ephemeral key: the RNG emits skEm, which keygen uses as the private
/// key unchanged.
#[test]
fn rfc9180_encaps() {
    for (i, v) in VECTORS.iter().enumerate() {
        let pk_r = X25519PublicKey::from_bytes(&decode_32(v.pk_rm)).unwrap();
        let mut rng = FixedSeedRNG::new(decode_32(v.sk_em));
        let (ss, enc) = X25519::encaps_rng(&pk_r, &mut rng).unwrap();
        assert_eq!(enc, decode_32(v.enc), "vector {i}: enc");
        assert_eq!(enc, decode_32(v.pk_em), "vector {i}: enc = pkEm");
        assert_eq!(ss.ref_to_bytes(), decode_32(v.shared_secret), "vector {i}: shared_secret");
        assert_eq!(ss.key_type(), KeyType::CryptographicRandom, "vector {i}");
        assert_eq!(ss.security_strength(), SecurityStrength::_128bit, "vector {i}");
    }
}

#[test]
fn rfc9180_decaps() {
    for (i, v) in VECTORS.iter().enumerate() {
        let sk_r = X25519PrivateKey::from_bytes(&decode_32(v.sk_rm)).unwrap();
        assert_eq!(sk_r.pk().as_bytes(), &decode_32(v.pk_rm), "vector {i}: pk(skRm)");
        let ss = X25519::decaps(&sk_r, &decode_32(v.enc)).unwrap();
        assert_eq!(ss.ref_to_bytes(), decode_32(v.shared_secret), "vector {i}: shared_secret");
        assert_eq!(ss.key_type(), KeyType::CryptographicRandom, "vector {i}");
        assert_eq!(ss.security_strength(), SecurityStrength::_128bit, "vector {i}");
    }
}

/// `DeriveKeyPair` (RFC 9180 Section 7.1.3) maps ikmE and ikmR to the vectors' key pairs.
///
/// The vectors list skEm and skRm unclamped, while RFC 9180 Section 7.1.2 requires a serialized
/// private key to be clamped, so the encodings are compared against the clamped vector values.
#[test]
fn rfc9180_derive_key_pair() {
    for (i, v) in VECTORS.iter().enumerate() {
        for (ikm, pkm, skm) in [(v.ikm_e, v.pk_em, v.sk_em), (v.ikm_r, v.pk_rm, v.sk_rm)] {
            let (pk, sk) = X25519DHKEM::derive_key_pair(&seed(ikm)).unwrap();
            assert_eq!(pk.encode(), decode_32(pkm), "vector {i}: pk from ikm {ikm}");
            assert_eq!(sk.encode(), clamp(decode_32(skm)), "vector {i}: sk from ikm {ikm}");
        }
    }
}

#[test]
fn derive_key_pair_rejects_bad_ikm() {
    let ikm = VECTORS[0].ikm_e;

    let mac_key = KeyMaterial256::from_bytes_as_type(&decode_32(ikm), KeyType::MACKey).unwrap();
    match X25519DHKEM::derive_key_pair(&mac_key) {
        Err(KEMError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError for the wrong key type"),
    }

    let short = KeyMaterial256::from_bytes_as_type(&decode_32(ikm)[..31], KeyType::Seed).unwrap();
    match X25519DHKEM::derive_key_pair(&short) {
        Err(KEMError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError for a 31-byte ikm"),
    }

    let mut weak = seed(ikm);
    weak.set_security_strength(SecurityStrength::_112bit).unwrap();
    match X25519DHKEM::derive_key_pair(&weak) {
        Err(KEMError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError for a 112-bit ikm"),
    }

    // Exactly the algorithm's strength is enough.
    let mut just_right = seed(ikm);
    just_right.set_security_strength(SecurityStrength::_128bit).unwrap();
    X25519DHKEM::derive_key_pair(&just_right).unwrap();

    // A longer ikm is allowed.
    let long = KeyMaterial256::from_bytes_as_type(&[0x5A; 32], KeyType::Seed).unwrap();
    X25519DHKEM::derive_key_pair(&long).unwrap();
}

/// `encaps_rng` rejects an RNG below 128 bits and accepts one at exactly 128 bits.
#[test]
fn encaps_rng_security_strength() {
    let (pk, _) = X25519::keygen().unwrap();

    let mut weak = FixedSeedRNG::new([0x5A; 32]);
    weak.set_security_strength(SecurityStrength::_112bit);
    match X25519::encaps_rng(&pk, &mut weak) {
        Err(KEMError::RNGError(_)) => { /* good */ }
        _ => panic!("expected RNGError for a 112-bit RNG"),
    }

    let mut just_right = FixedSeedRNG::new([0x5A; 32]);
    just_right.set_security_strength(SecurityStrength::_128bit);
    X25519::encaps_rng(&pk, &mut just_right).unwrap();
}

/// An RNG at full strength whose every request fails.
struct FailingRNG;

impl RNG for FailingRNG {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn next_bytes(&mut self, _: usize) -> Result<Vec<u8>, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn next_bytes_out(&mut self, _: &mut [u8]) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// An RNG failure while generating the ephemeral key pair is passed through as the RNG's error.
#[test]
fn encaps_rng_passes_through_rng_failure() {
    let (pk, _) = X25519::keygen().unwrap();
    match X25519::encaps_rng(&pk, &mut FailingRNG) {
        Err(KEMError::RNGError(RNGError::GenericError(_))) => { /* good */ }
        other => panic!("expected the RNG's error, got {other:?}"),
    }
}

#[test]
fn kem_framework() {
    // DHKEM is randomized. A modified ciphertext is another public key, so decaps succeeds with a
    // different shared secret, which is the behaviour the framework checks for an implicitly
    // rejecting KEM. Full bit-flipping is off: flipping bit 255 of enc gives the same shared
    // secret, since X25519 ignores that bit (RFC 7748 Section 5).
    TestFrameworkKEM::new(false, true).test_kem::<
        X25519PublicKey,
        X25519PrivateKey,
        X25519,
        POINT_SIZE,
        SCALAR_SIZE,
        POINT_SIZE,
        DHKEM_SS_LEN,
    >(keygen, false);
}

#[test]
fn kem_keys_framework() {
    TestFrameworkKEMKeys::new()
        .test_keys::<X25519PublicKey, X25519PrivateKey, POINT_SIZE, SCALAR_SIZE>(keygen);
}

/// Low-order public keys give an all-zero X25519 output, which RFC 9180 Section 7.1.4 requires
/// both sides to reject.
#[test]
fn rejects_low_order_public_key() {
    let (_, sk) = X25519::keygen().unwrap();
    let mut zero_bit_255 = [0_u8; 32];
    zero_bit_255[31] = 0x80;
    let p = decode_32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

    for u in [[0_u8; 32], p, zero_bit_255] {
        match X25519::encaps(&X25519PublicKey::from_bytes(&u).unwrap()) {
            Err(KEMError::InvalidPublicKey(_)) => { /* good */ }
            other => panic!("encaps: expected InvalidPublicKey for u = {u:02x?}, got {other:?}"),
        }
        match X25519::decaps(&sk, &u) {
            Err(KEMError::DecapsulationFailed) => { /* good */ }
            other => panic!("decaps: expected DecapsulationFailed for u = {u:02x?}, got {other:?}"),
        }
    }
}

/// RFC 9180 Section 7.1.2: SerializePrivateKey clamps its output and DeserializePrivateKey clamps
/// its input, and keys differing only in the clamped bits are the same key.
#[test]
fn private_key_encoding_is_clamped() {
    let raw = decode_32(VECTORS[0].sk_rm);
    assert_ne!(raw, clamp(raw), "the vector key must be unclamped for this test to mean anything");

    let sk = X25519PrivateKey::from_bytes(&raw).unwrap();
    assert_eq!(sk.encode(), clamp(raw));
    let mut out = [0xFF_u8; 32];
    assert_eq!(sk.encode_out(&mut out), 32);
    assert_eq!(out, clamp(raw));

    // A key from keygen_from_seed keeps the unclamped bytes, but is equal to the clamped one.
    let (_, unclamped) = X25519::keygen_from_seed(&seed(VECTORS[0].sk_rm)).unwrap();
    assert!(unclamped == sk);
    assert_eq!(unclamped.encode(), clamp(raw));
    assert!(unclamped.clone() == sk);

    let (_, other) = X25519::keygen().unwrap();
    assert!(other != sk);
}

#[test]
fn public_key_encoding() {
    let bytes = decode_32(VECTORS[0].pk_rm);
    let pk = <X25519PublicKey as KEMPublicKey<32>>::from_bytes(&bytes).unwrap();
    assert_eq!(pk.encode(), bytes);
    let mut out = [0xFF_u8; 32];
    assert_eq!(pk.encode_out(&mut out), 32);
    assert_eq!(out, bytes);
    assert_eq!(
        pk.to_string(),
        format!("X25519PublicKey {{ {} }}", VECTORS[0].pk_rm),
        "Display shows the bytes in hex"
    );
}
