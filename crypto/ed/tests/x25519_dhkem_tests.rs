//! X25519 as a KEM: DHKEM(X25519, HKDF-SHA256) of RFC 9180 Section 4.1, against the RFC 9180
//! Appendix A.1 vectors and the core-test-framework KEM suites.

use bouncycastle_core::errors::{KEMError, RNGError};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG,
};
use bouncycastle_core_test_framework::kem::{TestFrameworkKEM, TestFrameworkKEMKeys};
use bouncycastle_ed::x25519::{
    DHKEM_SS_LEN, POINT_LEN, SCALAR_LEN, X25519, X25519PrivateKey, X25519PublicKey, keygen,
    keygen_from_seed,
};
use bouncycastle_hex as hex;
use bouncycastle_hpke::dhkem::DHKEM;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG, HashDRBG_SHA512};

type X25519DHKEM = DHKEM<X25519, POINT_LEN, SCALAR_LEN, POINT_LEN, DHKEM_SS_LEN>;

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
const VECTORS: [Vector; 6] = [
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
    // A.2.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, Base): the same KEM.
    Vector {
        ikm_e: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        pk_em: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        sk_em: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        ikm_r: "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
        pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        enc: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        shared_secret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    },
    // A.2.2 (the same, PSK mode: the KEM does not see the PSK).
    Vector {
        ikm_e: "35706a0b09fb26fb45c39c2f5079c709c7cf98e43afa973f14d88ece7e29c2e3",
        pk_em: "2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04",
        sk_em: "0c35fdf49df7aa01cd330049332c40411ebba36e0c718ebc3edf5845795f6321",
        ikm_r: "26b923eade72941c8a85b09986cdfa3f1296852261adedc52d58d2930269812b",
        pk_rm: "13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062",
        sk_rm: "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879",
        enc: "2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04",
        shared_secret: "4be079c5e77779d0215b3f689595d59e3e9b0455d55662d1f3666ec606e50ea7",
    },
    // A.7.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD, Base).
    Vector {
        ikm_e: "55bc245ee4efda25d38f2d54d5bb6665291b99f8108a8c4b686c2b14893ea5d9",
        pk_em: "e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918",
        sk_em: "095182b502f1f91f63ba584c7c3ec473d617b8b4c2cec3fad5af7fa6748165ed",
        ikm_r: "683ae0da1d22181e74ed2e503ebf82840deb1d5e872cade20f4b458d99783e31",
        pk_rm: "194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664",
        sk_rm: "33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848",
        enc: "e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918",
        shared_secret: "e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66",
    },
    // A.7.2 (the same, PSK mode).
    Vector {
        ikm_e: "c51211a8799f6b8a0021fcba673d9c4067a98ebc6794232e5b06cb9febcbbdf5",
        pk_em: "d3805a97cbcd5f08babd21221d3e6b362a700572d14f9bbeb94ec078d051ae3d",
        sk_em: "1d72396121a6a826549776ef1a9d2f3a2907fc6a38902fa4e401afdb0392e627",
        ikm_r: "5e0516b1b29c0e13386529da16525210c796f7d647c37eac118023a6aa9eb89a",
        pk_rm: "d53af36ea5f58f8868bb4a1333ed4cc47e7a63b0040eb54c77b9c8ec456da824",
        sk_rm: "98f304d4ecb312689690b113973c61ffe0aa7c13f2fbe365e48f3ed09e5a6a0c",
        enc: "d3805a97cbcd5f08babd21221d3e6b362a700572d14f9bbeb94ec078d051ae3d",
        shared_secret: "024573db58c887decb4c57b6ed39f2c9a09c85600a8a0ecb11cac24c6aaec195",
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

/// `keygen` with its error mapped, in the shape the KEM test framework takes.
fn keygen_kem() -> Result<(X25519PublicKey, X25519PrivateKey), KEMError> {
    keygen(&mut DefaultRNG::default()).map_err(|_| KEMError::KeyGenError("X25519 keygen failed"))
}

/// `Encap` with the vector's ephemeral key: the RNG emits skEm, which keygen uses as the private
/// key unchanged.
#[test]
fn rfc9180_encaps() {
    for (i, v) in VECTORS.iter().enumerate() {
        let pk_r = X25519PublicKey::from_bytes(&decode_32(v.pk_rm)).unwrap();
        let mut rng = FixedSeedRNG::new(decode_32(v.sk_em));
        let (ss, enc) = pk_r.encaps(&mut rng, ()).unwrap();
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
        let ss = sk_r.decaps(&decode_32(v.enc), ()).unwrap();
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

/// `encaps` rejects an RNG below 128 bits and accepts one at exactly 128 bits.
#[test]
fn encaps_rng_security_strength() {
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();

    let mut weak = FixedSeedRNG::new([0x5A; 32]);
    weak.set_security_strength(SecurityStrength::_112bit);
    match pk.encaps(&mut weak, ()) {
        Err(KEMError::RNGError(_)) => { /* good */ }
        _ => panic!("expected RNGError for a 112-bit RNG"),
    }

    let mut just_right = FixedSeedRNG::new([0x5A; 32]);
    just_right.set_security_strength(SecurityStrength::_128bit);
    pk.encaps(&mut just_right, ()).unwrap();
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
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();
    match pk.encaps(&mut FailingRNG, ()) {
        Err(KEMError::RNGError(RNGError::GenericError(_))) => { /* good */ }
        other => panic!("expected the RNG's error, got {other:?}"),
    }
}

#[test]
fn kem_framework() {
    // DHKEM is randomized. A modified ciphertext is another public key, so decaps succeeds with a
    // different shared secret, which is the behaviour the framework checks for an implicitly
    // rejecting KEM. Every bit of enc is flipped: X25519 ignores bit 255 of a u-coordinate, but
    // enc is also in kem_context, so flipping any of its 256 bits changes the shared secret.
    TestFrameworkKEM::new(false, true)
        .test_kem::<(), X25519PublicKey, X25519PrivateKey, POINT_LEN, DHKEM_SS_LEN>(
            keygen_kem,
            (),
            true,
        );
}

#[test]
fn kem_keys_framework() {
    TestFrameworkKEMKeys::new()
        .test_keys::<X25519PublicKey, X25519PrivateKey, POINT_LEN, SCALAR_LEN>(keygen_kem);
}

/// Low-order public keys give an all-zero X25519 output, which RFC 9180 Section 7.1.4 requires
/// both sides to reject.
#[test]
fn rejects_low_order_public_key() {
    let (_, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut zero_bit_255 = [0_u8; 32];
    zero_bit_255[31] = 0x80;
    let p = decode_32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

    for u in [[0_u8; 32], p, zero_bit_255] {
        match X25519PublicKey::from_bytes(&u)
            .unwrap()
            .encaps(&mut HashDRBG_SHA512::new_from_os(), ())
        {
            Err(KEMError::InvalidPublicKey(_)) => { /* good */ }
            other => panic!("encaps: expected InvalidPublicKey for u = {u:02x?}, got {other:?}"),
        }
        match sk.decaps(&u, ()) {
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
    let (_, unclamped) = keygen_from_seed(&seed(VECTORS[0].sk_rm)).unwrap();
    assert!(unclamped == sk);
    assert_eq!(unclamped.encode(), clamp(raw));
    assert!(unclamped.clone() == sk);

    let (_, other) = keygen(&mut DefaultRNG::default()).unwrap();
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

/// The KEM workers called directly, not through the roles' provided one-shots (which zeroize
/// the buffers themselves): each leaves stale buffers zeroized when the key has small order.
#[test]
fn the_kem_workers_leave_stale_buffers_zeroized_on_a_small_order_key() {
    let (_, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let zero_pk = X25519PublicKey::from_bytes(&[0u8; POINT_LEN]).unwrap();
    let stale = || {
        KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; DHKEM_SS_LEN], KeyType::Seed)
            .unwrap()
    };

    let encapsulator = zero_pk.create_encapsulator(()).unwrap();
    let mut ct = [0xFFu8; POINT_LEN];
    let mut ss = stale();
    assert!(matches!(
        encapsulator.encaps_out(&mut HashDRBG_SHA512::new_from_os(), &mut ct, &mut ss),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(ct, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert_eq!(ss.key_len(), 0);

    let decapsulator = sk.create_decapsulator(()).unwrap();
    let mut ss = stale();
    assert!(matches!(
        decapsulator.decaps_out(&[0u8; POINT_LEN], &mut ss),
        Err(KEMError::DecapsulationFailed)
    ));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert_eq!(ss.key_len(), 0);
}
