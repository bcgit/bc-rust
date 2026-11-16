//! The generic DHKEM driven directly, over X25519 as its group, against RFC 9180 Appendix
//! A.1.1 (Base) and A.1.2 (PSK): `Encap` with the vector's ephemeral key, `Decap`,
//! `DeriveKeyPair`, the `_out` forms, and the buffers left zeroized on a small-order key. The
//! ed crate's own suites cover the same KEM through the key roles and the other four sets.

use bouncycastle_core::errors::KEMError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_ed::x25519::{
    DHKEM_SS_LEN, POINT_LEN, SCALAR_LEN, X25519, X25519PrivateKey, X25519PublicKey,
};
use bouncycastle_hex as hex;
use bouncycastle_hpke::dhkem::DHKEM;
use bouncycastle_rng::FixedSeedRNG;

type X25519DHKEM = DHKEM<X25519, POINT_LEN, SCALAR_LEN, POINT_LEN, DHKEM_SS_LEN>;

/// RFC 9180 Appendix A.1.1 (Base) and A.1.2 (PSK): ikmR, pkRm, skRm, skEm, enc, shared_secret.
const VECTORS: [[&str; 6]; 2] = [
    [
        "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    ],
    [
        "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098",
        "9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366",
        "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd",
        "463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588",
        "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b",
        "727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd",
    ],
];

fn decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn encap_and_decap_match_the_vectors_by_value_and_through_the_out_forms() {
    for (i, [ikm_r, pk_rm, sk_rm, sk_em, enc, shared_secret]) in VECTORS.iter().enumerate() {
        let pk_r = X25519PublicKey::from_bytes(&decode_32(pk_rm)).unwrap();
        let sk_r = X25519PrivateKey::from_bytes(&decode_32(sk_rm)).unwrap();

        let (ss, enc_got) =
            X25519DHKEM::encap_rng(&pk_r, &mut FixedSeedRNG::new(decode_32(sk_em))).unwrap();
        assert_eq!(enc_got, decode_32(enc), "vector {i}: enc");
        assert_eq!(ss.ref_to_bytes(), decode_32(shared_secret), "vector {i}: shared_secret");
        assert_eq!(ss.key_type(), KeyType::CryptographicRandom);
        assert_eq!(ss.security_strength(), SecurityStrength::_128bit);

        let mut enc_out = [0xFFu8; POINT_LEN];
        let mut ss_out =
            KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
        X25519DHKEM::encap_rng_out(
            &pk_r,
            &mut FixedSeedRNG::new(decode_32(sk_em)),
            &mut enc_out,
            &mut ss_out,
        )
        .unwrap();
        assert_eq!(enc_out, decode_32(enc), "vector {i}: enc (out form)");
        assert!(ss_out.equals(&ss), "vector {i}: shared_secret (out form)");

        let ss_dec = X25519DHKEM::decap(&decode_32(enc), &sk_r).unwrap();
        assert!(ss_dec.equals(&ss), "vector {i}: decap");
        let mut ss_dec_out =
            KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
        X25519DHKEM::decap_out(&decode_32(enc), &sk_r, &mut ss_dec_out).unwrap();
        assert!(ss_dec_out.equals(&ss), "vector {i}: decap (out form)");

        let ikm = KeyMaterial256::from_bytes_as_type(&decode_32(ikm_r), KeyType::Seed).unwrap();
        let (pk, sk) = X25519DHKEM::derive_key_pair(&ikm).unwrap();
        assert_eq!(pk.encode(), decode_32(pk_rm), "vector {i}: DeriveKeyPair pk");
        assert!(sk == sk_r, "vector {i}: DeriveKeyPair sk");
    }
}

#[test]
fn a_small_order_recipient_key_is_refused_and_the_buffers_left_zeroized() {
    let zero_pk = X25519PublicKey::from_bytes(&[0u8; POINT_LEN]).unwrap();
    let mut enc = [0xFFu8; POINT_LEN];
    let mut ss =
        KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
    assert!(matches!(
        X25519DHKEM::encap_rng_out(&zero_pk, &mut FixedSeedRNG::new([0x5A; 64]), &mut enc, &mut ss),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(enc, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);

    let sk = X25519PrivateKey::from_bytes(&decode_32(VECTORS[0][2])).unwrap();
    let mut ss =
        KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
    assert!(matches!(
        X25519DHKEM::decap_out(&[0u8; POINT_LEN], &sk, &mut ss),
        Err(KEMError::DecapsulationFailed)
    ));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}

/// An RNG below the group's strength is refused before any key is drawn.
#[test]
fn encap_refuses_a_weak_rng() {
    let pk_r = X25519PublicKey::from_bytes(&decode_32(VECTORS[0][1])).unwrap();
    let mut weak = FixedSeedRNG::new([0x5A; 64]);
    weak.set_security_strength(SecurityStrength::_112bit);
    assert!(matches!(X25519DHKEM::encap_rng(&pk_r, &mut weak), Err(KEMError::RNGError(_))));
}
