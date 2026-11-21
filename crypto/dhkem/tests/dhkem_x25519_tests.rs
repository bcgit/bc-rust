//! The generic DHKEM driven directly, over X25519 as its group, against RFC 9180 Appendix
//! A.1.1 (Base) and A.1.2 (PSK), and A.1.3 (Auth) and A.1.4 (AuthPSK) for `AuthEncap` and
//! `AuthDecap`: `Encap` with the vector's ephemeral key, `Decap`,
//! `DeriveKeyPair`, the `_out` forms, and the buffers left zeroized on a small-order key. The
//! ed crate's own suites cover the same KEM through the key roles and the other four sets.

use bouncycastle_core::errors::KEMError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_dhkem::DHKEM;
use bouncycastle_ed::x25519::{
    DHKEM_SS_LEN, POINT_LEN, SCALAR_LEN, X25519, X25519PrivateKey, X25519PublicKey,
};
use bouncycastle_hex as hex;

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
        // The out forms report what they wrote: Nenc for an encapsulation.
        let written = X25519DHKEM::encap_rng_out(
            &pk_r,
            &mut FixedSeedRNG::new(decode_32(sk_em)),
            &mut enc_out,
            &mut ss_out,
        );
        assert_eq!(written, Ok(POINT_LEN));
        assert_eq!(enc_out, decode_32(enc), "vector {i}: enc (out form)");
        assert!(ss_out.equals(&ss), "vector {i}: shared_secret (out form)");

        let ss_dec = X25519DHKEM::decap(&decode_32(enc), &sk_r).unwrap();
        assert!(ss_dec.equals(&ss), "vector {i}: decap");
        let mut ss_dec_out =
            KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
        // And Nsecret for a decapsulation.
        assert_eq!(
            X25519DHKEM::decap_out(&decode_32(enc), &sk_r, &mut ss_dec_out),
            Ok(DHKEM_SS_LEN)
        );
        assert!(ss_dec_out.equals(&ss), "vector {i}: decap (out form)");
        let mut with_pk =
            KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
        assert_eq!(
            X25519DHKEM::decap_with_pk_out(&decode_32(enc), &sk_r, &pk_r, &mut with_pk),
            Ok(DHKEM_SS_LEN)
        );
        assert!(with_pk.equals(&ss), "vector {i}: decap with pk(skR) supplied");

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

/// RFC 9180 Appendix A.1.3 (Auth) and A.1.4 (AuthPSK): pkRm, skRm, pkSm, skSm, skEm, enc,
/// shared_secret.
const AUTH_VECTORS: [[&str; 7]; 2] = [
    [
        "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e",
        "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e",
        "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b",
        "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd",
        "ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518",
        "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76",
        "2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7",
    ],
    [
        "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976",
        "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423",
        "2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e",
        "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4",
        "14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768",
        "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c",
        "f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577",
    ],
];

/// A stale secret buffer, to show that a call replaces or zeroizes it.
fn stale_secret() -> KeyMaterial<DHKEM_SS_LEN> {
    KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap()
}

#[test]
fn auth_encap_and_auth_decap_match_the_vectors_and_bind_the_senders_key() {
    for (i, [pk_rm, sk_rm, pk_sm, sk_sm, sk_em, enc, shared_secret]) in
        AUTH_VECTORS.iter().enumerate()
    {
        let pk_r = X25519PublicKey::from_bytes(&decode_32(pk_rm)).unwrap();
        let sk_r = X25519PrivateKey::from_bytes(&decode_32(sk_rm)).unwrap();
        let pk_s = X25519PublicKey::from_bytes(&decode_32(pk_sm)).unwrap();
        let sk_s = X25519PrivateKey::from_bytes(&decode_32(sk_sm)).unwrap();

        // AuthEncap(pkR, skS), with the vector's ephemeral key.
        let mut enc_out = [0xFFu8; POINT_LEN];
        let mut ss = stale_secret();
        let written = X25519DHKEM::auth_encap_rng_out(
            &pk_r,
            &sk_s,
            &mut FixedSeedRNG::new(decode_32(sk_em)),
            &mut enc_out,
            &mut ss,
        );
        assert_eq!(written, Ok(POINT_LEN));
        assert_eq!(enc_out, decode_32(enc), "vector {i}: enc");
        assert_eq!(ss.ref_to_bytes(), decode_32(shared_secret), "vector {i}: shared_secret");
        assert_eq!(ss.key_type(), KeyType::CryptographicRandom);
        assert_eq!(ss.security_strength(), SecurityStrength::_128bit);

        // AuthDecap(enc, skR, pkS), and with pk(skR) supplied.
        let mut ss_dec = stale_secret();
        assert_eq!(
            X25519DHKEM::auth_decap_out(&decode_32(enc), &sk_r, &pk_s, &mut ss_dec),
            Ok(DHKEM_SS_LEN)
        );
        assert!(ss_dec.equals(&ss), "vector {i}: auth_decap");
        let mut ss_dec = stale_secret();
        assert_eq!(
            X25519DHKEM::auth_decap_with_pk_out(&decode_32(enc), &sk_r, &pk_r, &pk_s, &mut ss_dec),
            Ok(DHKEM_SS_LEN)
        );
        assert!(ss_dec.equals(&ss), "vector {i}: auth_decap_with_pk");

        // Another sender's public key, and the unauthenticated Decap, each give another secret.
        let mut other = stale_secret();
        X25519DHKEM::auth_decap_out(&decode_32(enc), &sk_r, &pk_r, &mut other).unwrap();
        assert!(!other.equals(&ss), "vector {i}: another pkS");
        X25519DHKEM::decap_out(&decode_32(enc), &sk_r, &mut other).unwrap();
        assert!(!other.equals(&ss), "vector {i}: Decap");
    }
}

#[test]
fn the_authenticated_forms_refuse_small_order_keys_and_leave_the_buffers_zeroized() {
    let zero_pk = X25519PublicKey::from_bytes(&[0u8; POINT_LEN]).unwrap();
    let pk_r = X25519PublicKey::from_bytes(&decode_32(AUTH_VECTORS[0][0])).unwrap();
    let sk_r = X25519PrivateKey::from_bytes(&decode_32(AUTH_VECTORS[0][1])).unwrap();
    let pk_s = X25519PublicKey::from_bytes(&decode_32(AUTH_VECTORS[0][2])).unwrap();
    let sk_s = X25519PrivateKey::from_bytes(&decode_32(AUTH_VECTORS[0][3])).unwrap();
    let enc = decode_32(AUTH_VECTORS[0][5]);

    // The recipient's key, on the sender's side.
    let mut enc_out = [0xFFu8; POINT_LEN];
    let mut ss = stale_secret();
    assert!(matches!(
        X25519DHKEM::auth_encap_rng_out(
            &zero_pk,
            &sk_s,
            &mut FixedSeedRNG::new([0x5A; 64]),
            &mut enc_out,
            &mut ss
        ),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(enc_out, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);

    // A weak RNG is refused before any key is drawn.
    let mut weak = FixedSeedRNG::new([0x5A; 64]);
    weak.set_security_strength(SecurityStrength::_112bit);
    let mut enc_out = [0xFFu8; POINT_LEN];
    let mut ss = stale_secret();
    assert!(matches!(
        X25519DHKEM::auth_encap_rng_out(&pk_r, &sk_s, &mut weak, &mut enc_out, &mut ss),
        Err(KEMError::RNGError(_))
    ));
    assert_eq!(enc_out, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);

    // The ephemeral key and the sender's key, on the recipient's side.
    let mut ss = stale_secret();
    assert_eq!(
        X25519DHKEM::auth_decap_out(&[0u8; POINT_LEN], &sk_r, &pk_s, &mut ss),
        Err(KEMError::DecapsulationFailed)
    );
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    let mut ss = stale_secret();
    assert!(matches!(
        X25519DHKEM::auth_decap_out(&enc, &sk_r, &zero_pk, &mut ss),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}
