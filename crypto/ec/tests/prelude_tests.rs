//! `bouncycastle_ec::prelude` alone brings the methods of the calls below into scope: ECDSA, ECC CDH,
//! DHKEM and Ed25519 are called below with no other trait imported.

use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_ec::P256;
use bouncycastle_ec::ecdsa::keys::ECDSAPublicKey;
use bouncycastle_ec::ed::ed25519;
use bouncycastle_ec::ed::ed25519::Ed25519PrivateKey;
use bouncycastle_ec::prelude::*;
use bouncycastle_rng::HashDRBG_SHA512;

#[test]
fn ecdsa() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut rng).unwrap();
    assert!(sk.pub_key().unwrap() == pk);

    let sig = sk.sign(&mut rng, b"message", None).unwrap();
    pk.verify(b"message", None, &sig).unwrap();
    let det = sk.sign_deterministic(b"message", None).unwrap();
    pk.verify(b"message", None, &det).unwrap();

    let mut signer = sk.create_signer(&mut rng, None).unwrap();
    signer.do_update(b"message");
    let streamed = signer.do_final().unwrap();
    let mut verifier = pk.create_verifier(None).unwrap();
    verifier.do_update(b"message");
    verifier.do_verify_final(&streamed).unwrap();

    let decoded = ECDSAPublicKey::<P256, SHA256>::from_bytes(&pk.encode()).unwrap();
    assert!(decoded == pk);
}

#[test]
fn eccdh() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_a, sk_a) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    assert!(sk_a.pub_key().unwrap() == pk_a);

    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.create_agreement(()).unwrap().agree(&pk_a).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn dhkem_auth() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_r, sk_r) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_s, sk_s) = P256::generate_agreement_key_pair(&mut rng).unwrap();

    let mut enc = [0u8; 65];
    let mut ss = KeyMaterial::<32>::new();
    pk_r.auth_encaps_out(&mut rng, &sk_s, &mut enc, &mut ss).unwrap();
    let mut got = KeyMaterial::<32>::new();
    sk_r.auth_decaps_out(&enc, &pk_s, &mut got).unwrap();
    assert!(got.equals(&ss));
}

#[test]
fn eddsa() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = ed25519::keygen(&mut rng).unwrap();
    assert!(ed25519::Ed25519PrivateKey::from_bytes(&sk.encode()).unwrap() == sk);
    let sig = sk.sign_deterministic(b"message", None).unwrap();
    pk.verify(b"message", None, &sig).unwrap();
}

/// Key generation through `KeyPairGenerator`, which the prelude brings in from core.
#[test]
fn key_pair_generator() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = Ed25519PrivateKey::generate(&mut rng).unwrap();
    assert!(sk.pub_key().unwrap() == pk);
    let mut held = Ed25519PrivateKey::zeroized();
    Ed25519PrivateKey::generate_out(&mut rng, &mut held).unwrap();
    pk.verify(b"m", None, &sk.sign_deterministic(b"m", None).unwrap()).unwrap();
}
