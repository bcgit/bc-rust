//! `bouncycastle_hybrid::prelude` alone brings the methods of the calls below into scope: HPKE's Base and
//! Auth modes are called below with no other trait imported.

use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_ec::ed::x25519::keygen;
use bouncycastle_hybrid::hpke::{HpkeParams, NT};
use bouncycastle_hybrid::prelude::*;
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_symmetric::aes::AES128Key;
use bouncycastle_symmetric::modes::GCM;

#[test]
fn base_mode() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_r, sk_r) = keygen(&mut rng).unwrap();
    let params = HpkeParams::<SHA256, AES128Key<GCM>>::new(b"info");

    let (enc, mut sender) = pk_r.setup_sender(&mut rng, params).unwrap();
    let mut ct = [0u8; 5 + NT];
    sender.seal_out(b"aad", b"hello", &mut ct).unwrap();
    let mut recipient = sk_r.setup_recipient(&enc, params).unwrap();
    let mut pt = [0u8; 5 + NT];
    let n = recipient.open_out(b"aad", &ct, &mut pt).unwrap();
    assert_eq!(&pt[..n], b"hello");

    // Single-shot, on the keys.
    let (enc, n) = pk_r.seal_out(&mut rng, params, b"aad", b"hello", &mut ct).unwrap();
    let n = sk_r.open_out(&enc, params, b"aad", &ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..n], b"hello");
}

#[test]
fn auth_mode() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_r, sk_r) = keygen(&mut rng).unwrap();
    let (pk_s, sk_s) = keygen(&mut rng).unwrap();
    let params = HpkeParams::<SHA256, AES128Key<GCM>>::new(b"info");

    let (enc, sender) = pk_r.setup_auth_sender(&mut rng, &sk_s, params).unwrap();
    let recipient = sk_r.setup_auth_recipient(&enc, &pk_s, params).unwrap();
    let (mut a, mut b) = (KeyMaterial::<32>::new(), KeyMaterial::<32>::new());
    sender.export_out(b"context", &mut a);
    recipient.export_out(b"context", &mut b);
    assert!(a.equals(&b));
}
