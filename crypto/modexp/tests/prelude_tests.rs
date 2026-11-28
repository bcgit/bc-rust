//! `bouncycastle_modexp::prelude` alone brings the methods of the calls below into scope: RSA key
//! generation, signatures and RSASVE are called below with no other trait imported.

use bouncycastle_digest::sha2::SHA256;
use bouncycastle_modexp::prelude::*;
use bouncycastle_modexp::rsa::RSA2048;
use bouncycastle_rng::HashDRBG_SHA512;

#[test]
fn signature() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = RSA2048::generate_pss_signature_key_pair::<SHA256>(&mut rng).unwrap();

    let sig = sk.sign(&mut rng, b"message", None).unwrap();
    assert_eq!(sig.len(), 256);
    pk.verify(b"message", None, &sig).unwrap();

    let mut signer = sk.create_signer(&mut rng, None).unwrap();
    signer.do_update(b"message");
    let streamed = signer.do_final().unwrap();
    let mut verifier = pk.create_verifier(None).unwrap();
    verifier.do_update(b"message");
    verifier.do_verify_final(&streamed).unwrap();
}

#[test]
fn kem() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = RSA2048::generate_kem_key_pair(&mut rng).unwrap();
    let (ss, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert!(sk.decaps(&ct, ()).unwrap().equals(&ss));
}
