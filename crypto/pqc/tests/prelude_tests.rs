//! `bouncycastle_pqc::prelude` alone brings the methods of the calls below into scope: ML-KEM and ML-DSA,
//! in both forms, are called below with no other trait imported.

use bouncycastle_pqc::mldsa::MLDSA65;
use bouncycastle_pqc::mldsa_lowmemory::MLDSA65 as MLDSA65LowMemory;
use bouncycastle_pqc::mlkem::MLKEM768;
use bouncycastle_pqc::mlkem_lowmemory::MLKEM768 as MLKEM768LowMemory;
use bouncycastle_pqc::prelude::*;
use bouncycastle_rng::HashDRBG_SHA512;

#[test]
fn mlkem() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
    assert!(*sk.pk().unwrap() == pk);

    let (ss, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert_eq!(sk.decaps(&ct, ()).unwrap(), ss);

    let (ss, ct) = pk.create_encapsulator(()).unwrap().encaps(&mut rng).unwrap();
    assert_eq!(sk.create_decapsulator(()).unwrap().decaps(&ct).unwrap(), ss);
}

#[test]
fn mlkem_lowmemory() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLKEM768LowMemory::keygen(&mut rng).unwrap();
    let (ss, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert_eq!(sk.decaps(&ct, ()).unwrap(), ss);
}

#[test]
fn mldsa() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLDSA65::keygen(&mut rng).unwrap();
    assert!(sk.derive_pk() == pk);

    let sig = sk.sign(&mut rng, b"message", None).unwrap();
    pk.verify(b"message", None, &sig).unwrap();

    let mut signer = sk.create_signer(&mut rng, None).unwrap();
    signer.do_update(b"message");
    let streamed = signer.do_final().unwrap();
    let mut verifier = pk.create_verifier(None).unwrap();
    verifier.do_update(b"message");
    verifier.do_verify_final(&streamed).unwrap();

    let mu = pk.compute_mu(b"message", None).unwrap();
    let sig = sk.sign_mu(&mu, &mut rng).unwrap();
    pk.verify(b"message", None, &sig).unwrap();
}

#[test]
fn mldsa_lowmemory() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLDSA65LowMemory::keygen(&mut rng).unwrap();
    let sig = sk.sign(&mut rng, b"message", None).unwrap();
    pk.verify(b"message", None, &sig).unwrap();
}
