//! Tests for SignatureFactory and KEMFactory.

use bouncycastle_factory::AlgorithmFactory;
use bouncycastle_factory::kem_factory::{KEMFactory, KEMPrivateKey, KEMPublicKey};
use bouncycastle_factory::signature_factory::{
    SignatureFactory, SignaturePrivateKey, SignaturePublicKey,
};
use bouncycastle_mldsa::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
use bouncycastle_mlkem::{ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME};

#[test]
fn signature_defaults_and_names() {
    assert_eq!(
        SignatureFactory::default().algorithm_name(),
        ML_DSA_65_NAME
    );
    assert_eq!(
        SignatureFactory::default_128_bit().algorithm_name(),
        ML_DSA_44_NAME
    );
    assert_eq!(
        SignatureFactory::default_256_bit().algorithm_name(),
        ML_DSA_87_NAME
    );
    assert_eq!(
        SignatureFactory::new("Default").unwrap().algorithm_name(),
        ML_DSA_65_NAME
    );
    assert_eq!(
        SignatureFactory::new(ML_DSA_44_NAME)
            .unwrap()
            .algorithm_name(),
        ML_DSA_44_NAME
    );
    assert!(SignatureFactory::new("not-a-sig").is_err());
}

#[test]
fn signature_sign_verify_roundtrip_all_variants() {
    let msg = b"factory signature test message";
    for name in [ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME] {
        let factory = SignatureFactory::new(name).unwrap();
        let (pk, sk) = factory.keygen().unwrap();
        assert_eq!(pk.algorithm_name(), name);
        assert_eq!(sk.algorithm_name(), name);

        let sig = factory.sign(&sk, msg, None).unwrap();
        factory.verify(&pk, msg, None, &sig).unwrap();
        assert!(factory.verify(&pk, b"tampered", None, &sig).is_err());

        // encode/decode keys
        let pk2 = SignaturePublicKey::from_bytes(name, &pk.encode()).unwrap();
        let sk2 = SignaturePrivateKey::from_bytes(name, &sk.encode()).unwrap();
        let sig2 = factory.sign(&sk2, msg, Some(b"ctx")).unwrap();
        factory.verify(&pk2, msg, Some(b"ctx"), &sig2).unwrap();
    }
}

#[test]
fn signature_streaming_roundtrip() {
    let factory = SignatureFactory::default();
    let (pk, sk) = factory.keygen().unwrap();
    let mut signer = factory.sign_init(&sk, None).unwrap();
    signer.sign_update(b"hello ");
    signer.sign_update(b"world");
    let sig = signer.sign_final().unwrap();

    let mut verifier = factory.verify_init(&pk, None).unwrap();
    verifier.verify_update(b"hello ");
    verifier.verify_update(b"world");
    verifier.verify_final(&sig).unwrap();
}

#[test]
fn kem_defaults_and_names() {
    assert_eq!(KEMFactory::default().algorithm_name(), ML_KEM_768_NAME);
    assert_eq!(
        KEMFactory::default_128_bit().algorithm_name(),
        ML_KEM_512_NAME
    );
    assert_eq!(
        KEMFactory::default_256_bit().algorithm_name(),
        ML_KEM_1024_NAME
    );
    assert_eq!(
        KEMFactory::new("Default").unwrap().algorithm_name(),
        ML_KEM_768_NAME
    );
    assert!(KEMFactory::new("not-a-kem").is_err());
}

#[test]
fn kem_encaps_decaps_roundtrip_all_variants() {
    for name in [ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME] {
        let factory = KEMFactory::new(name).unwrap();
        let (pk, sk) = factory.keygen().unwrap();
        assert_eq!(pk.algorithm_name(), name);
        assert_eq!(sk.algorithm_name(), name);

        let (ss, ct) = factory.encaps(&pk).unwrap();
        let ss2 = factory.decaps(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);

        let pk2 = KEMPublicKey::from_bytes(name, &pk.encode()).unwrap();
        let sk2 = KEMPrivateKey::from_bytes(name, &sk.encode()).unwrap();
        let (ss3, ct3) = factory.encaps(&pk2).unwrap();
        let ss4 = factory.decaps(&sk2, &ct3).unwrap();
        assert_eq!(ss3, ss4);
    }
}

#[test]
fn key_algorithm_mismatch_errors() {
    let sig = SignatureFactory::new(ML_DSA_65_NAME).unwrap();
    let (_pk65, sk65) = sig.keygen().unwrap();
    let sig44 = SignatureFactory::new(ML_DSA_44_NAME).unwrap();
    assert!(sig44.sign(&sk65, b"msg", None).is_err());

    let kem = KEMFactory::new(ML_KEM_768_NAME).unwrap();
    let (pk768, _sk768) = kem.keygen().unwrap();
    let kem512 = KEMFactory::new(ML_KEM_512_NAME).unwrap();
    assert!(kem512.encaps(&pk768).is_err());
}
