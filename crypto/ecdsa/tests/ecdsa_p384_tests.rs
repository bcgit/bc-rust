//! Behavioural tests for [`ECDSAP384`], mirroring `ecdsa_p256_tests.rs`.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_ecdsa::ecdsa_p384::ECDSAP384;
use bouncycastle_ecdsa::keys_common::DerivePublicKey;
use bouncycastle_ecdsa::keys_p384::{ECDSAP384PrivateKey, ECDSAP384PublicKey, keygen};
use bouncycastle_rng::DefaultRNG;

#[test]
fn derive_pk_matches_keygen() {
    let (pk, sk) = keygen().unwrap();
    assert_eq!(sk.derive_pk(), pk);
}

#[test]
fn conformance_suite() {
    let framework = TestFrameworkSignature::new(true, false);
    framework.test_signature::<ECDSAP384PublicKey, ECDSAP384PrivateKey, ECDSAP384, ECDSAP384, 97, 48, 96>(
        keygen,
        true,
    );
}

#[test]
fn key_boundary_conditions() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<ECDSAP384PublicKey, ECDSAP384PrivateKey, 97, 48>(keygen);
}

#[test]
fn sign_randomized_produces_distinct_valid_signatures() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"randomised ECDSA signing";

    let sig1 = ECDSAP384::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    let sig2 = ECDSAP384::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    assert_ne!(sig1, sig2, "Appendix A.3.1's k comes from fresh randomness each call");

    ECDSAP384::verify(&pk, msg, None, &sig1).unwrap();
    ECDSAP384::verify(&pk, msg, None, &sig2).unwrap();
}

#[test]
fn sign_randomized_signature_rejected_under_wrong_key() {
    let (_, sk) = keygen().unwrap();
    let (other_pk, _) = keygen().unwrap();
    let msg = b"message";
    let sig = ECDSAP384::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    match ECDSAP384::verify(&other_pk, msg, None, &sig) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn sign_der_matches_raw_sign_and_round_trips_through_verify_der() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"DER-encoded ECDSA signing";

    let raw = ECDSAP384::sign(&sk, msg, None).unwrap();
    let (der, der_len) = ECDSAP384::sign_der(&sk, msg, None).unwrap();

    let mut r_out = [0u8; 48];
    let mut s_out = [0u8; 48];
    bouncycastle_ecdsa::der::decode(&der[..der_len], &mut r_out, &mut s_out)
        .expect("sign_der's output must be a well-formed DER SEQUENCE { r, s }");
    assert_eq!(r_out, raw[..48], "DER-decoded r must match sign's raw r");
    assert_eq!(s_out, raw[48..], "DER-decoded s must match sign's raw s");

    ECDSAP384::verify_der(&pk, msg, None, &der[..der_len]).unwrap();

    let mut tampered = der;
    tampered[der_len - 1] ^= 0xFF;
    assert!(
        ECDSAP384::verify_der(&pk, msg, None, &tampered[..der_len]).is_err(),
        "a corrupted DER signature must not verify"
    );
}

#[test]
fn public_key_uncompressed_and_compressed_round_trip() {
    let (pk, _) = keygen().unwrap();
    let uncompressed = pk.encode();
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(ECDSAP384PublicKey::from_bytes(&uncompressed).unwrap(), pk);

    let compressed_tag = if uncompressed[96] & 1 == 0 { 0x02 } else { 0x03 };
    let mut compressed = [0u8; 49];
    compressed[0] = compressed_tag;
    compressed[1..].copy_from_slice(&uncompressed[1..49]);
    assert_eq!(ECDSAP384PublicKey::from_bytes(&compressed).unwrap(), pk);
}

#[test]
fn private_key_rejects_zero() {
    match ECDSAP384PrivateKey::from_bytes(&[0u8; 48]) {
        Err(SignatureError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
}

#[test]
fn private_key_encode_round_trips_exact_bytes() {
    let mut bytes = [0u8; 48];
    bytes[47] = 0x2A; // d = 42
    let sk = ECDSAP384PrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(sk.encode(), bytes);

    let mut out = [0xFFu8; 48];
    let written = sk.encode_out(&mut out);
    assert_eq!(written, 48);
    assert_eq!(out, bytes);
}

#[test]
fn public_key_encode_out_matches_encode() {
    let (pk, _) = keygen().unwrap();
    let encoded = pk.encode();

    let mut out = [0xFFu8; 97];
    let written = pk.encode_out(&mut out);
    assert_eq!(written, 97);
    assert_eq!(out, encoded);
}

#[test]
fn public_key_display_differs_for_different_keys() {
    let (pk1, _) = keygen().unwrap();
    let (pk2, _) = keygen().unwrap();
    assert_ne!(format!("{pk1}"), format!("{pk2}"));
}

#[test]
fn keygen_from_rng_is_deterministic_given_a_deterministic_rng() {
    struct FixedRng;
    impl RNG for FixedRng {
        fn add_seed_keymaterial(
            &mut self,
            _additional_seed: &dyn bouncycastle_core::key_material::KeyMaterialTrait,
        ) -> Result<(), bouncycastle_core::errors::RNGError> {
            Ok(())
        }
        fn next_int(&mut self) -> Result<u32, bouncycastle_core::errors::RNGError> {
            Ok(0x42424242)
        }
        fn next_bytes(
            &mut self,
            len: usize,
        ) -> Result<Vec<u8>, bouncycastle_core::errors::RNGError> {
            Ok(vec![0x42u8; len])
        }
        fn next_bytes_out(
            &mut self,
            out: &mut [u8],
        ) -> Result<usize, bouncycastle_core::errors::RNGError> {
            out.fill(0x42);
            Ok(out.len())
        }
        fn fill_keymaterial_out(
            &mut self,
            _out: &mut dyn bouncycastle_core::key_material::KeyMaterialTrait,
        ) -> Result<usize, bouncycastle_core::errors::RNGError> {
            unimplemented!()
        }
        fn security_strength(&self) -> bouncycastle_core::traits::SecurityStrength {
            bouncycastle_core::traits::SecurityStrength::_256bit
        }
    }

    let (pk1, sk1) = bouncycastle_ecdsa::keys_p384::keygen_from_rng(&mut FixedRng).unwrap();
    let (pk2, sk2) = bouncycastle_ecdsa::keys_p384::keygen_from_rng(&mut FixedRng).unwrap();
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);
}
