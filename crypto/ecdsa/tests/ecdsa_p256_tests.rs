//! Behavioural tests for [`ECDSAP256`]: the shared `core-test-framework` conformance suite (per
//! QUALITY_AND_STYLE's rule that trait conformance lives there, not per-implementation), key
//! encode/decode boundary conditions, and this crate's own additions the generic suite doesn't
//! cover -- the randomised (Appendix A.3.1) signing path and public-key encoding round trips.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_ecdsa::ecdsa_p256::ECDSAP256;
use bouncycastle_ecdsa::keys::{ECDSAP256PrivateKey, ECDSAP256PublicKey, keygen};
use bouncycastle_rng::DefaultRNG;

/// RFC 6979 §3.4/§3.6: `k` is a deterministic function of `d` and the message, so `sign` always
/// reproduces the same `(r, s)`; ECDSA has no `ctx` input at all, so it ignores the one the
/// [`Signer`]/[`SignatureVerifier`] traits offer.
#[test]
fn conformance_suite() {
    let framework = TestFrameworkSignature::new(true, false);
    framework.test_signature::<ECDSAP256PublicKey, ECDSAP256PrivateKey, ECDSAP256, ECDSAP256, 65, 32, 64>(
        keygen,
        true,
    );
}

#[test]
fn key_boundary_conditions() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<ECDSAP256PublicKey, ECDSAP256PrivateKey, 65, 32>(keygen);
}

#[test]
fn sign_randomized_produces_distinct_valid_signatures() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"randomised ECDSA signing";

    let sig1 = ECDSAP256::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    let sig2 = ECDSAP256::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    assert_ne!(sig1, sig2, "Appendix A.3.1's k comes from fresh randomness each call");

    ECDSAP256::verify(&pk, msg, None, &sig1).unwrap();
    ECDSAP256::verify(&pk, msg, None, &sig2).unwrap();
}

#[test]
fn sign_randomized_signature_rejected_under_wrong_key() {
    let (_, sk) = keygen().unwrap();
    let (other_pk, _) = keygen().unwrap();
    let msg = b"message";
    let sig = ECDSAP256::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    match ECDSAP256::verify(&other_pk, msg, None, &sig) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn public_key_uncompressed_and_compressed_round_trip() {
    let (pk, _) = keygen().unwrap();
    let uncompressed = pk.encode();
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(ECDSAP256PublicKey::from_bytes(&uncompressed).unwrap(), pk);

    let compressed_tag = if uncompressed[64] & 1 == 0 { 0x02 } else { 0x03 };
    let mut compressed = [0u8; 33];
    compressed[0] = compressed_tag;
    compressed[1..].copy_from_slice(&uncompressed[1..33]);
    assert_eq!(ECDSAP256PublicKey::from_bytes(&compressed).unwrap(), pk);
}

#[test]
fn private_key_encode_round_trips_exact_bytes() {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x2A; // d = 42, well within [1, n-1]
    let sk = ECDSAP256PrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(sk.encode(), bytes);

    let mut out = [0xFFu8; 32];
    let written = sk.encode_out(&mut out);
    assert_eq!(written, 32);
    assert_eq!(out, bytes);
}

#[test]
fn public_key_encode_out_matches_encode() {
    let (pk, _) = keygen().unwrap();
    let encoded = pk.encode();

    let mut out = [0xFFu8; 65];
    let written = pk.encode_out(&mut out);
    assert_eq!(written, 65);
    assert_eq!(out, encoded);
}

#[test]
fn public_key_display_differs_for_different_keys() {
    let (pk1, _) = keygen().unwrap();
    let (pk2, _) = keygen().unwrap();
    assert_ne!(format!("{pk1}"), format!("{pk2}"), "Display should reflect the actual key bytes");
}

#[test]
fn private_key_rejects_zero() {
    match ECDSAP256PrivateKey::from_bytes(&[0u8; 32]) {
        Err(SignatureError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
}

#[test]
fn keygen_from_rng_is_deterministic_given_a_deterministic_rng() {
    // A fixed-output RNG (all-0x42 bytes) must yield the same key pair both times: pins that
    // `keygen_from_rng` has no hidden extra randomness source of its own.
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

    let (pk1, sk1) = bouncycastle_ecdsa::keys::keygen_from_rng(&mut FixedRng).unwrap();
    let (pk2, sk2) = bouncycastle_ecdsa::keys::keygen_from_rng(&mut FixedRng).unwrap();
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);
}
