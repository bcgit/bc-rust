//! Behavioural tests for [`ECDSABp256r1`], mirroring `ecdsa_p256_tests.rs`.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_ecdsa::ecdsa_bp256r1::ECDSABp256r1;
use bouncycastle_ecdsa::keys_bp256r1::{ECDSABp256r1PrivateKey, ECDSABp256r1PublicKey, keygen};
use bouncycastle_ecdsa::keys_common::DerivePublicKey;
use bouncycastle_rng::DefaultRNG;

#[test]
fn derive_pk_matches_keygen() {
    let (pk, sk) = keygen().unwrap();
    assert_eq!(sk.derive_pk(), pk);
}

/// RFC 6979 §3.4/§3.6: `k` is a deterministic function of `d` and the message, so `sign` always
/// reproduces the same `(r, s)`; ECDSA has no `ctx` input at all, so it ignores the one the
/// [`Signer`]/[`SignatureVerifier`] traits offer.
#[test]
fn conformance_suite() {
    let framework = TestFrameworkSignature::new(true, false);
    framework
        .test_signature::<ECDSABp256r1PublicKey, ECDSABp256r1PrivateKey, ECDSABp256r1, ECDSABp256r1, 65, 32, 64>(
            keygen,
            true,
        );
}

#[test]
fn key_boundary_conditions() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<ECDSABp256r1PublicKey, ECDSABp256r1PrivateKey, 65, 32>(keygen);
}

#[test]
fn sign_randomized_produces_distinct_valid_signatures() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"randomised ECDSA signing";

    let sig1 = ECDSABp256r1::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    let sig2 = ECDSABp256r1::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    assert_ne!(sig1, sig2, "Appendix A.3.1's k comes from fresh randomness each call");

    ECDSABp256r1::verify(&pk, msg, None, &sig1).unwrap();
    ECDSABp256r1::verify(&pk, msg, None, &sig2).unwrap();
}

#[test]
fn sign_randomized_signature_rejected_under_wrong_key() {
    let (_, sk) = keygen().unwrap();
    let (other_pk, _) = keygen().unwrap();
    let msg = b"message";
    let sig = ECDSABp256r1::sign_randomized(&sk, msg, &mut DefaultRNG::default()).unwrap();
    match ECDSABp256r1::verify(&other_pk, msg, None, &sig) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn sign_der_matches_raw_sign_and_round_trips_through_verify_der() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"DER-encoded ECDSA signing";

    let raw = ECDSABp256r1::sign(&sk, msg, None).unwrap();
    let (der, der_len) = ECDSABp256r1::sign_der(&sk, msg, None).unwrap();

    let mut r_out = [0u8; 32];
    let mut s_out = [0u8; 32];
    bouncycastle_ecdsa::der::decode(&der[..der_len], &mut r_out, &mut s_out)
        .expect("sign_der's output must be a well-formed DER SEQUENCE { r, s }");
    assert_eq!(r_out, raw[..32], "DER-decoded r must match sign's raw r");
    assert_eq!(s_out, raw[32..], "DER-decoded s must match sign's raw s");

    ECDSABp256r1::verify_der(&pk, msg, None, &der[..der_len]).unwrap();

    let mut tampered = der;
    tampered[der_len - 1] ^= 0xFF;
    assert!(
        ECDSABp256r1::verify_der(&pk, msg, None, &tampered[..der_len]).is_err(),
        "a corrupted DER signature must not verify"
    );
}

#[test]
fn public_key_uncompressed_and_compressed_round_trip() {
    let (pk, _) = keygen().unwrap();
    let uncompressed = pk.encode();
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(ECDSABp256r1PublicKey::from_bytes(&uncompressed).unwrap(), pk);

    let compressed_tag = if uncompressed[64] & 1 == 0 { 0x02 } else { 0x03 };
    let mut compressed = [0u8; 33];
    compressed[0] = compressed_tag;
    compressed[1..].copy_from_slice(&uncompressed[1..33]);
    assert_eq!(ECDSABp256r1PublicKey::from_bytes(&compressed).unwrap(), pk);
}

#[test]
fn private_key_encode_round_trips_exact_bytes() {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x2A; // d = 42, well within [1, n-1]
    let sk = ECDSABp256r1PrivateKey::from_bytes(&bytes).unwrap();
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
    match ECDSABp256r1PrivateKey::from_bytes(&[0u8; 32]) {
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

    let (pk1, sk1) = bouncycastle_ecdsa::keys_bp256r1::keygen_from_rng(&mut FixedRng).unwrap();
    let (pk2, sk2) = bouncycastle_ecdsa::keys_bp256r1::keygen_from_rng(&mut FixedRng).unwrap();
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);
}

/// FIPS 186-5 Appendix A.2.1 step 3: an RNG weaker than the 128-bit security strength
/// brainpoolP256r1's order calls for (SP 800-57 Part 1 Rev. 5, Table 2) is refused rather than silently
/// used.
#[test]
fn keygen_from_rng_rejects_an_rng_below_the_required_strength() {
    struct WeakRng;
    impl RNG for WeakRng {
        fn add_seed_keymaterial(
            &mut self,
            _additional_seed: &dyn bouncycastle_core::key_material::KeyMaterialTrait,
        ) -> Result<(), bouncycastle_core::errors::RNGError> {
            Ok(())
        }
        fn next_int(&mut self) -> Result<u32, bouncycastle_core::errors::RNGError> {
            Ok(0)
        }
        fn next_bytes(
            &mut self,
            len: usize,
        ) -> Result<Vec<u8>, bouncycastle_core::errors::RNGError> {
            Ok(vec![0u8; len])
        }
        fn next_bytes_out(
            &mut self,
            out: &mut [u8],
        ) -> Result<usize, bouncycastle_core::errors::RNGError> {
            out.fill(0);
            Ok(out.len())
        }
        fn fill_keymaterial_out(
            &mut self,
            _out: &mut dyn bouncycastle_core::key_material::KeyMaterialTrait,
        ) -> Result<usize, bouncycastle_core::errors::RNGError> {
            unimplemented!()
        }
        fn security_strength(&self) -> bouncycastle_core::traits::SecurityStrength {
            bouncycastle_core::traits::SecurityStrength::None
        }
    }

    assert!(matches!(
        bouncycastle_ecdsa::keys_bp256r1::keygen_from_rng(&mut WeakRng),
        Err(SignatureError::RNGError(
            bouncycastle_core::errors::RNGError::SecurityStrengthInsufficientForAlgorithm
        ))
    ));
}

/// FIPS 186-5 §6.2 puts `d` in `[1, n-1]`, so an encoding of `n` or anything above it is not a
/// key. Reducing such an encoding mod `n` instead of rejecting it would give a single key two (in
/// fact, unboundedly many) valid-looking encodings: `d = n + 1` would load as `d = 1`.
#[test]
fn private_key_rejects_values_at_or_above_the_group_order() {
    let n = bouncycastle_ec::bp256r1_sec1::be_bytes_from_limbs(
        &bouncycastle_ec::bp256r1_scalar::N_LIMBS,
    );
    let mut n_plus_1 = n;
    n_plus_1[31] += 1; // n's last byte is well below 0xff, so this never carries

    for (name, bytes) in [("n", n), ("n + 1", n_plus_1), ("2^256 - 1", [0xffu8; 32])] {
        match ECDSABp256r1PrivateKey::from_bytes(&bytes) {
            Err(SignatureError::DecodingError(_)) => {}
            other => panic!("d = {name} should have been rejected, got {other:?}"),
        }
    }

    // n - 1 is the largest valid d and must still load, and must not collide with any of the above.
    let mut n_minus_1 = n;
    n_minus_1[31] -= 1; // n is odd, so this never borrows
    let sk = ECDSABp256r1PrivateKey::from_bytes(&n_minus_1).expect("d = n - 1 is in range");
    assert_eq!(sk.encode(), n_minus_1, "d = n - 1 must round-trip unchanged");
}

/// The raw encoding is exactly `r || s`; anything longer or shorter is a different, malformed
/// encoding, not a signature in a roomy buffer. Accepting trailing bytes would turn one valid
/// signature into unlimited distinct byte strings that all verify.
#[test]
fn verify_rejects_signature_of_the_wrong_length() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"length-checked signature";
    let sig = ECDSABp256r1::sign(&sk, msg, None).unwrap();
    ECDSABp256r1::verify(&pk, msg, None, &sig).expect("the untampered signature must verify");

    for extra in 1..=3 {
        let mut too_long = sig.to_vec();
        too_long.extend(core::iter::repeat_n(0xAAu8, extra));
        match ECDSABp256r1::verify(&pk, msg, None, &too_long) {
            Err(SignatureError::SignatureVerificationFailed) => {}
            other => panic!("{extra} trailing byte(s) should have failed, got {other:?}"),
        }
    }

    for short in 1..=3 {
        match ECDSABp256r1::verify(&pk, msg, None, &sig[..64 - short]) {
            Err(SignatureError::SignatureVerificationFailed) => {}
            other => panic!("{short} byte(s) short should have failed, got {other:?}"),
        }
    }
}

/// FIPS 186-5 §6.4.2 step 1: `r` and `s` must each be in `[1, n-1]`, and an out-of-range value is
/// rejected rather than reduced. Each half of a valid signature is replaced in turn by `0`, by
/// `n`, and by the all-ones pattern; the untouched half stays valid, so only the range check can
/// be what rejects the result. The wycheproof suites cover this too, but only for the curves
/// and encodings they happen to include, and not by name.
#[test]
fn verify_rejects_r_or_s_outside_1_to_n_minus_1() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"range-checked r and s";
    let sig = ECDSABp256r1::sign(&sk, msg, None).unwrap();
    ECDSABp256r1::verify(&pk, msg, None, &sig).expect("the untampered signature must verify");

    let n = bouncycastle_ec::bp256r1_sec1::be_bytes_from_limbs(
        &bouncycastle_ec::bp256r1_scalar::N_LIMBS,
    );
    for (name, bad) in [("0", [0u8; 32]), ("n", n), ("2^256 - 1", [0xffu8; 32])] {
        for (half, offset) in [("r", 0usize), ("s", 32usize)] {
            let mut tampered = sig;
            tampered[offset..offset + 32].copy_from_slice(&bad);
            match ECDSABp256r1::verify(&pk, msg, None, &tampered) {
                Err(SignatureError::SignatureVerificationFailed) => {}
                other => panic!("{half} = {name} should have been rejected, got {other:?}"),
            }
        }
    }
}

/// One `ECDSABp256r1` value serves both the [`Signer`] and [`SignatureVerifier`] streaming APIs, holding
/// whichever key its `_init` was given. Finishing with the other trait's `_final` is a caller
/// error and must be reported as one, not panic and not produce output.
#[test]
fn sign_final_on_verify_initialized_state_errors() {
    let (pk, _) = keygen().unwrap();
    let v = ECDSABp256r1::verify_init(&pk, None).unwrap();
    match v.sign_final() {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
}

#[test]
fn verify_final_on_sign_initialized_state_errors() {
    let (_, sk) = keygen().unwrap();
    let s = ECDSABp256r1::sign_init(&sk, None).unwrap();
    match s.verify_final(&[0u8; 64]) {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
}
