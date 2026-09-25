//! Behavioural tests for [`SM2`]. Does not reuse
//! `bouncycastle_core_test_framework::signature::TestFrameworkSignature`: that framework calls
//! `sign(&sk, msg, None)` unconditionally in several of its checks (basic sign/verify, `sign_out`,
//! the large-message case), which is incompatible with SM2's requirement that `ctx` always carry
//! the signer's identity `IDA` (see [`crate::sm2`]'s module docs) -- every other primitive the
//! framework covers treats `ctx` as optional. This file instead covers the same ground by hand,
//! always passing `ctx = Some(id)`, plus a dedicated test that `ctx = None` is rejected.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_core_test_framework::signature::TestFrameworkSignatureKeys;
use bouncycastle_ec::sm2_scalar::N_LIMBS;
use bouncycastle_ec::sm2_sec1::be_bytes_from_limbs;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sm2::keys::{SM2PrivateKey, SM2PublicKey, keygen};
use bouncycastle_sm2::sm2::SM2;

const ID: &[u8] = b"test-identity@example.com";

#[test]
fn key_boundary_conditions() {
    TestFrameworkSignatureKeys::new().test_keys::<SM2PublicKey, SM2PrivateKey, 65, 32>(keygen);
}

#[test]
fn derive_pk_matches_keygen() {
    let (pk, sk) = keygen().unwrap();
    assert_eq!(sk.derive_pk(), pk);
}

#[test]
fn sign_then_verify_round_trips() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"The quick brown fox jumped over the lazy dog";

    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();
    SM2::verify(&pk, msg, Some(ID), &sig).unwrap();
}

#[test]
fn sign_is_non_deterministic() {
    // draft-shen-sm2-ecdsa-02 S5.1.3 step A3: k is drawn fresh from randomness each call, unlike
    // bouncycastle-ecdsa's RFC-6979-deterministic default.
    let (_, sk) = keygen().unwrap();
    let msg = b"same message, different k";

    let sig1 = SM2::sign(&sk, msg, Some(ID)).unwrap();
    let sig2 = SM2::sign(&sk, msg, Some(ID)).unwrap();
    assert_ne!(sig1, sig2);
}

#[test]
fn sign_and_verify_require_ctx() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"message";
    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();

    match SM2::sign(&sk, msg, None) {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
    match SM2::verify(&pk, msg, None, &sig) {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
}

#[test]
fn different_ctx_values_produce_signatures_valid_only_under_their_own_ctx() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"message";

    let sig_a = SM2::sign(&sk, msg, Some(b"identity-a")).unwrap();
    SM2::verify(&pk, msg, Some(b"identity-a"), &sig_a).unwrap();
    match SM2::verify(&pk, msg, Some(b"identity-b"), &sig_a) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn verify_rejects_signature_under_wrong_key() {
    let (_, sk) = keygen().unwrap();
    let (other_pk, _) = keygen().unwrap();
    let msg = b"message";
    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();
    match SM2::verify(&other_pk, msg, Some(ID), &sig) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn verify_rejects_bitflipped_signature() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"message";
    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();

    for i in 0..sig.len() {
        for j in 0..8u8 {
            let mut tampered = sig;
            tampered[i] ^= 1 << j;
            match SM2::verify(&pk, msg, Some(ID), &tampered) {
                Err(SignatureError::SignatureVerificationFailed) => {}
                _ => panic!("bit flip at byte {i} bit {j} should have failed verification"),
            }
        }
    }
}

#[test]
fn sign_randomized_produces_distinct_valid_signatures() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"randomised SM2 signing";

    let sig1 = SM2::sign_randomized(&sk, msg, ID, &mut DefaultRNG::default()).unwrap();
    let sig2 = SM2::sign_randomized(&sk, msg, ID, &mut DefaultRNG::default()).unwrap();
    assert_ne!(sig1, sig2);

    SM2::verify(&pk, msg, Some(ID), &sig1).unwrap();
    SM2::verify(&pk, msg, Some(ID), &sig2).unwrap();
}

#[test]
fn sign_out_produces_a_verifiable_signature() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"message";

    let mut out = [0xFFu8; 64];
    let written = SM2::sign_out(&sk, msg, Some(ID), &mut out).unwrap();
    assert_eq!(written, 64);
    SM2::verify(&pk, msg, Some(ID), &out).unwrap();
}

#[test]
fn large_message_round_trips() {
    let (pk, sk) = keygen().unwrap();
    let sig = SM2::sign(&sk, DUMMY_SEED, Some(ID)).unwrap();
    SM2::verify(&pk, DUMMY_SEED, Some(ID), &sig).unwrap();
}

#[test]
fn streaming_sign_and_verify_single_update() {
    let (pk, sk) = keygen().unwrap();

    let mut s = SM2::sign_init(&sk, Some(ID)).unwrap();
    s.sign_update(DUMMY_SEED);
    let sig = s.sign_final().unwrap();

    let mut v = SM2::verify_init(&pk, Some(ID)).unwrap();
    v.verify_update(DUMMY_SEED);
    v.verify_final(&sig).unwrap();
}

#[test]
fn streaming_sign_and_verify_chunked() {
    let (pk, sk) = keygen().unwrap();

    let mut s = SM2::sign_init(&sk, Some(ID)).unwrap();
    for chunk in DUMMY_SEED.chunks(100) {
        s.sign_update(chunk);
    }
    let sig = s.sign_final().unwrap();

    let mut v = SM2::verify_init(&pk, Some(ID)).unwrap();
    for chunk in DUMMY_SEED.chunks(100) {
        v.verify_update(chunk);
    }
    v.verify_final(&sig).unwrap();
}

#[test]
fn streaming_verify_rejects_wrong_message() {
    let (pk, sk) = keygen().unwrap();
    let sig = SM2::sign(&sk, DUMMY_SEED, Some(ID)).unwrap();

    let mut v = SM2::verify_init(&pk, Some(ID)).unwrap();
    v.verify_update(b"this is the wrong message");
    match v.verify_final(&sig) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn sign_final_out_matches_sign_final() {
    let (pk, sk) = keygen().unwrap();

    let mut s = SM2::sign_init(&sk, Some(ID)).unwrap();
    s.sign_update(DUMMY_SEED);
    let mut sig = [0u8; 64];
    let written = s.sign_final_out(&mut sig).unwrap();
    assert_eq!(written, 64);

    SM2::verify(&pk, DUMMY_SEED, Some(ID), &sig).unwrap();
}

#[test]
fn verify_rejects_signature_of_the_wrong_length() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"message";
    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();
    SM2::verify(&pk, msg, Some(ID), &sig).expect("the untampered signature must verify");

    // Trailing bytes must not be ignored: otherwise one valid signature yields unlimited distinct
    // byte strings that all verify, which breaks any caller that compares or deduplicates
    // signatures as opaque blobs.
    for extra in 1..=3 {
        let mut too_long = sig.to_vec();
        too_long.extend(core::iter::repeat_n(0xAAu8, extra));
        match SM2::verify(&pk, msg, Some(ID), &too_long) {
            Err(SignatureError::SignatureVerificationFailed) => {}
            other => panic!("{extra} trailing byte(s) should have failed, got {other:?}"),
        }
    }

    for short in 1..=3 {
        match SM2::verify(&pk, msg, Some(ID), &sig[..64 - short]) {
            Err(SignatureError::SignatureVerificationFailed) => {}
            other => panic!("{short} byte(s) short should have failed, got {other:?}"),
        }
    }
}

#[test]
fn sign_final_on_verify_initialized_state_errors() {
    let (pk, _) = keygen().unwrap();
    let v = SM2::verify_init(&pk, Some(ID)).unwrap();
    match v.sign_final() {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
}

#[test]
fn verify_final_on_sign_initialized_state_errors() {
    let (_, sk) = keygen().unwrap();
    let s = SM2::sign_init(&sk, Some(ID)).unwrap();
    match s.verify_final(&[0u8; 64]) {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
}

#[test]
fn public_key_uncompressed_and_compressed_round_trip() {
    let (pk, _) = keygen().unwrap();
    let uncompressed = pk.encode();
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(SM2PublicKey::from_bytes(&uncompressed).unwrap(), pk);

    let compressed_tag = if uncompressed[64] & 1 == 0 { 0x02 } else { 0x03 };
    let mut compressed = [0u8; 33];
    compressed[0] = compressed_tag;
    compressed[1..].copy_from_slice(&uncompressed[1..33]);
    assert_eq!(SM2PublicKey::from_bytes(&compressed).unwrap(), pk);
}

#[test]
fn private_key_encode_round_trips_exact_bytes() {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x2A; // d = 42, well within [1, n-1]
    let sk = SM2PrivateKey::from_bytes(&bytes).unwrap();
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
    assert_ne!(format!("{pk1}"), format!("{pk2}"));
}

#[test]
fn private_key_rejects_zero() {
    match SM2PrivateKey::from_bytes(&[0u8; 32]) {
        Err(SignatureError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
}

/// `draft-shen-sm2-ecdsa-02` §4 puts `dA` in `[1, n-1]`, so an encoding of `n` or above is not a
/// key. Reducing such an encoding mod `n` rather than rejecting it would give one key many
/// valid-looking encodings: `dA = n + 1` would load as `dA = 1`.
#[test]
fn private_key_rejects_values_at_or_above_the_group_order() {
    let n = be_bytes_from_limbs(&N_LIMBS);

    let mut n_plus_1 = n;
    n_plus_1[31] += 1; // N_LIMBS[0] ends 0x23, so this never carries
    for (name, bytes) in [("n", n), ("n + 1", n_plus_1), ("2^256 - 1", [0xffu8; 32])] {
        match SM2PrivateKey::from_bytes(&bytes) {
            Err(SignatureError::DecodingError(_)) => {}
            other => panic!("dA = {name} should have been rejected, got {other:?}"),
        }
    }

    let mut n_minus_1 = n;
    n_minus_1[31] -= 1;
    let sk = SM2PrivateKey::from_bytes(&n_minus_1).expect("dA = n - 1 is in range");
    assert_eq!(sk.encode(), n_minus_1, "dA = n - 1 must round-trip unchanged");
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

    let (pk1, sk1) = bouncycastle_sm2::keys::keygen_from_rng(&mut FixedRng).unwrap();
    let (pk2, sk2) = bouncycastle_sm2::keys::keygen_from_rng(&mut FixedRng).unwrap();
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);
}

/// FIPS 186-5 Appendix A.2.1 step 3: an RNG weaker than the 128-bit security strength
/// SM2's order calls for (SP 800-57 Part 1 Rev. 5, Table 2) is refused rather than silently
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
        bouncycastle_sm2::keys::keygen_from_rng(&mut WeakRng),
        Err(SignatureError::RNGError(
            bouncycastle_core::errors::RNGError::SecurityStrengthInsufficientForAlgorithm
        ))
    ));
}

/// `draft-shen-sm2-ecdsa-02` §5.2.2 step B1: `r'` and `s'` must each be in `[1, n-1]`, rejected
/// rather than reduced. Each half of a valid signature is replaced in turn by `0`, by `n`, and by
/// the all-ones pattern; the untouched half stays valid, so only the range check can be what
/// rejects the result.
#[test]
fn verify_rejects_r_or_s_outside_1_to_n_minus_1() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"range-checked r and s";
    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();
    SM2::verify(&pk, msg, Some(ID), &sig).expect("the untampered signature must verify");

    let n = be_bytes_from_limbs(&N_LIMBS);
    for (name, bad) in [("0", [0u8; 32]), ("n", n), ("2^256 - 1", [0xffu8; 32])] {
        for (half, offset) in [("r", 0usize), ("s", 32usize)] {
            let mut tampered = sig;
            tampered[offset..offset + 32].copy_from_slice(&bad);
            match SM2::verify(&pk, msg, Some(ID), &tampered) {
                Err(SignatureError::SignatureVerificationFailed) => {}
                other => panic!("{half} = {name} should have been rejected, got {other:?}"),
            }
        }
    }
}

/// `draft-shen-sm2-ecdsa-02` §5.2.2 step B4: `t = (r' + s') mod n`, and `t = 0` fails verification
/// outright. `s' = n - r'` is in `[1, n-1]` (so it passes step B1) and is the one value that makes
/// `t` zero -- a signature that would otherwise reach the point multiplication with `[0]PA`.
#[test]
fn verify_rejects_s_equal_to_n_minus_r() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"t = r + s must not be zero";
    let sig = SM2::sign(&sk, msg, Some(ID)).unwrap();

    let r_limbs = bouncycastle_ec::sm2_sec1::limbs_from_be_bytes(&sig[..32].try_into().unwrap());
    let (n_minus_r, borrow) = bouncycastle_ec::nat::sub(&N_LIMBS, &r_limbs);
    assert_eq!(borrow, 0, "r is in [1, n-1], so n - r never borrows");

    let mut tampered = sig;
    tampered[32..].copy_from_slice(&be_bytes_from_limbs(&n_minus_r));
    match SM2::verify(&pk, msg, Some(ID), &tampered) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

/// `ZA` encodes `IDA`'s bit length as the two-byte `ENTLA` (§5.1.2), so an identity of 8191 bytes
/// (65528 bits) is the longest that fits and 8192 bytes (65536 bits) is the shortest that does
/// not. The limit applies on both sides, since verification computes `ZA` too.
#[test]
fn identity_longer_than_entla_can_encode_is_rejected() {
    let (pk, sk) = keygen().unwrap();
    let msg = b"message";

    let longest = vec![0x41u8; 8191];
    let sig = SM2::sign(&sk, msg, Some(&longest)).expect("8191 bytes fits in ENTLA");
    SM2::verify(&pk, msg, Some(&longest), &sig).unwrap();

    let too_long = vec![0x41u8; 8192];
    match SM2::sign(&sk, msg, Some(&too_long)) {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError on sign, got {other:?}"),
    }
    match SM2::verify(&pk, msg, Some(&too_long), &sig) {
        Err(SignatureError::GenericError(_)) => {}
        other => panic!("expected GenericError on verify, got {other:?}"),
    }
}
