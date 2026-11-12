//! The behavioural suite every curve's test file runs over its conventional pairing, written
//! once over `C: Curve` and `H: EcdsaHash`: the core framework conformance suites (per
//! QUALITY_AND_STYLE's rule that trait conformance lives there), key loading at its edges,
//! the two signers against one verifier, and the signature's range and length checks.

#![allow(dead_code)] // each test file calls the functions it needs

use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
use bouncycastle_core::traits::{Algorithm, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_ec::curve::Curve;
use bouncycastle_ecdsa::ecdsa::ECDSA;
use bouncycastle_ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey, keygen};
use bouncycastle_ecdsa::keys_common::DerivePublicKey;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};

fn keygen_default<C: Curve, H: EcdsaHash>()
-> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError> {
    keygen::<C, H>(&mut DefaultRNG::default())
}

/// The framework suites over both signers and the key codecs, `derive_pk` against `keygen`, and
/// the algorithm's names and strength. The random signer draws a fresh `k` per signature
/// (FIPS 186-5 Appendix A.3.1), so the suite expects two signatures of one message to differ;
/// the deterministic one reproduces `(r, s)` (RFC 6979 Sections 3.4 and 3.6). ECDSA has no
/// `ctx` input, so it ignores the one the traits offer.
pub fn framework_and_metadata<
    C,
    H,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    alg_name: &str,
    deterministic_alg_name: &str,
    strength: SecurityStrength,
) where
    C: Curve
        + Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN], Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    let framework = TestFrameworkSignature::new(false);
    framework.test_signature::<ECDSA<C, H>, ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>, SIG_LEN>(
        keygen_default::<C, H>, true,
    );
    framework
        .test_deterministic_signature::<ECDSA<C, H>, ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>, SIG_LEN>(
            keygen_default::<C, H>,
            true,
        );
    TestFrameworkSignatureKeys::new()
        .test_keys::<ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>, PK_LEN, SK_LEN>(
            keygen_default::<C, H>,
        );

    let (pk, sk) = keygen_default::<C, H>().unwrap();
    assert_eq!(sk.derive_pk(), pk);

    assert_eq!(ECDSA::<C, H>::ALG_NAME, alg_name);
    assert_eq!(ECDSA::<C, H>::DETERMINISTIC_ALG_NAME, deterministic_alg_name);
    assert_eq!(ECDSA::<C, H>::MAX_SECURITY_STRENGTH, strength);
    assert_eq!(SIG_LEN, C::SIG_LEN);
    assert_eq!(PK_LEN, C::PK_UNCOMPRESSED_LEN);
    assert_eq!(SK_LEN, C::SCALAR_LEN);
    assert!(format!("{pk}").starts_with(&format!("ECDSAPublicKey<{}, {}>", C::NAME, H::ALG_NAME)));
    let (pk2, _) = keygen_default::<C, H>().unwrap();
    assert_ne!(format!("{pk}"), format!("{pk2}"), "Display reflects the key bytes");
}

/// FIPS 186-5 Section 6: Deterministic ECDSA "does not impact the signature verification
/// process", so either signer's signature verifies under the one verifier, two random
/// signatures of one message differ and both verify, and a signature fails under another key.
pub fn two_signers_one_verifier<C, H, const SIG_LEN: usize>()
where
    C: Curve<Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    let (pk, sk) = keygen_default::<C, H>().unwrap();
    let msg = b"one verifier for both kinds of k";
    let random =
        SigningKey::<ECDSA<C, H>, SIG_LEN>::sign(&sk, &mut DefaultRNG::default(), msg, None)
            .unwrap();
    let again =
        SigningKey::<ECDSA<C, H>, SIG_LEN>::sign(&sk, &mut DefaultRNG::default(), msg, None)
            .unwrap();
    assert_ne!(random, again, "Appendix A.3.1's k comes from fresh randomness each call");
    let deterministic =
        DeterministicSigningKey::<ECDSA<C, H>, SIG_LEN>::sign_deterministic(&sk, msg, None)
            .unwrap();
    for sig in [&random, &again, &deterministic] {
        VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, sig).unwrap();
    }

    let (other_pk, _) = keygen_default::<C, H>().unwrap();
    match VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&other_pk, msg, None, &random) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

/// The codecs' edges: both SEC 1 point encodings decode to the same key and `encode` emits the
/// uncompressed form; `encode_out` matches `encode` for both keys; a private key is refused at
/// `0`, at `n` and above (FIPS 186-5 Section 6.2 puts `d` in `[1, n-1]`, and reducing instead
/// of rejecting would give one key unboundedly many encodings), and `n - 1` loads.
pub fn key_loading<C, H, const PK_LEN: usize, const SK_LEN: usize>()
where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN]>,
    H: EcdsaHash,
{
    let (pk, _) = keygen_default::<C, H>().unwrap();
    let uncompressed = pk.encode();
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(ECDSAPublicKey::<C, H>::from_bytes(&uncompressed).unwrap(), pk);
    let compressed = {
        let (x, y) = C::decode(&uncompressed).unwrap();
        C::encode_compressed(&x, &y)
    };
    assert_eq!(ECDSAPublicKey::<C, H>::from_bytes(compressed.as_ref()).unwrap(), pk);
    let mut out = [0xFFu8; PK_LEN];
    assert_eq!(pk.encode_out(&mut out), PK_LEN);
    assert_eq!(out, uncompressed);
    let mut off_curve = uncompressed;
    off_curve[PK_LEN - 1] ^= 1;
    match ECDSAPublicKey::<C, H>::from_bytes(&off_curve) {
        Err(SignatureError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }

    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A; // d = 42, well within [1, n-1]
    let sk = ECDSAPrivateKey::<C, H>::from_bytes(&bytes).unwrap();
    assert_eq!(sk.encode(), bytes);
    let mut out = [0xFFu8; SK_LEN];
    assert_eq!(sk.encode_out(&mut out), SK_LEN);
    assert_eq!(out, bytes);

    match ECDSAPrivateKey::<C, H>::from_bytes(&[0u8; SK_LEN]) {
        Err(SignatureError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
    let n = C::be_bytes_from_limbs(&C::N);
    let mut n_plus_1 = n;
    n_plus_1[SK_LEN - 1] += 1; // n is odd, so no carry
    for (name, bad) in [("n", n), ("n + 1", n_plus_1), ("all ones", [0xffu8; SK_LEN])] {
        match ECDSAPrivateKey::<C, H>::from_bytes(&bad) {
            Err(SignatureError::DecodingError(_)) => {}
            other => panic!("d = {name} should have been rejected, got {other:?}"),
        }
    }
    match ECDSAPrivateKey::<C, H>::from_bytes(&n[..SK_LEN - 1]) {
        Err(SignatureError::DecodingError(_)) => {}
        other => panic!("a short encoding should have been rejected, got {other:?}"),
    }
    let mut n_minus_1 = n;
    n_minus_1[SK_LEN - 1] -= 1;
    let sk = ECDSAPrivateKey::<C, H>::from_bytes(&n_minus_1).expect("d = n - 1 is in range");
    assert_eq!(sk.encode(), n_minus_1, "d = n - 1 must round-trip unchanged");
}

/// FIPS 186-5 Appendix A.2.1 step 3: an RNG weaker than the strength the curve's order calls
/// for (SP 800-57 Part 1 Rev. 5 Table 2) is refused; one at exactly that strength is taken; and
/// key generation is a function of the DRBG output alone.
pub fn rng_rules<C, H, const PK_LEN: usize>(strength: SecurityStrength, below: SecurityStrength)
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
    H: EcdsaHash,
{
    let mut weak = FixedSeedRNG::new([0x42u8; 96]);
    weak.set_security_strength(below);
    assert!(matches!(
        keygen::<C, H>(&mut weak),
        Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));

    let seed = core::array::from_fn::<u8, 128, _>(|i| i as u8);
    let mut rng = FixedSeedRNG::new(seed);
    rng.set_security_strength(strength);
    let (pk, sk) = keygen::<C, H>(&mut rng).unwrap();
    assert_eq!(sk.derive_pk(), pk);

    let (pk1, sk1) = keygen::<C, H>(&mut FixedSeedRNG::new(seed)).unwrap();
    let (pk2, sk2) = keygen::<C, H>(&mut FixedSeedRNG::new(seed)).unwrap();
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);
}

/// The raw encoding is exactly `r || s`; anything longer or shorter is a different, malformed
/// encoding, not a signature in a roomy buffer (accepting trailing bytes would turn one valid
/// signature into unlimited distinct byte strings that all verify). And FIPS 186-5 Section 6.4.2
/// step 1: `r` and `s` must each be in `[1, n-1]`, rejected rather than reduced; each half of a
/// valid signature is replaced in turn by `0`, by `n` and by all ones, so only the range check
/// can be what rejects the result.
pub fn signature_length_and_range<C, H, const SK_LEN: usize, const SIG_LEN: usize>()
where
    C: Curve<ScalarBytes = [u8; SK_LEN], Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    let (pk, sk) = keygen_default::<C, H>().unwrap();
    let msg = b"length-checked, range-checked signature";
    let sig = SigningKey::<ECDSA<C, H>, SIG_LEN>::sign(&sk, &mut DefaultRNG::default(), msg, None)
        .unwrap();
    VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &sig)
        .expect("the untampered signature must verify");

    for extra in 1..=3 {
        let mut too_long = sig.to_vec();
        too_long.extend(core::iter::repeat_n(0xAAu8, extra));
        match VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &too_long) {
            Err(SignatureError::LengthError(_)) => {}
            other => panic!("{extra} trailing byte(s) should have failed, got {other:?}"),
        }
    }
    for short in 1..=3 {
        match VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &sig[..SIG_LEN - short])
        {
            Err(SignatureError::LengthError(_)) => {}
            other => panic!("{short} byte(s) short should have failed, got {other:?}"),
        }
    }

    let n = C::be_bytes_from_limbs(&C::N);
    for (name, bad) in [("0", [0u8; SK_LEN]), ("n", n), ("all ones", [0xffu8; SK_LEN])] {
        for (half, offset) in [("r", 0usize), ("s", SK_LEN)] {
            let mut tampered = sig;
            tampered[offset..offset + SK_LEN].copy_from_slice(&bad);
            match VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &tampered) {
                Err(SignatureError::SignatureVerificationFailed) => {}
                other => panic!("{half} = {name} should have been rejected, got {other:?}"),
            }
        }
    }
}
