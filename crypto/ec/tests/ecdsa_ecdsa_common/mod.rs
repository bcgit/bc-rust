//! The behavioural suite every curve's test file runs over its conventional pairing, written
//! once over `C: Curve` and `H: EcdsaHash`: the core framework conformance suites (per
//! QUALITY_AND_STYLE's rule that trait conformance lives there), key loading at its edges,
//! the two signers against one verifier, and the signature's range and length checks.

#![allow(dead_code)] // each test file calls the functions it needs

use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, RNGError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, CollisionResistantHash, PrivateKey, PublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle_core_test_framework::signature::{
    CtxBehaviour, TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_core_test_framework::{FailingRNG, ShortRNG};
use bouncycastle_ec::curve::Curve;
use bouncycastle_ec::ecdsa::ecdsa::ECDSA;
use bouncycastle_ec::ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ec::ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey, keygen, keygen_out};
use bouncycastle_ec::ecdsa::keys_common::SignatureKeyPair;
use bouncycastle_rng::DefaultRNG;

fn keygen_default<C: Curve, H: EcdsaHash + CollisionResistantHash>()
-> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError> {
    keygen::<C, H>(&mut DefaultRNG::default())
}

/// The framework suites over both signers and the key codecs, `pub_key` against `keygen`, and
/// the algorithm's names and strength. The random signer draws a fresh `k` per signature
/// (FIPS 186-5 Appendix A.3.1), so the suite expects two signatures of one message to differ;
/// the deterministic one reproduces `(r, s)` (RFC 6979 Sections 3.4 and 3.6). ECDSA has no
/// `ctx` input, so it refuses a non-empty one.
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
    H: EcdsaHash + CollisionResistantHash,
{
    let framework = TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Refused);
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
    assert_eq!(sk.pub_key().unwrap(), pk);

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
    H: EcdsaHash + CollisionResistantHash,
{
    let (pk, sk) = keygen_default::<C, H>().unwrap();
    let msg = b"one verifier for both kinds of k";
    let random =
        OneShotSigningKey::<ECDSA<C, H>, SIG_LEN>::sign(&sk, &mut DefaultRNG::default(), msg, None)
            .unwrap();
    let again =
        OneShotSigningKey::<ECDSA<C, H>, SIG_LEN>::sign(&sk, &mut DefaultRNG::default(), msg, None)
            .unwrap();
    assert_ne!(random, again, "Appendix A.3.1's k comes from fresh randomness each call");
    let deterministic =
        DeterministicOneShotSigningKey::<ECDSA<C, H>, SIG_LEN>::sign_deterministic(&sk, msg, None)
            .unwrap();
    for sig in [&random, &again, &deterministic] {
        OneShotVerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, sig).unwrap();
    }

    let (other_pk, _) = keygen_default::<C, H>().unwrap();
    match OneShotVerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&other_pk, msg, None, &random) {
        Err(SignatureError::SignatureVerificationFailed) => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

/// ECDSA has no context input (FIPS 186-5 Sections 6.4.1 and 6.4.2 list none): the absent and
/// the empty context are the same, and a non-empty one is a `LengthError` from both signers and
/// the verifier, one-shot and streaming, whatever else is true of the call.
pub fn context_is_refused<C, H, const SIG_LEN: usize>()
where
    C: Curve<Signature = [u8; SIG_LEN]>,
    H: EcdsaHash + CollisionResistantHash,
{
    fn refused<T>(result: Result<T, SignatureError>) -> bool {
        matches!(result, Err(SignatureError::LengthError("ECDSA takes no context")))
    }

    let (pk, sk) = keygen_default::<C, H>().unwrap();
    let mut rng = DefaultRNG::default();
    let msg = b"no context to bind";
    let empty = Some(&[][..]);

    // Absent and empty: the deterministic signature is the same, and both signers' verify.
    let deterministic = sk.sign_deterministic(msg, None).unwrap();
    assert_eq!(sk.sign_deterministic(msg, empty).unwrap(), deterministic);
    let random = sk.sign(&mut rng, msg, empty).unwrap();
    for sig in [&deterministic, &random] {
        pk.verify(msg, None, sig).unwrap();
        pk.verify(msg, empty, sig).unwrap();
    }
    let mut signer = sk.create_signer(&mut rng, empty).unwrap();
    signer.do_update(msg);
    let streamed = signer.do_final().unwrap();
    let mut signer = sk.create_signer_deterministic(empty).unwrap();
    signer.do_update(msg);
    assert_eq!(signer.do_final().unwrap(), deterministic);
    let mut verifier = pk.create_verifier(empty).unwrap();
    verifier.do_update(msg);
    verifier.do_verify_final(&streamed).unwrap();

    for ctx in [&b"c"[..], &[0u8; 256]] {
        let ctx = Some(ctx);

        // The random signer, which leaves zeros in the caller's buffer and draws nothing: the
        // refusal comes before the RNG's own failure.
        let mut out = [0xA5u8; SIG_LEN];
        assert!(refused(sk.sign_out(&mut rng, msg, ctx, &mut out)));
        assert_eq!(out, [0u8; SIG_LEN]);
        assert!(refused(sk.sign(&mut rng, msg, ctx)));
        assert!(refused(sk.sign(&mut FailingRNG, msg, ctx)));
        assert!(refused(sk.create_signer(&mut rng, ctx)));

        // The RFC 6979 signer.
        let mut out = [0xA5u8; SIG_LEN];
        assert!(refused(sk.sign_deterministic_out(msg, ctx, &mut out)));
        assert_eq!(out, [0u8; SIG_LEN]);
        assert!(refused(sk.sign_deterministic(msg, ctx)));
        assert!(refused(sk.create_signer_deterministic(ctx)));

        // The verifier, over a signature that is good without the context, and over one of
        // the wrong length.
        assert!(refused(pk.verify(msg, ctx, &deterministic)));
        assert!(refused(pk.verify(msg, ctx, &random)));
        assert!(refused(pk.verify(msg, ctx, &deterministic[..SIG_LEN - 1])));
        assert!(refused(pk.create_verifier(ctx)));
    }
}

/// The codecs' edges: both SEC 1 point encodings decode to the same key and `encode` emits the
/// uncompressed form; `encode_out` matches `encode` for both keys; a private key is refused at
/// `0`, at `n` and above (FIPS 186-5 Section 6.2 puts `d` in `[1, n-1]`, and reducing instead
/// of rejecting would give one key unboundedly many encodings), and `n - 1` loads.
pub fn key_loading<C, H, const PK_LEN: usize, const SK_LEN: usize>()
where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN]>,
    H: EcdsaHash + CollisionResistantHash,
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
        Err(KeyDecodingError(_)) => {}
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
        Err(KeyDecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
    let n = C::be_bytes_from_limbs(&C::N);
    let mut n_plus_1 = n;
    n_plus_1[SK_LEN - 1] += 1; // n is odd, so no carry
    for (name, bad) in [("n", n), ("n + 1", n_plus_1), ("all ones", [0xffu8; SK_LEN])] {
        match ECDSAPrivateKey::<C, H>::from_bytes(&bad) {
            Err(KeyDecodingError(_)) => {}
            other => panic!("d = {name} should have been rejected, got {other:?}"),
        }
    }
    match ECDSAPrivateKey::<C, H>::from_bytes(&n[..SK_LEN - 1]) {
        Err(KeyDecodingError(_)) => {}
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
    H: EcdsaHash + CollisionResistantHash,
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
    assert_eq!(sk.pub_key().unwrap(), pk);

    let (pk1, sk1) = keygen::<C, H>(&mut FixedSeedRNG::new(seed)).unwrap();
    let (pk2, sk2) = keygen::<C, H>(&mut FixedSeedRNG::new(seed)).unwrap();
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);

    // A draw that comes back short is the RNG failing, refused rather than reduced.
    assert!(matches!(
        keygen::<C, H>(&mut ShortRNG),
        Err(SignatureError::RNGError(RNGError::GenericError(_)))
    ));
}

/// The random signer's `k` from a draw that comes back short is refused, by every way of
/// signing that draws one, and `sign_out` leaves its output zeroized.
pub fn short_draw_is_refused<C, H, const SIG_LEN: usize>()
where
    C: Curve<Signature = [u8; SIG_LEN]>,
    H: EcdsaHash + CollisionResistantHash,
{
    let short = |r: Result<(), SignatureError>| {
        matches!(r, Err(SignatureError::RNGError(RNGError::GenericError(_))))
    };
    let (_, sk) = keygen_default::<C, H>().unwrap();
    let msg = b"short draw";
    assert!(short(sk.create_signer(&mut ShortRNG, None).map(|_| ())));
    assert!(short(sk.sign(&mut ShortRNG, msg, None).map(|_| ())));
    let mut out = [0xA5u8; SIG_LEN];
    assert!(short(sk.sign_out(&mut ShortRNG, msg, None, &mut out).map(|_| ())));
    assert_eq!(out, [0u8; SIG_LEN]);
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
    H: EcdsaHash + CollisionResistantHash,
{
    let (pk, sk) = keygen_default::<C, H>().unwrap();
    let msg = b"length-checked, range-checked signature";
    let sig =
        OneShotSigningKey::<ECDSA<C, H>, SIG_LEN>::sign(&sk, &mut DefaultRNG::default(), msg, None)
            .unwrap();
    OneShotVerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &sig)
        .expect("the untampered signature must verify");

    for extra in 1..=3 {
        let mut too_long = sig.to_vec();
        too_long.extend(core::iter::repeat_n(0xAAu8, extra));
        match OneShotVerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &too_long) {
            Err(SignatureError::LengthError(_)) => {}
            other => panic!("{extra} trailing byte(s) should have failed, got {other:?}"),
        }
    }
    for short in 1..=3 {
        match OneShotVerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(
            &pk,
            msg,
            None,
            &sig[..SIG_LEN - short],
        ) {
            Err(SignatureError::LengthError(_)) => {}
            other => panic!("{short} byte(s) short should have failed, got {other:?}"),
        }
    }

    let n = C::be_bytes_from_limbs(&C::N);
    for (name, bad) in [("0", [0u8; SK_LEN]), ("n", n), ("all ones", [0xffu8; SK_LEN])] {
        for (half, offset) in [("r", 0usize), ("s", SK_LEN)] {
            let mut tampered = sig;
            tampered[offset..offset + SK_LEN].copy_from_slice(&bad);
            match OneShotVerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(&pk, msg, None, &tampered) {
                Err(SignatureError::SignatureVerificationFailed) => {}
                other => panic!("{half} = {name} should have been rejected, got {other:?}"),
            }
        }
    }
}

fn keygen_out_default<C, H, const PK_LEN: usize>()
-> Result<(ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>), SignatureError>
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
    H: EcdsaHash + CollisionResistantHash,
{
    let mut sk = ECDSAPrivateKey::zeroized();
    keygen_out::<C, H>(&mut DefaultRNG::default(), &mut sk)?;
    Ok((sk.pub_key()?, sk))
}

/// `keygen_out`: the key it fills runs the framework suites; it is the key `keygen` and the
/// marker give from the same RNG output, and the marker's `generate_signature_key_out` is it;
/// it clears a key it is handed and leaves it cleared on every error (a weak, a short and a
/// failing RNG); and a key it never filled has no public key and signs nothing.
pub fn keygen_out_suite<C, H, const PK_LEN: usize, const SK_LEN: usize, const SIG_LEN: usize>(
    below: SecurityStrength,
) where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN], Signature = [u8; SIG_LEN]>
        + SignatureKeyPair,
    H: EcdsaHash + CollisionResistantHash,
{
    let framework = TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Refused);
    framework.test_signature::<ECDSA<C, H>, ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>, SIG_LEN>(
        keygen_out_default::<C, H, PK_LEN>,
        false,
    );
    framework
        .test_deterministic_signature::<ECDSA<C, H>, ECDSAPublicKey<C, H>, ECDSAPrivateKey<C, H>, SIG_LEN>(
            keygen_out_default::<C, H, PK_LEN>,
            false,
        );

    let seed = core::array::from_fn::<u8, 128, _>(|i| i as u8);
    let (pk, expected) = keygen::<C, H>(&mut FixedSeedRNG::new(seed)).unwrap();
    let mut sk = ECDSAPrivateKey::<C, H>::zeroized();
    keygen_out::<C, H>(&mut FixedSeedRNG::new(seed), &mut sk).unwrap();
    assert!(sk == expected, "keygen_out is keygen's key for the same RNG output");
    assert_eq!(sk.pub_key().unwrap(), pk);
    let mut from_marker = ECDSAPrivateKey::<C, H>::zeroized();
    C::generate_signature_key_out::<H>(&mut FixedSeedRNG::new(seed), &mut from_marker).unwrap();
    assert!(from_marker == expected);
    let other_seed = core::array::from_fn::<u8, 128, _>(|i| (i as u8).wrapping_mul(7));
    keygen_out::<C, H>(&mut FixedSeedRNG::new(other_seed), &mut from_marker).unwrap();
    assert!(from_marker != expected, "a filled key is overwritten");

    // Every error clears the key it was handed, filled or not.
    let zero = ECDSAPrivateKey::<C, H>::zeroized();
    let mut weak = FixedSeedRNG::new(seed);
    weak.set_security_strength(below);
    assert!(matches!(
        keygen_out::<C, H>(&mut weak, &mut sk),
        Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
    assert!(sk == zero);
    sk = expected.clone();
    assert!(matches!(
        C::generate_signature_key_out::<H>(&mut ShortRNG, &mut sk),
        Err(SignatureError::RNGError(RNGError::GenericError(_)))
    ));
    assert!(sk == zero);
    sk = expected.clone();
    assert!(keygen_out::<C, H>(&mut FailingRNG, &mut sk).is_err());
    assert!(sk == zero);

    // The unfilled key: equal only to another, encoded as zeros, refused by every role.
    let refused = |r: Result<(), SignatureError>| {
        matches!(r, Err(SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey)))
    };
    assert!(zero == ECDSAPrivateKey::<C, H>::zeroized());
    assert!(zero != expected);
    assert!(zero.encode().as_ref().iter().all(|b| *b == 0));
    assert!(zero.clone() == zero);
    assert!(refused(zero.pub_key().map(|_| ())));
    let mut rng = FixedSeedRNG::new(seed);
    let msg = b"from a key that was never filled";
    assert!(refused(zero.create_signer(&mut rng, None).map(|_| ())));
    assert!(refused(zero.sign(&mut rng, msg, None).map(|_| ())));
    let mut out = [0xA5u8; SIG_LEN];
    assert!(refused(zero.sign_out(&mut rng, msg, None, &mut out).map(|_| ())));
    assert_eq!(out, [0u8; SIG_LEN]);
    assert!(refused(zero.create_signer_deterministic(None).map(|_| ())));
    assert!(refused(zero.sign_deterministic(msg, None).map(|_| ())));
    assert!(refused(zero.with_hash::<H>().pub_key().map(|_| ())));
}
