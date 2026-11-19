//! Ed25519 and Ed25519ph on the signature roles: the core test framework's suites, and what
//! is particular to the two algorithms.

use bouncycastle_core::errors::{KeyMaterialError, SignatureError};
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
};
use bouncycastle_core::traits::{Hash, PrivateKey, SignatureSigner, SignatureVerifier};
use bouncycastle_core_test_framework::signature::{CtxBehaviour, TestFrameworkSignature};
use bouncycastle_ed::ed25519::{
    CONTEXT_MAX_LEN, ED25519_NAME, ED25519PH_NAME, Ed25519, Ed25519PrivateKey, Ed25519PublicKey,
    Ed25519ph, SIGNATURE_LEN, keygen,
};
use bouncycastle_rng::FixedSeedRNG;
use bouncycastle_sha2::SHA512;

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";
const FAILED: Result<(), SignatureError> = Err(SignatureError::SignatureVerificationFailed);
const ZEROIZED: SignatureError =
    SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

/// The group order L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032 Table 1) in
/// 32 little-endian octets, computed from that expression by script.
const L: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

fn key_pair() -> Result<(Ed25519PublicKey, Ed25519PrivateKey), SignatureError> {
    keygen(&mut FixedSeedRNG::new(core::array::from_fn::<u8, 64, _>(|i| i as u8)))
}

fn sign(sk: &Ed25519PrivateKey, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    DeterministicOneShotSigningKey::<Ed25519, _>::sign_deterministic(sk, msg, None).unwrap()
}

fn verify(pk: &Ed25519PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    OneShotVerifyingKey::<Ed25519, _>::verify(pk, msg, None, sig)
}

fn sign_ph(sk: &Ed25519PrivateKey, msg: &[u8], ctx: Option<&[u8]>) -> [u8; SIGNATURE_LEN] {
    DeterministicOneShotSigningKey::<Ed25519ph, _>::sign_deterministic(sk, msg, ctx).unwrap()
}

fn verify_ph(
    pk: &Ed25519PublicKey,
    msg: &[u8],
    ctx: Option<&[u8]>,
    sig: &[u8],
) -> Result<(), SignatureError> {
    OneShotVerifyingKey::<Ed25519ph, _>::verify(pk, msg, ctx, sig)
}

fn is_length_error<T>(result: Result<T, SignatureError>) -> bool {
    matches!(result, Err(SignatureError::LengthError(_)))
}

/// Ed25519 has the one-shot roles alone and refuses a context.
#[test]
fn ed25519_core_framework() {
    TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Refused)
        .test_deterministic_one_shot_signature::<Ed25519, _, _, SIGNATURE_LEN>(key_pair, true);
}

/// Ed25519ph streams and binds its context; the framework's long context is 256 octets, one
/// more than [`CONTEXT_MAX_LEN`].
#[test]
fn ed25519ph_core_framework() {
    let tf = TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Bound);
    tf.test_deterministic_signature::<Ed25519ph, _, _, SIGNATURE_LEN>(key_pair, true);
    tf.test_deterministic_one_shot_signature::<Ed25519ph, _, _, SIGNATURE_LEN>(key_pair, false);
}

#[test]
fn the_markers_and_workers_name_their_algorithm() {
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Algorithm, AlgorithmInfo};
    assert_eq!((Ed25519::ALG_NAME, ED25519_NAME), ("Ed25519", "Ed25519"));
    assert_eq!((Ed25519ph::ALG_NAME, ED25519PH_NAME), ("Ed25519ph", "Ed25519ph"));
    assert_eq!(Ed25519::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(Ed25519ph::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);

    // id-Ed25519, RFC 8410 Section 3: { 1 3 101 112 }; the encoding is the one inside the
    // RFC's example public key (Section 10.1), `30 2a 30 05 06 03 2b 65 70 ...`.
    use bouncycastle_core::traits::AlgorithmOID;
    assert_eq!(<Ed25519 as AlgorithmOID>::OID, &[1, 3, 101, 112]);
    assert_eq!(<Ed25519 as AlgorithmOID>::OID_DER, &[0x06, 0x03, 0x2b, 0x65, 0x70]);

    let (pk, sk) = key_pair().unwrap();
    let signer = sk.create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "Ed25519ph");
    assert_eq!(signer.max_security_strength(), SecurityStrength::_128bit);
    let verifier = pk.create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "Ed25519ph");
    assert_eq!(verifier.max_security_strength(), SecurityStrength::_128bit);
}

#[test]
fn signing_is_deterministic() {
    let (_, sk) = key_pair().unwrap();
    assert_eq!(sign(&sk, MSG), sign(&sk, MSG));
    assert_eq!(sign_ph(&sk, MSG, Some(b"ctx")), sign_ph(&sk, MSG, Some(b"ctx")));
    assert_ne!(sign(&sk, MSG), sign(&sk, &MSG[1..]));
}

/// The wrong message, the wrong key, and a signature whose `R` or `S` half was changed.
#[test]
fn ed25519_rejects_what_was_not_signed() {
    let (pk, sk) = key_pair().unwrap();
    let sig = sign(&sk, MSG);
    assert_eq!(verify(&pk, MSG, &sig), Ok(()));

    assert_eq!(verify(&pk, &MSG[1..], &sig), FAILED);
    assert_eq!(verify(&pk, b"", &sig), FAILED);

    let other = Ed25519PrivateKey::from_bytes(&[3; 32]).unwrap().pk().unwrap();
    assert_eq!(verify(&other, MSG, &sig), FAILED);

    for i in [0, 31, 32, 63] {
        let mut tampered = sig;
        tampered[i] ^= 1;
        assert_eq!(verify(&pk, MSG, &tampered), FAILED, "octet {i}");
    }
    // The two halves of two good signatures do not combine.
    let other_sig = sign(&sk, b"another message");
    let mut mixed = sig;
    mixed[32..].copy_from_slice(&other_sig[32..]);
    assert_eq!(verify(&pk, MSG, &mixed), FAILED);
}

/// RFC 8032 Section 5.1.7, step 1: "If any of the decodings fail (including S being out of
/// range), the signature is invalid." `S + L` is `S` mod L and fits 32 octets.
#[test]
fn s_not_below_the_group_order_is_rejected() {
    let (pk, sk) = key_pair().unwrap();
    let l = bouncycastle_hex::decode(L).unwrap();
    for (name, sig) in [("Ed25519", sign(&sk, MSG)), ("Ed25519ph", sign_ph(&sk, MSG, None))] {
        let mut malleated = sig;
        let mut carry = 0u16;
        for (s, l) in malleated[32..].iter_mut().zip(&l) {
            carry += u16::from(*s) + u16::from(*l);
            *s = carry as u8;
            carry >>= 8;
        }
        assert_eq!(carry, 0);
        assert_ne!(malleated, sig);
        let verdict = if name == "Ed25519" {
            verify(&pk, MSG, &malleated)
        } else {
            verify_ph(&pk, MSG, None, &malleated)
        };
        assert_eq!(verdict, FAILED, "{name}");

        // S = L itself, and S of all ones.
        let mut s_is_l = sig;
        s_is_l[32..].copy_from_slice(&l);
        assert_eq!(verify(&pk, MSG, &s_is_l), FAILED, "{name}");
        let mut s_is_max = sig;
        s_is_max[32..].fill(0xFF);
        assert_eq!(verify(&pk, MSG, &s_is_max), FAILED, "{name}");
    }
}

/// The two algorithms give different signatures of one message under one key, and neither
/// verifies as the other, over the message or over its SHA-512 digest.
#[test]
fn ed25519_and_ed25519ph_do_not_cross_verify() {
    let (pk, sk) = key_pair().unwrap();
    let mut digest = [0u8; 64];
    let mut hash = SHA512::new();
    hash.do_update(MSG);
    hash.do_final_out(&mut digest);

    let pure = sign(&sk, MSG);
    let ph = sign_ph(&sk, MSG, None);
    assert_ne!(pure, ph);

    assert_eq!(verify(&pk, MSG, &pure), Ok(()));
    assert_eq!(verify_ph(&pk, MSG, None, &ph), Ok(()));
    assert_eq!(verify(&pk, MSG, &ph), FAILED);
    assert_eq!(verify(&pk, &digest, &ph), FAILED);
    assert_eq!(verify_ph(&pk, MSG, None, &pure), FAILED);
    assert_eq!(verify_ph(&pk, MSG, None, &sign(&sk, &digest)), FAILED);
}

/// RFC 8032 Section 5.1, of Ed25519: "The context (if present at all) MUST be empty."
#[test]
fn ed25519_takes_no_context() {
    let (pk, sk) = key_pair().unwrap();
    let sig = sign(&sk, MSG);
    let empty = Some(&[][..]);
    assert_eq!(
        DeterministicOneShotSigningKey::<Ed25519, _>::sign_deterministic(&sk, MSG, empty),
        Ok(sig)
    );
    assert_eq!(OneShotVerifyingKey::<Ed25519, _>::verify(&pk, MSG, empty, &sig), Ok(()));

    for ctx in [&b"c"[..], &[0u8; 256]] {
        let mut out = [0xA5u8; SIGNATURE_LEN];
        assert!(is_length_error(
            DeterministicOneShotSigningKey::<Ed25519, _>::sign_deterministic_out(
                &sk,
                MSG,
                Some(ctx),
                &mut out
            )
        ));
        assert_eq!(out, [0u8; SIGNATURE_LEN]);
        assert!(is_length_error(OneShotVerifyingKey::<Ed25519, _>::verify(
            &pk,
            MSG,
            Some(ctx),
            &sig
        )));
    }
    // A signature of the wrong length is a length error, not a failed verification.
    assert!(is_length_error(verify(&pk, MSG, &sig[..63])));
    assert!(is_length_error(verify(&pk, MSG, &[])));
}

/// The Ed25519ph context: none is the empty one, the context is bound octet for octet, and
/// 255 octets is the longest (RFC 8032 Section 5.1: "maximum of 255 octets").
#[test]
fn the_ed25519ph_context() {
    let (pk, sk) = key_pair().unwrap();

    let sig = sign_ph(&sk, MSG, None);
    assert_eq!(sig, sign_ph(&sk, MSG, Some(&[])));
    let mut signer = sk.create_signer_deterministic(Some(&[])).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    assert_eq!(verify_ph(&pk, MSG, Some(&[]), &sig), Ok(()));

    let sig = sign_ph(&sk, MSG, Some(b"context"));
    assert_eq!(verify_ph(&pk, MSG, Some(b"context"), &sig), Ok(()));
    assert_eq!(verify_ph(&pk, MSG, Some(b"contexu"), &sig), FAILED);
    assert_eq!(verify_ph(&pk, MSG, Some(b"context\0"), &sig), FAILED);
    assert_eq!(verify_ph(&pk, MSG, Some(b"contex"), &sig), FAILED);
    assert_eq!(verify_ph(&pk, MSG, None, &sig), FAILED);

    assert_eq!(CONTEXT_MAX_LEN, 255);
    let long = [0x5Au8; CONTEXT_MAX_LEN + 1];
    let longest = &long[..CONTEXT_MAX_LEN];
    let sig = sign_ph(&sk, MSG, Some(longest));
    assert_eq!(verify_ph(&pk, MSG, Some(longest), &sig), Ok(()));
    assert_eq!(verify_ph(&pk, MSG, Some(&long[..CONTEXT_MAX_LEN - 1]), &sig), FAILED);
    let mut signer = sk.create_signer_deterministic(Some(longest)).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    let mut verifier = pk.create_verifier(Some(longest)).unwrap();
    verifier.do_update(MSG);
    assert_eq!(verifier.do_verify_final(&sig), Ok(()));

    assert!(is_length_error(sk.create_signer_deterministic(Some(&long))));
    assert!(is_length_error(pk.create_verifier(Some(&long))));
    assert!(is_length_error(verify_ph(&pk, MSG, Some(&long), &sig)));
    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert!(is_length_error(
        DeterministicOneShotSigningKey::<Ed25519ph, _>::sign_deterministic_out(
            &sk,
            MSG,
            Some(&long),
            &mut out
        )
    ));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
}

/// A streamed message is the same message however it is cut, and the streaming verifier
/// reports a signature of the wrong length as one.
#[test]
fn ed25519ph_streaming() {
    let (pk, sk) = key_pair().unwrap();
    let msg: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    let sig = sign_ph(&sk, &msg, Some(b"ctx"));
    for size in [1, 63, 64, 128, 129, 999, 1000] {
        let mut signer = sk.create_signer_deterministic(Some(b"ctx")).unwrap();
        let mut verifier = pk.create_verifier(Some(b"ctx")).unwrap();
        for chunk in msg.chunks(size) {
            signer.do_update(chunk);
            verifier.do_update(chunk);
        }
        let mut out = [0xA5u8; SIGNATURE_LEN];
        assert_eq!(signer.do_final_out(&mut out), Ok(SIGNATURE_LEN));
        assert_eq!(out, sig, "chunks of {size}");
        assert_eq!(verifier.do_verify_final(&sig), Ok(()));
    }
    // Nothing fed is the empty message.
    let signer = sk.create_signer_deterministic(None).unwrap();
    assert_eq!(signer.do_final().unwrap(), sign_ph(&sk, b"", None));

    let mut verifier = pk.create_verifier(Some(b"ctx")).unwrap();
    verifier.do_update(&msg);
    assert!(is_length_error(verifier.do_verify_final(&sig[..63])));
    let mut verifier = pk.create_verifier(Some(b"ctx")).unwrap();
    verifier.do_update(&msg[1..]);
    assert_eq!(verifier.do_verify_final(&sig), FAILED);
}

/// A key that was never filled signs nothing, under either algorithm, and leaves zeros in
/// the caller's buffer.
#[test]
fn an_unfilled_key_does_not_sign() {
    let sk = Ed25519PrivateKey::zeroized();
    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert_eq!(
        DeterministicOneShotSigningKey::<Ed25519, _>::sign_deterministic_out(
            &sk, MSG, None, &mut out
        ),
        Err(ZEROIZED)
    );
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    assert_eq!(
        DeterministicOneShotSigningKey::<Ed25519, _>::sign_deterministic(&sk, MSG, None),
        Err(ZEROIZED)
    );

    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert_eq!(
        DeterministicOneShotSigningKey::<Ed25519ph, _>::sign_deterministic_out(
            &sk, MSG, None, &mut out
        ),
        Err(ZEROIZED)
    );
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    assert!(matches!(sk.create_signer_deterministic(None), Err(ZEROIZED)));
}
