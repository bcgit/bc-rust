//! Ed25519 and Ed25519ph on the signature roles: the core test framework's suites, and what
//! is particular to the two algorithms.

use bouncycastle_core::errors::{KeyMaterialError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey,
    SignatureAlgorithm, VerifyingKey,
};
use bouncycastle_core::traits::{Hash, PrivateKey, PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle_core_test_framework::signature::{CtxBehaviour, TestFrameworkSignature};
use bouncycastle_digest::sha2::SHA512;
use bouncycastle_ed::ed25519::{
    CONTEXT_MAX_LEN, ED25519_NAME, ED25519PH_NAME, Ed25519, Ed25519PrivateKey, Ed25519PublicKey,
    Ed25519ph, Ed25519phPrivateKey, Ed25519phPublicKey, Ed25519phSigner, Ed25519phVerifier,
    SIGNATURE_LEN, keygen,
};
use std::sync::OnceLock;

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

/// The Ed25519ph views of that pair, for the framework, whose runners take a function that
/// returns the keys by value: a view borrows its key, so the pair lives in a static.
fn key_pair_ph()
-> Result<(Ed25519phPublicKey<'static>, Ed25519phPrivateKey<'static>), SignatureError> {
    static PAIR: OnceLock<(Ed25519PublicKey, Ed25519PrivateKey)> = OnceLock::new();
    let (pk, sk) = PAIR.get_or_init(|| key_pair().unwrap());
    Ok((pk.as_prehash(), sk.as_prehash()))
}

fn sign(sk: &Ed25519PrivateKey, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    sk.sign_deterministic(msg, None).unwrap()
}

fn verify(pk: &Ed25519PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    pk.verify(msg, None, sig)
}

fn sign_ph(sk: &Ed25519PrivateKey, msg: &[u8], ctx: Option<&[u8]>) -> [u8; SIGNATURE_LEN] {
    sk.as_prehash().sign_deterministic(msg, ctx).unwrap()
}

fn verify_ph(
    pk: &Ed25519PublicKey,
    msg: &[u8],
    ctx: Option<&[u8]>,
    sig: &[u8],
) -> Result<(), SignatureError> {
    pk.as_prehash().verify(msg, ctx, sig)
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

/// Ed25519ph, on the views of the keys, streams and binds its context; the framework's long
/// context is 256 octets, one more than [`CONTEXT_MAX_LEN`].
#[test]
fn ed25519ph_core_framework() {
    let tf = TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Bound);
    tf.test_deterministic_signature::<Ed25519ph, _, _, SIGNATURE_LEN>(key_pair_ph, true);
    tf.test_deterministic_one_shot_signature::<Ed25519ph, _, _, SIGNATURE_LEN>(key_pair_ph, false);
}

/// The keys are Ed25519's and the views Ed25519ph's, so no call names its algorithm: the
/// one-shots on a key and on a view, and the streaming constructors on a view that is a
/// temporary or a variable.
#[test]
fn no_call_names_the_algorithm() {
    let (pk, sk) = key_pair().unwrap();

    let sig = sk.sign_deterministic(MSG, None).unwrap();
    let mut out = [0u8; SIGNATURE_LEN];
    assert_eq!(sk.sign_deterministic_out(MSG, None, &mut out), Ok(SIGNATURE_LEN));
    assert_eq!(out, sig);
    assert_eq!(pk.verify(MSG, None, &sig), Ok(()));

    let sig_ph = sk.as_prehash().sign_deterministic(MSG, Some(b"ctx")).unwrap();
    let mut out = [0u8; SIGNATURE_LEN];
    assert_eq!(
        sk.as_prehash().sign_deterministic_out(MSG, Some(b"ctx"), &mut out),
        Ok(SIGNATURE_LEN)
    );
    assert_eq!(out, sig_ph);
    assert_eq!(pk.as_prehash().verify(MSG, Some(b"ctx"), &sig_ph), Ok(()));

    // The views are gone at the end of each statement; the workers borrow the keys.
    let mut signer = sk.as_prehash().create_signer_deterministic(Some(b"ctx")).unwrap();
    let mut verifier = pk.as_prehash().create_verifier(Some(b"ctx")).unwrap();
    signer.do_update(MSG);
    verifier.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig_ph);
    assert_eq!(verifier.do_verify_final(&sig_ph), Ok(()));

    let (pk_ph, sk_ph) = (pk.as_prehash(), sk.as_prehash());
    let mut signer = sk_ph.create_signer_deterministic(Some(b"ctx")).unwrap();
    let mut verifier = pk_ph.create_verifier(Some(b"ctx")).unwrap();
    signer.do_update(MSG);
    verifier.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig_ph);
    assert_eq!(verifier.do_verify_final(&sig_ph), Ok(()));
}

/// A worker made through a view borrows the key for the key's lifetime, so a function can
/// return one made from a view it did not keep.
fn signer_of(sk: &Ed25519PrivateKey) -> Ed25519phSigner<'_> {
    sk.as_prehash().create_signer_deterministic(None).unwrap()
}

fn verifier_of(pk: &Ed25519PublicKey) -> Ed25519phVerifier<'_> {
    pk.as_prehash().create_verifier(None).unwrap()
}

#[test]
fn the_workers_outlive_the_view() {
    let (pk, sk) = key_pair().unwrap();
    let mut signer = signer_of(&sk);
    let mut verifier = verifier_of(&pk);
    signer.do_update(MSG);
    verifier.do_update(MSG);
    let sig = signer.do_final().unwrap();
    assert_eq!(sig, sign_ph(&sk, MSG, None));
    assert_eq!(verifier.do_verify_final(&sig), Ok(()));
}

/// The view is a reference to the key and nothing else, so making one copies no key material.
#[test]
fn the_view_is_a_reference() {
    use core::mem::size_of;
    assert_eq!(size_of::<Ed25519phPrivateKey<'_>>(), size_of::<&Ed25519PrivateKey>());
    assert_eq!(size_of::<Ed25519phPublicKey<'_>>(), size_of::<&Ed25519PublicKey>());
    assert!(size_of::<Ed25519phPrivateKey<'_>>() < size_of::<Ed25519PrivateKey>());

    // A copy of a view is a view of the same key.
    let (pk, sk) = key_pair().unwrap();
    let (sk_ph, pk_ph) = (sk.as_prehash(), pk.as_prehash());
    let (sk_copy, pk_copy) = (sk_ph, pk_ph);
    let sig = sk_ph.sign_deterministic(MSG, None).unwrap();
    assert_eq!(sk_copy.sign_deterministic(MSG, None), Ok(sig));
    assert_eq!(pk_copy.verify(MSG, None, &sig), Ok(()));
    assert_eq!(pk_ph.verify(MSG, None, &sig), Ok(()));
}

/// Code generic over the streaming roles, which is handed the views.
fn streamed<A, SK, PK, const N: usize>(sk: &SK, pk: &PK) -> [u8; N]
where
    A: SignatureAlgorithm,
    SK: DeterministicSigningKey<A, N>,
    PK: VerifyingKey<A, N>,
{
    let mut signer = sk.create_signer_deterministic(None).unwrap();
    signer.do_update(MSG);
    let sig = signer.do_final().unwrap();
    let mut verifier = pk.create_verifier(None).unwrap();
    verifier.do_update(MSG);
    verifier.do_verify_final(&sig).unwrap();
    sig
}

/// Code generic over the one-shot roles, which is handed the keys or the views.
fn one_shot<A, SK, PK, const N: usize>(sk: &SK, pk: &PK) -> [u8; N]
where
    A: SignatureAlgorithm,
    SK: DeterministicOneShotSigningKey<A, N>,
    PK: OneShotVerifyingKey<A, N>,
{
    let sig = sk.sign_deterministic(MSG, None).unwrap();
    pk.verify(MSG, None, &sig).unwrap();
    sig
}

#[test]
fn generic_code_takes_the_keys_and_the_views() {
    let (pk, sk) = key_pair().unwrap();
    assert_eq!(one_shot(&sk, &pk), sign(&sk, MSG));
    assert_eq!(one_shot(&sk.as_prehash(), &pk.as_prehash()), sign_ph(&sk, MSG, None));
    assert_eq!(streamed(&sk.as_prehash(), &pk.as_prehash()), sign_ph(&sk, MSG, None));
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
    let signer = sk.as_prehash().create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "Ed25519ph");
    assert_eq!(signer.max_security_strength(), SecurityStrength::_128bit);
    let verifier = pk.as_prehash().create_verifier(None).unwrap();
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
    let l = bouncycastle_core::hex::decode(L).unwrap();
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
        let either = |sig: &[u8]| {
            if name == "Ed25519" { verify(&pk, MSG, sig) } else { verify_ph(&pk, MSG, None, sig) }
        };
        let mut s_is_l = sig;
        s_is_l[32..].copy_from_slice(&l);
        assert_eq!(either(&s_is_l), FAILED, "{name}");
        let mut s_is_max = sig;
        s_is_max[32..].fill(0xFF);
        assert_eq!(either(&s_is_max), FAILED, "{name}");
    }
}

// The vectors of the next two tests were generated with the Python library of RFC 8032
// Appendix A, lifted from the text of the RFC by script.

/// RFC 8032 Section 7.1, TEST 1's public key.
const RFC8032_TEST1_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

// Signatures of b"cofactored" under that key whose `R` is the point of order 4 with y = 0, and
// `S` = k s mod L: `[8][S]B = [8]R + [8][k]A` holds, and `[S]B = R + [k]A` does not.
const ZERO_R: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e0ed5470b77fb2d2fb5b76d0c54380f752f1be0560c47cb7f7e616ecbdcfde07",
);
const R_Y_IS_P: &str = concat!(
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "84d87ff0e0b71e676a40a2f31779b98583f3f45bbbd4735a64a035b7d850cd05",
);

/// Verification through the API is cofactored (RFC 8032 Section 5.1.7, step 3, the first
/// equation), and `R` must be canonically encoded (Section 5.1.3): the same point with its y
/// given as p is refused, though the equation would hold for it.
#[test]
fn a_small_order_r_is_accepted_only_canonically_encoded() {
    let pk =
        Ed25519PublicKey::from_bytes(&bouncycastle_core::hex::decode(RFC8032_TEST1_PK).unwrap())
            .unwrap();
    let zero_r = bouncycastle_core::hex::decode(ZERO_R).unwrap();
    assert_eq!(verify(&pk, b"cofactored", &zero_r), Ok(()));
    assert_eq!(verify(&pk, b"cofactoreD", &zero_r), FAILED);
    let r_y_is_p = bouncycastle_core::hex::decode(R_Y_IS_P).unwrap();
    assert_eq!(verify(&pk, b"cofactored", &r_y_is_p), FAILED);
}

// (context, signature) under the key and message of RFC 8032 Section 7.3
const ED25519PH_CONTEXTS: &[(&str, &str)] = &[
    (
        "00",
        concat!(
            "3e0a12876df934436205c5ee0e8559e1ed726098748aa5c932a7afa34e8fe8178ef3ad700f0a6aa8",
            "291d63deee2161df578dee604a433aece1b6d3f688222004",
        ),
    ),
    (
        "6162",
        concat!(
            "4f5c824df5d30fd1dea73a732202ec12150d0b7fac254b44f4046a9aa4c8b7a0e12e4a91a62e75fb",
            "3c79a16d568c59f47ecf5042f24815ab3b024b9e833ac407",
        ),
    ),
    (
        concat!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
            "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677",
            "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
        ),
        concat!(
            "e92b7df2fb33385643a075cb7f5baf8cf000f7c3fd17ebc8e353587f7b5247b3cbb4b6b931e67cf6",
            "c9f526ca203dee437528706964137893b9ec911be9cff70b",
        ),
    ),
];

/// Ed25519ph known answers under contexts of 1, 2 and 255 octets, which pin the length octet
/// and the placing of the context in `dom2` (RFC 8032 Section 2); the RFC's own Ed25519ph
/// vector has an empty context.
#[test]
fn ed25519ph_known_answers_with_a_context() {
    // RFC 8032 Section 7.3: the secret key, and the message "abc".
    let sk = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    let sk = Ed25519PrivateKey::from_bytes(&bouncycastle_core::hex::decode(sk).unwrap()).unwrap();
    let pk = sk.pk().unwrap();
    for (ctx, sig) in ED25519PH_CONTEXTS {
        let ctx = bouncycastle_core::hex::decode(ctx).unwrap();
        let sig = bouncycastle_core::hex::decode(sig).unwrap();
        assert_eq!(sign_ph(&sk, b"abc", Some(&ctx))[..], sig[..], "context of {}", ctx.len());
        assert_eq!(verify_ph(&pk, b"abc", Some(&ctx), &sig), Ok(()));
    }
}

/// The two algorithms give different signatures of one message under one key, and neither
/// verifies as the other, over the message or over its SHA-512 digest: a signature made
/// through the view verifies only through the view, and one made by the key only by the key.
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

    // The view's streaming verifier, likewise.
    for (sig, verdict) in [(ph, Ok(())), (pure, FAILED)] {
        let mut verifier = pk.as_prehash().create_verifier(None).unwrap();
        verifier.do_update(MSG);
        assert_eq!(verifier.do_verify_final(&sig), verdict);
    }
}

/// RFC 8032 Section 5.1, of Ed25519: "The context (if present at all) MUST be empty."
#[test]
fn ed25519_takes_no_context() {
    let (pk, sk) = key_pair().unwrap();
    let sig = sign(&sk, MSG);
    let empty = Some(&[][..]);
    assert_eq!(sk.sign_deterministic(MSG, empty), Ok(sig));
    assert_eq!(pk.verify(MSG, empty, &sig), Ok(()));

    for ctx in [&b"c"[..], &[0u8; 256]] {
        let mut out = [0xA5u8; SIGNATURE_LEN];
        assert!(is_length_error(sk.sign_deterministic_out(MSG, Some(ctx), &mut out)));
        assert_eq!(out, [0u8; SIGNATURE_LEN]);
        assert!(is_length_error(pk.verify(MSG, Some(ctx), &sig)));
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
    let mut signer = sk.as_prehash().create_signer_deterministic(Some(&[])).unwrap();
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
    let mut signer = sk.as_prehash().create_signer_deterministic(Some(longest)).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    let mut verifier = pk.as_prehash().create_verifier(Some(longest)).unwrap();
    verifier.do_update(MSG);
    assert_eq!(verifier.do_verify_final(&sig), Ok(()));

    assert!(is_length_error(sk.as_prehash().create_signer_deterministic(Some(&long))));
    assert!(is_length_error(pk.as_prehash().create_verifier(Some(&long))));
    assert!(is_length_error(verify_ph(&pk, MSG, Some(&long), &sig)));
    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert!(is_length_error(sk.as_prehash().sign_deterministic_out(MSG, Some(&long), &mut out)));
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
        let mut signer = sk.as_prehash().create_signer_deterministic(Some(b"ctx")).unwrap();
        let mut verifier = pk.as_prehash().create_verifier(Some(b"ctx")).unwrap();
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
    let signer = sk.as_prehash().create_signer_deterministic(None).unwrap();
    assert_eq!(signer.do_final().unwrap(), sign_ph(&sk, b"", None));

    let mut verifier = pk.as_prehash().create_verifier(Some(b"ctx")).unwrap();
    verifier.do_update(&msg);
    assert!(is_length_error(verifier.do_verify_final(&sig[..63])));
    let mut verifier = pk.as_prehash().create_verifier(Some(b"ctx")).unwrap();
    verifier.do_update(&msg[1..]);
    assert_eq!(verifier.do_verify_final(&sig), FAILED);
}

/// A key that was never filled signs nothing, under either algorithm, and leaves zeros in
/// the caller's buffer.
#[test]
fn an_unfilled_key_does_not_sign() {
    let sk = Ed25519PrivateKey::zeroized();
    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert_eq!(sk.sign_deterministic_out(MSG, None, &mut out), Err(ZEROIZED));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    assert_eq!(sk.sign_deterministic(MSG, None), Err(ZEROIZED));

    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert_eq!(sk.as_prehash().sign_deterministic_out(MSG, None, &mut out), Err(ZEROIZED));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    assert!(matches!(sk.as_prehash().create_signer_deterministic(None), Err(ZEROIZED)));
}
