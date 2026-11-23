//! Ed448 and Ed448ph on the signature roles: the core test framework's suites, and what is
//! particular to the two algorithms.

use bouncycastle_core::errors::{KeyMaterialError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey,
    SignatureAlgorithm, VerifyingKey,
};
use bouncycastle_core::traits::{Hash, PrivateKey, PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle_core_test_framework::signature::{CtxBehaviour, TestFrameworkSignature};
use bouncycastle_digest::sha3::SHAKE256;
use bouncycastle_ec::ed::ed448::{
    CONTEXT_MAX_LEN, ED448_NAME, ED448PH_NAME, Ed448, Ed448PrivateKey, Ed448PublicKey, Ed448ph,
    Ed448phPrivateKey, Ed448phPublicKey, Ed448phSigner, Ed448phVerifier, SIGNATURE_LEN, keygen,
};
use std::sync::OnceLock;

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";
const FAILED: Result<(), SignatureError> = Err(SignatureError::SignatureVerificationFailed);
const ZEROIZED: SignatureError =
    SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

/// The group order L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
/// (RFC 8032 Table 2) in 57 little-endian octets, computed from that expression by script.
const L: &str = concat!(
    "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffff3f00",
);

fn key_pair() -> Result<(Ed448PublicKey, Ed448PrivateKey), SignatureError> {
    keygen(&mut FixedSeedRNG::new(core::array::from_fn::<u8, 128, _>(|i| i as u8)))
}

/// The Ed448ph views of that pair, for the framework, whose runners take a function that
/// returns the keys by value: a view borrows its key, so the pair lives in a static.
fn key_pair_ph() -> Result<(Ed448phPublicKey<'static>, Ed448phPrivateKey<'static>), SignatureError>
{
    static PAIR: OnceLock<(Ed448PublicKey, Ed448PrivateKey)> = OnceLock::new();
    let (pk, sk) = PAIR.get_or_init(|| key_pair().unwrap());
    Ok((pk.as_prehash(), sk.as_prehash()))
}

fn sign(sk: &Ed448PrivateKey, msg: &[u8], ctx: Option<&[u8]>) -> [u8; SIGNATURE_LEN] {
    sk.sign_deterministic(msg, ctx).unwrap()
}

fn verify(
    pk: &Ed448PublicKey,
    msg: &[u8],
    ctx: Option<&[u8]>,
    sig: &[u8],
) -> Result<(), SignatureError> {
    pk.verify(msg, ctx, sig)
}

fn sign_ph(sk: &Ed448PrivateKey, msg: &[u8], ctx: Option<&[u8]>) -> [u8; SIGNATURE_LEN] {
    sk.as_prehash().sign_deterministic(msg, ctx).unwrap()
}

fn verify_ph(
    pk: &Ed448PublicKey,
    msg: &[u8],
    ctx: Option<&[u8]>,
    sig: &[u8],
) -> Result<(), SignatureError> {
    pk.as_prehash().verify(msg, ctx, sig)
}

fn is_length_error<T>(result: Result<T, SignatureError>) -> bool {
    matches!(result, Err(SignatureError::LengthError(_)))
}

type Sign = fn(&Ed448PrivateKey, &[u8], Option<&[u8]>) -> [u8; SIGNATURE_LEN];
type Verify = fn(&Ed448PublicKey, &[u8], Option<&[u8]>, &[u8]) -> Result<(), SignatureError>;

/// The one-shot forms of the two algorithms, for what holds of both.
const BOTH: [(&str, Sign, Verify); 2] = [("Ed448", sign, verify), ("Ed448ph", sign_ph, verify_ph)];

/// Ed448 has the one-shot roles alone and, unlike Ed25519, binds a context; the framework's
/// long context is 256 octets, one more than [`CONTEXT_MAX_LEN`].
#[test]
fn ed448_core_framework() {
    TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Bound)
        .test_deterministic_one_shot_signature::<Ed448, _, _, SIGNATURE_LEN>(key_pair, true);
}

/// Ed448ph, on the views of the keys, streams and binds its context.
#[test]
fn ed448ph_core_framework() {
    let tf = TestFrameworkSignature::with_ctx_behaviour(CtxBehaviour::Bound);
    tf.test_deterministic_signature::<Ed448ph, _, _, SIGNATURE_LEN>(key_pair_ph, true);
    tf.test_deterministic_one_shot_signature::<Ed448ph, _, _, SIGNATURE_LEN>(key_pair_ph, false);
}

/// The keys are Ed448's and the views Ed448ph's, so no call names its algorithm: the
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
fn signer_of(sk: &Ed448PrivateKey) -> Ed448phSigner<'_> {
    sk.as_prehash().create_signer_deterministic(None).unwrap()
}

fn verifier_of(pk: &Ed448PublicKey) -> Ed448phVerifier<'_> {
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
    assert_eq!(size_of::<Ed448phPrivateKey<'_>>(), size_of::<&Ed448PrivateKey>());
    assert_eq!(size_of::<Ed448phPublicKey<'_>>(), size_of::<&Ed448PublicKey>());
    assert!(size_of::<Ed448phPrivateKey<'_>>() < size_of::<Ed448PrivateKey>());

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
    assert_eq!(one_shot(&sk, &pk), sign(&sk, MSG, None));
    assert_eq!(one_shot(&sk.as_prehash(), &pk.as_prehash()), sign_ph(&sk, MSG, None));
    assert_eq!(streamed(&sk.as_prehash(), &pk.as_prehash()), sign_ph(&sk, MSG, None));
}

#[test]
fn the_markers_and_workers_name_their_algorithm() {
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Algorithm, AlgorithmInfo};
    assert_eq!((Ed448::ALG_NAME, ED448_NAME), ("Ed448", "Ed448"));
    assert_eq!((Ed448ph::ALG_NAME, ED448PH_NAME), ("Ed448ph", "Ed448ph"));
    // RFC 8032 Section 8.5 gives 224 bits; the library's next level down is 192.
    assert_eq!(Ed448::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(Ed448ph::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(SIGNATURE_LEN, 114);

    // id-Ed448, RFC 8410 Section 3: { 1 3 101 113 }. The RFC prints no encoding of it (its
    // examples are Ed25519 and X25519); this is the encoding of id-Ed25519 in its Section 10.1,
    // `06 03 2b 65 70`, with the last arc one higher.
    use bouncycastle_core::traits::AlgorithmOID;
    assert_eq!(<Ed448 as AlgorithmOID>::OID, &[1, 3, 101, 113]);
    assert_eq!(<Ed448 as AlgorithmOID>::OID_DER, &[0x06, 0x03, 0x2b, 0x65, 0x71]);

    let (pk, sk) = key_pair().unwrap();
    let signer = sk.as_prehash().create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "Ed448ph");
    assert_eq!(signer.max_security_strength(), SecurityStrength::_192bit);
    let verifier = pk.as_prehash().create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "Ed448ph");
    assert_eq!(verifier.max_security_strength(), SecurityStrength::_192bit);
}

#[test]
fn signing_is_deterministic() {
    let (_, sk) = key_pair().unwrap();
    for (name, sign, _) in BOTH {
        assert_eq!(sign(&sk, MSG, None), sign(&sk, MSG, None), "{name}");
        assert_eq!(sign(&sk, MSG, Some(b"ctx")), sign(&sk, MSG, Some(b"ctx")), "{name}");
        assert_ne!(sign(&sk, MSG, None), sign(&sk, &MSG[1..], None), "{name}");
        assert_ne!(sign(&sk, MSG, None), sign(&sk, MSG, Some(b"ctx")), "{name}");
    }
}

/// The wrong message, the wrong key, and a signature whose `R` or `S` half was changed.
#[test]
fn what_was_not_signed_is_rejected() {
    let (pk, sk) = key_pair().unwrap();
    let other = Ed448PrivateKey::from_bytes(&[3; 57]).unwrap().pk().unwrap();
    for (name, sign, verify) in BOTH {
        let sig = sign(&sk, MSG, None);
        assert_eq!(verify(&pk, MSG, None, &sig), Ok(()), "{name}");

        assert_eq!(verify(&pk, &MSG[1..], None, &sig), FAILED, "{name}");
        assert_eq!(verify(&pk, b"", None, &sig), FAILED, "{name}");
        assert_eq!(verify(&other, MSG, None, &sig), FAILED, "{name}");

        // The first and last octet of each half; octet 113, the top of S, is zero as signed.
        for i in [0, 56, 57, 112, 113] {
            let mut tampered = sig;
            tampered[i] ^= 1;
            assert_eq!(verify(&pk, MSG, None, &tampered), FAILED, "{name}: octet {i}");
        }
        // The two halves of two good signatures do not combine.
        let other_sig = sign(&sk, b"another message", None);
        let mut mixed = sig;
        mixed[57..].copy_from_slice(&other_sig[57..]);
        assert_eq!(verify(&pk, MSG, None, &mixed), FAILED, "{name}");

        // A signature of the wrong length is a length error, not a failed verification.
        assert!(is_length_error(verify(&pk, MSG, None, &sig[..113])), "{name}");
        assert!(is_length_error(verify(&pk, MSG, None, &[sig.as_slice(), &[0]].concat())));
        assert!(is_length_error(verify(&pk, MSG, None, &[])), "{name}");
    }
}

/// RFC 8032 Section 5.2.7, step 1: "If any of the decodings fail (including S being out of
/// range), the signature is invalid." `S + L` is `S` mod L and fits the 57 octets, as do
/// `S + 2 L` and `S + 3 L`; `2^448 + S` has `S` in its first 56 octets.
#[test]
fn s_not_below_the_group_order_is_rejected() {
    let (pk, sk) = key_pair().unwrap();
    let l = bouncycastle_core::hex::decode(L).unwrap();
    assert_eq!(l.len(), 57);
    for (name, sign, verify) in BOTH {
        let sig = sign(&sk, MSG, None);
        assert_eq!(sig[113], 0, "{name}");
        let mut malleated = sig;
        for multiple in 1..=3 {
            let mut carry = 0u16;
            for (s, l) in malleated[57..].iter_mut().zip(&l) {
                carry += u16::from(*s) + u16::from(*l);
                *s = carry as u8;
                carry >>= 8;
            }
            assert_eq!(carry, 0);
            assert_eq!(verify(&pk, MSG, None, &malleated), FAILED, "{name}: S + {multiple} L");
        }

        for top in [0x01, 0x80] {
            let mut high = sig;
            high[113] = top;
            assert_eq!(verify(&pk, MSG, None, &high), FAILED, "{name}: last octet {top:#x}");
        }

        // S = L itself, and S of all ones.
        let mut s_is_l = sig;
        s_is_l[57..].copy_from_slice(&l);
        assert_eq!(verify(&pk, MSG, None, &s_is_l), FAILED, "{name}");
        let mut s_is_max = sig;
        s_is_max[57..].fill(0xFF);
        assert_eq!(verify(&pk, MSG, None, &s_is_max), FAILED, "{name}");
    }
}

// The vectors of the next two tests were generated with the Python library of RFC 8032
// Appendix A, lifted from the text of the RFC by script.

/// The private key of the first vector of RFC 8032 Section 7.4, which the generated
/// vectors below are under.
const GENERATED_SK: &str = concat!(
    "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e",
    "39a3fc5b94492f8f032e7549a20098f95b",
);

/// Its public key.
const GENERATED_PK: &str = concat!(
    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c706",
    "1bd6783df1e50f6cd1fa1abeafe8256180",
);

// (what R is, signature on "cofactored" with the empty context): each satisfies
// [4][S]B = [4]R + [4][k]A and, but for the last, not [S]B = R + [k]A; made and checked
// with the Python library of RFC 8032 Appendix A
const COFACTORED_KATS: &[(&str, &str)] = &[
    (
        "[r]B + a point of order 2",
        concat!(
            "68d0c16d1d8cf6cfa2cf3a76f8a33925127f2c22b13df1e57824f6968c8a976b0695be41cff5017f",
            "7344a6c6b1f5699192675323019163fd80ec47264b4c717d7cb4b59c003823a2bfa76cf1b2991d23",
            "047681f093ea189c7ab49cf15a679b9910f5185f2f67c15bd108a609695e995f0500",
        ),
    ),
    (
        "a point of order 2",
        concat!(
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff00a84cd7246425c4aed784431358ddbb4ab5df47e6239875",
            "a60b1a41464b3d902b3f2fe2914eddbf2fe9bf7a6eb5cfa3c276fba10f4970410e00",
        ),
    ),
    (
        "[r]B + a point of order 4",
        concat!(
            "b1290a80518ecba63a43376b8fc05e8a92c6d3519dc9541e205370fa1e512ec93edda69cce5d2835",
            "46cc87ce6b190ce66f0f3a455491915680831369fce6f8145bd82014086a8d384871c0726f4fcc36",
            "568e2854a7869fcf7d01742c046686ded68daa71187fdb496fc61f7069c3faab0900",
        ),
    ),
    (
        "a point of order 4",
        concat!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000080f01af6bfcb571066268ddaf8297ae24cfb2ce5b21f8b1c",
            "094a75d149ebed5b7f4c803869f7e8fb03945c536633312ed80ed8334e21ff2c2900",
        ),
    ),
    (
        "[r]B + a point of order 4, the other",
        concat!(
            "4ed6f57fae713459c5bcc894703fa1756d392cae6236abe1dfac8f05e0aed136c122596331a2d7ca",
            "b933783194e6f31990f0c5baab6e6ea9003ab6731726f94ea139c2c5fa8e1aec0f7ba2b7a04f5b1a",
            "a261c86d81dbb579d53a54739744b115508b5a105d8c90f426bf1c9696fa07ef1500",
        ),
    ),
    (
        "a point of order 4, the other",
        concat!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000e74d7b455b5f0b5751bd27dc30c7c6009739f1d756f741",
            "fd419cf0795b8cef959d03839d84ac61dbdd61ba93cf3c04a30716285108932d3b00",
        ),
    ),
    (
        "the neutral element",
        concat!(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000017281c6bbb0203acdb2280f4ed557a8bb789306387987d",
            "d006f33a905d3f49ad5b5ff8de8ed8318e58d8de33893153ebfad5523d53d93b2100",
        ),
    ),
];

// (the encoding of R, signature on "cofactored" with the empty context): the points of
// small order again, in encodings RFC 8032 Section 5.2.3, step 1, refuses
const NON_CANONICAL_R_KATS: &[(&str, &str)] = &[
    (
        "y = p for (-1, 0)",
        concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff000432ef1e24ad001261bf5f10e6286f23bb60865db7bc71",
            "d58651d391e70f3f7c29131ca09ae39a41245ccd4ac2722868fa96010108e4480500",
        ),
    ),
    (
        "y = p for (1, 0)",
        concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff8013e4d386d4ce3ef9872be21a2871ad15294c9443bff3bc",
            "0e8b09bdb06aa70f1f643052853f49d6ccd5a6450e91c46b6437bd8c49e16c181000",
        ),
    ),
    (
        "y = p + 1 for (0, 1)",
        concat!(
            "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff00f12dab1388cf2926542495c4fcbaf0ece1f17f1691ed74",
            "0310186fa3ec8cc66aedf924cadaf4d2bce7043581a8cec11f9e2835048a4a1c1300",
        ),
    ),
    (
        "y = 2^448 for (-1, 0)",
        concat!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000001062987badae598a4c5955e056cb1132902ea1edbbee331",
            "587b2a8d4c0537c63e8e1651816aed30e9c39eb364c0135d46a2f71b266158233300",
        ),
    ),
    (
        "y = 2^448 + 1 for (0, 1)",
        concat!(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000001fdab0bd18f55be4bb40911b393286de615feb8fd7303d5",
            "8f5523f1d78e9c238dc5a4466391cafdc8e7671c5f7be072dc15dbf9484fdd1a0900",
        ),
    ),
];

/// Verification through the API is cofactored (RFC 8032 Section 5.2.7, step 3, the first
/// equation): a signature whose `R` is off by a point of order 2 or 4, or is one, is accepted.
/// `R` must be canonically encoded (Section 5.2.3): the same points with y given as p or as
/// p + 1, or with bit 448 set, are refused, though the equation would hold for them.
#[test]
fn a_small_order_r_is_accepted_only_canonically_encoded() {
    let pk =
        Ed448PublicKey::from_bytes(&bouncycastle_core::hex::decode(GENERATED_PK).unwrap()).unwrap();
    assert_eq!((COFACTORED_KATS.len(), NON_CANONICAL_R_KATS.len()), (7, 5));
    for (what, sig) in COFACTORED_KATS {
        let sig = bouncycastle_core::hex::decode(sig).unwrap();
        assert_eq!(verify(&pk, b"cofactored", None, &sig), Ok(()), "{what}");
        assert_eq!(verify(&pk, b"cofactored", Some(&[]), &sig), Ok(()), "{what}");
        assert_eq!(verify(&pk, b"cofactoreD", None, &sig), FAILED, "{what}");
        assert_eq!(verify(&pk, b"cofactored", Some(b"c"), &sig), FAILED, "{what}");
        assert_eq!(verify_ph(&pk, b"cofactored", None, &sig), FAILED, "{what}");
    }
    for (what, sig) in NON_CANONICAL_R_KATS {
        let sig = bouncycastle_core::hex::decode(sig).unwrap();
        assert_eq!(verify(&pk, b"cofactored", None, &sig), FAILED, "{what}");
    }
}

// (whether Ed448ph, context, signature on "abc"), by the Python library of RFC 8032
// Appendix A
const CONTEXT_KATS: &[(bool, &str, &str)] = &[
    (
        false,
        "",
        concat!(
            "50cf9c9532d4f906bc05eee0e6a35c47b539e66b47f7e9229e43b35bde4c2c9dddab4329de8e73ac",
            "7754d958bfdb4cbb3bc960ffbee8835e0026a993fccde9232465f1ad394ff14ad37e77ad38824259",
            "942d2884d671b7a8d1ac92c7c9841b1c0a4fd3adee3574ee1368f07988088d543100",
        ),
    ),
    (
        false,
        "00",
        concat!(
            "3ef478d25cf315f69a6d40d09bb4396960ebacf80bd0fa1afca71fabd7cfcd66672898618d167c79",
            "3c89e31d8b88ba129ce6c6526025215880b1c6407c796777dc06c197da55bf6c35d3a60686c2fb6b",
            "72f77b2e87fc2d08700dffdf43655a02cc2d064d4814ad6452cfa9eb78f03eb21800",
        ),
    ),
    (
        false,
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
            "ef900ed044a11e1e757bff530e638a97d76ea7fa888336be5fc510ddf629cdcde97949305691ae78",
            "07bf217ff323eb43d79c4347c8006dbd806effac5725b9725cae9ed75359c54010c853c16ef493bf",
            "0b255d7e239cb3286b6fc453b04a1736830ea8c6c3be2d843e49bd8bfba26b0a0a00",
        ),
    ),
    (
        true,
        "",
        concat!(
            "62a8fc722f705b0436c3528e6fc75c9347ceafe71ca6d70aaa9e62a9110ed2d01a5f353ba5b87961",
            "e6bc2a5789a58a3fd9384c4106e49f0a80b8705befd1054ee77231775340449868a7c4ef7d2e2531",
            "5f63873702eb33ac8a552a37b3e4bb670dcc4d945476cf094b5d28e944beeab81200",
        ),
    ),
    (
        true,
        "00",
        concat!(
            "41f8cb2f71623df358939809437efff4761969661aecc7bebcc8cfc17793e315f1ed9344fd855981",
            "3197852ca7d6ea9137152265c8f7aa7680b9003e27b70f626b2d26140176f3821a6700b96a97b2a1",
            "0b458cc756489fb92a4b4927ef80a6c65d646db3cf865f6c62eddb175bde9c742500",
        ),
    ),
    (
        true,
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
            "41ed3b313521d9b1b6f05c09f2e0a147fd811503553a04724b015708889e119b0226038e13535e96",
            "d2de5bcc17d5ab60d04d020768a0190380ee982d0f4886d48cf5521f531451afd8134fe836634604",
            "81437ff62970903282931c643a2f64e325e3a08f244b847cf763c68740b7b3ee2e00",
        ),
    ),
];

/// Known answers for both algorithms under contexts of 0, 1 and 255 octets, which pin the
/// length octet and the placing of the context in `dom4` (RFC 8032 Section 2).
#[test]
fn known_answers_with_a_context() {
    let sk = Ed448PrivateKey::from_bytes(&bouncycastle_core::hex::decode(GENERATED_SK).unwrap())
        .unwrap();
    let pk = sk.pk().unwrap();
    assert_eq!(pk.encode().as_slice(), bouncycastle_core::hex::decode(GENERATED_PK).unwrap());
    let mut seen = Vec::new();
    for (ph, ctx, sig) in CONTEXT_KATS {
        let ctx = bouncycastle_core::hex::decode(ctx).unwrap();
        let sig = bouncycastle_core::hex::decode(sig).unwrap();
        let (name, sign, verify) = BOTH[usize::from(*ph)];
        assert_eq!(sign(&sk, b"abc", Some(&ctx))[..], sig[..], "{name}: context of {}", ctx.len());
        assert_eq!(verify(&pk, b"abc", Some(&ctx), &sig), Ok(()), "{name}");
        if ctx.is_empty() {
            assert_eq!(sign(&sk, b"abc", None)[..], sig[..], "{name}: no context");
        }
        seen.push((*ph, ctx.len()));
    }
    assert_eq!(seen, [(false, 0), (false, 1), (false, 255), (true, 0), (true, 1), (true, 255)]);
}

/// The two algorithms give different signatures of one message under one key and context, and
/// neither verifies as the other, over the message or over its 64-octet SHAKE256 digest: a
/// signature made through the view verifies only through the view, and one made by the key
/// only by the key.
#[test]
fn ed448_and_ed448ph_do_not_cross_verify() {
    let (pk, sk) = key_pair().unwrap();
    let mut digest = [0u8; 64];
    let mut hash = SHAKE256::new();
    hash.do_update(MSG);
    hash.do_final_out(&mut digest);

    for ctx in [None, Some(&b"ctx"[..])] {
        let pure = sign(&sk, MSG, ctx);
        let ph = sign_ph(&sk, MSG, ctx);
        assert_ne!(pure, ph);

        assert_eq!(verify(&pk, MSG, ctx, &pure), Ok(()));
        assert_eq!(verify_ph(&pk, MSG, ctx, &ph), Ok(()));
        assert_eq!(verify(&pk, MSG, ctx, &ph), FAILED);
        assert_eq!(verify(&pk, &digest, ctx, &ph), FAILED);
        assert_eq!(verify_ph(&pk, MSG, ctx, &pure), FAILED);
        assert_eq!(verify_ph(&pk, MSG, ctx, &sign(&sk, &digest, ctx)), FAILED);

        // The view's streaming verifier, likewise.
        for (sig, verdict) in [(ph, Ok(())), (pure, FAILED)] {
            let mut verifier = pk.as_prehash().create_verifier(ctx).unwrap();
            verifier.do_update(MSG);
            assert_eq!(verifier.do_verify_final(&sig), verdict);
        }
    }
}

/// The context, of both algorithms: none is the empty one, the context is bound octet for
/// octet, and 255 octets is the longest (RFC 8032 Section 5.2: "maximum of 255 octets").
#[test]
fn the_context() {
    let (pk, sk) = key_pair().unwrap();
    assert_eq!(CONTEXT_MAX_LEN, 255);
    let long = [0x5Au8; CONTEXT_MAX_LEN + 1];
    let longest = &long[..CONTEXT_MAX_LEN];

    for (name, sign, verify) in BOTH {
        let sig = sign(&sk, MSG, None);
        assert_eq!(sig, sign(&sk, MSG, Some(&[])), "{name}");
        assert_eq!(verify(&pk, MSG, Some(&[]), &sig), Ok(()), "{name}");

        let sig = sign(&sk, MSG, Some(b"context"));
        assert_eq!(verify(&pk, MSG, Some(b"context"), &sig), Ok(()), "{name}");
        assert_eq!(verify(&pk, MSG, Some(b"contexu"), &sig), FAILED, "{name}");
        assert_eq!(verify(&pk, MSG, Some(b"context\0"), &sig), FAILED, "{name}");
        assert_eq!(verify(&pk, MSG, Some(b"contex"), &sig), FAILED, "{name}");
        assert_eq!(verify(&pk, MSG, None, &sig), FAILED, "{name}");

        let sig = sign(&sk, MSG, Some(longest));
        assert_eq!(verify(&pk, MSG, Some(longest), &sig), Ok(()), "{name}");
        assert_eq!(verify(&pk, MSG, Some(&long[..CONTEXT_MAX_LEN - 1]), &sig), FAILED, "{name}");

        // One octet more is a length error, whatever the signature is.
        assert!(is_length_error(verify(&pk, MSG, Some(&long), &sig)), "{name}");
        assert!(is_length_error(verify(&pk, MSG, Some(&long), &sig[..10])), "{name}");
    }

    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert!(is_length_error(sk.sign_deterministic_out(MSG, Some(&long), &mut out)));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert!(is_length_error(sk.as_prehash().sign_deterministic_out(MSG, Some(&long), &mut out)));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);

    // The streaming workers of Ed448ph take the same contexts.
    let sig = sign_ph(&sk, MSG, None);
    let mut signer = sk.as_prehash().create_signer_deterministic(Some(&[])).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    let sig = sign_ph(&sk, MSG, Some(longest));
    let mut signer = sk.as_prehash().create_signer_deterministic(Some(longest)).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    let mut verifier = pk.as_prehash().create_verifier(Some(longest)).unwrap();
    verifier.do_update(MSG);
    assert_eq!(verifier.do_verify_final(&sig), Ok(()));
    assert!(is_length_error(sk.as_prehash().create_signer_deterministic(Some(&long))));
    assert!(is_length_error(pk.as_prehash().create_verifier(Some(&long))));
}

/// A streamed message is the same message however it is cut, and the streaming verifier
/// reports a signature of the wrong length as one. 136 octets is SHAKE256's block.
#[test]
fn ed448ph_streaming() {
    let (pk, sk) = key_pair().unwrap();
    let msg: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    let sig = sign_ph(&sk, &msg, Some(b"ctx"));
    for size in [1, 135, 136, 137, 272, 999, 1000] {
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
    assert!(is_length_error(verifier.do_verify_final(&sig[..113])));
    let mut verifier = pk.as_prehash().create_verifier(Some(b"ctx")).unwrap();
    verifier.do_update(&msg[1..]);
    assert_eq!(verifier.do_verify_final(&sig), FAILED);
}

/// A key that was never filled signs nothing, under either algorithm, and leaves zeros in
/// the caller's buffer.
#[test]
fn an_unfilled_key_does_not_sign() {
    let sk = Ed448PrivateKey::zeroized();
    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert_eq!(sk.sign_deterministic_out(MSG, None, &mut out), Err(ZEROIZED));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    assert_eq!(sk.sign_deterministic(MSG, Some(b"ctx")), Err(ZEROIZED));

    let mut out = [0xA5u8; SIGNATURE_LEN];
    assert_eq!(sk.as_prehash().sign_deterministic_out(MSG, None, &mut out), Err(ZEROIZED));
    assert_eq!(out, [0u8; SIGNATURE_LEN]);
    assert!(matches!(sk.as_prehash().create_signer_deterministic(None), Err(ZEROIZED)));
}
