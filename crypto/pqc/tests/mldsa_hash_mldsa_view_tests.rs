//! The HashML-DSA keys as views of the ML-DSA keys: `as_prehash::<H>()` borrows the key and
//! copies nothing, the views carry the roles over `HashMLDSA<P, H>` and the ML-DSA keys those
//! over `MLDSA<P>` alone, and a signature made by one verifies under no other.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::WithoutCollisionResistance;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicPreHashSigningKey, DeterministicSigningKey,
    OneShotSigningKey, OneShotVerifyingKey, PreHashAlgorithm, PreHashSigningKey,
    PreHashVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, CollisionResistantHash, HashOneShot, SignatureSigner,
    SignatureVerifier,
};
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_digest::sha2::{SHA256, SHA512};
use bouncycastle_digest::sha3::{SHA3_256, SHA3_512, SHAKE128, SHAKE256};
use bouncycastle_pqc::mldsa::hazmat::AnyStrength;
use bouncycastle_pqc::mldsa::{
    HASH_ML_DSA_44_with_SHA256_NAME, HASH_ML_DSA_44_with_SHA512_NAME,
    HASH_ML_DSA_65_with_SHA512_NAME, HASH_ML_DSA_87_with_SHA512_NAME, HashMLDSA,
    HashMLDSA44_with_SHA256, HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512,
    HashMLDSA87_with_SHA512, HashMLDSAPrivateKey, HashMLDSAPublicKey, MLDSA44, MLDSA44_SIG_LEN,
    MLDSA44Params, MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65, MLDSA65Params, MLDSA87,
    MLDSA87Params, MLDSATrait,
};
use bouncycastle_rng::DefaultRNG;

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";
const CTX: Option<&[u8]> = Some(b"a view");
const FAILED: Result<(), SignatureError> = Err(SignatureError::SignatureVerificationFailed);

fn key_pair() -> (MLDSA44PublicKey, MLDSA44PrivateKey) {
    MLDSA44::keygen(&mut DefaultRNG::default()).unwrap()
}

/// The hash is named once, at `as_prehash`; no call after it names the algorithm. The one-shots
/// over the message and over the digest, and the streaming workers of a view that is a
/// temporary or a variable, give and take the same signature.
#[test]
fn no_call_names_the_algorithm() {
    let (pk, sk) = key_pair();
    let ph = SHA512::hash(MSG);

    let sig = sk.as_prehash::<SHA512>().sign_deterministic(MSG, CTX).unwrap();
    assert_eq!(sk.as_prehash::<SHA512>().sign_ph_deterministic(&ph, CTX).unwrap(), sig);
    let mut out = [0u8; MLDSA44_SIG_LEN];
    let written = sk.as_prehash::<SHA512>().sign_deterministic_out(MSG, CTX, &mut out);
    assert_eq!(written, Ok(MLDSA44_SIG_LEN));
    assert_eq!(out, sig);
    assert_eq!(pk.as_prehash::<SHA512>().verify(MSG, CTX, &sig), Ok(()));
    assert_eq!(pk.as_prehash::<SHA512>().verify_ph(&ph, CTX, &sig), Ok(()));

    let hedged = sk.as_prehash::<SHA512>().sign(&mut DefaultRNG::default(), MSG, CTX).unwrap();
    assert_ne!(hedged, sig);
    assert_eq!(pk.as_prehash::<SHA512>().verify(MSG, CTX, &hedged), Ok(()));
    let hedged = sk.as_prehash::<SHA512>().sign_ph(&mut DefaultRNG::default(), &ph, CTX).unwrap();
    assert_eq!(pk.as_prehash::<SHA512>().verify(MSG, CTX, &hedged), Ok(()));

    // The views are gone at the end of each statement; the workers borrow the keys.
    let mut signer = sk.as_prehash::<SHA512>().create_signer_deterministic(CTX).unwrap();
    let mut verifier = pk.as_prehash::<SHA512>().create_verifier(CTX).unwrap();
    signer.do_update(MSG);
    verifier.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    assert_eq!(verifier.do_verify_final(&sig), Ok(()));

    let (pk_ph, sk_ph) = (pk.as_prehash::<SHA512>(), sk.as_prehash::<SHA512>());
    let mut signer = sk_ph.create_signer(&mut DefaultRNG::default(), CTX).unwrap();
    let mut verifier = pk_ph.create_verifier(CTX).unwrap();
    signer.do_update(MSG);
    verifier.do_update(MSG);
    assert_eq!(verifier.do_verify_final(&signer.do_final().unwrap()), Ok(()));
}

/// A worker made through a view borrows the key for the key's lifetime, so a function can
/// return one made from a view it did not keep. That it cannot outlive the key is a
/// `compile_fail` doctest on `HashMLDSAPrivateKey`.
fn signer_of(sk: &MLDSA44PrivateKey) -> impl SignatureSigner<MLDSA44_SIG_LEN> + '_ {
    sk.as_prehash::<SHA512>().create_signer_deterministic(None).unwrap()
}

fn verifier_of(pk: &MLDSA44PublicKey) -> impl SignatureVerifier + '_ {
    pk.as_prehash::<SHA512>().create_verifier(None).unwrap()
}

#[test]
fn the_workers_outlive_the_view() {
    let (pk, sk) = key_pair();
    let mut signer = signer_of(&sk);
    let mut verifier = verifier_of(&pk);
    signer.do_update(MSG);
    verifier.do_update(MSG);
    let sig = signer.do_final().unwrap();
    assert_eq!(sig, sk.as_prehash::<SHA512>().sign_deterministic(MSG, None).unwrap());
    assert_eq!(verifier.do_verify_final(&sig), Ok(()));
}

/// The view is a reference to the key and nothing else, whatever the hash, so making one
/// copies no key material; a copy of a view is a view of the same key.
#[test]
fn the_view_is_a_reference() {
    use core::mem::size_of;
    type Sk<'k, H> = HashMLDSAPrivateKey<'k, MLDSA44Params, H>;
    type Pk<'k, H> = HashMLDSAPublicKey<'k, MLDSA44Params, H>;
    assert_eq!(size_of::<Sk<'_, SHA512>>(), size_of::<&MLDSA44PrivateKey>());
    assert_eq!(size_of::<Sk<'_, AnyStrength<SHAKE256>>>(), size_of::<&MLDSA44PrivateKey>());
    assert_eq!(size_of::<Pk<'_, SHA512>>(), size_of::<&MLDSA44PublicKey>());
    assert!(size_of::<Sk<'_, SHA512>>() < size_of::<MLDSA44PrivateKey>());

    use bouncycastle_pqc::mldsa::{MLDSA44PrivateKeyExpanded, MLDSA44PublicKeyExpanded};
    type SkExp<'k> = HashMLDSAPrivateKey<'k, MLDSA44Params, SHA512, MLDSA44PrivateKeyExpanded<'k>>;
    type PkExp<'k> = HashMLDSAPublicKey<'k, MLDSA44Params, SHA512, MLDSA44PublicKeyExpanded<'k>>;
    assert_eq!(size_of::<SkExp<'_>>(), size_of::<&MLDSA44PrivateKeyExpanded<'_>>());
    assert_eq!(size_of::<PkExp<'_>>(), size_of::<&MLDSA44PublicKeyExpanded<'_>>());

    let (pk, sk) = key_pair();
    let (sk_ph, pk_ph) = (sk.as_prehash::<SHA512>(), pk.as_prehash::<SHA512>());
    let (sk_copy, pk_copy) = (sk_ph, pk_ph);
    let sig = sk_ph.sign_deterministic(MSG, None).unwrap();
    assert_eq!(sk_copy.sign_deterministic(MSG, None), Ok(sig));
    assert_eq!(pk_copy.verify(MSG, None, &sig), Ok(()));
    assert_eq!(pk_ph.verify(MSG, None, &sig), Ok(()));
}

/// Code generic over the streaming roles, which is handed the keys or the views.
fn streamed<A, SK, PK, const N: usize>(sk: &SK, pk: &PK) -> [u8; N]
where
    A: SignatureAlgorithm,
    SK: DeterministicSigningKey<A, N>,
    PK: VerifyingKey<A, N>,
{
    let mut signer = sk.create_signer_deterministic(CTX).unwrap();
    assert_eq!(signer.alg_name(), A::ALG_NAME);
    signer.do_update(MSG);
    let sig = signer.do_final().unwrap();
    assert_eq!(sig, sk.sign_deterministic(MSG, CTX).unwrap());
    let mut verifier = pk.create_verifier(CTX).unwrap();
    assert_eq!(verifier.alg_name(), A::ALG_NAME);
    verifier.do_update(MSG);
    verifier.do_verify_final(&sig).unwrap();
    pk.verify(MSG, CTX, &sig).unwrap();
    sig
}

/// Code generic over the digest-supplied roles, which takes the hash from the key.
fn over_the_digest<A, SK, PK, const N: usize>(sk: &SK, pk: &PK) -> [u8; N]
where
    A: PreHashAlgorithm,
    A::Hash: CollisionResistantHash,
    SK: DeterministicPreHashSigningKey<A, N>,
    PK: PreHashVerifyingKey<A, N>,
{
    let ph = A::Hash::hash(MSG);
    let sig = sk.sign_ph_deterministic(&ph, CTX).unwrap();
    pk.verify_ph(&ph, CTX, &sig).unwrap();
    sig
}

#[test]
fn generic_code_takes_the_keys_and_the_views() {
    let (pk, sk) = key_pair();
    let pure = streamed(&sk, &pk);
    let ph = streamed(&sk.as_prehash::<SHA512>(), &pk.as_prehash::<SHA512>());
    assert_ne!(pure, ph);
    assert_eq!(over_the_digest(&sk.as_prehash::<SHA512>(), &pk.as_prehash::<SHA512>()), ph);
    let shake = streamed(&sk.as_prehash::<SHAKE128>(), &pk.as_prehash::<SHAKE128>());
    assert_eq!(over_the_digest(&sk.as_prehash::<SHAKE128>(), &pk.as_prehash::<SHAKE128>()), shake);
    assert_ne!(shake, ph);
}

/// A signature verifies under the key that made it and no other: an ML-DSA signature under the
/// ML-DSA key, a HashML-DSA one under the view over the same hash. Not under the ML-DSA key
/// over the message or the digest, not under a view over another hash, of the same digest
/// length (SHA3-512, another OID) or another (SHA-256), over the message or over its digest.
#[test]
fn a_signature_verifies_under_its_own_key_only() {
    let (pk, sk) = key_pair();
    let ph = SHA512::hash(MSG);

    let pure = sk.sign_deterministic(MSG, CTX).unwrap();
    let hashed = sk.as_prehash::<SHA512>().sign_deterministic(MSG, CTX).unwrap();
    assert_ne!(pure, hashed);

    assert_eq!(pk.verify(MSG, CTX, &pure), Ok(()));
    assert_eq!(pk.as_prehash::<SHA512>().verify(MSG, CTX, &hashed), Ok(()));

    assert_eq!(pk.verify(MSG, CTX, &hashed), FAILED);
    assert_eq!(pk.verify(&ph, CTX, &hashed), FAILED);
    assert_eq!(pk.as_prehash::<SHA512>().verify(MSG, CTX, &pure), FAILED);
    assert_eq!(pk.as_prehash::<SHA512>().verify_ph(&ph, CTX, &pure), FAILED);
    assert_eq!(
        pk.as_prehash::<SHA512>().verify_ph(&ph, CTX, &sk.sign_deterministic(&ph, CTX).unwrap()),
        FAILED
    );

    assert_eq!(pk.as_prehash::<SHA3_512>().verify(MSG, CTX, &hashed), FAILED);
    assert_eq!(pk.as_prehash::<SHA3_512>().verify_ph(&ph, CTX, &hashed), FAILED);
    assert_eq!(pk.as_prehash::<SHA256>().verify(MSG, CTX, &hashed), FAILED);
    assert_eq!(pk.as_prehash::<SHAKE256>().verify(MSG, CTX, &hashed), FAILED);

    // The streaming verifiers, likewise.
    let mut verifier = pk.create_verifier(CTX).unwrap();
    verifier.do_update(MSG);
    assert_eq!(verifier.do_verify_final(&hashed), FAILED);
    for (sig, verdict) in [(hashed, Ok(())), (pure, FAILED)] {
        let mut verifier = pk.as_prehash::<SHA512>().create_verifier(CTX).unwrap();
        verifier.do_update(MSG);
        assert_eq!(verifier.do_verify_final(&sig), verdict);
    }
    let mut verifier = pk.as_prehash::<SHA3_512>().create_verifier(CTX).unwrap();
    verifier.do_update(MSG);
    assert_eq!(verifier.do_verify_final(&hashed), FAILED);
}

/// The marker names every pairing: the four named pairings by their constants, any other hash by
/// the same pattern, and a hash wrapper by the hash it wraps. Its strength is the weaker of the
/// parameter set's and the hash's, and the workers report both.
#[test]
fn the_marker_names_the_algorithm() {
    assert_eq!(HashMLDSA44_with_SHA256::ALG_NAME, HASH_ML_DSA_44_with_SHA256_NAME);
    assert_eq!(HashMLDSA44_with_SHA512::ALG_NAME, HASH_ML_DSA_44_with_SHA512_NAME);
    assert_eq!(HashMLDSA65_with_SHA512::ALG_NAME, HASH_ML_DSA_65_with_SHA512_NAME);
    assert_eq!(HashMLDSA87_with_SHA512::ALG_NAME, HASH_ML_DSA_87_with_SHA512_NAME);

    type H44<H> = HashMLDSA<MLDSA44Params, H>;
    type H65<H> = HashMLDSA<MLDSA65Params, H>;
    type H87<H> = HashMLDSA<MLDSA87Params, H>;
    assert_eq!(H44::<SHA3_256>::ALG_NAME, "HashML-DSA-44_with_SHA3-256");
    assert_eq!(H44::<SHAKE128>::ALG_NAME, "HashML-DSA-44_with_SHAKE128");
    assert_eq!(H65::<SHAKE256>::ALG_NAME, "HashML-DSA-65_with_SHAKE256");
    assert_eq!(H87::<SHA3_512>::ALG_NAME, "HashML-DSA-87_with_SHA3-512");
    assert_eq!(H87::<AnyStrength<SHA256>>::ALG_NAME, "HashML-DSA-87_with_SHA256");
    assert_eq!(H44::<AnyStrength<RIPEMD160>>::ALG_NAME, "HashML-DSA-44_with_RIPEMD160");
    assert_eq!(
        H44::<AnyStrength<WithoutCollisionResistance<RIPEMD160>>>::ALG_NAME,
        "HashML-DSA-44_with_RIPEMD160"
    );
    assert_eq!(
        H44::<WithoutCollisionResistance<AnyStrength<RIPEMD160>>>::ALG_NAME,
        "HashML-DSA-44_with_RIPEMD160"
    );

    assert_eq!(H44::<SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(H44::<SHA512>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(H65::<SHA512>::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(H87::<SHAKE256>::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    assert_eq!(H87::<AnyStrength<SHA256>>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(H65::<AnyStrength<SHA512>>::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(H44::<AnyStrength<RIPEMD160>>::MAX_SECURITY_STRENGTH, SecurityStrength::None);

    let (pk, sk) = key_pair();
    let signer = sk.as_prehash::<SHA256>().create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "HashML-DSA-44_with_SHA256");
    assert_eq!(signer.max_security_strength(), SecurityStrength::_128bit);
    let signer = sk.as_prehash::<SHA512>().create_signer(&mut DefaultRNG::default(), None).unwrap();
    assert_eq!(signer.alg_name(), "HashML-DSA-44_with_SHA512");
    let verifier = pk.as_prehash::<AnyStrength<RIPEMD160>>().create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "HashML-DSA-44_with_RIPEMD160");
    assert_eq!(verifier.max_security_strength(), SecurityStrength::None);
    // The ML-DSA key's workers are ML-DSA's.
    assert_eq!(sk.create_signer_deterministic(None).unwrap().alg_name(), "ML-DSA-44");
    assert_eq!(pk.create_verifier(None).unwrap().alg_name(), "ML-DSA-44");
}

/// The expanded keys have the same conversion: a view of an expanded key signs and verifies as
/// the view of the key it was expanded from, and its workers borrow the expanded key.
#[test]
fn the_expanded_keys_have_the_same_views() {
    use bouncycastle_pqc::mldsa::{MLDSA44PrivateKeyExpanded, MLDSA44PublicKeyExpanded};
    let (pk, sk) = key_pair();
    let (pk_exp, sk_exp) =
        (MLDSA44PublicKeyExpanded::from(&pk), MLDSA44PrivateKeyExpanded::from(&sk));
    let ph = SHA512::hash(MSG);

    let sig = sk.as_prehash::<SHA512>().sign_deterministic(MSG, CTX).unwrap();
    assert_eq!(sk_exp.as_prehash::<SHA512>().sign_deterministic(MSG, CTX), Ok(sig));
    assert_eq!(sk_exp.as_prehash::<SHA512>().sign_ph_deterministic(&ph, CTX), Ok(sig));
    assert_eq!(streamed(&sk_exp.as_prehash::<SHA512>(), &pk_exp.as_prehash::<SHA512>()), sig);
    assert_eq!(pk_exp.as_prehash::<SHA512>().verify(MSG, CTX, &sig), Ok(()));
    assert_eq!(pk_exp.as_prehash::<SHA512>().verify_ph(&ph, CTX, &sig), Ok(()));
    assert_eq!(pk_exp.as_prehash::<SHA3_512>().verify(MSG, CTX, &sig), FAILED);
    assert_eq!(pk_exp.verify(MSG, CTX, &sig), FAILED);

    let mut signer = sk_exp.as_prehash::<SHA512>().create_signer_deterministic(CTX).unwrap();
    assert_eq!(signer.alg_name(), "HashML-DSA-44_with_SHA512");
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), sig);
    let hedged = sk_exp.as_prehash::<SHA512>().sign(&mut DefaultRNG::default(), MSG, CTX).unwrap();
    assert_eq!(pk.as_prehash::<SHA512>().verify(MSG, CTX, &hedged), Ok(()));
}

/// FIPS 204 Section 5.4's strength rule and the `CollisionResistantHash` requirement, cell by
/// cell: each hash, bare and under each wrapper and both nestings, signing and verifying, on
/// each parameter set. A cell is `ok`, `weak` (`PreHashTooWeak`), or `-` where the call does
/// not compile, which the `compile_fail` doctests on `HashMLDSAPrivateKey` hold.
#[test]
fn the_behaviour_matrix() {
    use bouncycastle_pqc::mldsa::{
        MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey,
    };

    fn cell<T>(result: Result<T, SignatureError>) -> &'static str {
        match result {
            Ok(_) => "ok",
            Err(SignatureError::PreHashTooWeak) => "weak",
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    /// Signs through the view `sk` at every signing entry point; the signature, where there is
    /// one, must verify under `pk_waived`, the view over the bare hash with the strength rule
    /// waived. Functions, not macro bodies, so that the signatures leave the stack between
    /// cells.
    fn sign_cell<A, SK, AW, PKW, const N: usize>(sk: &SK, pk_waived: &PKW) -> &'static str
    where
        A: PreHashAlgorithm,
        A::Hash: CollisionResistantHash,
        SK: PreHashSigningKey<A, N> + DeterministicPreHashSigningKey<A, N>,
        AW: SignatureAlgorithm,
        PKW: OneShotVerifyingKey<AW, N>,
    {
        let ph = A::Hash::hash(MSG);
        let det = sk.sign_deterministic(MSG, CTX);
        if let Ok(sig) = &det {
            pk_waived.verify(MSG, CTX, sig).unwrap();
        }
        let outcome = cell(det);
        assert_eq!(cell(sk.create_signer_deterministic(CTX).map(|_| ())), outcome);
        assert_eq!(cell(sk.create_signer(&mut DefaultRNG::default(), CTX).map(|_| ())), outcome);
        assert_eq!(cell(sk.sign(&mut DefaultRNG::default(), MSG, CTX)), outcome);
        assert_eq!(cell(sk.sign_ph(&mut DefaultRNG::default(), &ph, CTX)), outcome);
        assert_eq!(cell(sk.sign_ph_deterministic(&ph, CTX)), outcome);
        outcome
    }
    /// Verifies through the view `pk`, at every verifying entry point, a signature made by
    /// `sk_signs`, a view that signs over the same bare hash.
    fn verify_cell<A, PK, AS, SKS, const N: usize>(pk: &PK, sk_signs: &SKS) -> &'static str
    where
        A: PreHashAlgorithm,
        PK: PreHashVerifyingKey<A, N>,
        AS: SignatureAlgorithm,
        SKS: DeterministicOneShotSigningKey<AS, N>,
    {
        let sig = sk_signs.sign_deterministic(MSG, CTX).unwrap();
        let outcome = cell(pk.verify(MSG, CTX, &sig));
        assert_eq!(cell(pk.create_verifier(CTX).map(|_| ())), outcome);
        assert_eq!(cell(pk.verify_ph(&A::Hash::hash(MSG), CTX, &sig)), outcome);
        outcome
    }
    macro_rules! sign {
        ($sk:expr, $pk:expr, $H:ty, $Bare:ty) => {
            sign_cell(&$sk.as_prehash::<$H>(), &$pk.as_prehash::<AnyStrength<$Bare>>())
        };
    }
    macro_rules! verify {
        ($sk:expr, $pk:expr, $H:ty, $Bare:ty) => {
            verify_cell(
                &$pk.as_prehash::<$H>(),
                &$sk.as_prehash::<AnyStrength<WithoutCollisionResistance<$Bare>>>(),
            )
        };
    }
    /// The ten cells of one hash on one key pair: sign and verify, under the bare hash,
    /// `AnyStrength`, `WithoutCollisionResistance` and the two nestings. `$signs` says whether
    /// the hash is a `CollisionResistantHash`, so that signing with it compiles.
    macro_rules! row {
        ($sk:expr, $pk:expr, $B:ty, signs) => {
            [
                sign!($sk, $pk, $B, $B),
                sign!($sk, $pk, AnyStrength<$B>, $B),
                sign!($sk, $pk, WithoutCollisionResistance<$B>, $B),
                sign!($sk, $pk, AnyStrength<WithoutCollisionResistance<$B>>, $B),
                sign!($sk, $pk, WithoutCollisionResistance<AnyStrength<$B>>, $B),
                verify!($sk, $pk, $B, $B),
                verify!($sk, $pk, AnyStrength<$B>, $B),
                verify!($sk, $pk, WithoutCollisionResistance<$B>, $B),
                verify!($sk, $pk, AnyStrength<WithoutCollisionResistance<$B>>, $B),
                verify!($sk, $pk, WithoutCollisionResistance<AnyStrength<$B>>, $B),
            ]
        };
        ($sk:expr, $pk:expr, $B:ty, verifies_only) => {
            [
                "-",
                "-",
                sign!($sk, $pk, WithoutCollisionResistance<$B>, $B),
                sign!($sk, $pk, AnyStrength<WithoutCollisionResistance<$B>>, $B),
                sign!($sk, $pk, WithoutCollisionResistance<AnyStrength<$B>>, $B),
                verify!($sk, $pk, $B, $B),
                verify!($sk, $pk, AnyStrength<$B>, $B),
                verify!($sk, $pk, WithoutCollisionResistance<$B>, $B),
                verify!($sk, $pk, AnyStrength<WithoutCollisionResistance<$B>>, $B),
                verify!($sk, $pk, WithoutCollisionResistance<AnyStrength<$B>>, $B),
            ]
        };
    }
    macro_rules! rows {
        ($name:expr, $sk:expr, $pk:expr) => {
            [
                ($name, "SHA256", row!($sk, $pk, SHA256, signs)),
                ($name, "SHA512", row!($sk, $pk, SHA512, signs)),
                ($name, "SHAKE128", row!($sk, $pk, SHAKE128, signs)),
                ($name, "SHAKE256", row!($sk, $pk, SHAKE256, signs)),
                ($name, "RIPEMD160", row!($sk, $pk, RIPEMD160, verifies_only)),
            ]
        };
    }

    let (pk44, sk44): (MLDSA44PublicKey, MLDSA44PrivateKey) = key_pair();
    let (pk65, sk65): (MLDSA65PublicKey, MLDSA65PrivateKey) =
        MLDSA65::keygen(&mut DefaultRNG::default()).unwrap();
    let (pk87, sk87): (MLDSA87PublicKey, MLDSA87PrivateKey) =
        MLDSA87::keygen(&mut DefaultRNG::default()).unwrap();
    let mut table = String::new();
    for rows in [rows!("44", sk44, pk44), rows!("65", sk65, pk65), rows!("87", sk87, pk87)] {
        for (set, hash, cells) in rows {
            table.push_str(&format!("{set} {hash:<9} {}\n", cells.join(" ")));
        }
    }
    println!("set hash      sign: bare any wcr any<wcr> wcr<any> | verify: the same five\n{table}");

    // sign: bare, AnyStrength, WCR, Any<WCR>, WCR<Any>; then verify, the same five
    const STRONG: &str = "ok ok ok ok ok ok ok ok ok ok";
    const WEAK: &str = "weak ok weak ok ok weak ok weak ok ok";
    const RIPEMD: &str = "- - weak ok ok weak ok weak ok ok";
    let expected = [
        ("44", "SHA256", STRONG),
        ("44", "SHA512", STRONG),
        ("44", "SHAKE128", STRONG),
        ("44", "SHAKE256", STRONG),
        ("44", "RIPEMD160", RIPEMD),
        ("65", "SHA256", WEAK),
        ("65", "SHA512", STRONG),
        ("65", "SHAKE128", WEAK),
        ("65", "SHAKE256", STRONG),
        ("65", "RIPEMD160", RIPEMD),
        ("87", "SHA256", WEAK),
        ("87", "SHA512", STRONG),
        ("87", "SHAKE128", WEAK),
        ("87", "SHAKE256", STRONG),
        ("87", "RIPEMD160", RIPEMD),
    ];
    let expected: String =
        expected.iter().map(|(set, hash, cells)| format!("{set} {hash:<9} {cells}\n")).collect();
    assert_eq!(table, expected);
}
