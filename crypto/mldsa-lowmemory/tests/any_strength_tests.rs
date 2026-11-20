//! `hazmat::AnyStrength<H>`: the pre-hash `H` in everything but HashML-DSA's strength check
//! (FIPS 204 Section 5.4). A pairing the check refuses is accepted through the wrapper at every
//! entry point; a pairing it allows gives the same signature either way.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::{
    DeterministicPreHashSigningKey, PreHash, PreHashSigningKey, PreHashVerifyingKey,
    SignatureAlgorithm,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, HashAlgParams, HashOneShot, SignatureSigner,
    SignatureVerifier,
};
use bouncycastle_mldsa_lowmemory::hazmat::AnyStrength;
use bouncycastle_mldsa_lowmemory::{
    MLDSA44, MLDSA44_SIG_LEN, MLDSA65, MLDSA65_SIG_LEN, MLDSA87, MLDSA87_SIG_LEN,
    MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSATrait,
};
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";
const CTX: Option<&[u8]> = Some(b"any strength");

/// What the wrapper reports is `H`'s, the strength included; the rule is the one difference.
/// That it also computes what `H` does is tested in `bouncycastle-mldsa-common`.
fn reports_the_hash_it_wraps<H: PreHash>() {
    assert_eq!(<AnyStrength<H> as Algorithm>::ALG_NAME, H::ALG_NAME);
    assert_eq!(<AnyStrength<H> as Algorithm>::MAX_SECURITY_STRENGTH, H::MAX_SECURITY_STRENGTH);
    assert_eq!(<AnyStrength<H> as HashAlgParams>::OUTPUT_LEN, H::OUTPUT_LEN);
    assert_eq!(<AnyStrength<H> as HashAlgParams>::BLOCK_LEN, H::BLOCK_LEN);
    assert_eq!(<AnyStrength<H> as AlgorithmOID>::OID, H::OID);
    assert_eq!(<AnyStrength<H> as AlgorithmOID>::OID_DER, H::OID_DER);
    assert!(!H::PRE_HASH_STRENGTH_RULE.is_waived());
    assert!(<AnyStrength<H> as HashAlgParams>::PRE_HASH_STRENGTH_RULE.is_waived());
    assert_eq!(AnyStrength::<H>::hash(MSG), H::hash(MSG));
}

#[test]
fn any_strength_reports_the_hash_it_wraps() {
    reports_the_hash_it_wraps::<SHA224>();
    reports_the_hash_it_wraps::<SHA256>();
    reports_the_hash_it_wraps::<SHA384>();
    reports_the_hash_it_wraps::<SHA512>();
    reports_the_hash_it_wraps::<SHA512_224>();
    reports_the_hash_it_wraps::<SHA512_256>();
    reports_the_hash_it_wraps::<SHA3_224>();
    reports_the_hash_it_wraps::<SHA3_256>();
    reports_the_hash_it_wraps::<SHA3_384>();
    reports_the_hash_it_wraps::<SHA3_512>();
    reports_the_hash_it_wraps::<SHAKE128>();
    reports_the_hash_it_wraps::<SHAKE256>();
}

/// Signs and verifies through all six entry points with the hash `H`, which the key must accept,
/// and returns the deterministic and the hedged (fixed `rnd`) signatures.
fn every_entry_point<A, PK, SK, H, const SIG_LEN: usize>(
    pk: &PK,
    sk: &SK,
) -> ([u8; SIG_LEN], [u8; SIG_LEN])
where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    H: PreHash,
{
    let ph = H::hash(MSG);
    // 32 bytes is one draw of rnd, so the two hedged signers below draw the same one.
    let rnd: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);

    // deterministic: the one-shot over the digest and the streaming signer over the message
    let det = sk.sign_ph_deterministic::<H>(&ph, CTX).unwrap();
    let mut signer = sk.create_ph_signer_deterministic::<H>(CTX).unwrap();
    signer.do_update(&MSG[..10]);
    signer.do_update(&MSG[10..]);
    assert_eq!(signer.do_final().unwrap(), det);

    // hedged: likewise
    let hedged = sk.sign_ph::<H>(&mut FixedSeedRNG::new(rnd), &ph, CTX).unwrap();
    let mut signer = sk.create_ph_signer::<H>(&mut FixedSeedRNG::new(rnd), CTX).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), hedged);
    assert_ne!(hedged, det);

    for sig in [&det, &hedged] {
        // the one-shot verify over the digest and the streaming verifier over the message
        pk.verify_ph::<H>(&ph, CTX, sig).unwrap();
        let mut verifier = pk.create_ph_verifier::<H>(CTX).unwrap();
        verifier.do_update(&MSG[..20]);
        verifier.do_update(&MSG[20..]);
        verifier.do_verify_final(sig).unwrap();

        // and it is still a verification: another context, message or signature fails
        assert_eq!(
            pk.verify_ph::<H>(&ph, None, sig),
            Err(SignatureError::SignatureVerificationFailed)
        );
        let mut verifier = pk.create_ph_verifier::<H>(CTX).unwrap();
        verifier.do_update(b"another message");
        assert_eq!(verifier.do_verify_final(sig), Err(SignatureError::SignatureVerificationFailed));
        let mut tampered = *sig;
        tampered[SIG_LEN / 2] ^= 1;
        assert_eq!(
            pk.verify_ph::<H>(&ph, CTX, &tampered),
            Err(SignatureError::SignatureVerificationFailed)
        );
    }

    (det, hedged)
}

/// A pairing FIPS 204 Section 5.4 rules out: `H` is refused at every entry point, and
/// `AnyStrength<H>` is accepted at every one.
fn weak_pairing<A, PK, SK, H, const SIG_LEN: usize>(pk: &PK, sk: &SK)
where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    H: PreHash,
{
    assert!(H::MAX_SECURITY_STRENGTH < A::MAX_SECURITY_STRENGTH, "the pairing is a weak one");
    let ph = H::hash(MSG);
    let mut rng = DefaultRNG::default();
    let too_weak = Err(SignatureError::PreHashTooWeak);

    assert!(matches!(sk.create_ph_signer::<H>(&mut rng, CTX), Err(SignatureError::PreHashTooWeak)));
    assert_eq!(sk.sign_ph::<H>(&mut rng, &ph, CTX), too_weak);
    assert!(matches!(
        sk.create_ph_signer_deterministic::<H>(CTX),
        Err(SignatureError::PreHashTooWeak)
    ));
    assert_eq!(sk.sign_ph_deterministic::<H>(&ph, CTX), too_weak);
    assert!(matches!(pk.create_ph_verifier::<H>(CTX), Err(SignatureError::PreHashTooWeak)));
    assert_eq!(pk.verify_ph::<H>(&ph, CTX, &[0u8; SIG_LEN]), Err(SignatureError::PreHashTooWeak));

    let (det, hedged) = every_entry_point::<A, PK, SK, AnyStrength<H>, SIG_LEN>(pk, sk);

    // a worker over a waived weak hash reports the hash's strength, not the parameter set's
    let signer = sk.create_ph_signer_deterministic::<AnyStrength<H>>(CTX).unwrap();
    assert_eq!(signer.max_security_strength(), H::MAX_SECURITY_STRENGTH);
    let verifier = pk.create_ph_verifier::<AnyStrength<H>>(CTX).unwrap();
    assert_eq!(verifier.max_security_strength(), H::MAX_SECURITY_STRENGTH);

    // the wrapper did not turn the check off for the hash itself
    assert_eq!(pk.verify_ph::<H>(&ph, CTX, &det), Err(SignatureError::PreHashTooWeak));
    assert_eq!(pk.verify_ph::<H>(&ph, CTX, &hedged), Err(SignatureError::PreHashTooWeak));
}

/// A pairing FIPS 204 Section 5.4 allows: the wrapper changes nothing. The signatures are the
/// same bytes, and each verifies as the other.
fn strong_pairing<A, PK, SK, H, const SIG_LEN: usize>(pk: &PK, sk: &SK)
where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    H: PreHash,
{
    assert!(H::MAX_SECURITY_STRENGTH >= A::MAX_SECURITY_STRENGTH, "the pairing is a strong one");
    let (det, hedged) = every_entry_point::<A, PK, SK, H, SIG_LEN>(pk, sk);
    let (det_wrapped, hedged_wrapped) =
        every_entry_point::<A, PK, SK, AnyStrength<H>, SIG_LEN>(pk, sk);
    assert_eq!(det_wrapped, det);
    assert_eq!(hedged_wrapped, hedged);

    // and a worker over a hash at least as strong reports the parameter set's strength
    let signer = sk.create_ph_signer_deterministic::<AnyStrength<H>>(CTX).unwrap();
    assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
    let verifier = pk.create_ph_verifier::<H>(CTX).unwrap();
    assert_eq!(verifier.max_security_strength(), A::MAX_SECURITY_STRENGTH);

    // every_entry_point verified each under the hash it was made with; now crosswise
    let ph = H::hash(MSG);
    pk.verify_ph::<AnyStrength<H>>(&ph, CTX, &det).unwrap();
    pk.verify_ph::<H>(&ph, CTX, &det_wrapped).unwrap();
    let mut verifier = pk.create_ph_verifier::<AnyStrength<H>>(CTX).unwrap();
    verifier.do_update(MSG);
    verifier.do_verify_final(&hedged).unwrap();
    let mut verifier = pk.create_ph_verifier::<H>(CTX).unwrap();
    verifier.do_update(MSG);
    verifier.do_verify_final(&hedged_wrapped).unwrap();
}

#[test]
fn weak_pairings_need_the_wrapper() {
    let (pk, sk) = MLDSA44::keygen(&mut DefaultRNG::default()).unwrap();
    weak_pairing::<MLDSA44, _, _, SHA224, MLDSA44_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA44, _, _, SHA512_224, MLDSA44_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA44, _, _, SHA3_224, MLDSA44_SIG_LEN>(&pk, &sk);

    let (pk, sk) = MLDSA65::keygen(&mut DefaultRNG::default()).unwrap();
    weak_pairing::<MLDSA65, _, _, SHA224, MLDSA65_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA65, _, _, SHA256, MLDSA65_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA65, _, _, SHAKE128, MLDSA65_SIG_LEN>(&pk, &sk);

    let (pk, sk) = MLDSA87::keygen(&mut DefaultRNG::default()).unwrap();
    weak_pairing::<MLDSA87, _, _, SHA224, MLDSA87_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA87, _, _, SHA512_256, MLDSA87_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA87, _, _, SHA384, MLDSA87_SIG_LEN>(&pk, &sk);
    weak_pairing::<MLDSA87, _, _, SHA3_384, MLDSA87_SIG_LEN>(&pk, &sk);
}

#[test]
fn the_wrapper_changes_no_output() {
    let (pk, sk) = MLDSA44::keygen(&mut DefaultRNG::default()).unwrap();
    strong_pairing::<MLDSA44, _, _, SHA256, MLDSA44_SIG_LEN>(&pk, &sk);
    strong_pairing::<MLDSA44, _, _, SHAKE128, MLDSA44_SIG_LEN>(&pk, &sk);
    strong_pairing::<MLDSA44, _, _, SHA3_512, MLDSA44_SIG_LEN>(&pk, &sk);

    let (pk, sk) = MLDSA65::keygen(&mut DefaultRNG::default()).unwrap();
    strong_pairing::<MLDSA65, _, _, SHA384, MLDSA65_SIG_LEN>(&pk, &sk);
    strong_pairing::<MLDSA65, _, _, SHA512, MLDSA65_SIG_LEN>(&pk, &sk);

    let (pk, sk) = MLDSA87::keygen(&mut DefaultRNG::default()).unwrap();
    strong_pairing::<MLDSA87, _, _, SHA512, MLDSA87_SIG_LEN>(&pk, &sk);
    strong_pairing::<MLDSA87, _, _, SHAKE256, MLDSA87_SIG_LEN>(&pk, &sk);
}

/// The wrapper binds the wrapped hash into the signature as `H` would: the message
/// representative carries `H`'s OID (FIPS 204 Algorithm 4, line 23, and Algorithm 7, line 6),
/// checked through the external-mu path, so two hashes of one digest length stay distinct.
#[test]
fn the_signature_carries_the_wrapped_hash() {
    let (pk, sk) = MLDSA87::keygen(&mut DefaultRNG::default()).unwrap();
    let ctx = CTX.unwrap();
    let ph = SHA224::hash(MSG);

    // mu = H(tr || 0x01 || |ctx| || ctx || OID || PH_M, 64)
    let mut tr_m_prime = pk.compute_tr().to_vec();
    tr_m_prime.extend_from_slice(&[0x01, ctx.len() as u8]);
    tr_m_prime.extend_from_slice(ctx);
    tr_m_prime.extend_from_slice(SHA224::OID_DER);
    tr_m_prime.extend_from_slice(&ph);
    let mu: [u8; 64] = SHAKE256::hash(&tr_m_prime).try_into().unwrap();
    let by_mu: [u8; MLDSA87_SIG_LEN] = sk.sign_mu_deterministic(&mu).unwrap();

    let sig = sk.sign_ph_deterministic::<AnyStrength<SHA224>>(&ph, CTX).unwrap();
    assert_eq!(sig, by_mu);
    pk.verify_mu(&mu, &sig).unwrap();

    // SHA3-224 and SHA-512/224 digests are 28 bytes too, under other OIDs
    assert_eq!(
        pk.verify_ph::<AnyStrength<SHA3_224>>(&ph, CTX, &sig),
        Err(SignatureError::SignatureVerificationFailed)
    );
    assert_eq!(
        pk.verify_ph::<AnyStrength<SHA512_224>>(&ph, CTX, &sig),
        Err(SignatureError::SignatureVerificationFailed)
    );
    // and a digest of another length is still a length error
    assert!(matches!(
        pk.verify_ph::<AnyStrength<SHA256>>(&ph, CTX, &sig),
        Err(SignatureError::LengthError(_))
    ));
}
