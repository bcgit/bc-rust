//! `hazmat::AnyStrength<H>`: the pre-hash `H` in everything but HashML-DSA's strength check
//! (FIPS 204 Section 5.4). A pairing the check refuses is accepted through the wrapper at every
//! entry point; a pairing it allows gives the same signature either way. The hash is named where
//! the HashML-DSA key is made, `as_prehash::<AnyStrength<H>>()`.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicPreHashSigningKey, PreHash, PreHashAlgorithm, PreHashSigningKey,
    PreHashVerifyingKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, CollisionResistantHash, HashAlgParams, HashOneShot,
    SignatureSigner, SignatureVerifier,
};
use bouncycastle_mldsa_lowmemory::hazmat::AnyStrength;
use bouncycastle_mldsa_lowmemory::{
    MLDSA44, MLDSA44_SIG_LEN, MLDSA65, MLDSA87, MLDSA87_SIG_LEN, MLDSAPrivateKeyTrait,
    MLDSAPublicKeyTrait, MLDSATrait,
};
use bouncycastle_rng::DefaultRNG;
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

/// Signs and verifies through every entry point of a HashML-DSA key pair, which must accept its
/// hash, and returns the deterministic and the hedged (fixed `rnd`) signatures.
fn every_entry_point<A, PK, SK, const SIG_LEN: usize>(
    pk: &PK,
    sk: &SK,
) -> ([u8; SIG_LEN], [u8; SIG_LEN])
where
    A: PreHashAlgorithm,
    A::Hash: CollisionResistantHash,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
{
    let ph = A::Hash::hash(MSG);
    // 32 bytes is one draw of rnd, so the hedged signers below draw the same one.
    let rnd: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);

    // deterministic: the one-shots over the digest and the message, and the streaming signer
    let det = sk.sign_ph_deterministic(&ph, CTX).unwrap();
    assert_eq!(sk.sign_deterministic(MSG, CTX).unwrap(), det);
    let mut signer = sk.create_signer_deterministic(CTX).unwrap();
    signer.do_update(&MSG[..10]);
    signer.do_update(&MSG[10..]);
    assert_eq!(signer.do_final().unwrap(), det);

    // hedged: likewise
    let hedged = sk.sign_ph(&mut FixedSeedRNG::new(rnd), &ph, CTX).unwrap();
    assert_eq!(sk.sign(&mut FixedSeedRNG::new(rnd), MSG, CTX).unwrap(), hedged);
    let mut signer = sk.create_signer(&mut FixedSeedRNG::new(rnd), CTX).unwrap();
    signer.do_update(MSG);
    assert_eq!(signer.do_final().unwrap(), hedged);
    assert_ne!(hedged, det);

    for sig in [&det, &hedged] {
        // the one-shot verifies over the digest and the message, and the streaming verifier
        pk.verify_ph(&ph, CTX, sig).unwrap();
        pk.verify(MSG, CTX, sig).unwrap();
        let mut verifier = pk.create_verifier(CTX).unwrap();
        verifier.do_update(&MSG[..20]);
        verifier.do_update(&MSG[20..]);
        verifier.do_verify_final(sig).unwrap();

        // and it is still a verification: another context, message or signature fails
        assert_eq!(pk.verify_ph(&ph, None, sig), Err(SignatureError::SignatureVerificationFailed));
        let mut verifier = pk.create_verifier(CTX).unwrap();
        verifier.do_update(b"another message");
        assert_eq!(verifier.do_verify_final(sig), Err(SignatureError::SignatureVerificationFailed));
        let mut tampered = *sig;
        tampered[SIG_LEN / 2] ^= 1;
        assert_eq!(
            pk.verify_ph(&ph, CTX, &tampered),
            Err(SignatureError::SignatureVerificationFailed)
        );
    }

    (det, hedged)
}

/// A pairing FIPS 204 Section 5.4 rules out: the key pair over `H` refuses at every entry
/// point, and the one over `AnyStrength<H>` accepts at every one.
fn weak_pairing<A, PK, SK, AW, PKW, SKW, const SIG_LEN: usize>(
    pk: &PK,
    sk: &SK,
    pk_waived: &PKW,
    sk_waived: &SKW,
) where
    A: PreHashAlgorithm,
    A::Hash: CollisionResistantHash,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    AW: PreHashAlgorithm,
    AW::Hash: CollisionResistantHash,
    PKW: PreHashVerifyingKey<AW, SIG_LEN>,
    SKW: PreHashSigningKey<AW, SIG_LEN> + DeterministicPreHashSigningKey<AW, SIG_LEN>,
{
    let ph = A::Hash::hash(MSG);
    let mut rng = DefaultRNG::default();
    let too_weak = Err(SignatureError::PreHashTooWeak);

    assert!(matches!(sk.create_signer(&mut rng, CTX), Err(SignatureError::PreHashTooWeak)));
    assert_eq!(sk.sign(&mut rng, MSG, CTX), too_weak);
    assert_eq!(sk.sign_ph(&mut rng, &ph, CTX), too_weak);
    assert!(matches!(sk.create_signer_deterministic(CTX), Err(SignatureError::PreHashTooWeak)));
    assert_eq!(sk.sign_deterministic(MSG, CTX), too_weak);
    assert_eq!(sk.sign_ph_deterministic(&ph, CTX), too_weak);
    assert!(matches!(pk.create_verifier(CTX), Err(SignatureError::PreHashTooWeak)));
    assert_eq!(pk.verify(MSG, CTX, &[0u8; SIG_LEN]), Err(SignatureError::PreHashTooWeak));
    assert_eq!(pk.verify_ph(&ph, CTX, &[0u8; SIG_LEN]), Err(SignatureError::PreHashTooWeak));

    let (det, hedged) = every_entry_point(pk_waived, sk_waived);

    // the algorithm and a worker over a waived weak hash report the hash's strength, not the
    // parameter set's
    let weak = A::Hash::MAX_SECURITY_STRENGTH;
    assert_eq!(AW::MAX_SECURITY_STRENGTH, weak);
    assert_eq!(AW::ALG_NAME, A::ALG_NAME);
    let signer = sk_waived.create_signer_deterministic(CTX).unwrap();
    assert_eq!(signer.max_security_strength(), weak);
    let verifier = pk_waived.create_verifier(CTX).unwrap();
    assert_eq!(verifier.max_security_strength(), weak);

    // the wrapper did not turn the check off for the hash itself
    assert_eq!(pk.verify_ph(&ph, CTX, &det), Err(SignatureError::PreHashTooWeak));
    assert_eq!(pk.verify_ph(&ph, CTX, &hedged), Err(SignatureError::PreHashTooWeak));
}

/// [`weak_pairing`] over the views of one key pair under `H` and under `AnyStrength<H>`.
macro_rules! weak_pairing {
    ($pk:expr, $sk:expr, $H:ty) => {
        weak_pairing(
            &$pk.as_prehash::<$H>(),
            &$sk.as_prehash::<$H>(),
            &$pk.as_prehash::<AnyStrength<$H>>(),
            &$sk.as_prehash::<AnyStrength<$H>>(),
        )
    };
}

/// A pairing FIPS 204 Section 5.4 allows, at the parameter set's `strength`: the wrapper changes
/// nothing. The signatures are the same bytes, and each verifies as the other.
fn strong_pairing<A, PK, SK, AW, PKW, SKW, const SIG_LEN: usize>(
    pk: &PK,
    sk: &SK,
    pk_waived: &PKW,
    sk_waived: &SKW,
    strength: SecurityStrength,
) where
    A: PreHashAlgorithm,
    A::Hash: CollisionResistantHash,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    AW: PreHashAlgorithm,
    AW::Hash: CollisionResistantHash,
    PKW: PreHashVerifyingKey<AW, SIG_LEN>,
    SKW: PreHashSigningKey<AW, SIG_LEN> + DeterministicPreHashSigningKey<AW, SIG_LEN>,
{
    let (det, hedged) = every_entry_point(pk, sk);
    let (det_wrapped, hedged_wrapped) = every_entry_point(pk_waived, sk_waived);
    assert_eq!(det_wrapped, det);
    assert_eq!(hedged_wrapped, hedged);

    // the algorithm and a worker over a hash at least as strong report the parameter set's
    // strength, under the same name with the wrapper and without
    assert_eq!(A::MAX_SECURITY_STRENGTH, strength);
    assert_eq!(AW::MAX_SECURITY_STRENGTH, strength);
    assert_eq!(AW::ALG_NAME, A::ALG_NAME);
    let signer = sk_waived.create_signer_deterministic(CTX).unwrap();
    assert_eq!(signer.max_security_strength(), strength);
    assert_eq!(signer.alg_name(), A::ALG_NAME);
    let verifier = pk.create_verifier(CTX).unwrap();
    assert_eq!(verifier.max_security_strength(), strength);
    assert_eq!(verifier.alg_name(), A::ALG_NAME);

    // every_entry_point verified each under the hash it was made with; now crosswise
    let ph = A::Hash::hash(MSG);
    pk_waived.verify_ph(&ph, CTX, &det).unwrap();
    pk.verify_ph(&ph, CTX, &det_wrapped).unwrap();
    let mut verifier = pk_waived.create_verifier(CTX).unwrap();
    verifier.do_update(MSG);
    verifier.do_verify_final(&hedged).unwrap();
    let mut verifier = pk.create_verifier(CTX).unwrap();
    verifier.do_update(MSG);
    verifier.do_verify_final(&hedged_wrapped).unwrap();
}

/// [`strong_pairing`] over the views of one key pair under `H` and under `AnyStrength<H>`.
macro_rules! strong_pairing {
    ($pk:expr, $sk:expr, $H:ty, $alg:ty) => {
        strong_pairing(
            &$pk.as_prehash::<$H>(),
            &$sk.as_prehash::<$H>(),
            &$pk.as_prehash::<AnyStrength<$H>>(),
            &$sk.as_prehash::<AnyStrength<$H>>(),
            <$alg>::MAX_SECURITY_STRENGTH,
        )
    };
}

#[test]
fn weak_pairings_need_the_wrapper() {
    let (pk, sk) = MLDSA44::keygen(&mut DefaultRNG::default()).unwrap();
    weak_pairing!(pk, sk, SHA224);
    weak_pairing!(pk, sk, SHA512_224);
    weak_pairing!(pk, sk, SHA3_224);

    let (pk, sk) = MLDSA65::keygen(&mut DefaultRNG::default()).unwrap();
    weak_pairing!(pk, sk, SHA224);
    weak_pairing!(pk, sk, SHA256);
    weak_pairing!(pk, sk, SHAKE128);

    let (pk, sk) = MLDSA87::keygen(&mut DefaultRNG::default()).unwrap();
    weak_pairing!(pk, sk, SHA224);
    weak_pairing!(pk, sk, SHA512_256);
    weak_pairing!(pk, sk, SHA384);
    weak_pairing!(pk, sk, SHA3_384);
}

#[test]
fn the_wrapper_changes_no_output() {
    let (pk, sk) = MLDSA44::keygen(&mut DefaultRNG::default()).unwrap();
    strong_pairing!(pk, sk, SHA256, MLDSA44);
    strong_pairing!(pk, sk, SHAKE128, MLDSA44);
    strong_pairing!(pk, sk, SHA3_512, MLDSA44);

    let (pk, sk) = MLDSA65::keygen(&mut DefaultRNG::default()).unwrap();
    strong_pairing!(pk, sk, SHA384, MLDSA65);
    strong_pairing!(pk, sk, SHA512, MLDSA65);

    let (pk, sk) = MLDSA87::keygen(&mut DefaultRNG::default()).unwrap();
    strong_pairing!(pk, sk, SHA512, MLDSA87);
    strong_pairing!(pk, sk, SHAKE256, MLDSA87);
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

    let sig = sk.as_prehash::<AnyStrength<SHA224>>().sign_ph_deterministic(&ph, CTX).unwrap();
    assert_eq!(sig, by_mu);
    pk.verify_mu(&mu, &sig).unwrap();

    // SHA3-224 and SHA-512/224 digests are 28 bytes too, under other OIDs
    assert_eq!(
        pk.as_prehash::<AnyStrength<SHA3_224>>().verify_ph(&ph, CTX, &sig),
        Err(SignatureError::SignatureVerificationFailed)
    );
    assert_eq!(
        pk.as_prehash::<AnyStrength<SHA512_224>>().verify_ph(&ph, CTX, &sig),
        Err(SignatureError::SignatureVerificationFailed)
    );
    // and a digest of another length is still a length error
    assert!(matches!(
        pk.as_prehash::<AnyStrength<SHA256>>().verify_ph(&ph, CTX, &sig),
        Err(SignatureError::LengthError(_))
    ));
}

/// RIPEMD-160 has neither the parameter set's strength nor `CollisionResistantHash`. Verifying
/// needs the strength waiver alone; signing needs `hazmat::WithoutCollisionResistance` as well,
/// inside `AnyStrength` or around it, and either way the signature is the one over RIPEMD-160:
/// the same bytes, carrying its OID. That `AnyStrength<RIPEMD160>` does not sign is a
/// `compile_fail` doctest on `HashMLDSAPrivateKey`.
#[test]
fn a_hash_without_collision_resistance_verifies_and_signs_only_when_named() {
    use bouncycastle_core::hazmat::WithoutCollisionResistance;
    use bouncycastle_ripemd::RIPEMD160;
    type Inside = AnyStrength<WithoutCollisionResistance<RIPEMD160>>;
    type Outside = WithoutCollisionResistance<AnyStrength<RIPEMD160>>;

    let (pk, sk) = MLDSA44::keygen(&mut DefaultRNG::default()).unwrap();
    let (det, hedged) = every_entry_point(&pk.as_prehash::<Inside>(), &sk.as_prehash::<Inside>());
    let (det_outside, hedged_outside) =
        every_entry_point(&pk.as_prehash::<Outside>(), &sk.as_prehash::<Outside>());
    assert_eq!(det_outside, det);
    assert_eq!(hedged_outside, hedged);

    // the known answer: ML-DSA over mu = H(tr || 0x01 || |ctx| || ctx || OID || PH_M, 64) with
    // RIPEMD-160's OID (FIPS 204 Algorithm 4, line 23, and Algorithm 7, line 6)
    let ctx = CTX.unwrap();
    let ph = RIPEMD160::hash(MSG);
    let mut tr_m_prime = pk.compute_tr().to_vec();
    tr_m_prime.extend_from_slice(&[0x01, ctx.len() as u8]);
    tr_m_prime.extend_from_slice(ctx);
    tr_m_prime.extend_from_slice(RIPEMD160::OID_DER);
    tr_m_prime.extend_from_slice(&ph);
    let mu: [u8; 64] = SHAKE256::hash(&tr_m_prime).try_into().unwrap();
    let by_mu: [u8; MLDSA44_SIG_LEN] = sk.sign_mu_deterministic(&mu).unwrap();
    assert_eq!(det, by_mu);

    // verifying asks for the strength waiver only
    pk.as_prehash::<AnyStrength<RIPEMD160>>().verify_ph(&ph, CTX, &det).unwrap();
    let mut verifier = pk.as_prehash::<AnyStrength<RIPEMD160>>().create_verifier(CTX).unwrap();
    assert_eq!(verifier.max_security_strength(), SecurityStrength::None);
    verifier.do_update(MSG);
    verifier.do_verify_final(&hedged).unwrap();

    // and neither wrapper stands in for the other: the strength rule still refuses the bare
    // hash, and the collision-resistance wrapper alone
    assert_eq!(
        pk.as_prehash::<RIPEMD160>().verify_ph(&ph, CTX, &det),
        Err(SignatureError::PreHashTooWeak)
    );
    assert_eq!(
        sk.as_prehash::<WithoutCollisionResistance<RIPEMD160>>().sign_ph_deterministic(&ph, CTX),
        Err(SignatureError::PreHashTooWeak)
    );

    // over a hash that has the marker the wrapper changes nothing
    let (det_bare, _) = every_entry_point(&pk.as_prehash::<SHA512>(), &sk.as_prehash::<SHA512>());
    let (det_wrapped, _) = every_entry_point(
        &pk.as_prehash::<WithoutCollisionResistance<SHA512>>(),
        &sk.as_prehash::<WithoutCollisionResistance<SHA512>>(),
    );
    assert_eq!(det_wrapped, det_bare);
}
