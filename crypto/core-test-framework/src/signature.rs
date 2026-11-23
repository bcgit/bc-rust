//! Generic behaviour tests for the signature role traits of `bouncycastle_core::signature_key`
//! and the workers they produce.

use crate::{DUMMY_SEED, FailingRNG};
use bouncycastle_core::errors::{KeyDecodingError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicPreHashSigningKey, DeterministicSigningKey,
    OneShotSigningKey, OneShotVerifyingKey, PreHashAlgorithm, PreHashSigningKey,
    PreHashVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    AlgorithmInfo, CollisionResistantHash, HashOneShot, PrivateKey, PublicKey, RNG,
    SignatureSigner, SignatureVerifier,
};

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";

/// What a signature algorithm does with the `ctx` argument of its constructors and one-shots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtxBehaviour {
    /// The context is bound into the signature, and one longer than 255 bytes is refused.
    Bound,
    /// A non-empty context is a `LengthError`, from the one-shots and from the constructors of
    /// the workers; `None` and the empty context are accepted.
    Refused,
}

/// Instance of the test framework.
pub struct TestFrameworkSignature {
    ctx: CtxBehaviour,
}

impl TestFrameworkSignature {
    /// For an algorithm that binds the context into the signature (`true`,
    /// [`CtxBehaviour::Bound`]) or takes none and refuses one (`false`,
    /// [`CtxBehaviour::Refused`]).
    pub fn new(alg_accepts_ctx: bool) -> Self {
        Self::with_ctx_behaviour(if alg_accepts_ctx {
            CtxBehaviour::Bound
        } else {
            CtxBehaviour::Refused
        })
    }

    /// For an algorithm with the given treatment of the context.
    pub fn with_ctx_behaviour(ctx: CtxBehaviour) -> Self {
        Self { ctx }
    }

    /// The context the streaming suites sign and verify under: one, unless the algorithm
    /// refuses it.
    fn streaming_ctx(&self) -> Option<&'static [u8]> {
        match self.ctx {
            CtxBehaviour::Refused => None,
            CtxBehaviour::Bound => Some(b"streaming"),
        }
    }

    /// The context a constructor must refuse with a `LengthError`: the long one where a context
    /// is bound, any at all where none is taken.
    fn refused_ctx(&self) -> &'static [u8] {
        match self.ctx {
            CtxBehaviour::Bound => &[0u8; 256],
            CtxBehaviour::Refused => b"ctx A",
        }
    }

    /// Every member of [`SigningKey`] and [`VerifyingKey`], of the workers they produce and of
    /// the one-shot roles that come with them, for one algorithm `A` over the key pair `keygen`
    /// returns. The randomness comes from a [`FixedSeedRNG`] whose consecutive 32-byte draws
    /// differ, so the run is repeatable and two signatures of one message still get different
    /// randomizers.
    ///
    /// `run_full_bitflipping_tests` verifies a signature with each of its bits flipped in turn,
    /// which takes a while for a large signature.
    pub fn test_signature<
        A: SignatureAlgorithm,
        PK: VerifyingKey<A, SIG_LEN>,
        SK: SigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) {
        // The seed cycles, so it is longer than any one draw: a 64-byte seed hands two 64-byte
        // RSASSA-PSS/SHA-512 salts the same bytes, and the "two signatures differ" check fails.
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8));
        let (pk, sk) = keygen().unwrap();

        self.check_one_shots(&pk, &sk, &mut rng, run_full_bitflipping_tests);

        // streaming signer, in one chunk and in many; the worker names its algorithm
        let ctx = self.streaming_ctx();
        let mut signer = sk.create_signer(&mut rng, ctx).unwrap();
        assert_eq!(signer.alg_name(), A::ALG_NAME);
        assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
        signer.do_update(DUMMY_SEED);
        let sig = signer.do_final().unwrap();
        pk.verify(DUMMY_SEED, ctx, &sig).unwrap();

        let mut signer = sk.create_signer(&mut rng, ctx).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        let mut out = [0u8; SIG_LEN];
        assert_eq!(signer.do_final_out(&mut out).unwrap(), SIG_LEN);
        pk.verify(DUMMY_SEED, ctx, &out).unwrap();

        // the workers can be held as trait objects
        let mut signer = sk.create_signer(&mut rng, None).unwrap();
        let dyn_signer: &mut dyn SignatureSigner<SIG_LEN> = &mut signer;
        assert_eq!(dyn_signer.alg_name(), A::ALG_NAME);
        dyn_signer.do_update(MSG);
        let sig_dyn = signer.do_final().unwrap();
        let mut verifier = pk.create_verifier(None).unwrap();
        let dyn_verifier: &mut dyn SignatureVerifier = &mut verifier;
        assert_eq!(dyn_verifier.alg_name(), A::ALG_NAME);
        dyn_verifier.do_update(MSG);
        verifier.do_verify_final(&sig_dyn).unwrap();

        // and, held as `Box<dyn ..>`, finished through their `_boxed` finals
        let mut boxed_signer: Box<dyn SignatureSigner<SIG_LEN> + '_> =
            Box::new(sk.create_signer(&mut rng, None).unwrap());
        boxed_signer.do_update(MSG);
        let mut sig_boxed = [0u8; SIG_LEN];
        assert_eq!(boxed_signer.do_final_out_boxed(&mut sig_boxed).unwrap(), SIG_LEN);
        pk.verify(MSG, None, &sig_boxed).unwrap();
        let boxed_verifier = |msg: &[u8]| {
            let mut verifier: Box<dyn SignatureVerifier + '_> =
                Box::new(pk.create_verifier(None).unwrap());
            verifier.do_update(msg);
            verifier
        };
        boxed_verifier(MSG).do_verify_final_boxed(&sig_boxed).unwrap();
        assert!(matches!(
            boxed_verifier(b"this is the wrong message").do_verify_final_boxed(&sig_boxed),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        // a context the algorithm does not take is refused at construction; the empty one is none
        assert!(matches!(
            sk.create_signer(&mut rng, Some(self.refused_ctx())),
            Err(SignatureError::LengthError(_))
        ));
        assert!(sk.create_signer(&mut rng, Some(&[])).is_ok());
        self.check_streaming_verifier(&pk, &sig);
    }

    /// Every member of [`DeterministicSigningKey`] and [`VerifyingKey`], of the workers they
    /// produce and of the one-shot roles that come with them, for one algorithm `A` over the key
    /// pair `keygen` returns.
    pub fn test_deterministic_signature<
        A: SignatureAlgorithm,
        PK: VerifyingKey<A, SIG_LEN>,
        SK: DeterministicSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) {
        let (pk, sk) = keygen().unwrap();

        self.check_deterministic_one_shots(&pk, &sk, run_full_bitflipping_tests);

        // streaming signer, in one chunk and in many, equals the one-shot
        let ctx = self.streaming_ctx();
        let sig = sk.sign_deterministic(DUMMY_SEED, ctx).unwrap();
        let mut signer = sk.create_signer_deterministic(ctx).unwrap();
        // A deterministic variant may name how it picks its nonce (`ECDetDSA-P256` for RFC 6979
        // under the `ECDSAP256` marker), so only the strength is pinned to the marker here.
        assert!(!signer.alg_name().is_empty());
        assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
        signer.do_update(DUMMY_SEED);
        assert_eq!(signer.do_final().unwrap(), sig);

        let mut signer = sk.create_signer_deterministic(ctx).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        let mut out = [0u8; SIG_LEN];
        assert_eq!(signer.do_final_out(&mut out).unwrap(), SIG_LEN);
        assert_eq!(out, sig);

        // a context the algorithm does not take is refused at construction; the empty one is none
        assert!(matches!(
            sk.create_signer_deterministic(Some(self.refused_ctx())),
            Err(SignatureError::LengthError(_))
        ));
        let mut signer = sk.create_signer_deterministic(Some(&[])).unwrap();
        signer.do_update(MSG);
        assert_eq!(signer.do_final().unwrap(), sk.sign_deterministic(MSG, None).unwrap());
        self.check_streaming_verifier(&pk, &sig);
    }

    /// Every member of [`OneShotSigningKey`] and [`OneShotVerifyingKey`], for a key pair that
    /// may have no streaming role. [`test_signature`](Self::test_signature) runs the same checks
    /// on a pair that has one.
    pub fn test_one_shot_signature<
        A: SignatureAlgorithm,
        PK: OneShotVerifyingKey<A, SIG_LEN>,
        SK: OneShotSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) {
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8));
        let (pk, sk) = keygen().unwrap();
        self.check_one_shots(&pk, &sk, &mut rng, run_full_bitflipping_tests);
    }

    /// Every member of [`DeterministicOneShotSigningKey`] and [`OneShotVerifyingKey`], for a key
    /// pair that may have no streaming role.
    /// [`test_deterministic_signature`](Self::test_deterministic_signature) runs the same checks
    /// on a pair that has one.
    pub fn test_deterministic_one_shot_signature<
        A: SignatureAlgorithm,
        PK: OneShotVerifyingKey<A, SIG_LEN>,
        SK: DeterministicOneShotSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) {
        let (pk, sk) = keygen().unwrap();
        self.check_deterministic_one_shots(&pk, &sk, run_full_bitflipping_tests);
    }

    /// The hedged one-shots against the one-shot verify.
    fn check_one_shots<
        A: SignatureAlgorithm,
        PK: OneShotVerifyingKey<A, SIG_LEN>,
        SK: OneShotSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        pk: &PK,
        sk: &SK,
        rng: &mut dyn RNG,
        every_bit: bool,
    ) {
        // round trip, on a short message and a long one; two signatures of one message differ
        let sig = sk.sign(rng, MSG, None).unwrap();
        pk.verify(MSG, None, &sig).unwrap();
        assert_ne!(sig, sk.sign(rng, MSG, None).unwrap(), "two signatures must differ");
        let long = sk.sign(rng, DUMMY_SEED, None).unwrap();
        pk.verify(DUMMY_SEED, None, &long).unwrap();

        // `_out` overwrites what was in the buffer and reports the length
        let mut out = [0xA5u8; SIG_LEN];
        assert_eq!(sk.sign_out(rng, MSG, None, &mut out).unwrap(), SIG_LEN);
        pk.verify(MSG, None, &out).unwrap();

        // ... and leaves nothing stale in it when the RNG fails
        let mut out = [0xA5u8; SIG_LEN];
        assert!(matches!(
            sk.sign_out(&mut FailingRNG, MSG, None, &mut out),
            Err(SignatureError::RNGError(_))
        ));
        assert_eq!(out, [0u8; SIG_LEN]);
        assert!(matches!(sk.sign(&mut FailingRNG, MSG, None), Err(SignatureError::RNGError(_))));

        // no context and the empty context are the same
        let sig_empty = sk.sign(rng, MSG, Some(&[])).unwrap();
        pk.verify(MSG, None, &sig_empty).unwrap();

        // a context, as the algorithm treats one
        let sig_ctx = match self.ctx {
            CtxBehaviour::Refused => {
                let mut out = [0xA5u8; SIG_LEN];
                assert!(matches!(
                    sk.sign_out(rng, MSG, Some(b"ctx A"), &mut out),
                    Err(SignatureError::LengthError(_))
                ));
                assert_eq!(out, [0u8; SIG_LEN]);
                assert!(matches!(
                    sk.sign(rng, MSG, Some(b"ctx A")),
                    Err(SignatureError::LengthError(_))
                ));
                None
            }
            CtxBehaviour::Bound => Some(sk.sign(rng, MSG, Some(b"ctx A")).unwrap()),
        };
        if self.ctx == CtxBehaviour::Bound {
            let mut out = [0xA5u8; SIG_LEN];
            assert!(matches!(
                sk.sign_out(rng, MSG, Some(&[0u8; 256]), &mut out),
                Err(SignatureError::LengthError(_))
            ));
            assert_eq!(out, [0u8; SIG_LEN]);
        }

        self.check_one_shot_verify(pk, &sig, sig_ctx.as_ref(), every_bit);
    }

    /// The deterministic one-shots against the one-shot verify.
    fn check_deterministic_one_shots<
        A: SignatureAlgorithm,
        PK: OneShotVerifyingKey<A, SIG_LEN>,
        SK: DeterministicOneShotSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        pk: &PK,
        sk: &SK,
        every_bit: bool,
    ) {
        // round trip, on a short message and a long one; the same inputs give the same signature
        let sig = sk.sign_deterministic(MSG, None).unwrap();
        pk.verify(MSG, None, &sig).unwrap();
        assert_eq!(sig, sk.sign_deterministic(MSG, None).unwrap());
        let long = sk.sign_deterministic(DUMMY_SEED, None).unwrap();
        pk.verify(DUMMY_SEED, None, &long).unwrap();
        assert_ne!(sig, long);

        // `_out` overwrites what was in the buffer and reports the length
        let mut out = [0xA5u8; SIG_LEN];
        assert_eq!(sk.sign_deterministic_out(MSG, None, &mut out).unwrap(), SIG_LEN);
        assert_eq!(out, sig);

        // no context and the empty context are the same
        assert_eq!(sig, sk.sign_deterministic(MSG, Some(&[])).unwrap());

        // a context, as the algorithm treats one
        let sig_ctx = match self.ctx {
            CtxBehaviour::Refused => {
                let mut out = [0xA5u8; SIG_LEN];
                assert!(matches!(
                    sk.sign_deterministic_out(MSG, Some(b"ctx A"), &mut out),
                    Err(SignatureError::LengthError(_))
                ));
                assert_eq!(out, [0u8; SIG_LEN]);
                assert!(matches!(
                    sk.sign_deterministic(MSG, Some(b"ctx A")),
                    Err(SignatureError::LengthError(_))
                ));
                None
            }
            CtxBehaviour::Bound => Some(sk.sign_deterministic(MSG, Some(b"ctx A")).unwrap()),
        };
        if self.ctx == CtxBehaviour::Bound {
            assert_ne!(Some(sig), sig_ctx);
            // ... and `_out` leaves nothing stale in the buffer when it refuses a long one
            let mut out = [0xA5u8; SIG_LEN];
            assert!(matches!(
                sk.sign_deterministic_out(MSG, Some(&[0u8; 256]), &mut out),
                Err(SignatureError::LengthError(_))
            ));
            assert_eq!(out, [0u8; SIG_LEN]);
        }

        self.check_one_shot_verify(pk, &sig, sig_ctx.as_ref(), every_bit);
    }

    /// What the one-shot verify accepts and refuses: `sig` is over [`MSG`] with no context,
    /// `sig_ctx` over [`MSG`] under `"ctx A"`, for an algorithm that takes one.
    fn check_one_shot_verify<
        A: SignatureAlgorithm,
        PK: OneShotVerifyingKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        pk: &PK,
        sig: &[u8; SIG_LEN],
        sig_ctx: Option<&[u8; SIG_LEN]>,
        every_bit: bool,
    ) {
        // no context and the empty context are the same
        pk.verify(MSG, Some(&[]), sig).unwrap();

        // the wrong message
        assert!(matches!(
            pk.verify(b"this is the wrong message", None, sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        // a context, as the algorithm treats one
        match (self.ctx, sig_ctx) {
            (CtxBehaviour::Bound, Some(sig_ctx)) => {
                pk.verify(MSG, Some(b"ctx A"), sig_ctx).unwrap();
                assert!(matches!(
                    pk.verify(MSG, Some(b"ctx B"), sig_ctx),
                    Err(SignatureError::SignatureVerificationFailed)
                ));
                assert!(matches!(
                    pk.verify(MSG, None, sig_ctx),
                    Err(SignatureError::SignatureVerificationFailed)
                ));
                assert!(matches!(
                    pk.verify(MSG, Some(&[0u8; 256]), sig_ctx),
                    Err(SignatureError::LengthError(_))
                ));
            }
            (CtxBehaviour::Refused, None) => {
                assert!(matches!(
                    pk.verify(MSG, Some(b"ctx A"), sig),
                    Err(SignatureError::LengthError(_))
                ));
            }
            _ => unreachable!("a signature under a context exists unless one is refused"),
        }

        // a signature of the wrong length
        let mut too_long = vec![1u8; SIG_LEN + 2];
        too_long[..SIG_LEN].copy_from_slice(sig);
        assert!(matches!(pk.verify(MSG, None, &too_long), Err(SignatureError::LengthError(_))));
        assert!(matches!(
            pk.verify(MSG, None, &sig[..SIG_LEN - 1]),
            Err(SignatureError::LengthError(_))
        ));

        Self::check_corrupted_signatures(pk, MSG, sig, every_bit);
    }

    /// The streaming verifier: `sig` is over [`DUMMY_SEED`] under the suites' streaming context.
    fn check_streaming_verifier<
        A: SignatureAlgorithm,
        PK: VerifyingKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        pk: &PK,
        sig: &[u8; SIG_LEN],
    ) {
        // in one chunk and in many
        let ctx = self.streaming_ctx();
        let mut verifier = pk.create_verifier(ctx).unwrap();
        assert_eq!(verifier.alg_name(), A::ALG_NAME);
        verifier.do_update(DUMMY_SEED);
        verifier.do_verify_final(sig).unwrap();

        let mut verifier = pk.create_verifier(ctx).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            verifier.do_update(chunk);
        }
        verifier.do_verify_final(sig).unwrap();

        // the wrong message
        let mut verifier = pk.create_verifier(ctx).unwrap();
        verifier.do_update(b"this is the wrong message");
        assert!(matches!(
            verifier.do_verify_final(sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        // a signature of the wrong length
        let mut too_long = vec![1u8; SIG_LEN + 2];
        too_long[..SIG_LEN].copy_from_slice(sig);
        let mut verifier = pk.create_verifier(ctx).unwrap();
        verifier.do_update(DUMMY_SEED);
        assert!(matches!(verifier.do_verify_final(&too_long), Err(SignatureError::LengthError(_))));

        // a context the algorithm does not take is refused at construction; the empty one is none
        assert!(matches!(
            pk.create_verifier(Some(self.refused_ctx())),
            Err(SignatureError::LengthError(_))
        ));
        let mut verifier = pk.create_verifier(Some(&[])).unwrap();
        verifier.do_update(DUMMY_SEED);
        match self.ctx {
            CtxBehaviour::Bound => assert!(matches!(
                verifier.do_verify_final(sig),
                Err(SignatureError::SignatureVerificationFailed)
            )),
            CtxBehaviour::Refused => verifier.do_verify_final(sig).unwrap(),
        }
    }
    /// Every member of [`PreHashSigningKey`] and [`PreHashVerifyingKey`], against the streaming
    /// and one-shot roles of the same keys: a digest made with the key's `Hash` is signed and
    /// verified as the message it is the digest of. The roles over the message are
    /// [`test_signature`](Self::test_signature)'s job.
    pub fn test_ph_signature<
        A: PreHashAlgorithm,
        PK: PreHashVerifyingKey<A, SIG_LEN>,
        SK: PreHashSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) where
        A::Hash: CollisionResistantHash,
    {
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8));
        let (pk, sk) = keygen().unwrap();
        let ph = A::Hash::hash(DUMMY_SEED);

        // the streaming signer hashes the message itself
        let mut signer = sk.create_signer(&mut rng, Some(b"ph")).unwrap();
        assert_eq!(signer.alg_name(), A::ALG_NAME);
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        let sig = signer.do_final().unwrap();

        // ... and its signature verifies over the message and over the digest alike
        let mut verifier = pk.create_verifier(Some(b"ph")).unwrap();
        assert_eq!(verifier.alg_name(), A::ALG_NAME);
        verifier.do_update(DUMMY_SEED);
        verifier.do_verify_final(&sig).unwrap();
        pk.verify_ph(&ph, Some(b"ph"), &sig).unwrap();

        // the one-shots over the digest
        let sig = sk.sign_ph(&mut rng, &ph, Some(b"ph")).unwrap();
        pk.verify_ph(&ph, Some(b"ph"), &sig).unwrap();
        let mut verifier = pk.create_verifier(Some(b"ph")).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            verifier.do_update(chunk);
        }
        verifier.do_verify_final(&sig).unwrap();
        pk.verify(DUMMY_SEED, Some(b"ph"), &sig).unwrap();

        let mut out = [0u8; SIG_LEN];
        assert_eq!(sk.sign_ph_out(&mut rng, &ph, Some(b"ph"), &mut out).unwrap(), SIG_LEN);
        pk.verify_ph(&ph, Some(b"ph"), &out).unwrap();

        // a signature over a digest is one over that digest's message, and no other
        assert!(matches!(
            pk.verify(MSG, Some(b"ph"), &sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));
        assert!(matches!(
            pk.verify_ph(&A::Hash::hash(MSG), Some(b"ph"), &sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        // a digest of the wrong length is refused before anything is signed or checked, and
        // `_out` leaves nothing stale in the buffer
        let short = &ph[..ph.len() - 1];
        assert!(matches!(sk.sign_ph(&mut rng, short, None), Err(SignatureError::LengthError(_))));
        let mut out = [0xA5u8; SIG_LEN];
        assert!(matches!(
            sk.sign_ph_out(&mut rng, short, None, &mut out),
            Err(SignatureError::LengthError(_))
        ));
        assert_eq!(out, [0u8; SIG_LEN]);
        assert!(matches!(
            pk.verify_ph(short, Some(b"ph"), &sig),
            Err(SignatureError::LengthError(_))
        ));

        Self::check_corrupted_ph_signatures::<A, PK, SIG_LEN>(
            &pk,
            &ph,
            &sig,
            run_full_bitflipping_tests,
        );
    }

    /// Every member of [`DeterministicPreHashSigningKey`] and [`PreHashVerifyingKey`], against
    /// the streaming and one-shot roles of the same keys.
    pub fn test_deterministic_ph_signature<
        A: PreHashAlgorithm,
        PK: PreHashVerifyingKey<A, SIG_LEN>,
        SK: DeterministicPreHashSigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) where
        A::Hash: CollisionResistantHash,
    {
        let (pk, sk) = keygen().unwrap();
        let ph = A::Hash::hash(DUMMY_SEED);

        // the one-shot over the digest, the one-shot over the message and the streaming signer
        // agree
        let sig = sk.sign_ph_deterministic(&ph, Some(b"ph")).unwrap();
        assert_eq!(sig, sk.sign_ph_deterministic(&ph, Some(b"ph")).unwrap());
        assert_eq!(sig, sk.sign_deterministic(DUMMY_SEED, Some(b"ph")).unwrap());
        let mut signer = sk.create_signer_deterministic(Some(b"ph")).unwrap();
        // A deterministic variant may name how it picks its nonce (`ECDetDSA-P256` for RFC 6979
        // under the `ECDSAP256` marker), so only the strength is pinned to the marker here.
        assert!(!signer.alg_name().is_empty());
        assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        assert_eq!(signer.do_final().unwrap(), sig);

        let mut out = [0u8; SIG_LEN];
        assert_eq!(sk.sign_ph_deterministic_out(&ph, Some(b"ph"), &mut out).unwrap(), SIG_LEN);
        assert_eq!(out, sig);

        // verifies over the digest and over the message
        pk.verify_ph(&ph, Some(b"ph"), &sig).unwrap();
        let mut verifier = pk.create_verifier(Some(b"ph")).unwrap();
        verifier.do_update(DUMMY_SEED);
        verifier.do_verify_final(&sig).unwrap();

        assert!(matches!(
            pk.verify(MSG, Some(b"ph"), &sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));
        let short = &ph[..ph.len() - 1];
        assert!(matches!(
            sk.sign_ph_deterministic(short, None),
            Err(SignatureError::LengthError(_))
        ));
        let mut out = [0xA5u8; SIG_LEN];
        assert!(matches!(
            sk.sign_ph_deterministic_out(short, None, &mut out),
            Err(SignatureError::LengthError(_))
        ));
        assert_eq!(out, [0u8; SIG_LEN]);
        assert!(matches!(
            pk.verify_ph(short, Some(b"ph"), &sig),
            Err(SignatureError::LengthError(_))
        ));

        Self::check_corrupted_ph_signatures::<A, PK, SIG_LEN>(
            &pk,
            &ph,
            &sig,
            run_full_bitflipping_tests,
        );
    }

    /// A corrupted signature fails: a spot check, and optionally every single-bit flip.
    fn check_corrupted_signatures<
        A: SignatureAlgorithm,
        PK: OneShotVerifyingKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        pk: &PK,
        msg: &[u8],
        sig: &[u8; SIG_LEN],
        every_bit: bool,
    ) {
        let flips: &mut dyn Iterator<Item = (usize, u8)> = if every_bit {
            &mut (0..SIG_LEN).flat_map(|i| (0..8).map(move |j| (i, 1u8 << j)))
        } else {
            &mut core::iter::once((8, 0x0Fu8))
        };
        for (i, mask) in flips {
            let mut bad = *sig;
            bad[i] ^= mask;
            assert!(
                matches!(
                    pk.verify(msg, None, &bad),
                    Err(SignatureError::SignatureVerificationFailed)
                ),
                "byte {i} xor {mask:#x} must not verify"
            );
        }
    }

    /// As [`check_corrupted_signatures`](Self::check_corrupted_signatures), through `verify_ph`.
    fn check_corrupted_ph_signatures<
        A: PreHashAlgorithm,
        PK: PreHashVerifyingKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        pk: &PK,
        ph: &[u8],
        sig: &[u8; SIG_LEN],
        every_bit: bool,
    ) {
        let flips: &mut dyn Iterator<Item = (usize, u8)> = if every_bit {
            &mut (0..SIG_LEN).flat_map(|i| (0..8).map(move |j| (i, 1u8 << j)))
        } else {
            &mut core::iter::once((8, 0x0Fu8))
        };
        for (i, mask) in flips {
            let mut bad = *sig;
            bad[i] ^= mask;
            assert!(
                matches!(
                    pk.verify_ph(ph, Some(b"ph"), &bad),
                    Err(SignatureError::SignatureVerificationFailed)
                ),
                "byte {i} xor {mask:#x} must not verify"
            );
        }
    }
}

/// Instance of the test framework.
pub struct TestFrameworkSignatureKeys {}

impl TestFrameworkSignatureKeys {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Since key generation is not part of any signature trait, the caller supplies a
    /// `keygen` function pointer (the inherent `keygen` associated function on the algorithm struct).
    pub fn test_keys<
        PK: PublicKey<PK_LEN>,
        SK: PrivateKey<SK_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
    ) {
        self.test_boundary_conditions::<PK, SK, PK_LEN, SK_LEN>(keygen);
    }

    /// Tests the correct behaviour on buffers too large / too small.
    fn test_boundary_conditions<
        PK: PublicKey<PK_LEN>,
        SK: PrivateKey<SK_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
    ) {
        let (pk, sk) = keygen().unwrap();

        let pk_bytes = pk.encode();
        assert_eq!(pk_bytes.len(), PK_LEN);
        // too short
        match PK::from_bytes(&pk_bytes[..PK_LEN - 1]) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(PK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&pk_bytes[..PK_LEN]));
        bytes_too_long.push(0xFF);
        match PK::from_bytes(&bytes_too_long) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }

        let sk_bytes = sk.encode();
        assert_eq!(sk_bytes.len(), SK_LEN);
        // too short
        match SK::from_bytes(&sk_bytes[..SK_LEN - 1]) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(SK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&sk_bytes[..SK_LEN]));
        bytes_too_long.push(0xFF);
        match SK::from_bytes(&bytes_too_long) {
            Err(KeyDecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
    }
}
