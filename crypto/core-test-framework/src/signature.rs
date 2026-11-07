//! Generic behaviour tests for the signature role traits of `bouncycastle_core::signature_key`
//! and the workers they produce.

use crate::DUMMY_SEED;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::{
    DeterministicPreHashSigningKey, DeterministicSigningKey, PreHash, PreHashSigningKey,
    PreHashVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    AlgorithmInfo, RNG, SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle_rng::FixedSeedRNG;

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";

/// Instance of the test framework.
pub struct TestFrameworkSignature {
    /// Does the algorithm bind the context into the signature? `false` for an algorithm that
    /// ignores it (ECDSA, RSA), which is then not expected to refuse a long one either.
    alg_accepts_ctx: bool,
}

impl TestFrameworkSignature {
    ///
    pub fn new(alg_accepts_ctx: bool) -> Self {
        Self { alg_accepts_ctx }
    }

    /// Every member of [`SigningKey`] and [`VerifyingKey`], and of the workers they produce, for
    /// one algorithm `A` over the key pair `keygen` returns. The randomness comes from a
    /// [`FixedSeedRNG`] whose consecutive 32-byte draws differ, so the run is repeatable and two
    /// signatures of one message still get different randomizers.
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
        // RSASSA-PSS/SHA-512 salts the same bytes, and the "two signatures differ" check below fails.
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8));
        let (pk, sk) = keygen().unwrap();

        // one-shots
        let sig = sk.sign(&mut rng, MSG, None).unwrap();
        pk.verify(MSG, None, &sig).unwrap();

        // a randomized algorithm gives a different signature each time
        let sig2 = sk.sign(&mut rng, MSG, None).unwrap();
        assert_ne!(sig, sig2, "two signatures of one message must differ");

        let mut out = [0u8; SIG_LEN];
        assert_eq!(sk.sign_out(&mut rng, MSG, None, &mut out).unwrap(), SIG_LEN);
        pk.verify(MSG, None, &out).unwrap();

        // a large message
        let sig = sk.sign(&mut rng, DUMMY_SEED, None).unwrap();
        pk.verify(DUMMY_SEED, None, &sig).unwrap();

        // streaming signer, in one chunk and in many; the worker names its algorithm
        let mut signer = sk.create_signer(&mut rng, Some(b"streaming")).unwrap();
        assert_eq!(signer.alg_name(), A::ALG_NAME);
        assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
        signer.do_update(DUMMY_SEED);
        let sig = signer.do_final().unwrap();
        pk.verify(DUMMY_SEED, Some(b"streaming"), &sig).unwrap();

        let mut signer = sk.create_signer(&mut rng, Some(b"streaming")).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        let mut out = [0u8; SIG_LEN];
        assert_eq!(signer.do_final_out(&mut out).unwrap(), SIG_LEN);
        pk.verify(DUMMY_SEED, Some(b"streaming"), &out).unwrap();

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

        // streaming verifier, in one chunk and in many
        let mut verifier = pk.create_verifier(Some(b"streaming")).unwrap();
        assert_eq!(verifier.alg_name(), A::ALG_NAME);
        verifier.do_update(DUMMY_SEED);
        verifier.do_verify_final(&sig).unwrap();

        let mut verifier = pk.create_verifier(Some(b"streaming")).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            verifier.do_update(chunk);
        }
        verifier.do_verify_final(&sig).unwrap();

        // the wrong message, through the streaming verifier
        let mut verifier = pk.create_verifier(Some(b"streaming")).unwrap();
        verifier.do_update(b"this is the wrong message");
        assert!(matches!(
            verifier.do_verify_final(&sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        self.check_ctx_and_lengths(&pk, &sk, &mut rng);
        Self::check_corrupted_signatures(
            &pk,
            MSG,
            &sk.sign(&mut rng, MSG, None).unwrap(),
            run_full_bitflipping_tests,
        );
    }

    /// Every member of [`DeterministicSigningKey`] and [`VerifyingKey`], and of the workers they
    /// produce, for one algorithm `A` over the key pair `keygen` returns.
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

        // one-shots; the same inputs give the same signature
        let sig = sk.sign_deterministic(MSG, None).unwrap();
        pk.verify(MSG, None, &sig).unwrap();
        assert_eq!(sig, sk.sign_deterministic(MSG, None).unwrap());

        let mut out = [0u8; SIG_LEN];
        assert_eq!(sk.sign_deterministic_out(MSG, None, &mut out).unwrap(), SIG_LEN);
        assert_eq!(out, sig);

        // streaming signer, in one chunk and in many, equals the one-shot
        let sig = sk.sign_deterministic(DUMMY_SEED, Some(b"streaming")).unwrap();
        let mut signer = sk.create_signer_deterministic(Some(b"streaming")).unwrap();
        // A deterministic variant may name how it picks its nonce (`ECDetDSA-P256` for RFC 6979
        // under the `ECDSAP256` marker), so only the strength is pinned to the marker here.
        assert!(!signer.alg_name().is_empty());
        assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
        signer.do_update(DUMMY_SEED);
        assert_eq!(signer.do_final().unwrap(), sig);

        let mut signer = sk.create_signer_deterministic(Some(b"streaming")).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        let mut out = [0u8; SIG_LEN];
        assert_eq!(signer.do_final_out(&mut out).unwrap(), SIG_LEN);
        assert_eq!(out, sig);

        // streaming verifier, and the wrong message through it
        let mut verifier = pk.create_verifier(Some(b"streaming")).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            verifier.do_update(chunk);
        }
        verifier.do_verify_final(&sig).unwrap();

        let mut verifier = pk.create_verifier(Some(b"streaming")).unwrap();
        verifier.do_update(b"this is the wrong message");
        assert!(matches!(
            verifier.do_verify_final(&sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        // ctx: a signature made under one context does not verify under another
        if self.alg_accepts_ctx {
            let sig = sk.sign_deterministic(MSG, Some(b"ctx A")).unwrap();
            pk.verify(MSG, Some(b"ctx A"), &sig).unwrap();
            assert!(matches!(
                pk.verify(MSG, Some(b"ctx B"), &sig),
                Err(SignatureError::SignatureVerificationFailed)
            ));
            assert!(matches!(
                sk.create_signer_deterministic(Some(&[0u8; 256])),
                Err(SignatureError::LengthError(_))
            ));
        }
        Self::check_signature_lengths(&pk, MSG, &sk.sign_deterministic(MSG, None).unwrap());
        Self::check_corrupted_signatures(
            &pk,
            MSG,
            &sk.sign_deterministic(MSG, None).unwrap(),
            run_full_bitflipping_tests,
        );
    }

    /// Every member of [`PreHashSigningKey`] and [`PreHashVerifyingKey`] for the hash `H`, and
    /// of the workers they produce. The pure-message members are [`test_signature`](Self::test_signature)'s job.
    pub fn test_ph_signature<
        A: SignatureAlgorithm,
        PK: PreHashVerifyingKey<A, SIG_LEN>,
        SK: PreHashSigningKey<A, SIG_LEN>,
        H: PreHash,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) {
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8));
        let (pk, sk) = keygen().unwrap();
        let ph = H::hash(DUMMY_SEED);

        // the streaming pre-hash signer hashes the message itself
        let mut signer = sk.create_ph_signer::<H>(&mut rng, Some(b"ph")).unwrap();
        assert_eq!(signer.alg_name(), A::ALG_NAME);
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        let sig = signer.do_final().unwrap();

        // ... and its signature verifies over the message and over the digest alike
        let mut verifier = pk.create_ph_verifier::<H>(Some(b"ph")).unwrap();
        assert_eq!(verifier.alg_name(), A::ALG_NAME);
        verifier.do_update(DUMMY_SEED);
        verifier.do_verify_final(&sig).unwrap();
        pk.verify_ph::<H>(&ph, Some(b"ph"), &sig).unwrap();

        // the one-shots over the digest
        let sig = sk.sign_ph::<H>(&mut rng, &ph, Some(b"ph")).unwrap();
        pk.verify_ph::<H>(&ph, Some(b"ph"), &sig).unwrap();
        let mut verifier = pk.create_ph_verifier::<H>(Some(b"ph")).unwrap();
        for chunk in DUMMY_SEED.chunks(100) {
            verifier.do_update(chunk);
        }
        verifier.do_verify_final(&sig).unwrap();

        let mut out = [0u8; SIG_LEN];
        assert_eq!(sk.sign_ph_out::<H>(&mut rng, &ph, Some(b"ph"), &mut out).unwrap(), SIG_LEN);
        pk.verify_ph::<H>(&ph, Some(b"ph"), &out).unwrap();

        // a pre-hash signature is not a signature of the bare message, nor of another digest
        assert!(matches!(
            pk.verify(DUMMY_SEED, Some(b"ph"), &sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));
        assert!(matches!(
            pk.verify_ph::<H>(&H::hash(MSG), Some(b"ph"), &sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));

        // a digest of the wrong length is refused before anything is signed or checked
        let short = &ph[..ph.len() - 1];
        assert!(matches!(
            sk.sign_ph::<H>(&mut rng, short, None),
            Err(SignatureError::LengthError(_))
        ));
        assert!(matches!(
            pk.verify_ph::<H>(short, Some(b"ph"), &sig),
            Err(SignatureError::LengthError(_))
        ));

        Self::check_corrupted_ph_signatures::<A, PK, H, SIG_LEN>(
            &pk,
            &ph,
            &sig,
            run_full_bitflipping_tests,
        );
    }

    /// Every member of [`DeterministicPreHashSigningKey`] and [`PreHashVerifyingKey`] for the
    /// hash `H`, and of the workers they produce.
    pub fn test_deterministic_ph_signature<
        A: SignatureAlgorithm,
        PK: PreHashVerifyingKey<A, SIG_LEN>,
        SK: DeterministicPreHashSigningKey<A, SIG_LEN>,
        H: PreHash,
        const SIG_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), SignatureError>,
        run_full_bitflipping_tests: bool,
    ) {
        let (pk, sk) = keygen().unwrap();
        let ph = H::hash(DUMMY_SEED);

        // the one-shot over the digest, and the streaming signer over the message, agree
        let sig = sk.sign_ph_deterministic::<H>(&ph, Some(b"ph")).unwrap();
        assert_eq!(sig, sk.sign_ph_deterministic::<H>(&ph, Some(b"ph")).unwrap());
        let mut signer = sk.create_ph_signer_deterministic::<H>(Some(b"ph")).unwrap();
        // A deterministic variant may name how it picks its nonce (`ECDetDSA-P256` for RFC 6979
        // under the `ECDSAP256` marker), so only the strength is pinned to the marker here.
        assert!(!signer.alg_name().is_empty());
        assert_eq!(signer.max_security_strength(), A::MAX_SECURITY_STRENGTH);
        for chunk in DUMMY_SEED.chunks(100) {
            signer.do_update(chunk);
        }
        assert_eq!(signer.do_final().unwrap(), sig);

        let mut out = [0u8; SIG_LEN];
        assert_eq!(sk.sign_ph_deterministic_out::<H>(&ph, Some(b"ph"), &mut out).unwrap(), SIG_LEN);
        assert_eq!(out, sig);

        // verifies over the digest and over the message
        pk.verify_ph::<H>(&ph, Some(b"ph"), &sig).unwrap();
        let mut verifier = pk.create_ph_verifier::<H>(Some(b"ph")).unwrap();
        verifier.do_update(DUMMY_SEED);
        verifier.do_verify_final(&sig).unwrap();

        assert!(matches!(
            pk.verify(DUMMY_SEED, Some(b"ph"), &sig),
            Err(SignatureError::SignatureVerificationFailed)
        ));
        let short = &ph[..ph.len() - 1];
        assert!(matches!(
            sk.sign_ph_deterministic::<H>(short, None),
            Err(SignatureError::LengthError(_))
        ));
        assert!(matches!(
            pk.verify_ph::<H>(short, Some(b"ph"), &sig),
            Err(SignatureError::LengthError(_))
        ));

        Self::check_corrupted_ph_signatures::<A, PK, H, SIG_LEN>(
            &pk,
            &ph,
            &sig,
            run_full_bitflipping_tests,
        );
    }

    /// The context binding and the long-context refusal, and the signature-length checks.
    fn check_ctx_and_lengths<
        A: SignatureAlgorithm,
        PK: VerifyingKey<A, SIG_LEN>,
        SK: SigningKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        &self,
        pk: &PK,
        sk: &SK,
        rng: &mut dyn RNG,
    ) {
        let sig = sk.sign(rng, MSG, Some(b"ctx A")).unwrap();
        pk.verify(MSG, Some(b"ctx A"), &sig).unwrap();
        if self.alg_accepts_ctx {
            // a signature made under one context does not verify under another, and FIPS 204's
            // 255-byte limit is enforced at construction
            assert!(matches!(
                pk.verify(MSG, Some(b"ctx B"), &sig),
                Err(SignatureError::SignatureVerificationFailed)
            ));
            assert!(matches!(
                sk.create_signer(rng, Some(&[0u8; 256])),
                Err(SignatureError::LengthError(_))
            ));
            assert!(matches!(
                pk.create_verifier(Some(&[0u8; 256])),
                Err(SignatureError::LengthError(_))
            ));
        }
        Self::check_signature_lengths(pk, MSG, &sk.sign(rng, MSG, None).unwrap());
    }

    /// A signature of the wrong length is a `LengthError`, through both verify paths.
    fn check_signature_lengths<
        A: SignatureAlgorithm,
        PK: VerifyingKey<A, SIG_LEN>,
        const SIG_LEN: usize,
    >(
        pk: &PK,
        msg: &[u8],
        sig: &[u8; SIG_LEN],
    ) {
        let mut too_long = vec![1u8; SIG_LEN + 2];
        too_long[..SIG_LEN].copy_from_slice(sig);
        assert!(matches!(pk.verify(msg, None, &too_long), Err(SignatureError::LengthError(_))));
        assert!(matches!(
            pk.verify(msg, None, &sig[..SIG_LEN - 1]),
            Err(SignatureError::LengthError(_))
        ));
        let mut verifier = pk.create_verifier(None).unwrap();
        verifier.do_update(msg);
        assert!(matches!(verifier.do_verify_final(&too_long), Err(SignatureError::LengthError(_))));
    }

    /// A corrupted signature fails: a spot check, and optionally every single-bit flip.
    fn check_corrupted_signatures<
        A: SignatureAlgorithm,
        PK: VerifyingKey<A, SIG_LEN>,
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
        A: SignatureAlgorithm,
        PK: PreHashVerifyingKey<A, SIG_LEN>,
        H: PreHash,
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
                    pk.verify_ph::<H>(ph, Some(b"ph"), &bad),
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
        PK: SignaturePublicKey<PK_LEN>,
        SK: SignaturePrivateKey<SK_LEN>,
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
        PK: SignaturePublicKey<PK_LEN>,
        SK: SignaturePrivateKey<SK_LEN>,
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
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(PK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&pk_bytes[..PK_LEN]));
        bytes_too_long.push(0xFF);
        match PK::from_bytes(&bytes_too_long) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }

        let sk_bytes = sk.encode();
        assert_eq!(sk_bytes.len(), SK_LEN);
        // too short
        match SK::from_bytes(&sk_bytes[..SK_LEN - 1]) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(SK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&sk_bytes[..SK_LEN]));
        bytes_too_long.push(0xFF);
        match SK::from_bytes(&bytes_too_long) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
    }
}
