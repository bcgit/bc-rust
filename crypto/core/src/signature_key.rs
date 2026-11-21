//! Key objects for digital signatures: how a signer or verifier is made, and the one-shots over
//! them.
//!
//! A signature key is bound to one key encoding and may serve several algorithms with it: an
//! ML-DSA-44 key signs ML-DSA-44 and HashML-DSA-44, an ECDSA P-256 key signs with a random or an
//! RFC 6979 nonce, an RSA key signs PKCS#1 v1.5 and PSS. The algorithm is therefore a type
//! parameter of the role traits, not of the key: `A` in [`SigningKey<A, SIG_LEN>`] is a
//! [`SignatureAlgorithm`] marker that carries the metadata and holds no state. The worker traits
//! in [`crate::traits`], [`SignatureSigner`] and [`SignatureVerifier`], describe only an object
//! that already exists.
//!
//! Three pairs of role traits:
//!
//! * [`SigningKey`] / [`VerifyingKey`]: the algorithm draws randomness per signature (hedged
//!   ML-DSA, ECDSA, RSASSA-PSS), so `create_signer` takes an RNG.
//! * [`DeterministicSigningKey`]: the algorithm draws nothing (RFC 6979 ECDSA, RSASSA-PKCS1-v1_5),
//!   so no method of it takes an RNG. A key may implement both traits for two algorithms; the
//!   constructors have different names so the calls never clash.
//! * [`PreHashSigningKey`] / [`DeterministicPreHashSigningKey`] / [`PreHashVerifyingKey`]: the
//!   message is hashed with a hash the caller picks as a type parameter (HashML-DSA with any
//!   approved hash, RSA over any hash), either by the worker as the message streams in, or by
//!   the caller, who hands over the digest. The signing two take only a
//!   [`CollisionResistantHash`]; verifying takes any.
//!
//! The one-shots over a whole message are roles of their own, which name no worker:
//! [`OneShotSigningKey`], [`DeterministicOneShotSigningKey`] and [`OneShotVerifyingKey`]. Each
//! is a supertrait of the streaming role, so every key that streams has it, and a scheme that
//! cannot take its message in pieces implements it alone: `K: OneShotVerifyingKey<A, N>` is the
//! bound for any verifying key with the whole message in hand.
//!
//! ```text
//! let mut signer = sk.create_signer(&mut rng, Some(b"ctx"))?;   // SigningKey<MLDSA44, _>
//! signer.do_update(msg);
//! let sig = signer.do_final()?;
//! pk.verify(msg, Some(b"ctx"), &sig)?;                    // OneShotVerifyingKey<MLDSA44, _>
//!
//! let sig = sk.sign_ph::<SHA512>(&mut rng, &digest, None)?;     // PreHashSigningKey
//! ```
//!
//! A key with several impls in scope names the algorithm at the call:
//! `SigningKey::<MLDSA44, _>::create_signer(&sk, ..)`.
//!
//! Nothing here instantiates a DRBG for the caller: a method that draws randomness takes
//! `&mut dyn RNG`.
//!
//! # The `ctx` argument
//!
//! Every constructor takes an optional context string, which binds the signature to something
//! the application knows out of band -- "email" against "pdf", a protocol name -- so that a
//! signature lifted out of its intended use fails to verify. A context is only as good as its
//! secrecy from the attacker's influence: it should be a value the application knows by
//! construction, never one read off the wire. `None` and `Some(&[])` are the same. An algorithm
//! without a context input (ECDSA, RSA) documents what it does with one; FIPS 204 limits it to
//! 255 bytes, which an ML-DSA constructor reports as [`SignatureError::LengthError`].

use crate::errors::SignatureError;
use crate::traits::{
    Algorithm, AlgorithmOID, CollisionResistantHash, HashAlgParams, HashOneShot, RNG,
    SignatureSigner, SignatureVerifier,
};

/// Marker for one signature algorithm: ML-DSA-44, ECDSA P-256, ECDSA P-256 with RFC 6979,
/// RSASSA-PSS. It carries the metadata through [`Algorithm`] and holds no state; the role traits
/// take it as a type parameter so that one key can serve every algorithm its encoding fits. The
/// hash of a pre-hash signature is not part of the marker; see [`PreHashSigningKey`].
pub trait SignatureAlgorithm: Algorithm {}

/// A hash that can pre-hash a message for a signature: buildable from nothing, with its lengths
/// and its OID, which the algorithms that bind the hash's identity into the signature (HashML-DSA,
/// PKCS#1 v1.5) need. Implemented for every hash that has the three.
pub trait PreHash: HashOneShot + HashAlgParams + AlgorithmOID {}

impl<H: HashOneShot + HashAlgParams + AlgorithmOID> PreHash for H {}

/// Whether a signature scheme that requires its pre-hash to be at least as strong as its
/// parameter set (HashML-DSA, FIPS 204 Section 5.4) holds a hash type to that. Carried by
/// [`HashAlgParams::PRE_HASH_STRENGTH_RULE`], which every hash function leaves at
/// [`ENFORCED`](Self::ENFORCED).
///
/// The waived value says nothing about the hash and changes nothing a hash computes or reports:
/// [`Algorithm::MAX_SECURITY_STRENGTH`] stays the hash's own, so only a scheme that asks
/// [`is_waived`](Self::is_waived) behaves differently. The value originates
/// only from [`crate::hazmat::waive_pre_hash_strength_rule`]:
///
/// ```compile_fail
/// let rule = bouncycastle_core::signature_key::PreHashStrengthRule { waived: true };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreHashStrengthRule {
    waived: bool,
}

impl PreHashStrengthRule {
    /// The rule applies: a scheme refuses the hash where it is weaker than the parameter set.
    pub const ENFORCED: Self = Self { waived: false };

    /// For [`crate::hazmat::waive_pre_hash_strength_rule`].
    pub(crate) const WAIVED: Self = Self { waived: true };

    /// Whether the type opts out of the rule, so that the scheme accepts it at any strength.
    pub const fn is_waived(&self) -> bool {
        self.waived
    }
}

/// A key that signs with an algorithm that draws randomness for each signature, taking the
/// message as it arrives.
///
/// The signer is the algorithm's ordinary worker; this trait adds where it comes from. The
/// one-shots are the supertrait's.
pub trait SigningKey<A: SignatureAlgorithm, const SIG_LEN: usize>:
    OneShotSigningKey<A, SIG_LEN>
{
    /// The streaming signer this key produces, borrowing the key for `'k`.
    type Signer<'k>: SignatureSigner<SIG_LEN>
    where
        Self: 'k;

    /// Begins a signature, drawing from `rng` whatever the algorithm needs up front: ML-DSA's
    /// `rnd`, ECDSA's `k`, PSS's salt.
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the draw fails; [`SignatureError::LengthError`] if `ctx`
    /// is longer than the algorithm allows.
    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError>;
}

/// A key that signs a whole message with an algorithm that draws randomness for each signature:
/// the role every such key implements, and the only signing role of a scheme that cannot take its
/// message in pieces.
///
/// It is a supertrait of [`SigningKey`]: a key that streams implements it over its own signer
/// with [`sign_out_with_signer`], and its one-shots return the same bytes as streaming the
/// message by hand.
pub trait OneShotSigningKey<A: SignatureAlgorithm, const SIG_LEN: usize> {
    /// Signs `msg` into `output`, which is zeroized first; returns the number of bytes written,
    /// always `SIG_LEN`.
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if a draw from `rng` fails, which every hedged algorithm
    /// makes; [`SignatureError::LengthError`] if `ctx` is longer than the algorithm allows,
    /// which for an algorithm that takes no context is any non-empty one;
    /// [`SignatureError::RejectionLimitExceeded`] for an algorithm that bounds its rejection
    /// loop, and whatever else the algorithm's signing step can fail with.
    fn sign_out(
        &self,
        rng: &mut dyn RNG,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;

    /// The signature of `msg`.
    ///
    /// # Errors
    /// As [`sign_out`](Self::sign_out).
    fn sign(
        &self,
        rng: &mut dyn RNG,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_out(rng, msg, ctx, &mut out)?;
        Ok(out)
    }
}

/// A key that signs with an algorithm that draws nothing per signature: the same signature for
/// the same key, message and context every time. No method takes an RNG. The one-shots are the
/// supertrait's.
pub trait DeterministicSigningKey<A: SignatureAlgorithm, const SIG_LEN: usize>:
    DeterministicOneShotSigningKey<A, SIG_LEN>
{
    /// The streaming signer this key produces, borrowing the key for `'k`.
    type Signer<'k>: SignatureSigner<SIG_LEN>
    where
        Self: 'k;

    /// Begins a signature.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `ctx` is longer than the algorithm allows.
    fn create_signer_deterministic<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError>;
}

/// The deterministic form of [`OneShotSigningKey`]: a key that signs a whole message and draws
/// nothing. It is a supertrait of [`DeterministicSigningKey`]: a key that streams implements it
/// over its own signer with [`sign_out_with_signer`].
pub trait DeterministicOneShotSigningKey<A: SignatureAlgorithm, const SIG_LEN: usize> {
    /// Signs `msg` into `output`, which is zeroized first; returns the number of bytes written,
    /// always `SIG_LEN`.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `ctx` is longer than the algorithm allows, which for an
    /// algorithm that takes no context is any non-empty one, and whatever the algorithm's
    /// signing step can fail with.
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;

    /// The signature of `msg`.
    ///
    /// # Errors
    /// As [`sign_deterministic_out`](Self::sign_deterministic_out).
    fn sign_deterministic(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_deterministic_out(msg, ctx, &mut out)?;
        Ok(out)
    }
}

/// A key that verifies signatures made with `A`, over a message taken as it arrives. A key may
/// implement this and no signing trait, which is what a public key is. The one-shot is the
/// supertrait's.
pub trait VerifyingKey<A: SignatureAlgorithm, const SIG_LEN: usize>:
    OneShotVerifyingKey<A, SIG_LEN>
{
    /// The streaming verifier this key produces, borrowing the key for `'k`.
    type Verifier<'k>: SignatureVerifier
    where
        Self: 'k;

    /// Begins a verification.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `ctx` is longer than the algorithm allows.
    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError>;
}

/// A key that verifies a signature made with `A` over a whole message: the role every verifying
/// key implements, and the only one of a scheme that needs the signature before it can read the
/// message. It is a supertrait of [`VerifyingKey`]: a key that streams implements it over its
/// own verifier with [`verify_with_verifier`].
pub trait OneShotVerifyingKey<A: SignatureAlgorithm, const SIG_LEN: usize> {
    /// Checks `sig` over `msg`.
    ///
    /// # Errors
    /// [`SignatureError::SignatureVerificationFailed`] if the signature does not verify;
    /// [`SignatureError::LengthError`] if `sig` is not `SIG_LEN` bytes or `ctx` is longer than
    /// the algorithm allows, which for an algorithm that takes no context is any non-empty one.
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError>;
}

/// Signs `msg` through `signer` into `output`: the body of [`OneShotSigningKey::sign_out`] and
/// [`DeterministicOneShotSigningKey::sign_deterministic_out`] for a key with a streaming signer,
/// which passes the result of its `create_signer` or `create_signer_deterministic` straight in.
/// The signer must be one nothing has been fed to. Returns the number of bytes written, always
/// `SIG_LEN`.
///
/// `output` is zeroized before anything else, so it holds zeros when `signer` is an error; after
/// an error from the signer's final it holds what that final left.
///
/// # Errors
/// The error in `signer`, or that of the signer's final.
pub fn sign_out_with_signer<S: SignatureSigner<SIG_LEN>, const SIG_LEN: usize>(
    signer: Result<S, SignatureError>,
    msg: &[u8],
    output: &mut [u8; SIG_LEN],
) -> Result<usize, SignatureError> {
    output.fill(0);
    let mut signer = signer?;
    signer.do_update(msg);
    signer.do_final_out(output)
}

/// Checks `sig` over `msg` through `verifier`: the body of [`OneShotVerifyingKey::verify`] for a
/// key with a streaming verifier. The verifier must be one nothing has been fed to.
///
/// # Errors
/// Those of the verifier's final: [`SignatureError::SignatureVerificationFailed`] if the
/// signature does not verify, [`SignatureError::LengthError`] if `sig` is not the algorithm's
/// signature length.
pub fn verify_with_verifier<V: SignatureVerifier>(
    mut verifier: V,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SignatureError> {
    verifier.do_update(msg);
    verifier.do_verify_final(sig)
}

/// A [`SigningKey`] whose algorithm can also sign a digest of the message made with a hash the
/// caller chooses: HashML-DSA (FIPS 204 Section 5.4) with any approved hash, RSA over any hash.
///
/// The hash is a type parameter of each method, so one key and one algorithm marker serve every
/// hash. The digest may be taken by the worker as the message streams in, through
/// [`create_ph_signer`](Self::create_ph_signer), or handed over ready-made, through
/// [`sign_ph_out`](Self::sign_ph_out); the two produce the same signature.
///
/// Signing requires the hash to be a [`CollisionResistantHash`]; [`PreHashVerifyingKey`] does
/// not, so what was signed over a hash without the marker can still be verified.
pub trait PreHashSigningKey<A: SignatureAlgorithm, const SIG_LEN: usize>:
    SigningKey<A, SIG_LEN>
{
    /// The streaming pre-hash signer for the hash `H`, borrowing the key for `'k`.
    type PreHashSigner<'k, H: PreHash>: SignatureSigner<SIG_LEN>
    where
        Self: 'k;

    /// Begins a pre-hash signature: the worker hashes the message with `H` as it streams in and
    /// signs the digest.
    ///
    /// # Errors
    /// As [`SigningKey::create_signer`]; also [`SignatureError::PreHashTooWeak`] if the algorithm
    /// does not accept `H` (FIPS 204 Section 5.4 requires a hash of at least the parameter set's
    /// strength for HashML-DSA).
    fn create_ph_signer<'k, H: PreHash + CollisionResistantHash>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::PreHashSigner<'k, H>, SignatureError>;

    /// One-shot over a digest the caller already has: signs `ph`, the `H` hash of the message,
    /// into `output`, which is zeroized first; returns the number of bytes written, always
    /// `SIG_LEN`.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `ph` is not `H::OUTPUT_LEN` bytes; otherwise as
    /// [`create_ph_signer`](Self::create_ph_signer).
    fn sign_ph_out<H: PreHash + CollisionResistantHash>(
        &self,
        rng: &mut dyn RNG,
        ph: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;

    /// One-shot over a digest the caller already has: the signature of `ph`, the `H` hash of the
    /// message.
    ///
    /// # Errors
    /// As [`sign_ph_out`](Self::sign_ph_out).
    fn sign_ph<H: PreHash + CollisionResistantHash>(
        &self,
        rng: &mut dyn RNG,
        ph: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_ph_out::<H>(rng, ph, ctx, &mut out)?;
        Ok(out)
    }
}

/// The pre-hash form of [`DeterministicSigningKey`]; see [`PreHashSigningKey`] for the shape.
pub trait DeterministicPreHashSigningKey<A: SignatureAlgorithm, const SIG_LEN: usize>:
    DeterministicSigningKey<A, SIG_LEN>
{
    /// The streaming pre-hash signer for the hash `H`, borrowing the key for `'k`.
    type PreHashSigner<'k, H: PreHash>: SignatureSigner<SIG_LEN>
    where
        Self: 'k;

    /// Begins a pre-hash signature: the worker hashes the message with `H` as it streams in and
    /// signs the digest.
    ///
    /// # Errors
    /// As [`DeterministicSigningKey::create_signer_deterministic`]; also
    /// [`SignatureError::PreHashTooWeak`] if the algorithm does not accept `H`.
    fn create_ph_signer_deterministic<'k, H: PreHash + CollisionResistantHash>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::PreHashSigner<'k, H>, SignatureError>;

    /// One-shot over a digest the caller already has: signs `ph`, the `H` hash of the message,
    /// into `output`, which is zeroized first; returns the number of bytes written, always
    /// `SIG_LEN`.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `ph` is not `H::OUTPUT_LEN` bytes; otherwise as
    /// [`create_ph_signer_deterministic`](Self::create_ph_signer_deterministic).
    fn sign_ph_deterministic_out<H: PreHash + CollisionResistantHash>(
        &self,
        ph: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;

    /// One-shot over a digest the caller already has: the signature of `ph`, the `H` hash of the
    /// message.
    ///
    /// # Errors
    /// As [`sign_ph_deterministic_out`](Self::sign_ph_deterministic_out).
    fn sign_ph_deterministic<H: PreHash + CollisionResistantHash>(
        &self,
        ph: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_ph_deterministic_out::<H>(ph, ctx, &mut out)?;
        Ok(out)
    }
}

/// A [`VerifyingKey`] whose algorithm can also verify over a digest of the message made with a
/// hash the caller chooses; the counterpart of [`PreHashSigningKey`].
pub trait PreHashVerifyingKey<A: SignatureAlgorithm, const SIG_LEN: usize>:
    VerifyingKey<A, SIG_LEN>
{
    /// The streaming pre-hash verifier for the hash `H`, borrowing the key for `'k`.
    type PreHashVerifier<'k, H: PreHash>: SignatureVerifier
    where
        Self: 'k;

    /// Begins a pre-hash verification: the worker hashes the message with `H` as it streams in
    /// and verifies over the digest.
    ///
    /// # Errors
    /// As [`VerifyingKey::create_verifier`]; also [`SignatureError::PreHashTooWeak`] if the
    /// algorithm does not accept `H`.
    fn create_ph_verifier<'k, H: PreHash>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::PreHashVerifier<'k, H>, SignatureError>;

    /// One-shot over a digest the caller already has: checks `sig` over `ph`, the `H` hash of the
    /// message.
    ///
    /// # Errors
    /// [`SignatureError::LengthError`] if `ph` is not `H::OUTPUT_LEN` bytes or `sig` is not
    /// `SIG_LEN` bytes; [`SignatureError::SignatureVerificationFailed`] if the signature does not
    /// verify; otherwise as [`create_ph_verifier`](Self::create_ph_verifier).
    fn verify_ph<H: PreHash>(
        &self,
        ph: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError>;
}
