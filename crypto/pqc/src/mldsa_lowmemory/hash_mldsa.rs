//! HashML-DSA (FIPS 204 Section 5.4): ML-DSA over a digest of the message rather than the
//! message, for the case where the message is hashed before the signing key is known or on a
//! different machine.
//!
//! A HashML-DSA key is a view of an ML-DSA key under one hash, made by `as_prehash::<H>()`: a
//! reference to the key, which copies nothing. [`HashMLDSAPrivateKey`] and
//! [`HashMLDSAPublicKey`] implement the signature roles over [`HashMLDSA<P, H>`], so any hash of
//! at least the parameter set's strength goes with any ML-DSA key, SHAKE128 and SHAKE256 among
//! them as the fixed-length digests of RFC 8702 Section 3.1 (Algorithm 4's third case is
//! SHAKE128); that it is an approved one (FIPS 204 Section 5.4) is the caller's to ensure:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{
//!     OneShotVerifyingKey, PreHashSigningKey, PreHashVerifyingKey, SigningKey,
//! };
//! use bouncycastle_core::traits::{HashOneShot, SignatureSigner};
//! use bouncycastle_pqc::mldsa_lowmemory::{MLDSA65, MLDSATrait};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_digest::sha2::SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let msg = b"The quick brown fox jumped over the lazy dog";
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // The worker hashes the message as it streams in ...
//! let mut signer = sk.as_prehash::<SHA512>().create_signer(&mut rng, None).unwrap();
//! signer.do_update(msg);
//! let sig = signer.do_final().unwrap();
//!
//! // ... or the digest is made elsewhere, even before the key exists.
//! let ph = SHA512::hash(msg);
//! let sig2 = sk.as_prehash::<SHA512>().sign_ph(&mut rng, &ph, None).unwrap();
//!
//! // Either verifies over the message or over the digest.
//! let pk = pk.as_prehash::<SHA512>();
//! pk.verify(msg, None, &sig).unwrap();
//! match pk.verify_ph(&ph, None, &sig2) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! A HashML-DSA signature is not an ML-DSA signature of the message: the domain separator and
//! the hash's OID go into the message representative (Algorithm 4, line 23), so the ML-DSA key
//! rejects it, as a view over another hash does. FIPS 204 requires the hash to carry at least
//! the parameter set's strength (Section 5.4 and footnote 6), which is why SHA-256 pairs with
//! ML-DSA-44 only; a weaker hash is refused when a signer or verifier is made and by the
//! one-shots, unless it is named as [`hazmat::AnyStrength<H>`](crate::mldsa_lowmemory::hazmat::AnyStrength),
//! which opts out of that check and leaves the signature only as strong as the hash.
//!
//! Signing also requires the hash to be a [`CollisionResistantHash`], which `AnyStrength` does
//! not waive; verifying does not. See [`HashMLDSAPrivateKey`].
//!
//! # 🚨 Security Considerations 🚨
//!
//! FIPS 204 Section 5.4: "While a single key pair may be used for both ML-DSA and HashML-DSA
//! signatures, it is recommended that each key pair only be used for one version or the other."
//! The same section asks that a signature's identifier say which of the two it is and which
//! hash made the pre-hash; nothing in the signature or the key does.

use crate::mldsa_lowmemory::mldsa::{MLDSA_RND_LEN, Rnd, check_filled_tr, draw_rnd};
use crate::mldsa_lowmemory::params::{
    MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams, SignatureLen,
};
use crate::mldsa_lowmemory::{
    MLDSAPrivateKeyTrait, MLDSAPublicKey, MLDSAPublicKeyTrait, MLDSASeedPrivateKey,
};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::finish_token;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicPreHashSigningKey, DeterministicSigningKey,
    OneShotSigningKey, OneShotVerifyingKey, PreHash, PreHashAlgorithm, PreHashSigningKey,
    PreHashVerifyingKey, SignatureAlgorithm, SigningKey, VerifyingKey, verify_with_verifier,
};

use crate::mldsa_common::mu_builder::compute_mu_ph;
use crate::mldsa_common::params::weaker_of;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, CollisionResistantHash, FinishToken, RNG, SignatureSigner,
    SignatureVerifier,
};
use bouncycastle_digest::sha2::{SHA256, SHA512};
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// The buffer the pre-hash digest is finished into: 512 bits, the widest digest of a hash in
/// this library.
const MAX_PH_LEN: usize = 64;

/*** Constants ***/

#[doc(inline)]
pub use crate::mldsa_common::{
    HASH_ML_DSA_44_with_SHA256_NAME, HASH_ML_DSA_44_with_SHA512_NAME,
    HASH_ML_DSA_65_with_SHA512_NAME, HASH_ML_DSA_87_with_SHA512_NAME,
};

/*** The algorithm ***/

/// HashML-DSA over the parameter set `P` with the pre-hash `H` (FIPS 204 Section 5.4): the
/// algorithm marker the roles of [`HashMLDSAPrivateKey`] and [`HashMLDSAPublicKey`] are
/// implemented over. It carries the name, `HashML-DSA-44_with_SHA512` and so on, and the
/// strength, which is the weaker of the parameter set's and the hash's: the parameter set's for
/// every pairing the strength rule allows, the hash's under
/// [`AnyStrength`](crate::mldsa_lowmemory::hazmat::AnyStrength). A hash wrapper that reports `H`'s name
/// (`AnyStrength<H>`, `WithoutCollisionResistance<H>`) gives the name of the pairing over `H`.
///
/// The name is built for any pairing, and only four are registered names (the aliases below). A
/// pairing Section 5.4 rules out, ML-DSA-65 with SHA-256 say, has a name too; it is not a
/// registered pairing, and signing or verifying with it is reachable only under `AnyStrength`.
/// The name is at most 48 bytes, which leaves a hash 29: a hash with a longer name does not
/// compile as `H`.
pub struct HashMLDSA<P: MLDSAParams, H: PreHash> {
    _phantom: PhantomData<(P, H)>,
}

impl<P: MLDSAParams, H: PreHash> HashMLDSA<P, H> {
    const NAME: ConstStr<48> = ConstStr::concat(&["Hash", P::ALG_NAME, "_with_", H::ALG_NAME]);
}

impl<P: MLDSAParams, H: PreHash> Algorithm for HashMLDSA<P, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        weaker_of(P::MAX_SECURITY_STRENGTH, H::MAX_SECURITY_STRENGTH);
}

impl<P: MLDSAParams, H: PreHash> SignatureAlgorithm for HashMLDSA<P, H> {}

impl<P: MLDSAParams, H: PreHash> PreHashAlgorithm for HashMLDSA<P, H> {
    type Hash = H;
}

/// HashML-DSA-44-with-SHA256, the only SHA-256 pairing: FIPS 204 Section 5.4 requires the
/// pre-hash to provide "at least 𝜆 bits of classical security strength against both collision
/// and second preimage attacks", which SHA-256 meets for ML-DSA-44 (𝜆 = 128) and not for
/// ML-DSA-65 or -87.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA256 = HashMLDSA<MLDSA44Params, SHA256>;

/// HashML-DSA-44-with-SHA512.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA512 = HashMLDSA<MLDSA44Params, SHA512>;

/// HashML-DSA-65-with-SHA512.
#[allow(non_camel_case_types)]
pub type HashMLDSA65_with_SHA512 = HashMLDSA<MLDSA65Params, SHA512>;

/// HashML-DSA-87-with-SHA512.
#[allow(non_camel_case_types)]
pub type HashMLDSA87_with_SHA512 = HashMLDSA<MLDSA87Params, SHA512>;

/// The OIDs NIST assigned in the Computer Security Objects Register to the SHA-512 pairings:
/// id-hash-ml-dsa-44-with-sha512 { sigAlgs 32 }, -65 { sigAlgs 33 }, -87 { sigAlgs 34 }. The
/// SHA-256 pairing has none.
impl AlgorithmOID for HashMLDSA44_with_SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 32];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x20];
}

impl AlgorithmOID for HashMLDSA65_with_SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 33];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x21];
}

impl AlgorithmOID for HashMLDSA87_with_SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 34];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x22];
}

/*** The workers ***/

/// FIPS 204 Section 5.4: the hash must give at least the parameter set's strength, unless the
/// caller opted out by naming it as [`AnyStrength`](crate::mldsa_lowmemory::hazmat::AnyStrength), which waives
/// the rule.
fn check_hash_strength<P: MLDSAParams, H: PreHash>() -> Result<(), SignatureError> {
    if !H::PRE_HASH_STRENGTH_RULE.is_waived() && H::MAX_SECURITY_STRENGTH < P::MAX_SECURITY_STRENGTH
    {
        return Err(SignatureError::PreHashTooWeak);
    }
    Ok(())
}

/// Algorithm 4, line 1 and Algorithm 5, line 1: the context is at most 255 bytes.
fn parse_ctx(ctx: Option<&[u8]>) -> Result<([u8; 255], usize), SignatureError> {
    let ctx = ctx.unwrap_or(&[]);
    if ctx.len() > 255 {
        return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
    }
    let mut ctx_buf = [0u8; 255];
    ctx_buf[..ctx.len()].copy_from_slice(ctx);
    Ok((ctx_buf, ctx.len()))
}

fn check_ph_len<H: PreHash>(ph: &[u8]) -> Result<(), SignatureError> {
    if ph.len() != H::OUTPUT_LEN {
        return Err(SignatureError::LengthError("pre-hash is not the hash's output length"));
    }
    Ok(())
}

/// A HashML-DSA signature in progress: hashes the message with `H` as it streams in, then signs
/// the digest (FIPS 204 Algorithm 4 over Algorithm 7). Made by [`SigningKey::create_signer`] or
/// [`DeterministicSigningKey::create_signer_deterministic`] on a [`HashMLDSAPrivateKey`]; it
/// borrows the ML-DSA key behind the view.
pub struct HashMLDSASigner<'k, P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>, H: PreHash> {
    _phantom: PhantomData<P>,
    sk: &'k SK,
    hash: H,
    // HashML-DSA buffers the message in the pre-hash, not in mu, so the context waits here.
    ctx: [u8; 255],
    ctx_len: usize,
    rnd: Rnd,
}

fn new_ph_signer<'k, P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>, H: PreHash>(
    sk: &'k SK,
    rnd: &[u8; MLDSA_RND_LEN],
    ctx: Option<&[u8]>,
) -> Result<HashMLDSASigner<'k, P, SK, H>, SignatureError> {
    check_hash_strength::<P, H>()?;
    check_filled_tr(sk.tr())?;
    let (ctx, ctx_len) = parse_ctx(ctx)?;
    let mut signer = HashMLDSASigner {
        _phantom: PhantomData,
        sk,
        hash: H::default(),
        ctx,
        ctx_len,
        rnd: Rnd::new(),
    };
    *signer.rnd = *rnd;
    Ok(signer)
}

impl<P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>, H: PreHash> Algorithm
    for HashMLDSASigner<'_, P, SK, H>
{
    const ALG_NAME: &'static str = HashMLDSA::<P, H>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = HashMLDSA::<P, H>::MAX_SECURITY_STRENGTH;
}

impl<P: SignatureLen<SIG_LEN>, SK: MLDSAPrivateKeyTrait<P>, H: PreHash, const SIG_LEN: usize>
    SignatureSigner<SIG_LEN> for HashMLDSASigner<'_, P, SK, H>
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn finish_signature_into(
        &mut self,
        token: &FinishToken,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        const { assert!(H::OUTPUT_LEN <= MAX_PH_LEN, "the pre-hash digest fits MAX_PH_LEN") };
        let mut ph = [0u8; MAX_PH_LEN];
        let ph = &mut ph[..H::OUTPUT_LEN];
        self.hash.finish_into(token, ph);
        sign_ph_with_rnd::<P, SK, H, SIG_LEN>(
            self.sk,
            ph,
            Some(&self.ctx[..self.ctx_len]),
            &self.rnd,
            output,
        )
    }
}

/// The body of the one-shots over a message: the message hashed in this frame, then
/// [`sign_ph_with_rnd`] with `rnd`, which the caller holds. No signer is built, so `rnd` is not
/// moved with one and left behind.
fn sign_msg_with_rnd<
    P: SignatureLen<SIG_LEN>,
    SK: MLDSAPrivateKeyTrait<P>,
    H: PreHash,
    const SIG_LEN: usize,
>(
    sk: &SK,
    msg: &[u8],
    ctx: Option<&[u8]>,
    rnd: &[u8; MLDSA_RND_LEN],
    output: &mut [u8; SIG_LEN],
) -> Result<usize, SignatureError> {
    output.fill(0);
    check_filled_tr(sk.tr())?;
    check_hash_strength::<P, H>()?;
    const { assert!(H::OUTPUT_LEN <= MAX_PH_LEN, "the pre-hash digest fits MAX_PH_LEN") };
    let mut hash = H::default();
    hash.do_update(msg);
    let mut ph = [0u8; MAX_PH_LEN];
    let ph = &mut ph[..H::OUTPUT_LEN];
    hash.finish_into(&finish_token(), ph);
    sign_ph_with_rnd::<P, SK, H, SIG_LEN>(sk, ph, ctx, rnd, output)
}

/// Algorithm 4 from line 23 on, over a digest: the message representative with the hash's OID,
/// then Algorithm 7 with the given `rnd`.
fn sign_ph_with_rnd<
    P: SignatureLen<SIG_LEN>,
    SK: MLDSAPrivateKeyTrait<P>,
    H: PreHash,
    const SIG_LEN: usize,
>(
    sk: &SK,
    ph: &[u8],
    ctx: Option<&[u8]>,
    rnd: &[u8; MLDSA_RND_LEN],
    output: &mut [u8; SIG_LEN],
) -> Result<usize, SignatureError> {
    output.fill(0);
    check_hash_strength::<P, H>()?;
    check_ph_len::<H>(ph)?;
    // Algorithm 4, lines 1 and 23, and Algorithm 7, line 6
    let mu = compute_mu_ph(sk.tr(), ctx, H::OID_DER, ph)?;
    // 24: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    sk.sign_mu_with_rnd_out(&mu, rnd, output)
}

/// Algorithm 5 from line 1 on, over a digest.
fn verify_ph<
    P: SignatureLen<SIG_LEN>,
    PK: MLDSAPublicKeyTrait<P>,
    H: PreHash,
    const SIG_LEN: usize,
>(
    pk: &PK,
    ph: &[u8],
    ctx: Option<&[u8]>,
    sig: &[u8],
) -> Result<(), SignatureError> {
    check_hash_strength::<P, H>()?;
    check_ph_len::<H>(ph)?;
    let sig: &[u8; SIG_LEN] = sig
        .try_into()
        .map_err(|_| SignatureError::LengthError("Signature value is not the correct length."))?;
    // Algorithm 5, line 1, Algorithm 4, line 23, and Algorithm 7, line 6
    let mu = compute_mu_ph(&pk.compute_tr(), ctx, H::OID_DER, ph)?;
    pk.verify_mu(&mu, sig)
}

/// A HashML-DSA verification in progress: hashes the message with `H` as it streams in, then
/// verifies over the digest (FIPS 204 Algorithm 5 over Algorithm 8). Made by
/// [`VerifyingKey::create_verifier`] on a [`HashMLDSAPublicKey`]; it borrows the ML-DSA key
/// behind the view.
pub struct HashMLDSAVerifier<
    'k,
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P>,
    H: PreHash,
    const SIG_LEN: usize,
> {
    _phantom: PhantomData<P>,
    pk: &'k PK,
    hash: H,
    ctx: [u8; 255],
    ctx_len: usize,
}

fn new_ph_verifier<
    'k,
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P>,
    H: PreHash,
    const SIG_LEN: usize,
>(
    pk: &'k PK,
    ctx: Option<&[u8]>,
) -> Result<HashMLDSAVerifier<'k, P, PK, H, SIG_LEN>, SignatureError> {
    check_hash_strength::<P, H>()?;
    let (ctx, ctx_len) = parse_ctx(ctx)?;
    Ok(HashMLDSAVerifier { _phantom: PhantomData, pk, hash: H::default(), ctx, ctx_len })
}

impl<P: SignatureLen<SIG_LEN>, PK: MLDSAPublicKeyTrait<P>, H: PreHash, const SIG_LEN: usize>
    Algorithm for HashMLDSAVerifier<'_, P, PK, H, SIG_LEN>
{
    const ALG_NAME: &'static str = HashMLDSA::<P, H>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = HashMLDSA::<P, H>::MAX_SECURITY_STRENGTH;
}

impl<P: SignatureLen<SIG_LEN>, PK: MLDSAPublicKeyTrait<P>, H: PreHash, const SIG_LEN: usize>
    SignatureVerifier for HashMLDSAVerifier<'_, P, PK, H, SIG_LEN>
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn finish_signature_verify(
        &mut self,
        token: &FinishToken,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        const { assert!(H::OUTPUT_LEN <= MAX_PH_LEN, "the pre-hash digest fits MAX_PH_LEN") };
        let mut ph = [0u8; MAX_PH_LEN];
        let ph = &mut ph[..H::OUTPUT_LEN];
        self.hash.finish_into(token, ph);
        verify_ph::<P, PK, H, SIG_LEN>(self.pk, ph, Some(&self.ctx[..self.ctx_len]), sig)
    }
}

/*** The keys: views of the ML-DSA keys under one hash ***/

/// A HashML-DSA private key: the view `as_prehash::<H>()` gives of an ML-DSA private key, which
/// signs with [`HashMLDSA<P, H>`] through the signing roles, the message streamed or whole, and
/// through [`PreHashSigningKey`] and [`DeterministicPreHashSigningKey`] over a digest the caller
/// made with `H`. It is a reference to the key and holds no key material, so copying it copies
/// none. A signer it makes borrows the key, not the view:
///
/// ```
/// use bouncycastle_core::signature_key::DeterministicSigningKey;
/// use bouncycastle_core::traits::SignatureSigner;
/// use bouncycastle_pqc::mldsa_lowmemory::MLDSA44PrivateKey;
/// use bouncycastle_digest::sha2::SHA512;
///
/// fn signer(sk: &MLDSA44PrivateKey) -> impl SignatureSigner<2420> + '_ {
///     sk.as_prehash::<SHA512>().create_signer_deterministic(None).unwrap()
/// }
/// ```
///
/// The signer cannot outlive the key:
///
/// ```compile_fail,E0597
/// use bouncycastle_core::signature_key::DeterministicSigningKey;
/// use bouncycastle_pqc::mldsa_lowmemory::{MLDSA44, MLDSATrait};
/// use bouncycastle_rng::HashDRBG_SHA512;
/// use bouncycastle_digest::sha2::SHA512;
///
/// let signer = {
///     let (_pk, sk) = MLDSA44::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
///     sk.as_prehash::<SHA512>().create_signer_deterministic(None).unwrap()
/// };
/// drop(signer);
/// ```
///
/// It signs only where `H` is a [`CollisionResistantHash`]. A hash without the marker does not
/// sign, under [`AnyStrength`](crate::mldsa_lowmemory::hazmat::AnyStrength) or not, over a digest or over the
/// message:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::DeterministicPreHashSigningKey;
/// use bouncycastle_pqc::mldsa_lowmemory::hazmat::AnyStrength;
/// use bouncycastle_pqc::mldsa_lowmemory::{MLDSA44, MLDSATrait};
/// use bouncycastle_digest::ripemd::RIPEMD160;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let (_pk, sk) = MLDSA44::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
/// let sk = sk.as_prehash::<AnyStrength<RIPEMD160>>();
/// let _ = DeterministicPreHashSigningKey::sign_ph_deterministic(&sk, &[0u8; 20], None);
/// ```
///
/// ```compile_fail,E0277
/// # use bouncycastle_core::signature_key::SigningKey;
/// # use bouncycastle_pqc::mldsa_lowmemory::hazmat::AnyStrength;
/// # use bouncycastle_pqc::mldsa_lowmemory::{MLDSA44, MLDSATrait};
/// # use bouncycastle_digest::ripemd::RIPEMD160;
/// # use bouncycastle_rng::HashDRBG_SHA512;
/// # let mut rng = HashDRBG_SHA512::new_from_os();
/// # let (_pk, sk) = MLDSA44::keygen(&mut rng).unwrap();
/// let sk = sk.as_prehash::<AnyStrength<RIPEMD160>>();
/// let _ = SigningKey::create_signer(&sk, &mut rng, None);
/// ```
///
/// It verifies as `AnyStrength<H>`, and signs where the caller names
/// [`WithoutCollisionResistance`](bouncycastle_core::hazmat::WithoutCollisionResistance) as
/// well, inside `AnyStrength` or around it:
///
/// ```
/// use bouncycastle_core::hazmat::WithoutCollisionResistance;
/// use bouncycastle_core::signature_key::{DeterministicPreHashSigningKey, PreHashVerifyingKey};
/// use bouncycastle_pqc::mldsa_lowmemory::hazmat::AnyStrength;
/// use bouncycastle_pqc::mldsa_lowmemory::{MLDSA44, MLDSATrait};
/// use bouncycastle_digest::ripemd::RIPEMD160;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let (pk, sk) = MLDSA44::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
/// type H = AnyStrength<WithoutCollisionResistance<RIPEMD160>>;
/// let sig = sk.as_prehash::<H>().sign_ph_deterministic(&[0u8; 20], None)?;
/// pk.as_prehash::<AnyStrength<RIPEMD160>>().verify_ph(&[0u8; 20], None, &sig)?;
/// # Ok::<(), bouncycastle_core::errors::SignatureError>(())
/// ```
///
/// It is not an ML-DSA key: the roles over [`MLDSA`](crate::mldsa_lowmemory::MLDSA) are the plain key's.
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::DeterministicOneShotSigningKey;
/// use bouncycastle_pqc::mldsa_lowmemory::{MLDSA44, MLDSA44PrivateKey};
/// use bouncycastle_digest::sha2::SHA512;
///
/// fn sign(sk: &MLDSA44PrivateKey) {
///     let _ = DeterministicOneShotSigningKey::<MLDSA44, 2420>::sign_deterministic(
///         &sk.as_prehash::<SHA512>(),
///         b"msg",
///         None,
///     );
/// }
/// ```
pub struct HashMLDSAPrivateKey<'k, P: MLDSAParams, H, SK = MLDSASeedPrivateKey<P>> {
    sk: &'k SK,
    _phantom: PhantomData<(P, H)>,
}

/// A HashML-DSA public key: the view `as_prehash::<H>()` gives of an ML-DSA public key, which
/// verifies [`HashMLDSA<P, H>`] signatures through [`VerifyingKey`], the message streamed or
/// whole, and through [`PreHashVerifyingKey`] over a digest the caller made with `H`. It is a
/// reference to the key, and a verifier it makes borrows the key, not the view.
///
/// It verifies under its own hash and no other, and it is not an ML-DSA key:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::OneShotVerifyingKey;
/// use bouncycastle_pqc::mldsa_lowmemory::{HashMLDSA44_with_SHA256, MLDSA44PublicKey};
/// use bouncycastle_digest::sha2::SHA512;
///
/// fn verify(pk: &MLDSA44PublicKey, sig: &[u8]) {
///     let pk = pk.as_prehash::<SHA512>();
///     let _ =
///         OneShotVerifyingKey::<HashMLDSA44_with_SHA256, 2420>::verify(&pk, b"msg", None, sig);
/// }
/// ```
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::OneShotVerifyingKey;
/// use bouncycastle_pqc::mldsa_lowmemory::{MLDSA44, MLDSA44PublicKey};
/// use bouncycastle_digest::sha2::SHA512;
///
/// fn verify(pk: &MLDSA44PublicKey, sig: &[u8]) {
///     let pk = pk.as_prehash::<SHA512>();
///     let _ = OneShotVerifyingKey::<MLDSA44, 2420>::verify(&pk, b"msg", None, sig);
/// }
/// ```
pub struct HashMLDSAPublicKey<'k, P: MLDSAParams, H, PK = MLDSAPublicKey<P>> {
    pk: &'k PK,
    _phantom: PhantomData<(P, H)>,
}

// Written out, not derived: a derive would ask `P`, `H` and the key type to be `Copy`, and the
// view is a reference whatever they are.
impl<P: MLDSAParams, H, SK> Clone for HashMLDSAPrivateKey<'_, P, H, SK> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: MLDSAParams, H, SK> Copy for HashMLDSAPrivateKey<'_, P, H, SK> {}

impl<P: MLDSAParams, H, PK> Clone for HashMLDSAPublicKey<'_, P, H, PK> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: MLDSAParams, H, PK> Copy for HashMLDSAPublicKey<'_, P, H, PK> {}

impl<P: MLDSAParams> MLDSASeedPrivateKey<P> {
    /// The pre-hash form of this key, a [`HashMLDSA<P, H>`] signing key. The view borrows the key;
    /// no key material is copied or moved.
    pub fn as_prehash<H: PreHash>(&self) -> HashMLDSAPrivateKey<'_, P, H> {
        HashMLDSAPrivateKey { sk: self, _phantom: PhantomData }
    }
}

impl<P: MLDSAParams> MLDSAPublicKey<P> {
    /// The pre-hash form of this key, a [`HashMLDSA<P, H>`] verifying key. The view borrows the key
    /// and copies nothing.
    pub fn as_prehash<H: PreHash>(&self) -> HashMLDSAPublicKey<'_, P, H> {
        HashMLDSAPublicKey { pk: self, _phantom: PhantomData }
    }
}

/*** The signing roles, on the view of any private key type ***/

impl<'k, P, H, SK, const SIG_LEN: usize> SigningKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPrivateKey<'k, P, H, SK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
    SK: MLDSAPrivateKeyTrait<P>,
{
    // The signer borrows the key the view refers to, for the key's lifetime and not the
    // view's, so it outlives a view that was a temporary.
    type Signer<'s>
        = HashMLDSASigner<'k, P, SK, H>
    where
        Self: 's;

    fn create_signer<'s>(
        &'s self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'s>, SignatureError> {
        let mut rnd = Rnd::new();
        draw_rnd(rng, &mut rnd)?;
        new_ph_signer(self.sk, &rnd, ctx)
    }
}

impl<P, H, SK, const SIG_LEN: usize> OneShotSigningKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPrivateKey<'_, P, H, SK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
    SK: MLDSAPrivateKeyTrait<P>,
{
    fn sign_out(
        &self,
        rng: &mut dyn RNG,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        let mut rnd = Rnd::new();
        draw_rnd(rng, &mut rnd)?;
        sign_msg_with_rnd::<P, SK, H, SIG_LEN>(self.sk, msg, ctx, &rnd, output)
    }
}

/// FIPS 204 Algorithm 4, line 5, the deterministic variant: `rnd` is 32 zero bytes.
impl<'k, P, H, SK, const SIG_LEN: usize> DeterministicSigningKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPrivateKey<'k, P, H, SK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
    SK: MLDSAPrivateKeyTrait<P>,
{
    type Signer<'s>
        = HashMLDSASigner<'k, P, SK, H>
    where
        Self: 's;

    fn create_signer_deterministic<'s>(
        &'s self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'s>, SignatureError> {
        new_ph_signer(self.sk, &[0u8; MLDSA_RND_LEN], ctx)
    }
}

impl<P, H, SK, const SIG_LEN: usize> DeterministicOneShotSigningKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPrivateKey<'_, P, H, SK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
    SK: MLDSAPrivateKeyTrait<P>,
{
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        sign_msg_with_rnd::<P, SK, H, SIG_LEN>(self.sk, msg, ctx, &[0u8; MLDSA_RND_LEN], output)
    }
}

impl<P, H, SK, const SIG_LEN: usize> PreHashSigningKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPrivateKey<'_, P, H, SK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
    SK: MLDSAPrivateKeyTrait<P>,
{
    fn sign_ph_out(
        &self,
        rng: &mut dyn RNG,
        ph: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        let mut rnd = Rnd::new();
        draw_rnd(rng, &mut rnd)?;
        sign_ph_with_rnd::<P, SK, H, SIG_LEN>(self.sk, ph, ctx, &rnd, output)
    }
}

impl<P, H, SK, const SIG_LEN: usize> DeterministicPreHashSigningKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPrivateKey<'_, P, H, SK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
    SK: MLDSAPrivateKeyTrait<P>,
{
    fn sign_ph_deterministic_out(
        &self,
        ph: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        sign_ph_with_rnd::<P, SK, H, SIG_LEN>(self.sk, ph, ctx, &[0u8; MLDSA_RND_LEN], output)
    }
}

/*** The verifying roles ***/

impl<'k, P, H, PK, const SIG_LEN: usize> VerifyingKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPublicKey<'k, P, H, PK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash,
    PK: MLDSAPublicKeyTrait<P>,
{
    // As the signer: the verifier borrows the key, not the view.
    type Verifier<'s>
        = HashMLDSAVerifier<'k, P, PK, H, SIG_LEN>
    where
        Self: 's;

    fn create_verifier<'s>(
        &'s self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'s>, SignatureError> {
        new_ph_verifier(self.pk, ctx)
    }
}

impl<P, H, PK, const SIG_LEN: usize> OneShotVerifyingKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPublicKey<'_, P, H, PK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash,
    PK: MLDSAPublicKeyTrait<P>,
{
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        verify_with_verifier(self.create_verifier(ctx)?, msg, sig)
    }
}

impl<P, H, PK, const SIG_LEN: usize> PreHashVerifyingKey<HashMLDSA<P, H>, SIG_LEN>
    for HashMLDSAPublicKey<'_, P, H, PK>
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash,
    PK: MLDSAPublicKeyTrait<P>,
{
    fn verify_ph(&self, ph: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        verify_ph::<P, PK, H, SIG_LEN>(self.pk, ph, ctx, sig)
    }
}
