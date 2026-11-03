//! HashML-DSA (FIPS 204 Section 5.4): ML-DSA over a digest of the message rather than the
//! message, for the case where the message is hashed before the signing key is known or on a
//! different machine.
//!
//! The hash is a type parameter of the key's pre-hash methods, so any approved hash goes with any
//! ML-DSA key:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{PreHashSigningKey, PreHashVerifyingKey, SigningKey};
//! use bouncycastle_core::traits::{HashOneShot, SignatureSigner};
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let msg = b"The quick brown fox jumped over the lazy dog";
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // The worker hashes the message as it streams in ...
//! let mut signer = sk.create_ph_signer::<SHA512>(&mut rng, None).unwrap();
//! signer.do_update(msg);
//! let sig = signer.do_final().unwrap();
//!
//! // ... or the digest is made elsewhere, even before the key exists.
//! let ph = SHA512::hash(msg);
//! let sig2 = sk.sign_ph::<SHA512>(&mut rng, &ph, None).unwrap();
//!
//! // Either verifies over the message or over the digest.
//! pk.verify_ph::<SHA512>(&ph, None, &sig).unwrap();
//! match pk.verify_ph::<SHA512>(&ph, None, &sig2) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! A HashML-DSA signature is not an ML-DSA signature of the message: the domain separator and
//! the hash's OID go into the message representative (Algorithm 4, line 23), so a pure-message
//! verifier rejects it. FIPS 204 requires the hash to carry at least the parameter set's strength
//! (Section 5.4 and footnote 6), which is why SHA-256 pairs with ML-DSA-44 only; a weaker hash is
//! refused when the signer is made. The named pairings of FIPS 204 are the [`HashMLDSA`] marker
//! types below, which carry the pairing's name and OID.

use crate::mldsa::{MLDSA, MLDSA_RND_LEN, draw_rnd};
use crate::params::{
    HashMLDSA44_with_SHA256Params, HashMLDSA44_with_SHA512Params, HashMLDSA65_with_SHA512Params,
    HashMLDSA87_with_SHA512Params, HashMLDSAParams, MLDSAParams, SignatureLen,
};
use crate::{MLDSAPrivateKeyTrait, MLDSAPublicKey, MLDSAPublicKeyTrait, MLDSASeedPrivateKey};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicPreHashSigningKey, PreHash, PreHashSigningKey, PreHashVerifyingKey,
};
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, RNG, SignatureSigner, SignatureVerifier};
use bouncycastle_mldsa_common::mu_builder::compute_mu_ph;
use core::marker::PhantomData;

/*** Constants ***/

#[doc(inline)]
pub use bouncycastle_mldsa_common::{
    HASH_ML_DSA_44_with_SHA256_NAME, HASH_ML_DSA_44_with_SHA512_NAME,
    HASH_ML_DSA_65_with_SHA512_NAME, HASH_ML_DSA_87_with_SHA512_NAME,
};

/*** The named pairings ***/

/// A named HashML-DSA pairing of FIPS 204: the parameter set and the hash, with the pairing's
/// name and, where NIST assigned one, its OID. It is a marker only: signing and verifying go
/// through the ML-DSA keys' pre-hash methods with the hash as the type parameter, and the marker
/// says which hash that is for a given name.
pub struct HashMLDSA<P: HashMLDSAParams> {
    _phantom: PhantomData<P>,
}

/// HashML-DSA-44-with-SHA256, the only SHA-256 pairing: FIPS 204 Section 5.4 requires the
/// pre-hash to provide "at least lambda bits of classical security strength against both
/// collision and second preimage attacks", which SHA-256 meets for ML-DSA-44 (lambda = 128) and
/// not for ML-DSA-65 or -87.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA256 = HashMLDSA<HashMLDSA44_with_SHA256Params>;

/// HashML-DSA-44-with-SHA512.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA512 = HashMLDSA<HashMLDSA44_with_SHA512Params>;

/// HashML-DSA-65-with-SHA512.
#[allow(non_camel_case_types)]
pub type HashMLDSA65_with_SHA512 = HashMLDSA<HashMLDSA65_with_SHA512Params>;

/// HashML-DSA-87-with-SHA512.
#[allow(non_camel_case_types)]
pub type HashMLDSA87_with_SHA512 = HashMLDSA<HashMLDSA87_with_SHA512Params>;

impl<P: HashMLDSAParams> Algorithm for HashMLDSA<P> {
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

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

/// FIPS 204 Section 5.4: the hash must give at least the parameter set's strength.
fn check_hash_strength<P: MLDSAParams, H: PreHash>() -> Result<(), SignatureError> {
    if H::MAX_SECURITY_STRENGTH < P::MAX_SECURITY_STRENGTH {
        return Err(SignatureError::GenericError(
            "HashML-DSA: the pre-hash is weaker than the ML-DSA parameter set (FIPS 204 Section 5.4)",
        ));
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
/// the digest (FIPS 204 Algorithm 4 over Algorithm 7). Made by
/// [`PreHashSigningKey::create_ph_signer`] on an ML-DSA private key, which it borrows; the key
/// is expanded from its seed only when the signature is finished.
pub struct HashMLDSASigner<'k, P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>, H: PreHash> {
    _phantom: PhantomData<P>,
    sk: &'k SK,
    hash: H,
    // HashML-DSA buffers the message in the pre-hash, not in mu, so the context waits here.
    ctx: [u8; 255],
    ctx_len: usize,
    rnd: [u8; MLDSA_RND_LEN],
}

fn new_ph_signer<'k, P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>, H: PreHash>(
    sk: &'k SK,
    rnd: [u8; MLDSA_RND_LEN],
    ctx: Option<&[u8]>,
) -> Result<HashMLDSASigner<'k, P, SK, H>, SignatureError> {
    check_hash_strength::<P, H>()?;
    let (ctx, ctx_len) = parse_ctx(ctx)?;
    Ok(HashMLDSASigner { _phantom: PhantomData, sk, hash: H::default(), ctx, ctx_len, rnd })
}

/// The worker reports the ML-DSA parameter set it signs with; the hash is in its type.
impl<P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>, H: PreHash> Algorithm
    for HashMLDSASigner<'_, P, SK, H>
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P: SignatureLen<SIG_LEN>, SK: MLDSAPrivateKeyTrait<P>, H: PreHash, const SIG_LEN: usize>
    SignatureSigner<SIG_LEN> for HashMLDSASigner<'_, P, SK, H>
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.do_final_out(&mut out)?;
        Ok(out)
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        let ph = self.hash.do_final();
        sign_ph_with_rnd::<P, SK, H, SIG_LEN>(
            self.sk,
            &ph,
            Some(&self.ctx[..self.ctx_len]),
            self.rnd,
            output,
        )
    }
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
    rnd: [u8; MLDSA_RND_LEN],
    output: &mut [u8; SIG_LEN],
) -> Result<usize, SignatureError> {
    output.fill(0);
    check_hash_strength::<P, H>()?;
    check_ph_len::<H>(ph)?;
    // Algorithm 4, lines 1 and 23, and Algorithm 7, line 6
    let mu = compute_mu_ph(&sk.tr(), ctx, H::OID_DER, ph)?;
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
/// [`PreHashVerifyingKey::create_ph_verifier`] on an ML-DSA public key, which it borrows.
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
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P: SignatureLen<SIG_LEN>, PK: MLDSAPublicKeyTrait<P>, H: PreHash, const SIG_LEN: usize>
    SignatureVerifier for HashMLDSAVerifier<'_, P, PK, H, SIG_LEN>
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let ph = self.hash.do_final();
        verify_ph::<P, PK, H, SIG_LEN>(self.pk, &ph, Some(&self.ctx[..self.ctx_len]), sig)
    }
}

/*** The role impls ***/

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> PreHashSigningKey<MLDSA<P>, SIG_LEN>
    for MLDSASeedPrivateKey<P>
{
    type PreHashSigner<'k, H: PreHash>
        = HashMLDSASigner<'k, P, Self, H>
    where
        Self: 'k;

    fn create_ph_signer<'k, H: PreHash>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::PreHashSigner<'k, H>, SignatureError> {
        new_ph_signer(self, draw_rnd(rng)?, ctx)
    }

    fn sign_ph_out<H: PreHash>(
        &self,
        rng: &mut dyn RNG,
        ph: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        let rnd = draw_rnd(rng)?;
        sign_ph_with_rnd::<P, Self, H, SIG_LEN>(self, ph, ctx, rnd, output)
    }
}

/// The deterministic variant over a pre-hash; see
/// [`DeterministicSigningKey`](bouncycastle_core::signature_key::DeterministicSigningKey) on the key.
impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize>
    DeterministicPreHashSigningKey<MLDSA<P>, SIG_LEN> for MLDSASeedPrivateKey<P>
{
    type PreHashSigner<'k, H: PreHash>
        = HashMLDSASigner<'k, P, Self, H>
    where
        Self: 'k;

    fn create_ph_signer_deterministic<'k, H: PreHash>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::PreHashSigner<'k, H>, SignatureError> {
        new_ph_signer(self, [0u8; MLDSA_RND_LEN], ctx)
    }

    fn sign_ph_deterministic_out<H: PreHash>(
        &self,
        ph: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        sign_ph_with_rnd::<P, Self, H, SIG_LEN>(self, ph, ctx, [0u8; MLDSA_RND_LEN], output)
    }
}

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> PreHashVerifyingKey<MLDSA<P>, SIG_LEN>
    for MLDSAPublicKey<P>
{
    type PreHashVerifier<'k, H: PreHash>
        = HashMLDSAVerifier<'k, P, Self, H, SIG_LEN>
    where
        Self: 'k;

    fn create_ph_verifier<'k, H: PreHash>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::PreHashVerifier<'k, H>, SignatureError> {
        new_ph_verifier(self, ctx)
    }

    fn verify_ph<H: PreHash>(
        &self,
        ph: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        verify_ph::<P, Self, H, SIG_LEN>(self, ph, ctx, sig)
    }
}
