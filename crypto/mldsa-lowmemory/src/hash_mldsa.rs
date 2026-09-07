//! This implements the HashML-DSA algorithm specified in FIPS 204 which is useful for cases
//! it is necessary to process the message to be signed in chunks, and it is not possible to use the external mu
//! mode of [`MLDSA`]; possibly because it is necessary to digest the message before knowing which public key
//! will sign it.
//!
//! HashML-DSA is a full signature algorithm implementing the [`Signer`] and [`SignatureVerifier`] traits:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa_lowmemory::{MLDSATrait, HashMLDSA65_with_SHA512, HashMLDSA44_with_SHA512};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = HashMLDSA65_with_SHA512::keygen().unwrap();
//!
//! let sig = HashMLDSA65_with_SHA512::sign(&sk, msg, None).unwrap();
//! // This is the signature value that can be saved to a file or whatever it is needed.
//!
//! match HashMLDSA65_with_SHA512::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! There is also access to the pre-hashed function available from [`PHSigner`] and [`PHSignatureVerifier`]:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{
//!     Hash, PHSignatureVerifier, PHSigner, SignatureVerifier, Signer,
//! };
//! use bouncycastle_sha2::SHA512;
//! use bouncycastle_mldsa_lowmemory::{MLDSATrait, HashMLDSA65_with_SHA512, HashMLDSA44_with_SHA512};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! // Here, and in contrast to External Mu mode of ML-DSA, the message can be pre-hashed before
//! // generating the signing key.
//! let ph: [u8; 64] = SHA512::default().hash(msg).as_slice().try_into().unwrap();
//!
//!
//! let (pk, sk) = HashMLDSA65_with_SHA512::keygen().unwrap();
//!
//! let sig = HashMLDSA65_with_SHA512::sign_ph(&sk, &ph, None).unwrap();
//! // This is the signature value that can be saved to a file or whatever it is need.
//!
//! // This verifies either through the usual one-shot API of the [SignatureVerifier] trait
//! match HashMLDSA65_with_SHA512::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! // Or though the verify_ph of the [PHSignatureVerifier] trait
//! match HashMLDSA65_with_SHA512::verify_ph(&pk, &ph, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! Note that the [`HashMLDSA`] object is just a light wrapper around [`MLDSA`], and, for example, they share key types.
//! Thereofre, if the user needs the more sophisticated keygen functions, they should just use them from [`MLDSA`].
//! But a simple [`HashMLDSA::keygen`] is provided.

use crate::mldsa::{H, MLDSA_MU_LEN, MLDSA_RND_LEN, MLDSATrait};
use crate::mldsa::{MLDSA44_FULL_SK_LEN, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN};
use crate::mldsa::{MLDSA65_FULL_SK_LEN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA65_SK_LEN};
use crate::mldsa::{MLDSA87_FULL_SK_LEN, MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87_SK_LEN};
use crate::mldsa_keys::{MLDSAPrivateKeyInternalTrait, MLDSAPublicKeyInternalTrait};
use crate::params::{
    HashMLDSA44_with_SHA256Params, HashMLDSA44_with_SHA512Params, HashMLDSA65_with_SHA256Params,
    HashMLDSA65_with_SHA512Params, HashMLDSA87_with_SHA256Params, HashMLDSA87_with_SHA512Params,
    HashMLDSAParams,
};
use crate::{
    MLDSA, MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey,
    MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait,
};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, PHSignatureVerifier, PHSigner, RNG, SecurityStrength,
    SignatureVerifier, Signer, XOF,
};
use bouncycastle_rng::HashDRBG_SHA512;
use core::marker::PhantomData;
// Imports needed only for docs
#[allow(unused_imports)]
use crate::mldsa::MuBuilder;

/*** Constants ***/

///
pub const HASH_ML_DSA_44_with_SHA256_NAME: &str = "HashML-DSA-44_with_SHA256";
///
pub const HASH_ML_DSA_65_WITH_SHA256_NAME: &str = "HashML-DSA-65_with_SHA256";
///
pub const HASH_ML_DSA_87_with_SHA256_NAME: &str = "HashML-DSA-87_with_SHA256";
///
pub const HASH_ML_DSA_44_with_SHA512_NAME: &str = "HashML-DSA-44_with_SHA512";
///
pub const HASH_ML_DSA_65_WITH_SHA512_NAME: &str = "HashML-DSA-65_with_SHA512";
///
pub const HASH_ML_DSA_87_WITH_SHA512_NAME: &str = "HashML-DSA-87_with_SHA512";

/*** Pub Types ***/

impl<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> Algorithm for HashMLDSA<P, PK, SK, PH_LEN, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// The HashML-DSA-44_with_SHA256 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA256 = HashMLDSA<
    HashMLDSA44_with_SHA256Params,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    { HashMLDSA44_with_SHA256Params::PH_LEN },
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_FULL_SK_LEN,
    MLDSA44_SIG_LEN,
>;

/// The HashML-DSA-65_with_SHA256 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA65_with_SHA256 = HashMLDSA<
    HashMLDSA65_with_SHA256Params,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    { HashMLDSA65_with_SHA256Params::PH_LEN },
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_FULL_SK_LEN,
    MLDSA65_SIG_LEN,
>;

/// The HashML-DSA-87_with_SHA256 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA87_with_SHA256 = HashMLDSA<
    HashMLDSA87_with_SHA256Params,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    { HashMLDSA87_with_SHA256Params::PH_LEN },
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_FULL_SK_LEN,
    MLDSA87_SIG_LEN,
>;

/// The HashML-DSA-44_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA512 = HashMLDSA<
    HashMLDSA44_with_SHA512Params,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    { HashMLDSA44_with_SHA512Params::PH_LEN },
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_FULL_SK_LEN,
    MLDSA44_SIG_LEN,
>;
/// Assigned by NIST in the Computer Security Objects Register: id-hash-ml-dsa-44-with-sha512 { sigAlgs 32 }
impl AlgorithmOID for HashMLDSA44_with_SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 32];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x20];
}

/// The HashML-DSA-65_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA65_with_SHA512 = HashMLDSA<
    HashMLDSA65_with_SHA512Params,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    { HashMLDSA65_with_SHA512Params::PH_LEN },
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_FULL_SK_LEN,
    MLDSA65_SIG_LEN,
>;
/// Assigned by NIST in the Computer Security Objects Register: id-hash-ml-dsa-65-with-sha512 { sigAlgs 33 }
impl AlgorithmOID for HashMLDSA65_with_SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 33];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x21];
}

/// The HashML-DSA-87_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA87_with_SHA512 = HashMLDSA<
    HashMLDSA87_with_SHA512Params,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    { HashMLDSA87_with_SHA512Params::PH_LEN },
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_FULL_SK_LEN,
    MLDSA87_SIG_LEN,
>;
/// Assigned by NIST in the Computer Security Objects Register: id-hash-ml-dsa-87-with-sha512 { sigAlgs 34 }
impl AlgorithmOID for HashMLDSA87_with_SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 34];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x22];
}

/// An instance of the HashML-DSA algorithm.
///
/// The implementation exposing the HashMLDSA struct this way so that alternative hash functions can be used
/// without requiring modification of this source code; the user can add their own hash function
/// by specifying the hash function to use (in the verifier), and specifying the bytes of the OID to
/// to use as its domain separator in constructing the message representative M'.
pub struct HashMLDSA<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> {
    _phantom: PhantomData<(P, PK, SK)>,

    signer_rnd: Option<[u8; MLDSA_RND_LEN]>,

    /// only used in streaming sign operations
    sk: Option<SK>,

    /// only used in streaming sign operations instead of sk
    seed: Option<KeyMaterial<32>>,

    /// only used in streaming verify operations
    pk: Option<PK>,

    /// Hash function instance for streaming message hashing
    hash: P::PreHash,

    /// Since HashML-DSA does message buffering in the external pre-hash, not in mu,
    /// this needs to be saved for later
    ctx: [u8; 255],
    ctx_len: usize,
}

impl<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> HashMLDSA<P, PK, SK, PH_LEN, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>
{
    /// Generate a keypair, sourcing randomness from bouncycastle's default os-backed RNG.
    ///
    /// Key generation is intentionally not part of the [`Signer`] / [`SignatureVerifier`] traits;
    /// it is provided as an inherent associated function directly on the algorithm struct.
    /// Keys are interchangeable between MLDSA and HashMLDSA.
    /// Error condition: basically only on RNG failures.
    pub fn keygen() -> Result<(PK, SK), SignatureError> {
        MLDSA::<P::MLDSA, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>::keygen()
    }

    /// Imports a secret key from a seed.
    pub fn keygen_from_seed(seed: &KeyMaterial<32>) -> Result<(PK, SK), SignatureError> {
        MLDSA::<P::MLDSA, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>::keygen_internal(seed)
    }

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed ph instead of M', thus combining Algorithm 4 with Algorithm 7).
    ///
    /// Security note:
    /// This mode exposes deterministic signing (called "hedged mode" and allowed by FIPS 204).
    /// The ML-DSA algorithm is considered safe to use in deterministic mode, it must be clear that
    /// the responsibility is on the user to ensure that their nonce `rnd` is unique per signature.
    /// If not, some privacy properties may be lost. For example, it becomes easy to tell if a signer
    /// has signed the same message twice or two different messages, or to tell if the same message
    /// has been signed by the same signer twice or two different signers.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    pub fn sign_ph_deterministic(
        sk: &SK,
        ctx: Option<&[u8]>,
        ph: &[u8; PH_LEN],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_ph_deterministic_out(sk, ctx, ph, rnd, &mut out)?;
        Ok(out)
    }

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed ph instead of M', thus combining Algorithm 4 with Algorithm 7).
    ///
    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    ///
    /// Returns the number of bytes written to the output buffer. It can be called with an oversized buffer.
    pub fn sign_ph_deterministic_out(
        sk: &SK,
        ctx: Option<&[u8]>,
        ph: &[u8; PH_LEN],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        let ctx = if ctx.is_some() { ctx.unwrap() } else { &[] };

        // Algorithm 4
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        output.fill(0);

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut h = H::new();
        h.absorb(&sk.tr()).expect("absorb before squeeze is infallible");

        // Algorithm 4
        // 23: 𝑀' ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀)
        // all done together
        h.absorb(&[1u8]).expect("absorb before squeeze is infallible");
        h.absorb(&[ctx.len() as u8]).expect("absorb before squeeze is infallible");
        h.absorb(ctx).expect("absorb before squeeze is infallible");
        h.absorb(<P::PreHash as AlgorithmOID>::OID_DER)
            .expect("absorb before squeeze is infallible");
        h.absorb(ph).expect("absorb before squeeze is infallible");
        let mut mu = [0u8; MLDSA_MU_LEN];
        let bytes_written = h.squeeze_out(&mut mu);
        debug_assert_eq!(bytes_written, MLDSA_MU_LEN);

        // 24: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀', 𝑟𝑛𝑑)
        let bytes_written = MLDSA::<P::MLDSA, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>::sign_mu_deterministic_out(sk, &mu, rnd, output)?;

        Ok(bytes_written)
    }

    /// To be used for deterministic signing in conjunction with the [`Signer::sign_init`],
    /// [`Signer::sign_update`], and [`Signer::sign_final`] flow.
    /// It can be set anywhere after [`Signer::sign_init`] and before [`Signer::sign_final`]
    pub fn set_signer_rnd(&mut self, rnd: [u8; 32]) {
        self.signer_rnd = Some(rnd);
    }

    fn parse_ctx(ctx: Option<&[u8]>) -> Result<([u8; 255], usize), SignatureError> {
        if ctx.is_some() {
            // Algorithm 2
            // 1: if |𝑐𝑡𝑥| > 255 then
            if ctx.unwrap().len() > 255 {
                return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
            }

            let mut ctx_buf = [0u8; 255];
            ctx_buf[..ctx.unwrap().len()].copy_from_slice(ctx.unwrap());
            Ok((ctx_buf, ctx.unwrap().len()))
        } else {
            Ok(([0u8; 255], 0))
        }
    }

    /// Alternative initialization of the streaming signer where the user has their private key
    /// as a seed, and they want to delay its expansion as late as possible for memory-usage reasons.
    pub fn sign_init_from_seed(
        seed: &KeyMaterial<32>,
        ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        let (ctx, ctx_len) = Self::parse_ctx(ctx)?;
        Ok(Self {
            _phantom: PhantomData,
            signer_rnd: None,
            sk: None,
            seed: Some(seed.clone()),
            pk: None,
            hash: <P::PreHash as Default>::default(),
            ctx,
            ctx_len,
        })
    }
}

impl<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> Signer<SK, SK_LEN, SIG_LEN>
    for HashMLDSA<P, PK, SK, PH_LEN, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>
{
    /// Algorithm 4 HashML-DSA.Sign(𝑠𝑘, 𝑀 , 𝑐𝑡𝑥, PH)
    /// Generate a “pre-hash” ML-DSA signature.
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(
        sk: &SK,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        let mut ph_m = [0u8; PH_LEN];
        _ = <P::PreHash as Default>::default().hash_out(msg, &mut ph_m);
        Self::sign_ph_out(sk, &ph_m, ctx, output)
    }

    fn sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let (ctx, ctx_len) = Self::parse_ctx(ctx)?;
        Ok(Self {
            _phantom: PhantomData,
            signer_rnd: None,
            sk: Some(sk.clone()),
            seed: None,
            pk: None,
            hash: <P::PreHash as Default>::default(),
            ctx,
            ctx_len,
        })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_final_out(&mut out)?;
        Ok(out)
    }

    fn sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        let ph: [u8; PH_LEN] = self.hash.do_final().try_into().unwrap();

        if self.sk.is_none() && self.seed.is_none() {
            return Err(SignatureError::GenericError(
                "Somehow you managed to construct a streaming signer without a private key, impressive!",
            ));
        }

        output.fill(0);

        if self.sk.is_some() {
            if self.signer_rnd.is_none() {
                Self::sign_ph_out(&self.sk.unwrap(), &ph, Some(&self.ctx[..self.ctx_len]), output)
            } else {
                Self::sign_ph_deterministic_out(
                    &self.sk.unwrap(),
                    Some(&self.ctx[..self.ctx_len]),
                    &ph,
                    self.signer_rnd.unwrap(),
                    output,
                )
            }
        } else if self.seed.is_some() {
            let rnd = if self.signer_rnd.is_some() {
                self.signer_rnd.unwrap()
            } else {
                let mut rnd: [u8; MLDSA_RND_LEN] = [0u8; MLDSA_RND_LEN];
                HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;
                rnd
            };
            // At this point it's necessary to fully reconstruct SK in order to compute tr for mu.
            // Therefore there is no savings to using the more sophisticated MLDSA::sign_from_seed
            let (_pk, sk) = Self::keygen_from_seed(&self.seed.unwrap())?;
            Self::sign_ph_deterministic_out(&sk, Some(&self.ctx[..self.ctx_len]), &ph, rnd, output)
        } else {
            unreachable!()
        }
    }
}

impl<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> SignatureVerifier<PK, PK_LEN, SIG_LEN>
    for HashMLDSA<P, PK, SK, PH_LEN, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>
{
    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let mut ph_m = [0u8; PH_LEN];
        _ = <P::PreHash as Default>::default().hash_out(msg, &mut ph_m);

        Self::verify_ph(pk, &ph_m, ctx, sig)
    }

    fn verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let (ctx, ctx_len) = Self::parse_ctx(ctx)?;
        Ok(Self {
            _phantom: Default::default(),
            signer_rnd: None,
            sk: None,
            seed: None,
            pk: Some(pk.clone()),
            hash: <P::PreHash as Default>::default(),
            ctx,
            ctx_len,
        })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        assert!(
            self.pk.is_some(),
            "Somehow you managed to construct a streaming verifier without a public key, impressive!"
        );
        let ph: [u8; PH_LEN] = self.hash.do_final().try_into().unwrap();
        Self::verify_ph(&self.pk.unwrap(), &ph, Some(&self.ctx[..self.ctx_len]), &sig[..SIG_LEN])
    }
}

impl<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> PHSigner<PK, SK, PK_LEN, SK_LEN, SIG_LEN, PH_LEN>
    for HashMLDSA<P, PK, SK, PH_LEN, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>
{
    fn sign_ph(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        Self::sign_ph_out(sk, ph, ctx, &mut out)?;

        Ok(out)
    }

    /// Note that the PH expected here *is not the same* as the `mu` computed by [`MuBuilder`].
    /// To make use of this function, it is necessary to compute a straight hash of the message using
    /// the same hash function as the indicated in the HashML-DSA variant. For example, SHA256 for
    /// HashMDSA44_with_SHA256; SHA512 for HashMLDSA65_with_SHA512; etc.
    fn sign_ph_out(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        let mut rnd: [u8; MLDSA_RND_LEN] = [0u8; MLDSA_RND_LEN];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;
        Self::sign_ph_deterministic_out(sk, ctx, ph, rnd, output)
    }
}

impl<
    P: HashMLDSAParams,
    PK: MLDSAPublicKeyTrait<P::MLDSA, PK_LEN> + MLDSAPublicKeyInternalTrait<P::MLDSA, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P::MLDSA, PK_LEN, SK_LEN, FULL_SK_LEN>
        + MLDSAPrivateKeyInternalTrait<P::MLDSA, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const SIG_LEN: usize,
> PHSignatureVerifier<PK, PK_LEN, SIG_LEN, PH_LEN>
    for HashMLDSA<P, PK, SK, PH_LEN, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>
{
    fn verify_ph(
        pk: &PK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        if sig.len() != SIG_LEN {
            return Err(SignatureError::LengthError("Signature value is not the correct length."));
        }
        let sig_sized = &sig.try_into().unwrap();

        let ctx = if ctx.is_some() { ctx.unwrap() } else { &[] };

        // Algorithm 5
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut h = H::new();
        h.absorb(&pk.compute_tr()).expect("absorb before squeeze is infallible");

        // Algorithm 4
        // 23: 𝑀 ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀)
        // all done together
        h.absorb(&[1u8]).expect("absorb before squeeze is infallible");
        h.absorb(&[ctx.len() as u8]).expect("absorb before squeeze is infallible");
        h.absorb(ctx).expect("absorb before squeeze is infallible");
        h.absorb(<P::PreHash as AlgorithmOID>::OID_DER)
            .expect("absorb before squeeze is infallible");
        h.absorb(ph).expect("absorb before squeeze is infallible");
        let mut mu = [0u8; MLDSA_MU_LEN];
        _ = h.squeeze_out(&mut mu);

        MLDSA::<P::MLDSA, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, SIG_LEN>::verify_mu(
            pk, &mu, sig_sized,
        )
    }
}
