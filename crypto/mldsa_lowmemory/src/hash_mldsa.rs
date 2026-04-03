//! This implements the HashML-DSA algorithm specified in FIPS 204 which is useful for cases
//! where you need to process the to-be-signed message in chunks, and you cannot use the external mu
//! mode of [MLDSA]; possibly because you have to digest the message before you know which public key
//! will sign it.
//!
//! HashML-DSA is a full signature algorithm implementing the [Signature] trait:
//!
//! ```rust
//! use bouncycastle_core_interface::errors::SignatureError;
//! use bouncycastle_mldsa::{HashMLDSA65_with_SHA512, MLDSATrait, HashMLDSA44_with_SHA512};
//! use bouncycastle_core_interface::traits::Signature;
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = HashMLDSA65_with_SHA512::keygen().unwrap();
//!
//! let sig: Vec<u8> = HashMLDSA65_with_SHA512::sign(&sk, msg, None).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! match HashMLDSA65_with_SHA512::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! But you also have access to the pre-hashed function available from [PHSignature]:
//!
//! ```rust
//! use bouncycastle_core_interface::errors::SignatureError;
//! use bouncycastle_mldsa::{HashMLDSA65_with_SHA512, MLDSATrait, HashMLDSA44_with_SHA512};
//! use bouncycastle_core_interface::traits::{Signature, PHSignature, Hash};
//! use bouncycastle_sha2::SHA512;
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! // Here, and in contrast to External Mu mode of ML-DSA, we can pre-hash the message before
//! // even generating the signing key.
//! let ph: [u8; 64] = SHA512::default().hash(msg).as_slice().try_into().unwrap();
//!
//!
//! let (pk, sk) = HashMLDSA65_with_SHA512::keygen().unwrap();
//!
//! let sig: Vec<u8> = HashMLDSA65_with_SHA512::sign_ph(&sk, &ph, None).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! // This verifies either through the usual one-shot API of the [Signature] trait
//! match HashMLDSA65_with_SHA512::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! // Or though the verify_ph of the [PHSignature] trait
//! match HashMLDSA65_with_SHA512::verify_ph(&pk, &ph, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! Note that the [HashMLDSA] object is just a light wrapper around [MLDSA], and, for example, they share key types,
//! so if you need the fancy keygen functions, just use them from [MLDSA].
//! But a simple [HashMLDSA::keygen] is provided in order to have conformance to the [Signature] trait.

use core::marker::PhantomData;
use crate::mldsa::{H, MLDSATrait, MU_LEN, RND_LEN};
use crate::mldsa::{
    MLDSA44_BETA, MLDSA44_C_TILDE, MLDSA44_ETA, MLDSA44_GAMMA1, MLDSA44_GAMMA1_MASK_LEN,
    MLDSA44_GAMMA2, MLDSA44_LAMBDA, MLDSA44_LAMBDA_over_4, MLDSA44_OMEGA, MLDSA44_PK_LEN,
    MLDSA44_POLY_ETA_PACKED_LEN, MLDSA44_POLY_W1_PACKED_LEN, MLDSA44_POLY_Z_PACKED_LEN,
    MLDSA44_SIG_LEN, MLDSA44_SK_LEN, MLDSA44_TAU, MLDSA44_S1_PACKED_LEN, MLDSA44_S2_PACKED_LEN, MLDSA44_k, MLDSA44_l,
};
use crate::mldsa::{
    MLDSA65_BETA, MLDSA65_C_TILDE, MLDSA65_ETA, MLDSA65_GAMMA1, MLDSA65_GAMMA1_MASK_LEN,
    MLDSA65_GAMMA2, MLDSA65_LAMBDA, MLDSA65_LAMBDA_over_4, MLDSA65_OMEGA, MLDSA65_PK_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN, MLDSA65_POLY_W1_PACKED_LEN, MLDSA65_POLY_Z_PACKED_LEN,
    MLDSA65_SIG_LEN, MLDSA65_SK_LEN, MLDSA65_TAU, MLDSA65_S1_PACKED_LEN, MLDSA65_S2_PACKED_LEN, MLDSA65_k, MLDSA65_l,
};
use crate::mldsa::{
    MLDSA87_BETA, MLDSA87_C_TILDE, MLDSA87_ETA, MLDSA87_GAMMA1, MLDSA87_GAMMA1_MASK_LEN,
    MLDSA87_GAMMA2, MLDSA87_LAMBDA, MLDSA87_LAMBDA_over_4, MLDSA87_OMEGA, MLDSA87_PK_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN, MLDSA87_POLY_W1_PACKED_LEN, MLDSA87_POLY_Z_PACKED_LEN,
    MLDSA87_SIG_LEN, MLDSA87_SK_LEN, MLDSA87_TAU, MLDSA87_S1_PACKED_LEN, MLDSA87_S2_PACKED_LEN, MLDSA87_k, MLDSA87_l,
};
use crate::mldsa::{MLDSA44_T1_PACKED_LEN, MLDSA65_T1_PACKED_LEN, MLDSA87_T1_PACKED_LEN};
use crate::mldsa_keys::{MLDSAPrivateKeyInternalTrait, MLDSAPublicKeyInternalTrait};
use crate::{MLDSA, MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::KeyMaterialSized;
use bouncycastle_core_interface::traits::{Hash, PHSignature, RNG, Signature, XOF, Algorithm, SecurityStrength};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::{SHA256, SHA512};

// Imports needed only for docs
#[allow(unused_imports)]
use crate::mldsa::MuBuilder;

const SHA256_OID: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA512_OID: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/*** Constants ***/

///
pub const Hash_ML_DSA_44_with_SHA256_NAME: &str = "HashML-DSA-44_with_SHA256";
///
pub const Hash_ML_DSA_65_with_SHA256_NAME: &str = "HashML-DSA-65_with_SHA256";
///
pub const Hash_ML_DSA_87_with_SHA256_NAME: &str = "HashML-DSA-87_with_SHA256";
///
pub const Hash_ML_DSA_44_with_SHA512_NAME: &str = "HashML-DSA-44_with_SHA512";
///
pub const Hash_ML_DSA_65_with_SHA512_NAME: &str = "HashML-DSA-65_with_SHA512";
///
pub const Hash_ML_DSA_87_with_SHA512_NAME: &str = "HashML-DSA-87_with_SHA512";

/*** Pub Types ***/

/// The HashML-DSA-44_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA256 = HashMLDSA<
    SHA256,
    32,
    SHA256_OID,
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_SIG_LEN,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    MLDSA44_TAU,
    MLDSA44_LAMBDA,
    MLDSA44_GAMMA1,
    MLDSA44_GAMMA2,
    MLDSA44_k,
    MLDSA44_l,
    MLDSA44_ETA,
    MLDSA44_BETA,
    MLDSA44_OMEGA,
    MLDSA44_C_TILDE,
    MLDSA44_POLY_Z_PACKED_LEN,
    MLDSA44_POLY_W1_PACKED_LEN,
    MLDSA44_S1_PACKED_LEN,
    MLDSA44_S2_PACKED_LEN,
    MLDSA44_T1_PACKED_LEN,
    MLDSA44_POLY_ETA_PACKED_LEN,
    MLDSA44_LAMBDA_over_4,
    MLDSA44_GAMMA1_MASK_LEN,
>;

impl Algorithm for HashMLDSA44_with_SHA256 {
    const ALG_NAME: &'static str = Hash_ML_DSA_44_with_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The HashML-DSA-65_with_SHA256 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA65_with_SHA256 = HashMLDSA<
    SHA256,
    32,
    SHA256_OID,
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_SIG_LEN,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    MLDSA65_TAU,
    MLDSA65_LAMBDA,
    MLDSA65_GAMMA1,
    MLDSA65_GAMMA2,
    MLDSA65_k,
    MLDSA65_l,
    MLDSA65_ETA,
    MLDSA65_BETA,
    MLDSA65_OMEGA,
    MLDSA65_C_TILDE,
    MLDSA65_POLY_Z_PACKED_LEN,
    MLDSA65_POLY_W1_PACKED_LEN,
    MLDSA65_S1_PACKED_LEN,
    MLDSA65_S2_PACKED_LEN,
    MLDSA65_T1_PACKED_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_GAMMA1_MASK_LEN,
>;

impl Algorithm for HashMLDSA65_with_SHA256 {
    const ALG_NAME: &'static str = Hash_ML_DSA_65_with_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The HashML-DSA-87_with_SHA256 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA87_with_SHA256 = HashMLDSA<
    SHA256,
    32,
    SHA256_OID,
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_SIG_LEN,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    MLDSA87_TAU,
    MLDSA87_LAMBDA,
    MLDSA87_GAMMA1,
    MLDSA87_GAMMA2,
    MLDSA87_k,
    MLDSA87_l,
    MLDSA87_ETA,
    MLDSA87_BETA,
    MLDSA87_OMEGA,
    MLDSA87_C_TILDE,
    MLDSA87_POLY_Z_PACKED_LEN,
    MLDSA87_POLY_W1_PACKED_LEN,
    MLDSA87_S1_PACKED_LEN,
    MLDSA87_S2_PACKED_LEN,
    MLDSA87_T1_PACKED_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_GAMMA1_MASK_LEN,
>;

impl Algorithm for HashMLDSA87_with_SHA256 {
    const ALG_NAME: &'static str = Hash_ML_DSA_87_with_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The HashML-DSA-44_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA44_with_SHA512 = HashMLDSA<
    SHA512,
    64,
    SHA512_OID,
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_SIG_LEN,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    MLDSA44_TAU,
    MLDSA44_LAMBDA,
    MLDSA44_GAMMA1,
    MLDSA44_GAMMA2,
    MLDSA44_k,
    MLDSA44_l,
    MLDSA44_ETA,
    MLDSA44_BETA,
    MLDSA44_OMEGA,
    MLDSA44_C_TILDE,
    MLDSA44_POLY_Z_PACKED_LEN,
    MLDSA44_POLY_W1_PACKED_LEN,
    MLDSA44_S1_PACKED_LEN,
    MLDSA44_S2_PACKED_LEN,
    MLDSA44_T1_PACKED_LEN,
    MLDSA44_POLY_ETA_PACKED_LEN,
    MLDSA44_LAMBDA_over_4,
    MLDSA44_GAMMA1_MASK_LEN,
>;

impl Algorithm for HashMLDSA44_with_SHA512 {
    const ALG_NAME: &'static str = Hash_ML_DSA_44_with_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The HashML-DSA-65_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA65_with_SHA512 = HashMLDSA<
    SHA512,
    64,
    SHA512_OID,
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_SIG_LEN,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    MLDSA65_TAU,
    MLDSA65_LAMBDA,
    MLDSA65_GAMMA1,
    MLDSA65_GAMMA2,
    MLDSA65_k,
    MLDSA65_l,
    MLDSA65_ETA,
    MLDSA65_BETA,
    MLDSA65_OMEGA,
    MLDSA65_C_TILDE,
    MLDSA65_POLY_Z_PACKED_LEN,
    MLDSA65_POLY_W1_PACKED_LEN,
    MLDSA65_S1_PACKED_LEN,
    MLDSA65_S2_PACKED_LEN,
    MLDSA65_T1_PACKED_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_GAMMA1_MASK_LEN,
>;

impl Algorithm for HashMLDSA65_with_SHA512 {
    const ALG_NAME: &'static str = Hash_ML_DSA_65_with_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

/// The HashML-DSA-87_with_SHA512 signature algorithm.
#[allow(non_camel_case_types)]
pub type HashMLDSA87_with_SHA512 = HashMLDSA<
    SHA512,
    64,
    SHA512_OID,
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_SIG_LEN,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    MLDSA87_TAU,
    MLDSA87_LAMBDA,
    MLDSA87_GAMMA1,
    MLDSA87_GAMMA2,
    MLDSA87_k,
    MLDSA87_l,
    MLDSA87_ETA,
    MLDSA87_BETA,
    MLDSA87_OMEGA,
    MLDSA87_C_TILDE,
    MLDSA87_POLY_Z_PACKED_LEN,
    MLDSA87_POLY_W1_PACKED_LEN,
    MLDSA87_S1_PACKED_LEN,
    MLDSA87_S2_PACKED_LEN,
    MLDSA87_T1_PACKED_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_GAMMA1_MASK_LEN,
>;

impl Algorithm for HashMLDSA87_with_SHA512 {
    const ALG_NAME: &'static str = Hash_ML_DSA_87_with_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// An instance of the HashML-DSA algorithm.
///
/// We are exposing the HashMLDSA struct this way so that alternative hash functions can be used
/// without requiring modification of this source code; you can add your own hash function
/// by specifying the hash function to use (in the verifier), and specifying the bytes of the OID to
/// to use as its domain separator in constructing the message representative M'.
pub struct HashMLDSA<
    HASH: Hash + Default,
    const HASH_LEN: usize,
    const oid: &'static [u8],
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, T1_PACKED_LEN, PK_LEN> + MLDSAPublicKeyInternalTrait<k, T1_PACKED_LEN, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN>
        + MLDSAPrivateKeyInternalTrait<LAMBDA, GAMMA2, k, l, ETA, S1_PACKED_LEN, S2_PACKED_LEN, PK_LEN, SK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> {
    _phantom: PhantomData<(PK, SK)>,

    signer_rnd: Option<[u8; RND_LEN]>,

    /// only used in streaming sign operations
    sk: Option<SK>,

    /// only used in streaming sign operations instead of sk
    seed: Option<KeyMaterialSized<32>>,

    /// only used in streaming verify operations
    pk: Option<PK>,

    /// Hash function instance for streaming message hashing
    hash: HASH,

    /// Since HashML-DSA does message buffering in the external pre-hash, not in mu,
    /// we'll need to save this for later
    ctx: [u8; 255],
    ctx_len: usize,
}

impl<
    HASH: Hash + Default,
    const PH_LEN: usize,
    const oid: &'static [u8],
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, T1_PACKED_LEN, PK_LEN> + MLDSAPublicKeyInternalTrait<k, T1_PACKED_LEN, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN>
        + MLDSAPrivateKeyInternalTrait<LAMBDA, GAMMA2, k, l, ETA, S1_PACKED_LEN, S2_PACKED_LEN, PK_LEN, SK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
>
    HashMLDSA<
        HASH,
        PH_LEN,
        oid,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        POLY_ETA_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MASK_LEN,
    >
{
    /// Imports a secret key from a seed.
    pub fn keygen_from_seed(seed: &KeyMaterialSized<32>) -> Result<(PK, SK), SignatureError> {
        MLDSA::<
            PK_LEN,
            SK_LEN,
            SIG_LEN,
            PK,
            SK,
            TAU,
            LAMBDA,
            GAMMA1,
            GAMMA2,
            k,
            l,
            ETA,
            BETA,
            OMEGA,
            C_TILDE,
            POLY_Z_PACKED_LEN,
            POLY_W1_PACKED_LEN,
            S1_PACKED_LEN,
            S2_PACKED_LEN,
            T1_PACKED_LEN,
            POLY_ETA_PACKED_LEN,
            LAMBDA_over_4,
            GAMMA1_MASK_LEN,
        >::keygen_internal(seed)
    }

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed ph instead of M', thus combining Algorithm 4 with Algorithm 7).
    ///
    /// Security note:
    /// This mode exposes deterministic signing (called "hedged mode" and allowed by FIPS 204).
    /// The ML-DSA algorithm is considered safe to use in deterministic mode, but be aware that
    /// the responsibility is on you to ensure that your nonce `rnd` is unique per signature.
    /// If not, you may lose some privacy properties; for example it becomes easy to tell if a signer
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
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
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

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut h = H::new();
        h.absorb(&sk.tr());

        // Algorithm 4
        // 23: 𝑀' ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀)
        // all done together
        h.absorb(&[1u8]);
        h.absorb(&[ctx.len() as u8]);
        h.absorb(ctx);
        h.absorb(oid);
        h.absorb(ph);
        let mut mu = [0u8; MU_LEN];
        let bytes_written = h.squeeze_out(&mut mu);
        debug_assert_eq!(bytes_written, MU_LEN);

        // 24: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀', 𝑟𝑛𝑑)
        let bytes_written = MLDSA::<
            PK_LEN,
            SK_LEN,
            SIG_LEN,
            PK,
            SK,
            TAU,
            LAMBDA,
            GAMMA1,
            GAMMA2,
            k,
            l,
            ETA,
            BETA,
            OMEGA,
            C_TILDE,
            POLY_Z_PACKED_LEN,
            POLY_W1_PACKED_LEN,
            S1_PACKED_LEN,
            S2_PACKED_LEN,
            T1_PACKED_LEN,
            POLY_ETA_PACKED_LEN,
            LAMBDA_over_4,
            GAMMA1_MASK_LEN,
        >::sign_mu_deterministic_out(sk, &mu, rnd, output)?;

        Ok(bytes_written)
    }

    /// To be used for deterministic signing in conjunction with the [Signature::sign_init],
    /// [Signature::sign_update], and [Signature::sign_final] flow.
    /// Can be set anywhere after [Signature::sign_init] and before [Signature::sign_final]
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

    /// Alternative initialization of the streaming signer where you have your private key
    /// as a seed and you want to delay its expansion as late as possible for memory-usage reasons.
    pub fn sign_init_from_seed(seed: &KeyMaterialSized<32>, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let (ctx, ctx_len) = Self::parse_ctx(ctx)?;
        Ok(
            Self {
                _phantom: PhantomData,
                signer_rnd: None,
                sk: None,
                seed: Some(seed.clone()),
                pk: None,
                hash: HASH::default(),
                ctx,
                ctx_len,
            }
        )
    }
}

impl<
    HASH: Hash + Default,
    PK: MLDSAPublicKeyTrait<k, T1_PACKED_LEN, PK_LEN> + MLDSAPublicKeyInternalTrait<k, T1_PACKED_LEN, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN>
        + MLDSAPrivateKeyInternalTrait<LAMBDA, GAMMA2, k, l, ETA, S1_PACKED_LEN, S2_PACKED_LEN, PK_LEN, SK_LEN>,
    const PH_LEN: usize,
    const oid: &'static [u8],
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> Signature<PK, SK>
    for HashMLDSA<
        HASH,
        PH_LEN,
        oid,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        POLY_ETA_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MASK_LEN,
    >
{
    /// Keygen, and keys in general, are interchangeable between MLDSA and HashMLDSA.
    fn keygen() -> Result<(PK, SK), SignatureError> {
        MLDSA::<
            PK_LEN,
            SK_LEN,
            SIG_LEN,
            PK,
            SK,
            TAU,
            LAMBDA,
            GAMMA1,
            GAMMA2,
            k,
            l,
            ETA,
            BETA,
            OMEGA,
            C_TILDE,
            POLY_Z_PACKED_LEN,
            POLY_W1_PACKED_LEN,
            S1_PACKED_LEN,
            S2_PACKED_LEN,
            T1_PACKED_LEN,
            POLY_ETA_PACKED_LEN,
            LAMBDA_over_4,
            GAMMA1_MASK_LEN,
        >::keygen()
    }

    /// Algorithm 4 HashML-DSA.Sign(𝑠𝑘, 𝑀 , 𝑐𝑡𝑥, PH)
    /// Generate a “pre-hash” ML-DSA signature.
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(
        sk: &SK,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<usize, SignatureError> {
        let mut ph_m = [0u8; PH_LEN];
        _ = HASH::default().hash_out(msg, &mut ph_m);
        Self::sign_ph_out(sk, &ph_m, ctx, output)
    }

    fn sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let (ctx, ctx_len) = Self::parse_ctx(ctx)?;
        Ok(
            Self {
                _phantom: PhantomData,
                signer_rnd: None,
                sk: Some(sk.clone()),
                seed: None,
                pk: None,
                hash: HASH::default(),
                ctx,
                ctx_len,
            }
        )
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<Vec<u8>, SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_final_out(&mut out)?;
        Ok(Vec::from(out))
    }

    fn sign_final_out(self, output: &mut [u8]) -> Result<usize, SignatureError> {
        let ph: [u8; PH_LEN] = self.hash.do_final().try_into().unwrap();

        if self.sk.is_none() && self.seed.is_none() {
            return Err(SignatureError::GenericError("Somehow you managed to construct a streaming signer without a private key, impressive!"))
        }

        if output.len() < SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let output_sized: &mut [u8; SIG_LEN] = output[..SIG_LEN].as_mut().try_into().unwrap();

        if self.sk.is_some() {
            if self.signer_rnd.is_none() {
                Self::sign_ph_out(&self.sk.unwrap(), &ph, Some(&self.ctx[..self.ctx_len]), output_sized)
            } else {
                Self::sign_ph_deterministic_out(&self.sk.unwrap(), Some(&self.ctx[..self.ctx_len]), &ph, self.signer_rnd.unwrap(), output_sized)
            }
        } else if self.seed.is_some() {
            let rnd = if self.signer_rnd.is_some() {
                self.signer_rnd.unwrap()
            } else {
                let mut rnd: [u8; RND_LEN] = [0u8; RND_LEN];
                HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;
                rnd
            };
            // since at this point we need to fully reconstruct SK in order to compute tr for mu anyway
            // there is no savings to using the fancy MLDSA::sign_from_seed
            let (_pk, sk) = Self::keygen_from_seed(&self.seed.unwrap())?;
            Self::sign_ph_deterministic_out(&sk, Some(&self.ctx[..self.ctx_len]), &ph, rnd, output_sized)
        } else { unreachable!() }
    }

    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let mut ph_m = [0u8; PH_LEN];
        _ = HASH::default().hash_out(msg, &mut ph_m);

        Self::verify_ph(pk, &ph_m, ctx, sig)
    }

    fn verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let (ctx, ctx_len) = Self::parse_ctx(ctx)?;
        Ok(
            Self {
                _phantom: Default::default(),
                signer_rnd: None,
                sk: None,
                seed: None,
                pk: Some(pk.clone()),
                hash: HASH::default(),
                ctx,
                ctx_len,
            }
        )
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let ph: [u8; PH_LEN] = self.hash.do_final().try_into().unwrap();

        assert!(self.pk.is_some(), "Somehow you managed to construct a streaming verifier without a public key, impressive!");

        if sig.len() != SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }
        Self::verify_ph(&self.pk.unwrap(), &ph, Some(&self.ctx[..self.ctx_len]), &sig[..SIG_LEN])
    }
}

impl<
    HASH: Hash + Default,
    const PH_LEN: usize,
    const oid: &'static [u8],
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, T1_PACKED_LEN, PK_LEN> + MLDSAPublicKeyInternalTrait<k, T1_PACKED_LEN, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN>
        + MLDSAPrivateKeyInternalTrait<LAMBDA, GAMMA2, k, l, ETA, S1_PACKED_LEN, S2_PACKED_LEN, PK_LEN, SK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> PHSignature<PK, SK, PH_LEN>
    for HashMLDSA<
        HASH,
        PH_LEN,
        oid,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        POLY_ETA_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MASK_LEN,
    >
{

    fn sign_ph(sk: &SK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; SIG_LEN];
        Self::sign_out(sk, ph, ctx, &mut out)?;

        Ok(out)
    }

    /// Note that the PH expected here *is not the same* as the `mu` computed by [MuBuilder].
    /// To make use of this function, you need to compute a straight hash of the message using
    /// the same hash function as the indicated in the HashML-DSA variant; for example SHA256 for
    /// HashMDSA44_with_SHA256, SHA512 for HashMLDSA65_with_SHA512, etc.
    fn sign_ph_out(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<usize, SignatureError> {
        if output.len() < SIG_LEN {
            return Err(SignatureError::LengthError(
                "Output buffer insufficient size to hold signature",
            ));
        }
        let output_sized: &mut [u8; SIG_LEN] = output[..SIG_LEN].as_mut().try_into().unwrap();

        let mut rnd: [u8; RND_LEN] = [0u8; RND_LEN];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;
        Self::sign_ph_deterministic_out(sk, ctx, ph, rnd, output_sized)
    }

    fn verify_ph(
        pk: &PK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        if sig.len() != SIG_LEN {
            return Err(SignatureError::LengthError("Signature value is not the correct length."));
        }

        let ctx = if ctx.is_some() { ctx.unwrap() } else { &[] };

        // Algorithm 5
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut h = H::new();
        h.absorb(&pk.compute_tr());

        // Algorithm 4
        // 23: 𝑀 ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀)
        // all done together
        h.absorb(&[1u8]);
        h.absorb(&[ctx.len() as u8]);
        h.absorb(ctx);
        h.absorb(oid);
        h.absorb(ph);
        let mut mu = [0u8; MU_LEN];
        _ = h.squeeze_out(&mut mu);

        if MLDSA::<
            PK_LEN,
            SK_LEN,
            SIG_LEN,
            PK,
            SK,
            TAU,
            LAMBDA,
            GAMMA1,
            GAMMA2,
            k,
            l,
            ETA,
            BETA,
            OMEGA,
            C_TILDE,
            POLY_Z_PACKED_LEN,
            POLY_W1_PACKED_LEN,
            S1_PACKED_LEN,
            S2_PACKED_LEN,
            T1_PACKED_LEN,
            POLY_ETA_PACKED_LEN,
            LAMBDA_over_4,
            GAMMA1_MASK_LEN,
        >::verify_mu_internal(pk, &mu, &sig[..SIG_LEN].try_into().unwrap())
        {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }
}
