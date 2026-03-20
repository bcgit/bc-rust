//! Note in docs that this is just a light wrapper around [MLDSA], and, for example, the share key types,
//! so if you need the fancy keygen functions, just use them from [MLDSA].
//! But a simple [HashMLDSA::keygen] is provided in order to have conformance to the [PHSignature] trait.

use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::traits::{Hash, PHSignature, Signature, RNG, XOF};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::{SHA256, SHA512};
use crate::{MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSA};
use crate::mldsa::{MLDSATrait, H, MU_LEN, RND_LEN};
use crate::mldsa::{MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN, MLDSA44_TAU, MLDSA44_LAMBDA, MLDSA44_GAMMA1, MLDSA44_GAMMA2, MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_BETA, MLDSA44_OMEGA, MLDSA44_C_TILDE, MLDSA44_POLY_Z_PACKED_LEN, MLDSA44_POLY_W1_PACKED_LEN, MLDSA44_W1_PACKED_LEN, MLDSA44_POLY_ETA_PACKED_LEN, MLDSA44_LAMBDA_over_4, MLDSA44_GAMMA1_MASK_LEN};
use crate::mldsa::{MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN, MLDSA65_TAU, MLDSA65_LAMBDA, MLDSA65_GAMMA1, MLDSA65_GAMMA2, MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_BETA, MLDSA65_OMEGA, MLDSA65_C_TILDE, MLDSA65_POLY_Z_PACKED_LEN, MLDSA65_POLY_W1_PACKED_LEN, MLDSA65_W1_PACKED_LEN, MLDSA65_POLY_ETA_PACKED_LEN, MLDSA65_LAMBDA_over_4, MLDSA65_GAMMA1_MASK_LEN};
use crate::mldsa::{MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN, MLDSA87_TAU, MLDSA87_LAMBDA, MLDSA87_GAMMA1, MLDSA87_GAMMA2, MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_BETA, MLDSA87_OMEGA, MLDSA87_C_TILDE, MLDSA87_POLY_Z_PACKED_LEN, MLDSA87_POLY_W1_PACKED_LEN, MLDSA87_W1_PACKED_LEN, MLDSA87_POLY_ETA_PACKED_LEN, MLDSA87_LAMBDA_over_4, MLDSA87_GAMMA1_MASK_LEN};
use crate::mldsa_keys::{MLDSAPrivateKeyInternalTrait, MLDSAPublicKeyInternalTrait};

const SHA256_OID:   &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA512_OID:   &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];


/*** Constants ***/

pub const Hash_ML_DSA_44_with_SHA256_NAME: &str = "HashML-DSA-44_with_SHA256";
pub const Hash_ML_DSA_65_with_SHA256_NAME: &str = "HashML-DSA-65_with_SHA256";
pub const Hash_ML_DSA_87_with_SHA256_NAME: &str = "HashML-DSA-87_with_SHA256";

pub const Hash_ML_DSA_44_with_SHA512_NAME: &str = "HashML-DSA-44_with_SHA512";
pub const Hash_ML_DSA_65_with_SHA512_NAME: &str = "HashML-DSA-65_with_SHA512";
pub const Hash_ML_DSA_87_with_SHA512_NAME: &str = "HashML-DSA-87_with_SHA512";


/*** Pub Types ***/
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
    MLDSA44_W1_PACKED_LEN,
    MLDSA44_POLY_ETA_PACKED_LEN,
    MLDSA44_LAMBDA_over_4,
    MLDSA44_GAMMA1_MASK_LEN,
>;

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
    MLDSA65_W1_PACKED_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_GAMMA1_MASK_LEN,
>;

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
    MLDSA87_W1_PACKED_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_GAMMA1_MASK_LEN,
>;

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
    MLDSA44_W1_PACKED_LEN,
    MLDSA44_POLY_ETA_PACKED_LEN,
    MLDSA44_LAMBDA_over_4,
    MLDSA44_GAMMA1_MASK_LEN,
>;

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
    MLDSA65_W1_PACKED_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_GAMMA1_MASK_LEN,
>;

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
    MLDSA87_W1_PACKED_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_GAMMA1_MASK_LEN,
>;


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
    PK: MLDSAPublicKeyTrait<k, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
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
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> {
    _phantom_hash: std::marker::PhantomData<HASH>,
    _phantom_pk: std::marker::PhantomData<PK>,
    _phantom_sk: std::marker::PhantomData<SK>,
}

impl<
    HASH: Hash + Default,
    const PH_LEN: usize,
    const oid: &'static [u8],
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
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
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> HashMLDSA<
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
    W1_PACKED_LEN,
    POLY_ETA_PACKED_LEN,
    LAMBDA_over_4,
    GAMMA1_MASK_LEN,
> {

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed ph instead of M', thus combining Algorithm 4 with Algorithm 7).
    ///
    /// Security note:
    /// This mode exposes deterministic signing (called "hedged mode" and allowed by FIPS 204).
    /// The ML-DSA algorithm is considered safe to use in deterministic mode, but be aware that
    /// the responsibility is on you to ensure that your nonce `rnd` is unique per signature.
    /// If not, you may lose some privacy properties; for example it becomes easy to tell if a signer
    /// has signed the same message twice or two different messagase, or to tell if the same message
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
        h.absorb(sk.tr());

        // Algorithm 4
        // 23: 𝑀' ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀)
        // all done together
        h.absorb(&[1u8]);
        h.absorb(&[ctx.len() as u8]);
        h.absorb(ctx);
        /*todo:dbg*/ let tmp = oid;
        h.absorb(oid);
        h.absorb(ph);
        let mut mu = [0u8; MU_LEN]; // todo -- different from bc-java
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
            W1_PACKED_LEN,
            POLY_ETA_PACKED_LEN,
            LAMBDA_over_4,
            GAMMA1_MASK_LEN>::sign_mu_deterministic_out(sk, &mu, rnd, output)?;

        Ok(bytes_written)
    }
}

impl<
    HASH: Hash + Default,
    const PH_LEN: usize,
    const oid: &'static [u8],
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
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
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> PHSignature<PK, SK, PH_LEN> for HashMLDSA<
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
    W1_PACKED_LEN,
    POLY_ETA_PACKED_LEN,
    LAMBDA_over_4,
    GAMMA1_MASK_LEN,
> {
    /// Keygen, and keys in general, are interchangeable between MLDSA and HashMLDSA.
    fn keygen() -> Result<(PK, SK), SignatureError> {
        MLDSA::<PK_LEN,
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
        W1_PACKED_LEN,
        POLY_ETA_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MASK_LEN>::keygen()
    }

    /// Algorithm 4 HashML-DSA.Sign(𝑠𝑘, 𝑀 , 𝑐𝑡𝑥, PH)
    /// Generate a “pre-hash” ML-DSA signature.
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(sk: &SK, msg: &[u8], ctx: Option<&[u8]>, output: &mut [u8]) -> Result<usize, SignatureError> {
        let mut ph_m = [0u8; PH_LEN];
        _ = HASH::default().hash_out(msg, &mut ph_m);
        Self::sign_ph_out(sk, &ph_m, ctx, output)
    }

    fn sign_ph(sk: &SK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; SIG_LEN];
        Self::sign_out(sk, ph, ctx, &mut out)?;

        Ok(out)
    }

    /// Note that the PH expected here *is not the same* as the `mu` computed by [MLDSA::compute_mu] ... blah blah explain.
    fn sign_ph_out(sk: &SK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>, output: &mut [u8]) -> Result<usize, SignatureError> {
        if output.len() < SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let output_sized: &mut [u8; SIG_LEN] = output[..SIG_LEN].as_mut().try_into().unwrap();

        let mut rnd: [u8; RND_LEN] = [0u8; RND_LEN];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;
        Self::sign_ph_deterministic_out(sk, ctx, ph, rnd, output_sized)
    }

    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let mut ph_m = [0u8; PH_LEN];
        _ = HASH::default().hash_out(msg, &mut ph_m);
        
        Self::verify_ph(pk, &ph_m, ctx, sig)
    }

    fn verify_ph(pk: &PK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        if sig.len() != SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }

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


        if MLDSA::<PK_LEN,
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
            W1_PACKED_LEN,
            POLY_ETA_PACKED_LEN,
            LAMBDA_over_4,
            GAMMA1_MASK_LEN>::verify_mu_internal(pk, &mu, &sig[..SIG_LEN].try_into().unwrap())  {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }
}