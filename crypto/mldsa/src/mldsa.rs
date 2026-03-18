use std::marker::PhantomData;
use crate::aux_functions::{expand_mask, expandA, expandS, make_hint_vecs, ntt, power_2_round_vec, sample_in_ball, sig_encode, sig_decode, use_hint_vecs};
use crate::matrix::Vector;
use crate::mldsa_keys::{MLDSAPublicKeyTrait, MLDSAPublicKeyInternalTrait};
use crate::mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPrivateKeyInternalTrait};
use crate::{MLDSA44PublicKey, MLDSA44PrivateKey, MLDSA65PublicKey, MLDSA65PrivateKey, MLDSA87PublicKey, MLDSA87PrivateKey};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::{
    KeyMaterial, KeyMaterial256, KeyMaterialSized, KeyType,
};
use bouncycastle_core_interface::traits::{RNG, SecurityStrength, XOF, Signature};
use bouncycastle_rng::{HashDRBG_SHA512};
use bouncycastle_sha3::{SHAKE128, SHAKE256};



/*** Constants ***/
// From FIPS 204 Table 1 and Table 2


// Constants that are the same for all parameter sets
pub(crate) const N: usize = 256;
pub(crate) const q: i32 = 8380417;
pub(crate) const q_inv: i32 = 58728449; // q ^ (-1) mod 2 ^32
pub(crate) const d: i32 = 13;
pub(crate) const ROOT_OF_UNITY: i32 = 1753;
pub const SEED_LEN: usize = 32;
pub const RND_LEN: usize = 32;
pub const TR_LEN: usize = 64;
pub(crate) const POLY_T1PACKED_LEN: usize = 320;
pub(crate) const POLY_T0PACKED_LEN: usize = 416;


/* ML-DSA-44 params */

pub const MLDSA44_PK_LEN: usize = 1312;
pub const MLDSA44_SK_LEN: usize = 2560;
pub const MLDSA44_SIG_LEN: usize = 2420;
pub(crate) const MLDSA44_TAU: i32 = 39;
pub(crate) const MLDSA44_LAMBDA: i32 = 128;
pub(crate) const MLDSA44_GAMMA1: i32 = 1 << 17;
pub(crate) const MLDSA44_GAMMA2: i32 = (q - 1) / 88;
pub(crate) const MLDSA44_k: usize = 4;
pub(crate) const MLDSA44_l: usize = 4;
pub(crate) const MLDSA44_ETA: usize = 2;
pub(crate) const MLDSA44_BETA: i32 = 78;
pub(crate) const MLDSA44_OMEGA: i32 = 80;

// Useful derived values
pub(crate) const MLDSA44_C_TILDE: usize = 32;
pub(crate) const MLDSA44_POLY_Z_PACKED_LEN: usize = 576;
pub(crate) const MLDSA44_POLY_W1_PACKED_LEN: usize = 192;
pub(crate) const MLDSA44_W1_PACKED_LEN: usize = MLDSA44_k * MLDSA44_POLY_W1_PACKED_LEN;
pub(crate) const MLDSA44_POLY_ETA_PACKED_LEN: usize = 32*3;
pub(crate) const MLDSA44_LAMBDA_over_4: usize = 128/4;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA44_GAMMA1_MASK_LEN: usize = 576;  // 32*(1 + bitlen (𝛾1 − 1) )


/* ML-DSA-65 params */

pub const MLDSA65_PK_LEN: usize = 1952;
pub const MLDSA65_SK_LEN: usize = 4032;
pub const MLDSA65_SIG_LEN: usize = 3309;
pub(crate) const MLDSA65_TAU: i32 = 49;
pub(crate) const MLDSA65_LAMBDA: i32 = 192;
pub(crate) const MLDSA65_GAMMA1: i32 = 1 << 19;
pub(crate) const MLDSA65_GAMMA2: i32 = (q - 1) / 32;
pub(crate) const MLDSA65_k: usize = 6;
pub(crate) const MLDSA65_l: usize = 5;
pub(crate) const MLDSA65_ETA: usize = 4;
pub(crate) const MLDSA65_BETA: i32 = 196;
pub(crate) const MLDSA65_OMEGA: i32 = 55;

// Useful derived values
pub(crate) const MLDSA65_C_TILDE: usize = 48;
pub(crate) const MLDSA65_POLY_Z_PACKED_LEN: usize = 640;
pub(crate) const MLDSA65_POLY_W1_PACKED_LEN: usize = 128;
pub(crate) const MLDSA65_W1_PACKED_LEN: usize = MLDSA65_k * MLDSA65_POLY_W1_PACKED_LEN;
pub(crate) const MLDSA65_POLY_ETA_PACKED_LEN: usize = 32*4;
pub(crate) const MLDSA65_LAMBDA_over_4: usize = 192/4;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA65_GAMMA1_MASK_LEN: usize = 640;



/* ML-DSA-87 params */

pub const MLDSA87_PK_LEN: usize = 2592;
pub const MLDSA87_SK_LEN: usize = 4896;
pub const MLDSA87_SIG_LEN: usize = 4627;
pub(crate) const MLDSA87_TAU: i32 = 60;
pub(crate) const MLDSA87_LAMBDA: i32 = 256;
pub(crate) const MLDSA87_GAMMA1: i32 = 1 << 19;
pub(crate) const MLDSA87_GAMMA2: i32 = (q - 1) / 32;
pub(crate) const MLDSA87_k: usize = 8;
pub(crate) const MLDSA87_l: usize = 7;
pub(crate) const MLDSA87_ETA: usize = 2;
pub(crate) const MLDSA87_BETA: i32 = 120;
pub(crate) const MLDSA87_OMEGA: i32 = 75;

// Useful derived values
pub(crate) const MLDSA87_C_TILDE: usize = 64;
pub(crate) const MLDSA87_POLY_Z_PACKED_LEN: usize = 640;
pub(crate) const MLDSA87_POLY_W1_PACKED_LEN: usize = 128;
pub(crate) const MLDSA87_W1_PACKED_LEN: usize = MLDSA87_k * MLDSA87_POLY_W1_PACKED_LEN;
pub(crate) const MLDSA87_POLY_ETA_PACKED_LEN: usize = 32*3;
pub(crate) const MLDSA87_LAMBDA_over_4: usize = 256/4;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA87_GAMMA1_MASK_LEN: usize = 640;



// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;


/*** Pub Types ***/
pub type MLDSA44 = MLDSA<
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

pub type MLDSA65 = MLDSA<
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

pub type MLDSA87 = MLDSA<
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


pub struct MLDSA<
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
    const POLY_VEC_H_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> {
    _phantom: PhantomData<(PK, SK)>,

    /// used for streaming the message for both signing and verifying
    mu_builder: MuBuilder,

    signer_rnd: Option<[u8; RND_LEN]>,

    /// only used in streaming sign operations
    sk: Option<SK>,

    /// only used in streaming verify operations
    pk: Option<PK>,
}

impl<
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
> MLDSA<
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
>
{
    /// Implements Algorithm 6 of FIPS 204
    /// Note: NIST has made a special exception in the FIPS 204 FAQ that this _internal function
    /// may in fact be exposed outside the crypto module.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_256bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key] -- todo: make sure this works and copies key type and security strength correctly.
    fn keygen_internal(
        seed: &KeyMaterial256,
    ) -> Result<
        (PK, SK),
        SignatureError,
    > {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::BytesFullEntropy)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(SignatureError::KeyGenError("Seed SecurityStrength must match algorithm security strength: 128-bit (ML-DSA-44), 192-bit (ML-DSA-65), or 256-bit (ML-DSA-87)."));
        }

        // Alg 6 line 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut rho_prime: [u8; 64] = [0u8; 64];
        let mut K: [u8; 32] = [0u8; 32];

        // TODO: optimization: re-use variables rather than allocating new ones?
        // TODO: do with benches because it might not actually be faster. Rust seems to like local vars.

        let mut h = H::default();
        h.absorb(seed.ref_to_bytes());
        h.absorb(&(k as u8).to_le_bytes());
        h.absorb(&(l as u8).to_le_bytes());
        let bytes_written = h.squeeze_out(&mut rho);
        debug_assert_eq!(bytes_written, 32); // todo: remove these asserts once we have unit tests that pass?
        let bytes_written = h.squeeze_out(&mut rho_prime);
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.squeeze_out(&mut K);
        debug_assert_eq!(bytes_written, 32);

        // 3: 𝐀_hat ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        let A_hat = expandA::<k, l>(&rho);

        // 4: (𝐬1, 𝐬2) ← ExpandS(𝜌′)
        let (s1, s2) = expandS::<k, l, ETA>(&rho_prime);

        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let mut s1_hat = s1.clone();
        s1_hat.ntt();
        // let s1_hat = ntt_vec::<l>(&s1);
        let mut t_hat = A_hat.matrix_vector_ntt(&s1_hat);
        t_hat.reduce();
        // let mut t = inv_ntt_vec(&t_hat);
        let mut t = t_hat;
        t.inv_ntt();
        t.add_vector_ntt(&s2);
        t.conditional_add_q();

        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, t0) = power_2_round_vec::<k>(&t);

        // 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1)
        let pk = PK::new(&rho, &t1);

        // 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
        let tr = pk.compute_tr();

        // 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
        //   ▷ 𝐾 and 𝑡𝑟 are for use in signing
        let sk = SK::new(&rho, &K, &tr, &s1, &s2, &t0, Some(seed.clone()));

        // Clear the secret data before returning memory to the OS
        //   (SK::new() copies all values)
        rho.fill(0u8);
        K.fill(0u8);
        // tr is public data, does not need to be zeroized
        // s1, s2, t0 are all Vectors of Polynomials, so implement a zeroizing Drop

        // 11: return (𝑝𝑘, 𝑠𝑘)
        Ok((pk, sk))
    }

    /*** Key Generation and PK / SK consistency checks ***/

    /// Should still be ok in FIPS mode
    pub fn keygen_from_os_rng() -> Result<
        (PK, SK),
        SignatureError,
    > {
        let mut seed = KeyMaterial256::new();
        HashDRBG_SHA512::new_from_os().fill_keymaterial_out(&mut seed)?;
        Self::keygen_internal(&seed)
    }

    /// Imports a secret key from a seed.
    pub fn keygen_from_seed(seed: &KeyMaterialSized<32>) -> Result<(PK, SK), SignatureError> {
        Self::keygen_internal(seed)
    }

    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    pub fn keygen_from_seed_and_encoded(
        seed: &KeyMaterialSized<32>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<
        (PK, SK),
        SignatureError,
    > {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes = SK::sk_decode(encoded_sk);

        // MLDSAPrivateKey impls PartialEq with a constant-time equality check.
        if sk != sk_from_bytes {
            return Err(SignatureError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }

    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    ///
    /// Returns either `()` or [SignatureError::ConsistencyCheckFailed].
    ///
    /// TODO -- sync with openssl implementation
    /// TODO -- https://github.com/openssl/openssl/blob/master/crypto/ml_dsa/ml_dsa_key.c#L385
    pub fn keypair_consistency_check(
        pk: &PK,
        sk: &SK,
    ) -> Result<(), SignatureError> {
        todo!()
    }

        /// This provides the first half of the "External Mu" interface to ML-DSA which is described
        /// in, and allowed under, NIST's FAQ that accompanies FIPS 204.
        ///
        /// This function, together with [sign_mu] perform a complete ML-DSA signature which is indistinguishable
        /// from one produced by the one-shot sign APIs.
        ///
        /// The utility of this function is exactly as described
        /// on Line 6 of Algorithm 7 of FIPS 204:
        ///
        ///    message representative that may optionally be computed in a different cryptographic module
        ///
        /// The utility is when an extremely large message needs to be signed, where the message exists on one
        /// computing system and the private key to sign it is held on another and either the transfer time or bandwidth
        /// causes operational concerns (this is common for example with network HSMs or sending large messages
        /// to be signed by a smartcard communicating over near-field radio). Another use case is if the
        /// contents of the message are sensitive and the signer does not want to transmit the message itself
        /// for fear of leaking it via proxy logging and instead would prefer to only transmit a hash of it.
        ///
        /// Since "External Mu" mode is well-defined by FIPS 204 and allowed by NIST, the mu value produced here
        /// can be used with many hardware crypto modules.
        ///
        /// This "External Mu" mode of ML-DSA provides an alternative to the HashML-DSA algorithm in that it
        /// allows the message to be externally pre-hashed, however, unlike HashML-DSA, this is merely an optimization
        /// between the application holding the to-be-signed message and the cryptographic module holding the private key
        /// -- in particular, while HashML-DSA requires the verifier to know whether ML-DSA or HashML-DSA was used to sign
        /// the message, both "direct" ML-DSA and "External Mu" signatures can be verified with a standard
        /// ML-DSA verifier.
        ///
        /// This function requires the public key hash `tr`, which can be computed from the public key using [MLDSAPublicKey::compute_tr].
        ///
        /// For a streaming version of this, see [MuBuilder].
        pub fn compute_mu_from_tr(
            msg: &[u8],
            ctx: Option<&[u8]>,
            tr: &[u8; 64],
        ) -> Result<[u8; 64], SignatureError> {
            MuBuilder::compute_mu(msg, ctx, tr)
        }

        /// Same as [compute_mu_from_tr], but extracts tr from the public key.
        pub fn compute_mu_from_pk(
            msg: &[u8],
            ctx: Option<&[u8]>,
            pk: &PK,
        ) -> Result<[u8; 64], SignatureError> {
            MuBuilder::compute_mu(msg, ctx, &pk.compute_tr())
        }

        /// Same as [compute_mu_from_tr], but extracts tr from the private key.
        pub fn compute_mu_from_sk(
            msg: &[u8],
            ctx: Option<&[u8]>,
            sk: &SK,
        ) -> Result<[u8; 64], SignatureError> {
            MuBuilder::compute_mu(msg, ctx, &sk.tr())
        }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    fn sign_mu(
        sk: &SK,
        mu: &[u8; 64],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_out(sk, mu, &mut out)?;
        Ok(out)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_mu_out(
        sk: &SK,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        let mut rnd: [u8; 32] = [0u8; 32];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;

        Self::sign_mu_deterministic_out(sk, mu, rnd, output)
    }

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed mu instead of M')
    ///
    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    ///
    pub fn sign_mu_deterministic(
        sk: &SK,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_deterministic_out(sk, mu, rnd, &mut out)?;
        Ok(out)
    }

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed mu instead of M')
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
    pub(crate) fn sign_mu_deterministic_out(
        sk: &SK,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        // 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ← skDecode(𝑠𝑘)
        // Already done -- the sk struct is already decoded

        // 2: 𝐬1̂_hat ← NTT(𝐬1)
        let mut s1_hat = sk.s1().clone();
        s1_hat.ntt();

        // 3: 𝐬2̂_hat ← NTT(𝐬2)
        let mut s2_hat = sk.s2().clone();
        s2_hat.ntt();

        // 4: 𝐭0̂_hat ← NTT(𝐭0)̂
        let mut t0_hat = sk.t0().clone();
        t0_hat.ntt();

        // 5: 𝐀_hat ← ExpandA(𝜌)
        let A_hat = expandA::<k, l>(&sk.rho());

        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        // skip: mu has already been provided

        // 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
        let mut h = H::new();
        h.absorb(sk.K());
        h.absorb(&rnd);
        h.absorb(mu);
        let mut rho_p_p = [0u8; 64];
        h.squeeze_out(&mut rho_p_p);

        // 8: 𝜅 ← 0
        //  ▷ initialize counter 𝜅
        let mut kappa: u16 = 0;

        // 9: (𝐳, 𝐡) ← ⊥
        // handled in the loop

        // 10: while (𝐳, 𝐡) = ⊥ do
        //  ▷ rejection sampling loop

        // these need to be outside the loop because they form the encoded signature value
        let mut sig_val_c_tilde = [0u8; LAMBDA_over_4];
        let mut sig_val_z: Vector<l>;
        let mut sig_val_h: Vector<k>;
        loop {
            // FIPS 204 s. 6.2 allows:
            //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
            if kappa > 1000 * k as u16 { return Err(SignatureError::GenericError("Rejection sampling loop exceeded max iterations, try again with a different signing nonce."))}

            // 11: 𝐲 ∈ 𝑅^ℓ ← ExpandMask(𝜌″, 𝜅)
            let mut y = expand_mask::<l, GAMMA1, GAMMA1_MASK_LEN>(&rho_p_p, kappa);

            // last use of rho_p_p, so zeroizing it
            rho_p_p.fill(0u8);

            // 12: 𝐰 ← NTT−1(𝐀_hat * NTT(𝐲))
            let mut y_hat = y.clone();
            y_hat.ntt();
            let mut w = A_hat.matrix_vector_ntt(&y_hat);
            w.inv_ntt();
            w.conditional_add_q();

            // 13: 𝐰1 ← HighBits(𝐰)
            //  ▷ signer’s commitment
            let w1 = w.high_bits::<GAMMA2>();

            // 15: 𝑐_tilde ← H(𝜇||w1Encode(𝐰1), 𝜆/4)
            //  ▷ commitment hash
            let mut hash = H::new();
            hash.absorb(mu);
            hash.absorb(&w1.w1_encode::<W1_PACKED_LEN, POLY_W1_PACKED_LEN>());
            hash.squeeze_out(&mut sig_val_c_tilde);

            // 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
            //  ▷ verifier’s challenge
            let c = sample_in_ball::<LAMBDA_over_4, TAU>(&sig_val_c_tilde);

            // 17: 𝑐_hat ← NTT(𝑐)
            let c_hat = ntt(&c);

            // 18: ⟨⟨𝑐𝐬1⟩⟩ ← NTT−1(𝑐_hat * 𝐬1_hat)
            //  Note: <<.>> in FIPS 204 means that this value will be used again later, so you should hang on to it.
            let mut cs1 = s1_hat.scalar_vector_ntt(&c_hat);
            cs1.inv_ntt();

            // 20: 𝐳 ← 𝐲 + ⟨⟨𝑐𝐬1⟩⟩
            y.add_vector_ntt(&cs1);
            sig_val_z = y;

            // 23 (first half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            // out-of-order on purpose for performance reasons:
            //   might as well do the rejection sampling check before any extra heavy computation
            if sig_val_z.check_norm(GAMMA1 - BETA) {
                kappa += l as u16;
                continue;
            };

            // 19: ⟨⟨𝑐𝐬2⟩⟩ ← NTT−1(𝑐_hat * 𝐬2̂_hat)
            let mut cs2 = s2_hat.scalar_vector_ntt(&c_hat);
            cs2.inv_ntt();

            // 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
            let mut r0 = w.sub_vector(&cs2).low_bits::<GAMMA2>();

            // 23 (second half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            if r0.check_norm(GAMMA2 - BETA) {
                kappa += l as u16;
                continue;
            };

            // 25: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1(𝑐_hat * 𝐭0̂_hat )
            let mut ct0 = t0_hat.scalar_vector_ntt(&c_hat);
            ct0.inv_ntt();

            // 28 (first half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            // out-of-order on purpose for performance reasons:
            //   might as well do the rejection sampling check before any extra heavy computation
            if ct0.check_norm(GAMMA2) {
                kappa += l as u16;
                continue;
            };

            // 26: 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐𝐭0⟩⟩)
            //  ▷ Signer’s hint
            r0.add_vector_ntt(&ct0);
            r0.conditional_add_q();
            let (hint, hint_hamming_weight) =
                // make_hint_vecs::<k, GAMMA2>(&ct0.neg(), &w.sub_vector(&cs2_plus_ct0));
                make_hint_vecs::<k, GAMMA2>(&r0, &w1);
            sig_val_h = hint;

            // 28 (second half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            if hint_hamming_weight > OMEGA {
                kappa += l as u16;
                continue;
            };

            // "In addition, there is an alternative way of implementing the validity checks on 𝐳 and the computation of
            // 𝐡, which is described in Section 5.1 of. This method may also be used in implementations of ML-DSA."
            // todo -- check this out

            break;
        }

        // 33: 𝜎 ← sigEncode(𝑐, 𝐳̃ mod±𝑞, 𝐡)
        let bytes_written = sig_encode::<GAMMA1, k, l, LAMBDA_over_4, OMEGA, POLY_Z_PACKED_LEN, SIG_LEN>
            (&sig_val_c_tilde, &sig_val_z, &sig_val_h, output);

        Ok(bytes_written)
    }

    /// To be used for deterministic signing in conjunction with the [MLDSA44::sign_init], [MLDSA44::sign_update], and [MLDSA44::sign_final] flow.
    /// Can be set anywhere after [MLDSA44::sign_init] and before [MLDSA44::sign_final]
    pub fn set_signer_rnd(&mut self, rnd: [u8; 32]) {
        self.signer_rnd = Some(rnd);
    }

    /// Algorithm 8 ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎)
    /// Internal function to verify a signature 𝜎 for a formatted message 𝑀′ .
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑) and message 𝑀′ ∈ {0, 1}∗ .
    /// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
    fn verify_mu_internal(
        pk: &PK,
        mu: &[u8; 64],
        sig: &[u8; SIG_LEN],
    ) -> bool {
        // 1: (𝜌, 𝐭1) ← pkDecode(𝑝𝑘)
        // Already done -- the pk struct is already decoded

        // 2: (𝑐_tilde, 𝐳, 𝐡) ← sigDecode(𝜎)
        //  ▷ signer’s commitment hash c_tilde, response 𝐳, and hint 𝐡
        // 3: if 𝐡 = ⊥ then return false
        let (c_tilde, z, h) = match sig_decode::<GAMMA1, k, l, LAMBDA_over_4, OMEGA, POLY_Z_PACKED_LEN, SIG_LEN>(&sig) {
            Ok((c_tilde, z, h)) => (c_tilde, z, h),
            Err(_) => return false,
        };

        // 13 (first half) return [[ ||𝐳||∞ < 𝛾1 − 𝛽]]
        if z.check_norm(GAMMA1 - BETA) {
            return false;
        }

        // 5: 𝐀 ← ExpandA(𝜌)
        //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        #[allow(non_snake_case)]
        let A_hat = expandA::<k, l>(&pk.rho());

        // 6: 𝑡𝑟 ← H(𝑝𝑘, 64)
        // 7: 𝜇 ← (H(BytesToBits(𝑡𝑟)||𝑀 ′, 64))
        //   ▷ message representative that may optionally be
        //     computed in a different cryptographic module
        // skip because this function is being handed mu

        // 8: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
        let c = sample_in_ball::<LAMBDA_over_4, TAU>(&c_tilde);


        // 9: 𝐰′_approx ← NTT−1(𝐀_hat ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑))
        //   broken out for clarity:
        //   NTT−1(
        //      𝐀_hat ∘ NTT(𝐳) −
        //                  NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑)
        //   )
        // ▷ 𝐰'_approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2^𝑑
        let mut z_hat = z.clone();
        z_hat.ntt();
        let w1 = A_hat.matrix_vector_ntt(&z_hat);
        let mut t1_shift_hat = pk.t1().shift_left::<d>();
        t1_shift_hat.ntt();
        let w2 = t1_shift_hat.scalar_vector_ntt( &ntt(&c) );
        let mut wp_approx = w1.sub_vector(&w2);
        wp_approx.inv_ntt();
        wp_approx.conditional_add_q();
        // bc-java does a wp_approx.conditional_add_q();

        // 10: 𝐰1′ ← UseHint(𝐡, 𝐰'_approx)
        // ▷ reconstruction of signer’s commitment
        let w1p = use_hint_vecs::<k, GAMMA2>(&h, &wp_approx);

        // 12: 𝑐_tilde_p ← H(𝜇||w1Encode(𝐰1'), 𝜆/4)
        // ▷ hash it; this should match 𝑐_tilde
        let mut c_tilde_p = [0u8; LAMBDA_over_4];
        let mut hash = H::new();
        hash.absorb(mu);
        /* DEBUG */ let tmp = w1p.w1_encode::<W1_PACKED_LEN, POLY_W1_PACKED_LEN>();
        hash.absorb(&w1p.w1_encode::<W1_PACKED_LEN, POLY_W1_PACKED_LEN>());
        hash.squeeze_out(&mut c_tilde_p);


        // verification probably doesn't technically need to be constant-time, but why not?
        // 13 (second half): return [[ ||𝐳||∞ < 𝛾1 − 𝛽]] and [[𝑐 ̃ = 𝑐′ ]]
        bouncycastle_utils::ct::ct_eq_bytes(&c_tilde, &c_tilde_p)
    }
}

impl<
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
> Signature<PK, SK> for MLDSA<
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

    fn keygen() -> Result<(PK, SK), SignatureError> {
        Self::keygen_from_os_rng()
    }

    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(sk: &SK, msg: &[u8], ctx: Option<&[u8]>, output: &mut [u8]) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.tr())?;
        if output.len() < SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let output_sized: &mut [u8; SIG_LEN] = output[..SIG_LEN].as_mut().try_into().unwrap();
        let bytes_written = Self::sign_mu_out(sk, &mu, output_sized)?;

        Ok(bytes_written)
    }

    fn sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        Ok(
            Self {
                _phantom: PhantomData,
                mu_builder: MuBuilder::do_init(&sk.tr(), ctx)?,
                signer_rnd: None,
                sk: Some(sk.clone()),
                pk: None }
        )
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.mu_builder.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<Vec<u8>, SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_final_out(&mut out)?;
        Ok(Vec::from(out))
    }

    fn sign_final_out(self, output: &mut [u8]) -> Result<usize, SignatureError> {
        let mu = self.mu_builder.do_final();

        assert!(self.sk.is_some(), "Somehow you managed to construct a streaming signer without a private key, impressive!");

        if output.len() < SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let output_sized: &mut [u8; SIG_LEN] = output[..SIG_LEN].as_mut().try_into().unwrap();

        if self.signer_rnd.is_none() {
            Ok(Self::sign_mu_out(&self.sk.unwrap(), &mu, output_sized)?)
        } else {
            Ok(Self::sign_mu_deterministic_out(&self.sk.unwrap(), &mu, self.signer_rnd.unwrap(), output_sized)?)
        }
    }

    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.compute_tr())?;

        if sig.len() != SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }
        if Self::verify_mu_internal(pk, &mu, &sig[..SIG_LEN].try_into().unwrap()) {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }

    fn verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        Ok(
            Self {
                _phantom: Default::default(),
                mu_builder: MuBuilder::do_init(&pk.compute_tr(), ctx)?,
                signer_rnd: None,
                sk: None,
                pk: Some(pk.clone()) }
        )
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.mu_builder.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let mu = self.mu_builder.do_final();

        assert!(self.pk.is_some(), "Somehow you managed to construct a streaming verifier without a public key, impressive!");

        if sig.len() != SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }
        if Self::verify_mu_internal(&self.pk.unwrap(), &mu, &sig[..SIG_LEN].try_into().unwrap()) {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }
}


/// Implements parts of Algorithm 2 and Line 6 of Algorithm 7 of FIPS 204.
/// Provides a stateful version of [compute_mu_from_pk] and [compute_mu_from_tr] that supports streaming
/// large to-be-signed messages.
// todo: probably the best way to handle HashML-DSA is to have this take a ::<const IS_HashMLDSA>
pub struct MuBuilder {
    h: H,
}

impl MuBuilder {
    /// Algorithm 7
    /// 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀′, 64)
    pub fn compute_mu(msg: &[u8], ctx: Option<&[u8]>, tr: &[u8; 64]) -> Result<[u8; 64], SignatureError> {
        let mut mu_builder = MuBuilder::do_init(&tr, ctx)?;
        mu_builder.do_update(msg);
        let mu = mu_builder.do_final();

        Ok(mu)
    }

    /// This function requires the public key hash `tr`, which can be computed from the public key using [MLDSAPublicKey::compute_tr].
    pub fn do_init(tr: &[u8; 64], ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let ctx = match ctx { Some(ctx) => ctx, None => &[] };

        // Algorithm 2
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut mb = Self { h: H::new() };
        mb.h.absorb(tr);

        // Algorithm 2
        // 10: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        // all done together
        mb.h.absorb(&[0u8]);
        mb.h.absorb(&[ctx.len() as u8]);
        mb.h.absorb(ctx);

        // now ready to absorb M
        Ok(mb)
    }

    /// Stream a chunk of the message.
    pub fn do_update(&mut self, msg_chunk: &[u8]) {
        self.h.absorb(msg_chunk);
    }

    /// Finalize and return the mu value.
    pub fn do_final(mut self) -> [u8; 64] {
        // Completion of
        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        let mut mu = [0u8; 64];
        self.h.squeeze_out(&mut mu);

        mu
    }
}
