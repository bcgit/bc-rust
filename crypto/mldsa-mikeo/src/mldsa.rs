use crate::aux_functions::{expand_mask, expandA, expandS, inv_ntt_vec, make_hint_vecs, ntt, ntt_vec, power_2_round_vec, sample_in_ball, sig_encode, sig_decode, use_hint_vecs};
use crate::matrix::Vector;
use crate::mldsa_keys::{MLDSAPrivateKey, MLDSAPublicKey};
use crate::{MLDSA44PublicKey, MLDSA44PrivateKey, MLDSA65PublicKey, MLDSA65PrivateKey, MLDSA87PublicKey, MLDSA87PrivateKey};
// use crate::{
//     MLDSA44_PK_LEN,
//     MLDSA44_SK_LEN,
//     MLDSA44_SIG_LEN,
//     MLDSA44_TAU,
//     MLDSA44_GAMMA1,
//     MLDSA44_GAMMA2,
//     MLDSA44_k,
//     MLDSA44_l,
//     MLDSA44_ETA,
//     MLDSA44_BETA,
//     MLDSA44_OMEGA,
//     MLDSA44_C_TILDE,
//     MLDSA44_POLY_VEC_H_PACKED_LEN,
//     MLDSA44_POLY_Z_PACKED_LEN,
//     MLDSA44_POLY_W1_PACKED_LEN,
//     MLDSA44_POLY_ETA_PACKED_LEN,
//     MLDSA44_LAMBDA_over_4,
//     MLDSA44_GAMMA1_MASK_LEN,
// };
// use crate::{
//     MLDSA65_PK_LEN,
//     MLDSA65_SK_LEN,
//     MLDSA65_SIG_LEN,
//     MLDSA65_TAU,
//     MLDSA65_GAMMA1,
//     MLDSA65_GAMMA2,
//     MLDSA65_k,
//     MLDSA65_l,
//     MLDSA65_ETA,
//     MLDSA65_BETA,
//     MLDSA65_OMEGA,
//     MLDSA65_C_TILDE,
//     MLDSA65_POLY_VEC_H_PACKED_LEN,
//     MLDSA65_POLY_Z_PACKED_LEN,
//     MLDSA65_POLY_W1_PACKED_LEN,
//     MLDSA65_POLY_ETA_PACKED_LEN,
//     MLDSA65_LAMBDA_over_4,
//     MLDSA65_GAMMA1_MASK_LEN,
// };
// use crate::{
//     MLDSA87_PK_LEN,
//     MLDSA87_SK_LEN,
//     MLDSA87_SIG_LEN,
//     MLDSA87_TAU,
//     MLDSA87_GAMMA1,
//     MLDSA87_GAMMA2,
//     MLDSA87_k,
//     MLDSA87_l,
//     MLDSA87_ETA,
//     MLDSA87_BETA,
//     MLDSA87_OMEGA,
//     MLDSA87_C_TILDE,
//     MLDSA87_POLY_VEC_H_PACKED_LEN,
//     MLDSA87_POLY_Z_PACKED_LEN,
//     MLDSA87_POLY_W1_PACKED_LEN,
//     MLDSA87_POLY_ETA_PACKED_LEN,
//     MLDSA87_LAMBDA_over_4,
//     MLDSA87_GAMMA1_MASK_LEN,
// };
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
pub(crate) const SEED_LEN: usize = 32;
pub(crate) const RND_LEN: usize = 32;
pub(crate) const TR_LEN: usize = 64;
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
// pub(crate) const MLDSA44_POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
pub(crate) const MLDSA44_POLY_Z_PACKED_LEN: usize = 576;
pub(crate) const MLDSA44_POLY_W1_PACKED_LEN: usize = 192;
pub(crate) const MLDSA44_W1_PACKED_LEN: usize = MLDSA44_k * MLDSA44_POLY_W1_PACKED_LEN;
pub(crate) const MLDSA44_POLY_ETA_PACKED_LEN: usize = 32*3;
pub(crate) const MLDSA44_LAMBDA_over_4: usize = 128/4;
// todo -- bc-java does it as compute: 576usize.div_ceil(symmetric.stream_256_block_bytes) -- which should be 5
// todo -- might need to debug this against bc-java
// todo -- debug this against bc-java; or look in other implementations. I feel like this should be 32*17=544 or 32*19=608
// todo -- I'm not sure why they're adding an extra 32
// todo -- corresponds to aux_functions::expand_mask()

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
// pub(crate) const MLDSA65_POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
pub(crate) const MLDSA65_POLY_Z_PACKED_LEN: usize = 640;
pub(crate) const MLDSA65_POLY_W1_PACKED_LEN: usize = 128;
pub(crate) const MLDSA65_W1_PACKED_LEN: usize = MLDSA65_k * MLDSA65_POLY_W1_PACKED_LEN;
pub(crate) const MLDSA65_POLY_ETA_PACKED_LEN: usize = 32*4;
pub(crate) const MLDSA65_GAMMA1_MASK_LEN: usize = 640; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
pub(crate) const MLDSA65_LAMBDA_over_4: usize = 192/4;



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
// pub(crate) const MLDSA87_POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
pub(crate) const MLDSA87_POLY_Z_PACKED_LEN: usize = 640;
pub(crate) const MLDSA87_POLY_W1_PACKED_LEN: usize = 128;
pub(crate) const MLDSA87_W1_PACKED_LEN: usize = MLDSA87_k * MLDSA87_POLY_W1_PACKED_LEN;
pub(crate) const MLDSA87_POLY_ETA_PACKED_LEN: usize = 32*3;
pub(crate) const MLDSA87_GAMMA1_MASK_LEN: usize = 640; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
pub(crate) const MLDSA87_LAMBDA_over_4: usize = 256/4;



// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;

struct MLDSA<
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
    const POLY_VEC_H_PACKED_LEN: usize,
    // const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MASK_LEN: usize,
> {
    // only used in streaming sign operations
    priv_key: Option<MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>>,

    // only used in streaming verify operations
    pub_key: Option<MLDSAPublicKey<k, PK_LEN>>,
}

impl<
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
    // const POLY_VEC_H_PACKED_LEN: usize,
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
    // POLY_VEC_H_PACKED_LEN,
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
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>),
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

        // TODO: optimization: re-use variables rather than allocating new ones.
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
        let s1_hat = ntt_vec::<l>(&s1);
        let mut t_hat = A_hat.matrix_vector_ntt(&s1_hat);
        t_hat.reduce();
        let mut t = inv_ntt_vec(&t_hat);
        t.add_vector_ntt(&s2);
        t.conditional_add_q();

        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, t0) = power_2_round_vec::<k>(&t);

        // 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1)
        let pk = MLDSAPublicKey::<k, PK_LEN>::new(&rho, &t1);

        // 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
        let tr = pk.compute_tr();

        // 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
        //   ▷ 𝐾 and 𝑡𝑟 are for use in signing
        let sk = MLDSAPrivateKey::new(&rho, &K, &tr, &s1, &s2, &t0, Some(seed.clone()));

        // 11: return (𝑝𝑘, 𝑠𝑘)
        Ok((pk, sk))
    }

    /*** Key Generation and PK / SK consistency checks ***/

    /// Should still be ok in FIPS mode
    fn keygen_from_os_rng() -> Result<
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>),
        SignatureError,
    > {
        let mut seed = KeyMaterial256::new();
        HashDRBG_SHA512::new_from_os().fill_keymaterial_out(&mut seed)?;
        Self::keygen_internal(&seed)
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
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>),
        SignatureError,
    > {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes = MLDSAPrivateKey::<k, l, ETA, SK_LEN, PK_LEN>::sk_decode(encoded_sk);

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
        pk: MLDSAPublicKey<k, PK_LEN>,
        sk: MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>,
    ) -> Result<(), SignatureError> {
        todo!()
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    pub fn sign_mu(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>,
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
    pub fn sign_mu_out(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        let mut rnd: [u8; 32] = [0u8; 32];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;

        Self::sign_mu_internal_out(sk, mu, rnd, output)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    ///
    pub fn sign_mu_deterministic(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_internal_out(sk, mu, rnd, &mut out)?;
        Ok(out)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_deterministic_out(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        let mut rnd: [u8; 32] = [0u8; 32];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;

        Self::sign_mu_internal_out(sk, mu, rnd, output)
    }

    pub(crate) fn sign_mu_internal_out(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        // 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ← skDecode(𝑠𝑘)
        // Already done -- the sk struct is already decoded

        // 2: 𝐬1̂_hat ← NTT(𝐬1)
        let s1_hat = ntt_vec::<l>(&sk.s1);

        // 3: 𝐬2̂_hat ← NTT(𝐬2)
        let s2_hat = ntt_vec::<k>(&sk.s2);

        // 4: 𝐭0̂_hat ← NTT(𝐭0)̂
        let t0_hat = ntt_vec::<k>(&sk.t0);

        // 5: 𝐀_hat ← ExpandA(𝜌)
        let A_hat = expandA::<k, l>(&sk.rho);

        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        // skip: mu has already been provided

        // 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
        let mut h = H::new();
        h.absorb(&sk.K);
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
            // if count > 1000 { return Err(SignatureError::GenericError("Rejection sampling loop hit the hard-coded maximum number of iterations. Simply try again with a different random nonce rnd.")); }
            // count += 1;

            // todo: as the nursary does, could optimize by having the output vars work directly in the output signature buffer
            // todo: optimize by changing many of the member functions of matrix.rs to work in-ploce, then `let` rename the variable
            // todo:   ie figure out where you can consume the input variable, then just do it in place with a rename instead.

            // 11: 𝐲 ∈ 𝑅^ℓ ← ExpandMask(𝜌″, 𝜅)
            let mut y = expand_mask::<l, GAMMA1, GAMMA1_MASK_LEN>(&rho_p_p, kappa);

            // 12: 𝐰 ← NTT−1(𝐀_hat * NTT(𝐲))
            let y_hat = &y.ntt();
            let w_hat = A_hat.matrix_vector_ntt(y_hat);
            let mut w = w_hat.inv_ntt();
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
            let cs1 = (s1_hat.scalar_vector_ntt(&c_hat)).inv_ntt();

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
            let cs2 = s2_hat.scalar_vector_ntt(&c_hat).inv_ntt();

            // 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
            let mut r0 = w.sub_vector(&cs2).low_bits::<GAMMA2>();

            // 23 (second half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            if r0.check_norm(GAMMA2 - BETA) {
                kappa += l as u16;
                continue;
            };

            // 25: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1(𝑐_hat * 𝐭0̂_hat )
            let ct0 = t0_hat.scalar_vector_ntt(&c_hat).inv_ntt();

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

    /// Algorithm 8 ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎)
    /// Internal function to verify a signature 𝜎 for a formatted message 𝑀′ .
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑) and message 𝑀′ ∈ {0, 1}∗ .
    /// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
    pub fn verify_mu_internal(
        pk: &MLDSAPublicKey<k, PK_LEN>,
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
        let A_hat = expandA::<k, l>(&pk.rho);

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
        let w1 = A_hat.matrix_vector_ntt(&z.ntt());
        let w2 = pk.t1.shift_left::<d>().ntt().scalar_vector_ntt( &ntt(&c) );
        let wp_approx = w1.sub_vector(&w2).inv_ntt();

        // todo -- nursery has a
        // todo --   w1.reduce();
        //           w1.inverse_ntt_to_mont();
        //           w1.conditional_add_q();
        // todo -- here

        // 10: 𝐰1′ ← UseHint(𝐡, 𝐰'_approx)
        // ▷ reconstruction of signer’s commitment
        let w1p = use_hint_vecs::<k, GAMMA2>(&h, &wp_approx);

        // 12: 𝑐_tilde_p ← H(𝜇||w1Encode(𝐰1'), 𝜆/4)
        // ▷ hash it; this should match 𝑐_tilde
        let mut c_tilde_p = [0u8; LAMBDA_over_4];
        let mut hash = H::new();
        hash.absorb(mu);
        hash.absorb(&w1p.w1_encode::<W1_PACKED_LEN, POLY_W1_PACKED_LEN>());
        hash.squeeze_out(&mut c_tilde_p);


        // verification probably doesn't technically need to be constant-time, but why not?
        // 13 (second half): return [[ ||𝐳||∞ < 𝛾1 − 𝛽]] and [[𝑐 ̃ = 𝑐′ ]]
        bouncycastle_utils::ct::ct_eq_bytes(&c_tilde, &c_tilde_p)
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
    pub fn compute_mu(msg: &[u8], ctx: &[u8], tr: &[u8; 64]) -> Result<[u8; 64], SignatureError> {
        let mut mu_builder = MuBuilder::do_init(&tr, ctx)?;
        mu_builder.do_update(msg);
        let mu = mu_builder.do_final();

        Ok(mu)
    }

    /// This function requires the public key hash `tr`, which can be computed from the public key using [MLDSAPublicKey::compute_tr].
    pub fn do_init(tr: &[u8; 64], ctx: &[u8]) -> Result<Self, SignatureError> {
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



/*** ML-DSA-44 ***/

// todo -- crunch these three identical implementations down with a macro

pub struct MLDSA44 {
    // only used in streaming sign operations
    priv_key: Option<MLDSA44PrivateKey>,

    // only used in streaming verify operations
    pub_key: Option<MLDSA44PublicKey>,
}
type MLDSA44impl = MLDSA<
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_SIG_LEN,
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
    // MLDSA44_POLY_VEC_H_PACKED_LEN,
    MLDSA44_POLY_Z_PACKED_LEN,
    MLDSA44_POLY_W1_PACKED_LEN,
    MLDSA44_W1_PACKED_LEN,
    MLDSA44_POLY_ETA_PACKED_LEN,
    MLDSA44_LAMBDA_over_4,
    MLDSA44_GAMMA1_MASK_LEN,
>;

impl MLDSA44 {
    /// Genarate a fresh key pair using the default cryptographic RNG, seeded from the OS.
    pub fn keygen_from_os_rng() -> Result<(MLDSA44PublicKey, MLDSA44PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA44impl::keygen_from_os_rng()?;
        Ok((MLDSA44PublicKey(pk), MLDSA44PrivateKey(sk)))
    }

    /// Expand a (pk, sk) keypair from a private key seed.
    /// Both pk and sk objects will be fully populated.
    /// This is simply a pass-through to [MLDSA::keygen_internal], which is allowed to be exposed externally by NIST.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_256bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key] -- todo: make sure this works and copies key type and security strength correctly.
    pub fn keygen_from_seed(
        seed: &KeyMaterialSized<32>,
    ) -> Result<(MLDSA44PublicKey, MLDSA44PrivateKey), SignatureError> {
        // todo: can I make this infallible?
        let (pk, sk) = MLDSA44impl::keygen_internal(&seed)?;
        Ok((MLDSA44PublicKey(pk), MLDSA44PrivateKey(sk)))
    }

    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    pub fn keygen_from_seed_and_encoded(
        seed: &KeyMaterialSized<32>,
        encoded_sk: &[u8; MLDSA44_SK_LEN],
    ) -> Result<(MLDSA44PublicKey, MLDSA44PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA44impl::keygen_from_seed_and_encoded(seed, encoded_sk)?;
        Ok((MLDSA44PublicKey(pk), MLDSA44PrivateKey(sk)))
    }

    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    /// TODO -- sync with openssl implementation
    /// TODO -- https://github.com/openssl/openssl/blob/master/crypto/ml_dsa/ml_dsa_key.c#L385
    pub fn keypair_consistency_check(
        pk: MLDSA44PublicKey,
        sk: MLDSA44PrivateKey,
    ) -> Result<(), SignatureError> {
        MLDSA44impl::keypair_consistency_check(pk.0, sk.0)
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
        ctx: &[u8],
        tr: &[u8; 64],
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, tr)
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the public key.
    pub fn compute_mu_from_pk(
        msg: &[u8],
        ctx: &[u8],
        pk: &MLDSA44PublicKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &pk.compute_tr())
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the private key.
    pub fn compute_mu_from_sk(
        msg: &[u8],
        ctx: &[u8],
        sk: &MLDSA44PrivateKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &sk.0.tr)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    pub fn sign_mu(
        sk: &MLDSA44PrivateKey,
        mu: &[u8; 64],
    ) -> Result<[u8; MLDSA44_SIG_LEN], SignatureError> {
        MLDSA44impl::sign_mu(&sk.0, mu)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_out(
        sk: &MLDSA44PrivateKey,
        mu: &[u8; 64],
        output: &mut [u8; MLDSA44_SIG_LEN],
    ) -> Result<usize, SignatureError> {
        MLDSA44impl::sign_mu_out(&sk.0, mu, output)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    pub fn sign_mu_deterministic(
        sk: &MLDSA44PrivateKey,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; MLDSA44_SIG_LEN], SignatureError> {
        MLDSA44impl::sign_mu_deterministic(&sk.0, mu, rnd)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_deterministic_out(
        sk: &MLDSA44PrivateKey,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; MLDSA44_SIG_LEN],
    ) -> Result<usize, SignatureError> {
        MLDSA44impl::sign_mu_deterministic_out(&sk.0, mu, rnd, output)
    }

}

impl Signature<MLDSA44PublicKey, MLDSA44PrivateKey> for MLDSA44 {

    fn keygen() -> Result<(MLDSA44PublicKey, MLDSA44PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA44impl::keygen_from_os_rng()?;
        Ok((MLDSA44PublicKey(pk), MLDSA44PrivateKey(sk)))
    }

    fn sign(sk: &MLDSA44PrivateKey, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; MLDSA44_SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(sk: &MLDSA44PrivateKey, msg: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.0.tr)?;
        if output.len() < MLDSA44_SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let mut output_sized: [u8; MLDSA44_SIG_LEN] = output[..MLDSA44_SIG_LEN].try_into().unwrap();
        Self::sign_mu_out(sk, &mu, &mut output_sized)
    }

    fn sign_init(&mut self, sk: &MLDSA44PrivateKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn sign_final(&mut self, msg_chunk: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        todo!()
    }

    fn sign_final_out(&mut self, msg_chunk: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify(pk: &MLDSA44PublicKey, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;
        
        if sig.len() != MLDSA44_SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }
        
        if MLDSA44impl::verify_mu_internal(&pk.0, &mu, &sig[..MLDSA44_SIG_LEN].try_into().unwrap()) {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }

    fn verify_init(&mut self, sk: &MLDSA44PublicKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn verify_final(&mut self, msg_chunk: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        todo!()
    }
}




/*** ML-DSA-65 ***/

// exported as pub in lib.rs
pub struct MLDSA65 {
    // only used in streaming sign operations
    priv_key: Option<MLDSA65PrivateKey>,

    // only used in streaming verify operations
    pub_key: Option<MLDSA65PublicKey>,
}
type MLDSA65impl = MLDSA<
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_SIG_LEN,
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
    // MLDSA65_POLY_VEC_H_PACKED_LEN,
    MLDSA65_POLY_Z_PACKED_LEN,
    MLDSA65_POLY_W1_PACKED_LEN,
    MLDSA65_W1_PACKED_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_GAMMA1_MASK_LEN,
>;

impl MLDSA65 {
    /// Genarate a fresh key pair using the default cryptographic RNG, seeded from the OS.
    pub fn keygen_from_os_rng() -> Result<(MLDSA65PublicKey, MLDSA65PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA65impl::keygen_from_os_rng()?;
        Ok((MLDSA65PublicKey(pk), MLDSA65PrivateKey(sk)))
    }

    /// Expand a (pk, sk) keypair from a private key seed.
    /// Both pk and sk objects will be fully populated.
    /// This is simply a pass-through to [MLDSA::keygen_internal], which is allowed to be exposed externally by NIST.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_256bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key] -- todo: make sure this works and copies key type and security strength correctly.
    pub fn keygen_from_seed(
        seed: &KeyMaterialSized<32>,
    ) -> Result<(MLDSA65PublicKey, MLDSA65PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA65impl::keygen_internal(&seed)?;
        Ok((MLDSA65PublicKey(pk), MLDSA65PrivateKey(sk)))
    }

    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    pub fn keygen_from_seed_and_encoded(
        seed: &KeyMaterialSized<32>,
        encoded_sk: &[u8; MLDSA65_SK_LEN],
    ) -> Result<(MLDSA65PublicKey, MLDSA65PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA65impl::keygen_from_seed_and_encoded(seed, encoded_sk)?;
        Ok((MLDSA65PublicKey(pk), MLDSA65PrivateKey(sk)))
    }

    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    /// TODO -- sync with openssl implementation
    /// TODO -- https://github.com/openssl/openssl/blob/master/crypto/ml_dsa/ml_dsa_key.c#L385
    pub fn keypair_consistency_check(
        pk: MLDSA65PublicKey,
        sk: MLDSA65PrivateKey,
    ) -> Result<(), SignatureError> {
        MLDSA65impl::keypair_consistency_check(pk.0, sk.0)
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
        ctx: &[u8],
        tr: &[u8; 64],
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, tr)
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the public key.
    pub fn compute_mu_from_pk(
        msg: &[u8],
        ctx: &[u8],
        pk: &MLDSA65PublicKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &pk.compute_tr())
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the private key.
    pub fn compute_mu_from_sk(
        msg: &[u8],
        ctx: &[u8],
        sk: &MLDSA65PrivateKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &sk.0.tr)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    pub fn sign_mu(
        sk: &MLDSA65PrivateKey,
        mu: &[u8; 64],
    ) -> Result<[u8; MLDSA65_SIG_LEN], SignatureError> {
        MLDSA65impl::sign_mu(&sk.0, mu)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_out(
        sk: &MLDSA65PrivateKey,
        mu: &[u8; 64],
        output: &mut [u8; MLDSA65_SIG_LEN],
    ) -> Result<usize, SignatureError> {
        MLDSA65impl::sign_mu_out(&sk.0, mu, output)
    }


    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    pub fn sign_mu_deterministic(
        sk: &MLDSA65PrivateKey,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; MLDSA65_SIG_LEN], SignatureError> {
        MLDSA65impl::sign_mu_deterministic(&sk.0, mu, rnd)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_deterministic_out(
        sk: &MLDSA65PrivateKey,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; MLDSA65_SIG_LEN],
    ) -> Result<usize, SignatureError> {
        MLDSA65impl::sign_mu_deterministic_out(&sk.0, mu, rnd, output)
    }
}

impl Signature<MLDSA65PublicKey, MLDSA65PrivateKey> for MLDSA65 {

    fn keygen() -> Result<(MLDSA65PublicKey, MLDSA65PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA65impl::keygen_from_os_rng()?;
        Ok((MLDSA65PublicKey(pk), MLDSA65PrivateKey(sk)))
    }

    fn sign(sk: &MLDSA65PrivateKey, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; MLDSA65_SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(sk: &MLDSA65PrivateKey, msg: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.0.tr)?;
        if output.len() < MLDSA65_SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let mut output_sized: [u8; MLDSA65_SIG_LEN] = output[..MLDSA65_SIG_LEN].try_into().unwrap();
        Self::sign_mu_out(sk, &mu, &mut output_sized)
    }

    fn sign_init(&mut self, sk: &MLDSA65PrivateKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn sign_final(&mut self, msg_chunk: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        todo!()
    }

    fn sign_final_out(&mut self, msg_chunk: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify(pk: &MLDSA65PublicKey, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;

        if sig.len() != MLDSA65_SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }

        if MLDSA65impl::verify_mu_internal(&pk.0, &mu, &sig[..MLDSA65_SIG_LEN].try_into().unwrap()) {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }

    fn verify_init(&mut self, sk: &MLDSA65PublicKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn verify_final(&mut self, msg_chunk: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        todo!()
    }
}



/*** ML-DSA-87 ***/

// exported as pub in lib.rs
pub struct MLDSA87 {
    // only used in streaming sign operations
    priv_key: Option<MLDSA87PrivateKey>,

    // only used in streaming verify operations
    pub_key: Option<MLDSA87PublicKey>,
}
type MLDSA87impl = MLDSA<
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_SIG_LEN,
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
    // MLDSA87_POLY_VEC_H_PACKED_LEN,
    MLDSA87_POLY_Z_PACKED_LEN,
    MLDSA87_POLY_W1_PACKED_LEN,
    MLDSA87_W1_PACKED_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_GAMMA1_MASK_LEN,
>;

impl MLDSA87 {
    /// Genarate a fresh key pair using the default cryptographic RNG, seeded from the OS.
    pub fn keygen_from_os_rng() -> Result<(MLDSA87PublicKey, MLDSA87PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA87impl::keygen_from_os_rng()?;
        Ok((MLDSA87PublicKey(pk), MLDSA87PrivateKey(sk)))
    }

    /// Expand a (pk, sk) keypair from a private key seed.
    /// Both pk and sk objects will be fully populated.
    /// This is simply a pass-through to [MLDSA::keygen_internal], which is allowed to be exposed externally by NIST.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_256bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key] -- todo: make sure this works and copies key type and security strength correctly.
    pub fn keygen_from_seed(
        seed: &KeyMaterialSized<32>,
    ) -> Result<(MLDSA87PublicKey, MLDSA87PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA87impl::keygen_internal(&seed)?;
        Ok((MLDSA87PublicKey(pk), MLDSA87PrivateKey(sk)))
    }

    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    pub fn keygen_from_seed_and_encoded(
        seed: &KeyMaterialSized<32>,
        encoded_sk: &[u8; MLDSA87_SK_LEN],
    ) -> Result<(MLDSA87PublicKey, MLDSA87PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA87impl::keygen_from_seed_and_encoded(seed, encoded_sk)?;
        Ok((MLDSA87PublicKey(pk), MLDSA87PrivateKey(sk)))
    }

    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    /// TODO -- sync with openssl implementation
    /// TODO -- https://github.com/openssl/openssl/blob/master/crypto/ml_dsa/ml_dsa_key.c#L385
    pub fn keypair_consistency_check(
        pk: MLDSA87PublicKey,
        sk: MLDSA87PrivateKey,
    ) -> Result<(), SignatureError> {
        MLDSA87impl::keypair_consistency_check(pk.0, sk.0)
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
        ctx: &[u8],
        tr: [u8; 64],
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &tr)
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the public key.
    pub fn compute_mu_from_pk(
        msg: &[u8],
        ctx: &[u8],
        pk: &MLDSA65PublicKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &pk.compute_tr())
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the private key.
    pub fn compute_mu_from_sk(
        msg: &[u8],
        ctx: &[u8],
        sk: &MLDSA65PrivateKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &sk.0.tr)
    }


    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    pub fn sign_mu(
        sk: &MLDSA87PrivateKey,
        mu: &[u8; 64],
    ) -> Result<[u8; MLDSA87_SIG_LEN], SignatureError> {
        MLDSA87impl::sign_mu(&sk.0, mu)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_out(
        sk: &MLDSA87PrivateKey,
        mu: &[u8; 64],
        output: &mut [u8; MLDSA87_SIG_LEN],
    ) -> Result<usize, SignatureError> {
        MLDSA87impl::sign_mu_out(&sk.0, mu, output)
    }


    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    pub fn sign_mu_deterministic(
        sk: &MLDSA87PrivateKey,
        mu: &[u8; 64],
        rnd: [u8; 32]
    ) -> Result<[u8; MLDSA87_SIG_LEN], SignatureError> {
        MLDSA87impl::sign_mu_deterministic(&sk.0, mu, rnd)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    pub fn sign_mu_deterministic_out(
        sk: &MLDSA87PrivateKey,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; MLDSA87_SIG_LEN],
    ) -> Result<usize, SignatureError> {
        MLDSA87impl::sign_mu_deterministic_out(&sk.0, mu, rnd, output)
    }
}

impl Signature<MLDSA87PublicKey, MLDSA87PrivateKey> for MLDSA87 {

    fn keygen() -> Result<(MLDSA87PublicKey, MLDSA87PrivateKey), SignatureError> {
        let (pk, sk) = MLDSA87impl::keygen_from_os_rng()?;
        Ok((MLDSA87PublicKey(pk), MLDSA87PrivateKey(sk)))
    }

    fn sign(sk: &MLDSA87PrivateKey, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; MLDSA87_SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(sk: &MLDSA87PrivateKey, msg: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.0.tr)?;
        if output.len() < MLDSA87_SIG_LEN { return Err(SignatureError::LengthError("Output buffer insufficient size to hold signature")) }
        let mut output_sized: [u8; MLDSA87_SIG_LEN] = output[..MLDSA87_SIG_LEN].try_into().unwrap();
        Self::sign_mu_out(sk, &mu, &mut output_sized)
    }

    fn sign_init(&mut self, sk: &MLDSA87PrivateKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn sign_final(&mut self, msg_chunk: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        todo!()
    }

    fn sign_final_out(&mut self, msg_chunk: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify(pk: &MLDSA87PublicKey, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;

        if sig.len() != MLDSA87_SIG_LEN { return Err(SignatureError::LengthError("Signature value is not the correct length.")) }

        if MLDSA87impl::verify_mu_internal(&pk.0, &mu, &sig[..MLDSA87_SIG_LEN].try_into().unwrap()) {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }

    fn verify_init(&mut self, sk: &MLDSA87PublicKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn verify_final(&mut self, msg_chunk: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        todo!()
    }
}
