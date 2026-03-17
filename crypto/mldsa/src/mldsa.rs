use std::vec::Vec;

use crate::aux_functions::{
    absorb_use_hint_w1, bitpack_gamma1_into, expand_a_matrix_vector_ntt, expand_mask_poly, inv_ntt,
    ntt, rej_ntt_poly, sample_in_ball, sig_decode,
};
use crate::mldsa_keys::{MLDSAPrivateKey, MLDSAPublicKey};
use crate::polynomial::{self, Polynomial};
use crate::{
    MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey,
    MLDSA87PublicKey,
};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::{
    KeyMaterial, KeyMaterial256, KeyMaterialSized, KeyType,
};
use bouncycastle_core_interface::traits::Signature;
use bouncycastle_core_interface::traits::{SecurityStrength, XOF};
use bouncycastle_core_interface::traits::RNG;
use bouncycastle_sha3::{SHAKE128, SHAKE256};
use bouncycastle_rng::HashDRBG_SHA512;

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
pub const MLDSA44_COMPACT_SK_LEN: usize = 896;
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
pub(crate) const MLDSA44_POLY_ETA_PACKED_LEN: usize = 32 * 3;
pub(crate) const MLDSA44_LAMBDA_over_4: usize = 128 / 4;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA44_GAMMA1_MASK_LEN: usize = 576; // 32*(1 + bitlen (𝛾1 − 1) )

/* ML-DSA-65 params */

pub const MLDSA65_PK_LEN: usize = 1952;
pub const MLDSA65_SK_LEN: usize = 4032;
pub const MLDSA65_COMPACT_SK_LEN: usize = 1536;
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
pub(crate) const MLDSA65_POLY_ETA_PACKED_LEN: usize = 32 * 4;
pub(crate) const MLDSA65_LAMBDA_over_4: usize = 192 / 4;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA65_GAMMA1_MASK_LEN: usize = 640;

/* ML-DSA-87 params */

pub const MLDSA87_PK_LEN: usize = 2592;
pub const MLDSA87_SK_LEN: usize = 4896;
pub const MLDSA87_COMPACT_SK_LEN: usize = 1568;
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
pub(crate) const MLDSA87_POLY_ETA_PACKED_LEN: usize = 32 * 3;
pub(crate) const MLDSA87_LAMBDA_over_4: usize = 256 / 4;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA87_GAMMA1_MASK_LEN: usize = 640;

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;

fn fill_seed_from_os(seed: &mut KeyMaterial256) -> Result<(), SignatureError> {
    HashDRBG_SHA512::new_from_os().fill_keymaterial_out(seed)?;
    Ok(())
}

fn fill_rnd_from_os(rnd: &mut [u8; 32]) -> Result<(), SignatureError> {
    HashDRBG_SHA512::new_from_os().next_bytes_out(rnd)?;
    Ok(())
}

pub(crate) fn expand_key_seed_material<const k: usize, const l: usize>(
    seed: &KeyMaterialSized<32>,
) -> ([u8; 32], [u8; 64], [u8; 32]) {
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut K = [0u8; 32];

    let mut h = H::default();
    h.absorb(seed.ref_to_bytes());
    h.absorb(&(k as u8).to_le_bytes());
    h.absorb(&(l as u8).to_le_bytes());
    h.squeeze_out(&mut rho);
    h.squeeze_out(&mut rho_prime);
    h.squeeze_out(&mut K);

    (rho, rho_prime, K)
}

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
    const POLY_W1_PACKED_LEN: usize,
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const COMPACT_SK_LEN: usize,
    const GAMMA1_MASK_LEN: usize,
> {
    // only used in streaming sign operations
    priv_key: Option<MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>>,

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
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const W1_PACKED_LEN: usize,
    const POLY_ETA_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const COMPACT_SK_LEN: usize,
    const GAMMA1_MASK_LEN: usize,
>
    MLDSA<
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
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        W1_PACKED_LEN,
        POLY_ETA_PACKED_LEN,
        LAMBDA_over_4,
        COMPACT_SK_LEN,
        GAMMA1_MASK_LEN,
    >
{
    fn compute_w_row(rho: &[u8; 32], rho_p_p: &[u8; 64], kappa: u16, row: usize) -> Polynomial {
        debug_assert!(l > 0);

        let mut y_hat = ntt(&expand_mask_poly::<GAMMA1, GAMMA1_MASK_LEN>(rho_p_p, kappa));
        let mut acc = polynomial::multiply_ntt(&rej_ntt_poly(rho, &[0u8, row as u8]), &y_hat);

        for col in 1..l {
            y_hat = ntt(&expand_mask_poly::<GAMMA1, GAMMA1_MASK_LEN>(rho_p_p, kappa + col as u16));
            let tmp = polynomial::multiply_ntt(&rej_ntt_poly(rho, &[col as u8, row as u8]), &y_hat);
            acc.add_ntt(&tmp);
        }

        polynomial::reduce_poly(&mut acc);
        let mut w = inv_ntt(&acc);
        w.conditional_add_q();
        w
    }

    fn compute_z_component(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
        rho_p_p: &[u8; 64],
        c_hat: &Polynomial,
        kappa: u16,
        col: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Option<Polynomial>, SignatureError> {
        let y = expand_mask_poly::<GAMMA1, GAMMA1_MASK_LEN>(rho_p_p, kappa + col as u16);
        let s1_hat = ntt(&sk.s1_poly(col, rho_prime)?);
        let mut cs1 = polynomial::multiply_ntt(&s1_hat, c_hat);
        polynomial::reduce_poly(&mut cs1);
        let mut z = inv_ntt(&cs1);
        z.add_ntt(&y);

        if z.check_norm(GAMMA1 - BETA) { Ok(None) } else { Ok(Some(z)) }
    }

    fn compute_w0cs2_component(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
        w: &Polynomial,
        c_hat: &Polynomial,
        row: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Option<Polynomial>, SignatureError> {
        let s2_hat = ntt(&sk.s2_poly(row, rho_prime)?);
        let mut cs2 = polynomial::multiply_ntt(&s2_hat, c_hat);
        polynomial::reduce_poly(&mut cs2);
        let cs2 = inv_ntt(&cs2);

        let mut w0cs2 = w.low_bits::<GAMMA2>();
        w0cs2.sub(&cs2);
        if w0cs2.check_norm(GAMMA2 - BETA) { Ok(None) } else { Ok(Some(w0cs2)) }
    }

    fn compute_ct0_component(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
        c_hat: &Polynomial,
        row: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Option<Polynomial>, SignatureError> {
        let t0_row = sk.derive_t0_row(row, rho_prime)?;
        let t0_hat = ntt(&t0_row);
        let mut ct0 = polynomial::multiply_ntt(&t0_hat, c_hat);
        polynomial::reduce_poly(&mut ct0);
        let ct0 = inv_ntt(&ct0);

        if ct0.check_norm(GAMMA2) { Ok(None) } else { Ok(Some(ct0)) }
    }

    fn validate_seed(seed: &KeyMaterial256) -> Result<(), SignatureError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::BytesFullEntropy)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(SignatureError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength: 128-bit (ML-DSA-44), 192-bit (ML-DSA-65), or 256-bit (ML-DSA-87).",
            ));
        }

        Ok(())
    }

    fn private_key_from_seed_internal(
        seed: &KeyMaterial256,
    ) -> Result<MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>, SignatureError> {
        Self::validate_seed(seed)?;

        // Alg 6 line 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let (rho, rho_prime, K) = expand_key_seed_material::<k, l>(seed);
        let provisional_sk = MLDSAPrivateKey::<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN> {
            rho,
            K,
            tr: [0u8; 64],
            compact_bytes: None,
            seed: Some(seed.clone()),
        };

        let tr = provisional_sk.compute_tr_from_rows(Some(&rho_prime))?;

        Ok(MLDSAPrivateKey::<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN> {
            rho: provisional_sk.rho,
            K: provisional_sk.K,
            tr,
            compact_bytes: None,
            seed: Some(seed.clone()),
        })
    }

    fn pk_encode_from_seed_internal(
        seed: &KeyMaterial256,
        output: &mut [u8; PK_LEN],
    ) -> Result<[u8; 64], SignatureError> {
        Self::validate_seed(seed)?;
        let (rho, rho_prime, K) = expand_key_seed_material::<k, l>(seed);
        let sk = MLDSAPrivateKey::<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN> {
            rho,
            K,
            tr: [0u8; 64],
            compact_bytes: None,
            seed: Some(seed.clone()),
        };
        sk.pk_encode_rows_into(Some(&rho_prime), output)
    }

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
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>),
        SignatureError,
    > {
        let sk = Self::private_key_from_seed_internal(seed)?;
        let mut pk_bytes = [0u8; PK_LEN];
        let tr = Self::pk_encode_from_seed_internal(seed, &mut pk_bytes)?;
        debug_assert_eq!(tr, sk.tr);
        let pk = MLDSAPublicKey::<k, PK_LEN>::pk_decode(&pk_bytes);

        // 11: return (𝑝𝑘, 𝑠𝑘)
        Ok((pk, sk))
    }

    /*** Key Generation and PK / SK consistency checks ***/

    /// Should still be ok in FIPS mode
    fn keygen_from_os_rng() -> Result<
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>),
        SignatureError,
    > {
        let mut seed = KeyMaterial256::new();
        fill_seed_from_os(&mut seed)?;
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
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>),
        SignatureError,
    > {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes =
            MLDSAPrivateKey::<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>::sk_decode(encoded_sk);

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
        sk: MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
    ) -> Result<(), SignatureError> {
        todo!()
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    pub fn sign_mu(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
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
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        let mut rnd: [u8; 32] = [0u8; 32];
        fill_rnd_from_os(&mut rnd)?;

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
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
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
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        Self::sign_mu_internal_out(sk, mu, rnd, output)
    }

    pub(crate) fn sign_mu_internal_out(
        sk: &MLDSAPrivateKey<k, l, ETA, SK_LEN, PK_LEN, COMPACT_SK_LEN>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
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

        let mut sig_val_c_tilde = [0u8; LAMBDA_over_4];
        let rho_prime = if sk.compact_bytes.is_none() { Some(sk.seed_rho_prime()?) } else { None };
        let rho_prime_ref = rho_prime.as_ref();
        let z_offset = LAMBDA_over_4;
        let hint_offset = LAMBDA_over_4 + l * POLY_Z_PACKED_LEN;
        let mut encoded_w1 = [0u8; POLY_W1_PACKED_LEN];

        loop {
            // FIPS 204 s. 6.2 allows:
            //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
            if kappa > 1000 * k as u16 {
                return Err(SignatureError::GenericError(
                    "Rejection sampling loop exceeded max iterations, try again with a different signing nonce.",
                ));
            }

            // 11-15: derive c_tilde without materializing y_hat or w as full vectors.
            let mut hash = H::new();
            hash.absorb(mu);
            for row in 0..k {
                let mut w = Self::compute_w_row(&sk.rho, &rho_p_p, kappa, row);
                w.high_bits_assign::<GAMMA2>();
                w.w1_encode_into::<POLY_W1_PACKED_LEN>(&mut encoded_w1);
                hash.absorb(&encoded_w1);
            }
            hash.squeeze_out(&mut sig_val_c_tilde);

            // 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
            // 17: 𝑐_hat ← NTT(𝑐)
            let c_hat = ntt(&sample_in_ball::<LAMBDA_over_4, TAU>(&sig_val_c_tilde));

            output.fill(0);
            output[..LAMBDA_over_4].copy_from_slice(&sig_val_c_tilde);

            let (z_chunks, z_remainder) = output[z_offset..z_offset + l * POLY_Z_PACKED_LEN]
                .as_chunks_mut::<POLY_Z_PACKED_LEN>();
            debug_assert_eq!(z_chunks.len(), l);
            debug_assert_eq!(z_remainder.len(), 0);

            // 18-23 (z path): compute and encode each z polynomial directly into the caller buffer.
            let mut rejected = false;
            for col in 0..l {
                let z = match Self::compute_z_component(
                    sk, &rho_p_p, &c_hat, kappa, col, rho_prime_ref,
                )? {
                    Some(z) => z,
                    None => {
                        rejected = true;
                        break;
                    }
                };

                bitpack_gamma1_into::<POLY_Z_PACKED_LEN, GAMMA1>(&z, &mut z_chunks[col]);
            }

            if rejected {
                kappa += l as u16;
                continue;
            }

            // 19-28 (hint path): recompute rows as needed and write the packed hint directly.
            let mut hint_count = 0usize;
            for row in 0..k {
                let w = Self::compute_w_row(&sk.rho, &rho_p_p, kappa, row);
                let mut tmp =
                    match Self::compute_w0cs2_component(sk, &w, &c_hat, row, rho_prime_ref)? {
                        Some(tmp) => tmp,
                        None => {
                            rejected = true;
                            break;
                        }
                    };

                let ct0 = match Self::compute_ct0_component(sk, &c_hat, row, rho_prime_ref)? {
                    Some(ct0) => ct0,
                    None => {
                        rejected = true;
                        break;
                    }
                };

                tmp.add_ntt(&ct0);
                tmp.conditional_add_q();

                let w1 = w.high_bits::<GAMMA2>();
                let (hint_row, weight) = tmp.make_hint::<GAMMA2>(&w1);
                let next_hint_count = hint_count + weight as usize;
                if next_hint_count > OMEGA as usize {
                    rejected = true;
                    break;
                }

                for idx in 0..N {
                    if hint_row.0[idx] != 0 {
                        output[hint_offset + hint_count] = idx as u8;
                        hint_count += 1;
                    }
                }
                debug_assert_eq!(hint_count, next_hint_count);
                output[hint_offset + OMEGA as usize + row] = hint_count as u8;
            }

            if rejected {
                kappa += l as u16;
                continue;
            }

            return Ok(SIG_LEN);
        }
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
        let (c_tilde, mut z, h) = match sig_decode::<
            GAMMA1,
            k,
            l,
            LAMBDA_over_4,
            OMEGA,
            POLY_Z_PACKED_LEN,
            SIG_LEN,
        >(&sig)
        {
            Ok((c_tilde, z, h)) => (c_tilde, z, h),
            Err(_) => return false,
        };

        // 13 (first half) return [[ ||𝐳||∞ < 𝛾1 − 𝛽]]
        if z.check_norm(GAMMA1 - BETA) {
            return false;
        }

        // 5: 𝐀 ← ExpandA(𝜌)
        //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        // 6: 𝑡𝑟 ← H(𝑝𝑘, 64)
        // 7: 𝜇 ← (H(BytesToBits(𝑡𝑟)||𝑀 ′, 64))
        //   ▷ message representative that may optionally be
        //     computed in a different cryptographic module
        // skip because this function is being handed mu

        // 8: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
        // 9: 𝐰′_approx ← NTT−1(𝐀_hat ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑))
        //   broken out for clarity:
        //   NTT−1(
        //      𝐀_hat ∘ NTT(𝐳) −
        //                  NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑)
        //   )
        // ▷ 𝐰'_approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2^𝑑
        z.ntt();
        let mut wp_approx = expand_a_matrix_vector_ntt::<k, l>(&pk.rho, &z);
        let mut t1_shift_hat = pk.t1.clone();
        t1_shift_hat.shift_left_in_place::<d>();
        t1_shift_hat.ntt();
        let w2 =
            t1_shift_hat.scalar_vector_ntt(&ntt(&sample_in_ball::<LAMBDA_over_4, TAU>(&c_tilde)));
        wp_approx.sub_assign(&w2);
        wp_approx.reduce();
        wp_approx.inv_ntt();
        wp_approx.conditional_add_q();

        // 12: 𝑐_tilde_p ← H(𝜇||w1Encode(𝐰1'), 𝜆/4)
        // ▷ hash it; this should match 𝑐_tilde
        let mut c_tilde_p = [0u8; LAMBDA_over_4];
        let mut hash = H::new();
        hash.absorb(mu);
        absorb_use_hint_w1::<k, GAMMA2, POLY_W1_PACKED_LEN>(&mut hash, &h, &wp_approx);
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
    MLDSA44_COMPACT_SK_LEN,
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

    fn sign_out(
        sk: &MLDSA44PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.0.tr)?;
        if output.len() < MLDSA44_SIG_LEN {
            return Err(SignatureError::LengthError(
                "Output buffer insufficient size to hold signature",
            ));
        }
        let sig_out: &mut [u8; MLDSA44_SIG_LEN] =
            (&mut output[..MLDSA44_SIG_LEN]).try_into().unwrap();
        Self::sign_mu_out(sk, &mu, sig_out)
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

    fn sign_final_out(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify(
        pk: &MLDSA44PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;

        if sig.len() != MLDSA44_SIG_LEN {
            return Err(SignatureError::LengthError("Signature value is not the correct length."));
        }

        if MLDSA44impl::verify_mu_internal(&pk.0, &mu, &sig[..MLDSA44_SIG_LEN].try_into().unwrap())
        {
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

    fn verify_final(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureError> {
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
    MLDSA65_POLY_Z_PACKED_LEN,
    MLDSA65_POLY_W1_PACKED_LEN,
    MLDSA65_W1_PACKED_LEN,
    MLDSA65_POLY_ETA_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_COMPACT_SK_LEN,
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

    /// Expand only the seed-backed private key material required for signing.
    pub fn private_key_from_seed(
        seed: &KeyMaterialSized<32>,
    ) -> Result<MLDSA65PrivateKey, SignatureError> {
        Ok(MLDSA65PrivateKey(MLDSA65impl::private_key_from_seed_internal(seed)?))
    }

    /// Same as [private_key_from_seed], but takes a raw 32-byte seed.
    pub fn private_key_from_seed_bytes(
        seed: &[u8; 32],
    ) -> Result<MLDSA65PrivateKey, SignatureError> {
        let seed = KeyMaterial256::from_bytes_as_type(seed, KeyType::Seed)
            .map_err(|_| SignatureError::KeyGenError("Invalid ML-DSA seed material"))?;
        Self::private_key_from_seed(&seed)
    }

    /// Encode the public key directly from the seed without constructing a full `MLDSA65PublicKey`.
    pub fn pk_encode_from_seed(
        seed: &KeyMaterialSized<32>,
    ) -> Result<[u8; MLDSA65_PK_LEN], SignatureError> {
        let mut out = [0u8; MLDSA65_PK_LEN];
        MLDSA65impl::pk_encode_from_seed_internal(seed, &mut out)?;
        Ok(out)
    }

    /// Same as [pk_encode_from_seed], but takes a raw 32-byte seed.
    pub fn pk_encode_from_seed_bytes(
        seed: &[u8; 32],
    ) -> Result<[u8; MLDSA65_PK_LEN], SignatureError> {
        let seed = KeyMaterial256::from_bytes_as_type(seed, KeyType::Seed)
            .map_err(|_| SignatureError::KeyGenError("Invalid ML-DSA seed material"))?;
        Self::pk_encode_from_seed(&seed)
    }

    /// Encode the public key directly from the seed into the provided output buffer.
    pub fn pk_encode_from_seed_out(
        seed: &KeyMaterialSized<32>,
        output: &mut [u8; MLDSA65_PK_LEN],
    ) -> Result<(), SignatureError> {
        MLDSA65impl::pk_encode_from_seed_internal(seed, output)?;
        Ok(())
    }

    /// Same as [pk_encode_from_seed_out], but takes a raw 32-byte seed.
    pub fn pk_encode_from_seed_bytes_out(
        seed: &[u8; 32],
        output: &mut [u8; MLDSA65_PK_LEN],
    ) -> Result<(), SignatureError> {
        let seed = KeyMaterial256::from_bytes_as_type(seed, KeyType::Seed)
            .map_err(|_| SignatureError::KeyGenError("Invalid ML-DSA seed material"))?;
        Self::pk_encode_from_seed_out(&seed, output)
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

    pub fn verify_mu(
        pk: &MLDSA65PublicKey,
        mu: &[u8; 64],
        sig: &[u8; MLDSA65_SIG_LEN],
    ) -> Result<(), SignatureError> {
        if MLDSA65impl::verify_mu_internal(&pk.0, mu, sig) {
            Ok(())
        } else {
            Err(SignatureError::SignatureVerificationFailed)
        }
    }

    pub fn verify(
        pk: &MLDSA65PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8; MLDSA65_SIG_LEN],
    ) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;
        Self::verify_mu(pk, &mu, sig)
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

    fn sign_out(
        sk: &MLDSA65PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.0.tr)?;
        if output.len() < MLDSA65_SIG_LEN {
            return Err(SignatureError::LengthError(
                "Output buffer insufficient size to hold signature",
            ));
        }
        let sig_out: &mut [u8; MLDSA65_SIG_LEN] =
            (&mut output[..MLDSA65_SIG_LEN]).try_into().unwrap();
        Self::sign_mu_out(sk, &mu, sig_out)
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

    fn sign_final_out(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify(
        pk: &MLDSA65PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;

        if sig.len() != MLDSA65_SIG_LEN {
            return Err(SignatureError::LengthError("Signature value is not the correct length."));
        }

        if MLDSA65impl::verify_mu_internal(&pk.0, &mu, &sig[..MLDSA65_SIG_LEN].try_into().unwrap())
        {
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

    fn verify_final(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureError> {
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
    MLDSA87_POLY_Z_PACKED_LEN,
    MLDSA87_POLY_W1_PACKED_LEN,
    MLDSA87_W1_PACKED_LEN,
    MLDSA87_POLY_ETA_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_COMPACT_SK_LEN,
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
        pk: &MLDSA87PublicKey,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(msg, ctx, &pk.compute_tr())
    }

    /// Same as [compute_mu_from_tr], but extracts tr from the private key.
    pub fn compute_mu_from_sk(
        msg: &[u8],
        ctx: &[u8],
        sk: &MLDSA87PrivateKey,
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
        rnd: [u8; 32],
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

    fn sign_out(
        sk: &MLDSA87PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<usize, SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &sk.0.tr)?;
        if output.len() < MLDSA87_SIG_LEN {
            return Err(SignatureError::LengthError(
                "Output buffer insufficient size to hold signature",
            ));
        }
        let sig_out: &mut [u8; MLDSA87_SIG_LEN] =
            (&mut output[..MLDSA87_SIG_LEN]).try_into().unwrap();
        Self::sign_mu_out(sk, &mu, sig_out)
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

    fn sign_final_out(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify(
        pk: &MLDSA87PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(msg, ctx, &pk.0.compute_tr())?;

        if sig.len() != MLDSA87_SIG_LEN {
            return Err(SignatureError::LengthError("Signature value is not the correct length."));
        }

        if MLDSA87impl::verify_mu_internal(&pk.0, &mu, &sig[..MLDSA87_SIG_LEN].try_into().unwrap())
        {
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

    fn verify_final(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        todo!()
    }
}
