use crate::aux_functions::{
    bit_pack_eta, bit_pack_t0, bitlen_eta, power_2_round, rej_bounded_poly, simple_bit_pack_t1,
    simple_bit_unpack_t1,
};
use crate::low_memory_helpers::{expandA_elem, s_unpack};
use crate::mldsa::{H, N, POLY_T0PACKED_LEN};
use crate::mldsa::{
    MLDSA44_ETA, MLDSA44_FULL_SK_LEN, MLDSA44_GAMMA2, MLDSA44_LAMBDA, MLDSA44_PK_LEN,
    MLDSA44_S1_PACKED_LEN, MLDSA44_S2_PACKED_LEN, MLDSA44_SK_LEN, MLDSA44_k, MLDSA44_l,
};
use crate::mldsa::{
    MLDSA44_T1_PACKED_LEN, MLDSA65_T1_PACKED_LEN, MLDSA87_T1_PACKED_LEN, POLY_T1PACKED_LEN,
};
use crate::mldsa::{
    MLDSA65_ETA, MLDSA65_FULL_SK_LEN, MLDSA65_GAMMA2, MLDSA65_LAMBDA, MLDSA65_PK_LEN,
    MLDSA65_S1_PACKED_LEN, MLDSA65_S2_PACKED_LEN, MLDSA65_SK_LEN, MLDSA65_k, MLDSA65_l,
};
use crate::mldsa::{
    MLDSA87_ETA, MLDSA87_FULL_SK_LEN, MLDSA87_GAMMA2, MLDSA87_LAMBDA, MLDSA87_PK_LEN,
    MLDSA87_S1_PACKED_LEN, MLDSA87_S2_PACKED_LEN, MLDSA87_SK_LEN, MLDSA87_k, MLDSA87_l,
};
use crate::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    Secret, SecurityStrength, SignaturePrivateKey, SignaturePublicKey, XOF,
};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;
use crate::polynomial::Polynomial;

/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44_k, MLDSA44_T1_PACKED_LEN, MLDSA44_PK_LEN>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey = MLDSASeedPrivateKey<
    MLDSA44_LAMBDA,
    MLDSA44_GAMMA2,
    MLDSA44_k,
    MLDSA44_l,
    MLDSA44_ETA,
    MLDSA44_S1_PACKED_LEN,
    MLDSA44_S2_PACKED_LEN,
    MLDSA44_T1_PACKED_LEN,
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_FULL_SK_LEN,
>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65_k, MLDSA65_T1_PACKED_LEN, MLDSA65_PK_LEN>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey = MLDSASeedPrivateKey<
    MLDSA65_LAMBDA,
    MLDSA65_GAMMA2,
    MLDSA65_k,
    MLDSA65_l,
    MLDSA65_ETA,
    MLDSA65_S1_PACKED_LEN,
    MLDSA65_S2_PACKED_LEN,
    MLDSA65_T1_PACKED_LEN,
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_FULL_SK_LEN,
>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87_k, MLDSA87_T1_PACKED_LEN, MLDSA87_PK_LEN>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey = MLDSASeedPrivateKey<
    MLDSA87_LAMBDA,
    MLDSA87_GAMMA2,
    MLDSA87_k,
    MLDSA87_l,
    MLDSA87_ETA,
    MLDSA87_S1_PACKED_LEN,
    MLDSA87_S2_PACKED_LEN,
    MLDSA87_T1_PACKED_LEN,
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_FULL_SK_LEN,
>;

/// An ML-DSA public key.
#[derive(Clone)]
pub struct MLDSAPublicKey<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) t1_packed: [u8; T1_PACKED_LEN],
}

/// General trait for all ML-DSA public keys types.
pub trait MLDSAPublicKeyTrait<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize>:
    SignaturePublicKey<PK_LEN>
{
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self;

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    fn compute_tr(&self) -> [u8; 64];
}

pub(crate) trait MLDSAPublicKeyInternalTrait<
    const k: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: [u8; 32], t1_packed: [u8; T1_PACKED_LEN]) -> Self;

    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get a ref to t1
    fn unpack_t1_row(&self, row: usize) -> Polynomial;
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize>
    MLDSAPublicKeyTrait<k, T1_PACKED_LEN, PK_LEN> for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        Self { rho: pk[..32].try_into().unwrap(), t1_packed: pk[32..].try_into().unwrap() }
    }

    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&self.encode(), &mut tr);

        tr
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize>
    MLDSAPublicKeyInternalTrait<k, T1_PACKED_LEN, PK_LEN>
    for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
    fn new(rho: [u8; 32], t1_packed: [u8; T1_PACKED_LEN]) -> Self {
        Self { rho, t1_packed }
    }

    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    fn unpack_t1_row(&self, row: usize) -> Polynomial {
        simple_bit_unpack_t1(
            &self.t1_packed[row * POLY_T1PACKED_LEN..(row + 1) * POLY_T1PACKED_LEN]
                .try_into()
                .unwrap(),
        )
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> SignaturePublicKey<PK_LEN>
    for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        self.encode_out(&mut pk);

        pk
    }
    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        debug_assert_eq!(out.len(), PK_LEN);

        out.fill(0);

        out[..32].copy_from_slice(&self.rho);
        out[32..].copy_from_slice(&self.t1_packed);

        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != PK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let sized_bytes: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(Self::pk_decode(&sized_bytes))
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> Eq
    for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> PartialEq
    for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> fmt::Debug
    for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(f, "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.compute_tr(),)
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> Display
    for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(f, "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.compute_tr(),)
    }
}

/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<
    const k: usize,
    const l: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
>: SignaturePrivateKey<SK_LEN>
{
    /// New from KeyMaterial. Can throw a SignatureError if the KeyMaterial does not contain sufficient entropy.
    fn from_keymaterial(seed: &KeyMaterial<32>) -> Result<Self, SignatureError>;

    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> Option<&KeyMaterial<32>>;

    /// Get a copy of the key hash `tr`.
    /// This is computationally intensive as it requires fully re-computing the public key (and then discarding it).
    /// It is highly recommended that if you already have a copy of the public key, get `tr` from that,
    /// or else compute tr once and store it.
    fn tr(&self) -> [u8; 64];
    /// Returns the full public key, and has the side-effect of setting the public key hash tr in this MLDSASeedSK object.
    fn derive_pk(&self) -> MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>;
    /// This produces the full private key in the encoding specified in FIPS 204 Algorithm 24 skEncode()
    /// so that it is compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [MLDSASeedPrivateKey].
    fn encode_full_sk(&self) -> [u8; FULL_SK_LEN];
    /// This produces the full private key in the encoding specified in FIPS 204 Algorithm 24 skEncode()
    /// so that it is compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [MLDSASeedPrivateKey].
    fn encode_full_sk_out(&self, out: &mut [u8; FULL_SK_LEN]) -> usize;
    /// Algorithm 25 skDecode(𝑠𝑘)
    /// Reverses the procedure skEncode.
    /// Input: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((ℓ+𝑘)⋅bitlen (2𝜂)+𝑑𝑘).
    /// Output: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 ,
    /// 𝐬1 ∈ 𝑅ℓ , 𝐬2 ∈ 𝑅𝑘 , 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    ///
    /// Note: this object contains only the simple decoding routine to unpack a semi-expanded key.
    /// See [MLDSATrait] for key generation functions, including derive-from-seed and consistency-check functions.
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self;
}

/// Internal structure for holding a seed-based private key for ML-DSA.
#[derive(Clone, PartialEq, Eq)]
pub struct MLDSASeedPrivateKey<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
> {
    seed: KeyMaterial<32>,
    rho: [u8; 32],
    rho_prime: [u8; 64],
    K: [u8; 32],
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const FULL_SK_LEN: usize,
> Drop
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    fn drop(&mut self) {
        // seed is a KeyMaterialSized which will zeroize itself
        self.rho.fill(0u8);
        self.rho_prime.fill(0u8);
        self.K.fill(0u8);
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
> Secret
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
> Debug
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(f, "MLDSASeedPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.tr(),)
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
> Display
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(f, "MLDSASeedPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.tr(),)
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
>
    MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    /// Create a new MLDSASeedPrivateKey from a 32-byte KeyMaterial.
    /// Seed SecurityStrength must match algorithm security strength: 128-bit (ML-DSA-44), 192-bit (ML-DSA-65), or 256-bit (ML-DSA-87),
    /// otherwise it throws a SignatureError::KeyGenError("SecurityStrength".
    pub fn new(seed: &KeyMaterial<32>) -> Result<Self, SignatureError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(SignatureError::KeyGenError("SecurityStrength"));
        }

        let (rho, rho_prime, K) = Self::compute_rhos_and_K(&seed);
        Ok(Self { seed: seed.clone(), rho, rho_prime, K })
    }

    fn compute_rhos_and_K(seed: &KeyMaterial<32>) -> ([u8; 32], [u8; 64], [u8; 32]) {
        // derive sk.K
        // Alg 6; 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut rho_prime: [u8; 64] = [0u8; 64];
        let mut K: [u8; 32] = [0u8; 32];

        let mut h = H::default();
        h.absorb(seed.ref_to_bytes());
        h.absorb(&(k as u8).to_le_bytes());
        h.absorb(&(l as u8).to_le_bytes());
        let bytes_written = h.squeeze_out(&mut rho);
        debug_assert_eq!(bytes_written, 32);
        let bytes_written = h.squeeze_out(&mut rho_prime);
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.squeeze_out(&mut K);
        debug_assert_eq!(bytes_written, 32);

        (rho, rho_prime, K)
    }

    fn compute_t_row(&self, idx: usize, s1_packed: &[u8], s2_packed: &[u8]) -> Polynomial {
        debug_assert!(idx < k);

        // [Optimization Note]:
        // This is one of the places that a row of s1 can be re-computed instead of expanded from the compressed form.
        // let mut s1 = self.compute_s1_row(0);
        let mut s1_hat_i = s_unpack::<eta>(s1_packed, 0);
        s1_hat_i.ntt();

        let mut t_i = {
            let mut t_hat_i = expandA_elem(&self.rho, idx, 0);
            t_hat_i.multiply_ntt(&s1_hat_i);

            for col in 1..l {
                // [Optimization Note]:
                // This is one of the places that a row of s1 can be re-computed instead of expanded from the compressed form.
                // s1 = self.compute_s1_row(col);
                let mut s1_hat = s_unpack::<eta>(s1_packed, col);
                s1_hat.ntt();
                let mut A_elem = expandA_elem(&self.rho, idx, col);
                A_elem.multiply_ntt(&s1_hat);
                t_hat_i.add_ntt(&A_elem);
            }
            t_hat_i.inv_ntt();

            t_hat_i
        };

        // [Optimization Note]:
        // This is one of the places that a row of s2 can be re-computed instead of unpacked from the compressed form.
        // let s2 = self.compute_s2_row(idx);
        let s2 = s_unpack::<eta>(s2_packed, idx);
        t_i.add_ntt(&s2);
        t_i.conditional_add_q();

        t_i
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
> SignaturePrivateKey<SK_LEN>
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    /// Encodes the private key seed.
    fn encode(&self) -> [u8; SK_LEN] {
        debug_assert_eq!(SK_LEN, /* seed */ 32);

        self.seed.ref_to_bytes().try_into().unwrap()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        out.copy_from_slice(self.seed.ref_to_bytes());

        debug_assert_eq!(self.seed.ref_to_bytes().len(), SK_LEN);
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != 32 {
            return Err(SignatureError::DecodingError("Invalid seed length"));
        }
        let mut keymat = KeyMaterial::<32>::from_bytes(bytes)?;
        key_material::do_hazardous_operations(&mut keymat, |keymat| {
            keymat.set_key_type(KeyType::Seed)?;
            keymat.set_security_strength(SecurityStrength::_256bit)
        })?;

        Self::new(&keymat)
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
>
    MLDSAPrivateKeyTrait<
        k,
        l,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    fn from_keymaterial(seed: &KeyMaterial<32>) -> Result<Self, SignatureError> {
        Self::new(seed)
    }

    fn seed(&self) -> Option<&KeyMaterial<32>> {
        Some(&self.seed)
    }

    fn tr(&self) -> [u8; 64] {
        let pk: MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> = self.derive_pk();
        pk.compute_tr()
    }

    fn derive_pk(&self) -> MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
        // The goal here is to get t1, which we will build and compress one row at a time.

        let s1_packed: [u8; S1_PACKED_LEN] = self.compute_s1_packed();
        let s2_packed: [u8; S2_PACKED_LEN] = self.compute_s2_packed();

        let mut t1_packed = [0u8; T1_PACKED_LEN];
        debug_assert_eq!(T1_PACKED_LEN, POLY_T1PACKED_LEN * k);

        for i in 0..k {
            t1_packed[i * POLY_T1PACKED_LEN..(i + 1) * POLY_T1PACKED_LEN].copy_from_slice(
                &simple_bit_pack_t1(&self.compute_t1_row(i, &s1_packed, &s2_packed)),
            );
        }

        MLDSAPublicKey::<k, T1_PACKED_LEN, PK_LEN>::new(self.rho.clone(), t1_packed)
    }
    fn encode_full_sk(&self) -> [u8; FULL_SK_LEN] {
        let mut out = [0; FULL_SK_LEN];
        _ = self.encode_full_sk_out(&mut out);

        out
    }
    fn encode_full_sk_out(&self, out: &mut [u8; FULL_SK_LEN]) -> usize {
        out.fill(0);

        // Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)

        let mut off: usize = 0;

        // 1: 𝑠𝑘 ← 𝜌||𝐾||𝑡𝑟
        out[0..32].copy_from_slice(&self.rho);
        out[32..64].copy_from_slice(&self.K);
        out[64..128].copy_from_slice(&self.tr());
        off += 128;

        // 2: for 𝑖 from 0 to ℓ − 1 do
        // 3:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐬1[𝑖], 𝜂, 𝜂)
        // 4: end for
        let s1_packed = self.compute_s1_packed();
        out[off..off + S1_PACKED_LEN].copy_from_slice(&s1_packed);
        off += S1_PACKED_LEN;

        // 5: for 𝑖 from 0 to 𝑘 − 1 do
        // 6:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐬2[𝑖], 𝜂, 𝜂)
        // 7: end for
        let s2_packed = self.compute_s2_packed();
        out[off..off + S2_PACKED_LEN].copy_from_slice(&s2_packed);
        off += S2_PACKED_LEN;

        // 8: for 𝑖 from 0 to 𝑘 − 1 do
        // 9:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐭0[𝑖], 2𝑑−1 − 1, 2𝑑−1)
        // 10: end for
        debug_assert_eq!(off + k * POLY_T0PACKED_LEN, FULL_SK_LEN);
        for row in 0..k {
            let t0_i = self.compute_t0_row(row, &s1_packed, &s2_packed);
            out[off..off + POLY_T0PACKED_LEN].copy_from_slice(&bit_pack_t0(&t0_i));
            off += POLY_T0PACKED_LEN;
        }
        debug_assert_eq!(off, FULL_SK_LEN);

        FULL_SK_LEN
    }

    fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
        Self::from_bytes(sk).unwrap()
    }
}

pub(crate) trait MLDSAPrivateKeyInternalTrait<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>: Sized
{
    fn rho(&self) -> &[u8; 32];
    fn K(&self) -> &[u8; 32];

    fn compute_s1_row(&self, idx: usize) -> Polynomial;

    fn compute_s1_packed(&self) -> [u8; S1_PACKED_LEN];

    fn compute_s2_row(&self, idx: usize) -> Polynomial;

    fn compute_s2_packed(&self) -> [u8; S2_PACKED_LEN];

    fn compute_t0_row(&self, idx: usize, s1_packed: &[u8], s2_packed: &[u8]) -> Polynomial;

    fn compute_t1_row(&self, idx: usize, s1_packed: &[u8], s2_packed: &[u8]) -> Polynomial;
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
>
    MLDSAPrivateKeyInternalTrait<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        PK_LEN,
        SK_LEN,
    >
    for MLDSASeedPrivateKey<
        LAMBDA,
        GAMMA2,
        k,
        l,
        eta,
        S1_PACKED_LEN,
        S2_PACKED_LEN,
        T1_PACKED_LEN,
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
    >
{
    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    fn K(&self) -> &[u8; 32] {
        &self.K
    }

    fn compute_s1_row(&self, idx: usize) -> Polynomial {
        debug_assert!(idx < l);
        rej_bounded_poly::<eta>(&self.rho_prime, &(idx as u16).to_le_bytes())
    }

    fn compute_s1_packed(&self) -> [u8; S1_PACKED_LEN] {
        let mut s1_packed = [0u8; S1_PACKED_LEN];
        for idx in 0..l {
            let s1_i = self.compute_s1_row(idx);
            bit_pack_eta::<eta>(
                &s1_i,
                &mut s1_packed[idx * bitlen_eta(eta)..(idx + 1) * bitlen_eta(eta)],
            );
        }
        s1_packed
    }

    fn compute_s2_row(&self, idx: usize) -> Polynomial {
        debug_assert!(idx < k);
        rej_bounded_poly::<eta>(&self.rho_prime, &((idx + l) as u16).to_le_bytes())
    }

    fn compute_s2_packed(&self) -> [u8; S2_PACKED_LEN] {
        let mut s2_packed = [0u8; S2_PACKED_LEN];
        for idx in 0..k {
            let s2_i = self.compute_s2_row(idx);
            bit_pack_eta::<eta>(
                &s2_i,
                &mut s2_packed[idx * bitlen_eta(eta)..(idx + 1) * bitlen_eta(eta)],
            );
        }
        s2_packed
    }

    fn compute_t0_row(&self, idx: usize, s1_packed: &[u8], s2_packed: &[u8]) -> Polynomial {
        let mut t0 = self.compute_t_row(idx, s1_packed, s2_packed);
        for j in 0..N {
            (_, t0[j]) = power_2_round(t0[j]);
        }

        t0
    }

    fn compute_t1_row(&self, idx: usize, s1_packed: &[u8], s2_packed: &[u8]) -> Polynomial {
        let mut t1 = self.compute_t_row(idx, s1_packed, s2_packed);
        for j in 0..N {
            (t1[j], _) = power_2_round(t1[j]);
        }

        t1
    }
}
