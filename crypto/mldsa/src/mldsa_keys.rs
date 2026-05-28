use crate::aux_functions::{
    bit_pack_eta, bit_pack_t0, bit_unpack_eta, bit_unpack_t0, bitlen_eta, expandA,
    power_2_round_vec, simple_bit_pack_t1, simple_bit_unpack_t1,
};
use crate::matrix::{Matrix, Vector};
use crate::mldsa::H;
use crate::mldsa::{MLDSA44_ETA, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_k, MLDSA44_l};
use crate::mldsa::{MLDSA65_ETA, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_k, MLDSA65_l};
use crate::mldsa::{MLDSA87_ETA, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_k, MLDSA87_l};
use crate::mldsa::{POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
use crate::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{Secret, SignaturePrivateKey, SignaturePublicKey, XOF};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;

/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44_k, MLDSA44_l, MLDSA44_PK_LEN>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey =
    MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65_k, MLDSA65_l, MLDSA65_PK_LEN>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey =
    MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87_k, MLDSA87_l, MLDSA87_PK_LEN>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey =
    MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>;

/* Pre-expanded keys for repeated operations */

/// ML-DSA-44 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLDSA44PublicKeyExpanded =
    MLDSAPublicKeyExpanded<MLDSA44_k, MLDSA44_l, MLDSA44PublicKey, MLDSA44_PK_LEN>;
/// ML-DSA-44 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLDSA44PrivateKeyExpanded = MLDSAPrivateKeyExpanded<
    MLDSA44_k,
    MLDSA44_l,
    MLDSA44_ETA,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    MLDSA44_SK_LEN,
    MLDSA44_PK_LEN,
>;
/// ML-DSA-65 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLDSA65PublicKeyExpanded =
    MLDSAPublicKeyExpanded<MLDSA65_k, MLDSA65_l, MLDSA65PublicKey, MLDSA65_PK_LEN>;
/// ML-DSA-65 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLDSA65PrivateKeyExpanded = MLDSAPrivateKeyExpanded<
    MLDSA65_k,
    MLDSA65_l,
    MLDSA65_ETA,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    MLDSA65_SK_LEN,
    MLDSA65_PK_LEN,
>;
/// ML-DSA-87 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLDSA87PublicKeyExpanded =
    MLDSAPublicKeyExpanded<MLDSA87_k, MLDSA87_l, MLDSA87PublicKey, MLDSA87_PK_LEN>;
/// ML-DSA-87 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLDSA87PrivateKeyExpanded = MLDSAPrivateKeyExpanded<
    MLDSA87_k,
    MLDSA87_l,
    MLDSA87_ETA,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    MLDSA87_SK_LEN,
    MLDSA87_PK_LEN,
>;

/// An ML-DSA public key.
#[derive(Clone)]
pub struct MLDSAPublicKey<const k: usize, const l: usize, const PK_LEN: usize> {
    rho: [u8; 32],
    t1: Vector<k>,
}

impl<const k: usize, const l: usize, const PK_LEN: usize> MLDSAPublicKey<k, l, PK_LEN> {
    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    fn pk_encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out[0..32].copy_from_slice(&self.rho);

        let (pk_chunks, last_chunk) = out[32..].as_chunks_mut::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (pk_chunk, t1_i) in pk_chunks.into_iter().zip(&self.t1.vec) {
            pk_chunk.copy_from_slice(&simple_bit_pack_t1(&t1_i));
        }

        PK_LEN
    }
}

/// General trait for all ML-DSA public keys types.
pub trait MLDSAPublicKeyTrait<const k: usize, const l: usize, const PK_LEN: usize>:
    SignaturePublicKey<PK_LEN>
{
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self;

    /// Get a copy of the expanded public matrix A_hat
    fn A_hat(&self) -> Matrix<k, l>;

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    fn compute_tr(&self) -> [u8; 64];
}

pub(crate) trait MLDSAPublicKeyInternalTrait<const k: usize, const PK_LEN: usize>:
    SignaturePublicKey<PK_LEN>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: [u8; 32], t1: Vector<k>) -> Self;

    /// Get a ref to t1
    fn t1(&self) -> &Vector<k>;
}

impl<const k: usize, const l: usize, const PK_LEN: usize> MLDSAPublicKeyTrait<k, l, PK_LEN>
    for MLDSAPublicKey<k, l, PK_LEN>
{
    // todo: block a t1 of all zeros? Maybe add to consistency_check() ?
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        let rho = pk[0..32].try_into().unwrap();
        let mut t1 = Vector::<k>::new();

        let (pk_chunks, last_chunk) = pk[32..].as_chunks::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t1_i, pk_chunk) in t1.vec.iter_mut().zip(pk_chunks) {
            // 3: 𝐭1[𝑖] ← SimpleBitUnpack(𝑧𝑖, 2bitlen (𝑞−1)−𝑑 − 1)
            //  ▷ This is always in the correct range
            //  Therefore, we don't need to check that the coeeffs are in range
            t1_i.coeffs.copy_from_slice(&simple_bit_unpack_t1(pk_chunk).coeffs);
        }

        Self::new(rho, t1)
    }

    fn A_hat(&self) -> Matrix<k, l> {
        expandA::<k, l>(&self.rho)
    }

    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&self.encode(), &mut tr);

        tr
    }
}

impl<const k: usize, const l: usize, const PK_LEN: usize> MLDSAPublicKeyInternalTrait<k, PK_LEN>
    for MLDSAPublicKey<k, l, PK_LEN>
{
    fn new(rho: [u8; 32], t1: Vector<k>) -> Self {
        Self { rho, t1 }
    }

    fn t1(&self) -> &Vector<k> {
        &self.t1
    }
}

impl<const k: usize, const l: usize, const PK_LEN: usize> SignaturePublicKey<PK_LEN>
    for MLDSAPublicKey<k, l, PK_LEN>
{
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        let bytes_written = self.encode_out(&mut pk);
        debug_assert_eq!(bytes_written, PK_LEN);

        pk
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        self.pk_encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != PK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let bytes_sized: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(Self::pk_decode(&bytes_sized))
    }
}

impl<const k: usize, const l: usize, const PK_LEN: usize> Eq for MLDSAPublicKey<k, l, PK_LEN> {}

impl<const k: usize, const l: usize, const PK_LEN: usize> PartialEq
    for MLDSAPublicKey<k, l, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<const k: usize, const l: usize, const PK_LEN: usize> Debug for MLDSAPublicKey<k, l, PK_LEN> {
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

impl<const k: usize, const l: usize, const PK_LEN: usize> Display for MLDSAPublicKey<k, l, PK_LEN> {
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

/// A fully expanded ML-DSA public key that includes the intermediate values needed for performing
/// multiple verification operations against the same public key, which causes the public key struct
/// to take up more memory, but results in more efficient repeated verify() operations.
#[derive(Clone)]
pub struct MLDSAPublicKeyExpanded<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> {
    pub(crate) pk: PK,
    pub(crate) A_hat: Matrix<k, l>,
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> SignaturePublicKey<PK_LEN> for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
    fn encode(&self) -> [u8; PK_LEN] {
        self.pk.encode()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        self.pk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != PK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let bytes_sized: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(Self::pk_decode(&bytes_sized))
    }
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> PartialEq for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk)
    }
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> Eq for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> Debug for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPublicKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            alg,
            self.compute_tr(),
        )
    }
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> Display for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPublicKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            alg,
            self.compute_tr(),
        )
    }
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> From<&PK> for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(pk: &PK) -> Self {
        let A_hat = pk.A_hat();

        Self { pk: pk.clone(), A_hat }
    }
}

impl<
    const k: usize,
    const l: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> MLDSAPublicKeyTrait<k, l, PK_LEN> for MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        let pk1 = PK::pk_decode(pk);
        let A_hat = pk1.A_hat();
        Self { pk: pk1, A_hat }
    }

    fn A_hat(&self) -> Matrix<k, l> {
        self.A_hat.clone()
    }

    fn compute_tr(&self) -> [u8; 64] {
        self.pk.compute_tr()
    }
}

/// An ML-DSA private key.
#[derive(Clone)]
pub struct MLDSAPrivateKey<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    rho: [u8; 32],
    K: [u8; 32],
    tr: [u8; 64],
    // Deviation from the FIPS:
    //  s1, s2, and t0 are only ever used in their ntt form; the only time they need to be in their
    //  natural domain form is when encoding or decoding to the standardized byte representation.
    //  So we are going to hold them as s1_hat, s2_hat, and t0_hat.
    //  Note: these are not necessarily in their reduced form; so you'll need to reduce them before
    //  inv_ntt()'ing them or hashing them.
    s1_hat: Vector<l>,
    s2_hat: Vector<k>,
    t0_hat: Vector<k>,
    seed: Option<KeyMaterial<32>>,
}

/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
>: SignaturePrivateKey<SK_LEN>
{
    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> &Option<KeyMaterial<32>>;

    /// Get a ref to the key hash `tr`.
    fn tr(&self) -> &[u8; 64];

    /// Get the public matrix A_hat.
    fn A_hat(&self) -> Matrix<k, l>;

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn derive_pk(&self) -> MLDSAPublicKey<k, l, PK_LEN>;
    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    fn sk_encode(&self) -> [u8; SK_LEN];
    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize;
    /// Algorithm 25 skDecode(𝑠𝑘)
    /// Reverses the procedure skEncode.
    /// Input: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((ℓ+𝑘)⋅bitlen (2𝜂)+𝑑𝑘).
    /// Output: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 ,
    /// 𝐬1 ∈ 𝑅ℓ, 𝐬2 ∈ 𝑅𝑘, 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    ///
    /// Note: this object contains only the simple decoding routine to unpack a semi-expanded key.
    /// See [MLDSATrait] for key generation functions, including derive-from-seed and consistency-check functions.
    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError>;
}

pub(crate) trait MLDSAPrivateKeyInternalTrait<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(
        rho: [u8; 32],
        K: [u8; 32],
        tr: [u8; 64],
        s1_hat: Vector<l>,
        s2_hat: Vector<k>,
        t0_hat: Vector<k>,
        seed: Option<KeyMaterial<32>>,
    ) -> Self;
    /// Get a ref to K
    fn K(&self) -> &[u8; 32];
    /// Get a ref to s1
    fn s1_hat(&self) -> &Vector<l>;
    /// Get a ref to s2
    fn s2_hat(&self) -> &Vector<k>;
    /// Get a ref to t0
    fn t0_hat(&self) -> &Vector<k>;
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN> for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn seed(&self) -> &Option<KeyMaterial<32>> {
        &self.seed
    }

    fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    fn A_hat(&self) -> Matrix<k, l> {
        expandA::<k, l>(&self.rho)
    }

    fn derive_pk(&self) -> MLDSAPublicKey<k, l, PK_LEN> {
        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let mut t = {
            // scope for A_hat
            // 3: 𝐀 ← ExpandA(𝜌)
            //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
            let A_hat = expandA::<k, l>(&self.rho);

            let mut t_ntt = A_hat.matrix_vector_ntt(&self.s1_hat);
            t_ntt.inv_ntt();
            t_ntt
        };

        {
            // Deviation from the FIPS:
            //  Because we're holding s2 in ntt form, we need to reverse that here before adding it to t
            let mut s2 = self.s2_hat.clone();
            s2.reduce();
            s2.inv_ntt();

            t.add_vector_ntt(&s2);
            t.conditional_add_q();
        }
        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, _) = power_2_round_vec::<k>(&t);

        MLDSAPublicKey::<k, l, PK_LEN>::new(self.rho.clone(), t1)
    }
    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    fn sk_encode(&self) -> [u8; SK_LEN] {
        let mut out = [0u8; SK_LEN];
        let bytes_written = self.sk_encode_out(&mut out);
        debug_assert_eq!(bytes_written, SK_LEN);
        out
    }
    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        // counter of progress along the output buffer
        let mut off: usize = 0;

        out[0..32].copy_from_slice(&self.rho);
        out[32..64].copy_from_slice(&self.K);
        out[64..128].copy_from_slice(&self.tr);
        off += 128;

        let mut buf = [0u8; 32 * 4]; // largest possible buffer
        let eta_pack_len = bitlen_eta(eta);

        let sk_chunks = out[off..off + l * bitlen_eta(eta)].chunks_mut(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), l);
        for (sk_chunk, s1_hat_i) in sk_chunks.into_iter().zip(&self.s1_hat.vec) {
            // Deviation from the FIPS:
            //   We are holding these in ntt form, so need to convert back to standard form
            let mut s1_hat_i = s1_hat_i.clone();
            s1_hat_i.reduce();
            s1_hat_i.inv_ntt();
            let s1_i = s1_hat_i;

            bit_pack_eta::<eta>(&s1_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += l * bitlen_eta(eta);

        let sk_chunks = out[off..off + k * bitlen_eta(eta)].chunks_mut(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, s2_hat_i) in sk_chunks.into_iter().zip(&self.s2_hat.vec) {
            // Deviation from the FIPS:
            //   We are holding these in ntt form, so need to convert back to standard form
            let mut s2_hat_i = s2_hat_i.clone();
            s2_hat_i.reduce();
            s2_hat_i.inv_ntt();
            let s2_i = s2_hat_i;

            bit_pack_eta::<eta>(&s2_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += k * bitlen_eta(eta);

        let sk_chunks = out[off..off + k * POLY_T0PACKED_LEN].chunks_mut(POLY_T0PACKED_LEN);
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, t0_hat_i) in sk_chunks.into_iter().zip(&self.t0_hat.vec) {
            // Deviation from the FIPS:
            //   We are holding these in ntt form, so need to convert back to standard form
            let mut t0_hat_i = t0_hat_i.clone();
            t0_hat_i.reduce();
            t0_hat_i.inv_ntt();
            let t0_i = t0_hat_i;

            sk_chunk.copy_from_slice(&bit_pack_t0(&t0_i));
        }

        SK_LEN
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError> {
        let rho = sk[0..32].try_into().unwrap();
        let K = sk[32..64].try_into().unwrap();
        let tr = sk[64..128].try_into().unwrap();
        let mut s1 = Vector::<l>::new();
        let mut s2 = Vector::<k>::new();
        let mut t0 = Vector::<k>::new();
        let mut off = 128;

        // unpack s1
        // let mut i: usize = 0;
        let sk_chunks = sk[128..128 + (l * bitlen_eta(eta))].chunks(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), l);
        for (s1_i, sk_chunk) in s1.vec.iter_mut().zip(sk_chunks) {
            // 3: 𝐬1[𝑖] ← BitUnpack(𝑦𝑖, 𝜂, 𝜂)
            //  ▷ this may lie outside [−𝜂, 𝜂] if input is malformed
            s1_i.coeffs.copy_from_slice(&bit_unpack_eta::<eta>(&sk_chunk).coeffs);

            // check that the coefficients are within the expected range
            for coeff in s1_i.coeffs.iter() {
                if *coeff < -(eta as i32) || *coeff > (eta as i32) {
                    return Err(SignatureError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        // Deviation from the FIPS:
        //   Convert this to ntt form as part of decode
        s1.ntt();
        off += l * bitlen_eta(eta);

        // unpack s2
        let sk_chunks = sk[off..off + (k * bitlen_eta(eta))].chunks(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), k);
        for (s2_i, sk_chunk) in s2.vec.iter_mut().zip(sk_chunks) {
            // 6: 𝐬2[𝑖] ← BitUnpack(𝑧𝑖, 𝜂, 𝜂)
            //  ▷ this may lie outside [−𝜂, 𝜂] if input is malformed
            s2_i.coeffs.copy_from_slice(&bit_unpack_eta::<eta>(&sk_chunk).coeffs);

            // check that the coefficients are within the expected range
            for coeff in s2_i.coeffs.iter() {
                if *coeff < -(eta as i32) || *coeff > (eta as i32) {
                    return Err(SignatureError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        // Deviation from the FIPS:
        //   Convert this to ntt form as part of decode
        s2.ntt();
        off += k * bitlen_eta(eta);

        // unpack t0
        let (sk_chunks, last_chunk) =
            sk[off..off + (k * POLY_T0PACKED_LEN)].as_chunks::<POLY_T0PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(sk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t0_i, sk_chunk) in t0.vec.iter_mut().zip(sk_chunks) {
            t0_i.coeffs.copy_from_slice(&bit_unpack_t0(sk_chunk).coeffs);
        }
        // Deviation from the FIPS:
        //   Convert this to ntt form as part of decode
        t0.ntt();

        Ok(Self { rho, K, tr, s1_hat: s1, s2_hat: s2, t0_hat: t0, seed: None })
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>
    for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn new(
        rho: [u8; 32],
        K: [u8; 32],
        tr: [u8; 64],
        s1_hat: Vector<l>,
        s2_hat: Vector<k>,
        t0_hat: Vector<k>,
        seed: Option<KeyMaterial<32>>,
    ) -> Self {
        Self {
            rho: rho.clone(),
            K: K.clone(),
            tr: tr.clone(),
            s1_hat: s1_hat.clone(),
            s2_hat: s2_hat.clone(),
            t0_hat: t0_hat.clone(),
            seed: seed.clone(),
        }
    }

    fn K(&self) -> &[u8; 32] {
        &self.K
    }

    fn s1_hat(&self) -> &Vector<l> {
        &self.s1_hat
    }

    fn s2_hat(&self) -> &Vector<k> {
        &self.s2_hat
    }

    fn t0_hat(&self) -> &Vector<k> {
        &self.t0_hat
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    SignaturePrivateKey<SK_LEN> for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.sk_encode()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        self.sk_encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != SK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let bytes_sized: [u8; SK_LEN] = bytes[..SK_LEN].try_into().unwrap();

        Ok(Self::sk_decode(&bytes_sized)?)
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize> Eq
    for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    PartialEq for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.sk_encode();
        let other_encoded = other.sk_encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    Secret for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    fmt::Debug for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            alg,
            self.tr,
            self.seed.is_some(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    Display for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            alg,
            self.tr,
            self.seed.is_some(),
        )
    }
}

/// Zeroizing drop
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    Drop for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn drop(&mut self) {
        self.K.fill(0u8);
        // s1, s2, t0, seed have their own zeroizing drop
    }
}

/// A fully expanded ML-DSA private key that includes the intermediate values needed for performing
/// multiple sign operations with the same private key, which causes the private ey struct to take up
/// more memory, but results in more efficient repeated sign() operations.
#[derive(Clone)]
pub struct MLDSAPrivateKeyExpanded<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    _phantom: core::marker::PhantomData<PK>,
    pub(crate) sk: SK,
    pub(crate) A_hat: Matrix<k, l>,
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> PartialEq for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.sk.eq(&other.sk)
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Eq for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Secret for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Drop for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    fn drop(&mut self) {
        // Nothing to do since self.sk already impls zeroizing Drop
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Debug for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPrivateKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            alg,
            self.sk.tr(),
            self.sk.seed().is_some(),
        )
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Display for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPrivateKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            alg,
            self.sk.tr(),
            self.sk.seed().is_some(),
        )
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> From<&SK> for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(sk: &SK) -> Self {
        let A_hat = sk.derive_pk().A_hat();

        Self { _phantom: core::marker::PhantomData, sk: sk.clone(), A_hat }
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignaturePrivateKey<SK_LEN> for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.sk.encode()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        self.sk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sk = SK::from_bytes(bytes)?;
        Ok(Self::from(&sk))
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    PK: MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN>
    for MLDSAPrivateKeyExpanded<k, l, eta, PK, SK, SK_LEN, PK_LEN>
{
    fn seed(&self) -> &Option<KeyMaterial<32>> {
        self.sk.seed()
    }

    fn tr(&self) -> &[u8; 64] {
        self.sk.tr()
    }

    fn A_hat(&self) -> Matrix<k, l> {
        self.sk.A_hat()
    }

    fn derive_pk(&self) -> MLDSAPublicKey<k, l, PK_LEN> {
        self.sk.derive_pk()
    }

    fn sk_encode(&self) -> [u8; SK_LEN] {
        self.sk.sk_encode()
    }

    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        self.sk.sk_encode_out(out)
    }

    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError> {
        let sk1 = SK::sk_decode(sk)?;
        let A_hat = sk1.derive_pk().A_hat();

        Ok(Self { _phantom: core::marker::PhantomData, sk: sk1, A_hat })
    }
}
