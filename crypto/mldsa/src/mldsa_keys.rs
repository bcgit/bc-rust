use crate::aux_functions::{
    bit_pack_eta, bit_pack_t0, bit_unpack_eta, bit_unpack_t0, bitlen_eta, expandA,
    power_2_round_vec, simple_bit_pack_t1, simple_bit_unpack_t1,
};
use crate::matrix::{MatrixTrait, VectorTrait};
use crate::mldsa::H;
use crate::mldsa::{POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
use crate::params::{MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey, XOF};
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;
#[allow(unused_imports)]
use crate::polynomial::Polynomial;

/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44Params, { MLDSA44Params::PK_LEN }>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey =
    MLDSAPrivateKey<MLDSA44Params, { MLDSA44Params::SK_LEN }, { MLDSA44Params::PK_LEN }>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65Params, { MLDSA65Params::PK_LEN }>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey =
    MLDSAPrivateKey<MLDSA65Params, { MLDSA65Params::SK_LEN }, { MLDSA65Params::PK_LEN }>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87Params, { MLDSA87Params::PK_LEN }>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey =
    MLDSAPrivateKey<MLDSA87Params, { MLDSA87Params::SK_LEN }, { MLDSA87Params::PK_LEN }>;

/* Pre-expanded keys for repeated operations */

/// ML-DSA-44 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLDSA44PublicKeyExpanded =
    MLDSAPublicKeyExpanded<MLDSA44Params, MLDSA44PublicKey, { MLDSA44Params::PK_LEN }>;
/// ML-DSA-44 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLDSA44PrivateKeyExpanded = MLDSAPrivateKeyExpanded<
    MLDSA44Params,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    { MLDSA44Params::SK_LEN },
    { MLDSA44Params::PK_LEN },
>;
/// ML-DSA-65 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLDSA65PublicKeyExpanded =
    MLDSAPublicKeyExpanded<MLDSA65Params, MLDSA65PublicKey, { MLDSA65Params::PK_LEN }>;
/// ML-DSA-65 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLDSA65PrivateKeyExpanded = MLDSAPrivateKeyExpanded<
    MLDSA65Params,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    { MLDSA65Params::SK_LEN },
    { MLDSA65Params::PK_LEN },
>;
/// ML-DSA-87 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLDSA87PublicKeyExpanded =
    MLDSAPublicKeyExpanded<MLDSA87Params, MLDSA87PublicKey, { MLDSA87Params::PK_LEN }>;
/// ML-DSA-87 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLDSA87PrivateKeyExpanded = MLDSAPrivateKeyExpanded<
    MLDSA87Params,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    { MLDSA87Params::SK_LEN },
    { MLDSA87Params::PK_LEN },
>;

/// An ML-DSA public key.
///
/// `PK_LEN` duplicates `MLDSAParams::PK_LEN`; it has to be carried separately because
/// [`SignaturePublicKey`] takes the encoded length as a const generic parameter, and an associated
/// const of a type parameter may not be used as a const generic argument. The two are checked
/// against each other at compile time -- see the `ASSERT_PK_LEN` const on this type.
pub struct MLDSAPublicKey<P: MLDSAParams, const PK_LEN: usize> {
    rho: [u8; 32],
    t1: P::VecK,
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLDSAParams, const PK_LEN: usize> Clone for MLDSAPublicKey<P, PK_LEN> {
    fn clone(&self) -> Self {
        Self { rho: self.rho, t1: self.t1 }
    }
}

impl<P: MLDSAParams, const PK_LEN: usize> MLDSAPublicKey<P, PK_LEN> {
    /// Fails to evaluate, and so fails the build, if this type is instantiated with a `PK_LEN`
    /// that is not the parameter set's own. Referenced from every constructor so that it is
    /// reached during monomorphization.
    const ASSERT_PK_LEN: () =
        assert!(PK_LEN == P::PK_LEN, "PK_LEN does not match MLDSAParams::PK_LEN");

    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    fn pk_encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);

        out[0..32].copy_from_slice(&self.rho);

        let (pk_chunks, last_chunk) = out[32..].as_chunks_mut::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (pk_chunk, t1_i) in pk_chunks.into_iter().zip(self.t1.elems()) {
            pk_chunk.copy_from_slice(&simple_bit_pack_t1(t1_i));
        }

        PK_LEN
    }
}

/// General trait for all ML-DSA public keys types.
pub trait MLDSAPublicKeyTrait<P: MLDSAParams, const PK_LEN: usize>:
    SignaturePublicKey<PK_LEN>
{
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self;

    /// Get a copy of the expanded public matrix A_hat
    fn A_hat(&self) -> P::MatrixA;

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    fn compute_tr(&self) -> [u8; 64];
}

pub(crate) trait MLDSAPublicKeyInternalTrait<P: MLDSAParams, const PK_LEN: usize>:
    SignaturePublicKey<PK_LEN>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: [u8; 32], t1: P::VecK) -> Self;

    /// Get a ref to t1
    fn t1(&self) -> &P::VecK;
}

impl<P: MLDSAParams, const PK_LEN: usize> MLDSAPublicKeyTrait<P, PK_LEN>
    for MLDSAPublicKey<P, PK_LEN>
{
    // todo: block a t1 of all zeros? Maybe add to consistency_check() ?
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        let rho = pk[0..32].try_into().unwrap();
        let mut t1 = P::VecK::new();

        let (pk_chunks, last_chunk) = pk[32..].as_chunks::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t1_i, pk_chunk) in t1.elems_mut().iter_mut().zip(pk_chunks) {
            // 3: 𝐭1[𝑖] ← SimpleBitUnpack(𝑧𝑖, 2bitlen (𝑞−1)−𝑑 − 1)
            //  ▷ This is always in the correct range
            //  Therefore, we don't need to check that the coeeffs are in range
            t1_i.coeffs.copy_from_slice(&simple_bit_unpack_t1(pk_chunk).coeffs);
        }

        <Self as MLDSAPublicKeyInternalTrait<P, PK_LEN>>::new(rho, t1)
    }

    fn A_hat(&self) -> P::MatrixA {
        expandA::<P>(&self.rho)
    }

    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&self.encode(), &mut tr);

        tr
    }
}

impl<P: MLDSAParams, const PK_LEN: usize> MLDSAPublicKeyInternalTrait<P, PK_LEN>
    for MLDSAPublicKey<P, PK_LEN>
{
    fn new(rho: [u8; 32], t1: P::VecK) -> Self {
        let () = Self::ASSERT_PK_LEN;
        Self { rho, t1 }
    }

    fn t1(&self) -> &P::VecK {
        &self.t1
    }
}

impl<P: MLDSAParams, const PK_LEN: usize> SignaturePublicKey<PK_LEN> for MLDSAPublicKey<P, PK_LEN> {
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        let bytes_written = self.encode_out(&mut pk);
        debug_assert_eq!(bytes_written, PK_LEN);

        pk
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);

        self.pk_encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != PK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let bytes_sized: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(<Self as MLDSAPublicKeyTrait<P, PK_LEN>>::pk_decode(&bytes_sized))
    }
}

impl<P: MLDSAParams, const PK_LEN: usize> Eq for MLDSAPublicKey<P, PK_LEN> {}

impl<P: MLDSAParams, const PK_LEN: usize> PartialEq for MLDSAPublicKey<P, PK_LEN> {
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<P: MLDSAParams, const PK_LEN: usize> Debug for MLDSAPublicKey<P, PK_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            <Self as MLDSAPublicKeyTrait<P, PK_LEN>>::compute_tr(self),
        )
    }
}

impl<P: MLDSAParams, const PK_LEN: usize> Display for MLDSAPublicKey<P, PK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            <Self as MLDSAPublicKeyTrait<P, PK_LEN>>::compute_tr(self),
        )
    }
}

/// A fully expanded ML-DSA public key that includes the intermediate values needed for performing
/// multiple verification operations against the same public key, which causes the public key struct
/// to take up more memory, but results in more efficient repeated verify() operations.
pub struct MLDSAPublicKeyExpanded<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> {
    pub(crate) pk: PK,
    pub(crate) A_hat: P::MatrixA,
}

/// See the note on [`MLDSAPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLDSAParams, PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> Clone
    for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    fn clone(&self) -> Self {
        Self { pk: self.pk.clone(), A_hat: self.A_hat.clone() }
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> SignaturePublicKey<PK_LEN> for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    fn encode(&self) -> [u8; PK_LEN] {
        self.pk.encode()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);

        self.pk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != PK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let bytes_sized: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(<Self as MLDSAPublicKeyTrait<P, PK_LEN>>::pk_decode(&bytes_sized))
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> PartialEq for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk)
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> Eq for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> Debug for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            self.pk.compute_tr(),
        )
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> Display for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            self.pk.compute_tr(),
        )
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> From<&PK> for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(pk: &PK) -> Self {
        let A_hat = pk.A_hat();

        Self { pk: pk.clone(), A_hat }
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyTrait<P, PK_LEN> + MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> MLDSAPublicKeyTrait<P, PK_LEN> for MLDSAPublicKeyExpanded<P, PK, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        let pk1 = PK::pk_decode(pk);
        let A_hat = pk1.A_hat();
        Self { pk: pk1, A_hat }
    }

    fn A_hat(&self) -> P::MatrixA {
        self.A_hat.clone()
    }

    fn compute_tr(&self) -> [u8; 64] {
        self.pk.compute_tr()
    }
}

/// An ML-DSA private key.
///
/// See [`MLDSAPublicKey`] for why `SK_LEN` and `PK_LEN` are carried alongside `P`.
//
// Dev note: This will automatically inherit the [`Secret`] protections because [`Polynomial`] wraps the underlying data with [`Secret`].
pub struct MLDSAPrivateKey<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> {
    rho: [u8; 32],
    K: Secret<[u8; 32]>,
    tr: [u8; 64],
    // Deviation from the FIPS:
    //  s1, s2, and t0 are only ever used in their ntt form; the only time they need to be in their
    //  natural domain form is when encoding or decoding to the standardized byte representation.
    //  So we are going to hold them as s1_hat, s2_hat, and t0_hat.
    //  Note: these are not necessarily in their reduced form; so you'll need to reduce them before
    //  inv_ntt()'ing them or hashing them.
    s1_hat: Secret<P::VecL>,
    s2_hat: Secret<P::VecK>,
    t0_hat: P::VecK,
    // note: KeyMaterial is inherently Secret
    seed: Option<KeyMaterial<32>>,
}

/// See the note on [`MLDSAPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> Clone
    for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn clone(&self) -> Self {
        Self {
            rho: self.rho,
            K: self.K.clone(),
            tr: self.tr,
            s1_hat: self.s1_hat.clone(),
            s2_hat: self.s2_hat.clone(),
            t0_hat: self.t0_hat,
            seed: self.seed.clone(),
        }
    }
}

impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> MLDSAPrivateKey<P, SK_LEN, PK_LEN> {
    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        // counter of progress along the output buffer
        let mut off: usize = 0;

        out[0..32].copy_from_slice(&self.rho);
        out[32..64].copy_from_slice(&*self.K);
        out[64..128].copy_from_slice(&self.tr);
        off += 128;

        let mut buf = [0u8; 32 * 4]; // largest possible buffer
        let eta_pack_len = bitlen_eta(P::ETA);

        let sk_chunks = out[off..off + P::l * eta_pack_len].chunks_mut(eta_pack_len);
        debug_assert_eq!(sk_chunks.len(), P::l);
        for (sk_chunk, s1_hat_i) in sk_chunks.into_iter().zip(self.s1_hat.elems()) {
            // Deviation from the FIPS:
            //   We are holding these in ntt form, so need to convert back to standard form
            let mut s1_i = *s1_hat_i;
            s1_i.reduce();
            s1_i.inv_ntt();

            bit_pack_eta::<P>(&s1_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += P::l * eta_pack_len;

        let sk_chunks = out[off..off + P::k * eta_pack_len].chunks_mut(eta_pack_len);
        debug_assert_eq!(sk_chunks.len(), P::k);
        for (sk_chunk, s2_hat_i) in sk_chunks.into_iter().zip(self.s2_hat.elems()) {
            // Deviation from the FIPS:
            //   We are holding these in ntt form, so need to convert back to standard form
            let mut s2_i = *s2_hat_i;
            s2_i.reduce();
            s2_i.inv_ntt();

            bit_pack_eta::<P>(&s2_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += P::k * eta_pack_len;

        let sk_chunks = out[off..off + P::k * POLY_T0PACKED_LEN].chunks_mut(POLY_T0PACKED_LEN);
        debug_assert_eq!(sk_chunks.len(), P::k);
        for (sk_chunk, t0_hat_i) in sk_chunks.into_iter().zip(self.t0_hat.elems()) {
            // Deviation from the FIPS:
            //   We are holding these in ntt form, so need to convert back to standard form
            let mut t0_i = *t0_hat_i;
            t0_i.reduce();
            t0_i.inv_ntt();

            sk_chunk.copy_from_slice(&bit_pack_t0(&t0_i));
        }

        SK_LEN
    }
}

/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize>:
    SignaturePrivateKey<SK_LEN>
{
    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> Option<&KeyMaterial<32>>;

    /// Get a ref to the key hash `tr`.
    fn tr(&self) -> &[u8; 64];

    /// Get the public matrix A_hat.
    fn A_hat(&self) -> P::MatrixA;

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn derive_pk(&self) -> MLDSAPublicKey<P, PK_LEN>;
    /// Algorithm 25 skDecode(𝑠𝑘)
    /// Reverses the procedure skEncode.
    /// Input: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((ℓ+𝑘)⋅bitlen (2𝜂)+𝑑𝑘).
    /// Output: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 ,
    /// 𝐬1 ∈ 𝑅ℓ, 𝐬2 ∈ 𝑅𝑘, 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    ///
    /// Note: this object contains only the simple decoding routine to unpack a semi-expanded key.
    /// See [`MLDSATrait`] for key generation functions, including derive-from-seed and consistency-check functions.
    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError>;
}

pub(crate) trait MLDSAPrivateKeyInternalTrait<
    P: MLDSAParams,
    const SK_LEN: usize,
    const PK_LEN: usize,
>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(
        rho: [u8; 32],
        K: Secret<[u8; 32]>,
        tr: [u8; 64],
        s1_hat: Secret<P::VecL>,
        s2_hat: Secret<P::VecK>,
        t0_hat: P::VecK,
        seed: Option<KeyMaterial<32>>,
    ) -> Self;
    /// Get a ref to K
    fn K(&self) -> &Secret<[u8; 32]>;
    /// Get a ref to s1
    fn s1_hat(&self) -> &P::VecL;
    /// Get a ref to s2
    fn s2_hat(&self) -> &P::VecK;
    /// Get a ref to t0
    fn t0_hat(&self) -> &P::VecK;
}

impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn seed(&self) -> Option<&KeyMaterial<32>> {
        match self.seed {
            Some(_) => self.seed.as_ref(),
            None => None,
        }
    }

    fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    fn A_hat(&self) -> P::MatrixA {
        expandA::<P>(&self.rho)
    }

    fn derive_pk(&self) -> MLDSAPublicKey<P, PK_LEN> {
        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let mut t = {
            // scope for A_hat
            // 3: 𝐀 ← ExpandA(𝜌)
            //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
            let A_hat = expandA::<P>(&self.rho);

            let mut t_ntt = A_hat.matrix_vector_ntt(&self.s1_hat);
            t_ntt.inv_ntt();
            t_ntt
        };

        {
            // Deviation from the FIPS:
            // Because s2 is in ntt form, it is necessary to reverse that here before adding it to t
            let mut s2 = *self.s2_hat;
            s2.reduce();
            s2.inv_ntt();

            t.add_vector_ntt(&s2);
            t.conditional_add_q();
        }
        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, _) = power_2_round_vec(&t);

        <MLDSAPublicKey<P, PK_LEN> as MLDSAPublicKeyInternalTrait<P, PK_LEN>>::new(self.rho, t1)
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError> {
        // Construct the (Secret-protected) key up front and unpack each field directly into it,
        // rather than decoding into unprotected temporaries and copying them in at the end. This
        // way the secret material is written straight into its protected home; and if a range
        // check below fails, `key` is dropped and its `Secret` fields are zeroized on the way out.
        let mut key = Self {
            rho: sk[0..32].try_into().unwrap(),
            K: Secret::new(),
            tr: sk[64..128].try_into().unwrap(),
            s1_hat: Secret::new(),
            s2_hat: Secret::new(),
            t0_hat: P::VecK::new(),
            seed: None,
        };
        key.K.copy_from_slice(&sk[32..64]);
        let mut off = 128;
        let eta_pack_len = bitlen_eta(P::ETA);
        let eta = P::ETA as i32;

        // unpack s1 directly into key.s1_hat so that we don't make additional non-Secret copies.
        let sk_chunks = sk[off..off + (P::l * eta_pack_len)].chunks(eta_pack_len);
        debug_assert_eq!(sk_chunks.len(), P::l);
        for (s1_i, sk_chunk) in key.s1_hat.elems_mut().iter_mut().zip(sk_chunks) {
            // 3: 𝐬1[𝑖] ← BitUnpack(𝑦𝑖, 𝜂, 𝜂)
            //  ▷ this may lie outside [−𝜂, 𝜂] if input is malformed
            s1_i.coeffs.copy_from_slice(&bit_unpack_eta::<P>(sk_chunk).coeffs);

            // check that the coefficients are within the expected range
            for coeff in s1_i.coeffs.iter() {
                if *coeff < -eta || *coeff > eta {
                    return Err(SignatureError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        // Deviation from the FIPS:
        //   Convert this to ntt form as part of decode
        key.s1_hat.ntt();
        off += P::l * eta_pack_len;

        // unpack s2 directly into key.s2_hat so that we don't make additional non-Secret copies.
        let sk_chunks = sk[off..off + (P::k * eta_pack_len)].chunks(eta_pack_len);
        debug_assert_eq!(sk_chunks.len(), P::k);
        for (s2_i, sk_chunk) in key.s2_hat.elems_mut().iter_mut().zip(sk_chunks) {
            // 6: 𝐬2[𝑖] ← BitUnpack(𝑧𝑖, 𝜂, 𝜂)
            //  ▷ this may lie outside [−𝜂, 𝜂] if input is malformed
            s2_i.coeffs.copy_from_slice(&bit_unpack_eta::<P>(sk_chunk).coeffs);

            // check that the coefficients are within the expected range
            for coeff in s2_i.coeffs.iter() {
                if *coeff < -eta || *coeff > eta {
                    return Err(SignatureError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        // Deviation from the FIPS:
        // Convert this to ntt form as part of decode
        key.s2_hat.ntt();
        off += P::k * eta_pack_len;

        // unpack t0 directly into key.t0_hat
        let (sk_chunks, last_chunk) =
            sk[off..off + (P::k * POLY_T0PACKED_LEN)].as_chunks::<POLY_T0PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(sk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t0_i, sk_chunk) in key.t0_hat.elems_mut().iter_mut().zip(sk_chunks) {
            t0_i.coeffs.copy_from_slice(&bit_unpack_t0(sk_chunk).coeffs);
        }
        // Deviation from the FIPS:
        // Convert this to ntt form as part of decode
        key.t0_hat.ntt();

        Ok(key)
    }
}

impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN> for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn new(
        rho: [u8; 32],
        K: Secret<[u8; 32]>,
        tr: [u8; 64],
        s1_hat: Secret<P::VecL>,
        s2_hat: Secret<P::VecK>,
        t0_hat: P::VecK,
        seed: Option<KeyMaterial<32>>,
    ) -> Self {
        Self { rho, K, tr, s1_hat, s2_hat, t0_hat, seed }
    }

    fn K(&self) -> &Secret<[u8; 32]> {
        &self.K
    }

    fn s1_hat(&self) -> &P::VecL {
        &self.s1_hat
    }

    fn s2_hat(&self) -> &P::VecK {
        &self.s2_hat
    }

    fn t0_hat(&self) -> &P::VecK {
        &self.t0_hat
    }
}

impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> SignaturePrivateKey<SK_LEN>
    for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn encode(&self) -> [u8; SK_LEN] {
        let mut out = [0u8; SK_LEN];
        let bytes_written = self.sk_encode_out(&mut out);
        debug_assert_eq!(bytes_written, SK_LEN);

        out
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        self.sk_encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != SK_LEN {
            return Err(SignatureError::DecodingError(
                "Provided key bytes are the incorrect length",
            ));
        }
        let bytes_sized: [u8; SK_LEN] = bytes[..SK_LEN].try_into().unwrap();

        <Self as MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN>>::sk_decode(&bytes_sized)
    }
}

impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> Eq
    for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
}

impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> PartialEq
    for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> fmt::Debug
    for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.tr,
            self.seed.is_some(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<P: MLDSAParams, const SK_LEN: usize, const PK_LEN: usize> Display
    for MLDSAPrivateKey<P, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.tr,
            self.seed.is_some(),
        )
    }
}

/// A fully expanded ML-DSA private key that includes the intermediate values needed for performing
/// multiple sign operations with the same private key, which causes the private ey struct to take up
/// more memory, but results in more efficient repeated sign() operations.
pub struct MLDSAPrivateKeyExpanded<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    _phantom: core::marker::PhantomData<PK>,
    pub(crate) sk: SK,
    pub(crate) A_hat: P::MatrixA,
}

/// See the note on [`MLDSAPublicKey`]'s `Clone` for why this is not derived.
impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Clone for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn clone(&self) -> Self {
        Self { _phantom: core::marker::PhantomData, sk: self.sk.clone(), A_hat: self.A_hat.clone() }
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> PartialEq for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.sk.eq(&other.sk)
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Eq for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Debug for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPrivateKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.sk.tr(),
            self.sk.seed().is_some(),
        )
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Display for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPrivateKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.sk.tr(),
            self.sk.seed().is_some(),
        )
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> From<&SK> for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(sk: &SK) -> Self {
        let A_hat =
            <MLDSAPublicKey<P, PK_LEN> as MLDSAPublicKeyTrait<P, PK_LEN>>::A_hat(&sk.derive_pk());

        Self { _phantom: core::marker::PhantomData, sk: sk.clone(), A_hat }
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> SignaturePrivateKey<SK_LEN> for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.sk.encode()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        self.sk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sk = SK::from_bytes(bytes)?;
        Ok(Self::from(&sk))
    }
}

impl<
    P: MLDSAParams,
    PK: MLDSAPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> + MLDSAPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLDSAPrivateKeyTrait<P, SK_LEN, PK_LEN> for MLDSAPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn seed(&self) -> Option<&KeyMaterial<32>> {
        self.sk.seed()
    }

    fn tr(&self) -> &[u8; 64] {
        self.sk.tr()
    }

    fn A_hat(&self) -> P::MatrixA {
        self.sk.A_hat()
    }

    fn derive_pk(&self) -> MLDSAPublicKey<P, PK_LEN> {
        self.sk.derive_pk()
    }

    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError> {
        let sk1 = SK::sk_decode(sk)?;
        let A_hat =
            <MLDSAPublicKey<P, PK_LEN> as MLDSAPublicKeyTrait<P, PK_LEN>>::A_hat(&sk1.derive_pk());

        Ok(Self { _phantom: core::marker::PhantomData, sk: sk1, A_hat })
    }
}
