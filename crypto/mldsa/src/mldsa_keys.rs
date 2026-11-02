use crate::aux_functions::{expandA, power_2_round_vec};
use crate::matrix::{MatrixTrait, VectorTrait};
use crate::mldsa::{H, MuBuilder, draw_rnd, sign_internal, verify_internal};
use crate::mldsa::{MLDSA_MU_LEN, MLDSA_RND_LEN};
use crate::mldsa::{POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
use crate::params::{MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams};
use crate::params::{PrivateKeyLen, PublicKeyLen, SignatureLen};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey, XOF};
use bouncycastle_mldsa_common::aux_functions::{
    bit_pack_eta, bit_pack_t0, bit_unpack_eta, bit_unpack_t0, simple_bit_pack_t1,
    simple_bit_unpack_t1,
};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;
#[allow(unused_imports)]
use bouncycastle_mldsa_common::polynomial::Polynomial;

/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44Params>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey = MLDSAPrivateKey<MLDSA44Params>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65Params>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey = MLDSAPrivateKey<MLDSA65Params>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87Params>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey = MLDSAPrivateKey<MLDSA87Params>;

/* Pre-expanded keys for repeated operations */

/// ML-DSA-44 Public Key with a pre-expanded public matrix A for repeated verify operations.
pub type MLDSA44PublicKeyExpanded<'k> = MLDSAPublicKeyExpanded<'k, MLDSA44Params>;
/// ML-DSA-44 Private Key with a pre-expanded public matrix A for repeated sign operations.
pub type MLDSA44PrivateKeyExpanded<'k> = MLDSAPrivateKeyExpanded<'k, MLDSA44Params>;
/// ML-DSA-65 Public Key with a pre-expanded public matrix A for repeated verify operations.
pub type MLDSA65PublicKeyExpanded<'k> = MLDSAPublicKeyExpanded<'k, MLDSA65Params>;
/// ML-DSA-65 Private Key with a pre-expanded public matrix A for repeated sign operations.
pub type MLDSA65PrivateKeyExpanded<'k> = MLDSAPrivateKeyExpanded<'k, MLDSA65Params>;
/// ML-DSA-87 Public Key with a pre-expanded public matrix A for repeated verify operations.
pub type MLDSA87PublicKeyExpanded<'k> = MLDSAPublicKeyExpanded<'k, MLDSA87Params>;
/// ML-DSA-87 Private Key with a pre-expanded public matrix A for repeated sign operations.
pub type MLDSA87PrivateKeyExpanded<'k> = MLDSAPrivateKeyExpanded<'k, MLDSA87Params>;

/// An ML-DSA public key.
///
/// The parameter set fixes every length, so `P` is the only type parameter. [`SignaturePublicKey`]
/// and the role traits take the encoded lengths as const generics, and an associated const of a
/// type parameter may not be used as one, so their impls are generic over the length and bound
/// through the per-length traits (`P: PublicKeyLen<PK_LEN>`), which have one impl per parameter
/// set and so let the length be inferred from `P`.
pub struct MLDSAPublicKey<P: MLDSAParams> {
    rho: [u8; 32],
    t1: P::VecK,
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLDSAParams> Clone for MLDSAPublicKey<P> {
    fn clone(&self) -> Self {
        Self { rho: self.rho, t1: self.t1 }
    }
}

impl<P: MLDSAParams> MLDSAPublicKey<P> {
    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    pub(crate) fn pk_encode_out(&self, out: &mut [u8]) -> usize {
        debug_assert_eq!(out.len(), P::PK_LEN);
        out.fill(0);

        out[0..32].copy_from_slice(&self.rho);

        let (pk_chunks, last_chunk) = out[32..].as_chunks_mut::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (pk_chunk, t1_i) in pk_chunks.iter_mut().zip(self.t1.elems()) {
            pk_chunk.copy_from_slice(&simple_bit_pack_t1(t1_i));
        }

        P::PK_LEN
    }

    /// The encoding in a parameter-set-sized buffer, for the places with no const generic in
    /// scope to size an array.
    fn encode_buf(&self) -> P::PkEncoded {
        let mut out = P::PkEncoded::ZEROED;
        self.pk_encode_out(out.as_mut());
        out
    }

    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    pub(crate) fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Self
    where
        P: PublicKeyLen<PK_LEN>,
    {
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

        <Self as MLDSAPublicKeyInternalTrait<P>>::new(rho, t1)
    }

    /// The public matrix 𝐀̂ = ExpandA(𝜌), FIPS 204 Algorithm 32; the expanded keys cache it.
    pub(crate) fn A_hat(&self) -> P::MatrixA {
        expandA::<P>(&self.rho)
    }
}

/// General trait for all ML-DSA public keys types.
pub trait MLDSAPublicKeyTrait<P: MLDSAParams>: Sized {
    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///    to use, for example, to build a public key lookup or deny-listing table.
    fn compute_tr(&self) -> [u8; 64];

    /// The message representative mu = H(tr || M') of `msg` under `ctx` (FIPS 204, Algorithm 7
    /// line 6): the public half of the external-mu interface, see
    /// [`MLDSAPrivateKeyTrait::sign_mu`]. [`MuBuilder`] builds it from a streamed message.
    fn compute_mu(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; MLDSA_MU_LEN], SignatureError> {
        let mut mb = self.create_mu_builder(ctx)?;
        mb.do_update(msg);
        Ok(mb.do_final())
    }

    /// The streaming form of [`compute_mu`](Self::compute_mu): a [`MuBuilder`] bound to this
    /// key's `tr` and to `ctx`, which then takes the message in chunks. `ctx` longer than 255
    /// bytes is the error of FIPS 204 Algorithm 2, line 1.
    fn create_mu_builder(&self, ctx: Option<&[u8]>) -> Result<MuBuilder, SignatureError> {
        MuBuilder::from_tr(&self.compute_tr(), ctx)
    }

    /// FIPS 204 Algorithm 8 with line 7 removed: verifies `sig` over an externally computed
    /// `mu`. Any ML-DSA signature verifies here with the `mu` of its message, and a signature
    /// made with [`MLDSAPrivateKeyTrait::sign_mu`] verifies with [`VerifyingKey::verify`]
    /// over the message.
    ///
    /// [`VerifyingKey::verify`]: bouncycastle_core::signature_key::VerifyingKey::verify
    fn verify_mu<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        sig: &[u8; SIG_LEN],
    ) -> Result<(), SignatureError>
    where
        P: SignatureLen<SIG_LEN>;
}

pub(crate) trait MLDSAPublicKeyInternalTrait<P: MLDSAParams> {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: [u8; 32], t1: P::VecK) -> Self;

    /// Get a ref to t1
    fn t1(&self) -> &P::VecK;
}

impl<P: MLDSAParams> MLDSAPublicKeyTrait<P> for MLDSAPublicKey<P> {
    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().xof_out(self.encode_buf().as_ref(), &mut tr);

        tr
    }

    fn verify_mu<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        sig: &[u8; SIG_LEN],
    ) -> Result<(), SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        verify_internal::<P, Self, SIG_LEN>(self, &self.A_hat(), mu, sig)
    }
}

impl<P: MLDSAParams> MLDSAPublicKeyInternalTrait<P> for MLDSAPublicKey<P> {
    fn new(rho: [u8; 32], t1: P::VecK) -> Self {
        Self { rho, t1 }
    }

    fn t1(&self) -> &P::VecK {
        &self.t1
    }
}

impl<P: PublicKeyLen<PK_LEN>, const PK_LEN: usize> SignaturePublicKey<PK_LEN>
    for MLDSAPublicKey<P>
{
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
        Ok(Self::pk_decode(&bytes_sized))
    }
}

impl<P: MLDSAParams> Eq for MLDSAPublicKey<P> {}

impl<P: MLDSAParams> PartialEq for MLDSAPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode_buf();
        let other_encoded = other.encode_buf();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<P: MLDSAParams> Debug for MLDSAPublicKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            <Self as MLDSAPublicKeyTrait<P>>::compute_tr(self),
        )
    }
}

impl<P: MLDSAParams> Display for MLDSAPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            <Self as MLDSAPublicKeyTrait<P>>::compute_tr(self),
        )
    }
}

/// An ML-DSA public key with its public matrix 𝐀̂ expanded once, for repeated verifications under
/// the same key: it borrows the [`MLDSAPublicKey`] and carries the matrix beside it (see the
/// crate's Memory Usage table), and implements the same verifying roles as the key it borrows.
/// The encoding is the borrowed key's, [`key()`](Self::key).
pub struct MLDSAPublicKeyExpanded<'k, P: MLDSAParams> {
    pub(crate) pk: &'k MLDSAPublicKey<P>,
    pub(crate) A_hat: P::MatrixA,
}

impl<'k, P: MLDSAParams> MLDSAPublicKeyExpanded<'k, P> {
    /// The key this expansion was made from.
    pub fn key(&self) -> &'k MLDSAPublicKey<P> {
        self.pk
    }
}

/// See the note on [`MLDSAPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLDSAParams> Clone for MLDSAPublicKeyExpanded<'_, P> {
    fn clone(&self) -> Self {
        Self { pk: self.pk, A_hat: self.A_hat.clone() }
    }
}

impl<P: MLDSAParams> PartialEq for MLDSAPublicKeyExpanded<'_, P> {
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(other.pk)
    }
}

impl<P: MLDSAParams> Eq for MLDSAPublicKeyExpanded<'_, P> {}

impl<P: MLDSAParams> Debug for MLDSAPublicKeyExpanded<'_, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            self.pk.compute_tr(),
        )
    }
}

impl<P: MLDSAParams> Display for MLDSAPublicKeyExpanded<'_, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKeyExpanded {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            self.pk.compute_tr(),
        )
    }
}

impl<'k, P: MLDSAParams> From<&'k MLDSAPublicKey<P>> for MLDSAPublicKeyExpanded<'k, P> {
    /// Expands the public matrix A once, for repeated verifications under the same public key.
    fn from(pk: &'k MLDSAPublicKey<P>) -> Self {
        Self { pk, A_hat: pk.A_hat() }
    }
}

impl<P: MLDSAParams> MLDSAPublicKeyTrait<P> for MLDSAPublicKeyExpanded<'_, P> {
    fn compute_tr(&self) -> [u8; 64] {
        self.pk.compute_tr()
    }

    /// Verifies with the expanded matrix the key carries.
    fn verify_mu<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        sig: &[u8; SIG_LEN],
    ) -> Result<(), SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        verify_internal::<P, MLDSAPublicKey<P>, SIG_LEN>(self.pk, &self.A_hat, mu, sig)
    }
}

/// An ML-DSA private key.
//
// Dev note: This will automatically inherit the [`Secret`] protections because [`Polynomial`] wraps the underlying data with [`Secret`].
pub struct MLDSAPrivateKey<P: MLDSAParams> {
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
impl<P: MLDSAParams> Clone for MLDSAPrivateKey<P> {
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

impl<P: MLDSAParams> MLDSAPrivateKey<P> {
    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    pub(crate) fn sk_encode_out(&self, out: &mut [u8]) -> usize {
        debug_assert_eq!(out.len(), P::SK_LEN);
        out.fill(0);

        // counter of progress along the output buffer
        let mut off: usize = 0;

        out[0..32].copy_from_slice(&self.rho);
        out[32..64].copy_from_slice(&*self.K);
        out[64..128].copy_from_slice(&self.tr);
        off += 128;

        let mut buf = [0u8; 32 * 4]; // largest possible buffer
        let eta_pack_len = P::POLY_ETA_PACKED_LEN;

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

        P::SK_LEN
    }

    /// The encoding in a parameter-set-sized `Secret` buffer; see [`MLDSAPublicKey::encode_buf`].
    fn encode_buf(&self) -> Secret<P::SkEncoded> {
        let mut out = Secret::<P::SkEncoded>::new();
        self.sk_encode_out((*out).as_mut());
        out
    }

    /// The public matrix 𝐀̂ = ExpandA(𝜌), FIPS 204 Algorithm 32; the expanded key caches it.
    pub(crate) fn A_hat(&self) -> P::MatrixA {
        expandA::<P>(&self.rho)
    }

    /// Algorithm 25 skDecode(𝑠𝑘)
    /// Reverses the procedure skEncode.
    /// Input: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((ℓ+𝑘)⋅bitlen (2𝜂)+𝑑𝑘).
    /// Output: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 ,
    /// 𝐬1 ∈ 𝑅ℓ, 𝐬2 ∈ 𝑅𝑘, 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    pub(crate) fn sk_decode<const SK_LEN: usize>(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError>
    where
        P: PrivateKeyLen<SK_LEN>,
    {
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
        let eta_pack_len = P::POLY_ETA_PACKED_LEN;
        let eta = P::eta as i32;

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

/// The step every signing path shares: FIPS 204 Algorithm 7 over an externally computed mu with
/// the randomizer `rnd` already chosen. Crate-private so that `rnd` is never a caller's choice: the
/// public methods draw it from the caller's RNG (the hedged variant of Section 3.4), and a
/// known-answer test that must reproduce a vector's `rnd` passes an RNG that returns it.
pub(crate) trait SignMuWithRnd<P: MLDSAParams> {
    fn sign_mu_with_rnd_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rnd: [u8; MLDSA_RND_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>;
}

/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<P: MLDSAParams>: Sized + SignMuWithRnd<P> {
    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> Option<&KeyMaterial<32>>;

    /// Get a ref to the key hash `tr`.
    fn tr(&self) -> &[u8; 64];

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn derive_pk(&self) -> MLDSAPublicKey<P>;
    /// The message representative mu of `msg` under `ctx`, from the key's `tr`; see
    /// [`MLDSAPublicKeyTrait::compute_mu`].
    fn compute_mu(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; MLDSA_MU_LEN], SignatureError> {
        let mut mb = self.create_mu_builder(ctx)?;
        mb.do_update(msg);
        Ok(mb.do_final())
    }

    /// The streaming form of [`compute_mu`](Self::compute_mu): a [`MuBuilder`] bound to this
    /// key's `tr` and to `ctx`, which then takes the message in chunks. `ctx` longer than 255
    /// bytes is the error of FIPS 204 Algorithm 2, line 1.
    fn create_mu_builder(&self, ctx: Option<&[u8]>) -> Result<MuBuilder, SignatureError> {
        MuBuilder::from_tr(self.tr(), ctx)
    }

    /// Signs an externally computed message representative `mu`: FIPS 204 Algorithm 7 with
    /// line 6 removed, which FIPS 204 and NIST's FAQ on it allow, the representative being one
    /// that "may optionally be computed in a different cryptographic module". This is the
    /// "external mu" interface: the application computes `mu` with
    /// [`MLDSAPublicKeyTrait::compute_mu`] or [`MuBuilder`] and sends only that to the module
    /// holding the key, which serves a message too large to move (a network HSM, a smartcard
    /// over near-field radio) or too sensitive to transmit. The signature is indistinguishable
    /// from one made over the message by [`SigningKey::create_signer`], and unlike a HashML-DSA
    /// signature it verifies with a standard ML-DSA verifier, which need not know how `mu` was
    /// made. The hedged variant: `rnd` is drawn from `rng`.
    ///
    /// [`SigningKey::create_signer`]: bouncycastle_core::signature_key::SigningKey::create_signer
    fn sign_mu<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rng: &mut dyn RNG,
    ) -> Result<[u8; SIG_LEN], SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        let mut out = [0u8; SIG_LEN];
        self.sign_mu_out(mu, rng, &mut out)?;
        Ok(out)
    }

    /// As [`sign_mu`](Self::sign_mu), writing into `output`; returns the number of bytes written.
    fn sign_mu_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rng: &mut dyn RNG,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        self.sign_mu_with_rnd_out(mu, draw_rnd(rng)?, output)
    }

    /// FIPS 204 Section 3.4, the deterministic variant of [`sign_mu`](Self::sign_mu): `rnd` is
    /// 32 zero bytes, so the signature is a function of the key and `mu` alone. See the crate
    /// docs on `rnd` for what that gives up.
    fn sign_mu_deterministic<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
    ) -> Result<[u8; SIG_LEN], SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        let mut out = [0u8; SIG_LEN];
        self.sign_mu_deterministic_out(mu, &mut out)?;
        Ok(out)
    }

    /// As [`sign_mu_deterministic`](Self::sign_mu_deterministic), writing into `output`.
    fn sign_mu_deterministic_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        self.sign_mu_with_rnd_out(mu, [0u8; MLDSA_RND_LEN], output)
    }
}

pub(crate) trait MLDSAPrivateKeyInternalTrait<P: MLDSAParams>: Sized {
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

impl<P: MLDSAParams> MLDSAPrivateKeyTrait<P> for MLDSAPrivateKey<P> {
    fn seed(&self) -> Option<&KeyMaterial<32>> {
        self.seed.as_ref()
    }

    fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    fn derive_pk(&self) -> MLDSAPublicKey<P> {
        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let mut t = {
            // scope for A_hat
            // 3: 𝐀 ← ExpandA(𝜌)
            //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
            let A_hat = expandA::<P>(&self.rho);

            let mut t_ntt = A_hat.matrix_vector_ntt(&self.s1_hat);
            // Bound-keeping step before NTT⁻¹, not in FIPS 204: see [`Polynomial::reduce32`].
            t_ntt.reduce32();
            t_ntt.inv_ntt();
            t_ntt
        };

        {
            // Deviation from the FIPS:
            // Because s2 is in ntt form, it is necessary to reverse that here before adding it to t
            let mut s2: Secret<P::VecK> = self.s2_hat.clone();
            s2.reduce();
            s2.inv_ntt();

            t.add_vector_ntt(&s2);
            t.conditional_add_q();
        }
        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, _) = power_2_round_vec(&t);

        <MLDSAPublicKey<P> as MLDSAPublicKeyInternalTrait<P>>::new(self.rho, t1)
    }
}

impl<P: MLDSAParams> MLDSAPrivateKeyInternalTrait<P> for MLDSAPrivateKey<P> {
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

impl<P: PrivateKeyLen<SK_LEN>, const SK_LEN: usize> SignaturePrivateKey<SK_LEN>
    for MLDSAPrivateKey<P>
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

        Self::sk_decode(&bytes_sized)
    }
}

impl<P: MLDSAParams> Eq for MLDSAPrivateKey<P> {}

impl<P: MLDSAParams> PartialEq for MLDSAPrivateKey<P> {
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode_buf();
        let other_encoded = other.encode_buf();
        bouncycastle_utils::ct::ct_eq_bytes((*self_encoded).as_ref(), (*other_encoded).as_ref())
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLDSAParams> fmt::Debug for MLDSAPrivateKey<P> {
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
impl<P: MLDSAParams> Display for MLDSAPrivateKey<P> {
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

/// An ML-DSA private key with its public matrix 𝐀̂ expanded once, for repeated signatures under the
/// same key: it borrows the [`MLDSAPrivateKey`], so the secret exists in one place, and carries the
/// matrix beside it (see the crate's Memory Usage table). It implements the same signing roles as
/// the key it borrows; the encoding is the borrowed key's, [`key()`](Self::key).
pub struct MLDSAPrivateKeyExpanded<'k, P: MLDSAParams> {
    pub(crate) sk: &'k MLDSAPrivateKey<P>,
    pub(crate) A_hat: P::MatrixA,
}

impl<'k, P: MLDSAParams> MLDSAPrivateKeyExpanded<'k, P> {
    /// The key this expansion was made from.
    pub fn key(&self) -> &'k MLDSAPrivateKey<P> {
        self.sk
    }
}

/// See the note on [`MLDSAPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLDSAParams> Clone for MLDSAPrivateKeyExpanded<'_, P> {
    fn clone(&self) -> Self {
        Self { sk: self.sk, A_hat: self.A_hat.clone() }
    }
}

impl<P: MLDSAParams> PartialEq for MLDSAPrivateKeyExpanded<'_, P> {
    fn eq(&self, other: &Self) -> bool {
        self.sk.eq(other.sk)
    }
}

impl<P: MLDSAParams> Eq for MLDSAPrivateKeyExpanded<'_, P> {}

impl<P: MLDSAParams> Debug for MLDSAPrivateKeyExpanded<'_, P> {
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

impl<P: MLDSAParams> Display for MLDSAPrivateKeyExpanded<'_, P> {
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

impl<'k, P: MLDSAParams> From<&'k MLDSAPrivateKey<P>> for MLDSAPrivateKeyExpanded<'k, P> {
    /// Expands the public matrix A once, for repeated signatures under the same private key.
    fn from(sk: &'k MLDSAPrivateKey<P>) -> Self {
        Self { sk, A_hat: sk.A_hat() }
    }
}

impl<P: MLDSAParams> MLDSAPrivateKeyTrait<P> for MLDSAPrivateKeyExpanded<'_, P> {
    fn seed(&self) -> Option<&KeyMaterial<32>> {
        self.sk.seed()
    }

    fn tr(&self) -> &[u8; 64] {
        self.sk.tr()
    }

    fn derive_pk(&self) -> MLDSAPublicKey<P> {
        self.sk.derive_pk()
    }
}

impl<P: MLDSAParams> SignMuWithRnd<P> for MLDSAPrivateKey<P> {
    fn sign_mu_with_rnd_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rnd: [u8; MLDSA_RND_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        sign_internal::<P, Self, SIG_LEN>(self, &self.A_hat(), mu, rnd, output)
    }
}

impl<P: MLDSAParams> SignMuWithRnd<P> for MLDSAPrivateKeyExpanded<'_, P> {
    /// Signs with the expanded matrix the key carries.
    fn sign_mu_with_rnd_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rnd: [u8; MLDSA_RND_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        sign_internal::<P, MLDSAPrivateKey<P>, SIG_LEN>(self.sk, &self.A_hat, mu, rnd, output)
    }
}
