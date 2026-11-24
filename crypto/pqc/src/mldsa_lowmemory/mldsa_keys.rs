use crate::mldsa_common::aux_functions::{
    bit_pack_eta, bit_pack_t0, power_2_round, rej_bounded_poly_out, simple_bit_pack_t1,
    simple_bit_unpack_t1,
};
use crate::mldsa_common::polynomial::Polynomial;
use crate::mldsa_lowmemory::low_memory_helpers::{expandA_elem, s_unpack_out};
use crate::mldsa_lowmemory::mldsa::{
    H, MLDSA_MU_LEN, MLDSA_RND_LEN, N, POLY_T0PACKED_LEN, POLY_T1PACKED_LEN,
};
use crate::mldsa_lowmemory::mldsa::{
    MuBuilder, Rnd, check_filled_tr, draw_rnd, sign_internal, verify_internal,
};
use crate::mldsa_lowmemory::params::{
    FullPrivateKeyLen, PrivateKeyLen, PublicKeyLen, SignatureLen,
};
use crate::mldsa_lowmemory::params::{MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams};
use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, SignatureError};
use bouncycastle_core::hazmat::{do_hazardous_operations, finish_token};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Hash, PrivateKey, PublicKey, RNG, XOF, XOFSqueezer};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::ops::DerefMut;
// imports just for docs
#[allow(unused_imports)]
use crate::mldsa_lowmemory::mldsa::MLDSATrait;

/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44Params>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey = MLDSASeedPrivateKey<MLDSA44Params>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65Params>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey = MLDSASeedPrivateKey<MLDSA65Params>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87Params>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey = MLDSASeedPrivateKey<MLDSA87Params>;

/// An ML-DSA public key.
///
/// It is a key of [`MLDSA`](crate::mldsa_lowmemory::MLDSA), and verifies HashML-DSA only through the view
/// [`as_prehash`](Self::as_prehash) gives; the key itself has no pre-hash method:
///
/// ```compile_fail,E0599
/// use bouncycastle_core::signature_key::PreHashVerifyingKey;
/// use bouncycastle_pqc::mldsa_lowmemory::MLDSA44PublicKey;
///
/// fn verify(pk: &MLDSA44PublicKey, sig: &[u8]) {
///     let _ = pk.verify_ph(&[0u8; 64], None, sig);
/// }
/// ```
pub struct MLDSAPublicKey<P: MLDSAParams> {
    pub(in crate::mldsa_lowmemory) rho: [u8; 32],
    pub(in crate::mldsa_lowmemory) t1_packed: P::T1Packed,
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLDSAParams> Clone for MLDSAPublicKey<P> {
    fn clone(&self) -> Self {
        Self { rho: self.rho, t1_packed: self.t1_packed }
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
    /// made with [`MLDSAPrivateKeyTrait::sign_mu`] verifies with [`OneShotVerifyingKey::verify`]
    /// over the message.
    ///
    /// [`OneShotVerifyingKey::verify`]:
    ///     bouncycastle_core::signature_key::OneShotVerifyingKey::verify
    fn verify_mu<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        sig: &[u8; SIG_LEN],
    ) -> Result<(), SignatureError>
    where
        P: SignatureLen<SIG_LEN>;
}

pub(in crate::mldsa_lowmemory) trait MLDSAPublicKeyInternalTrait<P: MLDSAParams> {
    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get a ref to t1
    fn unpack_t1_row(&self, row: usize) -> Polynomial;
}

impl<P: MLDSAParams> MLDSAPublicKey<P> {
    /// The all-zero key: the public key [`MLDSATrait::keygen_out`] and
    /// [`MLDSATrait::keygen_from_seed_out`] write into. It is not a public key, and until one of
    /// them fills it, verification with it is refused
    /// ([`KeyMaterialError::ActingOnZeroizedKey`]).
    ///
    /// The test is on 𝜌, so a decoded key whose 𝜌 is all zero is refused in the same way; no
    /// generated key has one.
    pub fn zeroized() -> Self {
        Self { rho: [0u8; 32], t1_packed: <P::T1Packed as ZeroizablePrimitive>::ZEROED }
    }

    /// [`KeyMaterialError::ActingOnZeroizedKey`] unless the key holds a key. 𝜌 says so: it is 32
    /// bytes of SHAKE256 output in a generated key, and all zero in the state
    /// [`zeroized`](Self::zeroized) makes and the `_out` generators leave on an error.
    pub(in crate::mldsa_lowmemory) fn check_filled(&self) -> Result<(), SignatureError> {
        if self.rho == [0u8; 32] {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        Ok(())
    }

    /// Back to the all-zero key.
    pub(in crate::mldsa_lowmemory) fn clear(&mut self) {
        self.rho = [0u8; 32];
        // Cleared where it lies: assigning the zero value builds it in a temporary first.
        self.t1_packed.as_mut().fill(0);
    }

    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    pub(in crate::mldsa_lowmemory) fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Self
    where
        P: PublicKeyLen<PK_LEN>,
    {
        let mut t1_packed = <P::T1Packed as ZeroizablePrimitive>::ZEROED;
        t1_packed.as_mut().copy_from_slice(&pk[32..]);
        Self { rho: pk[..32].try_into().unwrap(), t1_packed }
    }
}

impl<P: MLDSAParams> MLDSAPublicKeyTrait<P> for MLDSAPublicKey<P> {
    /// Refused for a key that was never filled, and so are its verifiers.
    fn create_mu_builder(&self, ctx: Option<&[u8]>) -> Result<MuBuilder, SignatureError> {
        self.check_filled()?;
        MuBuilder::from_tr(&self.compute_tr(), ctx)
    }

    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        // tr = H(pkEncode(rho, t1), 64), the encoding being rho || t1_packed
        let mut h = H::new();
        h.do_update(&self.rho);
        h.do_update(self.t1_packed.as_ref());
        h.into_squeezer().do_output_out(&mut tr);

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
        self.check_filled()?;
        verify_internal::<P, Self, SIG_LEN>(self, mu, sig)
    }
}

impl<P: MLDSAParams> MLDSAPublicKeyInternalTrait<P> for MLDSAPublicKey<P> {
    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    fn unpack_t1_row(&self, row: usize) -> Polynomial {
        simple_bit_unpack_t1(
            self.t1_packed.as_ref()[row * POLY_T1PACKED_LEN..(row + 1) * POLY_T1PACKED_LEN]
                .try_into()
                .expect("a T1Packed row is exactly POLY_T1PACKED_LEN bytes"),
        )
    }
}

impl<P: PublicKeyLen<PK_LEN>, const PK_LEN: usize> PublicKey<PK_LEN> for MLDSAPublicKey<P> {
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
        out[32..].copy_from_slice(self.t1_packed.as_ref());

        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        if bytes.len() != PK_LEN {
            return Err(KeyDecodingError("Provided key bytes are the incorrect length"));
        }
        let sized_bytes: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(Self::pk_decode(&sized_bytes))
    }
}

impl<P: MLDSAParams> Eq for MLDSAPublicKey<P> {}

impl<P: MLDSAParams> PartialEq for MLDSAPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        bouncycastle_utils::ct::ct_eq_bytes(&self.rho, &other.rho)
            & bouncycastle_utils::ct::ct_eq_bytes(self.t1_packed.as_ref(), other.t1_packed.as_ref())
    }
}

impl<P: MLDSAParams> fmt::Debug for MLDSAPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            self.compute_tr(),
        )
    }
}

impl<P: MLDSAParams> Display for MLDSAPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            P::ALG_NAME,
            self.compute_tr(),
        )
    }
}

/// The step every signing path shares: FIPS 204 Algorithm 7 over an externally computed mu with
/// the randomizer `rnd` already chosen. Module-private so that `rnd` is never a caller's choice: the
/// public methods draw it from the caller's RNG (the hedged variant of Section 3.4), and a
/// known-answer test that must reproduce a vector's `rnd` passes an RNG that returns it.
pub(in crate::mldsa_lowmemory) trait SignMuWithRnd<P: MLDSAParams> {
    fn sign_mu_with_rnd_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rnd: &[u8; MLDSA_RND_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>;
}

/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<P: MLDSAParams>: Sized + SignMuWithRnd<P> {
    /// New from KeyMaterial. Can throw a SignatureError if the KeyMaterial does not contain sufficient entropy.
    fn from_keymaterial(seed: &KeyMaterial<32>) -> Result<Self, SignatureError>;

    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> Option<&KeyMaterial<32>>;

    /// Get a copy of the key hash `tr`, computed once when the key was built.
    fn tr(&self) -> &[u8; 64];
    /// Derives the full public key from the seed: a key generation's worth of work.
    fn derive_pk(&self) -> MLDSAPublicKey<P>;
    /// This produces the full private key in the encoding specified in FIPS 204 Algorithm 24 skEncode()
    /// so that it is compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [`MLDSASeedPrivateKey`].
    fn encode_full_sk<const FULL_SK_LEN: usize>(&self) -> [u8; FULL_SK_LEN]
    where
        P: FullPrivateKeyLen<FULL_SK_LEN>;
    /// This produces the full private key in the encoding specified in FIPS 204 Algorithm 24 skEncode()
    /// so that it is compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [`MLDSASeedPrivateKey`].
    fn encode_full_sk_out<const FULL_SK_LEN: usize>(&self, out: &mut [u8; FULL_SK_LEN]) -> usize
    where
        P: FullPrivateKeyLen<FULL_SK_LEN>;
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
        // A key that was never filled is refused here, so its signers are too.
        check_filled_tr(self.tr())?;
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
    /// # Errors
    /// [`SignatureError::RejectionLimitExceeded`] if the bounded rejection loop (FIPS 204
    /// Section 6.2) runs out, which has negligible probability, and the RNG's error if `rnd`
    /// cannot be drawn; nothing is written.
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
    /// `output` is zeroized first and left so on every error.
    fn sign_mu_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rng: &mut dyn RNG,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        // Cleared before the draw, so that an RNG failure leaves no stale bytes in it.
        output.fill(0);
        let mut rnd = Rnd::new();
        draw_rnd(rng, &mut rnd)?;
        self.sign_mu_with_rnd_out(mu, &rnd, output)
    }

    /// FIPS 204 Section 3.4, the deterministic variant of [`sign_mu`](Self::sign_mu): `rnd` is
    /// 32 zero bytes, so the signature is a function of the key and `mu` alone. See the module
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
        self.sign_mu_with_rnd_out(mu, &[0u8; MLDSA_RND_LEN], output)
    }
}

/// Internal structure for holding a seed-based private key for ML-DSA.
///
/// It is a key of [`MLDSA`](crate::mldsa_lowmemory::MLDSA), and signs HashML-DSA only through the view
/// [`as_prehash`](Self::as_prehash) gives; the key itself has no pre-hash method:
///
/// ```compile_fail,E0599
/// use bouncycastle_core::signature_key::DeterministicPreHashSigningKey;
/// use bouncycastle_pqc::mldsa_lowmemory::MLDSA44PrivateKey;
///
/// fn sign(sk: &MLDSA44PrivateKey) {
///     let _ = sk.sign_ph_deterministic(&[0u8; 64], None);
/// }
/// ```
pub struct MLDSASeedPrivateKey<P: MLDSAParams> {
    _phantom: core::marker::PhantomData<P>,
    // note: KeyMaterial is inherently Secret
    seed: KeyMaterial<32>,
    // public seed rho does not need to be secret
    rho: [u8; 32],
    rho_prime: Secret<[u8; 64]>,
    K: Secret<[u8; 32]>,
    // Algorithm 6 line 9, tr = H(pk, 64): public data. Computed once when the key is built, since
    // every signature needs it for mu and deriving it means a full public-key derivation.
    tr: [u8; 64],
}
// Written out rather than derived: the derives would demand `P: Clone` / `P: Eq`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLDSAParams> Clone for MLDSASeedPrivateKey<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: core::marker::PhantomData,
            seed: self.seed.clone(),
            rho: self.rho,
            rho_prime: self.rho_prime.clone(),
            K: self.K.clone(),
            tr: self.tr,
        }
    }
}

impl<P: MLDSAParams> PartialEq for MLDSASeedPrivateKey<P> {
    fn eq(&self, other: &Self) -> bool {
        // Compared through `KeyMaterial`/`Secret`'s own `PartialEq`, which is constant-time: do
        // not deref to the inner arrays, as that would select the array's variable-time `==`.
        let seed = self.seed == other.seed;
        let rho = self.rho == other.rho;
        let rho_prime = self.rho_prime == other.rho_prime;
        let K = self.K == other.K;
        seed & rho & rho_prime & K
    }
}

impl<P: MLDSAParams> Eq for MLDSASeedPrivateKey<P> {}

impl<P: MLDSAParams> Debug for MLDSASeedPrivateKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = P::ALG_NAME;
        write!(f, "MLDSASeedPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.tr(),)
    }
}

impl<P: MLDSAParams> Display for MLDSASeedPrivateKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = P::ALG_NAME;
        write!(f, "MLDSASeedPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.tr(),)
    }
}

impl<P: MLDSAParams> MLDSASeedPrivateKey<P> {
    /// The all-zero key: the key [`MLDSATrait::keygen_out`] and
    /// [`MLDSATrait::keygen_from_seed_out`] write into, so that the seed and what is derived from
    /// it are written where they will live and never moved. It is not a generated key: until one
    /// of them fills it, signing with it is refused ([`KeyMaterialError::ActingOnZeroizedKey`]),
    /// it has no [`seed`](MLDSAPrivateKeyTrait::seed), and its encodings are all zero.
    pub fn zeroized() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
            seed: KeyMaterial::new(),
            rho: [0u8; 32],
            rho_prime: Secret::new(),
            K: Secret::new(),
            tr: [0u8; 64],
        }
    }

    /// Whether the key holds a key: `tr` is a SHAKE256 output in a generated key, and all zero in
    /// the state [`zeroized`](Self::zeroized) makes and the `_out` generators leave on an error.
    fn is_filled(&self) -> bool {
        self.tr != [0u8; 64]
    }

    /// [`KeyMaterialError::ActingOnZeroizedKey`] unless the key holds a key.
    pub(in crate::mldsa_lowmemory) fn check_filled(&self) -> Result<(), SignatureError> {
        check_filled_tr(&self.tr)
    }

    /// Back to the all-zero key, the secret fields wiped.
    pub(in crate::mldsa_lowmemory) fn clear(&mut self) {
        self.seed.zeroize();
        self.rho = [0u8; 32];
        self.rho_prime.zeroize();
        self.K.zeroize();
        self.tr = [0u8; 64];
    }

    /// FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) from `seed` into this key and `pk`, both
    /// cleared first and left so on an error: the seed is copied, and 𝜌, 𝜌′ and 𝐾 derived, where
    /// they live in the key.
    pub(in crate::mldsa_lowmemory) fn fill_out(
        &mut self,
        seed: &KeyMaterial<32>,
        pk: &mut MLDSAPublicKey<P>,
    ) -> Result<(), SignatureError> {
        self.clear();
        pk.clear();
        Self::check_seed(seed)?;

        // Copied in place: a `clone` would stage the seed in a temporary and move it in.
        let copied = do_hazardous_operations(&mut self.seed, |own| {
            own.set_bytes_as_type(seed.ref_to_bytes(), seed.key_type())?;
            own.set_security_strength(seed.security_strength())
        });
        if let Err(e) = copied {
            self.clear();
            return Err(e.into());
        }

        // Alg 6; 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        let mut h = H::default();
        h.do_update(self.seed.ref_to_bytes());
        h.do_update(&(P::k as u8).to_le_bytes());
        h.do_update(&(P::l as u8).to_le_bytes());
        let mut h = h.finish_squeezer(&finish_token());
        let bytes_written = h.do_output_out(&mut self.rho);
        debug_assert_eq!(bytes_written, 32);
        let bytes_written = h.do_output_out(self.rho_prime.deref_mut());
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.do_output_out(self.K.deref_mut());
        debug_assert_eq!(bytes_written, 32);

        pk.rho = self.rho;
        self.derive_t1_packed_into(&mut pk.t1_packed);
        self.tr = pk.compute_tr();
        Ok(())
    }

    /// The 𝐭1 of [`MLDSAPrivateKeyTrait::derive_pk`], packed into `t1_packed`.
    fn derive_t1_packed_into(&self, t1_packed: &mut P::T1Packed) {
        // The goal here is to get t1, which is built and compressed one row at a time.

        let mut s1_packed = Secret::<P::S1Packed>::new();
        self.compute_s1_packed_out(&mut s1_packed);
        let mut s2_packed = Secret::<P::S2Packed>::new();
        self.compute_s2_packed_out(&mut s2_packed);

        debug_assert_eq!(P::T1_PACKED_LEN, POLY_T1PACKED_LEN * P::k);
        let mut t1_i = Polynomial::new();
        for i in 0..P::k {
            self.compute_t1_row_out(i, &s1_packed, &s2_packed, &mut t1_i);
            t1_packed.as_mut()[i * POLY_T1PACKED_LEN..(i + 1) * POLY_T1PACKED_LEN]
                .copy_from_slice(&simple_bit_pack_t1(&t1_i));
        }
    }

    /// The seed checks of key generation.
    fn check_seed(seed: &KeyMaterial<32>) -> Result<(), SignatureError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }

        if seed.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(SignatureError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength: 128-bit (ML-DSA-44), 192-bit (ML-DSA-65), or 256-bit (ML-DSA-87).",
            ));
        }
        Ok(())
    }

    /// Create a new MLDSASeedPrivateKey from a 32-byte KeyMaterial, deriving `tr` on the way.
    /// The seed's `SecurityStrength` must be at least the parameter set's: 128-bit (ML-DSA-44),
    /// 192-bit (ML-DSA-65) or 256-bit (ML-DSA-87); otherwise [`SignatureError::KeyGenError`].
    pub fn new(seed: &KeyMaterial<32>) -> Result<Self, SignatureError> {
        Self::new_with_pk(seed).map(|(sk, _pk)| sk)
    }

    /// [`Self::new`], also returning the public key the construction derives on the way to
    /// `tr`, so that key generation does not derive it twice.
    // Its own assembly rather than a wrapper over `fill_out`: as a wrapper it cost the KeyGen
    // rows of the module's memory table 0.8 to 2.5 kB of stack. `keygen_out` is the form that
    // leaves no copy of the key behind.
    pub(in crate::mldsa_lowmemory) fn new_with_pk(
        seed: &KeyMaterial<32>,
    ) -> Result<(Self, MLDSAPublicKey<P>), SignatureError> {
        Self::check_seed(seed)?;

        let (rho, rho_prime, K) = Self::compute_rhos_and_K(seed);

        let mut sk = Self {
            _phantom: core::marker::PhantomData,
            seed: seed.clone(),
            rho,
            rho_prime,
            K,
            tr: [0u8; 64],
        };
        let pk = sk.derive_pk();
        sk.tr = pk.compute_tr();
        Ok((sk, pk))
    }

    fn compute_rhos_and_K(
        seed: &KeyMaterial<32>,
    ) -> ([u8; 32], Secret<[u8; 64]>, Secret<[u8; 32]>) {
        // derive sk.K
        // Alg 6; 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho = [0u8; 32];
        let mut rho_prime: Secret<[u8; 64]> = Secret::new();
        let mut K: Secret<[u8; 32]> = Secret::new();

        let mut h = H::default();
        h.do_update(seed.ref_to_bytes());
        h.do_update(&(P::k as u8).to_le_bytes());
        h.do_update(&(P::l as u8).to_le_bytes());
        let mut h = h.finish_squeezer(&finish_token());
        let bytes_written = h.do_output_out(&mut rho);
        debug_assert_eq!(bytes_written, 32);
        let bytes_written = h.do_output_out(rho_prime.deref_mut());
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.do_output_out(K.deref_mut());
        debug_assert_eq!(bytes_written, 32);

        (rho, rho_prime, K)
    }

    /// Row `idx` of 𝐭 = NTT−1(𝐀̂ ∘ NTT(𝐬1)) + 𝐬2, into `t_i`. The rows of 𝐬1 and 𝐬2 and their
    /// products are held in `Secret`s here.
    fn compute_t_row_out(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
        t_i: &mut Polynomial,
    ) {
        debug_assert!(idx < P::k);

        let mut s_row = Secret::<Polynomial>::new();
        let mut A_elem = Secret::<Polynomial>::new();
        // One loop body for every column, the first added to a zero accumulator; see
        // `compute_wp_approx_row`.
        *t_i = Polynomial::new();
        for col in 0..P::l {
            // s1 is unpacked from its compressed form a row at a time.
            s_unpack_out::<P, _>(s1_packed, col, &mut s_row);
            s_row.ntt();
            *A_elem = expandA_elem(&self.rho, idx, col);
            A_elem.multiply_ntt(&s_row);
            t_i.add_ntt(&A_elem);
        }
        // Bound-keeping step before NTT⁻¹, not in FIPS 204: see [`Polynomial::reduce32`].
        t_i.reduce32();
        t_i.inv_ntt();

        s_unpack_out::<P, _>(s2_packed, idx, &mut s_row);
        t_i.add_ntt(&s_row);
        t_i.conditional_add_q();
    }
}

impl<P: PrivateKeyLen<SK_LEN>, const SK_LEN: usize> PrivateKey<SK_LEN> for MLDSASeedPrivateKey<P> {
    /// Encodes the private key seed.
    fn encode(&self) -> [u8; SK_LEN] {
        let mut out = [0u8; SK_LEN];
        self.encode_out(&mut out);
        out
    }

    /// All zero for a key that was never filled.
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        if !self.is_filled() {
            return SK_LEN;
        }

        out.copy_from_slice(self.seed.ref_to_bytes());

        debug_assert_eq!(self.seed.ref_to_bytes().len(), SK_LEN);
        SK_LEN
    }

    /// Takes the 32 bytes as the seed and tags them [`KeyType::Seed`] at 256-bit strength. The
    /// bytes are the key, so there is nothing here to check them against: a caller importing a
    /// seed from storage vouches for how it was generated. [`crate::mldsa_lowmemory::MLDSATrait::keygen_from_seed`]
    /// on typed [`KeyMaterial`] keeps the key-type and strength checks.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        if bytes.len() != 32 {
            return Err(KeyDecodingError("Invalid seed length"));
        }
        let mut keymat = KeyMaterial::<32>::from_bytes(bytes)
            .map_err(|_| KeyDecodingError("Invalid ML-DSA seed private key"))?;
        do_hazardous_operations(&mut keymat, |keymat| {
            keymat.set_key_type(KeyType::Seed)?;
            keymat.set_security_strength(SecurityStrength::_256bit)
        })
        .map_err(|_| KeyDecodingError("Invalid ML-DSA seed private key"))?;

        Self::new(&keymat).map_err(|_| KeyDecodingError("Invalid ML-DSA seed private key"))
    }
}

impl<P: MLDSAParams> MLDSAPrivateKeyTrait<P> for MLDSASeedPrivateKey<P> {
    fn from_keymaterial(seed: &KeyMaterial<32>) -> Result<Self, SignatureError> {
        Self::new(seed)
    }

    fn seed(&self) -> Option<&KeyMaterial<32>> {
        self.is_filled().then_some(&self.seed)
    }

    fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    fn derive_pk(&self) -> MLDSAPublicKey<P> {
        let mut t1_packed = <P::T1Packed as ZeroizablePrimitive>::ZEROED;
        self.derive_t1_packed_into(&mut t1_packed);
        MLDSAPublicKey { rho: self.rho, t1_packed }
    }
    fn encode_full_sk<const FULL_SK_LEN: usize>(&self) -> [u8; FULL_SK_LEN]
    where
        P: FullPrivateKeyLen<FULL_SK_LEN>,
    {
        let mut out = [0; FULL_SK_LEN];
        _ = self.encode_full_sk_out(&mut out);

        out
    }
    fn encode_full_sk_out<const FULL_SK_LEN: usize>(&self, out: &mut [u8; FULL_SK_LEN]) -> usize
    where
        P: FullPrivateKeyLen<FULL_SK_LEN>,
    {
        out.fill(0);
        // A key that was never filled encodes as zeros, not as the key of an all-zero seed.
        if !self.is_filled() {
            return FULL_SK_LEN;
        }

        // Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)

        let mut off: usize = 0;

        // 1: 𝑠𝑘 ← 𝜌||𝐾||𝑡𝑟
        out[0..32].copy_from_slice(&self.rho);
        // K is protected inside a Secret<[u8]>, but here we really do need to deref and copy it out.
        out[32..64].copy_from_slice(&*self.K);
        out[64..128].copy_from_slice(self.tr());
        off += 128;

        // 2: for 𝑖 from 0 to ℓ − 1 do
        // 3:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐬1[𝑖], 𝜂, 𝜂)
        // 4: end for
        let mut s1_packed = Secret::<P::S1Packed>::new();
        self.compute_s1_packed_out(&mut s1_packed);
        out[off..off + P::S1_PACKED_LEN].copy_from_slice((*s1_packed).as_ref());
        off += P::S1_PACKED_LEN;

        // 5: for 𝑖 from 0 to 𝑘 − 1 do
        // 6:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐬2[𝑖], 𝜂, 𝜂)
        // 7: end for
        let mut s2_packed = Secret::<P::S2Packed>::new();
        self.compute_s2_packed_out(&mut s2_packed);
        out[off..off + P::S2_PACKED_LEN].copy_from_slice((*s2_packed).as_ref());
        off += P::S2_PACKED_LEN;

        // 8: for 𝑖 from 0 to 𝑘 − 1 do
        // 9:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐭0[𝑖], 2𝑑−1 − 1, 2𝑑−1)
        // 10: end for
        debug_assert_eq!(off + P::k * POLY_T0PACKED_LEN, FULL_SK_LEN);
        let mut t0_i = Secret::<Polynomial>::new();
        for row in 0..P::k {
            self.compute_t0_row_out(row, &s1_packed, &s2_packed, &mut t0_i);
            out[off..off + POLY_T0PACKED_LEN].copy_from_slice(&bit_pack_t0(&t0_i));
            off += POLY_T0PACKED_LEN;
        }
        debug_assert_eq!(off, FULL_SK_LEN);

        FULL_SK_LEN
    }
}

pub(in crate::mldsa_lowmemory) trait MLDSAPrivateKeyInternalTrait<P: MLDSAParams>:
    Sized
{
    fn rho(&self) -> &[u8; 32];
    fn K(&self) -> &[u8; 32];

    /// [`MLDSAPrivateKeyTrait::from_keymaterial`], also returning the public key derived on the
    /// way, for key generation.
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<32>,
    ) -> Result<(Self, MLDSAPublicKey<P>), SignatureError>;

    /// Row `idx` of 𝐬1, into `s1_i`, which the caller holds: it is secret.
    fn compute_s1_row_out(&self, idx: usize, s1_i: &mut Polynomial);

    /// 𝐬1 in the packing of FIPS 204 Algorithm 24 lines 2-4, into `out`, which the caller holds
    /// in a `Secret`.
    fn compute_s1_packed_out(&self, out: &mut P::S1Packed);

    /// Row `idx` of 𝐬2, into `s2_i`, which the caller holds: it is secret.
    fn compute_s2_row_out(&self, idx: usize, s2_i: &mut Polynomial);

    /// 𝐬2 in the packing of FIPS 204 Algorithm 24 lines 5-7, into `out`, which the caller holds
    /// in a `Secret`.
    fn compute_s2_packed_out(&self, out: &mut P::S2Packed);

    /// Private key component: row `idx` of 𝐭0, into `t0_i`, which the caller holds.
    fn compute_t0_row_out(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
        t0_i: &mut Polynomial,
    );

    /// Public key component: row `idx` of 𝐭1, into `t1_i`.
    fn compute_t1_row_out(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
        t1_i: &mut Polynomial,
    );
}

impl<P: MLDSAParams> MLDSAPrivateKeyInternalTrait<P> for MLDSASeedPrivateKey<P> {
    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<32>,
    ) -> Result<(Self, MLDSAPublicKey<P>), SignatureError> {
        Self::new_with_pk(seed)
    }

    fn K(&self) -> &[u8; 32] {
        &self.K
    }

    fn compute_s1_row_out(&self, idx: usize, s1_i: &mut Polynomial) {
        debug_assert!(idx < P::l);
        rej_bounded_poly_out::<P>(&self.rho_prime, &(idx as u16).to_le_bytes(), s1_i)
    }

    fn compute_s1_packed_out(&self, out: &mut P::S1Packed) {
        let mut s1_i = Secret::<Polynomial>::new();
        let width = P::POLY_ETA_PACKED_LEN;
        for idx in 0..P::l {
            self.compute_s1_row_out(idx, &mut s1_i);
            bit_pack_eta::<P>(&s1_i, &mut out.as_mut()[idx * width..(idx + 1) * width]);
        }
    }

    fn compute_s2_row_out(&self, idx: usize, s2_i: &mut Polynomial) {
        debug_assert!(idx < P::k);
        rej_bounded_poly_out::<P>(&self.rho_prime, &((idx + P::l) as u16).to_le_bytes(), s2_i)
    }

    fn compute_s2_packed_out(&self, out: &mut P::S2Packed) {
        let mut s2_i = Secret::<Polynomial>::new();
        let width = P::POLY_ETA_PACKED_LEN;
        for idx in 0..P::k {
            self.compute_s2_row_out(idx, &mut s2_i);
            bit_pack_eta::<P>(&s2_i, &mut out.as_mut()[idx * width..(idx + 1) * width]);
        }
    }

    fn compute_t0_row_out(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
        t0_i: &mut Polynomial,
    ) {
        self.compute_t_row_out(idx, s1_packed, s2_packed, t0_i);
        for j in 0..N {
            (_, t0_i[j]) = power_2_round(t0_i[j]);
        }
    }

    fn compute_t1_row_out(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
        t1_i: &mut Polynomial,
    ) {
        self.compute_t_row_out(idx, s1_packed, s2_packed, t1_i);
        for j in 0..N {
            (t1_i[j], _) = power_2_round(t1_i[j]);
        }
    }
}

impl<P: MLDSAParams> SignMuWithRnd<P> for MLDSASeedPrivateKey<P> {
    fn sign_mu_with_rnd_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rnd: &[u8; MLDSA_RND_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        output.fill(0);
        self.check_filled()?;
        sign_internal::<P, Self, SIG_LEN>(self, mu, rnd, output)
    }
}
