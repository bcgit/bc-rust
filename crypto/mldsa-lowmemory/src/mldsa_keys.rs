use crate::low_memory_helpers::{expandA_elem, s_unpack};
use crate::mldsa::{H, MLDSA_MU_LEN, MLDSA_RND_LEN, N, POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
use crate::mldsa::{MuBuilder, draw_rnd, sign_internal, verify_internal};
use crate::params::{FullPrivateKeyLen, PrivateKeyLen, PublicKeyLen, SignatureLen};
use crate::params::{MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Hash, RNG, SignaturePrivateKey, SignaturePublicKey, XOF, XOFSqueezer,
};
use bouncycastle_mldsa_common::aux_functions::{
    bit_pack_eta, bit_pack_t0, power_2_round, rej_bounded_poly, simple_bit_pack_t1,
    simple_bit_unpack_t1,
};
use bouncycastle_mldsa_common::polynomial::Polynomial;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::ops::DerefMut;
// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;

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
pub struct MLDSAPublicKey<P: MLDSAParams> {
    pub(crate) rho: [u8; 32],
    pub(crate) t1_packed: P::T1Packed,
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
    /// Not exposing a constructor publicly because the user should get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: [u8; 32], t1_packed: P::T1Packed) -> Self;

    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get a ref to t1
    fn unpack_t1_row(&self, row: usize) -> Polynomial;
}

impl<P: MLDSAParams> MLDSAPublicKey<P> {
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    pub(crate) fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Self
    where
        P: PublicKeyLen<PK_LEN>,
    {
        let mut t1_packed = <P::T1Packed as ZeroizablePrimitive>::ZEROED;
        t1_packed.as_mut().copy_from_slice(&pk[32..]);
        Self { rho: pk[..32].try_into().unwrap(), t1_packed }
    }
}

impl<P: MLDSAParams> MLDSAPublicKeyTrait<P> for MLDSAPublicKey<P> {
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
        verify_internal::<P, Self, SIG_LEN>(self, mu, sig)
    }
}

impl<P: MLDSAParams> MLDSAPublicKeyInternalTrait<P> for MLDSAPublicKey<P> {
    fn new(rho: [u8; 32], t1_packed: P::T1Packed) -> Self {
        Self { rho, t1_packed }
    }

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

impl<P: PublicKeyLen<PK_LEN>, const PK_LEN: usize> SignaturePublicKey<PK_LEN>
    for MLDSAPublicKey<P>
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
        out[32..].copy_from_slice(self.t1_packed.as_ref());

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
    /// Section 6.2) runs out, which has negligible probability; nothing is written.
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

/// Internal structure for holding a seed-based private key for ML-DSA.
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
    /// Create a new MLDSASeedPrivateKey from a 32-byte KeyMaterial, deriving `tr` on the way.
    /// The seed's `SecurityStrength` must be at least the parameter set's: 128-bit (ML-DSA-44),
    /// 192-bit (ML-DSA-65) or 256-bit (ML-DSA-87); otherwise [`SignatureError::KeyGenError`].
    pub fn new(seed: &KeyMaterial<32>) -> Result<Self, SignatureError> {
        Self::new_with_pk(seed).map(|(sk, _pk)| sk)
    }

    /// [`Self::new`], also returning the public key the construction derives on the way to
    /// `tr`, so that key generation does not derive it twice.
    pub(crate) fn new_with_pk(
        seed: &KeyMaterial<32>,
    ) -> Result<(Self, MLDSAPublicKey<P>), SignatureError> {
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
        let mut h = h.into_squeezer();
        let bytes_written = h.do_output_out(&mut rho);
        debug_assert_eq!(bytes_written, 32);
        let bytes_written = h.do_output_out(rho_prime.deref_mut());
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.do_output_out(K.deref_mut());
        debug_assert_eq!(bytes_written, 32);

        (rho, rho_prime, K)
    }

    fn compute_t_row(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
    ) -> Polynomial {
        debug_assert!(idx < P::k);

        // [Optimization Note]:
        // This is one of the places that a row of s1 can be re-computed instead of expanded from the compressed form.
        // let mut s1 = self.compute_s1_row(0);
        let mut s1_hat_i = s_unpack::<P, _>(s1_packed, 0);
        s1_hat_i.ntt();

        let mut t_i = {
            let mut t_hat_i = expandA_elem(&self.rho, idx, 0);
            t_hat_i.multiply_ntt(&s1_hat_i);

            for col in 1..P::l {
                // [Optimization Note]:
                // This is one of the places that a row of s1 can be re-computed instead of expanded from the compressed form.
                // s1 = self.compute_s1_row(col);
                let mut s1_hat = s_unpack::<P, _>(s1_packed, col);
                s1_hat.ntt();
                let mut A_elem = expandA_elem(&self.rho, idx, col);
                A_elem.multiply_ntt(&s1_hat);
                t_hat_i.add_ntt(&A_elem);
            }
            // Bound-keeping step before NTT⁻¹, not in FIPS 204: see [`Polynomial::reduce32`].
            t_hat_i.reduce32();
            t_hat_i.inv_ntt();

            t_hat_i
        };

        // [Optimization Note]:
        // This is one of the places that a row of s2 can be re-computed instead of unpacked from the compressed form.
        // let s2 = self.compute_s2_row(idx);
        let s2 = s_unpack::<P, _>(s2_packed, idx);
        t_i.add_ntt(&s2);
        t_i.conditional_add_q();

        t_i
    }
}

impl<P: PrivateKeyLen<SK_LEN>, const SK_LEN: usize> SignaturePrivateKey<SK_LEN>
    for MLDSASeedPrivateKey<P>
{
    /// Encodes the private key seed.
    fn encode(&self) -> [u8; SK_LEN] {
        self.seed.ref_to_bytes().try_into().unwrap()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        out.copy_from_slice(self.seed.ref_to_bytes());

        debug_assert_eq!(self.seed.ref_to_bytes().len(), SK_LEN);
        SK_LEN
    }

    /// Takes the 32 bytes as the seed and tags them [`KeyType::Seed`] at 256-bit strength. The
    /// bytes are the key, so there is nothing here to check them against: a caller importing a
    /// seed from storage vouches for how it was generated. [`crate::MLDSATrait::keygen_from_seed`]
    /// on typed [`KeyMaterial`] keeps the key-type and strength checks.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != 32 {
            return Err(SignatureError::DecodingError("Invalid seed length"));
        }
        let mut keymat = KeyMaterial::<32>::from_bytes(bytes)?;
        do_hazardous_operations(&mut keymat, |keymat| {
            keymat.set_key_type(KeyType::Seed)?;
            keymat.set_security_strength(SecurityStrength::_256bit)
        })?;

        Self::new(&keymat)
    }
}

impl<P: MLDSAParams> MLDSAPrivateKeyTrait<P> for MLDSASeedPrivateKey<P> {
    fn from_keymaterial(seed: &KeyMaterial<32>) -> Result<Self, SignatureError> {
        Self::new(seed)
    }

    fn seed(&self) -> Option<&KeyMaterial<32>> {
        Some(&self.seed)
    }

    fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    fn derive_pk(&self) -> MLDSAPublicKey<P> {
        // The goal here is to get t1, which is built and compressed one row at a time.

        let s1_packed: Secret<P::S1Packed> = self.compute_s1_packed();
        let s2_packed: Secret<P::S2Packed> = self.compute_s2_packed();

        let mut t1_packed = <P::T1Packed as ZeroizablePrimitive>::ZEROED;
        debug_assert_eq!(P::T1_PACKED_LEN, POLY_T1PACKED_LEN * P::k);

        for i in 0..P::k {
            t1_packed.as_mut()[i * POLY_T1PACKED_LEN..(i + 1) * POLY_T1PACKED_LEN].copy_from_slice(
                &simple_bit_pack_t1(&self.compute_t1_row(i, &s1_packed, &s2_packed)),
            );
        }

        MLDSAPublicKey::<P>::new(self.rho, t1_packed)
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
        let s1_packed = self.compute_s1_packed();
        out[off..off + P::S1_PACKED_LEN].copy_from_slice((*s1_packed).as_ref());
        off += P::S1_PACKED_LEN;

        // 5: for 𝑖 from 0 to 𝑘 − 1 do
        // 6:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐬2[𝑖], 𝜂, 𝜂)
        // 7: end for
        let s2_packed = self.compute_s2_packed();
        out[off..off + P::S2_PACKED_LEN].copy_from_slice((*s2_packed).as_ref());
        off += P::S2_PACKED_LEN;

        // 8: for 𝑖 from 0 to 𝑘 − 1 do
        // 9:   𝑠𝑘 ← 𝑠𝑘 || BitPack (𝐭0[𝑖], 2𝑑−1 − 1, 2𝑑−1)
        // 10: end for
        debug_assert_eq!(off + P::k * POLY_T0PACKED_LEN, FULL_SK_LEN);
        for row in 0..P::k {
            let t0_i = self.compute_t0_row(row, &s1_packed, &s2_packed);
            out[off..off + POLY_T0PACKED_LEN].copy_from_slice(&bit_pack_t0(&t0_i));
            off += POLY_T0PACKED_LEN;
        }
        debug_assert_eq!(off, FULL_SK_LEN);

        FULL_SK_LEN
    }
}

pub(crate) trait MLDSAPrivateKeyInternalTrait<P: MLDSAParams>: Sized {
    fn rho(&self) -> &[u8; 32];
    fn K(&self) -> &[u8; 32];

    /// [`MLDSAPrivateKeyTrait::from_keymaterial`], also returning the public key derived on the
    /// way, for key generation.
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<32>,
    ) -> Result<(Self, MLDSAPublicKey<P>), SignatureError>;

    /// A single entry of a privacy key vector.
    /// These tend to be used very transiently, so we won't bother wrapping it as a Secret.
    fn compute_s1_row(&self, idx: usize) -> Polynomial;

    /// Private key component.
    /// The packed representation sticks around for the whole computation, so
    /// we'll wrap in as a Secret.
    fn compute_s1_packed(&self) -> Secret<P::S1Packed>;

    /// A single entry of a privacy key vector.
    /// These tend to be used very transiently, so we won't bother wrapping it as a Secret.
    fn compute_s2_row(&self, idx: usize) -> Polynomial;

    /// Private key component.
    /// The packed representation sticks around for the whole computation, so
    /// we'll wrap in as a Secret.
    fn compute_s2_packed(&self) -> Secret<P::S2Packed>;

    /// Public key component.
    fn compute_t0_row(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
    ) -> Polynomial;

    /// Public key component.
    fn compute_t1_row(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
    ) -> Polynomial;
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

    fn compute_s1_row(&self, idx: usize) -> Polynomial {
        debug_assert!(idx < P::l);
        rej_bounded_poly::<P>(&self.rho_prime, &(idx as u16).to_le_bytes())
    }

    fn compute_s1_packed(&self) -> Secret<P::S1Packed> {
        let mut s1_packed: Secret<P::S1Packed> = Secret::new();
        let width = P::POLY_ETA_PACKED_LEN;
        for idx in 0..P::l {
            let s1_i = self.compute_s1_row(idx);
            bit_pack_eta::<P>(&s1_i, &mut s1_packed.as_mut()[idx * width..(idx + 1) * width]);
        }
        s1_packed
    }

    fn compute_s2_row(&self, idx: usize) -> Polynomial {
        debug_assert!(idx < P::k);
        rej_bounded_poly::<P>(&self.rho_prime, &((idx + P::l) as u16).to_le_bytes())
    }

    fn compute_s2_packed(&self) -> Secret<P::S2Packed> {
        let mut s2_packed: Secret<P::S2Packed> = Secret::new();
        let width = P::POLY_ETA_PACKED_LEN;
        for idx in 0..P::k {
            let s2_i = self.compute_s2_row(idx);
            bit_pack_eta::<P>(&s2_i, &mut s2_packed.as_mut()[idx * width..(idx + 1) * width]);
        }
        s2_packed
    }

    fn compute_t0_row(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
    ) -> Polynomial {
        let mut t0 = self.compute_t_row(idx, s1_packed, s2_packed);
        for j in 0..N {
            (_, t0[j]) = power_2_round(t0[j]);
        }

        t0
    }

    fn compute_t1_row(
        &self,
        idx: usize,
        s1_packed: &Secret<P::S1Packed>,
        s2_packed: &Secret<P::S2Packed>,
    ) -> Polynomial {
        let mut t1 = self.compute_t_row(idx, s1_packed, s2_packed);
        for j in 0..N {
            (t1[j], _) = power_2_round(t1[j]);
        }

        t1
    }
}

impl<P: MLDSAParams> SignMuWithRnd<P> for MLDSASeedPrivateKey<P> {
    fn sign_mu_with_rnd_out<const SIG_LEN: usize>(
        &self,
        mu: &[u8; MLDSA_MU_LEN],
        rnd: [u8; MLDSA_RND_LEN],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>
    where
        P: SignatureLen<SIG_LEN>,
    {
        sign_internal::<P, Self, SIG_LEN>(self, mu, rnd, output)
    }
}
