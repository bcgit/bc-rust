use crate::mlkem_common::aux_functions::sample_poly_CBD_out;
use crate::mlkem_common::polynomial::Polynomial;
use crate::mlkem_lowmemory::low_memory_helpers::{
    compute_A_hat_dot_s_hat_out, pack_s_hat_row, pack_t_hat_row, unpack_t_hat_row,
};
use crate::mlkem_lowmemory::mlkem::{G, H, MLKEM_SEED_LEN, POLY_BYTES, q};
use crate::mlkem_lowmemory::params::{
    MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams, PrivateKeyLen, PublicKeyLen,
};
use bouncycastle_core::errors::{KEMError, KeyDecodingError, KeyMaterialError};
use bouncycastle_core::hazmat::{do_hazardous_operations, finish_token};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Hash, PrivateKey, PublicKey};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
// imports just for docs

/* Pub Types */

/// ML-KEM-512 Public Key
pub type MLKEM512PublicKey = MLKEMPublicKey<MLKEM512Params>;
/// ML-KEM-512 Private Key
pub type MLKEM512PrivateKey = MLKEMSeedPrivateKey<MLKEM512Params>;
/// ML-KEM-768 Public Key
pub type MLKEM768PublicKey = MLKEMPublicKey<MLKEM768Params>;
/// ML-KEM-768 Private Key
pub type MLKEM768PrivateKey = MLKEMSeedPrivateKey<MLKEM768Params>;
/// ML-KEM-1024 Public Key
pub type MLKEM1024PublicKey = MLKEMPublicKey<MLKEM1024Params>;
/// ML-KEM-1024 Private Key
pub type MLKEM1024PrivateKey = MLKEMSeedPrivateKey<MLKEM1024Params>;

/* Expanded keys for repeated decapsulation */

/// ML-KEM-512 Private Key with the packed 𝐭̂ kept alongside the seed, for repeated decapsulations.
pub type MLKEM512PrivateKeyExpanded = MLKEMSeedPrivateKeyExpanded<MLKEM512Params>;
/// ML-KEM-768 Private Key with the packed 𝐭̂ kept alongside the seed, for repeated decapsulations.
pub type MLKEM768PrivateKeyExpanded = MLKEMSeedPrivateKeyExpanded<MLKEM768Params>;
/// ML-KEM-1024 Private Key with the packed 𝐭̂ kept alongside the seed, for repeated decapsulations.
pub type MLKEM1024PrivateKeyExpanded = MLKEMSeedPrivateKeyExpanded<MLKEM1024Params>;

/// An ML-KEM public key.
///
/// The parameter set fixes every length, so `P` is the only type parameter. [`PublicKey`]
/// takes the encoded length as a const generic, and an associated const of a type parameter may
/// not be used as one, so its impl is generic over the length and bound through the per-length
/// trait (`P: PublicKeyLen<PK_LEN>`), which has one impl per parameter set and so lets the length
/// be inferred from `P`.
pub struct MLKEMPublicKey<P: MLKEMParams> {
    t_hat_packed: P::TPacked,
    rho: [u8; 32],
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLKEMParams> Clone for MLKEMPublicKey<P> {
    fn clone(&self) -> Self {
        Self { t_hat_packed: self.t_hat_packed, rho: self.rho }
    }
}

/// General trait for all ML-KEM public keys types.
pub trait MLKEMPublicKeyTrait<P: MLKEMParams>: Sized {
    /// Decodes an encapsulation key, FIPS 203 Algorithm 14 (K-PKE.Encrypt) lines 2-3:
    /// 𝐭̂ ← ByteDecode12(ekPKE\[0 ∶ 384𝑘]), 𝜌 ← ekPKE\[384𝑘 ∶ 384𝑘 + 32], with the Section 7.2
    /// modulus check on 𝐭̂.
    /// Input: encapsulation key ek ∈ 𝔹^(384𝑘+32).
    /// Output: 𝐭̂ ∈ (ℤ𝑞^256)^𝑘, 𝜌 ∈ 𝔹^32, or an error if a coefficient is not in \[0, 𝑞 − 1].
    fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>
    where
        P: PublicKeyLen<PK_LEN>;

    /// Get a ref to t_hat_packed byte array
    fn t_hat_packed(&self) -> &P::TPacked;

    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get the hash of the public key
    fn compute_hash(&self) -> [u8; 32];
}

pub(in crate::mlkem_lowmemory) trait MLKEMPublicKeyInternalTrait<P: MLKEMParams>:
    MLKEMPublicKeyTrait<P>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(t_hat: P::TPacked, rho: [u8; 32]) -> Self;
}

impl<P: MLKEMParams> MLKEMPublicKey<P> {
    /// FIPS 203 Algorithm 13 (K-PKE.KeyGen) line 19, ekPKE ← ByteEncode12(𝐭̂) ‖ 𝜌, into a slice
    /// of the encoded length. Shared by the array encoding and the FIPS 203 private-key encoding
    /// that embeds ek, so the length is a run-time `debug_assert` here and a type elsewhere.
    pub(in crate::mlkem_lowmemory) fn encode_into(&self, out: &mut [u8]) {
        debug_assert_eq!(self.t_hat_packed.as_ref().len(), P::T_PACKED_LEN);
        debug_assert_eq!(out.len(), P::PK_LEN);

        out[..P::T_PACKED_LEN].copy_from_slice(self.t_hat_packed.as_ref());
        debug_assert_eq!(out[P::T_PACKED_LEN..].len(), 32);
        out[P::T_PACKED_LEN..].copy_from_slice(&self.rho);
    }

    /// The inverse of [`Self::encode_into`], with the Section 7.2 modulus check; see
    /// [`MLKEMPublicKeyTrait::pk_decode`].
    pub(in crate::mlkem_lowmemory) fn decode_from(pk: &[u8]) -> Result<Self, KeyDecodingError> {
        if pk.len() != P::PK_LEN {
            return Err(KeyDecodingError("Provided key bytes are the incorrect length"));
        }
        let pk = Self::new(
            {
                let mut t = <P::TPacked as ZeroizablePrimitive>::ZEROED;
                t.as_mut().copy_from_slice(&pk[..P::T_PACKED_LEN]);
                t
            },
            pk[P::T_PACKED_LEN..].try_into().unwrap(),
        );

        // check that all entries are in range
        for i in 0..P::k {
            let p = unpack_t_hat_row(pk.t_hat_packed.as_ref(), i);
            for w in p.coeffs.iter() {
                if *w >= q {
                    return Err(KeyDecodingError("Invalid public key"));
                }
            }
        }

        Ok(pk)
    }
}

impl<P: MLKEMParams> MLKEMPublicKeyTrait<P> for MLKEMPublicKey<P> {
    fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>
    where
        P: PublicKeyLen<PK_LEN>,
    {
        Ok(Self::decode_from(pk)?)
    }

    fn t_hat_packed(&self) -> &P::TPacked {
        &self.t_hat_packed
    }

    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    fn compute_hash(&self) -> [u8; 32] {
        // The encoded public key is just t_hat and rho, so feed the elements of the public key into the hash one-by-one

        let mut out = [0u8; 32];
        let mut h = H::default();
        h.do_update(self.t_hat_packed.as_ref());
        h.do_update(&self.rho);
        let bytes_written = h.do_final_out(&mut out);
        debug_assert_eq!(bytes_written, 32);
        out
    }
}

impl<P: MLKEMParams> MLKEMPublicKeyInternalTrait<P> for MLKEMPublicKey<P> {
    fn new(t_hat_packed: P::TPacked, rho: [u8; 32]) -> Self {
        Self { rho, t_hat_packed }
    }
}

impl<P: MLKEMParams + PublicKeyLen<PK_LEN>, const PK_LEN: usize> PublicKey<PK_LEN>
    for MLKEMPublicKey<P>
{
    /// Encodes the encapsulation key, FIPS 203 Algorithm 13 (K-PKE.KeyGen) line 19:
    /// ekPKE ← ByteEncode12(𝐭̂) ‖ 𝜌.
    /// Output: ek ∈ 𝔹^(384𝑘+32).
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        self.encode_out(&mut pk);

        pk
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        self.encode_into(out);
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        if bytes.len() != PK_LEN {
            return Err(KeyDecodingError("Provided key bytes are the incorrect length"));
        }
        Self::decode_from(bytes)
    }
}

impl<P: MLKEMParams> Eq for MLKEMPublicKey<P> {}

impl<P: MLKEMParams> PartialEq for MLKEMPublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        bouncycastle_utils::ct::ct_eq_bytes(self.t_hat_packed.as_ref(), other.t_hat_packed.as_ref())
            & bouncycastle_utils::ct::ct_eq_bytes(&self.rho, &other.rho)
    }
}

impl<P: MLKEMParams> Debug for MLKEMPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = self.compute_hash();
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams> Display for MLKEMPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = self.compute_hash();
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

/// An ML-KEM private key, held as its seed.
///
/// `P` is its only type parameter, for the reason given on [`MLKEMPublicKey`]. Its own encoding
/// is the 64-byte seed for every parameter set; the FIPS 203 encoding, whose length the
/// parameter set fixes, is [`MLKEMPrivateKeyTrait::encode_full_sk`].
pub struct MLKEMSeedPrivateKey<P: MLKEMParams> {
    _phantom: core::marker::PhantomData<P>,
    rho: [u8; 32],
    sigma: Secret<[u8; 32]>,
    /// H(ek), computed once when the key is built: decapsulation (Algorithm 18, line 6) and the
    /// FIPS 203 encoding (Algorithm 16, line 3) both need it, and deriving it means a key
    /// generation's worth of work.
    pk_hash: [u8; 32],
    z: Secret<[u8; 32]>,
    seed_d: Secret<[u8; 32]>,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams> Clone for MLKEMSeedPrivateKey<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: core::marker::PhantomData,
            rho: self.rho,
            sigma: self.sigma.clone(),
            pk_hash: self.pk_hash,
            z: self.z.clone(),
            seed_d: self.seed_d.clone(),
        }
    }
}

impl<P: MLKEMParams> MLKEMSeedPrivateKey<P> {
    /// The all-zero key: the key [`MLKEMTrait::keygen_out`](crate::mlkem_lowmemory::MLKEMTrait::keygen_out) and
    /// [`MLKEMTrait::keygen_from_seed_out`](crate::mlkem_lowmemory::MLKEMTrait::keygen_from_seed_out) write into, so that the seeds are written where they
    /// will live and never moved. It is not a generated key: until one of them fills it,
    /// decapsulation with it and its [`pk()`](MLKEMPrivateKeyTrait::pk) are refused
    /// ([`KeyMaterialError::ActingOnZeroizedKey`]), and its seed and encodings are all zero.
    pub fn zeroized() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
            rho: [0u8; 32],
            sigma: Secret::new(),
            pk_hash: [0u8; 32],
            z: Secret::new(),
            seed_d: Secret::new(),
        }
    }

    /// Whether the key holds a key. H(ek) says so: it is a SHA3-256 hash, and all zero in the
    /// state [`zeroized`](Self::zeroized) makes and the `_out` generators leave on an error.
    fn is_filled(&self) -> bool {
        self.pk_hash != [0u8; 32]
    }

    /// Back to the all-zero key, the secret fields wiped.
    pub(in crate::mlkem_lowmemory) fn clear(&mut self) {
        self.rho = [0u8; 32];
        self.sigma.zeroize();
        self.pk_hash = [0u8; 32];
        self.z.zeroize();
        self.seed_d.zeroize();
    }

    /// The public key, derived from 𝜌 and 𝜎 (Algorithm 13) whether or not the key is filled.
    fn derive_pk(&self) -> MLKEMPublicKey<P> {
        MLKEMPublicKey::<P>::new(self.t_hat_packed(), self.rho)
    }

    /// FIPS 203 Algorithm 16 (ML-KEM.KeyGen_internal) from `seed` into this key, cleared first
    /// and left so on an error; see [`MLKEMTrait::keygen_from_seed_out`](crate::mlkem_lowmemory::MLKEMTrait::keygen_from_seed_out).
    pub(in crate::mlkem_lowmemory) fn fill_out(
        &mut self,
        seed: &KeyMaterial<64>,
    ) -> Result<(), KEMError> {
        self.fill(seed).map(|_pk| ())
    }

    /// Create a new MLKEMSeedPrivateKey from a 64-byte KeyMaterial.
    /// Seed SecurityStrength must match algorithm security strength: 128-bit (ML-KEM-512), 192-bit (ML-KEM-768), or 256-bit (ML-KEM-1024).
    ///
    /// Costs a key generation: the public key is derived once to store its hash.
    pub fn new(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        Ok(Self::new_with_pk(seed)?.0)
    }

    /// As [`Self::new`], also returning the public key the construction derived, so that key
    /// generation does not run Algorithm 13 a second time for it.
    pub(in crate::mlkem_lowmemory) fn new_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P>), KEMError> {
        let mut sk = Self::zeroized();
        let pk = sk.fill(seed)?;
        Ok((sk, pk))
    }

    /// The key of `seed`, into this one, cleared first and left so on an error: its fields are
    /// written where they live, straight out of the seed's `Secret`. Returns the public key,
    /// which it derives for H(ek).
    fn fill(&mut self, seed: &KeyMaterial<64>) -> Result<MLKEMPublicKey<P>, KEMError> {
        self.clear();
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 64
        {
            return Err(KEMError::KeyGenError(
                "Seed must be 64 bytes and KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }

        if seed.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(KEMError::KeyGenError(
                "Seed security strength is below the parameter set's: 128-bit for ML-KEM-512, 192-bit for ML-KEM-768, 256-bit for ML-KEM-1024.",
            ));
        }

        self.seed_d.copy_from_slice(&seed.ref_to_bytes()[..32]);
        self.z.copy_from_slice(&seed.ref_to_bytes()[32..]);
        self.compute_rho_and_sigma();
        let pk = self.derive_pk();
        self.pk_hash = pk.compute_hash();

        Ok(pk)
    }
    /// Algorithm 16 line 3, dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧), given the public key, which the seed key
    /// derives and the expanded key holds.
    fn full_sk_out<const FULL_SK_LEN: usize>(
        &self,
        pk: &MLKEMPublicKey<P>,
        out: &mut [u8; FULL_SK_LEN],
    ) -> usize {
        out.fill(0);
        debug_assert_eq!(FULL_SK_LEN, P::FULL_SK_LEN);

        let mut pos = 0usize;

        /* dk_pke */
        // Alg 13; line 20: dkPKE ← ByteEncode12(𝐬)
        for i in 0..P::k {
            let mut s_hat_i = Secret::<Polynomial>::new();
            self.compute_s_hat_row_out(i, &mut s_hat_i);
            pack_s_hat_row::<P>(&s_hat_i, i, out);
        }
        pos += P::k * POLY_BYTES;

        /* ek */
        // Alg 13; line 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
        pk.encode_into(&mut out[pos..pos + P::PK_LEN]);
        pos += P::PK_LEN;

        /* H(ek) */
        out[pos..pos + 32].copy_from_slice(&self.pk_hash);
        pos += 32;

        /* z */
        out[pos..pos + 32].copy_from_slice(&*self.z);

        FULL_SK_LEN
    }

    /// Algorithm 13 K-PKE.KeyGen(𝑑)
    /// 1: (𝜌, 𝜎) ← G(𝑑‖𝑘)
    ///  ▷ expand 32+1 bytes to two pseudorandom 32-byte seeds1
    /// rho: public seed
    /// sigma: noise seed
    ///
    /// From the key's 𝑑 into its 𝜌 and 𝜎.
    fn compute_rho_and_sigma(&mut self) {
        // Only the second half of the output is secret, but we'll wrap the whole thing
        // so that the local copy gets zeriozed on drop.
        let mut buf: Secret<[u8; 64]> = Secret::new();

        let mut g = G::new();
        g.do_update(&*self.seed_d);
        g.do_update(&[P::k as u8]);
        // In place, not by the consuming final: a move would leave the secret input unwiped.
        let bytes_written = g.finish_into(&finish_token(), buf.as_mut());
        debug_assert_eq!(bytes_written, 64);

        self.rho.copy_from_slice(&buf[..32]);
        self.sigma.copy_from_slice(&buf[32..64]);
    }
}

/// General trait for all ML-KEM private keys types.
pub trait MLKEMPrivateKeyTrait<P: MLKEMParams>: Sized {
    /// New from KeyMaterial. Can throw a KEMError if the KeyMaterial does not contain sufficient entropy.
    fn from_keymaterial(seed: &KeyMaterial<64>) -> Result<Self, KEMError>;
    /// The seed (𝑑 ‖ 𝑧) this key was built from, typed as a seed at the parameter set's strength;
    /// for a key that was never filled, an empty [`KeyMaterial`].
    fn seed(&self) -> KeyMaterial<64>;
    /// Runs essentially a full keygen according to Algorithm 13.
    ///
    /// # Errors
    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a private key that was never filled
    /// ([`MLKEMSeedPrivateKey::zeroized`], or a key generation into it that failed).
    // Dev note: This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn pk(&self) -> Result<MLKEMPublicKey<P>, KEMError>;
    /// H(ek), stored when the key was built.
    fn pk_hash(&self) -> &[u8; 32];
    /// This produces the full private key in the encoding specified in FIPS 203 so that it is
    /// compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [`MLKEMSeedPrivateKey`].
    ///
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn encode_full_sk<const FULL_SK_LEN: usize>(&self) -> [u8; FULL_SK_LEN]
    where
        P: PrivateKeyLen<FULL_SK_LEN>;
    /// As [`encode_full_sk`](Self::encode_full_sk), into `out`, which is zeroized first; returns
    /// the number of bytes written, always `FULL_SK_LEN`.
    fn encode_full_sk_out<const FULL_SK_LEN: usize>(&self, out: &mut [u8; FULL_SK_LEN]) -> usize
    where
        P: PrivateKeyLen<FULL_SK_LEN>;
    /// Decode the private key from its 64-byte seed encoding.
    fn sk_decode(sk: &[u8; MLKEM_SEED_LEN]) -> Self;
}

pub(in crate::mlkem_lowmemory) trait MLKEMPrivateKeyInternalTrait<P: MLKEMParams>:
    MLKEMPrivateKeyTrait<P>
{
    /// As `MLKEMPrivateKeyTrait::from_keymaterial`, also returning the public key the
    /// construction derived.
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P>), KEMError>;

    fn z(&self) -> &[u8; 32];

    /// [`KeyMaterialError::ActingOnZeroizedKey`] unless the key has been generated or decoded.
    fn check_filled(&self) -> Result<(), KEMError>;

    /// Row `idx` of 𝐬̂, into `s_hat_i`, which the caller holds: it is secret.
    fn compute_s_hat_row_out(&self, idx: usize, s_hat_i: &mut Polynomial);

    fn rho(&self) -> &[u8; 32];

    /// Note: this one is not a ref because the data does not exist in the private key.
    fn t_hat_packed(&self) -> P::TPacked;
}

impl<P: MLKEMParams> MLKEMPrivateKeyTrait<P> for MLKEMSeedPrivateKey<P> {
    fn from_keymaterial(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        Self::new(seed)
    }
    fn seed(&self) -> KeyMaterial<64> {
        if !self.is_filled() {
            return KeyMaterial::new();
        }
        let mut tmp = Secret::<[u8; 64]>::new();
        tmp[..32].as_mut().copy_from_slice(&*self.seed_d);
        tmp[32..].as_mut().copy_from_slice(&*self.z);

        // `from_bytes` types all-zero input as Zeroized, and `set_security_strength` refuses a
        // strength on a Zeroized key, so the type is set first, inside the hazardous block, where
        // `set_key_type` is unconditional: that is what `from_bytes` on this type does, and it is
        // how an all-zero seed loaded through it reads back out. After that the strength call can
        // only fail on a key shorter than the strength needs, and this one is 64 bytes.
        let mut seed =
            KeyMaterial::<64>::from_bytes(&*tmp).expect("64 bytes fit a KeyMaterial<64>");
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed)?;
            seed.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })
        .expect("a 64-byte Seed accepts every ML-KEM security strength");

        seed
    }
    fn pk(&self) -> Result<MLKEMPublicKey<P>, KEMError> {
        self.check_filled()?;
        Ok(self.derive_pk())
    }
    fn pk_hash(&self) -> &[u8; 32] {
        &self.pk_hash
    }
    fn encode_full_sk<const FULL_SK_LEN: usize>(&self) -> [u8; FULL_SK_LEN]
    where
        P: PrivateKeyLen<FULL_SK_LEN>,
    {
        let mut out = [0u8; FULL_SK_LEN];
        self.encode_full_sk_out(&mut out);

        out
    }
    fn encode_full_sk_out<const FULL_SK_LEN: usize>(&self, out: &mut [u8; FULL_SK_LEN]) -> usize
    where
        P: PrivateKeyLen<FULL_SK_LEN>,
    {
        // A key that was never filled encodes as zeros, not as the key of an all-zero seed.
        if !self.is_filled() {
            out.fill(0);
            return FULL_SK_LEN;
        }
        self.full_sk_out(&self.derive_pk(), out)
    }
    fn sk_decode(sk: &[u8; MLKEM_SEED_LEN]) -> Self {
        // `from_bytes` fails only on a length other than 64, and the array is 64 bytes.
        Self::from_bytes(sk).unwrap()
    }
}

impl<P: MLKEMParams> MLKEMPrivateKeyInternalTrait<P> for MLKEMSeedPrivateKey<P> {
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P>), KEMError> {
        Self::new_with_pk(seed)
    }

    fn z(&self) -> &[u8; 32] {
        &self.z
    }

    fn check_filled(&self) -> Result<(), KEMError> {
        if self.is_filled() { Ok(()) } else { Err(KeyMaterialError::ActingOnZeroizedKey.into()) }
    }

    fn compute_s_hat_row_out(&self, idx: usize, s_hat_i: &mut Polynomial) {
        debug_assert!(idx < P::k);

        // We're doing just one row of this:
        // 8: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //  ▷ generate 𝐬 ∈ (ℤ256)^P::k
        // 9: 𝐬[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
        //   ▷ 𝐬[𝑖] ∈ ℤ256 sampled from CBD
        // 10: 𝑁 ← 𝑁 + 1
        // Note: here n = 0
        sample_poly_CBD_out(&self.sigma, idx as u8, P::eta1, s_hat_i);

        // 16: 𝐬_hat ← NTT(𝐬)̂
        s_hat_i.ntt();
    }

    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }
    /// Runs essentially a full keygen according to Algorithm 13
    /// Outputs t_hat in the packed encoding specified in FIPS 203
    fn t_hat_packed(&self) -> P::TPacked {
        let mut t_hat_packed = <P::TPacked as ZeroizablePrimitive>::ZEROED;

        // A row is 𝐭̂ only once 𝐞̂ is added: until then it is 𝐀̂ ∘ 𝐬̂, from which 𝐞̂ = 𝐭̂ − 𝐀̂ ∘ 𝐬̂
        // follows, so it is held in a `Secret`, as 𝐞 is.
        let mut t_hat_i = Secret::<Polynomial>::new();
        for i in 0..P::k {
            // first half of
            // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
            compute_A_hat_dot_s_hat_out::<P>(&self.rho, &self.sigma, i, &mut t_hat_i);

            // second half of
            // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
            {
                // 12: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
                //  ▷ generate 𝐞 ∈ (ℤ256)^P::k
                // 13: 𝐞[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁))
                //   ▷ 𝐞[𝑖] ∈ ℤ256 sampled from CBD
                // 14: 𝑁 ← 𝑁 + 1
                // Note: here n = P::k
                let mut e_i = Secret::<Polynomial>::new();
                sample_poly_CBD_out(&self.sigma, (P::k + i) as u8, P::eta1, &mut e_i);

                e_i.ntt(); // technically now e_hat_i
                t_hat_i.add(&e_i);
            }
            t_hat_i.poly_reduce();

            pack_t_hat_row::<P>(&t_hat_i, i, &mut t_hat_packed);
        }

        t_hat_packed
    }
}

impl<P: MLKEMParams> PrivateKey<MLKEM_SEED_LEN> for MLKEMSeedPrivateKey<P> {
    /// Encode the private key as a 64-byte seed (d || z)
    fn encode(&self) -> [u8; MLKEM_SEED_LEN] {
        let mut sk = [0u8; MLKEM_SEED_LEN];
        self.encode_out(&mut sk);

        sk
    }

    fn encode_out(&self, out: &mut [u8; MLKEM_SEED_LEN]) -> usize {
        out.fill(0);

        out[..32].copy_from_slice(&*self.seed_d);
        out[32..].copy_from_slice(&*self.z);

        MLKEM_SEED_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        if bytes.len() != MLKEM_SEED_LEN {
            return Err(KeyDecodingError("Invalid seed length"));
        }
        let mut keymat = KeyMaterial::<64>::from_bytes(bytes)
            .map_err(|_| KeyDecodingError("Invalid ML-KEM seed private key"))?;
        do_hazardous_operations(&mut keymat, |keymat| {
            keymat.set_key_type(KeyType::Seed)?;
            keymat.set_security_strength(SecurityStrength::_256bit)
        })
        .map_err(|_| KeyDecodingError("Invalid ML-KEM seed private key"))?;

        Self::new(&keymat).map_err(|_| KeyDecodingError("Invalid ML-KEM seed private key"))
    }
}

impl<P: MLKEMParams> Eq for MLKEMSeedPrivateKey<P> {}

impl<P: MLKEMParams> PartialEq for MLKEMSeedPrivateKey<P> {
    fn eq(&self, other: &Self) -> bool {
        // The encodings are the seed: held in `Secret` buffers for the comparison.
        let mut self_encoded = Secret::<[u8; MLKEM_SEED_LEN]>::new();
        let mut other_encoded = Secret::<[u8; MLKEM_SEED_LEN]>::new();
        self.encode_out(&mut self_encoded);
        other.encode_out(&mut other_encoded);
        bouncycastle_utils::ct::ct_eq_bytes(&*self_encoded, &*other_encoded)
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams> fmt::Debug for MLKEMSeedPrivateKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMSeedPrivateKey {{ alg: {}, pub_key_hash: {:x?} }}",
            P::ALG_NAME,
            self.pk_hash
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams> Display for MLKEMSeedPrivateKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMSeedPrivateKey {{ alg: {}, pub_key_hash: {:x?} }}",
            P::ALG_NAME,
            self.pk_hash
        )
    }
}

/// A seed private key with the packed 𝐭̂ kept alongside it, for repeated decapsulations with one key.
///
/// Decapsulation re-encrypts (FIPS 203 Algorithm 18, line 8), which needs 𝐭̂; a
/// [`MLKEMSeedPrivateKey`] derives it each time, a key generation's worth of work, and this type
/// derives it once, when built. It costs 384𝑘 more bytes in memory (768, 1152, 1536) and nothing on
/// disk: its encoding is the same 64-byte seed. It implements the same traits as
/// [`MLKEMSeedPrivateKey`], so it is used the same way.
pub struct MLKEMSeedPrivateKeyExpanded<P: MLKEMParams> {
    dk: MLKEMSeedPrivateKey<P>,
    t_hat_packed: P::TPacked,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams> Clone for MLKEMSeedPrivateKeyExpanded<P> {
    fn clone(&self) -> Self {
        Self { dk: self.dk.clone(), t_hat_packed: self.t_hat_packed }
    }
}

impl<P: MLKEMParams> From<&MLKEMSeedPrivateKey<P>> for MLKEMSeedPrivateKeyExpanded<P> {
    /// Derives 𝐭̂ from the seed key (Algorithm 13) and keeps it alongside a copy of the key.
    fn from(dk: &MLKEMSeedPrivateKey<P>) -> Self {
        Self { dk: dk.clone(), t_hat_packed: dk.t_hat_packed() }
    }
}

impl<P: MLKEMParams> MLKEMPrivateKeyTrait<P> for MLKEMSeedPrivateKeyExpanded<P> {
    fn from_keymaterial(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        Ok(Self::from_keymaterial_with_pk(seed)?.0)
    }
    fn seed(&self) -> KeyMaterial<64> {
        self.dk.seed()
    }
    fn pk(&self) -> Result<MLKEMPublicKey<P>, KEMError> {
        self.dk.check_filled()?;
        Ok(MLKEMPublicKey::<P>::new(self.t_hat_packed, self.dk.rho))
    }
    fn pk_hash(&self) -> &[u8; 32] {
        self.dk.pk_hash()
    }
    fn encode_full_sk<const FULL_SK_LEN: usize>(&self) -> [u8; FULL_SK_LEN]
    where
        P: PrivateKeyLen<FULL_SK_LEN>,
    {
        let mut out = [0u8; FULL_SK_LEN];
        self.encode_full_sk_out(&mut out);

        out
    }
    fn encode_full_sk_out<const FULL_SK_LEN: usize>(&self, out: &mut [u8; FULL_SK_LEN]) -> usize
    where
        P: PrivateKeyLen<FULL_SK_LEN>,
    {
        if !self.dk.is_filled() {
            out.fill(0);
            return FULL_SK_LEN;
        }
        self.dk.full_sk_out(&MLKEMPublicKey::<P>::new(self.t_hat_packed, self.dk.rho), out)
    }
    fn sk_decode(sk: &[u8; MLKEM_SEED_LEN]) -> Self {
        Self::from(&MLKEMSeedPrivateKey::sk_decode(sk))
    }
}

impl<P: MLKEMParams> MLKEMPrivateKeyInternalTrait<P> for MLKEMSeedPrivateKeyExpanded<P> {
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P>), KEMError> {
        // The construction derives t-hat for H(ek); keep it rather than derive it again.
        let (dk, pk) = MLKEMSeedPrivateKey::new_with_pk(seed)?;
        let t_hat_packed = *pk.t_hat_packed();
        Ok((Self { dk, t_hat_packed }, pk))
    }

    fn z(&self) -> &[u8; 32] {
        self.dk.z()
    }

    fn check_filled(&self) -> Result<(), KEMError> {
        self.dk.check_filled()
    }

    fn compute_s_hat_row_out(&self, idx: usize, s_hat_i: &mut Polynomial) {
        self.dk.compute_s_hat_row_out(idx, s_hat_i)
    }

    fn rho(&self) -> &[u8; 32] {
        self.dk.rho()
    }

    /// The stored 𝐭̂, a copy.
    fn t_hat_packed(&self) -> P::TPacked {
        self.t_hat_packed
    }
}

impl<P: MLKEMParams> PrivateKey<MLKEM_SEED_LEN> for MLKEMSeedPrivateKeyExpanded<P> {
    /// The 64-byte seed (d || z), as for the seed key: 𝐭̂ is derived again on load.
    fn encode(&self) -> [u8; MLKEM_SEED_LEN] {
        self.dk.encode()
    }

    fn encode_out(&self, out: &mut [u8; MLKEM_SEED_LEN]) -> usize {
        self.dk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        Ok(Self::from(&MLKEMSeedPrivateKey::from_bytes(bytes)?))
    }
}

impl<P: MLKEMParams> Eq for MLKEMSeedPrivateKeyExpanded<P> {}

impl<P: MLKEMParams> PartialEq for MLKEMSeedPrivateKeyExpanded<P> {
    /// Two keys are equal when their seeds are; 𝐭̂ is a function of the seed.
    fn eq(&self, other: &Self) -> bool {
        self.dk == other.dk
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams> fmt::Debug for MLKEMSeedPrivateKeyExpanded<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMSeedPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}",
            P::ALG_NAME,
            self.dk.pk_hash
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams> Display for MLKEMSeedPrivateKeyExpanded<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMSeedPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}",
            P::ALG_NAME,
            self.dk.pk_hash
        )
    }
}
