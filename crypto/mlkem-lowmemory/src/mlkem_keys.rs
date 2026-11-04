use crate::low_memory_helpers::{
    compute_A_hat_dot_s_hat, pack_s_hat_row, pack_t_hat_row, unpack_t_hat_row,
};
use crate::mlkem::{G, H, MLKEM_SEED_LEN, POLY_BYTES, q};
use crate::mlkem::{MLKEM512_FULL_SK_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN};
use crate::mlkem::{MLKEM768_FULL_SK_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN};
use crate::mlkem::{MLKEM1024_FULL_SK_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};
use crate::params::{MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Hash, HashOneShot, KEMPrivateKey, KEMPublicKey};
use bouncycastle_mlkem_common::aux_functions::sample_poly_CBD;
use bouncycastle_mlkem_common::polynomial::Polynomial;
use bouncycastle_sha3::SHA3_256;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
// imports just for docs

/* Pub Types */

/// ML-KEM-512 Public Key
pub type MLKEM512PublicKey = MLKEMPublicKey<MLKEM512Params, MLKEM512_PK_LEN>;
/// ML-KEM-512 Private Key
pub type MLKEM512PrivateKey =
    MLKEMSeedPrivateKey<MLKEM512Params, MLKEM512_SK_LEN, MLKEM512_FULL_SK_LEN, MLKEM512_PK_LEN>;
/// ML-KEM-768 Public Key
pub type MLKEM768PublicKey = MLKEMPublicKey<MLKEM768Params, MLKEM768_PK_LEN>;
/// ML-KEM-768 Private Key
pub type MLKEM768PrivateKey =
    MLKEMSeedPrivateKey<MLKEM768Params, MLKEM768_SK_LEN, MLKEM768_FULL_SK_LEN, MLKEM768_PK_LEN>;
/// ML-KEM-1024 Public Key
pub type MLKEM1024PublicKey = MLKEMPublicKey<MLKEM1024Params, MLKEM1024_PK_LEN>;
/// ML-KEM-1024 Private Key
pub type MLKEM1024PrivateKey =
    MLKEMSeedPrivateKey<MLKEM1024Params, MLKEM1024_SK_LEN, MLKEM1024_FULL_SK_LEN, MLKEM1024_PK_LEN>;

/* Expanded keys for repeated decapsulation */

/// ML-KEM-512 Private Key with the packed 𝐭̂ kept alongside the seed, for repeated decapsulations.
pub type MLKEM512PrivateKeyExpanded = MLKEMSeedPrivateKeyExpanded<
    MLKEM512Params,
    MLKEM512_SK_LEN,
    MLKEM512_FULL_SK_LEN,
    MLKEM512_PK_LEN,
>;
/// ML-KEM-768 Private Key with the packed 𝐭̂ kept alongside the seed, for repeated decapsulations.
pub type MLKEM768PrivateKeyExpanded = MLKEMSeedPrivateKeyExpanded<
    MLKEM768Params,
    MLKEM768_SK_LEN,
    MLKEM768_FULL_SK_LEN,
    MLKEM768_PK_LEN,
>;
/// ML-KEM-1024 Private Key with the packed 𝐭̂ kept alongside the seed, for repeated decapsulations.
pub type MLKEM1024PrivateKeyExpanded = MLKEMSeedPrivateKeyExpanded<
    MLKEM1024Params,
    MLKEM1024_SK_LEN,
    MLKEM1024_FULL_SK_LEN,
    MLKEM1024_PK_LEN,
>;

/// An ML-KEM public key.
pub struct MLKEMPublicKey<P: MLKEMParams, const PK_LEN: usize> {
    pub(crate) t_hat_packed: P::TPacked,
    pub(crate) rho: [u8; 32],
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLKEMParams, const PK_LEN: usize> Clone for MLKEMPublicKey<P, PK_LEN> {
    fn clone(&self) -> Self {
        Self { t_hat_packed: self.t_hat_packed, rho: self.rho }
    }
}

/// General trait for all ML-KEM public keys types.
pub trait MLKEMPublicKeyTrait<P: MLKEMParams, const PK_LEN: usize>: KEMPublicKey<PK_LEN> {
    /// Decodes an encapsulation key, FIPS 203 Algorithm 14 (K-PKE.Encrypt) lines 2-3:
    /// 𝐭̂ ← ByteDecode12(ekPKE\[0 ∶ 384𝑘]), 𝜌 ← ekPKE\[384𝑘 ∶ 384𝑘 + 32], with the Section 7.2
    /// modulus check on 𝐭̂.
    /// Input: encapsulation key ek ∈ 𝔹^(384𝑘+32).
    /// Output: 𝐭̂ ∈ (ℤ𝑞^256)^𝑘, 𝜌 ∈ 𝔹^32, or an error if a coefficient is not in \[0, 𝑞 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>;

    /// Get a ref to t_hat_packed byte array
    fn t_hat_packed(&self) -> &P::TPacked;

    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get the hash of the public key
    fn compute_hash(&self) -> [u8; 32];
}

pub(crate) trait MLKEMPublicKeyInternalTrait<P: MLKEMParams, const PK_LEN: usize>:
    MLKEMPublicKeyTrait<P, PK_LEN>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(t_hat: P::TPacked, rho: [u8; 32]) -> Self;
}

impl<P: MLKEMParams, const PK_LEN: usize> MLKEMPublicKeyTrait<P, PK_LEN>
    for MLKEMPublicKey<P, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError> {
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
                    return Err(KEMError::DecodingError("Invalid public key"));
                }
            }
        }

        Ok(pk)
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

impl<P: MLKEMParams, const PK_LEN: usize> MLKEMPublicKeyInternalTrait<P, PK_LEN>
    for MLKEMPublicKey<P, PK_LEN>
{
    fn new(t_hat_packed: P::TPacked, rho: [u8; 32]) -> Self {
        Self { rho, t_hat_packed }
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> KEMPublicKey<PK_LEN> for MLKEMPublicKey<P, PK_LEN> {
    /// Encodes the encapsulation key, FIPS 203 Algorithm 13 (K-PKE.KeyGen) line 19:
    /// ekPKE ← ByteEncode12(𝐭̂) ‖ 𝜌.
    /// Output: ek ∈ 𝔹^(384𝑘+32).
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        self.encode_out(&mut pk);

        pk
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        // Check length
        debug_assert_eq!(self.t_hat_packed.as_ref().len(), P::T_PACKED_LEN);

        out.fill(0);

        out[..P::T_PACKED_LEN].copy_from_slice(self.t_hat_packed.as_ref());
        debug_assert_eq!(out[P::T_PACKED_LEN..].len(), 32);
        out[P::T_PACKED_LEN..].copy_from_slice(&self.rho);

        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        if bytes.len() != PK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }
        let bytes_sized: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Self::pk_decode(&bytes_sized)
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> Eq for MLKEMPublicKey<P, PK_LEN> {}

impl<P: MLKEMParams, const PK_LEN: usize> PartialEq for MLKEMPublicKey<P, PK_LEN> {
    fn eq(&self, other: &Self) -> bool {
        bouncycastle_utils::ct::ct_eq_bytes(&self.encode(), &other.encode())
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> Debug for MLKEMPublicKey<P, PK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = SHA3_256::hash(&self.encode());
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> Display for MLKEMPublicKey<P, PK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = SHA3_256::hash(&self.encode());
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

/// An ML-KEM private key.
pub struct MLKEMSeedPrivateKey<
    P: MLKEMParams,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const PK_LEN: usize,
> {
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
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Clone
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
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

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    /// Create a new MLKEMSeedPrivateKey from a 64-byte KeyMaterial.
    /// Seed SecurityStrength must match algorithm security strength: 128-bit (ML-KEM-512), 192-bit (ML-KEM-768), or 256-bit (ML-KEM-1024).
    ///
    /// Costs a key generation: the public key is derived once to store its hash.
    pub fn new(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        Ok(Self::new_with_pk(seed)?.0)
    }

    /// As [`Self::new`], also returning the public key the construction derived, so that key
    /// generation does not run Algorithm 13 a second time for it.
    pub(crate) fn new_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P, PK_LEN>), KEMError> {
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

        // These are Secret-safe because we're using .copy_from_slice directly out of one Secret<[u8]>
        // into another and the contents are never touching a non-Secret buffer.
        let mut seed_d = Secret::<[u8; 32]>::new();
        seed_d.as_mut().copy_from_slice(seed.ref_to_bytes()[..32].try_into().unwrap());
        let mut z = Secret::<[u8; 32]>::new();
        z.as_mut().copy_from_slice(seed.ref_to_bytes()[32..].try_into().unwrap());

        let (rho, sigma) = Self::compute_rho_and_sigma(&seed_d);

        let mut sk =
            Self { _phantom: core::marker::PhantomData, rho, sigma, pk_hash: [0u8; 32], z, seed_d };
        let pk = sk.pk();
        sk.pk_hash = pk.compute_hash();

        Ok((sk, pk))
    }
    /// Algorithm 16 line 3, dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧), given the public key, which the seed key
    /// derives and the expanded key holds.
    fn full_sk_out(&self, pk: &MLKEMPublicKey<P, PK_LEN>, out: &mut [u8; FULL_SK_LEN]) -> usize {
        out.fill(0);

        let mut pos = 0usize;

        /* dk_pke */
        // Alg 13; line 20: dkPKE ← ByteEncode12(𝐬)
        for i in 0..P::k {
            pack_s_hat_row::<P>(&self.compute_s_hat_row(i), i, out);
        }
        pos += P::k * POLY_BYTES;

        /* ek */
        // Alg 13; line 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
        out[pos..pos + PK_LEN].copy_from_slice(&pk.encode());
        pos += PK_LEN;

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
    fn compute_rho_and_sigma(seed_d: &[u8; 32]) -> ([u8; 32], Secret<[u8; 32]>) {
        // Only the second half of the output is secret, but we'll wrap the whole thing
        // so that the local copy gets zeriozed on drop.
        let mut buf: Secret<[u8; 64]> = Secret::new();

        let mut g = G::new();
        g.do_update(seed_d);
        g.do_update(&[P::k as u8]);
        let bytes_written = g.do_final_out(buf.as_mut());
        debug_assert_eq!(bytes_written, 64);

        let mut sigma = Secret::<[u8; 32]>::new();
        sigma.as_mut().copy_from_slice(buf[32..64].try_into().unwrap());

        (buf[..32].try_into().unwrap(), sigma)
    }
}

/// General trait for all ML-KEM private keys types.
pub trait MLKEMPrivateKeyTrait<
    P: MLKEMParams,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const PK_LEN: usize,
>: KEMPrivateKey<SK_LEN>
{
    /// New from KeyMaterial. Can throw a KEMError if the KeyMaterial does not contain sufficient entropy.
    fn from_keymaterial(seed: &KeyMaterial<64>) -> Result<Self, KEMError>;
    /// The seed (𝑑 ‖ 𝑧) this key was built from, typed as a seed at the parameter set's strength.
    /// A key of this crate always has one.
    fn seed(&self) -> KeyMaterial<64>;
    /// Runs essentially a full keygen according to Algorithm 13.
    // Dev note: This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn pk(&self) -> MLKEMPublicKey<P, PK_LEN>;
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
    fn encode_full_sk(&self) -> [u8; FULL_SK_LEN];
    /// This produces the full private key in the encoding specified in FIPS 203 so that it is
    /// compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [`MLKEMSeedPrivateKey`].
    ///
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn encode_full_sk_out(&self, out: &mut [u8; FULL_SK_LEN]) -> usize;
    /// Decode the private key.
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self;
}

pub(crate) trait MLKEMPrivateKeyInternalTrait<
    P: MLKEMParams,
    const SK_LEN: usize,
    const PK_LEN: usize,
>
{
    /// As `MLKEMPrivateKeyTrait::from_keymaterial`, also returning the public key the
    /// construction derived.
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P, PK_LEN>), KEMError>
    where
        Self: Sized;

    fn z(&self) -> &[u8; 32];

    fn compute_s_hat_row(&self, idx: usize) -> Polynomial;

    fn rho(&self) -> &[u8; 32];

    /// Note: this one is not a ref because the data does not exist in the private key.
    fn t_hat_packed(&self) -> P::TPacked;
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn from_keymaterial(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        Self::new(seed)
    }
    fn seed(&self) -> KeyMaterial<64> {
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
    fn pk(&self) -> MLKEMPublicKey<P, PK_LEN> {
        MLKEMPublicKey::<P, PK_LEN>::new(self.t_hat_packed(), self.rho)
    }
    fn pk_hash(&self) -> &[u8; 32] {
        &self.pk_hash
    }
    /// This produces the full private key in the encoding specified in FIPS 203 so that it is
    /// compatible with other implementations.
    ///
    /// Note that since this encoding does not include the seed, this is a one-way operation;
    /// after exporting in this encoding, it will be impossible to re-import it into a [`MLKEMSeedPrivateKey`].
    ///
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn encode_full_sk(&self) -> [u8; FULL_SK_LEN] {
        let mut out = [0u8; FULL_SK_LEN];
        self.encode_full_sk_out(&mut out);

        out
    }
    /// This produces the full private key in the encoding specified in the FIPS so that it is
    /// compatible with other implementations.
    /// Note that this encoding does not include the seed, so if exporting in this encoding, it will
    /// be impossible to re-import it into this implementation.
    ///
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn encode_full_sk_out(&self, out: &mut [u8; FULL_SK_LEN]) -> usize {
        self.full_sk_out(&self.pk(), out)
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
        // `from_bytes` fails only on a length other than 64, and SK_LEN is the 64-byte seed.
        debug_assert_eq!(SK_LEN, MLKEM_SEED_LEN);
        Self::from_bytes(sk).unwrap()
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P, PK_LEN>), KEMError> {
        Self::new_with_pk(seed)
    }

    fn z(&self) -> &[u8; 32] {
        &self.z
    }

    fn compute_s_hat_row(&self, idx: usize) -> Polynomial {
        debug_assert!(idx < P::k);

        // We're doing just one row of this:
        // 8: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //  ▷ generate 𝐬 ∈ (ℤ256)^P::k
        // 9: 𝐬[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
        //   ▷ 𝐬[𝑖] ∈ ℤ256 sampled from CBD
        // 10: 𝑁 ← 𝑁 + 1
        // Note: here n = 0
        let mut s_i = sample_poly_CBD(&self.sigma, idx as u8, P::eta1);

        // 16: 𝐬_hat ← NTT(𝐬)̂
        s_i.ntt();
        s_i
    }

    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }
    /// Runs essentially a full keygen according to Algorithm 13
    /// Outputs t_hat in the packed encoding specified in FIPS 203
    fn t_hat_packed(&self) -> P::TPacked {
        let mut t_hat_packed = <P::TPacked as ZeroizablePrimitive>::ZEROED;

        for i in 0..P::k {
            // first half of
            // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
            let mut t_hat_i = compute_A_hat_dot_s_hat::<P>(&self.rho, &self.sigma, i);

            // second half of
            // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
            {
                // 12: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
                //  ▷ generate 𝐞 ∈ (ℤ256)^P::k
                // 13: 𝐞[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁))
                //   ▷ 𝐞[𝑖] ∈ ℤ256 sampled from CBD
                // 14: 𝑁 ← 𝑁 + 1
                // Note: here n = P::k
                let mut e_i = sample_poly_CBD(&self.sigma, (P::k + i) as u8, P::eta1);

                e_i.ntt(); // technically now e_hat_i
                t_hat_i.add(&e_i);
            }
            t_hat_i.poly_reduce();

            pack_t_hat_row::<P>(&t_hat_i, i, &mut t_hat_packed);
        }

        t_hat_packed
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    KEMPrivateKey<SK_LEN> for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    /// Encode the private key as a 64-byte seed (d || z)
    fn encode(&self) -> [u8; SK_LEN] {
        let mut sk = [0u8; SK_LEN];
        self.encode_out(&mut sk);

        sk
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        out[..32].copy_from_slice(&*self.seed_d);
        out[32..].copy_from_slice(&*self.z);

        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        if bytes.len() != 64 {
            return Err(KEMError::DecodingError("Invalid seed length"));
        }
        let mut keymat = KeyMaterial::<64>::from_bytes(bytes)?;
        do_hazardous_operations(&mut keymat, |keymat| {
            keymat.set_key_type(KeyType::Seed)?;
            keymat.set_security_strength(SecurityStrength::_256bit)
        })?;

        Self::new(&keymat)
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Eq
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> PartialEq
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        // The encodings are the seed: held in `Secret` buffers for the comparison.
        let mut self_encoded = Secret::<[u8; SK_LEN]>::new();
        let mut other_encoded = Secret::<[u8; SK_LEN]>::new();
        self.encode_out(&mut self_encoded);
        other.encode_out(&mut other_encoded);
        bouncycastle_utils::ct::ct_eq_bytes(&*self_encoded, &*other_encoded)
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> fmt::Debug
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
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
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Display
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
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
/// disk: its encoding is the same 64-byte seed. Use it through
/// [`MLKEMTrait::decaps_with_expanded_key`](crate::MLKEMTrait::decaps_with_expanded_key).
pub struct MLKEMSeedPrivateKeyExpanded<
    P: MLKEMParams,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const PK_LEN: usize,
> {
    dk: MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>,
    t_hat_packed: P::TPacked,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Clone
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn clone(&self) -> Self {
        Self { dk: self.dk.clone(), t_hat_packed: self.t_hat_packed }
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    From<&MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>>
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    /// Derives 𝐭̂ from the seed key (Algorithm 13) and keeps it alongside a copy of the key.
    fn from(dk: &MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>) -> Self {
        Self { dk: dk.clone(), t_hat_packed: dk.t_hat_packed() }
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn from_keymaterial(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        Ok(Self::from_keymaterial_with_pk(seed)?.0)
    }
    fn seed(&self) -> KeyMaterial<64> {
        self.dk.seed()
    }
    fn pk(&self) -> MLKEMPublicKey<P, PK_LEN> {
        MLKEMPublicKey::<P, PK_LEN>::new(self.t_hat_packed, self.dk.rho)
    }
    fn pk_hash(&self) -> &[u8; 32] {
        self.dk.pk_hash()
    }
    fn encode_full_sk(&self) -> [u8; FULL_SK_LEN] {
        let mut out = [0u8; FULL_SK_LEN];
        self.encode_full_sk_out(&mut out);

        out
    }
    fn encode_full_sk_out(&self, out: &mut [u8; FULL_SK_LEN]) -> usize {
        self.dk.full_sk_out(&self.pk(), out)
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
        Self::from(&MLKEMSeedPrivateKey::sk_decode(sk))
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn from_keymaterial_with_pk(
        seed: &KeyMaterial<64>,
    ) -> Result<(Self, MLKEMPublicKey<P, PK_LEN>), KEMError> {
        // The construction derives t-hat for H(ek); keep it rather than derive it again.
        let (dk, pk) = MLKEMSeedPrivateKey::new_with_pk(seed)?;
        let t_hat_packed = pk.t_hat_packed;
        Ok((Self { dk, t_hat_packed }, pk))
    }

    fn z(&self) -> &[u8; 32] {
        self.dk.z()
    }

    fn compute_s_hat_row(&self, idx: usize) -> Polynomial {
        self.dk.compute_s_hat_row(idx)
    }

    fn rho(&self) -> &[u8; 32] {
        self.dk.rho()
    }

    /// The stored 𝐭̂, a copy.
    fn t_hat_packed(&self) -> P::TPacked {
        self.t_hat_packed
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    KEMPrivateKey<SK_LEN> for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    /// The 64-byte seed (d || z), as for the seed key: 𝐭̂ is derived again on load.
    fn encode(&self) -> [u8; SK_LEN] {
        self.dk.encode()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        self.dk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        Ok(Self::from(&MLKEMSeedPrivateKey::from_bytes(bytes)?))
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Eq
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> PartialEq
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    /// Two keys are equal when their seeds are; 𝐭̂ is a function of the seed.
    fn eq(&self, other: &Self) -> bool {
        self.dk == other.dk
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> fmt::Debug
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
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
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Display
    for MLKEMSeedPrivateKeyExpanded<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMSeedPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}",
            P::ALG_NAME,
            self.dk.pk_hash
        )
    }
}
