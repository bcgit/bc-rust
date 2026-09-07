use crate::aux_functions::sample_poly_CBD;
use crate::low_memory_helpers::{
    compute_A_hat_dot_s_hat, pack_s_hat_row, pack_t_hat_row, unpack_t_hat_row,
};
use crate::mlkem::{G, H, POLY_BYTES, q};
use crate::mlkem::{MLKEM512_FULL_SK_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN};
use crate::mlkem::{MLKEM768_FULL_SK_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN};
use crate::mlkem::{MLKEM1024_FULL_SK_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};
use crate::params::{MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams};
use crate::polynomial::Polynomial;
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{Hash, KEMPrivateKey, KEMPublicKey, SecurityStrength};
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
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    // todo: go make the equivalent thing also throw an error in the non-optimized impl
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
    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    fn encode(&self) -> [u8; PK_LEN] {
        debug_assert_eq!(PK_LEN, 32 + 12 * P::k * 32);
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
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> Display for MLKEMPublicKey<P, PK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = SHA3_256::new().hash(&self.encode());
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
    pk_hash: Option<[u8; 32]>,
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
    pub fn new(seed: &KeyMaterial<64>) -> Result<Self, KEMError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 64
        {
            return Err(KEMError::KeyGenError(
                "Seed must be 64 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(KEMError::KeyGenError("SecurityStrength"));
        }

        // These are Secret-safe because we're using .copy_from_slice directly out of one Secret<[u8]>
        // into another and the contents are never touching a non-Secret buffer.
        let mut seed_d = Secret::<[u8; 32]>::new();
        seed_d.as_mut().copy_from_slice(seed.ref_to_bytes()[..32].try_into().unwrap());
        let mut z = Secret::<[u8; 32]>::new();
        z.as_mut().copy_from_slice(seed.ref_to_bytes()[32..].try_into().unwrap());

        let (rho, sigma) = Self::compute_rho_and_sigma(&seed_d);

        // Deviation from the FIPS: The implementation does not persist the hash of the public key H(ek) in the
        // in-memory representation because it can be re-computed as needed.
        Ok(Self { _phantom: core::marker::PhantomData, rho, sigma, pk_hash: None, z, seed_d })
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
    /// Get a ref to the seed, which there always will be for a MLKEMSeedPrivateKey
    /// In this implementation, we always have a seed, so will always return Some.
    fn seed(&self) -> Option<KeyMaterial<64>>;
    /// Runs essentially a full keygen according to Algorithm 13.
    // Dev note: This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn pk(&self) -> MLKEMPublicKey<P, PK_LEN>;
    /// Get a ref to the stored public key hash.
    /// Since in this implementation, this requires running the full keygen, this is a lazy evaluation and
    /// will only be computationally heavy the first time it is called for a given key.
    /// This requires a mutable copy. If you don't have then, then you can compute the full public key via [`MLKEMPrivateKeyTrait::pk`]
    /// and then get the hash of that.
    fn pk_hash(&mut self) -> &[u8; 32];
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
    fn seed(&self) -> Option<KeyMaterial<64>> {
        let mut tmp = Secret::<[u8; 64]>::new();
        tmp[..32].as_mut().copy_from_slice(&*self.seed_d);
        tmp[32..].as_mut().copy_from_slice(&*self.z);
        let mut seed = KeyMaterial::<64>::from_bytes_as_type(&*tmp, KeyType::Seed).unwrap();
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })
        .unwrap();

        Some(seed)
    }
    fn pk(&self) -> MLKEMPublicKey<P, PK_LEN> {
        MLKEMPublicKey::<P, PK_LEN>::new(self.t_hat_packed(), self.rho)
    }
    fn pk_hash(&mut self) -> &[u8; 32] {
        if self.pk_hash.is_none() {
            self.pk_hash = Some(self.pk().compute_hash().clone());
        }

        &self.pk_hash.as_ref().unwrap()
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
        let pk = self.pk();
        out[pos..pos + PK_LEN].copy_from_slice(&pk.encode());
        pos += PK_LEN;

        /* H(ek) */
        out[pos..pos + 32].copy_from_slice(&pk.compute_hash());
        pos += 32;

        /* z */
        out[pos..pos + 32].copy_from_slice(&*self.z);

        FULL_SK_LEN
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
        debug_assert_eq!(SK_LEN, /* seed*/ 64);
        Self::from_bytes(sk).unwrap()
    }
}

impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize>
    MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
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
        debug_assert_eq!(SK_LEN, 64);

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
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> fmt::Debug
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let pk_hash = self.pk().compute_hash();
        write!(f, "MLKEMSeedPrivateKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, &pk_hash,)
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams, const SK_LEN: usize, const FULL_SK_LEN: usize, const PK_LEN: usize> Display
    for MLKEMSeedPrivateKey<P, SK_LEN, FULL_SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let pk_hash = self.pk().compute_hash();
        write!(f, "MLKEMSeedPrivateKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, &pk_hash,)
    }
}
