use crate::aux_functions::{byte_decode, byte_encode, expandA};
use crate::matrix::VectorTrait;
use crate::mlkem::{H, POLY_BYTES, q};
use crate::mlkem::{MLKEM512_PK_LEN, MLKEM512_SK_LEN};
use crate::mlkem::{MLKEM768_PK_LEN, MLKEM768_SK_LEN};
use crate::mlkem::{MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};
use crate::params::{MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Hash, KEMPrivateKey, KEMPublicKey};
use bouncycastle_sha3::SHA3_256;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mlkem::MLKEMTrait;
#[allow(unused_imports)]
use crate::polynomial::Polynomial;

/* Pub Types */

/// ML-KEM-512 Public Key
pub type MLKEM512PublicKey = MLKEMPublicKey<MLKEM512Params, MLKEM512_PK_LEN>;
/// ML-KEM-512 Private Key
pub type MLKEM512PrivateKey =
    MLKEMPrivateKey<MLKEM512Params, MLKEM512PublicKey, MLKEM512_SK_LEN, MLKEM512_PK_LEN>;
/// ML-KEM-768 Public Key
pub type MLKEM768PublicKey = MLKEMPublicKey<MLKEM768Params, MLKEM768_PK_LEN>;
/// ML-KEM-768 Private Key
pub type MLKEM768PrivateKey =
    MLKEMPrivateKey<MLKEM768Params, MLKEM768PublicKey, MLKEM768_SK_LEN, MLKEM768_PK_LEN>;
/// ML-KEM-1024 Public Key
pub type MLKEM1024PublicKey = MLKEMPublicKey<MLKEM1024Params, MLKEM1024_PK_LEN>;
/// ML-KEM-1024 Private Key
pub type MLKEM1024PrivateKey =
    MLKEMPrivateKey<MLKEM1024Params, MLKEM1024PublicKey, MLKEM1024_SK_LEN, MLKEM1024_PK_LEN>;

/* Pre-expanded keys for repeated operations */

/// ML-KEM-512 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM512PublicKeyExpanded =
    MLKEMPublicKeyExpanded<MLKEM512Params, MLKEM512PublicKey, MLKEM512_PK_LEN>;
/// ML-KEM-512 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM512PrivateKeyExpanded = MLKEMPrivateKeyExpanded<
    MLKEM512Params,
    MLKEM512PublicKey,
    MLKEM512PrivateKey,
    MLKEM512_SK_LEN,
    MLKEM512_PK_LEN,
>;
/// ML-KEM-768 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM768PublicKeyExpanded =
    MLKEMPublicKeyExpanded<MLKEM768Params, MLKEM768PublicKey, MLKEM768_PK_LEN>;
/// ML-KEM-768 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM768PrivateKeyExpanded = MLKEMPrivateKeyExpanded<
    MLKEM768Params,
    MLKEM768PublicKey,
    MLKEM768PrivateKey,
    MLKEM768_SK_LEN,
    MLKEM768_PK_LEN,
>;
/// ML-KEM-1024 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM1024PublicKeyExpanded =
    MLKEMPublicKeyExpanded<MLKEM1024Params, MLKEM1024PublicKey, MLKEM1024_PK_LEN>;
/// ML-KEM-1024 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM1024PrivateKeyExpanded = MLKEMPrivateKeyExpanded<
    MLKEM1024Params,
    MLKEM1024PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024_SK_LEN,
    MLKEM1024_PK_LEN,
>;

/// An ML-KEM public key.
pub struct MLKEMPublicKey<P: MLKEMParams, const PK_LEN: usize> {
    t_hat: P::VecK,
    rho: [u8; 32],
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLKEMParams, const PK_LEN: usize> Clone for MLKEMPublicKey<P, PK_LEN> {
    fn clone(&self) -> Self {
        Self { t_hat: self.t_hat, rho: self.rho }
    }
}

/// General trait for all ML-KEM public keys types.
pub trait MLKEMPublicKeyTrait<P: MLKEMParams, const PK_LEN: usize>: KEMPublicKey<PK_LEN> {
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>;
    /// Get a copy of the expanded public matrix A_hat
    fn A_hat(&self) -> P::MatrixA;
    /// Get the hash of the public key
    fn compute_hash(&self) -> [u8; 32];
}

pub(crate) trait MLKEMPublicKeyInternalTrait<P: MLKEMParams, const PK_LEN: usize>:
    MLKEMPublicKeyTrait<P, PK_LEN>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(t_hat: P::VecK, rho: [u8; 32]) -> Self;

    /// Get a ref to t1
    fn t_hat(&self) -> &P::VecK;
}

impl<P: MLKEMParams, const PK_LEN: usize> MLKEMPublicKeyTrait<P, PK_LEN>
    for MLKEMPublicKey<P, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError> {
        let (pk_chunks, last_chunk) = pk.as_chunks::<POLY_BYTES>();

        // that should divide evenly the remainder of the array, leaving space for rho at the end
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 32);

        let t_hat = {
            let mut t_hat = P::VecK::new();

            for (t_i, pk_chunk) in t_hat.elems_mut().iter_mut().zip(pk_chunks) {
                t_i.coeffs.copy_from_slice(&byte_decode::<12, POLY_BYTES>(pk_chunk).coeffs);

                // FIPS 203 says:
                //      "Specifically, ByteDecode12 converts each 12-bit
                //      segment of its input into an integer modulo 2^{12} = 4096 and then reduces the result
                //      modulo 𝑞. This is no longer a one-to-one operation. Indeed, some 12-bit segments could
                //      correspond to an integer greater than 𝑞 − 1 = 3328 but less than 4096."
                //  Since this concerns to the case d=12, it should be checked that all coeffs are less than q-1
                for coeff in t_i.coeffs.iter() {
                    if *coeff < 0 || *coeff >= q {
                        return Err(KEMError::DecodingError("Invalid or corrupted key"));
                    }
                }
            }

            t_hat
        };
        let rho = last_chunk.try_into().unwrap();

        Ok(Self::new(t_hat, rho))
    }

    fn A_hat(&self) -> P::MatrixA {
        expandA::<P>(&self.rho)
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes_written = H::default().hash_out(&self.encode(), &mut out);
        debug_assert_eq!(bytes_written, 32);
        out
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> MLKEMPublicKeyInternalTrait<P, PK_LEN>
    for MLKEMPublicKey<P, PK_LEN>
{
    fn new(t_hat: P::VecK, rho: [u8; 32]) -> Self {
        Self { rho, t_hat }
    }

    fn t_hat(&self) -> &P::VecK {
        &self.t_hat
    }
}

impl<P: MLKEMParams, const PK_LEN: usize> KEMPublicKey<PK_LEN> for MLKEMPublicKey<P, PK_LEN> {
    /// Encodes the public key as per FIPS 203 Algorithm 13
    /// 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        self.encode_out(&mut pk);

        pk
    }
    /// Encodes the public key as per FIPS 203 Algorithm 13
    /// 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        debug_assert_eq!(POLY_BYTES, 12 * 32);

        out.fill(0);

        let (pk_chunks, last_chunk) = out.as_chunks_mut::<POLY_BYTES>();

        // that should divide evenly the remainder of the array, leaving space for rho at the end
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 32);

        for (pk_chunk, t_i) in pk_chunks.into_iter().zip(self.t_hat.elems()) {
            pk_chunk.copy_from_slice(&byte_encode::<12, POLY_BYTES>(t_i));
        }
        last_chunk.copy_from_slice(&self.rho);

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

/// A fully expanded ML-KEM public key that includes the intermediate values needed for performing multiple encaps operations
/// against the same public key, which causes the MLKEMPublicKey struct to take up more memory, but results
/// in more efficient repeated encaps() operations.
pub struct MLKEMPublicKeyExpanded<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const PK_LEN: usize,
> {
    pub(crate) ek: PK,
    pub(crate) A_hat: P::MatrixA,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> Clone
    for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn clone(&self) -> Self {
        Self { ek: self.ek.clone(), A_hat: self.A_hat.clone() }
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize>
    MLKEMPublicKeyInternalTrait<P, PK_LEN> for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn new(t_hat: P::VecK, rho: [u8; 32]) -> Self {
        let ek = PK::new(t_hat, rho);
        let A_hat = ek.A_hat();

        Self { ek, A_hat }
    }

    fn t_hat(&self) -> &P::VecK {
        self.ek.t_hat()
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize>
    KEMPublicKey<PK_LEN> for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        self.encode_out(&mut pk);

        pk
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);

        self.ek.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        if bytes.len() != PK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }
        let bytes_sized: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Self::pk_decode(&bytes_sized)
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> PartialEq
    for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.encode() == other.encode()
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> Eq
    for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> Debug
    for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> Display
    for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize>
    MLKEMPublicKeyTrait<P, PK_LEN> for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError> {
        let ek = PK::pk_decode(pk)?;
        let A_hat = ek.A_hat();
        Ok(Self { ek, A_hat })
    }

    fn A_hat(&self) -> P::MatrixA {
        self.A_hat.clone()
    }

    fn compute_hash(&self) -> [u8; 32] {
        self.ek.compute_hash()
    }
}

impl<P: MLKEMParams, PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>, const PK_LEN: usize> From<&PK>
    for MLKEMPublicKeyExpanded<P, PK, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(ek: &PK) -> Self {
        let A_hat = ek.A_hat();

        Self { ek: ek.clone(), A_hat }
    }
}

/// An ML-KEM private key.
///
// Dev note: This will automatically inherit the [`Secret`] protections because [`Polynomial`] wraps the underlying data with [`Secret`].
pub struct MLKEMPrivateKey<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    s_hat: Secret<P::VecK>,
    ek: PK,
    pk_hash: [u8; 32],
    z: Secret<[u8; 32]>,
    seed_d: Option<Secret<[u8; 32]>>,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Clone for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    fn clone(&self) -> Self {
        Self {
            s_hat: self.s_hat.clone(),
            ek: self.ek.clone(),
            pk_hash: self.pk_hash,
            z: self.z.clone(),
            seed_d: self.seed_d.clone(),
        }
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        debug_assert_eq!(
            SK_LEN,
            /* dk_pke*/ 12*P::k*32 + /*ek*/PK_LEN + /*H(ek)*/32 + /*z*/32
        );

        let mut pos = 0usize;

        /* dk_pke */
        // Alg 13; line 20: dkPKE ← ByteEncode12(𝐬)
        for i in 0..P::k {
            out[i * POLY_BYTES..(i + 1) * POLY_BYTES]
                .copy_from_slice(&byte_encode::<12, POLY_BYTES>(&self.s_hat[i]));
        }
        pos += P::k * POLY_BYTES;

        /* ek */
        // Alg 13; line 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
        debug_assert_eq!(self.ek.encode().len(), PK_LEN);
        out[pos..pos + PK_LEN].copy_from_slice(&self.ek.encode());
        pos += PK_LEN;

        /* H(ek) */
        out[pos..pos + 32].copy_from_slice(&self.pk_hash);
        pos += 32;

        /* z */
        out[pos..pos + 32].copy_from_slice(&*self.z);

        debug_assert_eq!(pos + 32, SK_LEN);
        SK_LEN
    }
}

/// General trait for all ML-KEM private keys types.
pub trait MLKEMPrivateKeyTrait<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
>: KEMPrivateKey<SK_LEN>
{
    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> Option<KeyMaterial<64>>;

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn pk(&self) -> &PK;
    /// Get a ref to the stored public key hash.
    fn pk_hash(&self) -> &[u8; 32];
    /// Decode the private key.
    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, KEMError>;
}

pub(crate) trait MLKEMPrivateKeyInternalTrait<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(
        s_hat: Secret<P::VecK>,
        ek: PK,
        h: [u8; 32],
        z: Secret<[u8; 32]>,
        seed_d: Option<Secret<[u8; 32]>>,
    ) -> Self;

    /// Get a ref to s_hat
    fn s_hat(&self) -> &P::VecK;

    fn z(&self) -> &Secret<[u8; 32]>;
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN> for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    fn seed(&self) -> Option<KeyMaterial<64>> {
        if self.seed_d.is_none() {
            None
        } else {
            let mut tmp = Secret::<[u8; 64]>::new();
            tmp[..32].copy_from_slice(&self.seed_d.clone().unwrap().as_ref());
            tmp[32..].copy_from_slice(&*self.z);
            let mut seed = KeyMaterial::<64>::from_bytes_as_type(&*tmp, KeyType::Seed).unwrap();

            key_material::do_hazardous_operations(&mut seed, |seed| {
                seed.set_security_strength(P::MAX_SECURITY_STRENGTH)
            })
            .unwrap();

            Some(seed)
        }
    }

    fn pk(&self) -> &PK {
        &self.ek
    }

    fn pk_hash(&self) -> &[u8; 32] {
        &self.pk_hash
    }

    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, KEMError> {
        debug_assert_eq!(
            SK_LEN,
            /* dk_pke*/ 12*P::k*32 + /*ek*/PK_LEN + /*H(ek)*/32 + /*z*/32
        );

        let mut pos = 0usize;

        /* dk_pke */
        let mut s_hat: Secret<P::VecK> = Secret::new();
        // for (s_i, sk_chunk) in s_hat.0.iter_mut().zip(sk_chunks) {
        for i in 0..P::k {
            s_hat[i] = byte_decode::<12, POLY_BYTES>(
                sk[i * POLY_BYTES..(i + 1) * POLY_BYTES].try_into().unwrap(),
            );

            // FIPS 203 says:
            //      "Specifically, ByteDecode12 converts each 12-bit
            //      segment of its input into an integer modulo 2^{12} = 4096 and then reduces the result
            //      modulo 𝑞. This is no longer a one-to-one operation. Indeed, some 12-bit segments could
            //      correspond to an integer greater than 𝑞 − 1 = 3328 but less than 4096."
            //  Since this concerns to the case d=12, it should be checked that all coeffs are less than q-1
            for coeff in s_hat[i].coeffs.iter() {
                if *coeff < 0 || *coeff >= q {
                    return Err(KEMError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        pos += P::k * POLY_BYTES;

        /* ek */
        let ek = PK::pk_decode(sk[pos..pos + PK_LEN].try_into().unwrap())?;
        pos += PK_LEN;

        /* H(ek) */
        let h_pk: [u8; 32] = sk[pos..pos + 32].try_into().unwrap();
        pos += 32;

        // This satisfies the "Decapsulation input check #3) in FIPS 203 section 7.3.
        // It is done here on key load rather than as part of the decapsulation for performance
        // because if multiple decapsulations are being performed, this check needs to be done only once.
        if h_pk != ek.compute_hash() {
            return Err(KEMError::ConsistencyCheckFailed(
                "Corrupted private key: computed hash of ek != h_ek stored in private key",
            ));
        }

        /* z */
        let mut z = Secret::<[u8; 32]>::new();
        z.copy_from_slice(sk[pos..pos + 32].try_into().unwrap());

        Ok(Self::new(s_hat, ek, h_pk, z, None))
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN> for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    /// Note to future maintainers: FIPS 203 section 7.3 requires that ek be hashed and compared to pk_hash.
    fn new(
        s_hat: Secret<P::VecK>,
        ek: PK,
        pk_hash: [u8; 32],
        z: Secret<[u8; 32]>,
        seed_d: Option<Secret<[u8; 32]>>,
    ) -> Self {
        Self { s_hat, ek, pk_hash, z, seed_d: seed_d.clone() }
    }

    fn s_hat(&self) -> &P::VecK {
        &self.s_hat
    }

    fn z(&self) -> &Secret<[u8; 32]> {
        &self.z
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> KEMPrivateKey<SK_LEN> for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    fn encode(&self) -> [u8; SK_LEN] {
        let mut out = [0u8; SK_LEN];
        self.encode_out(&mut out);

        out
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        self.sk_encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        if bytes.len() != SK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }
        if bytes.len() != SK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }
        let bytes_sized: [u8; SK_LEN] = bytes[..SK_LEN].try_into().unwrap();

        Self::sk_decode(&bytes_sized)
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Eq for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> PartialEq for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> fmt::Debug for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKey {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.pk_hash,
            self.seed_d.is_some(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Display for MLKEMPrivateKey<P, PK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKey {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.pk_hash,
            self.seed_d.is_some(),
        )
    }
}

/// A fully expanded ML-KEM private key that includes the intermediate values needed for performing
/// multiple decaps operations with the same private key, which causes the private key struct to
/// take up more memory, but results in more efficient repeated decaps() operations.
pub struct MLKEMPrivateKeyExpanded<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    _phantom: core::marker::PhantomData<PK>,
    pub(crate) dk: SK,
    pub(crate) A_hat: P::MatrixA,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Clone for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn clone(&self) -> Self {
        Self { _phantom: core::marker::PhantomData, dk: self.dk.clone(), A_hat: self.A_hat.clone() }
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> From<&SK> for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(dk: &SK) -> Self {
        let A_hat = dk.pk().A_hat();

        Self { _phantom: core::marker::PhantomData, dk: dk.clone(), A_hat }
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> KEMPrivateKey<SK_LEN> for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.dk.encode()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        self.dk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        Ok(Self::from(&SK::from_bytes(bytes)?))
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> PartialEq for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.dk.eq(&other.dk)
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Eq for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Debug for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.dk.pk().compute_hash(),
            self.dk.seed().is_some(),
        )
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Display for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.dk.pk().compute_hash(),
            self.dk.seed().is_some(),
        )
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
    for MLKEMPrivateKeyExpanded<P, PK, SK, SK_LEN, PK_LEN>
{
    fn seed(&self) -> Option<KeyMaterial<64>> {
        self.dk.seed()
    }

    fn pk(&self) -> &PK {
        self.dk.pk()
    }

    fn pk_hash(&self) -> &[u8; 32] {
        &self.dk.pk_hash()
    }

    fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, KEMError> {
        let dk = SK::sk_decode(sk)?;
        let A_hat = dk.pk().A_hat();

        Ok(Self { _phantom: core::marker::PhantomData, dk: dk.clone(), A_hat })
    }
}
