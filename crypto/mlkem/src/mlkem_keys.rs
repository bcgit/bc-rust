use crate::aux_functions::{byte_decode, byte_encode, expandA};
use crate::matrix::{Matrix, Vector};
use crate::mlkem::{H, POLY_BYTES, q};
use crate::mlkem::{MLKEM512_PK_LEN, MLKEM512_SK_LEN, MLKEM512_k};
use crate::mlkem::{MLKEM768_PK_LEN, MLKEM768_SK_LEN, MLKEM768_k};
use crate::mlkem::{MLKEM1024_PK_LEN, MLKEM1024_SK_LEN, MLKEM1024_k};
use crate::{ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Hash, KEMPrivateKey, KEMPublicKey, Secret, SecurityStrength};
use bouncycastle_sha3::SHA3_256;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mlkem::MLKEMTrait;

/* Pub Types */

/// ML-KEM-512 Public Key
pub type MLKEM512PublicKey = MLKEMPublicKey<MLKEM512_k, MLKEM512_PK_LEN>;
/// ML-KEM-512 Private Key
pub type MLKEM512PrivateKey =
    MLKEMPrivateKey<MLKEM512_k, MLKEM512PublicKey, MLKEM512_SK_LEN, MLKEM512_PK_LEN>;
/// ML-KEM-768 Public Key
pub type MLKEM768PublicKey = MLKEMPublicKey<MLKEM768_k, MLKEM768_PK_LEN>;
/// ML-KEM-768 Private Key
pub type MLKEM768PrivateKey =
    MLKEMPrivateKey<MLKEM768_k, MLKEM768PublicKey, MLKEM768_SK_LEN, MLKEM768_PK_LEN>;
/// ML-KEM-1024 Public Key
pub type MLKEM1024PublicKey = MLKEMPublicKey<MLKEM1024_k, MLKEM1024_PK_LEN>;
/// ML-KEM-1024 Private Key
pub type MLKEM1024PrivateKey =
    MLKEMPrivateKey<MLKEM1024_k, MLKEM1024PublicKey, MLKEM1024_SK_LEN, MLKEM1024_PK_LEN>;

/* Pre-expanded keys for repeated operations */

/// ML-KEM-512 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM512PublicKeyExpanded =
    MLKEMPublicKeyExpanded<MLKEM512_k, MLKEM512PublicKey, MLKEM512_PK_LEN>;
/// ML-KEM-512 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM512PrivateKeyExpanded = MLKEMPrivateKeyExpanded<
    MLKEM512_k,
    MLKEM512PublicKey,
    MLKEM512PrivateKey,
    MLKEM512_SK_LEN,
    MLKEM512_PK_LEN,
>;
/// ML-KEM-768 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM768PublicKeyExpanded =
    MLKEMPublicKeyExpanded<MLKEM768_k, MLKEM768PublicKey, MLKEM768_PK_LEN>;
/// ML-KEM-768 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM768PrivateKeyExpanded = MLKEMPrivateKeyExpanded<
    MLKEM768_k,
    MLKEM768PublicKey,
    MLKEM768PrivateKey,
    MLKEM768_SK_LEN,
    MLKEM768_PK_LEN,
>;
/// ML-KEM-1024 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM1024PublicKeyExpanded =
    MLKEMPublicKeyExpanded<MLKEM1024_k, MLKEM1024PublicKey, MLKEM1024_PK_LEN>;
/// ML-KEM-1024 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM1024PrivateKeyExpanded = MLKEMPrivateKeyExpanded<
    MLKEM1024_k,
    MLKEM1024PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024_SK_LEN,
    MLKEM1024_PK_LEN,
>;

/// An ML-KEM public key.
#[derive(Clone)]
pub struct MLKEMPublicKey<const k: usize, const PK_LEN: usize> {
    t_hat: Vector<k>,
    rho: [u8; 32],
}

/// General trait for all ML-KEM public keys types.
pub trait MLKEMPublicKeyTrait<const k: usize, const PK_LEN: usize>: KEMPublicKey<PK_LEN> {
    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>;
    /// Get a copy of the expanded public matrix A_hat
    fn A_hat(&self) -> Matrix<k, k>;
    /// Get the hash of the public key
    fn compute_hash(&self) -> [u8; 32];
}

pub(crate) trait MLKEMPublicKeyInternalTrait<const k: usize, const PK_LEN: usize>:
    MLKEMPublicKeyTrait<k, PK_LEN>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(t_hat: Vector<k>, rho: [u8; 32]) -> Self;

    /// Get a ref to t1
    fn t_hat(&self) -> &Vector<k>;
}

impl<const k: usize, const PK_LEN: usize> MLKEMPublicKeyTrait<k, PK_LEN>
    for MLKEMPublicKey<k, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError> {
        let (pk_chunks, last_chunk) = pk.as_chunks::<POLY_BYTES>();

        // that should divide evenly the remainder of the array, leaving space for rho at the end
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 32);

        let t_hat = {
            let mut t_hat = Vector::<k>::new();

            for (t_i, pk_chunk) in t_hat.vec.iter_mut().zip(pk_chunks) {
                t_i.coeffs.copy_from_slice(&byte_decode::<12, POLY_BYTES>(pk_chunk).coeffs);

                // FIPS 203 says:
                //      "Specifically, ByteDecode12 converts each 12-bit
                //      segment of its input into an integer modulo 212 = 4096 and then reduces the result
                //      modulo 𝑞. This is no longer a one-to-one operation. Indeed, some 12-bit segments could
                //      correspond to an integer greater than 𝑞 − 1 = 3328 but less than 4096."
                //  Since we are here in the d=12 case, we can and should check that all coeffs are less than q-1
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

    fn A_hat(&self) -> Matrix<k, k> {
        expandA(&self.rho)
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes_written = H::default().hash_out(&self.encode(), &mut out);
        debug_assert_eq!(bytes_written, 32);
        out
    }
}

impl<const k: usize, const PK_LEN: usize> MLKEMPublicKeyInternalTrait<k, PK_LEN>
    for MLKEMPublicKey<k, PK_LEN>
{
    fn new(t_hat: Vector<k>, rho: [u8; 32]) -> Self {
        Self { rho, t_hat }
    }

    fn t_hat(&self) -> &Vector<k> {
        &self.t_hat
    }
}

impl<const k: usize, const PK_LEN: usize> KEMPublicKey<PK_LEN> for MLKEMPublicKey<k, PK_LEN> {
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
        debug_assert_eq!(PK_LEN, 12 * k * 32 + 32);
        debug_assert_eq!(POLY_BYTES, 12 * 32);

        out.fill(0);

        let (pk_chunks, last_chunk) = out.as_chunks_mut::<POLY_BYTES>();

        // that should divide evenly the remainder of the array, leaving space for rho at the end
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 32);

        for (pk_chunk, t_i) in pk_chunks.into_iter().zip(&self.t_hat.vec) {
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

impl<const k: usize, const PK_LEN: usize> Eq for MLKEMPublicKey<k, PK_LEN> {}

impl<const k: usize, const PK_LEN: usize> PartialEq for MLKEMPublicKey<k, PK_LEN> {
    fn eq(&self, other: &Self) -> bool {
        bouncycastle_utils::ct::ct_eq_bytes(&self.encode(), &other.encode())
    }
}

impl<const k: usize, const PK_LEN: usize> Debug for MLKEMPublicKey<k, PK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", alg, hash)
    }
}

impl<const k: usize, const PK_LEN: usize> Display for MLKEMPublicKey<k, PK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", alg, hash)
    }
}

/// A fully expanded ML-KEM public key that includes the intermediate values needed for performing multiple encaps operations
/// against the same public key, which causes the MLKEMPublicKey struct to take up more memory, but results
/// in more efficient repeated encaps() operations.
#[derive(Clone)]
pub struct MLKEMPublicKeyExpanded<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const PK_LEN: usize,
> {
    pub(crate) ek: PK,
    pub(crate) A_hat: Matrix<k, k>,
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize>
    MLKEMPublicKeyInternalTrait<k, PK_LEN> for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
    fn new(t_hat: Vector<k>, rho: [u8; 32]) -> Self {
        let ek = PK::new(t_hat, rho);
        let A_hat = ek.A_hat();

        Self { ek, A_hat }
    }

    fn t_hat(&self) -> &Vector<k> {
        self.ek.t_hat()
    }
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize>
    KEMPublicKey<PK_LEN> for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
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

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize> PartialEq
    for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.encode() == other.encode()
    }
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize> Eq
    for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize> Debug
    for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}", alg, hash)
    }
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize> Display
    for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        let hash = SHA3_256::new().hash(&self.encode());
        write!(f, "MLKEMPublicKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}", alg, hash)
    }
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize>
    MLKEMPublicKeyTrait<k, PK_LEN> for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
    fn pk_decode(pk: &[u8; PK_LEN]) -> Result<Self, KEMError> {
        let ek = PK::pk_decode(pk)?;
        let A_hat = ek.A_hat();
        Ok(Self { ek, A_hat })
    }

    fn A_hat(&self) -> Matrix<k, k> {
        self.A_hat.clone()
    }

    fn compute_hash(&self) -> [u8; 32] {
        self.ek.compute_hash()
    }
}

impl<const k: usize, PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>, const PK_LEN: usize> From<&PK>
    for MLKEMPublicKeyExpanded<k, PK, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(ek: &PK) -> Self {
        let A_hat = ek.A_hat();

        Self { ek: ek.clone(), A_hat }
    }
}

/// An ML-KEM private key.
#[derive(Clone)]
pub struct MLKEMPrivateKey<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    s_hat: Vector<k>,
    ek: PK,
    pk_hash: [u8; 32],
    z: [u8; 32],
    seed_d: Option<[u8; 32]>,
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        debug_assert_eq!(SK_LEN, /* dk_pke*/ 12*k*32 + /*ek*/PK_LEN + /*H(ek)*/32 + /*z*/32);

        let mut pos = 0usize;

        /* dk_pke */
        // Alg 13; line 20: dkPKE ← ByteEncode12(𝐬)
        for i in 0..k {
            out[i * POLY_BYTES..(i + 1) * POLY_BYTES]
                .copy_from_slice(&byte_encode::<12, POLY_BYTES>(&self.s_hat[i]));
        }
        pos += k * POLY_BYTES;

        /* ek */
        // Alg 13; line 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
        debug_assert_eq!(self.ek.encode().len(), PK_LEN);
        out[pos..pos + PK_LEN].copy_from_slice(&self.ek.encode());
        pos += PK_LEN;

        /* H(ek) */
        out[pos..pos + 32].copy_from_slice(&self.pk_hash);
        pos += 32;

        /* z */
        out[pos..pos + 32].copy_from_slice(&self.z);

        debug_assert_eq!(pos + 32, SK_LEN);
        SK_LEN
    }
}

/// General trait for all ML-KEM private keys types.
pub trait MLKEMPrivateKeyTrait<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
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
    const k: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(s_hat: Vector<k>, ek: PK, h: [u8; 32], z: [u8; 32], seed_d: Option<[u8; 32]>) -> Self;

    /// Get a ref to s_hat
    fn s_hat(&self) -> &Vector<k>;

    fn z(&self) -> &[u8; 32];
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN> for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    fn seed(&self) -> Option<KeyMaterial<64>> {
        if self.seed_d.is_none() {
            None
        } else {
            let mut tmp = [0u8; 64];
            tmp[..32].copy_from_slice(&self.seed_d.unwrap());
            tmp[32..].copy_from_slice(&self.z);
            let mut seed = KeyMaterial::<64>::from_bytes_as_type(&tmp, KeyType::Seed).unwrap();
            seed.allow_hazardous_operations();
            seed.set_security_strength(match k {
                2 => SecurityStrength::_128bit,
                3 => SecurityStrength::_192bit,
                4 => SecurityStrength::_256bit,
                _ => unreachable!("Invalid mlkem param set"),
            })
            .unwrap();
            seed.drop_hazardous_operations();
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
        debug_assert_eq!(SK_LEN, /* dk_pke*/ 12*k*32 + /*ek*/PK_LEN + /*H(ek)*/32 + /*z*/32);

        let mut pos = 0usize;

        /* dk_pke */
        let mut s_hat = Vector::<k>::new();
        // for (s_i, sk_chunk) in s_hat.0.iter_mut().zip(sk_chunks) {
        for i in 0..k {
            s_hat[i] = byte_decode::<12, POLY_BYTES>(
                sk[i * POLY_BYTES..(i + 1) * POLY_BYTES].try_into().unwrap(),
            );

            // FIPS 203 says:
            //      "Specifically, ByteDecode12 converts each 12-bit
            //      segment of its input into an integer modulo 212 = 4096 and then reduces the result
            //      modulo 𝑞. This is no longer a one-to-one operation. Indeed, some 12-bit segments could
            //      correspond to an integer greater than 𝑞 − 1 = 3328 but less than 4096."
            //  Since we are here in the d=12 case, we can and should check that all coeffs are less than q
            for coeff in s_hat[i].coeffs.iter() {
                if *coeff < 0 || *coeff >= q {
                    return Err(KEMError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        pos += k * POLY_BYTES;

        /* ek */
        let ek = PK::pk_decode(sk[pos..pos + PK_LEN].try_into().unwrap())?;
        pos += PK_LEN;

        /* H(ek) */
        let h_pk: [u8; 32] = sk[pos..pos + 32].try_into().unwrap();
        pos += 32;

        // This satisfies the "Decapsulation input check #3) in FIPS 203 section 7.3.
        // We're doing it here on key load rather than as part of the decapsulation for performance
        // because if you're doing multiple decapsulations, you only need to perform this check once.
        if h_pk != ek.compute_hash() {
            return Err(KEMError::ConsistencyCheckFailed(
                "Corrupted private key: computed hash of ek != h_ek stored in private key",
            ));
        }

        /* z */
        let z: [u8; 32] = sk[pos..pos + 32].try_into().unwrap();

        Ok(Self::new(s_hat, ek, h_pk, z, None))
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN> for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    /// Note to future maintainers: FIPS 203 section 7.3 requires that ek be hashed and compared to pk_hash.
    fn new(
        s_hat: Vector<k>,
        ek: PK,
        pk_hash: [u8; 32],
        z: [u8; 32],
        seed_d: Option<[u8; 32]>,
    ) -> Self {
        Self { s_hat, ek, pk_hash, z, seed_d: seed_d.clone() }
    }

    fn s_hat(&self) -> &Vector<k> {
        &self.s_hat
    }

    fn z(&self) -> &[u8; 32] {
        &self.z
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> KEMPrivateKey<SK_LEN> for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
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
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Eq for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> PartialEq for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.encode();
        let other_encoded = other.encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Secret for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> fmt::Debug for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLKEMPrivateKey {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            alg,
            self.pk_hash,
            self.seed_d.is_some(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Display for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLKEMPrivateKey {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            alg,
            self.pk_hash,
            self.seed_d.is_some(),
        )
    }
}

/// Zeroizing drop
impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Drop for MLKEMPrivateKey<k, PK, SK_LEN, PK_LEN>
{
    fn drop(&mut self) {
        // s_hat, has its own zeroizing drop
        self.pk_hash.fill(0u8);
        self.z.fill(0u8);
        if self.seed_d.is_some() {
            self.seed_d.as_mut().unwrap().fill(0u8);
        }
    }
}

/// A fully expanded ML-KEM private key that includes the intermediate values needed for performing
/// multiple decaps operations with the same private key, which causes the private key struct to
/// take up more memory, but results in more efficient repeated decaps() operations.
#[derive(Clone)]
pub struct MLKEMPrivateKeyExpanded<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    _phantom: core::marker::PhantomData<PK>,
    pub(crate) dk: SK,
    pub(crate) A_hat: Matrix<k, k>,
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> From<&SK> for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
    /// Fully expands the intermediate values needed for performing multiple encaps operations
    /// against the same public key, which causes the MLKEMPublicKey struct to take up
    fn from(dk: &SK) -> Self {
        let A_hat = dk.pk().A_hat();

        Self { _phantom: core::marker::PhantomData, dk: dk.clone(), A_hat }
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> KEMPrivateKey<SK_LEN> for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
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
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> PartialEq for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.dk.eq(&other.dk)
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Eq for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Secret for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Drop for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
    fn drop(&mut self) {
        // Nothing to do since self.sk already impls zeroizing Drop
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Debug for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLKEMPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            alg,
            self.dk.pk().compute_hash(),
            self.dk.seed().is_some(),
        )
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> Display for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            2 => ML_KEM_512_NAME,
            3 => ML_KEM_768_NAME,
            4 => ML_KEM_1024_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLKEMPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            alg,
            self.dk.pk().compute_hash(),
            self.dk.seed().is_some(),
        )
    }
}

impl<
    const k: usize,
    PK: MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
> MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
    for MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>
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
