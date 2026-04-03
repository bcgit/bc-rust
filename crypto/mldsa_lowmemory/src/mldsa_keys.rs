use crate::aux_functions::{bit_pack_eta, bitlen_eta, power_2_round, rej_bounded_poly, rej_ntt_poly, simple_bit_pack_t1, simple_bit_unpack_t1};
use crate::mldsa::{H, N};
use crate::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
use crate::mldsa::{MLDSA44_LAMBDA, MLDSA44_GAMMA2, MLDSA44_ETA, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_k, MLDSA44_l, MLDSA44_S1_PACKED_LEN, MLDSA44_S2_PACKED_LEN};
use crate::mldsa::{MLDSA65_LAMBDA, MLDSA65_GAMMA2, MLDSA65_ETA, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_k, MLDSA65_l, MLDSA65_S1_PACKED_LEN, MLDSA65_S2_PACKED_LEN};
use crate::mldsa::{MLDSA87_LAMBDA, MLDSA87_GAMMA2, MLDSA87_ETA, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_k, MLDSA87_l, MLDSA87_S1_PACKED_LEN, MLDSA87_S2_PACKED_LEN};
use crate::mldsa::{POLY_T1PACKED_LEN, MLDSA44_T1_PACKED_LEN, MLDSA65_T1_PACKED_LEN, MLDSA87_T1_PACKED_LEN};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::{KeyMaterialSized, KeyType};
use bouncycastle_core_interface::traits::{KeyMaterial, Secret, SecurityStrength, SignaturePrivateKey, SignaturePublicKey, XOF};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use crate::low_memory_helpers::s_unpack;
// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;
use crate::polynomial::Polynomial;


/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44_k, MLDSA44_T1_PACKED_LEN, MLDSA44_PK_LEN>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey = MLDSASeedPrivateKey<MLDSA44_LAMBDA, MLDSA44_GAMMA2, MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_S1_PACKED_LEN, MLDSA44_S2_PACKED_LEN, MLDSA44_T1_PACKED_LEN, MLDSA44_PK_LEN, MLDSA44_SK_LEN>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65_k, MLDSA65_T1_PACKED_LEN, MLDSA65_PK_LEN>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey = MLDSASeedPrivateKey<MLDSA65_LAMBDA, MLDSA65_GAMMA2, MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_S1_PACKED_LEN, MLDSA65_S2_PACKED_LEN, MLDSA65_T1_PACKED_LEN, MLDSA65_PK_LEN, MLDSA65_SK_LEN>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87_k, MLDSA87_T1_PACKED_LEN, MLDSA87_PK_LEN>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey = MLDSASeedPrivateKey<MLDSA87_LAMBDA, MLDSA87_GAMMA2, MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_S1_PACKED_LEN, MLDSA87_S2_PACKED_LEN, MLDSA87_T1_PACKED_LEN, MLDSA87_PK_LEN, MLDSA87_SK_LEN>;

/// An ML-DSA public key.
#[derive(Clone)]
pub struct MLDSAPublicKey<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) t1_packed: [u8; T1_PACKED_LEN],
}

/// General trait for all ML-DSA public keys types.
pub trait MLDSAPublicKeyTrait<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> : SignaturePublicKey {
    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    fn pk_encode(&self) -> [u8; PK_LEN];

    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self;

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    fn compute_tr(&self) -> [u8; 64];
}

pub(crate) trait MLDSAPublicKeyInternalTrait<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: &[u8; 32], t1_packed: &[u8; T1_PACKED_LEN]) -> Self;

    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get a ref to t1
    fn unpack_t1_row(&self, row: usize) -> Polynomial;
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> MLDSAPublicKeyTrait<k, T1_PACKED_LEN, PK_LEN> for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
    // todo -- I think this becomes trivial
    // fn pk_encode(&self) -> [u8; PK_LEN] {
    //     let mut pk = [0u8; PK_LEN];
    //
    //     pk[0..32].copy_from_slice(&self.rho);
    //
    //     let (pk_chunks, last_chunk) = pk[32..].as_chunks_mut::<POLY_T1PACKED_LEN>();
    //
    //     // that should divide evenly the remainder of the array
    //     debug_assert_eq!(pk_chunks.len(), k);
    //     debug_assert_eq!(last_chunk.len(), 0);
    //
    //     for (pk_chunk, t1_i) in pk_chunks.into_iter().zip(&self.t1.vec) {
    //         pk_chunk.copy_from_slice(&simple_bit_pack_t1(&t1_i));
    //     }
    //
    //     pk
    // }
    fn pk_encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        pk[..32].copy_from_slice(&self.rho);
        pk[32..].copy_from_slice(&self.t1_packed);
        pk
    }

    // fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
    //     let rho = pk[0..32].try_into().unwrap();
    //     let mut t1 = Vector::<k>::new();
    //
    //     let (pk_chunks, last_chunk) = pk[32..].as_chunks::<POLY_T1PACKED_LEN>();
    //
    //     // that should divide evenly the remainder of the array
    //     debug_assert_eq!(pk_chunks.len(), k);
    //     debug_assert_eq!(last_chunk.len(), 0);
    //
    //     for (t1_i, pk_chunk) in t1.vec.iter_mut().zip(pk_chunks) {
    //         t1_i.0.copy_from_slice(&simple_bit_unpack_t1(pk_chunk).0);
    //     }
    //
    //     Self::new(&rho, &t1)
    // }
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        Self {
            rho: pk[..32].try_into().unwrap(),
            t1_packed: pk[32..].try_into().unwrap()
        }
    }

    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&self.pk_encode(), &mut tr);

        tr
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> MLDSAPublicKeyInternalTrait<k, T1_PACKED_LEN, PK_LEN> for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
    fn new(rho: &[u8; 32], t1_packed: &[u8; T1_PACKED_LEN]) -> Self {
        Self { rho: rho.clone(), t1_packed: t1_packed.clone() }
    }

    fn rho(&self) -> &[u8; 32] { &self.rho }

    fn unpack_t1_row(&self, row: usize) -> Polynomial {
        simple_bit_unpack_t1(&self.t1_packed[row * POLY_T1PACKED_LEN .. (row + 1) * POLY_T1PACKED_LEN].try_into().unwrap())
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize>  SignaturePublicKey for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
    fn encode(&self) -> Vec<u8> {
        Vec::from(self.pk_encode())
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < PK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.pk_encode();
            debug_assert_eq!(tmp.len(), PK_LEN);
            out[..PK_LEN].copy_from_slice(&tmp);
            Ok(PK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != PK_LEN { return Err(SignatureError::DecodingError("Provided key bytes are the incorrect length")) }
        let sized_bytes: [u8; PK_LEN] = bytes[..PK_LEN].try_into().unwrap();
        Ok(Self::pk_decode(&sized_bytes))
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> Eq for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> { }

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> PartialEq for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.pk_encode();
        let other_encoded = other.pk_encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> fmt::Debug for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
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

impl<const k: usize, const T1_PACKED_LEN: usize, const PK_LEN: usize> Display for MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
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



/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<
    const k: usize,
    const l: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize
> : SignaturePrivateKey {
    /// New from KeyMaterial. Can throw a SignatureError if the KeyMaterial does not contain sufficient entropy.
    fn from_keymaterial(seed: &KeyMaterialSized<32>) -> Result<Self, SignatureError>;

    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> &KeyMaterialSized<32>;

    /// Get a copy of the key hash `tr`.
    /// This is computationally intensive as it requires fully re-computing the public key (and then discarding it).
    /// It is highly recommended that if you already have a copy of the public key, get `tr` from that,
    /// or else compute tr once and store it.
    fn tr(&self) -> [u8; 64];

    /// Returns the full public key, and has the side-effect of setting the public key hash tr in this MLDSASeedSK object.
    fn derive_pk(&self) -> MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN>;
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
    /// 𝐬1 ∈ 𝑅ℓ , 𝐬2 ∈ 𝑅𝑘 , 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    ///
    /// Note: this object contains only the simple decoding routine to unpack a semi-expanded key.
    /// See [MLDSATrait] for key generation functions, including derive-from-seed and consistency-check functions.
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self;
}

/// Internal structure for holding a seed-based private key for ML-DSA.
#[derive(Clone, PartialEq, Eq)]
pub struct MLDSASeedPrivateKey<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> {
    seed: KeyMaterialSized<32>,
    rho: [u8; 32],
    rho_prime: [u8; 64],
    K: [u8; 32],
    tr: Option<[u8; 64]>,
}


impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
>  Drop for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN,> {
    fn drop(&mut self) {
        // seed is a KeyMaterialSized which will zeroize itself
        self.rho.fill(0u8);
        self.rho_prime.fill(0u8);
        self.K.fill(0u8);
        if self.tr.is_some() {
            self.tr.unwrap().as_mut().fill(0u8);
            debug_assert_eq!(&self.tr.unwrap(), &[0u8; 64]);
        }
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> Secret for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> Debug for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSASeedPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            alg,
            self.tr(),
        )
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> Display for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSASeedPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?} }}",
            alg,
            self.tr(),
        )
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {
    /// Create a new MLDSASeedPrivateKey from a 32-byte KeyMaterial.
    pub fn new(seed: &KeyMaterialSized<32>) -> Result<Self, SignatureError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::BytesFullEntropy)
                || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(SignatureError::KeyGenError("Seed SecurityStrength must match algorithm security strength: 128-bit (ML-DSA-44), 192-bit (ML-DSA-65), or 256-bit (ML-DSA-87)."));
        }

        let (rho, rho_prime, K) = Self::compute_rhos_and_K(&seed);
        Ok(Self { seed: seed.clone(), rho, rho_prime, K, tr: None, })
    }

    fn compute_rhos_and_K(seed: &KeyMaterialSized<32>) -> ([u8; 32], [u8; 64], [u8; 32]) {
        // derive sk.K
        // Alg 6; 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut rho_prime: [u8; 64] = [0u8; 64];
        let mut K: [u8; 32] = [0u8; 32];

        let mut h = H::default();
        h.absorb(seed.ref_to_bytes());
        h.absorb(&(k as u8).to_le_bytes());
        h.absorb(&(l as u8).to_le_bytes());
        let bytes_written = h.squeeze_out(&mut rho);
        debug_assert_eq!(bytes_written, 32);
        let bytes_written = h.squeeze_out(&mut rho_prime);
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.squeeze_out(&mut K);
        debug_assert_eq!(bytes_written, 32);

        (rho, rho_prime, K)
    }

    fn compute_t_row(
        &self,
        idx: usize,
        s1_packed: &[u8],
        s2_packed: &[u8],
    ) -> Polynomial {
        debug_assert!(idx < k);

        // [Optimization Note]:
        // This is one of the places that a row of s1 can be re-computed instead of expanded from the compressed form.
        // let mut s1 = self.compute_s1_row(0);
        let mut s1_hat = s_unpack::<eta>(s1_packed, 0);
        s1_hat.ntt();

        let mut t_hat = rej_ntt_poly(&self.rho, &[0u8, idx as u8]);
            // polynomial::multiply_ntt(&rej_ntt_poly(&self.rho, &[0u8, idx as u8]), &s1_hat);
        t_hat.multiply_ntt(&s1_hat);

        for col in 1..l {
            // [Optimization Note]:
            // This is one of the places that a row of s1 can be re-computed instead of expanded from the compressed form.
            // s1 = self.compute_s1_row(col);
            let mut s1_hat = s_unpack::<eta>(s1_packed, col);
            s1_hat.ntt();
            // let tmp = polynomial::multiply_ntt(
            //     // [Optimization Note]:
            //     // this is reconstructing a row of the public matrix A_hat,
            //     // which nobody is proposing to keep in memory.
            //     &rej_ntt_poly(&self.rho, &[col as u8, idx as u8]),
            //     &s1_hat,
            // );
            let mut tmp = rej_ntt_poly(&self.rho, &[col as u8, idx as u8]);
            tmp.multiply_ntt(&s1_hat);
            t_hat.add_ntt(&tmp);
        }

        t_hat.inv_ntt();
        let mut t = t_hat;
        // [Optimization Note]:
        // This is one of the places that a row of s2 can be re-computed instead of unpacked from the compressed form.
        // let s2 = self.compute_s2_row(idx);
        let s2 = s_unpack::<eta>(s2_packed, idx);
        t.add_ntt(&s2);
        t.conditional_add_q();

        t
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> SignaturePrivateKey for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {
    fn encode(&self) -> Vec<u8> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.seed.ref_to_bytes());
        out.to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < 32 {
            return Err(SignatureError::EncodingError("Output buffer too small"));
        }
        out[..32].copy_from_slice(self.seed.ref_to_bytes());
        Ok(32)

    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != 32 {
            return Err(SignatureError::DecodingError("Invalid seed length"));
        }
        let mut keymat = KeyMaterialSized::<32>::from_bytes(bytes)?;
        keymat.allow_hazardous_operations();
        keymat.set_key_type(KeyType::Seed)?;
        keymat.set_security_strength(SecurityStrength::_256bit)?;
        keymat.drop_hazardous_operations();

        Self::new(&keymat)
    }
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> MLDSAPrivateKeyTrait<k, l, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN>
for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {
    fn from_keymaterial(seed: &KeyMaterialSized<32>) -> Result<Self, SignatureError> {
        Self::new(seed)
    }

    fn seed(&self) -> &KeyMaterialSized<32> { &self.seed }

    fn tr(&self) -> [u8; 64] {
        let pk: MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> = self.derive_pk();
        pk.compute_tr()
    }

    fn derive_pk(&self) -> MLDSAPublicKey<k, T1_PACKED_LEN, PK_LEN> {
        // The goal here is to get t1, which we will build and compress one row at a time.

        let s1_packed: [u8; S1_PACKED_LEN] = self.compute_s1_packed();
        let s2_packed: [u8; S2_PACKED_LEN] = self.compute_s2_packed();

        let mut t1_packed = [0u8; T1_PACKED_LEN];
        debug_assert_eq!(T1_PACKED_LEN, POLY_T1PACKED_LEN * k);

        for i in 0..k {
            t1_packed[i * POLY_T1PACKED_LEN .. (i+1) * POLY_T1PACKED_LEN]
                .copy_from_slice(
                    &simple_bit_pack_t1(&self.compute_t1_row(i, &s1_packed, &s2_packed))
                );
        }

        MLDSAPublicKey::<k, T1_PACKED_LEN, PK_LEN>::new(&self.rho, &t1_packed)
    }

    fn sk_encode(&self) -> [u8; SK_LEN] {
       self.seed.ref_to_bytes().try_into().unwrap()
    }

    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.copy_from_slice(self.seed.ref_to_bytes());

        SK_LEN
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
        Self::from_bytes(sk).unwrap()
    }
}

pub(crate) trait MLDSAPrivateKeyInternalTrait<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> : Sized
{
    fn rho(&self) -> &[u8; 32];
    fn K(&self) -> &[u8; 32];

    fn compute_s1_row(
        &self,
        idx: usize,
    ) -> Polynomial;

    fn compute_s1_packed(&self) -> [u8; S1_PACKED_LEN];

    fn compute_s2_row(
        &self,
        idx: usize,
    ) -> Polynomial;

    fn compute_s2_packed(&self) -> [u8; S2_PACKED_LEN];

    fn compute_t0_row(
        &self,
        idx: usize,
        s1_packed: &[u8],
        s2_packed: &[u8],
    ) -> Polynomial;

    fn compute_t1_row(
        &self,
        idx: usize,
        s1_packed: &[u8],
        s2_packed: &[u8],
    ) -> Polynomial;
}

impl<
    const LAMBDA: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const eta: usize,
    const S1_PACKED_LEN: usize,
    const S2_PACKED_LEN: usize,
    const T1_PACKED_LEN: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
> MLDSAPrivateKeyInternalTrait<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, PK_LEN, SK_LEN>
for MLDSASeedPrivateKey<LAMBDA, GAMMA2, k, l, eta, S1_PACKED_LEN, S2_PACKED_LEN, T1_PACKED_LEN, PK_LEN, SK_LEN> {
    fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    fn K(&self) -> &[u8; 32] {
        &self.K
    }

    fn compute_s1_row(
        &self,
        idx: usize,
    ) -> Polynomial {
        debug_assert!(idx < l);
        rej_bounded_poly::<eta>(&self.rho_prime, &(idx as u16).to_le_bytes())
    }

    fn compute_s1_packed(&self) -> [u8; S1_PACKED_LEN] {
        let mut s1_packed = [0u8; S1_PACKED_LEN];
        for idx in 0..l {
            let s1_i = self.compute_s1_row(idx);
            bit_pack_eta::<eta>(&s1_i, &mut s1_packed[idx * bitlen_eta(eta)..(idx + 1) * bitlen_eta(eta)]);
        }
        s1_packed
    }

    fn compute_s2_row(
        &self,
        idx: usize,
    ) -> Polynomial {
        debug_assert!(idx < k);
        rej_bounded_poly::<eta>(&self.rho_prime, &((idx + l) as u16).to_le_bytes())
    }

    fn compute_s2_packed(&self) -> [u8; S2_PACKED_LEN] {
        let mut s2_packed = [0u8; S2_PACKED_LEN];
        for idx in 0..k {
            let s2_i = self.compute_s2_row(idx);
            bit_pack_eta::<eta>(&s2_i, &mut s2_packed[idx * bitlen_eta(eta)..(idx + 1) * bitlen_eta(eta)]);
        }
        s2_packed
    }

    fn compute_t0_row(
        &self,
        idx: usize,
        s1_packed: &[u8],
        s2_packed: &[u8],
    ) -> Polynomial {
        let mut t0 = self.compute_t_row(idx, s1_packed, s2_packed);
        for j in 0..N {
            (_, t0.0[j]) = power_2_round(t0.0[j]);
        }

        t0
    }

    fn compute_t1_row(
        &self,
        idx: usize,
        s1_packed: &[u8],
        s2_packed: &[u8],
    ) -> Polynomial {
        let mut t1 = self.compute_t_row(idx, s1_packed, s2_packed);
        for j in 0..N {
            (t1.0[j], _) = power_2_round(t1.0[j]);
        }

        t1
    }
}

