use crate::aux_functions::{
    bit_pack_eta, bit_pack_t0, bit_unpack_eta, bit_unpack_t0, bitlen_eta, expandA, inv_ntt_vec,
    ntt_vec, power_2_round_vec, simple_bit_pack_t1, simple_bit_unpack_t1,
};
use crate::matrix::Vector;
use crate::mldsa::H;
use crate::{ML_DSA_44_NAME, MLDSA44_ETA, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_k, MLDSA44_l};
use crate::{ML_DSA_65_NAME, MLDSA65_ETA, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_k, MLDSA65_l};
use crate::{ML_DSA_87_NAME, MLDSA87_ETA, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_k, MLDSA87_l};
use crate::{POLY_T0PACKED_LEN, POLY_T1PACKED_LEN, SEED_LEN};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::KeyMaterialSized;
use bouncycastle_core_interface::traits::{SignaturePublicKey, XOF};
use std::fmt;

/// An ML-DSA public key.
#[derive(Clone)]
pub struct MLDSAPublicKey<const k: usize, const PK_LEN: usize> {
    pub(crate) rho: [u8; SEED_LEN],
    pub(crate) t1: Vector<k>,
}

impl<const k: usize, const PK_LEN: usize> MLDSAPublicKey<k, PK_LEN> {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<k>) -> Self {
        Self { rho: rho.clone(), t1: t1.clone() }
    }

    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    pub fn pk_encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];

        pk[0..SEED_LEN].copy_from_slice(&self.rho);

        let (pk_chunks, last_chunk) = pk[SEED_LEN..].as_chunks_mut::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        // Potential optimization point:
        // these loops have no interaction between sequential iterations,
        // so could be replaced with some kind of threaded for construct.
        // This should be done carefully against benchmarks to make sure we're actually making a
        // performance improvement, and making sure that whatever multi-threading construst is used
        // falls back to sequential execution when not available (such as a no_std build).
        for (pk_chunk, t1_i) in pk_chunks.into_iter().zip(&self.t1.vec) {
            pk_chunk.copy_from_slice(&simple_bit_pack_t1(&t1_i));
        }

        pk
    }

    /// Algorithm 23 pkDecode(𝑝𝑘)
    /// Reverses the procedure pkEncode.
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    /// Output: 𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    pub fn pk_decode(pk: &[u8]) -> Result<Self, SignatureError> {
        if pk.len() != PK_LEN {
            return Err(SignatureError::DecodingError("Input is the incorrect length"));
        }

        let rho = pk[0..32].try_into().unwrap();
        let mut t1 = Vector::<k>::new();

        let (pk_chunks, last_chunk) = pk[32..].as_chunks::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t1_i, pk_chunk) in t1.vec.iter_mut().zip(pk_chunks) {
            t1_i.0.copy_from_slice(&simple_bit_unpack_t1(pk_chunk).0);
        }

        Ok(Self::new(&rho, &t1))
    }

    // todo -- these probably don't need to be pub anymore

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    pub fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&self.pk_encode(), &mut tr);

        tr
    }
}

impl<const k: usize, const PK_LEN: usize> PartialEq for MLDSAPublicKey<k, PK_LEN> {
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.pk_encode();
        let other_encoded = other.pk_encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<const k: usize, const PK_LEN: usize> fmt::Debug for MLDSAPublicKey<k, PK_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(f, "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.compute_tr(),)
    }
}

impl<const k: usize, const PK_LEN: usize> fmt::Display for MLDSAPublicKey<k, PK_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(f, "MLDSAPublicKey {{ alg: {}, pub_key_hash (tr): {:x?} }}", alg, self.compute_tr(),)
    }
}

impl<const k: usize, const PK_LEN: usize> SignaturePublicKey for MLDSAPublicKey<k, PK_LEN> {
    fn encode(&self) -> Vec<u8> {
        self.pk_encode().to_vec()
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
        Self::pk_decode(bytes)
    }
}

/// An ML-DSA private key.
#[derive(Clone)]
pub struct MLDSAPrivateKey<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    pub(crate) rho: [u8; 32],
    pub(crate) K: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s1: Vector<l>,
    pub(crate) s2: Vector<k>,
    pub(crate) t0: Vector<k>,
    pub(crate) seed: Option<KeyMaterialSized<32>>,
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<l>,
        s2: &Vector<k>,
        t0: &Vector<k>,
        seed: Option<KeyMaterialSized<32>>,
    ) -> Self {
        Self {
            rho: rho.clone(),
            K: K.clone(),
            tr: tr.clone(),
            s1: s1.clone(),
            s2: s2.clone(),
            t0: t0.clone(),
            seed: seed.clone(),
        }
    }

    pub fn has_seed(&self) -> bool {
        self.seed.is_some()
    }

    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.seed.clone()
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSAPublicKey<k, PK_LEN> {
        // 3: 𝐀 ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        let A_ntt = expandA::<k, l>(&self.rho);

        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let s1_ntt = ntt_vec::<l>(&self.s1);
        let mut t_ntt = A_ntt.matrix_vector_ntt(&s1_ntt);
        t_ntt.reduce();
        let mut t = inv_ntt_vec(&t_ntt);
        t.add_vector_ntt(&self.s2);
        t.conditional_add_q();

        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, _) = power_2_round_vec::<k>(&t);

        MLDSAPublicKey::<k, PK_LEN>::new(&self.rho, &t1)
    }

    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    pub fn sk_encode(&self) -> [u8; SK_LEN] {
        let mut sk = [0u8; SK_LEN];

        // bytes written counter
        let mut off: usize = 0;

        sk[0..32].copy_from_slice(&self.rho);
        sk[32..64].copy_from_slice(&self.K);
        sk[64..128].copy_from_slice(&self.tr);
        off += 128;

        // for i in 0..l {
        //     let mut tmp = [0u8; 32 * 4]; // largest possible buffer
        //     bit_pack_eta::<eta>(self.s1.vec[i], &mut tmp);
        //     let eta_pack_len = bitlen_eta(eta);
        //     sk[bw..bw + bitlen_eta(eta)].copy_from_slice(&tmp[..eta_pack_len]);
        //     bw += eta_pack_len;
        // }

        let mut buf = [0u8; 32 * 4]; // largest possible buffer
        let eta_pack_len = bitlen_eta(eta);

        let sk_chunks = sk[off..off + l * bitlen_eta(eta)].chunks_mut(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), l);
        for (sk_chunk, s1_i) in sk_chunks.into_iter().zip(&self.s1.vec) {
            bit_pack_eta::<eta>(s1_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += l * bitlen_eta(eta);

        // // that should divide evenly the remainder of the array
        // debug_assert_eq!(pk_chunks.len(), k);
        // debug_assert_eq!(last_chunk.len(), 0);
        // for i in 0..k {
        //     let mut tmp = [0u8; 32 * 4]; // largest possible buffer
        //     bit_pack_eta::<eta>(self.s2.vec[i], &mut tmp);
        //     let eta_pack_len = bitlen_eta(eta);
        //     sk[bw..bw + bitlen_eta(eta)].copy_from_slice(&tmp[..eta_pack_len]);
        //     bw += eta_pack_len;
        // }
        let sk_chunks = sk[off..off + k * bitlen_eta(eta)].chunks_mut(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, s2_i) in sk_chunks.into_iter().zip(&self.s2.vec) {
            bit_pack_eta::<eta>(s2_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += k * bitlen_eta(eta);

        // for i in 0..k {
        //     sk[off..off + POLY_T0PACKED_LEN].copy_from_slice(&bitpack_t0(self.t0.vec[i]));
        //     off += POLY_T0PACKED_LEN;
        // }
        let sk_chunks = sk[off..off + k * POLY_T0PACKED_LEN].chunks_mut(POLY_T0PACKED_LEN);
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, t0_i) in sk_chunks.into_iter().zip(&self.t0.vec) {
            sk_chunk.copy_from_slice(&bit_pack_t0(t0_i));
        }

        sk
    }

    /// Algorithm 25 skDecode(𝑠𝑘)
    /// Reverses the procedure skEncode.
    /// Input: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((ℓ+𝑘)⋅bitlen (2𝜂)+𝑑𝑘).
    /// Output: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 ,
    /// 𝐬1 ∈ 𝑅ℓ , 𝐬2 ∈ 𝑅𝑘 , 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    ///
    /// Note: this object contains only the simple decoding routine to unpack a semi-expanded key.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    // pub fn sk_decode(sk: &[u8; SK_LEN]) -> Result<Self, SignatureError> {
    pub fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
        let rho = sk[0..32].try_into().unwrap();
        let K = sk[32..64].try_into().unwrap();
        let tr = sk[64..128].try_into().unwrap();
        let mut s1 = Vector::<l>::new();
        let mut s2 = Vector::<k>::new();
        let mut t0 = Vector::<k>::new();
        let mut off = 128;

        // unpack s1
        // let mut i: usize = 0;
        let sk_chunks = sk[128..128 + (l * bitlen_eta(eta))].chunks(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), l);
        // for sk_chunk in sk_chunks {
        //     s1.vec[i] = bit_unpack_eta::<eta>(&sk_chunk);
        //     i += 1;
        //     debug_assert!(i < l);
        // }
        for (s1_i, sk_chunk) in s1.vec.iter_mut().zip(sk_chunks) {
            s1_i.0.copy_from_slice(&bit_unpack_eta::<eta>(&sk_chunk).0);
        }
        off += l * bitlen_eta(eta);

        // unpack s2
        // let mut i: usize = 0;
        // let off = 128 + (l * bitlen_eta(eta));
        let sk_chunks = sk[off..off + (k * bitlen_eta(eta))].chunks(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), k);
        // for sk_chunk in sk_chunks {
        //     s2.vec[i] = bit_unpack_eta::<eta>(&sk_chunk);
        //     i += 1;
        //     debug_assert!(i < k);
        // }
        for (s2_i, sk_chunk) in s2.vec.iter_mut().zip(sk_chunks) {
            s2_i.0.copy_from_slice(&bit_unpack_eta::<eta>(&sk_chunk).0);
        }
        off += k * bitlen_eta(eta);

        // unpack t0
        // let mut i: usize = 0;
        // let off = off + (k * bitlen_eta(eta));
        let (sk_chunks, last_chunk) =
            sk[off..off + (k * POLY_T0PACKED_LEN)].as_chunks::<POLY_T0PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(sk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        // for sk_chunk in sk_chunks {
        //     t0.vec[i] = bit_unpack_eta::<eta>(&sk_chunk);
        //     i += 1;
        //     debug_assert!(i < k);
        // }
        for (t0_i, sk_chunk) in t0.vec.iter_mut().zip(sk_chunks) {
            t0_i.0.copy_from_slice(&bit_unpack_t0(sk_chunk).0);
        }

        Self::new(&rho, &K, &tr, &s1, &s2, &t0, None)
    }
}

// todo -- implement SignaturePrivateKey abstraction layer
// impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
//     SignaturePrivateKey for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
// {
//     fn encode(&self) -> Vec<u8> {
//         self.sk_encode().to_vec()
//     }
//
//     fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
//         if out.len() < SK_LEN {
//             Err(SignatureError::EncodingError("Output buffer too small"))
//         } else {
//             let tmp = self.sk_encode();
//             debug_assert_eq!(tmp.len(), SK_LEN);
//             out[..SK_LEN].copy_from_slice(&tmp);
//             Ok(SK_LEN)
//         }
//     }
//
//     /// Note: this does not perform any consistency checks, so importing a malformed key will
//     /// give you a valid-looking private key that will blow up when you try to use it.
//     fn from_bytes(sk_bytes: &[u8]) -> Result<Self, SignatureError> {
//         Self::sk_decode(sk_bytes)
//     }
// }

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    PartialEq for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.sk_encode();
        let other_encoded = other.sk_encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    fmt::Debug for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            alg,
            self.tr,
            self.has_seed(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    fmt::Display for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let alg = match k {
            4 => ML_DSA_44_NAME,
            6 => ML_DSA_65_NAME,
            8 => ML_DSA_87_NAME,
            _ => panic!("Unsupported key length"),
        };
        write!(
            f,
            "MLDSAPrivateKey {{ alg: {}, pub_key_hash (tr): {:x?}, has_seed: {} }}",
            alg,
            self.tr,
            self.has_seed(),
        )
    }
}

/// Zeroizing drop
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    Drop for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn drop(&mut self) {
        self.K.fill(0u8);
        // s1, s2, t0, seed have their own zeroizing drop
    }
}

/*** Public Key Struct defs ***/

/// ML-DSA-44 public key
pub struct MLDSA44PublicKey(pub(crate) MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>);

impl From<MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>>
for MLDSA44PublicKey {
    fn from(pk: MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>) -> Self {
        Self(pk)
    }
}

impl MLDSA44PublicKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<MLDSA44_k>) -> Self {
        Self(MLDSAPublicKey::<MLDSA44_k, MLDSA44_PK_LEN>::new(rho, t1))
    }

    /// Encode the public key
    pub fn encode(&self) -> [u8; MLDSA44_PK_LEN] {
        self.0.pk_encode()
    }

    pub fn decode(pk: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(MLDSAPublicKey::<MLDSA44_k, MLDSA44_PK_LEN>::pk_decode(pk)?))
    }

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    pub fn compute_tr(&self) -> [u8; 64] {
        self.0.compute_tr()
    }
}

/// ML-DSA-65 public key
pub struct MLDSA65PublicKey(pub(crate) MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>);

impl From<MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>>
for MLDSA65PublicKey {
    fn from(pk: MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>) -> Self {
        Self(pk)
    }
}

impl MLDSA65PublicKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<MLDSA65_k>) -> Self {
        Self(MLDSAPublicKey::<MLDSA65_k, MLDSA65_PK_LEN>::new(rho, t1))
    }

    /// Encode the public key
    pub fn encode(&self) -> [u8; MLDSA65_PK_LEN] {
        self.0.pk_encode()
    }

    pub fn decode(pk: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(MLDSAPublicKey::<MLDSA65_k, MLDSA65_PK_LEN>::pk_decode(pk)?))
    }

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    pub fn compute_tr(&self) -> [u8; 64] {
        self.0.compute_tr()
    }
}

/// ML-DSA-87 public key
pub struct MLDSA87PublicKey(pub(crate) MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>);

impl From<MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>>
for MLDSA87PublicKey {
    fn from(pk: MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>) -> Self {
        Self(pk)
    }
}

impl MLDSA87PublicKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<MLDSA87_k>) -> Self {
        Self(MLDSAPublicKey::<MLDSA87_k, MLDSA87_PK_LEN>::new(rho, t1))
    }

    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn from_pk(pk: MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>) -> Self {
        Self(MLDSAPublicKey::<MLDSA87_k, MLDSA87_PK_LEN>::new(&pk.rho, &pk.t1))
    }

    /// Encode the public key into the standard byte serialization.
    pub fn encode(&self) -> [u8; MLDSA87_PK_LEN] {
        self.0.pk_encode()
    }

    /// Decode the public key from the standard byte serialization.
    pub fn decode(pk: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self::from_pk(MLDSAPublicKey::<MLDSA87_k, MLDSA87_PK_LEN>::pk_decode(pk)?))
    }

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    pub fn compute_tr(&self) -> [u8; 64] {
        self.0.compute_tr()
    }
}

/*** Private Key Struct defs ***/

/// ML-DSA-44 Private Key
pub struct MLDSA44PrivateKey(
    pub(crate) MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>,
);

impl From<MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>>
for MLDSA44PrivateKey {
    fn from(sk: MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>) -> Self {
        Self(sk)
    }
}

impl MLDSA44PrivateKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<MLDSA44_l>,
        s2: &Vector<MLDSA44_k>,
        t0: &Vector<MLDSA44_k>,
        seed: Option<KeyMaterialSized<32>>,
    ) -> Self {
        Self(MLDSAPrivateKey::<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>::new(
            rho, K, tr, s1, s2, t0, seed
        ))
    }

    /// Does this ML-DSA Private Key contain a seed value?
    pub fn has_seed(&self) -> bool {
        self.0.has_seed()
    }

    /// If this ML-DSA Private Key contains a seed, then return it, otherwise return None
    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.0.get_seed()
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSA44PublicKey {
        let pk = self.0.derive_public_key();
        MLDSA44PublicKey::new(&pk.rho, &pk.t1)
    }

    /// Encode the private key into the standard byte serialization.
    pub fn encode(&self) -> [u8; MLDSA44_SK_LEN] {
        self.0.sk_encode()
    }

    /// Decode the public key from the standard byte serialization.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    pub fn sk_decode(sk: &[u8; MLDSA44_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>::sk_decode(sk))
    }
}

/// ML-DSA-65 Private Key
pub struct MLDSA65PrivateKey(
    pub(crate) MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>,
);

// todo -- did these end up getting used?
impl From<MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>>
for MLDSA65PrivateKey {
    fn from(sk: MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>) -> Self {
        Self(sk)
    }
}

impl MLDSA65PrivateKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<MLDSA65_l>,
        s2: &Vector<MLDSA65_k>,
        t0: &Vector<MLDSA65_k>,
        seed: Option<KeyMaterialSized<32>>,
    ) -> Self {
        Self(MLDSAPrivateKey::<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>::new(
            rho, K, tr, s1, s2, t0, seed
        ))
    }

    /// Does this ML-DSA Private Key contain a seed value?
    pub fn has_seed(&self) -> bool {
        self.0.has_seed()
    }

    /// If this ML-DSA Private Key contains a seed, then return it, otherwise return None
    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.0.get_seed()
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSA65PublicKey {
        let pk = self.0.derive_public_key();
        MLDSA65PublicKey::new(&pk.rho, &pk.t1)
    }

    /// Encode the private key into the standard byte serialization.
    pub fn encode(&self) -> [u8; MLDSA65_SK_LEN] {
        self.0.sk_encode()
    }

    /// Decode the public key from the standard byte serialization.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    pub fn sk_decode(sk: &[u8; MLDSA65_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>::sk_decode(sk))
    }
}

/// ML-DSA-87 Private Key
pub struct MLDSA87PrivateKey(
    pub(crate) MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>,
);

impl From<MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>>
for MLDSA87PrivateKey {
    fn from(sk: MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>) -> Self {
        Self(sk)
    }
}

impl MLDSA87PrivateKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<MLDSA87_l>,
        s2: &Vector<MLDSA87_k>,
        t0: &Vector<MLDSA87_k>,
        seed: Option<KeyMaterialSized<32>>,
    ) -> Self {
        Self(MLDSAPrivateKey::<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>::new(
            rho, K, tr, s1, s2, t0, seed
        ))
    }

    /// Does this ML-DSA Private Key contain a seed value?
    pub fn has_seed(&self) -> bool {
        self.0.has_seed()
    }

    /// If this ML-DSA Private Key contains a seed, then return it, otherwise return None
    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.0.get_seed()
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSA87PublicKey {
        let pk = self.0.derive_public_key();
        MLDSA87PublicKey::new(&pk.rho, &pk.t1)
    }

    /// Encode the private key into the standard byte serialization.
    pub fn encode(&self) -> [u8; MLDSA87_SK_LEN] {
        self.0.sk_encode()
    }

    /// Decode the public key from the standard byte serialization.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    pub fn sk_decode(sk: &[u8; MLDSA87_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>::sk_decode(sk))
    }
}
