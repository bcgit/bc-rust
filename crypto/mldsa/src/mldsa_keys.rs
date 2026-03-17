use std::fmt;
use std::vec::Vec;

use crate::aux_functions::{
    bit_pack_eta, bit_pack_t0, bit_unpack_eta, bitlen_eta, inv_ntt, ntt, power_2_round,
    rej_bounded_poly, rej_ntt_poly, simple_bit_pack_t1, simple_bit_unpack_t1,
};
use crate::matrix::Vector;
use crate::mldsa::H;
use crate::mldsa::{
    MLDSA44_COMPACT_SK_LEN, MLDSA44_ETA, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_k, MLDSA44_l,
    expand_key_seed_material,
};
use crate::mldsa::{
    MLDSA65_COMPACT_SK_LEN, MLDSA65_ETA, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_k, MLDSA65_l,
};
use crate::mldsa::{
    MLDSA87_COMPACT_SK_LEN, MLDSA87_ETA, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_k, MLDSA87_l,
};
use crate::mldsa::{POLY_T0PACKED_LEN, POLY_T1PACKED_LEN, SEED_LEN};
use crate::polynomial;
use crate::polynomial::Polynomial;
use crate::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::KeyMaterialSized;
use bouncycastle_core_interface::traits::{
    Secret, SignaturePrivateKey, SignaturePublicKey, XOF,
};

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
        // performance improvement, and making sure that whatever multi-threading construct is used
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
    pub fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        let rho = pk[0..32].try_into().unwrap();
        let mut t1 = Vector::<k>::new();

        let (pk_chunks, last_chunk) = pk[32..].as_chunks::<POLY_T1PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t1_i, pk_chunk) in t1.vec.iter_mut().zip(pk_chunks) {
            t1_i.0.copy_from_slice(&simple_bit_unpack_t1(pk_chunk).0);
        }

        Self::new(&rho, &t1)
    }

    /// Compute the public key hash (tr) from the public key.
    ///
    /// This is exposed as a public API for a few reasons:
    /// 1. `tr` is required for some external-prehashing schemes such as the so-called "external mu" signing mode.
    /// 2. `tr` is the canonical fingerprint of an ML-DSA public key, so would be an appropriate value
    ///     to use, for example, to build a public key lookup or deny-listing table.
    pub(crate) fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        let mut h = H::new();
        h.absorb(&self.rho);
        for t1_i in &self.t1.vec {
            h.absorb(&simple_bit_pack_t1(t1_i));
        }
        h.squeeze_out(&mut tr);

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

impl<const k: usize, const PK_LEN: usize> fmt::Display for MLDSAPublicKey<k, PK_LEN> {
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

/// An ML-DSA private key.
#[derive(Clone)]
pub struct MLDSAPrivateKey<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> {
    pub(crate) rho: [u8; 32],
    pub(crate) K: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) compact_bytes: Option<[u8; COMPACT_SK_LEN]>,
    pub(crate) seed: Option<KeyMaterialSized<32>>,
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
{
    fn pack_compact_bytes(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<l>,
        s2: &Vector<k>,
    ) -> [u8; COMPACT_SK_LEN] {
        let mut sk = [0u8; COMPACT_SK_LEN];
        let mut off = 0usize;
        let eta_pack_len = bitlen_eta(eta);
        let mut buf = [0u8; 32 * 4];

        sk[0..32].copy_from_slice(rho);
        sk[32..64].copy_from_slice(K);
        sk[64..128].copy_from_slice(tr);
        off += 128;

        let sk_chunks = sk[off..off + l * eta_pack_len].chunks_mut(eta_pack_len);
        debug_assert_eq!(sk_chunks.len(), l);
        for (sk_chunk, s1_i) in sk_chunks.into_iter().zip(&s1.vec) {
            bit_pack_eta::<eta>(s1_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += l * eta_pack_len;

        let sk_chunks = sk[off..off + k * eta_pack_len].chunks_mut(eta_pack_len);
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, s2_i) in sk_chunks.into_iter().zip(&s2.vec) {
            bit_pack_eta::<eta>(s2_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }

        sk
    }

    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<l>,
        s2: &Vector<k>,
        _t0: &Vector<k>,
        seed: Option<KeyMaterialSized<32>>,
    ) -> Self {
        Self {
            rho: rho.clone(),
            K: K.clone(),
            tr: tr.clone(),
            compact_bytes: Some(Self::pack_compact_bytes(rho, K, tr, s1, s2)),
            seed: seed.clone(),
        }
    }

    pub fn has_seed(&self) -> bool {
        self.seed.is_some()
    }

    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.seed.clone()
    }

    pub fn has_t0(&self) -> bool {
        false
    }

    pub(crate) fn seed_rho_prime(&self) -> Result<[u8; 64], SignatureError> {
        let seed = self.seed.as_ref().ok_or(SignatureError::KeyGenError(
            "Private key does not contain enough material to reconstruct s1 and s2",
        ))?;
        let (rho, rho_prime, K) = expand_key_seed_material::<k, l>(seed);
        debug_assert_eq!(rho, self.rho);
        debug_assert_eq!(K, self.K);
        Ok(rho_prime)
    }

    pub(crate) fn s1_poly(
        &self,
        idx: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Polynomial, SignatureError> {
        debug_assert!(idx < l);
        if let Some(compact) = &self.compact_bytes {
            let eta_pack_len = bitlen_eta(eta);
            let off = 128 + idx * eta_pack_len;
            Ok(bit_unpack_eta::<eta>(&compact[off..off + eta_pack_len]))
        } else {
            let rho_prime = rho_prime.ok_or(SignatureError::KeyGenError(
                "Missing rho_prime for seed-only key reconstruction",
            ))?;
            Ok(rej_bounded_poly::<eta>(rho_prime, &(idx as u16).to_le_bytes()))
        }
    }

    pub(crate) fn s2_poly(
        &self,
        idx: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Polynomial, SignatureError> {
        debug_assert!(idx < k);
        if let Some(compact) = &self.compact_bytes {
            let eta_pack_len = bitlen_eta(eta);
            let off = 128 + l * eta_pack_len + idx * eta_pack_len;
            Ok(bit_unpack_eta::<eta>(&compact[off..off + eta_pack_len]))
        } else {
            let rho_prime = rho_prime.ok_or(SignatureError::KeyGenError(
                "Missing rho_prime for seed-only key reconstruction",
            ))?;
            Ok(rej_bounded_poly::<eta>(rho_prime, &((idx + l) as u16).to_le_bytes()))
        }
    }

    pub(crate) fn compute_t_row(
        &self,
        row: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Polynomial, SignatureError> {
        debug_assert!(row < k);

        let mut s1 = self.s1_poly(0, rho_prime)?;
        let s1_hat = ntt(&s1);
        let mut t_hat =
            polynomial::multiply_ntt(&rej_ntt_poly(&self.rho, &[0u8, row as u8]), &s1_hat);

        for col in 1..l {
            s1 = self.s1_poly(col, rho_prime)?;
            let s1_hat = ntt(&s1);
            let tmp = polynomial::multiply_ntt(
                &rej_ntt_poly(&self.rho, &[col as u8, row as u8]),
                &s1_hat,
            );
            t_hat.add_ntt(&tmp);
        }

        polynomial::reduce_poly(&mut t_hat);
        let mut t = inv_ntt(&t_hat);
        let s2 = self.s2_poly(row, rho_prime)?;
        t.add_ntt(&s2);
        t.conditional_add_q();

        Ok(t)
    }

    pub(crate) fn derive_t1_row(
        &self,
        row: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Polynomial, SignatureError> {
        let t = self.compute_t_row(row, rho_prime)?;
        let mut t1 = Polynomial::new();
        for i in 0..crate::mldsa::N {
            let (hi, _) = power_2_round(t.0[i]);
            t1.0[i] = hi;
        }

        Ok(t1)
    }

    pub(crate) fn compute_tr_from_rows(
        &self,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<[u8; 64], SignatureError> {
        let mut h = H::new();
        h.absorb(&self.rho);

        for row in 0..k {
            let t1_i = self.derive_t1_row(row, rho_prime)?;
            h.absorb(&simple_bit_pack_t1(&t1_i));
        }

        let mut tr = [0u8; 64];
        h.squeeze_out(&mut tr);
        Ok(tr)
    }

    pub(crate) fn pk_encode_rows_into(
        &self,
        rho_prime: Option<&[u8; 64]>,
        output: &mut [u8; PK_LEN],
    ) -> Result<[u8; 64], SignatureError> {
        output[..SEED_LEN].copy_from_slice(&self.rho);

        let mut h = H::new();
        h.absorb(&self.rho);

        let (pk_chunks, last_chunk) = output[SEED_LEN..].as_chunks_mut::<POLY_T1PACKED_LEN>();
        debug_assert_eq!(pk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (row, pk_chunk) in pk_chunks.into_iter().enumerate() {
            let t1_i = self.derive_t1_row(row, rho_prime)?;
            let packed = simple_bit_pack_t1(&t1_i);
            pk_chunk.copy_from_slice(&packed);
            h.absorb(&packed);
        }

        let mut tr = [0u8; 64];
        h.squeeze_out(&mut tr);
        Ok(tr)
    }

    pub(crate) fn derive_t0_row(
        &self,
        row: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<Polynomial, SignatureError> {
        let t = self.compute_t_row(row, rho_prime)?;
        let mut t0 = Polynomial::new();
        for i in 0..crate::mldsa::N {
            let (_, lo) = power_2_round(t.0[i]);
            t0.0[i] = lo;
        }

        Ok(t0)
    }

    pub(crate) fn derive_t_row(
        &self,
        row: usize,
        rho_prime: Option<&[u8; 64]>,
    ) -> Result<(Polynomial, Polynomial), SignatureError> {
        let t = self.compute_t_row(row, rho_prime)?;

        let mut t1 = Polynomial::new();
        let mut t0 = Polynomial::new();
        for i in 0..crate::mldsa::N {
            let (hi, lo) = power_2_round(t.0[i]);
            t1.0[i] = hi;
            t0.0[i] = lo;
        }

        Ok((t1, t0))
    }

    fn recover_s1_s2(&self) -> Result<(Vector<l>, Vector<k>), SignatureError> {
        let rho_prime =
            if self.compact_bytes.is_none() { Some(self.seed_rho_prime()?) } else { None };
        let rho_prime_ref = rho_prime.as_ref();
        let mut s1 = Vector::<l>::new();
        let mut s2 = Vector::<k>::new();

        for i in 0..l {
            s1.vec[i] = self.s1_poly(i, rho_prime_ref)?;
        }
        for i in 0..k {
            s2.vec[i] = self.s2_poly(i, rho_prime_ref)?;
        }

        Ok((s1, s2))
    }

    pub(crate) fn recover_signing_state(
        &self,
    ) -> Result<(Vector<l>, Vector<k>, Vector<k>), SignatureError> {
        let (s1, s2) = self.recover_s1_s2()?;
        let rho_prime =
            if self.compact_bytes.is_none() { Some(self.seed_rho_prime()?) } else { None };
        let rho_prime_ref = rho_prime.as_ref();
        let mut t0 = Vector::<k>::new();
        for row in 0..k {
            t0.vec[row] = self.derive_t0_row(row, rho_prime_ref)?;
        }

        Ok((s1, s2, t0))
    }

    pub fn to_compact(&self) -> Self {
        Self {
            rho: self.rho,
            K: self.K,
            tr: self.tr,
            compact_bytes: Some(self.compact_encode()),
            seed: None,
        }
    }

    pub fn to_seed_only(&self) -> Result<Self, SignatureError> {
        let seed = self
            .seed
            .clone()
            .ok_or(SignatureError::KeyGenError("Private key does not contain a seed"))?;

        Ok(Self { rho: self.rho, K: self.K, tr: self.tr, compact_bytes: None, seed: Some(seed) })
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSAPublicKey<k, PK_LEN> {
        let rho_prime =
            if self.compact_bytes.is_none() {
                Some(self.seed_rho_prime().expect(
                    "ML-DSA private key must contain enough material to derive the public key",
                ))
            } else {
                None
            };
        let rho_prime_ref = rho_prime.as_ref();
        let mut t1 = Vector::<k>::new();
        for row in 0..k {
            t1.vec[row] = self
                .derive_t1_row(row, rho_prime_ref)
                .expect("ML-DSA private key must contain enough material to derive the public key");
        }

        MLDSAPublicKey::<k, PK_LEN>::new(&self.rho, &t1)
    }

    /// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
    /// Encodes a secret key for ML-DSA into a byte string.
    /// Input: 𝜌 ∈ 𝔹32, 𝐾 ∈ 𝔹32, 𝑡𝑟 ∈ 𝔹64 , 𝐬1 ∈ 𝑅ℓ with coefficients in [−𝜂, 𝜂], 𝐬2 ∈ 𝑅𝑘 with
    /// coefficients in [−𝜂, 𝜂], 𝐭0 ∈ 𝑅𝑘 with coefficients in [−2𝑑−1 + 1, 2𝑑−1].
    /// Output: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘).
    pub fn sk_encode(&self) -> [u8; SK_LEN] {
        let mut sk = [0u8; SK_LEN];
        let compact = self.compact_encode();
        let rho_prime = if self.compact_bytes.is_none() {
            Some(self.seed_rho_prime().expect(
                "ML-DSA private key must contain enough material to encode the standard secret key",
            ))
        } else {
            None
        };
        let rho_prime_ref = rho_prime.as_ref();

        // bytes written counter
        let mut off: usize = 0;

        sk[0..32].copy_from_slice(&self.rho);
        sk[32..64].copy_from_slice(&self.K);
        sk[64..128].copy_from_slice(&self.tr);
        off += 128;
        sk[off..off + (COMPACT_SK_LEN - 128)].copy_from_slice(&compact[128..]);
        off += COMPACT_SK_LEN - 128;

        let sk_chunks = sk[off..off + k * POLY_T0PACKED_LEN].chunks_mut(POLY_T0PACKED_LEN);
        debug_assert_eq!(sk_chunks.len(), k);
        for (row, sk_chunk) in sk_chunks.into_iter().enumerate() {
            let t0_i = self.derive_t0_row(row, rho_prime_ref).expect(
                "ML-DSA private key must contain enough material to encode the standard secret key",
            );
            sk_chunk.copy_from_slice(&bit_pack_t0(&t0_i));
        }

        sk
    }

    pub(crate) fn compact_encode(&self) -> [u8; COMPACT_SK_LEN] {
        if let Some(compact) = self.compact_bytes {
            compact
        } else {
            let rho_prime = self
                .seed_rho_prime()
                .expect("ML-DSA private key must contain enough material to encode a compact key");
            let mut sk = [0u8; COMPACT_SK_LEN];
            let mut off = 0usize;
            let eta_pack_len = bitlen_eta(eta);
            let mut buf = [0u8; 32 * 4];

            sk[0..32].copy_from_slice(&self.rho);
            sk[32..64].copy_from_slice(&self.K);
            sk[64..128].copy_from_slice(&self.tr);
            off += 128;

            let sk_chunks = sk[off..off + l * eta_pack_len].chunks_mut(eta_pack_len);
            debug_assert_eq!(sk_chunks.len(), l);
            for (idx, sk_chunk) in sk_chunks.into_iter().enumerate() {
                let s1_i = rej_bounded_poly::<eta>(&rho_prime, &(idx as u16).to_le_bytes());
                bit_pack_eta::<eta>(&s1_i, &mut buf);
                sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
            }
            off += l * eta_pack_len;

            let sk_chunks = sk[off..off + k * eta_pack_len].chunks_mut(eta_pack_len);
            debug_assert_eq!(sk_chunks.len(), k);
            for (idx, sk_chunk) in sk_chunks.into_iter().enumerate() {
                let s2_i = rej_bounded_poly::<eta>(&rho_prime, &((idx + l) as u16).to_le_bytes());
                bit_pack_eta::<eta>(&s2_i, &mut buf);
                sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
            }

            sk
        }
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
        let mut compact = [0u8; COMPACT_SK_LEN];
        compact.copy_from_slice(&sk[..COMPACT_SK_LEN]);

        Self { rho, K, tr, compact_bytes: Some(compact), seed: None }
    }

    pub(crate) fn compact_decode(sk: &[u8; COMPACT_SK_LEN]) -> Self {
        let rho = sk[0..32].try_into().unwrap();
        let K = sk[32..64].try_into().unwrap();
        let tr = sk[64..128].try_into().unwrap();
        Self { rho, K, tr, compact_bytes: Some(*sk), seed: None }
    }
}

// todo -- implement SignaturePrivateKey abstraction layer
// impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize, const COMPACT_SK_LEN: usize>
//     SignaturePrivateKey for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
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

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> PartialEq for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.sk_encode();
        let other_encoded = other.sk_encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> Secret for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
{
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> fmt::Debug for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> fmt::Display for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const COMPACT_SK_LEN: usize,
> Drop for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN, COMPACT_SK_LEN>
{
    fn drop(&mut self) {
        self.K.fill(0u8);
        if let Some(compact) = self.compact_bytes.as_mut() {
            compact.fill(0u8);
        }
        // seed has its own zeroizing drop
    }
}

/*** Public Key Struct defs ***/

/// ML-DSA-44 public key
#[derive(Debug)]
pub struct MLDSA44PublicKey(pub(crate) MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>);

impl From<MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>> for MLDSA44PublicKey {
    fn from(pk: MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>) -> Self {
        Self(pk)
    }
}

/// Strictly speaking, public keys are public data, so don't need a constant-time equality check, but
/// we'll add one anyway because there may be cases where this saves a CVE.
impl PartialEq for MLDSA44PublicKey {
    fn eq(&self, other: &MLDSA44PublicKey) -> bool {
        self.0 == other.0
    }
}

impl MLDSA44PublicKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<MLDSA44_k>) -> Self {
        Self(MLDSAPublicKey::<MLDSA44_k, MLDSA44_PK_LEN>::new(rho, t1))
    }

    /// Encode the public key
    pub fn pk_encode(&self) -> [u8; MLDSA44_PK_LEN] {
        self.0.pk_encode()
    }

    pub fn pk_decode(pk: &[u8; MLDSA44_PK_LEN]) -> Self {
        Self(MLDSAPublicKey::<MLDSA44_k, MLDSA44_PK_LEN>::pk_decode(pk))
    }

    /// Decode the public key from the standard byte serialization.
    pub fn from_pk_bytes(bytes: &[u8; MLDSA44_PK_LEN]) -> Self {
        Self::pk_decode(bytes)
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

impl SignaturePublicKey for MLDSA44PublicKey {
    fn encode(&self) -> Vec<u8> {
        self.0.pk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < MLDSA44_PK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.0.pk_encode();
            debug_assert_eq!(tmp.len(), MLDSA44_PK_LEN);
            out[..MLDSA44_PK_LEN].copy_from_slice(&tmp);
            Ok(MLDSA44_PK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sized_bytes: [u8; MLDSA44_PK_LEN] = match bytes[..MLDSA44_PK_LEN].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(SignatureError::DecodingError(
                    "Provided bytes are the incorrect length",
                ));
            }
        };
        Ok(Self::pk_decode(&sized_bytes))
    }
}

/// ML-DSA-65 public key
#[derive(Debug)]
pub struct MLDSA65PublicKey(pub(crate) MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>);

impl From<MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>> for MLDSA65PublicKey {
    fn from(pk: MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>) -> Self {
        Self(pk)
    }
}

/// Strictly speaking, public keys are public data, so don't need a constant-time equality check, but
/// we'll add one anyway because there may be cases where this saves a CVE.
impl PartialEq for MLDSA65PublicKey {
    fn eq(&self, other: &MLDSA65PublicKey) -> bool {
        self.0 == other.0
    }
}

impl MLDSA65PublicKey {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<MLDSA65_k>) -> Self {
        Self(MLDSAPublicKey::<MLDSA65_k, MLDSA65_PK_LEN>::new(rho, t1))
    }

    /// Encode the public key
    pub fn pk_encode(&self) -> [u8; MLDSA65_PK_LEN] {
        self.0.pk_encode()
    }

    /// Decode the public key from the standard byte serialization.
    pub fn pk_decode(pk: &[u8; MLDSA65_PK_LEN]) -> Self {
        Self(MLDSAPublicKey::<MLDSA65_k, MLDSA65_PK_LEN>::pk_decode(pk))
    }

    pub fn from_pk_bytes(bytes: &[u8; MLDSA65_PK_LEN]) -> Self {
        Self::pk_decode(bytes)
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

impl SignaturePublicKey for MLDSA65PublicKey {
    fn encode(&self) -> Vec<u8> {
        self.0.pk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < MLDSA65_PK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.0.pk_encode();
            debug_assert_eq!(tmp.len(), MLDSA65_PK_LEN);
            out[..MLDSA65_PK_LEN].copy_from_slice(&tmp);
            Ok(MLDSA65_PK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sized_bytes: [u8; MLDSA65_PK_LEN] = match bytes[..MLDSA65_PK_LEN].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(SignatureError::DecodingError(
                    "Provided bytes are the incorrect length",
                ));
            }
        };
        Ok(Self::pk_decode(&sized_bytes))
    }
}

/// ML-DSA-87 public key
#[derive(Debug)]
pub struct MLDSA87PublicKey(pub(crate) MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>);

impl From<MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>> for MLDSA87PublicKey {
    fn from(pk: MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>) -> Self {
        Self(pk)
    }
}

/// Strictly speaking, public keys are public data, so don't need a constant-time equality check, but
/// we'll add one anyway because there may be cases where this saves a CVE.
impl PartialEq for MLDSA87PublicKey {
    fn eq(&self, other: &MLDSA87PublicKey) -> bool {
        self.0 == other.0
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
    pub fn pk_encode(&self) -> [u8; MLDSA87_PK_LEN] {
        self.0.pk_encode()
    }

    /// Decode the public key from the standard byte serialization.
    pub fn pk_decode(pk: &[u8; MLDSA87_PK_LEN]) -> Self {
        Self::from_pk(MLDSAPublicKey::<MLDSA87_k, MLDSA87_PK_LEN>::pk_decode(pk))
    }

    /// Decode the public key from the standard byte serialization.
    pub fn from_pk_bytes(bytes: &[u8; MLDSA87_PK_LEN]) -> Self {
        Self::pk_decode(bytes)
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

impl SignaturePublicKey for MLDSA87PublicKey {
    fn encode(&self) -> Vec<u8> {
        self.0.pk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < MLDSA87_PK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.0.pk_encode();
            debug_assert_eq!(tmp.len(), MLDSA87_PK_LEN);
            out[..MLDSA87_PK_LEN].copy_from_slice(&tmp);
            Ok(MLDSA87_PK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sized_bytes: [u8; MLDSA87_PK_LEN] = match bytes[..MLDSA87_PK_LEN].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(SignatureError::DecodingError(
                    "Provided bytes are the incorrect length",
                ));
            }
        };
        Ok(Self::pk_decode(&sized_bytes))
    }
}

/*** Private Key Struct defs ***/

/// ML-DSA-44 Private Key
#[derive(Debug)] // should be safe because the inner structure impls Debug and won't dump private key contents
pub struct MLDSA44PrivateKey(
    pub(crate)  MLDSAPrivateKey<
        MLDSA44_k,
        MLDSA44_l,
        MLDSA44_ETA,
        MLDSA44_SK_LEN,
        MLDSA44_PK_LEN,
        MLDSA44_COMPACT_SK_LEN,
    >,
);

impl
    From<
        MLDSAPrivateKey<
            MLDSA44_k,
            MLDSA44_l,
            MLDSA44_ETA,
            MLDSA44_SK_LEN,
            MLDSA44_PK_LEN,
            MLDSA44_COMPACT_SK_LEN,
        >,
    > for MLDSA44PrivateKey
{
    fn from(
        sk: MLDSAPrivateKey<
            MLDSA44_k,
            MLDSA44_l,
            MLDSA44_ETA,
            MLDSA44_SK_LEN,
            MLDSA44_PK_LEN,
            MLDSA44_COMPACT_SK_LEN,
        >,
    ) -> Self {
        Self(sk)
    }
}

/// Constant-time equality check of the private key data.
impl PartialEq for MLDSA44PrivateKey {
    fn eq(&self, other: &MLDSA44PrivateKey) -> bool {
        self.0 == other.0
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
        Self(MLDSAPrivateKey::<
            MLDSA44_k,
            MLDSA44_l,
            MLDSA44_ETA,
            MLDSA44_SK_LEN,
            MLDSA44_PK_LEN,
            MLDSA44_COMPACT_SK_LEN,
        >::new(rho, K, tr, s1, s2, t0, seed))
    }

    /// Does this ML-DSA Private Key contain a seed value?
    pub fn has_seed(&self) -> bool {
        self.0.has_seed()
    }

    /// If this ML-DSA Private Key contains a seed, then return it, otherwise return None
    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.0.get_seed()
    }

    pub fn has_t0(&self) -> bool {
        self.0.has_t0()
    }

    pub fn public_key_hash(&self) -> [u8; 64] {
        self.0.tr
    }

    pub fn to_compact(&self) -> Self {
        Self(self.0.to_compact())
    }

    pub fn to_seed_only(&self) -> Result<Self, SignatureError> {
        Ok(Self(self.0.to_seed_only()?))
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSA44PublicKey {
        let pk = self.0.derive_public_key();
        MLDSA44PublicKey::new(&pk.rho, &pk.t1)
    }

    /// Encode the private key into the standard byte serialization.
    pub fn sk_encode(&self) -> [u8; MLDSA44_SK_LEN] {
        self.0.sk_encode()
    }

    pub fn compact_encode(&self) -> [u8; MLDSA44_COMPACT_SK_LEN] {
        self.0.compact_encode()
    }

    /// Decode the private key from the standard byte serialization.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    pub fn sk_decode(sk: &[u8; MLDSA44_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<
            MLDSA44_k,
            MLDSA44_l,
            MLDSA44_ETA,
            MLDSA44_SK_LEN,
            MLDSA44_PK_LEN,
            MLDSA44_COMPACT_SK_LEN,
        >::sk_decode(sk))
    }

    /// Decode the private key from the standard byte serialization.
    pub fn from_sk_bytes(bytes: &[u8; MLDSA44_SK_LEN]) -> Self {
        Self::sk_decode(bytes)
    }

    pub fn compact_decode(sk: &[u8; MLDSA44_COMPACT_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<
            MLDSA44_k,
            MLDSA44_l,
            MLDSA44_ETA,
            MLDSA44_SK_LEN,
            MLDSA44_PK_LEN,
            MLDSA44_COMPACT_SK_LEN,
        >::compact_decode(sk))
    }

    pub fn from_compact_bytes(bytes: &[u8; MLDSA44_COMPACT_SK_LEN]) -> Self {
        Self::compact_decode(bytes)
    }
}

impl SignaturePrivateKey for MLDSA44PrivateKey {
    fn encode(&self) -> Vec<u8> {
        self.0.sk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < MLDSA44_SK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.0.sk_encode();
            debug_assert_eq!(tmp.len(), MLDSA44_SK_LEN);
            out[..MLDSA44_SK_LEN].copy_from_slice(&tmp);
            Ok(MLDSA44_SK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sized_bytes: [u8; MLDSA44_SK_LEN] = match bytes[..MLDSA44_SK_LEN].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(SignatureError::DecodingError(
                    "Provided bytes are the incorrect length",
                ));
            }
        };
        Ok(Self::sk_decode(&sized_bytes))
    }
}

/// ML-DSA-65 Private Key
#[derive(Debug)] // should be safe because the inner structure impls Debug and won't dump private key contents
pub struct MLDSA65PrivateKey(
    pub(crate)  MLDSAPrivateKey<
        MLDSA65_k,
        MLDSA65_l,
        MLDSA65_ETA,
        MLDSA65_SK_LEN,
        MLDSA65_PK_LEN,
        MLDSA65_COMPACT_SK_LEN,
    >,
);

// todo -- did these end up getting used?
impl
    From<
        MLDSAPrivateKey<
            MLDSA65_k,
            MLDSA65_l,
            MLDSA65_ETA,
            MLDSA65_SK_LEN,
            MLDSA65_PK_LEN,
            MLDSA65_COMPACT_SK_LEN,
        >,
    > for MLDSA65PrivateKey
{
    fn from(
        sk: MLDSAPrivateKey<
            MLDSA65_k,
            MLDSA65_l,
            MLDSA65_ETA,
            MLDSA65_SK_LEN,
            MLDSA65_PK_LEN,
            MLDSA65_COMPACT_SK_LEN,
        >,
    ) -> Self {
        Self(sk)
    }
}

/// Constant-time equality check of the private key data.
impl PartialEq for MLDSA65PrivateKey {
    fn eq(&self, other: &MLDSA65PrivateKey) -> bool {
        self.0 == other.0
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
        Self(MLDSAPrivateKey::<
            MLDSA65_k,
            MLDSA65_l,
            MLDSA65_ETA,
            MLDSA65_SK_LEN,
            MLDSA65_PK_LEN,
            MLDSA65_COMPACT_SK_LEN,
        >::new(rho, K, tr, s1, s2, t0, seed))
    }

    /// Does this ML-DSA Private Key contain a seed value?
    pub fn has_seed(&self) -> bool {
        self.0.has_seed()
    }

    /// If this ML-DSA Private Key contains a seed, then return it, otherwise return None
    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.0.get_seed()
    }

    pub fn has_t0(&self) -> bool {
        self.0.has_t0()
    }

    pub fn public_key_hash(&self) -> [u8; 64] {
        self.0.tr
    }

    pub fn to_compact(&self) -> Self {
        Self(self.0.to_compact())
    }

    pub fn to_seed_only(&self) -> Result<Self, SignatureError> {
        Ok(Self(self.0.to_seed_only()?))
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSA65PublicKey {
        let pk = self.0.derive_public_key();
        MLDSA65PublicKey::new(&pk.rho, &pk.t1)
    }

    /// Encode the private key into the standard byte serialization.
    pub fn sk_encode(&self) -> [u8; MLDSA65_SK_LEN] {
        self.0.sk_encode()
    }

    pub fn compact_encode(&self) -> [u8; MLDSA65_COMPACT_SK_LEN] {
        self.0.compact_encode()
    }

    /// Decode the public key from the standard byte serialization.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    pub fn sk_decode(sk: &[u8; MLDSA65_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<
            MLDSA65_k,
            MLDSA65_l,
            MLDSA65_ETA,
            MLDSA65_SK_LEN,
            MLDSA65_PK_LEN,
            MLDSA65_COMPACT_SK_LEN,
        >::sk_decode(sk))
    }

    /// Decode the private key from the standard byte serialization.
    pub fn from_sk_bytes(bytes: &[u8; MLDSA65_SK_LEN]) -> Self {
        Self::sk_decode(bytes)
    }

    pub fn compact_decode(sk: &[u8; MLDSA65_COMPACT_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<
            MLDSA65_k,
            MLDSA65_l,
            MLDSA65_ETA,
            MLDSA65_SK_LEN,
            MLDSA65_PK_LEN,
            MLDSA65_COMPACT_SK_LEN,
        >::compact_decode(sk))
    }

    pub fn from_compact_bytes(bytes: &[u8; MLDSA65_COMPACT_SK_LEN]) -> Self {
        Self::compact_decode(bytes)
    }
}

impl SignaturePrivateKey for MLDSA65PrivateKey {
    fn encode(&self) -> Vec<u8> {
        self.0.sk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < MLDSA65_SK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.0.sk_encode();
            debug_assert_eq!(tmp.len(), MLDSA65_SK_LEN);
            out[..MLDSA65_SK_LEN].copy_from_slice(&tmp);
            Ok(MLDSA65_SK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sized_bytes: [u8; MLDSA65_SK_LEN] = match bytes[..MLDSA65_SK_LEN].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(SignatureError::DecodingError(
                    "Provided bytes are the incorrect length",
                ));
            }
        };
        Ok(Self::sk_decode(&sized_bytes))
    }
}

/// ML-DSA-87 Private Key
#[derive(Debug)] // should be safe because the inner structure impls Debug and won't dump private key contents
pub struct MLDSA87PrivateKey(
    pub(crate)  MLDSAPrivateKey<
        MLDSA87_k,
        MLDSA87_l,
        MLDSA87_ETA,
        MLDSA87_SK_LEN,
        MLDSA87_PK_LEN,
        MLDSA87_COMPACT_SK_LEN,
    >,
);

impl
    From<
        MLDSAPrivateKey<
            MLDSA87_k,
            MLDSA87_l,
            MLDSA87_ETA,
            MLDSA87_SK_LEN,
            MLDSA87_PK_LEN,
            MLDSA87_COMPACT_SK_LEN,
        >,
    > for MLDSA87PrivateKey
{
    fn from(
        sk: MLDSAPrivateKey<
            MLDSA87_k,
            MLDSA87_l,
            MLDSA87_ETA,
            MLDSA87_SK_LEN,
            MLDSA87_PK_LEN,
            MLDSA87_COMPACT_SK_LEN,
        >,
    ) -> Self {
        Self(sk)
    }
}

/// Constant-time equality check of the private key data.
impl PartialEq for MLDSA87PrivateKey {
    fn eq(&self, other: &MLDSA87PrivateKey) -> bool {
        self.0 == other.0
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
        Self(MLDSAPrivateKey::<
            MLDSA87_k,
            MLDSA87_l,
            MLDSA87_ETA,
            MLDSA87_SK_LEN,
            MLDSA87_PK_LEN,
            MLDSA87_COMPACT_SK_LEN,
        >::new(rho, K, tr, s1, s2, t0, seed))
    }

    /// Does this ML-DSA Private Key contain a seed value?
    pub fn has_seed(&self) -> bool {
        self.0.has_seed()
    }

    /// If this ML-DSA Private Key contains a seed, then return it, otherwise return None
    pub fn get_seed(&self) -> Option<KeyMaterialSized<32>> {
        self.0.get_seed()
    }

    pub fn has_t0(&self) -> bool {
        self.0.has_t0()
    }

    pub fn to_compact(&self) -> Self {
        Self(self.0.to_compact())
    }

    pub fn to_seed_only(&self) -> Result<Self, SignatureError> {
        Ok(Self(self.0.to_seed_only()?))
    }

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    pub fn derive_public_key(&self) -> MLDSA87PublicKey {
        let pk = self.0.derive_public_key();
        MLDSA87PublicKey::new(&pk.rho, &pk.t1)
    }

    /// Encode the private key into the standard byte serialization.
    pub fn sk_encode(&self) -> [u8; MLDSA87_SK_LEN] {
        self.0.sk_encode()
    }

    pub fn compact_encode(&self) -> [u8; MLDSA87_COMPACT_SK_LEN] {
        self.0.compact_encode()
    }

    /// Decode the public key from the standard byte serialization.
    /// See [MLDSA] for key generation functions, including derive-from-seed and consistency-check functions.
    pub fn sk_decode(sk: &[u8; MLDSA87_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<
            MLDSA87_k,
            MLDSA87_l,
            MLDSA87_ETA,
            MLDSA87_SK_LEN,
            MLDSA87_PK_LEN,
            MLDSA87_COMPACT_SK_LEN,
        >::sk_decode(sk))
    }

    /// Decode the private key from the standard byte serialization.
    pub fn from_sk_bytes(bytes: &[u8; MLDSA87_SK_LEN]) -> Self {
        Self::sk_decode(bytes)
    }

    pub fn compact_decode(sk: &[u8; MLDSA87_COMPACT_SK_LEN]) -> Self {
        Self(MLDSAPrivateKey::<
            MLDSA87_k,
            MLDSA87_l,
            MLDSA87_ETA,
            MLDSA87_SK_LEN,
            MLDSA87_PK_LEN,
            MLDSA87_COMPACT_SK_LEN,
        >::compact_decode(sk))
    }

    pub fn from_compact_bytes(bytes: &[u8; MLDSA87_COMPACT_SK_LEN]) -> Self {
        Self::compact_decode(bytes)
    }
}

impl SignaturePrivateKey for MLDSA87PrivateKey {
    fn encode(&self) -> Vec<u8> {
        self.0.sk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < MLDSA87_SK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let tmp = self.0.sk_encode();
            debug_assert_eq!(tmp.len(), MLDSA87_SK_LEN);
            out[..MLDSA87_SK_LEN].copy_from_slice(&tmp);
            Ok(MLDSA87_SK_LEN)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sized_bytes: [u8; MLDSA87_SK_LEN] = match bytes[..MLDSA87_SK_LEN].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(SignatureError::DecodingError(
                    "Provided bytes are the incorrect length",
                ));
            }
        };
        Ok(Self::sk_decode(&sized_bytes))
    }
}
