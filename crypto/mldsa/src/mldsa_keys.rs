use crate::aux_functions::{
    bit_pack_eta, bit_pack_t0, bit_unpack_eta, bit_unpack_t0, bitlen_eta, expandA, power_2_round_vec,
    simple_bit_pack_t1, simple_bit_unpack_t1
};
use crate::matrix::Vector;
use crate::mldsa::H;
use crate::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
use crate::mldsa::{MLDSA44_ETA, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_k, MLDSA44_l};
use crate::mldsa::{MLDSA65_ETA, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_k, MLDSA65_l};
use crate::mldsa::{MLDSA87_ETA, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_k, MLDSA87_l};
use crate::mldsa::{POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::KeyMaterialSized;
use bouncycastle_core_interface::traits::{Secret, SignaturePrivateKey, SignaturePublicKey, XOF};
use std::fmt;
use std::fmt::{Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mldsa::MLDSATrait;



/* Pub Types */

/// ML-DSA-44 Public Key
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>;
/// ML-DSA-44 Private Key
pub type MLDSA44PrivateKey = MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>;
/// ML-DSA-65 Public Key
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>;
/// ML-DSA-65 Private Key
pub type MLDSA65PrivateKey = MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>;
/// ML-DSA-87 Public Key
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>;
/// ML-DSA-87 Private Key
pub type MLDSA87PrivateKey = MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>;

/// An ML-DSA public key.
#[derive(Clone)]
pub struct MLDSAPublicKey<const k: usize, const PK_LEN: usize> {
    rho: [u8; 32],
    t1: Vector<k>,
}

/// General trait for all ML-DSA public keys types.
pub trait MLDSAPublicKeyTrait<const k: usize, const PK_LEN: usize> : SignaturePublicKey {
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

pub(crate) trait MLDSAPublicKeyInternalTrait<const k: usize, const PK_LEN: usize> {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(rho: &[u8; 32], t1: &Vector<k>) -> Self;

    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get a ref to t1
    fn t1(&self) -> &Vector<k>;
}

impl<const k: usize, const PK_LEN: usize> MLDSAPublicKeyTrait<k, PK_LEN> for MLDSAPublicKey<k, PK_LEN> {
    fn pk_encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];

        pk[0..32].copy_from_slice(&self.rho);

        let (pk_chunks, last_chunk) = pk[32..].as_chunks_mut::<POLY_T1PACKED_LEN>();

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

    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
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

    fn compute_tr(&self) -> [u8; 64] {
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&self.pk_encode(), &mut tr);

        tr
    }
}

impl<const k: usize, const PK_LEN: usize> MLDSAPublicKeyInternalTrait<k, PK_LEN> for MLDSAPublicKey<k, PK_LEN> {
    fn new(rho: &[u8; 32], t1: &Vector<k>) -> Self {
        Self { rho: rho.clone(), t1: t1.clone() }
    }

    fn rho(&self) -> &[u8; 32] { &self.rho }

    fn t1(&self) -> &Vector<k> { &self.t1 }
}

impl<const k: usize, const PK_LEN: usize>  SignaturePublicKey for MLDSAPublicKey<k, PK_LEN> {
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

impl<const k: usize, const PK_LEN: usize> Eq for MLDSAPublicKey<k, PK_LEN> { }

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

impl<const k: usize, const PK_LEN: usize> Display for MLDSAPublicKey<k, PK_LEN> {
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

/// An ML-DSA private key.
#[derive(Clone)]
pub struct MLDSAPrivateKey<
    const k: usize,
    const l: usize,
    const eta: usize,
    const SK_LEN: usize,
    const PK_LEN: usize,
> {
    rho: [u8; 32],
    K: [u8; 32],
    tr: [u8; 64],
    s1: Vector<l>,
    s2: Vector<k>,
    t0: Vector<k>,
    seed: Option<KeyMaterialSized<32>>,
}

/// General trait for all ML-DSA private keys types.
pub trait MLDSAPrivateKeyTrait<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize> : SignaturePrivateKey {
    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> &Option<KeyMaterialSized<32>>;

    /// Get a ref to the key hash `tr`.
    fn tr(&self) -> &[u8; 64];

    /// This is a partial implementation of keygen_internal(), and probably not allowed in FIPS mode.
    fn derive_pk(&self) -> MLDSAPublicKey<k, PK_LEN>;
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

pub(crate) trait MLDSAPrivateKeyInternalTrait<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize> {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(
        rho: &[u8; 32],
        K: &[u8; 32],
        tr: &[u8; 64],
        s1: &Vector<l>,
        s2: &Vector<k>,
        t0: &Vector<k>,
        seed: Option<KeyMaterialSized<32>>,
    ) -> Self;
    /// Get a ref to rho
    fn rho(&self) -> &[u8; 32];

    /// Get a ref to K
    fn K(&self) -> &[u8; 32];

    /// Get a ref to tr
    // don't need here because there's one in the public trait
    // fn tr(&self) -> &[u8; 64];

    /// Get a ref to s1
    fn s1(&self) -> &Vector<l>;

    /// Get a ref to s2
    fn s2(&self) -> &Vector<k>;

    /// Get a ref to t0
    fn t0(&self) -> &Vector<k>;
}


impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKeyTrait<k, l, eta, SK_LEN, PK_LEN> for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN> {
    fn seed(&self) -> &Option<KeyMaterialSized<32>> { &self.seed }

    fn tr(&self) -> &[u8; 64] {
        &self.tr
    }

    fn derive_pk(&self) -> MLDSAPublicKey<k, PK_LEN> {

        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let mut s1_hat = self.s1.clone();
        s1_hat.ntt();

        let mut t = { // scope for A_hat
            let A_hat = expandA::<k, l>(&self.rho);

            // 3: 𝐀 ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
            let mut t_ntt = A_hat.matrix_vector_ntt(&s1_hat);
            t_ntt.inv_ntt();
            t_ntt
        };
        t.add_vector_ntt(&self.s2);
        t.conditional_add_q();

        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, _) = power_2_round_vec::<k>(&t);

        MLDSAPublicKey::<k, PK_LEN>::new(&self.rho, &t1)
    }

    fn sk_encode(&self) -> [u8; SK_LEN] {
        let mut out = [0u8; SK_LEN];
        let bytes_written = self.sk_encode_out(&mut out);
        debug_assert_eq!(bytes_written, SK_LEN);
        out
    }

    fn sk_encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        // bytes written counter
        let mut off: usize = 0;

        out[0..32].copy_from_slice(&self.rho);
        out[32..64].copy_from_slice(&self.K);
        out[64..128].copy_from_slice(&self.tr);
        off += 128;

        let mut buf = [0u8; 32 * 4]; // largest possible buffer
        let eta_pack_len = bitlen_eta(eta);

        let sk_chunks = out[off..off + l * bitlen_eta(eta)].chunks_mut(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), l);
        for (sk_chunk, s1_i) in sk_chunks.into_iter().zip(&self.s1.vec) {
            bit_pack_eta::<eta>(s1_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += l * bitlen_eta(eta);

        let sk_chunks = out[off..off + k * bitlen_eta(eta)].chunks_mut(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, s2_i) in sk_chunks.into_iter().zip(&self.s2.vec) {
            bit_pack_eta::<eta>(s2_i, &mut buf);
            sk_chunk.copy_from_slice(&buf[..eta_pack_len]);
        }
        off += k * bitlen_eta(eta);

        let sk_chunks = out[off..off + k * POLY_T0PACKED_LEN].chunks_mut(POLY_T0PACKED_LEN);
        debug_assert_eq!(sk_chunks.len(), k);
        for (sk_chunk, t0_i) in sk_chunks.into_iter().zip(&self.t0.vec) {
            sk_chunk.copy_from_slice(&bit_pack_t0(t0_i));
        }

        SK_LEN
    }
    fn sk_decode(sk: &[u8; SK_LEN]) -> Self {
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
        for (s1_i, sk_chunk) in s1.vec.iter_mut().zip(sk_chunks) {
            s1_i.0.copy_from_slice(&bit_unpack_eta::<eta>(&sk_chunk).0);
        }
        off += l * bitlen_eta(eta);

        // unpack s2
        let sk_chunks = sk[off..off + (k * bitlen_eta(eta))].chunks(bitlen_eta(eta));
        debug_assert_eq!(sk_chunks.len(), k);
        for (s2_i, sk_chunk) in s2.vec.iter_mut().zip(sk_chunks) {
            s2_i.0.copy_from_slice(&bit_unpack_eta::<eta>(&sk_chunk).0);
        }
        off += k * bitlen_eta(eta);

        // unpack t0
        let (sk_chunks, last_chunk) =
            sk[off..off + (k * POLY_T0PACKED_LEN)].as_chunks::<POLY_T0PACKED_LEN>();

        // that should divide evenly the remainder of the array
        debug_assert_eq!(sk_chunks.len(), k);
        debug_assert_eq!(last_chunk.len(), 0);

        for (t0_i, sk_chunk) in t0.vec.iter_mut().zip(sk_chunks) {
            t0_i.0.copy_from_slice(&bit_unpack_t0(sk_chunk).0);
        }

        Self::new(&rho, &K, &tr, &s1, &s2, &t0, None)
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    MLDSAPrivateKeyInternalTrait<k, l, eta, SK_LEN, PK_LEN> for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN> {
    fn new(
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

    fn rho(&self) -> &[u8; 32] { &self.rho }

    fn K(&self) -> &[u8; 32] { &self.K }

    // don't need here because there's one in the public trait
    // fn tr(&self) -> &[u8; 64] { &self.tr }

    fn s1(&self) -> &Vector<l> { &self.s1 }

    fn s2(&self) -> &Vector<k> { &self.s2 }

    fn t0(&self) -> &Vector<k> { &self.t0 }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    SignaturePrivateKey for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN> {
    fn encode(&self) -> Vec<u8> {
        self.sk_encode().to_vec()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        if out.len() < SK_LEN {
            Err(SignatureError::EncodingError("Output buffer too small"))
        } else {
            let out_sized: &mut [u8; SK_LEN] = out[..SK_LEN].as_mut().try_into().unwrap();
            Ok(self.sk_encode_out(out_sized))
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != SK_LEN { return Err(SignatureError::DecodingError("Provided key bytes are the incorrect length")) }
        let sized_bytes: [u8; SK_LEN] = bytes[..SK_LEN].try_into().unwrap();
        Ok(Self::sk_decode(&sized_bytes))
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    Eq for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN> {}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    PartialEq for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        let self_encoded = self.sk_encode();
        let other_encoded = other.sk_encode();
        bouncycastle_utils::ct::ct_eq_bytes(self_encoded.as_ref(), other_encoded.as_ref())
    }
}

impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
Secret for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN> {}

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
            self.seed.is_some(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<const k: usize, const l: usize, const eta: usize, const SK_LEN: usize, const PK_LEN: usize>
    Display for MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>
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
            self.seed.is_some(),
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
