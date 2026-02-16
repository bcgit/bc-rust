use bouncycastle_core_interface::key_material::KeyMaterialInternal;
use crate::{MLDSAParams, POLY_T1PACKED_LEN, SEED_LEN};
use crate::aux_functions::simple_bit_pack_t1;
use crate::matrix::Vector;

// pub struct MLDSAPublickey<PARAMS: MLDSAParams> {
//     pub(crate) rho: [u8; SEED_LEN],
//     pub(crate) t1: Vector<{PARAMS::k}>,
// }

pub struct MLDSAPublickey<const k: usize, const PK_LEN: usize> {
    pub(crate) rho: [u8; SEED_LEN],
    pub(crate) t1: Vector<k>,
}

impl<const k: usize, const PK_LEN: usize> MLDSAPublickey<k, PK_LEN> {
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    pub(crate) fn new(rho: &[u8; SEED_LEN], t1: &Vector<k>) -> Self {
        Self { rho: rho.clone(), t1: t1.clone() }
    }

    /// Algorithm 22 pkEncode(𝜌, 𝐭1)
    /// Encodes a public key for ML-DSA into a byte string.
    /// Input:𝜌 ∈ 𝔹32, 𝐭1 ∈ 𝑅𝑘 with coefficients in [0, 2bitlen (𝑞−1)−𝑑 − 1].
    /// Output: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑).
    pub fn encode(&self) -> [u8; PK_LEN] {
        let mut out = [0u8; PK_LEN];

        out[0..SEED_LEN].copy_from_slice(&self.rho);

        for i in 0 .. k {
            out[SEED_LEN + i * POLY_T1PACKED_LEN..SEED_LEN + (i + 1) * POLY_T1PACKED_LEN]
                .copy_from_slice(&simple_bit_pack_t1(&self.t1.vec[i]));
        }

        out
    }

    // todo: other constructors, encode(), decode(), etc
}


pub struct MLDSAPrivatekey<const k: usize, const l: usize, const SK_LEN: usize> {
    pub(crate) rho: [u8; 32],
    #[allow(non_snake_case)]
    pub(crate) K: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s1: Vector<l>,
    pub(crate) s2: Vector<k>,
    pub(crate) t0: Vector<k>,    
    seed: Option<KeyMaterialInternal<32>>,
}

impl<const k: usize, const l: usize, const SK_LEN: usize> MLDSAPrivatekey<k, l, SK_LEN>{
    // pub fn from_seed(seed: KeyMaterialInternal::<32>) -> Self {
    //     todo!()
    //     self.expanded = Some(keygen_internal(seed));
    //     // derive expanded
    // }
    // 
    // pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
    //     todo!()
    //     // construct the KeyMaterial and call the other one
    // }
    // 
    // pub fn from_expanded(expanded_key: KeyMaterialInternal::<X>) -> Self {
    //     todo!()
    //     MlDsaParameters::init_from_encoding(&expanded_key);
    // }
    // 
    // pub fn from_expanded_bytes(expanded_bytes: &[u8; X]) -> Self {
    //     todo!()
    //     // construct the KeyMaterial and call the other one
    // }
    // 
    // pub fn from_seed_and_expanded(eta: KeyMaterialInternal::<32>, expanded_key: KeyMaterialInternal::<X>) -> Self {
    //     todo!()
    //     self.expanded = Some(keygen_internal(seed));
    //     // check for consistence
    // }
    // 
    // pub fn from_seed_and_expanded_bytes(rho: [u8; 32], expanded_key: [u8; X]) -> Self {
    //     todo!()
    //     self.expanded = Some(keygen(rho));
    //     // check for consistence
    // }
    // 
    // pub fn has_seed(&self) -> bool {
    //     self.seed.is_some()
    // }
    // 
    // pub fn get_seed(): Option<KeyMaterialInternal::<32>> {
    // self.seed
    // }
    // 
    // pub fn get_expanded(): KeyMaterialInternal::<X> {
    // self.expanded.fips204encode()
    // }

}