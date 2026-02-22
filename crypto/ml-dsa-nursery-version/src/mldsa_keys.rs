use bouncycastle_core_interface::key_material::KeyMaterialSized;
use crate::{MLDSAParams, SEED_LEN};
use crate::polynomial::Polynomial;

pub struct MLDSAPublickey<PARAMS: MLDSAParams> {
    pub(crate) rho: [u8; SEED_LEN],
    pub(crate) t1: [Polynomial; MLDSAParams::K],
}

pub struct MLDSAPrivatekey<PARAMS: MLDSAParams> {
    expanded: MlDsaParameters,
    seed: Option<KeyMaterialSized::<32>>,
    pubkey: Option<MLDSAPublickey<PARAMS>>,
}

impl<PARAMS: MLDSAParams> MLDSAPrivatekey<PARAMS> {
    pub fn from_seed(seed: KeyMaterialSized::<32>) -> Self {
        todo!()
        self.expanded = Some(keygen_internal(seed));
        // derive expanded
    }

    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        todo!()
        // construct the KeyMaterial and call the other one
    }

    pub fn from_expanded(expanded_key: KeyMaterialSized::<X>) -> Self {
        todo!()
        MlDsaParameters::init_from_encoding(&expanded_key);
    }

    pub fn from_expanded_bytes(expanded_bytes: &[u8; X]) -> Self {
        todo!()
        // construct the KeyMaterial and call the other one
    }

    pub fn from_seed_and_expanded(eta: KeyMaterialSized::<32>, expanded_key: KeyMaterialSized::<X>) -> Self {
        todo!()
        self.expanded = Some(keygen_internal(seed));
        // check for consistence
    }

    pub fn from_seed_and_expanded_bytes(rho: [u8; 32], expanded_key: [u8; X]) -> Self {
        todo!()
        self.expanded = Some(keygen(rho));
        // check for consistence
    }

    pub fn has_seed(&self) -> bool {
        self.seed.is_some()
    }

    pub fn get_seed(): Option<KeyMaterialInternal::<32>> {
    self.seed
    }

    pub fn get_expanded(): KeyMaterialInternal::<X> {
    self.expanded.fips204encode()
    }

}