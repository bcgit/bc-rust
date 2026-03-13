# TODO before release:

- [ ] Play with optimization using the rayon crate's .into_per_iter to optimize the vectorizable loops (hide this behind a cargo feature that falls back to the for-loop impl)
- [ ] check all .clone() and .copy_from_slice() to make sure that you're not returning secret data to the OS.
- [ ] check Michael Rosenberg's checklist on "Trustworthy public Rust repos" (signal chat)



// add to bouncycastle_core_interface::traits




// TODO: fork MLDSAPrivateKey into a new .rs file


struct MLDSAPrivatekey<X> {
    seed: Option<KeyMaterialInternal::<32>>,
    expanded: MlDsaParameters,
    pubkey: Option<MlDsaPublicKeyParameters>,
}

impl MLDSAPrivatekey<32> {
    /// NIST assesses the security strength of ML-DSA not in terms of traditional "bits of security",
    /// but in terms of "Security Category Levels 1 - 5" with the following mappings for ML-DSA:
    /// 
    /// * ML-DSA-44: Category 2: equivalent to a collision search on SHA-256 (approximately 128 bits).
    /// * ML-DSA-65: Category 3: equivalent to an exhaustive key search on AES-192 (approximately 192 bits).
    /// * ML-DSA-87: Category 5: equivalent to an exhaustive key search on AES-256 (approximately 256 bits).
    ///
    /// As such, this function enforces that the seed be tagged with a [SecurityStrength] of 
    /// [SecurityStrength::_128bit] for ML-DSA-44 [SecurityStrength::_192bit] for ML-DSA-65 and
    /// [SecurityStrength::_255bit] for ML-DSA-87 otherwise it will throw a [KeyMaterialError::SecurityStrength] error.
    /// While you can make this error go away by forcing a [KeyMaterial] to any [SecurityStrength] by using the 
    /// [KeyMaterial::allow_hazardous_operations] flag,
    /// the intention here is make application developers aware when they use an RNG or a KDF that is instantiated
    /// at a lower security level than the ML-DSA scheme they are trying to derive a key for.
    /// So a well-designed application should be using appropriately-instantiated RNGs and KDFs and therefore never
    /// need to force a key's security strength using [KeyMaterial::allow_hazardous_operations].
    pub fn from_seed(rho: KeyMaterialInternal::<32>) -> Result<Self, KeyMaterialError> {
        todo!()
        self.expanded = Some(keygen(rho));
        // derive expanded
    }

    pub fn from_seed_bytes(rho: &[u8; 32]) -> Self {
        todo!()
        // construct the KeyMaterial and call the other one
    }

    pub fn from_expanded(expanded_key: KeyMaterialInternal::<X>) -> Self {
        todo!()
        MlDsaParameters::init_from_encoding(&expanded_key);
    }

    pub fn from_expanded_bytes(expanded_bytes: &[u8; X]) -> Self {
        todo!()
        // construct the KeyMaterial and call the other one
    }

    pub fn from_seed_and_expanded(rho: KeyMaterialInternal::<32>, expanded_key: KeyMaterialInternal::<X>) -> Self {
        todo!()
        self.expanded = Some(keygen(rho));
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



#[test]
fn test_keygen() {
  // go extract the samples from RFC9881 Appendix C 
}