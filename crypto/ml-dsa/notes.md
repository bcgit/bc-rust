

struct MLDSAPrivatekey<X> {
    seed: Option<KeyMaterialInternal::<32>>,
    expanded: KeyMaterialInternal::<X>,
}

impl MLDSAPrivatekey<32> {
    pub fn from_seed(seed: KeyMaterialInternal::<32>) -> Self {
        todo!()
        self.expanded = Some(keygen(seed));
        // derive expanded
    }

    pub fn from_expanded(expanded: KeyMaterialInternal::<X>) -> Self {
        todo!() // just set it
    }

    pub fn from_seed_and_expanded(seed: KeyMaterialInternal::<32>, expanded: KeyMaterialInternal::<X>) -> Self {
        todo!()
        self.expanded = Some(keygen(seed));
        // check for consistence
    }

    pub fn has_seed(&self) -> bool {
        self.seed.is_some()
    }

    pub fn get_seed(): Option<KeyMaterialInternal::<32>> {
        self.seed
    }
    
    pub fn get_expanded(): KeyMaterialInternal::<X> {
        self.expanded
    }    

}



#[test]
fn test_keygen() {
  // go extract the samples from RFC9881 Appendix C 
}