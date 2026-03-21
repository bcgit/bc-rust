#[cfg(test)]
mod tests {
    use bouncycastle_core_interface::traits::{SecurityStrength, RNG};
    use bouncycastle_factory::AlgorithmFactory;
    use bouncycastle_factory as factory;

    #[test]
    fn test_defaults() {
        // All the ways to get "default"
        let mut rng = factory::rng_factory::RNGFactory::default();
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);

        let mut rng = factory::rng_factory::RNGFactory::new("Default").unwrap();
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);

        let mut rng = factory::rng_factory::RNGFactory::new(factory::DEFAULT).unwrap();
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);


        // All the ways to get "default_128_bit"
        let mut rng = factory::rng_factory::RNGFactory::default_128_bit();
        assert_eq!(rng.security_strength(), SecurityStrength::_128bit);
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);

        let mut rng = factory::rng_factory::RNGFactory::new("Default128Bit").unwrap();
        assert_eq!(rng.security_strength(), SecurityStrength::_128bit);
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);

        let mut rng = factory::rng_factory::RNGFactory::new(factory::DEFAULT_128_BIT).unwrap();
        assert_eq!(rng.security_strength(), SecurityStrength::_128bit);
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);


        // All the ways to get "default_256_bit"
        let mut rng = factory::rng_factory::RNGFactory::default_256_bit();
        assert_eq!(rng.security_strength(), SecurityStrength::_256bit);
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);

        let mut rng = factory::rng_factory::RNGFactory::new("Default256Bit").unwrap();
        assert_eq!(rng.security_strength(), SecurityStrength::_256bit);
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);

        let mut rng = factory::rng_factory::RNGFactory::new(factory::DEFAULT_256_BIT).unwrap();
        assert_eq!(rng.security_strength(), SecurityStrength::_256bit);
        let out = rng.next_bytes(10).unwrap();
        assert_ne!(out, &[0u8; 10],);
    }
}