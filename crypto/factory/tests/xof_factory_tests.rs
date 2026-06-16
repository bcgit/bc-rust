#[cfg(test)]
mod tests {
    use bouncycastle_ascon::ASCON_XOF128_NAME;
    use bouncycastle_ascon::ascon_xof128::AsconXof128;
    use bouncycastle_core::traits::XOF;
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_factory::AlgorithmFactory;
    use bouncycastle_factory::FactoryError;
    use bouncycastle_factory::xof_factory::XOFFactory;

    #[test]
    fn ascon_xof_round_trip() {
        let direct = AsconXof128::new().hash_xof(DUMMY_SEED_512, 64);

        // Construct by literal name and by the crate's name constant; both must match the direct
        // implementation.
        let by_name = XOFFactory::new("Ascon-XOF128").unwrap();
        assert_eq!(by_name.hash_xof(DUMMY_SEED_512, 64), direct);

        let by_const = XOFFactory::new(ASCON_XOF128_NAME).unwrap();
        assert_eq!(by_const.hash_xof(DUMMY_SEED_512, 64), direct);
    }

    #[test]
    fn unknown_xof_name_is_rejected() {
        assert!(matches!(
            XOFFactory::new("Ascon-XOF999"),
            Err(FactoryError::UnsupportedAlgorithm(_))
        ));
    }
}
