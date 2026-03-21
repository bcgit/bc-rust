#[cfg(test)]
mod tests {
    use bouncycastle_core_interface::traits::SecurityStrength;

    #[test]
    fn test_security_strength() {
        let ss = SecurityStrength::from_bits(0);
        assert_eq!(ss, SecurityStrength::None);
        let ss = SecurityStrength::from_bytes(0);
        assert_eq!(ss, SecurityStrength::None);

        let ss = SecurityStrength::from_bits(12);
        assert_eq!(ss, SecurityStrength::None);
        let ss = SecurityStrength::from_bytes(1);
        assert_eq!(ss, SecurityStrength::None);

        let ss = SecurityStrength::from_bits(112);
        assert_eq!(ss, SecurityStrength::_112bit);
        let ss = SecurityStrength::from_bytes(14);
        assert_eq!(ss, SecurityStrength::_112bit);

        let ss = SecurityStrength::from_bits(114);
        assert_eq!(ss, SecurityStrength::_112bit);
        let ss = SecurityStrength::from_bytes(15);
        assert_eq!(ss, SecurityStrength::_112bit);

        let ss = SecurityStrength::from_bits(128);
        assert_eq!(ss, SecurityStrength::_128bit);
        let ss = SecurityStrength::from_bytes(16);
        assert_eq!(ss, SecurityStrength::_128bit);

        let ss = SecurityStrength::from_bits(130);
        assert_eq!(ss, SecurityStrength::_128bit);
        let ss = SecurityStrength::from_bytes(17);
        assert_eq!(ss, SecurityStrength::_128bit);

        let ss = SecurityStrength::from_bits(192);
        assert_eq!(ss, SecurityStrength::_192bit);
        let ss = SecurityStrength::from_bytes(28);
        assert_eq!(ss, SecurityStrength::_192bit);

        let ss = SecurityStrength::from_bits(200);
        assert_eq!(ss, SecurityStrength::_192bit);
        let ss = SecurityStrength::from_bytes(29);
        assert_eq!(ss, SecurityStrength::_192bit);

        let ss = SecurityStrength::from_bits(256);
        assert_eq!(ss, SecurityStrength::_256bit);
        let ss = SecurityStrength::from_bytes(32);
        assert_eq!(ss, SecurityStrength::_256bit);

        let ss = SecurityStrength::from_bits(1000);
        assert_eq!(ss, SecurityStrength::_256bit);
        let ss = SecurityStrength::from_bytes(100);
        assert_eq!(ss, SecurityStrength::_256bit);

        let ss = SecurityStrength::None;
        assert_eq!(ss.as_int(), 0);

        let ss = SecurityStrength::_112bit;
        assert_eq!(ss.as_int(), 112);

        let ss = SecurityStrength::_128bit;
        assert_eq!(ss.as_int(), 128);

        let ss = SecurityStrength::_192bit;
        assert_eq!(ss.as_int(), 192);

        let ss = SecurityStrength::_256bit;
        assert_eq!(ss.as_int(), 256);
    }
}
