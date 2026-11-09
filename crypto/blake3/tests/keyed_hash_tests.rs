//! Tests for [`BLAKE3KeyedHashKey`], the [`BLAKE3KeyedHash`] worker it hands out (`keyed_hash`
//! mode) and [`BLAKE3KeyedSqueezer`].
//!
//! Vector sources: the official BLAKE3 test vectors (see `vectors/mod.rs`). bc-test-data has no
//! BLAKE3 data, and Wycheproof has no BLAKE vectors (C2SP/wycheproof testvectors_v1 has no blake*
//! file), so the "against bc-test-data and wycheproof" requirement is met vacuously.

mod vectors;

#[cfg(test)]
mod keyed_hash_tests {
    use super::vectors::{CASES, KEY, OUTPUT_LEN, input};
    use bouncycastle_blake3::*;
    use bouncycastle_core::errors::{KeyMaterialError, MACError};
    use bouncycastle_core::key_material::{
        KeyMaterial256, KeyMaterial512, KeyMaterialTrait, KeyType,
    };
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::symmetric_key::{
        FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey,
    };
    use bouncycastle_core::traits::{
        Algorithm, AlgorithmInfo, HashOneShot, MAC, MIN_MAC_OUTPUT_LEN, XOFSqueezer,
    };
    use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromAnyKeyMaterial;
    use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
    use bouncycastle_hex as hex;
    use bouncycastle_rng::FixedSeedRNG;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn material() -> KeyMaterial256 {
        KeyMaterial256::from_bytes_as_type(KEY, KeyType::MACKey).unwrap()
    }

    fn key() -> BLAKE3KeyedHashKey {
        BLAKE3KeyedHashKey::from_key_material(&material()).unwrap()
    }

    fn other_key() -> BLAKE3KeyedHashKey {
        let m = KeyMaterial256::from_bytes_as_type(&[9u8; 32], KeyType::MACKey).unwrap();
        BLAKE3KeyedHashKey::from_key_material(&m).unwrap()
    }

    /* ----------------------------------- official vectors ----------------------------------- */

    /// Every `keyed_hash` case: the 32-byte tag through the MAC path, and the full 131 bytes (and
    /// split reads) through `into_squeezer`.
    #[test]
    fn official_vectors_keyed_hash() {
        let k = key();
        for case in CASES {
            let msg = input(case.input_len);
            let expected = h(case.keyed_hash);
            let len = case.input_len;

            assert_eq!(k.mac(&msg), expected[..32], "len {len}");
            assert!(k.verify(&msg, &expected[..32]));

            let mut m = k.create_generator();
            m.do_update(&msg);
            assert_eq!(m.into_squeezer().do_output(OUTPUT_LEN), expected, "len {len}");

            for split in [1usize, 64, 65] {
                let mut m = k.create_generator();
                m.do_update(&msg);
                let mut s = m.into_squeezer();
                let first = s.do_output(split);
                let mut second = vec![0xAAu8; OUTPUT_LEN - split];
                assert_eq!(s.do_output_out(&mut second), OUTPUT_LEN - split);
                assert_eq!([first, second].concat(), expected, "split {split} / len {len}");
            }
        }
    }

    /// The default `do_output_final` of the keyed squeezer continues the stream.
    #[test]
    fn keyed_squeezer_do_output_final() {
        let expected = h(CASES[3].keyed_hash);
        let mut m = key().create_generator();
        m.do_update(&input(CASES[3].input_len));
        let mut s = m.into_squeezer();
        let first = s.do_output(10);
        assert_eq!([first, s.clone().do_output_final(121)].concat(), expected);
        let mut rest = vec![0u8; 121];
        assert_eq!(s.do_output_final_out(&mut rest), 121);
        assert_eq!(rest, expected[10..]);
    }

    /* --------------------------------- core-test-framework ---------------------------------- */

    #[test]
    fn core_test_framework_mac_key() {
        let tf = TestFrameworkMAC::new();
        let k = key();
        for case in CASES.iter().filter(|c| c.input_len <= 4097) {
            tf.test_mac_key(&k, &input(case.input_len), &h(case.keyed_hash)[..32]);
        }
    }

    /// Key type, the strength policy (including strength-before-length for a 64-byte key of no
    /// strength) and `generate`.
    #[test]
    fn core_test_framework_from_any_key_material() {
        TestFrameworkFromAnyKeyMaterial::new().test::<BLAKE3KeyedHashKey>(&material());
    }

    /* ------------------------------------- MAC behaviour ------------------------------------ */

    /// Output buffers: a short buffer truncates down to MIN_MAC_OUTPUT_LEN, below that is an
    /// error, a long buffer gets 32 bytes and zeros.
    #[test]
    fn mac_output_buffers() {
        assert_eq!(MIN_MAC_OUTPUT_LEN, 4);
        let k = key();
        let tag = k.mac(b"abc");
        assert_eq!(k.create_generator().output_len(), 32);

        for len in [4usize, 5, 31, 32] {
            let mut out = vec![0xAAu8; len];
            assert_eq!(k.mac_out(b"abc", &mut out).unwrap(), len);
            assert_eq!(out, tag[..len]);

            let mut m = k.create_generator();
            m.do_update(b"abc");
            let mut out = vec![0xAAu8; len];
            assert_eq!(m.do_final_out(&mut out).unwrap(), len);
            assert_eq!(out, tag[..len]);
        }

        // Below the floor: an error, and the buffer still comes back zeroized.
        for len in [0usize, 1, 3] {
            let mut out = vec![0xA5u8; len];
            assert!(matches!(k.mac_out(b"abc", &mut out), Err(MACError::InvalidLength(_))));
            assert!(out.iter().all(|&b| b == 0), "key mac_out / len {len}");

            let mut out = vec![0xA5u8; len];
            assert!(matches!(
                k.create_generator().mac_out(b"abc", &mut out),
                Err(MACError::InvalidLength(_))
            ));
            assert!(out.iter().all(|&b| b == 0), "worker mac_out / len {len}");

            let mut out = vec![0xA5u8; len];
            let mut m = k.create_generator();
            m.do_update(b"abc");
            assert!(matches!(m.do_final_out(&mut out), Err(MACError::InvalidLength(_))));
            assert!(out.iter().all(|&b| b == 0), "do_final_out / len {len}");
        }

        let mut out = [0xAAu8; 50];
        assert_eq!(k.create_generator().mac_out(b"abc", &mut out).unwrap(), 32);
        assert_eq!(out[..32], tag);
        assert_eq!(out[32..], [0u8; 18]);
    }

    /// Verification needs the exact, full-length tag.
    #[test]
    fn verify_exact_match() {
        let k = key();
        let tag = k.mac(b"abc");
        assert!(k.verify(b"abc", &tag));
        assert!(!k.verify(b"abd", &tag));
        assert!(!k.verify(b"abc", &tag[..31]), "truncated tag");
        assert!(!k.verify(b"abc", &[&tag[..], &[0u8]].concat()), "extended tag");
        let mut flipped = tag.clone();
        flipped[31] ^= 1;
        assert!(!k.verify(b"abc", &flipped));

        let mut m = k.create_verifier();
        m.do_update(b"abc");
        assert!(m.clone().do_verify_final(&tag));
        assert!(!m.do_verify_final(&tag[..16]));

        // The worker's own one-shot.
        assert!(k.create_verifier().verify(b"abc", &tag));
        assert!(!k.create_verifier().verify(b"abd", &tag));
        assert!(!k.create_verifier().verify(b"abc", &tag[..31]));
    }

    /// The keyed mode differs from the hash mode, and from other keys.
    #[test]
    fn keyed_differs() {
        let a = key().mac(b"abc");
        assert_ne!(a, other_key().mac(b"abc"));
        assert_ne!(a, BLAKE3::hash(b"abc"));
    }

    /// The BLAKE3-specific construction rule the shared suite cannot know: exactly 32 bytes
    /// (s. 2.3), whatever the strength. A Zeroized (all-zero) key is a MAC key, though a weak one.
    #[test]
    fn key_length_rules() {
        for len in [0usize, 1, 16, 31, 33, 64] {
            let mut k = KeyMaterial512::from_bytes_as_type(&[7u8; 64], KeyType::MACKey).unwrap();
            k.set_key_len(len).unwrap();
            if len > 0 {
                k.set_key_type(KeyType::MACKey).unwrap();
                k.set_security_strength(SecurityStrength::_128bit).unwrap_or(());
            }
            assert!(
                matches!(
                    BLAKE3KeyedHashKey::from_key_material_allow_weak(&k),
                    Err(MACError::InvalidLength(_))
                ),
                "key length {len}"
            );
        }

        let zero = KeyMaterial256::from_bytes_as_type(&[0u8; 32], KeyType::Zeroized).unwrap();
        assert_eq!(zero.key_type(), KeyType::Zeroized);
        assert!(BLAKE3KeyedHashKey::from_key_material_allow_weak(&zero).is_ok());

        // 128 bits is enough; the strength tag does not change the computation.
        let mut ok = material();
        ok.set_security_strength(SecurityStrength::_128bit).unwrap();
        let strong = BLAKE3KeyedHashKey::from_key_material(&ok).unwrap();
        let mut weak = material();
        weak.set_security_strength(SecurityStrength::_112bit).unwrap();
        let weak = BLAKE3KeyedHashKey::from_key_material_allow_weak(&weak).unwrap();
        assert_eq!(strong.mac(b"abc"), weak.mac(b"abc"));
        assert_eq!(strong.mac(b"abc"), key().mac(b"abc"));
    }

    /// `generate` draws 32 bytes from the RNG and tags them at the RNG's strength (capped at the
    /// length's), so an RNG below 128 bits cannot produce a key.
    #[test]
    fn generate_strength_and_bytes() {
        let seed: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let from_seed = KeyMaterial256::from_bytes_as_type(&seed[..32], KeyType::MACKey).unwrap();
        let expected = BLAKE3KeyedHashKey::from_key_material(&from_seed).unwrap().mac(b"abc");

        for strength in [SecurityStrength::_128bit, SecurityStrength::_256bit] {
            let mut rng = FixedSeedRNG::new(seed);
            rng.set_security_strength(strength);
            let key = BLAKE3KeyedHashKey::generate(&mut rng).unwrap();
            assert_eq!(key.mac(b"abc"), expected, "the first 32 RNG bytes are the key");
        }

        for strength in [SecurityStrength::None, SecurityStrength::_112bit] {
            let mut rng = FixedSeedRNG::new(seed);
            rng.set_security_strength(strength);
            assert!(matches!(
                BLAKE3KeyedHashKey::generate(&mut rng),
                Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
            ));
        }
    }

    #[test]
    fn constants_and_params() {
        assert_eq!(BLAKE3_KEYED_HASH_NAME, "BLAKE3-KeyedHash");
        assert_eq!(BLAKE3KeyedHash::ALG_NAME, BLAKE3_KEYED_HASH_NAME);
        assert_eq!(BLAKE3KeyedHash::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(key().create_generator().max_security_strength(), SecurityStrength::_128bit);
        assert_eq!(size_of::<BLAKE3KeyedHashKey>(), 32);
    }
}
