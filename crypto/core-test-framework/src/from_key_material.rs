//! Generic behaviour tests for the key constructors [`FromKeyMaterial`] and
//! [`FromAnyKeyMaterial`]: the key-type and security-strength policy that the cipher and MAC
//! suites used to check at every `do_*_init`, now checked once where the key is made.

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::{KeyMaterialError, MACError, SymmetricCipherError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, FromKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::MAC;

/// Instance of the test framework.
pub struct TestFrameworkFromKeyMaterial {
    // Put any config options here
}

impl Default for TestFrameworkFromKeyMaterial {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkFromKeyMaterial {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Exercises the [`FromKeyMaterial`] contract for one key type, whose workers report
    /// `alg_name` and whose strength is `max_strength`.
    ///
    /// Checks, in order:
    /// * material of the right type, unbound or bound to `alg_name`, is accepted;
    /// * material of the wrong [`KeyType`] is refused with [`KeyMaterialError::InvalidKeyType`];
    /// * the security-strength policy matches `max_strength`;
    /// * [`FromKeyMaterial::generate`] draws a key from an RNG of sufficient strength, tagged
    ///   [`FromKeyMaterial::KEY_TYPE`], and refuses one instantiated below the key's strength.
    pub fn test<const KEY_LEN: usize, K: FromKeyMaterial<KEY_LEN>>(
        &self,
        alg_name: &'static str,
        max_strength: SecurityStrength,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], K::KEY_TYPE)
            .unwrap();
        K::from_key_material(&key).unwrap_or_else(|e| {
            panic!("{alg_name}: material of the key's own type must be accepted: {e:?}")
        });

        // the wrong key type
        let other_type = match K::KEY_TYPE {
            KeyType::MACKey => KeyType::SymmetricCipherKey,
            _ => KeyType::MACKey,
        };
        let wrong =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], other_type).unwrap();
        match K::from_key_material(&wrong) {
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
            Ok(_) => panic!("a key of the wrong KeyType must be refused"),
            Err(e) => panic!("a key of the wrong KeyType must be refused as InvalidKeyType: {e:?}"),
        }

        // security strengths too weak, and strong enough
        let mut key = key;
        for ss in [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ] {
            // Skip the strengths a KEY_LEN-byte key cannot carry; see
            // `TestFrameworkElectronicCodeBook`.
            if ss > SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();
            match K::from_key_material(&key) {
                Ok(_) => assert!(
                    ss >= max_strength,
                    "should have required a key at least as strong as the algorithm ({ss:?})"
                ),
                Err(SymmetricCipherError::KeyMaterialError(_)) => assert!(
                    ss < max_strength,
                    "should not have rejected a key strong enough for the algorithm ({ss:?})"
                ),
                Err(e) => panic!("unexpected error for a {ss:?} key: {e:?}"),
            }
        }

        // generate: from a strong enough RNG, and not from a weaker one
        let mut rng = FixedSeedRNG::<KEY_LEN>::new(core::array::from_fn(|i| DUMMY_SEED[200 + i]));
        K::generate(&mut rng).expect("generate from a 256-bit RNG");
        let mut weak = FixedSeedRNG::<KEY_LEN>::new(core::array::from_fn(|i| DUMMY_SEED[200 + i]));
        weak.set_security_strength(SecurityStrength::None);
        match K::generate(&mut weak) {
            Ok(_) => assert!(
                max_strength <= SecurityStrength::None,
                "generate must refuse an RNG below the key's strength"
            ),
            Err(SymmetricCipherError::KeyMaterialError(_)) => {}
            Err(e) => panic!("unexpected error from generate: {e:?}"),
        }
    }
}

/// Instance of the test framework.
pub struct TestFrameworkFromAnyKeyMaterial {
    // Put any config options here
}

impl Default for TestFrameworkFromAnyKeyMaterial {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkFromAnyKeyMaterial {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Exercises the [`FromAnyKeyMaterial`] contract for one MAC key type, given a key its
    /// construction accepts (the strength check is what `from_key_material_allow_weak` skips).
    ///
    /// Checks, in order:
    /// * `from_key_material_allow_weak` accepts `key` and produces a working generator;
    /// * a key tagged at no security strength is refused by `from_key_material` with
    ///   [`KeyMaterialError::SecurityStrength`];
    /// * a key one step below the construction's strength is refused by `from_key_material` and
    ///   accepted by `from_key_material_allow_weak`;
    /// * material of the wrong [`KeyType`] is refused with [`KeyMaterialError::InvalidKeyType`];
    /// * [`FromAnyKeyMaterial::generate`] draws a usable key.
    pub fn test<K: FromAnyKeyMaterial + MacGenerationKey>(&self, key: &impl KeyMaterialTrait) {
        let weak_ok = K::from_key_material_allow_weak(key).expect("allow_weak must accept the key");
        let strength = weak_ok.create_generator().max_security_strength();
        let mut generator = weak_ok.create_generator();
        generator.do_update(b"Hi There");
        assert_eq!(generator.do_final().len(), weak_ok.create_generator().output_len());

        // a no-security (and non-zero) key is refused at any strength
        let mut key_none =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[0..64], KeyType::MACKey).unwrap();
        key_none.set_security_strength(SecurityStrength::None).unwrap();
        match K::from_key_material(&key_none) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
            _ => panic!("a key of no security strength must be refused as SecurityStrength"),
        }

        // one step below the construction's strength: refused, unless weak keys are allowed.
        // The key takes the caller's length where that fits, so a construction that accepts
        // exactly one length is tested at that length.
        let weak_key_len = |default_len: usize, min_len: usize| match key.key_len() {
            1..=64 => key.key_len().max(min_len),
            _ => default_len,
        };
        let mut low =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
        do_hazardous_operations(&mut low, |low| {
            match strength {
                SecurityStrength::None => {
                    low.set_key_len(weak_key_len(13, 0))?;
                    low.set_security_strength(SecurityStrength::None)
                }
                SecurityStrength::_112bit => {
                    low.set_key_len(weak_key_len(28, 0))?;
                    low.set_security_strength(SecurityStrength::None)
                }
                SecurityStrength::_128bit => {
                    low.set_key_len(weak_key_len(32, 14))?;
                    low.set_security_strength(SecurityStrength::_112bit)
                }
                SecurityStrength::_192bit => {
                    low.set_key_len(weak_key_len(48, 16))?;
                    low.set_security_strength(SecurityStrength::_128bit)
                }
                SecurityStrength::_256bit => {
                    low.set_key_len(weak_key_len(64, 24))?;
                    low.set_security_strength(SecurityStrength::_192bit)
                }
                // `SecurityStrength` is `#[non_exhaustive]`, so this arm is required.
                _ => panic!("unhandled SecurityStrength variant -- add a case for it here"),
            }
        })
        .unwrap();
        assert!(low.security_strength() < strength);
        match K::from_key_material(&low) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
            _ => panic!("a key below the construction's strength must be refused"),
        }
        let allowed = K::from_key_material_allow_weak(&low).expect("allow_weak must accept it");
        let mut generator = allowed.create_generator();
        generator.do_update(b"Hi There");
        generator.do_final();

        // the wrong key type
        let cipher_key =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::SymmetricCipherKey)
                .unwrap();
        match K::from_key_material(&cipher_key) {
            Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
            _ => panic!("a key that is not a MAC key must be refused as InvalidKeyType"),
        }
        match K::from_key_material_allow_weak(&cipher_key) {
            Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
            _ => panic!("allow_weak must still refuse a key that is not a MAC key"),
        }

        // generate
        let mut rng = FixedSeedRNG::<64>::new(core::array::from_fn(|i| DUMMY_SEED[300 + i]));
        let generated = K::generate(&mut rng).expect("generate from a 256-bit RNG");
        let mut generator = generated.create_generator();
        generator.do_update(b"Hi There");
        assert_eq!(generator.do_final().len(), generated.create_generator().output_len());
    }
}
