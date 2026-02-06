use crate::DUMMY_SEED_512;
use bouncycastle_core_interface::errors::{KeyMaterialError, MACError};
use bouncycastle_core_interface::key_material::{KeyMaterial512, KeyType};
use bouncycastle_core_interface::traits::MAC;
use bouncycastle_core_interface::traits::{KeyMaterial, SecurityStrength};

pub struct TestFrameworkMAC {
    // Put any config options here
}

impl TestFrameworkMAC {
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test_mac<M: MAC>(
        &self,
        key: &impl KeyMaterial,
        input: &[u8],
        expected_output: &[u8],
    ) {
        // Test ::mac()
        let out = M::new_allow_weak_key(key).unwrap().mac(input);
        assert_eq!(out, expected_output);

        // Test ::mac_out
        let mut out = vec![0u8; expected_output.len()];
        let bytes_written = M::new_allow_weak_key(key).unwrap().mac_out(input, &mut out).unwrap();
        assert_eq!(bytes_written, expected_output.len());
        assert_eq!(out, expected_output);

        // Test an output buffer that's too small (should truncate)
        let mut out = vec![0u8; expected_output.len() - 2];
        let bytes_written = M::new_allow_weak_key(key).unwrap().mac_out(input, &mut out).unwrap();
        assert_eq!(bytes_written, expected_output.len() - 2);
        assert_eq!(out, expected_output[..expected_output.len() - 2]);

        // Test an output buffer that's too big (expect the first L bytes to get filled)
        let mut out = vec![0u8; 2 * expected_output.len()];
        let bytes_written = M::new_allow_weak_key(key).unwrap().mac_out(input, &mut out).unwrap();
        assert_eq!(bytes_written, expected_output.len());
        assert_eq!(&out[..expected_output.len()], expected_output);
        assert_eq!(&out[expected_output.len()..], vec![0u8; expected_output.len()]);

        // Test ::verify()
        assert!(M::new_allow_weak_key(key).unwrap().verify(input, expected_output));

        // Test .new(), .do_update(), .do_mac_final()
        // At the same time, test .output_len()
        let mut mac = M::new_allow_weak_key(key).unwrap();
        let output_len = mac.output_len();
        mac.do_update(input);
        let out = mac.do_final();
        assert_eq!(out, expected_output);

        // Test .output_len()
        assert_eq!(output_len, out.len());

        // Test .init(), .do_update(), .do_mac_final_out()
        let mut mac = M::new_allow_weak_key(key).unwrap();
        mac.do_update(input);
        let mut out = vec![0u8; mac.output_len()];
        let out_len = mac.do_final_out(&mut *out).unwrap();
        assert_eq!(out, expected_output);
        assert_eq!(out_len, out.len());

        // Test .init(), .do_update(), .do_verify_final_out()
        let mut mac = M::new_allow_weak_key(key).unwrap();
        mac.do_update(input);
        mac.do_verify_final(expected_output);


        // entropy of input key

        // MACs of all security strengths should throw an error on a no-security (and non-zero) key.

        let mut key_none =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[0..64], KeyType::MACKey).unwrap();
        key_none.set_security_strength(SecurityStrength::None).unwrap();

        match M::new(&key_none) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */ },
            _ => panic!("This should have thrown a KeyMaterialError::SecurityStrength error but it didn't"),
        }

        let mut low_security_key =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        low_security_key.allow_hazardous_operations();
        match M::new_allow_weak_key(key).unwrap().max_security_strength() {
            SecurityStrength::None => {
                low_security_key.truncate(13).unwrap();
                low_security_key.set_security_strength(SecurityStrength::None).unwrap();
            }
            SecurityStrength::_112bit => {
                low_security_key.truncate(28).unwrap();
                low_security_key.set_security_strength(SecurityStrength::None).unwrap();
            }
            SecurityStrength::_128bit => {
                low_security_key.truncate(32).unwrap();
                low_security_key.set_security_strength(SecurityStrength::_112bit).unwrap();
            }
            SecurityStrength::_192bit => {
                low_security_key.truncate(48).unwrap();
                low_security_key.set_security_strength(SecurityStrength::_128bit).unwrap();
            }
            SecurityStrength::_256bit => {
                low_security_key.truncate(64).unwrap();
                low_security_key.set_security_strength(SecurityStrength::_192bit).unwrap();
            }
        };
        low_security_key.drop_hazardous_operations();

        // init
        assert!(low_security_key.security_strength() < M::new_allow_weak_key(key).unwrap().max_security_strength());
        // complains at first
        match M::new(&low_security_key) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */ }
            _ => { panic!("This should have thrown a KeyMaterialError::SecurityStrength error but it didn't") }
        }
        // but fine if you do it with .allow_weak_keys()
        let mut hmac = M::new_allow_weak_key(&low_security_key).unwrap();
        hmac.do_update(b"Hi There");
        hmac.do_final();
    }
}
