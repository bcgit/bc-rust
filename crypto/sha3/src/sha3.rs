use bouncycastle_core_interface::errors::{HashError, KDFError};
use bouncycastle_core_interface::key_material::{KeyMaterialSized, KeyType};
use bouncycastle_core_interface::traits::{Hash, KeyMaterial, SecurityStrength, KDF};
use bouncycastle_utils::{max, min};
use crate::keccak::KeccakDigest;
use crate::SHA3Params;

#[derive(Clone)]
pub struct SHA3<PARAMS: SHA3Params> {
    _params: std::marker::PhantomData<PARAMS>,
    keccak: KeccakDigest,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

// Note: don't need a zeroizing Drop here because all the sensitive info is in KeccakDigest, which has one.

impl<PARAMS: SHA3Params> SHA3<PARAMS> {
    pub fn new() -> Self {
        Self {
            _params: std::marker::PhantomData,
            keccak: KeccakDigest::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Swallows errors and simply returns an empty Vec<u8> if the hashes fails for whatever reason.
    fn hash_internal(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn mix_key_internal(&mut self, key: &impl KeyMaterial) {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                max(&self.kdf_security_strength, &key.security_strength()).clone();
            self.kdf_security_strength = min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(PARAMS::OUTPUT_LEN * 8 / 2),
            )
                .clone();
        }

        self.do_update(key.ref_to_bytes())
    }

    fn derive_key_final_internal(
        self,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        let mut output_key = KeyMaterialSized::<64>::new();
        self.derive_key_out_final_internal(additional_input, &mut output_key)?;

        Ok(Box::new(output_key))
    }

    fn derive_key_out_final_internal(
        mut self,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
        // it requires full-entropy input that is at least block length.
        // TODO: citation needed, which NIST spec did I get this from?
        if self.kdf_entropy < PARAMS::OUTPUT_LEN {
            self.kdf_key_type = min(&self.kdf_key_type, &KeyType::BytesLowEntropy).clone();
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        self.do_update(additional_input);

        let mut key_type = self.kdf_key_type.clone();
        let output_security_strength = self.kdf_security_strength.clone();
        output_key.allow_hazardous_operations();
        let bytes_written = self.do_final_out(output_key.mut_ref_to_bytes()?);
        output_key.set_key_len(bytes_written)?;

        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
        if key_type == KeyType::Zeroized {
            key_type = KeyType::BytesLowEntropy;
        }
        output_key.set_key_type(key_type)?;
        output_key.set_security_strength(
            min(&output_security_strength, &SecurityStrength::from_bits(bytes_written * 8)).clone(),
        )?;
        output_key.drop_hazardous_operations();
        output_key.truncate(min(&output_key.key_len(), &PARAMS::OUTPUT_LEN).clone())?;
        Ok(bytes_written)
    }
}

impl<PARAMS: SHA3Params> Default for SHA3<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA3Params> Hash for SHA3<PARAMS> {
    /// As per FIPS 202 Table 3.
    /// Required, for example, to compute the pad lengths in HMAC.
    fn block_bitlen(&self) -> usize {
        PARAMS::BLOCK_LEN * 8
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output: Vec<u8> = vec![0u8; PARAMS::OUTPUT_LEN];
        _ = self.hash_internal(data, &mut output[..]);
        output
    }

    fn hash_out(self, data: &[u8], mut output: &mut [u8]) -> usize {
        self.hash_internal(data, &mut output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.keccak.absorb(data)
    }

    fn do_final(self) -> Vec<u8> {
        let dbg_rslt_len = self.output_len();
        let mut output: Vec<u8> = vec![0u8; self.output_len()];
        let bytes_written = self.do_final_out(output.as_mut_slice());
        debug_assert_eq!(bytes_written, dbg_rslt_len);

        output
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        self.keccak.absorb_bits(0x02, 2).expect("do_final_out: keccak.absorb_bits failed."); // this shouldn't fail because by construction you can only enter this function once, and this is the only way to absorb partial bits.

        let bytes_written = if output.len() <= self.output_len() {
            self.keccak.squeeze(output)
        } else {
            let min =
                if output.len() >= self.output_len() { self.output_len() } else { output.len() };
            self.keccak.squeeze(&mut output[..min])
        };
        bytes_written
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let dbg_rslt_len = self.output_len();
        let mut output: Vec<u8> = vec![0u8; self.output_len()];
        let bytes_written =
            self.do_final_partial_bits_out(partial_byte, num_partial_bits, output.as_mut_slice())?;
        debug_assert_eq!(bytes_written, dbg_rslt_len);

        Ok(output)
    }

    fn do_final_partial_bits_out(
        mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        // Mutants note: yep, this is just bit-setting into empty space, so it doesn't matter whether it's OR or XOR.
        let mut final_input: u16 =
            ((partial_byte as u16) & ((1 << num_partial_bits) - 1)) | (0x02 << num_partial_bits);
        let mut final_bits = num_partial_bits + 2;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        self.keccak.absorb_bits(final_input as u8, final_bits)?;

        let min = if output.len() >= self.output_len() { self.output_len() } else { output.len() };
        Ok(self.keccak.squeeze(&mut output[..min]))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/// SHA3 is allowed to be used as a KDF in the form HASH(X) as per NIST SP 800-56C.
impl<PARAMS: SHA3Params> KDF for SHA3<PARAMS> {
    /// Returns a [KeyMaterialSized].
    /// For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
    /// it requires full-entropy input that is at least the bit size (ie 256 bits for SHA3-256, etc).
    fn derive_key(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        self.mix_key_internal(key);
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output_key)
        self.mix_key_internal(key);
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn derive_key_from_multiple(
        mut self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_from_multiple_out(
        mut self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_internal(keys, additional_input, output_key)
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}