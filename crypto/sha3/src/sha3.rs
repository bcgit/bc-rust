use crate::SHA3Params;
use crate::keccak::{
    KeccakInternal, SHA3_FAMILY_STATE_LEN, SUSPENDED_SHA3_STATE_LEN, deserialize_sha3_family_state,
    serialize_sha3_family_state,
};
use bouncycastle_core::errors::{HashError, KDFError, SuspendableError};
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, KDF, SecurityStrength, Suspendable};
use bouncycastle_utils::{max, min};

/// Internal struct for SHA3.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// provided and NIST-approved parameters.
#[derive(Clone)]
pub struct SHA3Internal<PARAMS: SHA3Params> {
    _params: core::marker::PhantomData<PARAMS>,
    keccak: KeccakInternal,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

// Note: zeroizing Drop is not necessary here because all the sensitive info is in KeccakDigest, which has one.

impl<PARAMS: SHA3Params> SHA3Internal<PARAMS> {
    /// Get a new SHA3 instance, ready for use.
    pub fn new() -> Self {
        Self {
            _params: core::marker::PhantomData,
            keccak: KeccakInternal::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Swallows errors and simply returns an empty Vec<u8> if the hashes fails for whatever reason.
    fn hash_internal(mut self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        self.do_update(data);
        self.do_final_out(output)
    }

    fn mix_key_internal(&mut self, key: &impl KeyMaterialTrait) {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                *max(&self.kdf_security_strength, &key.security_strength());
            self.kdf_security_strength = *min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(PARAMS::OUTPUT_LEN * 8 / 2),
            );
        }

        self.do_update(key.ref_to_bytes())
    }

    fn derive_key_final_internal(
        self,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        let mut output_key = KeyMaterial::<64>::new();
        self.derive_key_out_final_internal(additional_input, &mut output_key)?;

        Ok(Box::new(output_key))
    }

    fn derive_key_out_final_internal(
        mut self,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
        // it requires full-entropy input that is at least block length.
        // TODO: citation needed (NIST)
        if self.kdf_entropy < PARAMS::OUTPUT_LEN {
            self.kdf_key_type = *min(&self.kdf_key_type, &KeyType::Unknown);
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        self.do_update(additional_input);

        let mut key_type = self.kdf_key_type;
        let output_security_strength = self.kdf_security_strength;
        let mut bytes_written: usize = 0;
        key_material::do_hazardous_operations(output_key, |output_key| {
            bytes_written = self.do_final_out(output_key.ref_to_bytes_mut()?);
            output_key.set_key_len(bytes_written)?;
            Ok(())
        })
        .expect(
            "both mut_ref_to_bytes() and set_key_len() should be infallible within a hazop block",
        );

        // since computation has been performed, the result will not actually be zeroized,
        // even if all input key material was zeroized.
        if key_type == KeyType::Zeroized {
            key_type = KeyType::Unknown;
        }
        key_material::do_hazardous_operations(&mut *output_key, |output_key| {
            output_key.set_key_type(key_type)?;
            output_key.set_security_strength(*min(
                &output_security_strength,
                &SecurityStrength::from_bits(bytes_written * 8),
            ))
        })
        .expect(
            "both set_key_type() and set_security_strength() should be infallible within a hazop block",
        );

        output_key
            .set_key_len(*min(&output_key.key_len(), &PARAMS::OUTPUT_LEN))
            .expect("should be infallible to truncate key length");
        Ok(bytes_written)
    }
}

impl<PARAMS: SHA3Params> Default for SHA3Internal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA3Params> Algorithm for SHA3Internal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHA3Params> Hash for SHA3Internal<PARAMS> {
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

    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
        // hash_internal zeroizes `output` before writing.
        self.hash_internal(data, output)
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

    // TODO: investigate why this doesn't take a &mut [u8; HASH_LEN] 
    // Being able to do so would improve ergonomics
    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        // this shouldn't fail because, by construction, the function is only called once, 
        // and this is the only way to absorb partial bits.
        self.keccak.absorb_bits(0x02, 2).expect("do_final_out: keccak.absorb_bits failed."); 

        // Truncate to output_len() if the caller supplied a larger buffer (see the Hash trait docs).
        let n = *min(&output.len(), &self.output_len());
        self.keccak.squeeze(&mut output[..n])
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
        output.fill(0);

        // Validate before shifting: `1 << num_partial_bits` on a u16 would overflow for values >= 16,
        // and 8..=15 would silently absorb garbage. 0 is allowed and is equivalent to do_final_out().
        if num_partial_bits > 7 {
            return Err(HashError::InvalidLength("num_partial_bits must be in the range [0,7]"));
        }

        // Mutants note: This is just bit-setting into empty space. 
        // It works the same regardless of whether it's OR or XOR.
        let mut final_input: u16 =
            ((partial_byte as u16) & ((1 << num_partial_bits) - 1)) | (0x02 << num_partial_bits);
        let mut final_bits = num_partial_bits + 2;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        self.keccak.absorb_bits(final_input as u8, final_bits)?;

        let n = *min(&output.len(), &self.output_len());
        Ok(self.keccak.squeeze(&mut output[..n]))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/// SHA3 is allowed to be used as a KDF in the form HASH(X) as per NIST SP 800-56C.
impl<PARAMS: SHA3Params> KDF for SHA3Internal<PARAMS> {
    /// Returns a [`KeyMaterial`].
    /// For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
    /// it requires full-entropy input that is at least the bit size (ie 256 bits for SHA3-256, etc).
    fn derive_key(
        mut self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        self.mix_key_internal(key);
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output_key)
        self.mix_key_internal(key);
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn derive_key_from_multiple(
        mut self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_from_multiple_out(
        mut self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
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

impl<PARAMS: SHA3Params> Suspendable<SUSPENDED_SHA3_STATE_LEN> for SHA3Internal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA3_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_SHA3_STATE_LEN];

        // insert the version tag
        let out: &mut [u8; SHA3_FAMILY_STATE_LEN] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        serialize_sha3_family_state(
            out,
            PARAMS::STATE_TAG,
            &self.keccak,
            self.kdf_key_type,
            self.kdf_security_strength,
            self.kdf_entropy,
        );

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA3_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // check the version tag. At the moment, we have no not_before version to specify.
        let input: &[u8; SHA3_FAMILY_STATE_LEN] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        // The variant tag rejects states from any other SHA3/SHAKE variant; the rate is then the
        // correct one to rebuild with (both are fully determined by the algorithm parameters).
        let rate = 1600 - ((PARAMS::SIZE as usize) << 1);
        let (keccak, kdf_key_type, kdf_security_strength, kdf_entropy) =
            deserialize_sha3_family_state(input, PARAMS::STATE_TAG, rate)?;

        Ok(SHA3Internal {
            _params: core::marker::PhantomData,
            keccak,
            kdf_key_type,
            kdf_security_strength,
            kdf_entropy,
        })
    }
}
