use bouncycastle_core_interface::errors::{HashError, KDFError};
use bouncycastle_core_interface::key_material::{KeyMaterialInternal, KeyType};
use bouncycastle_core_interface::traits::{Algorithm, KeyMaterial, SecurityStrength, KDF, XOF};
use bouncycastle_utils::{max, min};
use crate::keccak::KeccakDigest;
use crate::SHAKEParams;


/// Note: FIPS 202 section 7 states:
///
///   "SHAKE128 and SHAKE256 are approved XOFs, whose approved uses will be specified in
/// NIST Special Publications. Although some of those uses may overlap with the uses of approved
/// hash functions, the XOFs are not approved as hash functions, due to the property that is
/// discussed in Sec. A.2."
///
/// Section A.2 describes how SHAKE does not internally diversify its output based on the requested length.
/// For example, the first 32 bytes of SHAKE128("message", 64) and SHAKE128("message", 128), will be identical
/// and equal to SHAKE128("message", 32). Proper hash functions don't do this, and NIST is concerned that
/// this could lead to application vulnerabilities.
///
/// As such, even though SHAKE is physically capable of acting as a hash function, and in fact is secure
/// as such if the provided message includes the requested length, SHAKE does not implement the [Hash] trait.
#[derive(Clone)]
pub struct SHAKE<PARAMS: SHAKEParams> {
    _phantomdata: std::marker::PhantomData<PARAMS>,
    keccak: KeccakDigest,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

// Note: don't need a zeroizing Drop here because all the sensitive info is in KeccakDigest, which has one.

impl<PARAMS: SHAKEParams> Algorithm for SHAKE<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> SHAKE<PARAMS> {
    pub fn new() -> Self {
        Self {
            _phantomdata: std::marker::PhantomData,
            keccak: KeccakDigest::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Swallows errors and simply returns an empty Vec<u8> if the hashes fails for whatever reason.
    fn hash_internal(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.absorb(data);
        self.squeeze(result_len)
    }

    fn hash_internal_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.absorb(data);
        self.squeeze_out(output)
    }

    fn mix_key_internal(&mut self, key: &impl KeyMaterial) {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                max(&self.kdf_security_strength, &key.security_strength()).clone();
            self.kdf_security_strength =
                min(&self.kdf_security_strength, &SecurityStrength::from_bits(PARAMS::SIZE as usize))
                    .clone();
        }

        self.absorb(key.ref_to_bytes())
    }

    fn derive_key_final_internal(
        mut self,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        // It's unfortunate to return an oversized KeyMaterial most of the time, but I've had enough
        // of fighting with Rust traits for now ...
        let mut output_key = KeyMaterialInternal::<64>::new();
        self.derive_key_out_final_internal(additional_input, &mut output_key)?;

        // 128 => 32, 256 => 64
        output_key.truncate(2 * (PARAMS::SIZE as usize) / 8)?;
        Ok(Box::new(output_key))
    }

    fn derive_key_out_final_internal(
        &mut self,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
        // it requires full-entropy input that is at least 2x the bit size (ie 256 bits for SHAKE128, and 512 bits for SHAKE256).
        // TODO: citation needed, which NIST spec did I get this from?
        // TODO: intuitivitely this makes sense since SHAKE256 and SHA3-256 are both KECCAK[512], and SHAKE128 is KECCAK[256],
        // TODO: but I would rather find an actual reference for this "fully-seeded" threshold.
        if self.kdf_entropy < 2 * (PARAMS::SIZE as usize) / 8 {
            self.kdf_key_type = min(&self.kdf_key_type, &KeyType::BytesLowEntropy).clone();
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        self.absorb(additional_input);

        // let mut buf = [0u8; 64];
        output_key.allow_hazardous_operations();
        let bytes_written = self.squeeze_out(output_key.mut_ref_to_bytes().expect("We just set .allow_hazardous_operations(), so this should be fine."));
        output_key.set_key_len(bytes_written)?;

        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
        if self.kdf_key_type == KeyType::Zeroized {
            self.kdf_key_type = KeyType::BytesLowEntropy;
        }
        output_key.set_key_type(self.kdf_key_type)?;
        output_key.set_security_strength(
            min(&self.kdf_security_strength, &SecurityStrength::from_bits(bytes_written * 8))
                .clone(),
        )?;
        output_key.drop_hazardous_operations();
        Ok(bytes_written)
    }
}

impl<PARAMS: SHAKEParams> KDF for SHAKE<PARAMS> {
    /// Returns a [KeyMaterialInternal].
    /// For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
    /// it requires full-entropy input that is at least 2x the bit size (ie 256 bits for SHAKE128, and 512 bits for SHAKE256).
    /// Returns a 32 byte key for SHAKE128 and a 64 byte key for SHAKE256.
    /// To produce longer keys, use [KDF::derive_key_out].
    /// To produce shorter keys, either use [KDF::derive_key_out] or truncate this result down with
    /// [KeyMaterialInternal::truncate].
    fn derive_key(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError> {
        // self.derive_key_from_multiple(&[key], additional_input)
        self.mix_key_internal(key);
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output)
        self.mix_key_internal(key);
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    /// Always returns a full [KeyMaterialInternal]; ie that fills the internal buffer of the
    /// appropriately-sized key material for the underlying cryptographic hash function.
    /// This can be truncated down with [KeyMaterialInternal::truncate].
    /// Returns a 32 byte key for SHAKE128 and a 64 byte key for SHAKE256.
    /// To produce longer keys, use [KDF::derive_key_out].
    /// To produce shorter keys, either use [KDF::derive_key_out] or truncate this result down with [KeyMaterialInternal::truncate].
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
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

impl<PARAMS: SHAKEParams> Default for SHAKE<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHAKEParams> XOF for SHAKE<PARAMS> {
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        self.hash_internal_out(data, output)
    }

    fn absorb(&mut self, data: &[u8]) {
        self.keccak.absorb(data)
    }

    /// Switches to squeezing.
    fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError> {
        if !(1..=7).contains(&num_partial_bits) {
            return Err(HashError::InvalidLength("must be in the range [0,7]"));
        }
        // Mutants note: yep, this is just bit-setting into empty space, so it doesn't matter whether it's OR or XOR.
        let mut final_input: u16 =
            ((partial_byte as u16) & ((1 << num_partial_bits) - 1)) | (0x0F << num_partial_bits);
        let mut final_bits = num_partial_bits + 4;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        self.keccak.absorb_bits(final_input as u8, final_bits).expect("Absorb failed.");

        Ok(())
    }

    fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; num_bytes];
        self.squeeze_out(&mut out);
        out
    }

    fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        if !self.keccak.squeezing {
            self.keccak.absorb_bits(0x0F, 4).expect("Absorb_bits failed");
        };

        self.keccak.squeeze(output)
    }

    fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError> {
        let mut output: u8 = 0;
        self.squeeze_partial_byte_final_out(num_bits, &mut output)?;
        Ok(output)
    }

    /// Result is the number of bits squezed into `output`.
    fn squeeze_partial_byte_final_out(
        mut self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError> {
        if !(1..=7).contains(&num_bits) {
            return Err(HashError::InvalidLength("must be in the range [0,7]"));
        }

        let mut buf = [0u8; 1];
        self.keccak.squeeze(&mut buf);
        *output = buf[0] >> 8 - num_bits;
        Ok(())
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}