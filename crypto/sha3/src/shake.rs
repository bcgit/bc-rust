use crate::SHAKEParams;
use crate::keccak::{
    KeccakInternal, SHA3_FAMILY_STATE_LEN, SUSPENDED_SHA3_STATE_LEN, deserialize_sha3_family_state,
    serialize_sha3_family_state,
};
use bouncycastle_core::errors::{HashError, KDFError, SuspendableError};
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
// `KeyMaterial` and `KeccakSize` are only used by the alloc-gated `derive_key_final_internal`.
#[cfg(feature = "alloc")]
use crate::keccak::KeccakSize;
#[cfg(feature = "alloc")]
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, KDF, SecurityStrength, Suspendable, XOF};
use bouncycastle_utils::{max, min};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec, vec::Vec};

/// Internal struct for SHAKE.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// provided and NIST-approved parameters.
///
/// Note that even though SHAKE is physically capable of acting as a hash function, and in fact is secure
/// as such if the provided message includes the requested length, SHAKE does not implement the [`Hash`] trait.
/// FIPS 202 section 7 states:
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
#[derive(Clone)]
pub struct SHAKEInternal<PARAMS: SHAKEParams> {
    _phantomdata: core::marker::PhantomData<PARAMS>,
    keccak: KeccakInternal,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

impl<PARAMS: SHAKEParams> Algorithm for SHAKEInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> SHAKEInternal<PARAMS> {
    /// Get a new SHA3 instance, ready for use.
    pub fn new() -> Self {
        Self {
            _phantomdata: core::marker::PhantomData,
            keccak: KeccakInternal::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Swallows errors and simply returns an empty Vec<u8> if the hashes fails for whatever reason.
    #[cfg(feature = "alloc")]
    fn hash_internal(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        // Infallible: this is the only absorb, and it precedes the squeeze below.
        self.absorb(data).expect("absorb precedes squeeze on a fresh SHAKE");
        self.squeeze(result_len)
    }

    fn hash_internal_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        // Infallible: this is the only absorb, and it precedes the squeeze below.
        self.absorb(data).expect("absorb precedes squeeze on a fresh SHAKE");
        self.squeeze_out(output)
    }

    fn mix_key_internal(&mut self, key: &impl KeyMaterialTrait) {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                max(&self.kdf_security_strength, &key.security_strength()).clone();
            self.kdf_security_strength = min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(PARAMS::SIZE as usize),
            )
            .clone();
        }

        // Infallible: mix_key_internal is only called during the absorb phase, before any squeeze.
        self.absorb(key.ref_to_bytes()).expect("absorb precedes squeeze during key mixing");
    }

    #[cfg(feature = "alloc")]
    fn derive_key_final_internal(
        mut self,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        // At the moment, oversized KeyMaterial is returned for most cases.
        let mut output_key = KeyMaterial::<64>::new();
        self.derive_key_out_final_internal(additional_input, &mut output_key)?;

        // truncate
        // 128 => 32, 256 => 64
        match PARAMS::SIZE {
            KeccakSize::_128 => output_key.set_key_len(32).expect("truncate should be infallible"),
            KeccakSize::_256 => output_key.set_key_len(64).expect("truncate should be infallible"),
            _ => unreachable!(),
        }
        Ok(Box::new(output_key))
    }

    fn derive_key_out_final_internal(
        &mut self,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
        // it requires full-entropy input that is at least 2x the bit size (ie 256 bits for SHAKE128, and 512 bits for SHAKE256).
        // TODO: citation needed (NIST)
        // TODO: The intuition behind this is that SHAKE256 and SHA3-256 are both KECCAK[512], and SHAKE128 is KECCAK[256],
        // TODO: However, it is necessary to find an actual reference for this "fully-seeded" threshold.
        if self.kdf_entropy < 2 * (PARAMS::SIZE as usize) / 8 {
            self.kdf_key_type = min(&self.kdf_key_type, &KeyType::Unknown).clone();
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        // Infallible: additional_input is absorbed before the squeeze below, and this method is only
        // reached during the absorb phase.
        self.absorb(additional_input).expect("absorb precedes squeeze during key derivation");

        let mut bytes_written: usize = 0;
        key_material::do_hazardous_operations(output_key, |output_key| {
            bytes_written = self.squeeze_out(
                output_key.ref_to_bytes_mut().expect("Infallible within do_hazardous_operations"),
            );
            output_key.set_key_len(bytes_written)
        })?;

        // since computation has been performed, the result will not actually be zeroized, even if all input key material was zeroized.
        if self.kdf_key_type == KeyType::Zeroized {
            self.kdf_key_type = KeyType::Unknown;
        }
        key_material::do_hazardous_operations(output_key, |output_key| {
            output_key.set_key_type(self.kdf_key_type)?;
            output_key.set_security_strength(
                min(&self.kdf_security_strength, &SecurityStrength::from_bits(bytes_written * 8))
                    .clone(),
            )
        })?;
        Ok(bytes_written)
    }
}

impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_SHA3_STATE_LEN> for SHAKEInternal<PARAMS> {
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

        Ok(SHAKEInternal {
            _phantomdata: core::marker::PhantomData,
            keccak,
            kdf_key_type,
            kdf_security_strength,
            kdf_entropy,
        })
    }
}

impl<PARAMS: SHAKEParams> KDF for SHAKEInternal<PARAMS> {
    /// Returns a [`KeyMaterial`].
    /// For the KDF to be considered "fully-seeded" and be capable of outputting full-entropy KeyMaterials,
    /// it requires full-entropy input that is at least 2x the bit size (ie 256 bits for SHAKE128, and 512 bits for SHAKE256).
    /// Returns a 32 byte key for SHAKE128 and a 64 byte key for SHAKE256.
    /// To produce longer keys, use [`KDF::derive_key_out`].
    /// To produce shorter keys, either use [`KDF::derive_key_out`], truncate this result in place with
    /// [`KeyMaterial::set_key_len`], or copy it into a smaller [`KeyMaterial`] with
    /// [`KeyMaterialTrait::truncate`].
    #[cfg(feature = "alloc")]
    fn derive_key(
        mut self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        // self.derive_key_from_multiple(&[key], additional_input)
        self.mix_key_internal(key);
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output)
        self.mix_key_internal(key);
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    /// Always returns a full [`KeyMaterial`]; ie that fills the internal buffer of the
    /// appropriately-sized key material for the underlying cryptographic hash function.
    /// This can be truncated down in place with [`KeyMaterial::set_key_len`], or copied into a smaller
    /// [`KeyMaterial`] with [`KeyMaterialTrait::truncate`].
    /// Returns a 32 byte key for SHAKE128 and a 64 byte key for SHAKE256.
    /// To produce longer keys, use [`KDF::derive_key_out`].
    /// To produce shorter keys, either use [`KDF::derive_key_out`], truncate this result in place with
    /// [`KeyMaterial::set_key_len`], or copy it into a smaller [`KeyMaterial`] with
    /// [`KeyMaterialTrait::truncate`].
    #[cfg(feature = "alloc")]
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
        for key in keys {
            self.mix_key_internal(*key);
        }
        self.derive_key_out_final_internal(additional_input, output_key)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

impl<PARAMS: SHAKEParams> Default for SHAKEInternal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHAKEParams> XOF for SHAKEInternal<PARAMS> {
    #[cfg(feature = "alloc")]
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        self.hash_internal_out(data, output)
    }

    /// This can throw a [`HashError::InvalidState`] if called after squeezing has begun,
    /// but is safe to consider infallible otherwise -- IE feel free to use `.unwrap()` or `.expect()`
    /// on the result if you are confident that your code cannot call `absorb` after squeezing.
    ///
    /// A rejected call leaves the SHAKE object untouched so the output stream continues consistently.
    /// IE it is safe to attempt to feed in more input and do nothing if the absorb fails
    /// ("safe" in the sense that it won't panic, but it may still produce an incorrect output which
    /// could be insecure in the sense of being predictable or low-entropy).
    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        // A sponge XOF cannot return to absorbing once squeezing has begun (FIPS 202 defines SHAKE as
        // a single function of the whole message; re-absorbing would be an unapproved duplex).
        if self.keccak.squeezing {
            return Err(HashError::InvalidState("cannot absorb after squeezing has begun"));
        }
        self.keccak.absorb(data);
        Ok(())
    }

    /// Switches to squeezing.
    fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError> {
        // Same phase rule as absorb(): reject a partial-byte absorb once squeezing has begun. Checked
        // before any state mutation so a rejected call leaves the sponge untouched.
        if self.keccak.squeezing {
            return Err(HashError::InvalidState("cannot absorb after squeezing has begun"));
        }
        if !(1..=7).contains(&num_partial_bits) {
            return Err(HashError::InvalidLength("must be in the range [0,7]"));
        }
        // Mutants note: This is just bit-setting into empty space.
        // It works the same regardless of whether it's OR or XOR.
        let mut final_input: u16 =
            ((partial_byte as u16) & ((1 << num_partial_bits) - 1)) | (0x0F << num_partial_bits);
        let mut final_bits = num_partial_bits + 4;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        // Infallible: guarded above (not squeezing), the queue is byte-aligned here, and final_bits is
        // in 0..=7 by construction.
        self.keccak.absorb_bits(final_input as u8, final_bits).expect("Absorb failed.");

        Ok(())
    }

    #[cfg(feature = "alloc")]
    fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; num_bytes];
        self.squeeze_out(&mut out);
        out
    }

    fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);

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

        *output = 0;

        let mut buf = [0u8; 1];
        self.keccak.squeeze(&mut buf);
        *output = buf[0] >> 8 - num_bits;
        Ok(())
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}
