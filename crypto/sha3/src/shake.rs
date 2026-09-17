use crate::SHAKEParams;
use crate::keccak::{
    KeccakInternal, KeccakSize, SHA3_FAMILY_STATE_LEN, SUSPENDED_SHA3_STATE_LEN,
    deserialize_sha3_family_state, serialize_sha3_family_state,
};
use bouncycastle_core::errors::{HashError, KDFError, SuspendableError};
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{
    Algorithm, Hash, KDF, SecurityStrength, Suspendable, XOF, XOFSqueezer,
};
use bouncycastle_utils::{max, min};

/// Internal struct for SHAKE.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// provided and NIST-approved parameters.
///
/// SHAKE is exposed as a [`Hash`] because the core API now treats XOFs as hashes with a nominal
/// output length. The XOF API remains the right interface when the caller chooses an arbitrary
/// output length.
pub struct SHAKEInternal<PARAMS: SHAKEParams> {
    _phantomdata: core::marker::PhantomData<PARAMS>,
    keccak: KeccakInternal,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
}

/// Squeezing state for SHAKE.
pub struct SHAKESqueezer<PARAMS: SHAKEParams> {
    _phantomdata: core::marker::PhantomData<PARAMS>,
    keccak: KeccakInternal,
}

impl<PARAMS: SHAKEParams> Clone for SHAKEInternal<PARAMS> {
    fn clone(&self) -> Self {
        Self {
            _phantomdata: core::marker::PhantomData,
            keccak: self.keccak.clone(),
            kdf_key_type: self.kdf_key_type,
            kdf_security_strength: self.kdf_security_strength,
            kdf_entropy: self.kdf_entropy,
        }
    }
}

impl<PARAMS: SHAKEParams> Clone for SHAKESqueezer<PARAMS> {
    fn clone(&self) -> Self {
        Self { _phantomdata: core::marker::PhantomData, keccak: self.keccak.clone() }
    }
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
    fn hash_internal(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        // The absorb fails if this object has already begun squeezing, which the caller is free to
        // have done: these one-shot APIs take `self`, they do not require a fresh object.
        if self.absorb(data).is_err() {
            return Vec::new();
        }
        self.squeeze(result_len)
    }

    /// Swallows errors and simply returns 0, leaving `output` zeroized, if the hashes fails for
    /// whatever reason.
    fn hash_internal_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        // The absorb fails if this object has already begun squeezing, which the caller is free to
        // have done: these one-shot APIs take `self`, they do not require a fresh object.
        if self.absorb(data).is_err() {
            return 0;
        }
        self.squeeze_out(output)
    }

    fn nominal_output_len() -> usize {
        match PARAMS::SIZE {
            KeccakSize::_128 => 32,
            KeccakSize::_256 => 64,
            _ => unreachable!(),
        }
    }

    /// Compatibility helper for the old one-shot XOF API.
    pub fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    /// Compatibility helper for the old one-shot XOF API.
    pub fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        self.hash_internal_out(data, output)
    }

    /// Compatibility helper for the old streaming API: absorb bytes while still in the input phase.
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        if self.keccak.squeezing {
            return Err(HashError::InvalidState("cannot absorb after squeezing has begun"));
        }
        self.keccak.absorb(data);
        Ok(())
    }

    /// Compatibility helper for the old streaming API: switch to squeezing with a final partial byte.
    pub fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError> {
        if self.keccak.squeezing {
            return Err(HashError::InvalidState("cannot absorb after squeezing has begun"));
        }
        if num_partial_bits > 7 {
            return Err(HashError::InvalidLength("num_partial_bits must be in the range [0,7]"));
        }

        let message_bits = (partial_byte.reverse_bits() as u16) & ((1 << num_partial_bits) - 1);
        let mut final_input: u16 = message_bits | (0x0F << num_partial_bits);
        let mut final_bits = num_partial_bits + 4;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        self.keccak.absorb_bits(final_input as u8, final_bits).expect("Absorb failed.");

        Ok(())
    }

    /// Compatibility helper for the old streaming API: produce `num_bytes` bytes.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; num_bytes];
        self.squeeze_out(&mut out);
        out
    }

    /// Compatibility helper for the old streaming API: fill `output` from the XOF stream.
    pub fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        if !self.keccak.squeezing {
            self.keccak.absorb_bits(0x0F, 4).expect("Absorb_bits failed");
        };

        self.keccak.squeeze(output)
    }

    /// Compatibility helper for the old streaming API: finish with a partial output byte.
    pub fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError> {
        let mut output: u8 = 0;
        self.squeeze_partial_byte_final_out(num_bits, &mut output)?;
        Ok(output)
    }

    /// Compatibility helper for the old streaming API: finish with a partial output byte.
    pub fn squeeze_partial_byte_final_out(
        mut self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError> {
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_bits must be in the range [0,7]"));
        }

        *output = 0;

        let mut buf = [0u8; 1];
        self.squeeze_out(&mut buf);

        *output = buf[0].reverse_bits() & ((0xFF00u16 >> num_bits) as u8);
        Ok(())
    }

    /// Returns [`KDFError::HashError`] wrapping a [`HashError::InvalidState`] if this object has
    /// already begun squeezing, since key material absorbed after that point would not contribute
    /// to the derived key.
    fn mix_key_internal(&mut self, key: &impl KeyMaterialTrait) -> Result<(), KDFError> {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            self.kdf_entropy += key.key_len();
            self.kdf_security_strength =
                *max(&self.kdf_security_strength, &key.security_strength());
            self.kdf_security_strength = *min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(PARAMS::SIZE as usize),
            );
        }

        // The absorb fails if this object has already begun squeezing, which the caller is free to
        // have done: the KDF entry points take `self`, they do not require a fresh object.
        Ok(self.absorb(key.ref_to_bytes())?)
    }

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
            self.kdf_key_type = *min(&self.kdf_key_type, &KeyType::Unknown);
            self.kdf_security_strength = SecurityStrength::None; // BytesLowEntropy can't have a securtiy level.
        }

        // As in mix_key_internal(): the absorb fails if this object has already begun squeezing.
        self.absorb(additional_input)?;

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
            output_key.set_security_strength(*min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(bytes_written * 8),
            ))
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
    fn derive_key(
        mut self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        // self.derive_key_from_multiple(&[key], additional_input)
        self.mix_key_internal(key)?;
        self.derive_key_final_internal(additional_input)
    }

    fn derive_key_out(
        mut self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // self.derive_key_from_multiple_out(&[key], additional_input, output)
        self.mix_key_internal(key)?;
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
    fn derive_key_from_multiple(
        mut self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        for key in keys {
            self.mix_key_internal(*key)?;
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
            self.mix_key_internal(*key)?;
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

impl<PARAMS: SHAKEParams> Hash for SHAKEInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        1600 - ((PARAMS::SIZE as usize) << 1)
    }

    fn output_len(&self) -> usize {
        Self::nominal_output_len()
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        self.hash_internal(data, Self::nominal_output_len())
    }

    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);
        let n = core::cmp::min(output.len(), Self::nominal_output_len());
        self.hash_internal_out(data, &mut output[..n])
    }

    fn do_update(&mut self, data: &[u8]) {
        self.absorb(data).expect("cannot absorb after squeezing has begun")
    }

    fn do_final(self) -> Vec<u8> {
        self.into_squeezer().do_final(Self::nominal_output_len())
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        output.fill(0);
        let n = core::cmp::min(output.len(), Self::nominal_output_len());
        self.into_squeezer().do_final_out(&mut output[..n])
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let squeezer = self.into_squeezer_partial_bits(partial_byte, num_partial_bits)?;
        Ok(squeezer.do_final(Self::nominal_output_len()))
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        output.fill(0);
        let n = core::cmp::min(output.len(), Self::nominal_output_len());
        let squeezer = self.into_squeezer_partial_bits(partial_byte, num_partial_bits)?;
        Ok(squeezer.do_final_out(&mut output[..n]))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

impl<PARAMS: SHAKEParams> XOF for SHAKEInternal<PARAMS> {
    type Squeezer = SHAKESqueezer<PARAMS>;

    fn into_squeezer(mut self) -> Self::Squeezer {
        if !self.keccak.squeezing {
            self.keccak.absorb_bits(0x0F, 4).expect("Absorb_bits failed");
        }
        SHAKESqueezer { _phantomdata: core::marker::PhantomData, keccak: self.keccak }
    }

    fn into_squeezer_partial_bits(
        mut self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        self.absorb_last_partial_byte(partial_byte, num_bits)?;
        Ok(SHAKESqueezer { _phantomdata: core::marker::PhantomData, keccak: self.keccak })
    }

    fn xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    fn xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        self.hash_internal_out(data, output)
    }
}

impl<PARAMS: SHAKEParams> XOFSqueezer for SHAKESqueezer<PARAMS> {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);
        self.keccak.squeeze(output)
    }
}
