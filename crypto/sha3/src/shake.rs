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
    Algorithm, Hash, KDF, SecurityStrength, Suspendable, XOF, XofOutput,
};
use bouncycastle_utils::{max, min};

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

    fn hash_internal(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.keccak.absorb(data);
        self.into_output().do_output(result_len)
    }

    fn hash_internal_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.keccak.absorb(data);
        self.into_output().do_output_out(output)
    }

    /// Produces the next bytes of the output stream, applying the SHAKE "1111" domain separator
    /// (FIPS 202 s. 6.2) on the first call. Reached only through [`SHAKEOutput`], so the caller
    /// cannot interleave this with absorbing.
    fn squeeze_internal_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);
        if !self.keccak.squeezing {
            self.keccak.absorb_bits(0x0F, 4).expect("Absorb_bits failed");
        }
        self.keccak.squeeze(output)
    }

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

        self.keccak.absorb(key.ref_to_bytes());
        Ok(())
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

        self.keccak.absorb(additional_input);

        let mut bytes_written: usize = 0;
        key_material::do_hazardous_operations(output_key, |output_key| {
            bytes_written = self.squeeze_internal_out(
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

        // A SHAKEInternal accepts input, so it must never be rebuilt in the squeezing phase --
        // that is the invariant `Hash::do_update` relies on. A suspended squeezing sponge is a
        // SHAKEOutput; resume it as one.
        if keccak.squeezing {
            // InvalidData rather than a new variant: for this type the phase byte is simply wrong.
            return Err(SuspendableError::InvalidData);
        }

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

/// The squeezing half of SHAKE: what [`XOF::into_output`] hands back.
///
/// It owns the sponge, so the absorbing value is gone by the time this exists. That is the whole
/// point: [`Hash::do_update`] cannot be called on a SHAKE that has begun producing output, because
/// there is no longer a SHAKE to call it on.
pub struct SHAKEOutput<PARAMS: SHAKEParams> {
    shake: SHAKEInternal<PARAMS>,
}

impl<PARAMS: SHAKEParams> XofOutput for SHAKEOutput<PARAMS> {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.shake.squeeze_internal_out(output)
    }
}

impl<PARAMS: SHAKEParams + Clone> Clone for SHAKEOutput<PARAMS> {
    fn clone(&self) -> Self {
        Self { shake: self.shake.clone() }
    }
}

/// The squeezing phase suspends and resumes just as the absorbing phase does, so a long output
/// stream can be paused. The serialized form is the same one [`SHAKEInternal`] writes -- the
/// keccak state records which phase it is in -- so the two `from_suspended` implementations
/// accept exactly the states the other rejects.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_SHA3_STATE_LEN> for SHAKEOutput<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA3_STATE_LEN] {
        self.shake.suspend()
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA3_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let input: &[u8; SHA3_FAMILY_STATE_LEN] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();
        let rate = 1600 - ((PARAMS::SIZE as usize) << 1);
        let (keccak, kdf_key_type, kdf_security_strength, kdf_entropy) =
            deserialize_sha3_family_state(input, PARAMS::STATE_TAG, rate)?;

        // The mirror of the check in `SHAKEInternal::from_suspended`: a state that had not begun
        // producing output is still absorbing, and resuming it here would skip the domain suffix.
        if !keccak.squeezing {
            return Err(SuspendableError::InvalidData);
        }

        Ok(Self {
            shake: SHAKEInternal {
                _phantomdata: core::marker::PhantomData,
                keccak,
                kdf_key_type,
                kdf_security_strength,
                kdf_entropy,
            },
        })
    }
}

impl<PARAMS: SHAKEParams> Hash for SHAKEInternal<PARAMS> {
    /// The sponge rate in bits: `1600 - 2c`, where the capacity `c` is twice the security level
    /// (FIPS 202 Table 3 -- 1344 bits for SHAKE128, 1088 for SHAKE256).
    fn block_bitlen(&self) -> usize {
        1600 - ((PARAMS::SIZE as usize) << 1)
    }

    /// The nominal digest size: 32 bytes for SHAKE128, 64 for SHAKE256.
    ///
    /// A XOF has no inherent output length, so this is a convention rather than a property of the
    /// function. It is BC Java's: `SHAKEDigest.getDigestSize()` returns `fixedOutputLength / 4`,
    /// which is the length at which the output carries the full security level.
    fn output_len(&self) -> usize {
        (PARAMS::SIZE as usize) / 4
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let result_len = self.output_len();
        self.hash_internal(data, result_len)
    }

    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
        // hash_internal_out zeroizes `output` before writing.
        self.hash_internal_out(data, output)
    }

    /// Infallible, and this is a fact about the type rather than a promise.
    ///
    /// Absorbing after squeezing has begun would be wrong -- FIPS 202 defines SHAKE as a single
    /// function of the whole message, so re-absorbing would be an unapproved duplex -- and it cannot
    /// be expressed: producing output goes through [`XOF::into_output`], which consumes the value,
    /// and every `KDF` entry point takes `self` by value too. A `SHAKEInternal` a caller can still
    /// name has therefore never squeezed.
    fn do_update(&mut self, data: &[u8]) {
        // Pins the invariant the doc above argues for, so a future change that lets a squeezing
        // SHAKE escape fails the test suite rather than silently corrupting the sponge.
        debug_assert!(!self.keccak.squeezing, "a reachable SHAKEInternal has never squeezed");
        self.keccak.absorb(data);
    }

    /// Produces [`output_len`](Self::output_len) bytes and ends the object, as BC Java's
    /// `Digest.doFinal(out, outOff)` does via `doFinal(out, outOff, getDigestSize())`.
    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        let mut out = vec![0u8; n];
        self.do_final_out(&mut out);
        out
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        self.into_output().do_output_out(output)
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let mut out = vec![0u8; self.output_len()];
        self.do_final_partial_bits_out(partial_byte, num_bits, &mut out)?;
        Ok(out)
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        // Validated before anything is written, so a rejected call leaves `output` untouched.
        Ok(self.into_output_partial_bits(partial_byte, num_bits)?.do_output_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

/// The absorb-then-squeeze rule, as a compile error rather than a runtime one.
///
/// ```compile_fail
/// use bouncycastle_core::traits::{Hash, XOF, XofOutput};
/// use bouncycastle_sha3::SHAKE128;
///
/// let mut shake = SHAKE128::new();
/// shake.do_update(b"abc");
/// let mut out = shake.into_output();
/// let _ = out.do_output(32);
/// shake.do_update(b"more");   // `shake` was moved by into_output()
/// ```
///
/// The same value used correctly:
///
/// ```
/// use bouncycastle_core::traits::{Hash, XOF, XofOutput};
/// use bouncycastle_sha3::SHAKE128;
///
/// let mut shake = SHAKE128::new();
/// shake.do_update(b"abc");
/// let mut out = shake.into_output();
/// assert_eq!(out.do_output(32).len(), 32);
/// ```
impl<PARAMS: SHAKEParams> XOF for SHAKEInternal<PARAMS> {
    type Output = SHAKEOutput<PARAMS>;

    fn into_output(mut self) -> Self::Output {
        // The SHAKE domain separator, "1111" (FIPS 202 s. 6.2), applied as the sponge switches to
        // squeezing. Infallible: this value has never squeezed (see `do_update`), so the queue is
        // byte-aligned and `absorb_bits` cannot reject it.
        self.keccak.absorb_bits(0x0F, 4).expect("a SHAKE that has not squeezed can absorb bits");
        SHAKEOutput { shake: self }
    }

    fn into_output_partial_bits(
        mut self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Output, HashError> {
        // A partial byte has at most 7 bits; 0 means the message ends on a byte boundary.
        // Checked before any state change, so a rejected call leaves the sponge untouched.
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_bits must be in the range [0,7]"));
        }
        // Mutants note: this is bit-setting into empty space, so OR and XOR behave identically.
        // The public convention puts the message bits in the most significant bits of partial_byte,
        // leading bit first (ASN.1 BIT STRING order, X.690 s. 8.6.2.1). Keccak absorbs a byte
        // LSB-first: FIPS 202 Algorithm 10 (h2b) step 3 sets message bit T[8i + j] = b_ij, the bit
        // of weight 2^j in byte i. So reverse the bit order and keep the low num_bits bits.
        let message_bits = (partial_byte.reverse_bits() as u16) & ((1 << num_bits) - 1);
        let mut final_input: u16 = message_bits | (0x0F << num_bits);
        let mut final_bits = num_bits + 4;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        // Infallible: this value has never squeezed, the queue is byte-aligned here, and final_bits
        // is in 0..=7 by construction.
        self.keccak.absorb_bits(final_input as u8, final_bits).expect("Absorb failed.");

        // The "1111" suffix is already folded into final_input above, so the sponge is finished
        // absorbing; wrap it without applying the suffix a second time.
        Ok(SHAKEOutput { shake: self })
    }

    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        // hash_internal_out zeroizes `output` before writing.
        self.hash_internal_out(data, output)
    }
}
