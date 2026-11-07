use crate::SHAKEParams;
use crate::keccak::{
    KeccakInternal, SHA3_FAMILY_STATE_LEN, SUSPENDED_SHA3_STATE_LEN, deserialize_sha3_family_state,
    serialize_sha3_family_state,
};
use bouncycastle_core::errors::{HashError, KDFError, SuspendableError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, Hash, HashOneShot, KDF, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_utils::{max, min};

/// Internal struct for SHAKE. Use [`SHAKE128`](crate::SHAKE128) or [`SHAKE256`](crate::SHAKE256);
/// the parameter trait is sealed.
///
/// A [`XOF`], with a [`Hash`] view at the nominal [`Hash::output_len`] (32 or 64 bytes) for
/// callers that want a fixed-length digest. The two views are the same function: the digest is
/// the first bytes of the stream. FIPS 202 Sec 7 approves SHAKE as a XOF and not as a hash
/// function "due to the property that is discussed in Sec. A.2", which is exactly that prefix
/// relation -- SHAKE128(M, 256) is the first 32 bytes of SHAKE128(M, 512). Where two output
/// lengths of one message must be unrelated, use an SP 800-185 function, which binds the length.
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
    /// Get a new SHAKE instance, ready for use.
    pub fn new() -> Self {
        Self {
            _phantomdata: core::marker::PhantomData,
            keccak: KeccakInternal::new(PARAMS::SIZE),
            kdf_key_type: KeyType::Zeroized,
            kdf_security_strength: SecurityStrength::None,
            kdf_entropy: 0,
        }
    }

    /// Writes the SHA3-family state under `tag` into `out`, which is exactly
    /// `SHA3_FAMILY_STATE_LEN` bytes: the sponge and the KDF metadata, with no version header.
    /// For the functions built on SHAKE, which stamp their own tag and add fields of their own.
    pub(crate) fn write_family_state(&self, tag: u8, out: &mut [u8]) {
        let out: &mut [u8; SHA3_FAMILY_STATE_LEN] =
            out.try_into().expect("a family state is exactly SHA3_FAMILY_STATE_LEN bytes");
        serialize_sha3_family_state(
            out,
            tag,
            &self.keccak,
            self.kdf_key_type,
            self.kdf_security_strength,
            self.kdf_entropy,
        );
    }

    /// The reverse of [`Self::write_family_state`]. The sponge comes back in whichever phase it
    /// was suspended in; [`Self::is_squeezing`] says which, and the caller decides what that
    /// means for it.
    pub(crate) fn read_family_state(state: &[u8], tag: u8) -> Result<Self, SuspendableError> {
        let input: &[u8; SHA3_FAMILY_STATE_LEN] =
            state.try_into().map_err(|_| SuspendableError::InvalidData)?;
        let rate = PARAMS::SIZE.rate_bits();
        let (keccak, kdf_key_type, kdf_security_strength, kdf_entropy) =
            deserialize_sha3_family_state(input, tag, rate)?;
        Ok(Self {
            _phantomdata: core::marker::PhantomData,
            keccak,
            kdf_key_type,
            kdf_security_strength,
            kdf_entropy,
        })
    }

    /// Whether the sponge has begun producing output.
    pub(crate) fn is_squeezing(&self) -> bool {
        self.keccak.squeezing
    }

    fn hash_internal(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.keccak.absorb(data);
        self.into_squeezer().do_output(result_len)
    }

    fn hash_internal_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.keccak.absorb(data);
        self.into_squeezer().do_output_out(output)
    }

    /// Ends absorbing with a caller-chosen domain separator and returns the squeezing half.
    ///
    /// SHAKE uses "1111" (FIPS 202 s. 6.2), but cSHAKE uses "00" (SP 800-185 s. 3.3, the `00` in
    /// the `KECCAK[c](... || X || 00, L)` branch), so the suffix cannot be baked in here. Crate
    /// internal: callers outside pick a function, and the function picks its own separator.
    ///
    /// Infallible for the same reason [`Hash::do_update`] is: a `SHAKEInternal` a caller can name
    /// has never squeezed, so the queue is byte-aligned and `absorb_bits` cannot reject it.
    pub(crate) fn into_squeezer_with_suffix(
        mut self,
        suffix: u8,
        num_bits: usize,
    ) -> SHAKESqueezer<PARAMS> {
        self.keccak
            .absorb_bits(suffix, num_bits)
            .expect("a sponge that has not squeezed can absorb a domain separator");
        SHAKESqueezer { shake: self }
    }

    /// Produces the next bytes of the output stream, applying the SHAKE "1111" domain separator
    /// (FIPS 202 s. 6.2) on the first call. Reached only through [`SHAKESqueezer`], so the caller
    /// cannot interleave this with absorbing.
    fn squeeze_internal_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);
        if !self.keccak.squeezing {
            self.keccak.absorb_bits(0x0F, 4).expect("four bits is a whole partial byte");
        }
        self.keccak.squeeze(output)
    }

    fn mix_key_internal(&mut self, key: &(impl KeyMaterialTrait + ?Sized)) {
        // track the strongest input key type
        self.kdf_key_type = *max(&self.kdf_key_type, &key.key_type());

        // track input entropy
        if key.is_full_entropy() {
            // Saturating: the counter is bookkeeping, and a resumed state may carry any value.
            self.kdf_entropy = self.kdf_entropy.saturating_add(key.key_len());
            self.kdf_security_strength =
                *max(&self.kdf_security_strength, &key.security_strength());
            self.kdf_security_strength = *min(
                &self.kdf_security_strength,
                &SecurityStrength::from_bits(PARAMS::SIZE as usize),
            );
        }

        self.keccak.absorb(key.ref_to_bytes());
    }

    /// Absorbs `fixed_info` and squeezes `len` bytes into `output_key`, typed by the rule of
    /// [`KDF`]'s docs: full-entropy output once at least the bytes that carry the strength the
    /// XOF can claim went in as full-entropy key material, 16 for SHAKE128 and 32 for SHAKE256.
    fn derive_out_final_internal(
        mut self,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        output_key.zeroize();
        if len > output_key.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold len bytes"));
        }
        if self.kdf_entropy < PARAMS::SIZE as usize / 8 {
            self.kdf_key_type = *min(&self.kdf_key_type, &KeyType::Unknown);
            self.kdf_security_strength = SecurityStrength::None;
        }

        self.keccak.absorb(fixed_info);

        // since computation has been performed, the result will not actually be zeroized, even
        // if all input key material was zeroized.
        let key_type = if self.kdf_key_type == KeyType::Zeroized {
            KeyType::Unknown
        } else {
            self.kdf_key_type
        };
        let strength = *min(&self.kdf_security_strength, &SecurityStrength::from_bits(len * 8));
        do_hazardous_operations(output_key, |output_key| {
            let written = self.squeeze_internal_out(&mut output_key.ref_to_bytes_mut()?[..len]);
            output_key.set_key_len(written)?;
            output_key.set_key_type(key_type)?;
            output_key.set_security_strength(strength)
        })?;
        Ok(len)
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
        let rate = PARAMS::SIZE.rate_bits();
        let (keccak, kdf_key_type, kdf_security_strength, kdf_entropy) =
            deserialize_sha3_family_state(input, PARAMS::STATE_TAG, rate)?;

        // A SHAKEInternal accepts input, so it must never be rebuilt in the squeezing phase --
        // that is the invariant `Hash::do_update` relies on. A suspended squeezing sponge is a
        // SHAKESqueezer; resume it as one.
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
    /// `SHAKE(ikm || fixed_info)` squeezed to `len` bytes, any length, with the entropy
    /// bookkeeping of [`KDF`]'s docs.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let mut xof = self.clone();
        xof.mix_key_internal(ikm);
        xof.derive_out_final_internal(fixed_info, len, output_key)
    }

    /// `SHAKE(ikm_1 || .. || ikm_n || fixed_info)`, each key credited.
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let mut xof = self.clone();
        for ikm in ikms {
            xof.mix_key_internal(*ikm);
        }
        xof.derive_out_final_internal(fixed_info, len, output_key)
    }
}

impl<PARAMS: SHAKEParams> Default for SHAKEInternal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

/// The squeezing half of SHAKE: what [`XOF::into_squeezer`] hands back.
///
/// It owns the sponge, so the absorbing value is gone by the time this exists. That is the whole
/// point: [`Hash::do_update`] cannot be called on a SHAKE that has begun producing output, because
/// there is no longer a SHAKE to call it on.
pub struct SHAKESqueezer<PARAMS: SHAKEParams> {
    shake: SHAKEInternal<PARAMS>,
}

impl<PARAMS: SHAKEParams> SHAKESqueezer<PARAMS> {
    /// Wraps a sponge that is already squeezing, as read back from a suspended state.
    pub(crate) fn from_squeezing(shake: SHAKEInternal<PARAMS>) -> Self {
        debug_assert!(shake.is_squeezing());
        Self { shake }
    }

    /// [`SHAKEInternal::write_family_state`] for the squeezing half.
    pub(crate) fn write_family_state(&self, tag: u8, out: &mut [u8]) {
        self.shake.write_family_state(tag, out)
    }
}

impl<PARAMS: SHAKEParams> XOFSqueezer for SHAKESqueezer<PARAMS> {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.shake.squeeze_internal_out(output)
    }
}

impl<PARAMS: SHAKEParams> Clone for SHAKESqueezer<PARAMS> {
    fn clone(&self) -> Self {
        Self { shake: self.shake.clone() }
    }
}

/// The squeezing phase suspends and resumes just as the absorbing phase does, so a long output
/// stream can be paused. The serialized form is the same one [`SHAKEInternal`] writes -- the
/// keccak state records which phase it is in -- so the two `from_suspended` implementations
/// accept exactly the states the other rejects.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_SHA3_STATE_LEN> for SHAKESqueezer<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA3_STATE_LEN] {
        self.shake.suspend()
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA3_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let input: &[u8; SHA3_FAMILY_STATE_LEN] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();
        let rate = PARAMS::SIZE.rate_bits();
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
        PARAMS::SIZE.rate_bits()
    }

    /// The nominal digest size: 32 bytes for SHAKE128, 64 for SHAKE256.
    ///
    /// A XOF has no inherent output length, so this is a convention rather than a property of the
    /// function: it is twice the security strength, the length at which the output carries the
    /// full security level.
    fn output_len(&self) -> usize {
        (PARAMS::SIZE as usize) / 4
    }

    /// Infallible, and this is a fact about the type rather than a promise.
    ///
    /// Absorbing after squeezing has begun would be wrong -- FIPS 202 defines SHAKE as a single
    /// function of the whole message, so re-absorbing would be an unapproved duplex -- and it cannot
    /// be expressed: producing output goes through [`XOF::into_squeezer`], which consumes the value,
    /// and every `KDF` entry point takes `self` by value too. A `SHAKEInternal` a caller can still
    /// name has therefore never squeezed.
    fn do_update(&mut self, data: &[u8]) {
        // Pins the invariant the doc above argues for, so a future change that lets a squeezing
        // SHAKE escape fails the test suite rather than silently corrupting the sponge.
        debug_assert!(!self.keccak.squeezing, "a reachable SHAKEInternal has never squeezed");
        self.keccak.absorb(data);
    }

    /// A final read at the nominal length: [`output_len`](Self::output_len) bytes, 32 for
    /// SHAKE128 and 64 for SHAKE256, twice the security strength.
    ///
    /// FIPS 202 gives SHAKE no length to bind -- the output length is not an input to the function
    /// -- so these are the same bytes the squeezer produces. What the `Hash` view fixes is *how
    /// many*: a hash has one output length and it is this one. Ask for another through the XOF.
    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_squeezer().do_output_final(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len();
        // Per Hash::do_final_out: a short buffer is filled and the output truncated, a long one
        // takes it in its first output_len bytes and zeros after. To fill a longer buffer, use the
        // XOF spelling -- XOF::xof_out and XOFSqueezer::do_output_out take their length from the
        // buffer, which is exactly the difference between a XOF and a hash.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.into_squeezer().do_output_final_out(&mut output[..written])
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
        let n = self.output_len();
        // Validated before anything is written, so a rejected call leaves `output` untouched.
        let squeezer = self.into_squeezer_partial_bits(partial_byte, num_bits)?;
        // The buffer rule of do_final_out applies here too: output_len bytes, then zeros.
        let written = n.min(output.len());
        output[written..].fill(0);
        Ok(squeezer.do_output_final_out(&mut output[..written]))
    }
}

/// The absorb-then-squeeze rule, as a compile error rather than a runtime one.
///
/// ```compile_fail
/// use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
/// use bouncycastle_sha3::SHAKE128;
///
/// let mut shake = SHAKE128::new();
/// shake.do_update(b"abc");
/// let mut out = shake.into_squeezer();
/// let _ = out.do_output(32);
/// shake.do_update(b"more");   // `shake` was moved by into_squeezer()
/// ```
///
/// The same value used correctly:
///
/// ```
/// use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
/// use bouncycastle_sha3::SHAKE128;
///
/// let mut shake = SHAKE128::new();
/// shake.do_update(b"abc");
/// let mut out = shake.into_squeezer();
/// assert_eq!(out.do_output(32).len(), 32);
/// ```
impl<PARAMS: SHAKEParams> XOF for SHAKEInternal<PARAMS> {
    type Squeezer = SHAKESqueezer<PARAMS>;

    fn into_squeezer(self) -> Self::Squeezer {
        // The SHAKE domain separator, "1111" (FIPS 202 s. 6.2).
        self.into_squeezer_with_suffix(0x0F, 4)
    }

    fn into_squeezer_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        // The SHAKE domain separator, "1111" (FIPS 202 s. 6.2).
        self.into_squeezer_partial_bits_with_suffix(partial_byte, num_bits, 0x0F, 4)
    }

    fn xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.hash_internal(data, result_len)
    }

    fn xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        // hash_internal_out zeroizes `output` before writing.
        self.hash_internal_out(data, output)
    }
}

impl<PARAMS: SHAKEParams> SHAKEInternal<PARAMS> {
    /// [`XOF::into_squeezer_partial_bits`] with a caller-chosen domain separator, for cSHAKE.
    ///
    /// The message's trailing bits and the separator are absorbed together, so the separator
    /// cannot simply be applied afterwards -- hence the suffix travels in rather than being
    /// hardcoded. See [`Self::into_squeezer_with_suffix`].
    pub(crate) fn into_squeezer_partial_bits_with_suffix(
        mut self,
        partial_byte: u8,
        num_bits: usize,
        suffix: u8,
        suffix_bits: usize,
    ) -> Result<SHAKESqueezer<PARAMS>, HashError> {
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
        let mut final_input: u16 = message_bits | ((suffix as u16) << num_bits);
        let mut final_bits = num_bits + suffix_bits;

        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        // Infallible: this value has never squeezed, the queue is byte-aligned here, and final_bits
        // is in 0..=7 by construction.
        self.keccak.absorb_bits(final_input as u8, final_bits).expect("Absorb failed.");

        // The suffix is already folded into final_input above, so the sponge is finished
        // absorbing; wrap it without applying the suffix a second time.
        Ok(SHAKESqueezer { shake: self })
    }
}

// The one-shot form: `Default` is the function itself.
impl<PARAMS: SHAKEParams> HashOneShot for SHAKEInternal<PARAMS> {}
