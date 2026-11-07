use crate::SHA3Params;
use crate::kdf_credit::{KdfCredit, len_prefix};
use crate::keccak::{
    KeccakInternal, SHA3_FAMILY_STATE_LEN, SUSPENDED_SHA3_STATE_LEN, deserialize_sha3_family_state,
    serialize_sha3_family_state,
};
use bouncycastle_core::errors::{HashError, KDFError, SuspendableError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, Hash, HashOneShot, KDF, Suspendable};
use bouncycastle_utils::min;
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};

/// Internal struct for SHA3.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// provided and NIST-approved parameters.
#[derive(Clone)]
pub struct SHA3Internal<PARAMS: SHA3Params> {
    _params: core::marker::PhantomData<PARAMS>,
    keccak: KeccakInternal,
}

// Note: zeroizing Drop is not necessary here because all the sensitive info is in KeccakDigest, which has one.

impl<PARAMS: SHA3Params> SHA3Internal<PARAMS> {
    /// Get a new SHA3 instance, ready for use.
    pub fn new() -> Self {
        Self { _params: core::marker::PhantomData, keccak: KeccakInternal::new(PARAMS::SIZE) }
    }

    /// Appends the SHA3 domain-separation suffix and pads as per FIPS 202 s. 6.1, then squeezes the digest.
    ///
    /// Private, infallible body shared by [`Hash::do_final_out`] and [`Hash::do_final_partial_bits_out`].
    /// The `num_partial_bits` (0..=7, validated by the caller) trailing message bits are the most
    /// significant bits of `partial_byte`, leading bit first (ASN.1 BIT STRING order); they are reversed
    /// below into the FIPS 202 Appendix B.1 bit ordering that Keccak absorbs. FIPS 202 s. 6.1
    /// defines SHA3-d(M) = KECCAK[c](M || 01, d), so the two suffix bits are appended directly above
    /// the message bits; pad10*1 is then applied by the sponge when it switches to squeezing.
    ///
    /// Returns the number of bytes written (`min(output.len(), OUTPUT_LEN)`); a shorter output buffer
    /// truncates the digest, a longer one is zero-filled past the digest.
    fn do_final_bits_out(
        mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> usize {
        debug_assert!(num_partial_bits <= 7);
        output.fill(0);

        // Mutants note: This is just bit-setting into empty space.
        // It works the same regardless of whether it's OR or XOR.
        // The public convention puts the message bits in the most significant bits of partial_byte,
        // leading bit first (ASN.1 BIT STRING order, X.690 s. 8.6.2.1). Keccak absorbs a byte
        // LSB-first: FIPS 202 Algorithm 10 (h2b) step 3 sets message bit T[8i + j] = b_ij, the bit
        // of weight 2^j in byte i. So reverse the bit order and keep the low num_partial_bits bits.
        let message_bits = (partial_byte.reverse_bits() as u16) & ((1 << num_partial_bits) - 1);
        let mut final_input: u16 = message_bits | (0x02 << num_partial_bits);
        let mut final_bits = num_partial_bits + 2;

        // If message bits + suffix fill a whole byte, absorb it as a normal byte first.
        if final_bits >= 8 {
            self.keccak.absorb(&[final_input as u8]);
            final_bits -= 8;
            final_input >>= 8;
        }

        // Infallible: the queue is byte-aligned here, final_bits is in 0..=7 by construction, and a
        // Hash object cannot have started squeezing (do_final_bits_out consumes self and is the only squeeze path).
        self.keccak
            .absorb_bits(final_input as u8, final_bits)
            .expect("absorb_bits is infallible on a byte-aligned, not-yet-squeezing Hash");

        // Truncate to OUTPUT_LEN if the caller supplied a larger buffer (see the Hash trait docs).
        let n = *min(&output.len(), &PARAMS::OUTPUT_LEN);
        self.keccak.squeeze(&mut output[..n])
    }

    /// The derivation of [`KDF`] over this hash: `H(len(ikm_1) || ikm_1 || .. || len(ikm_n) ||
    /// ikm_n || fixed_info)` from a fresh sponge, each length a 4-byte big-endian count so the
    /// keys and the info are bound unambiguously, written to `output_key` at `len` bytes, at
    /// most one hash output, and typed by [`KDF`]'s rule: full-entropy output once at least half
    /// a hash output of credited key material went in, the bytes that carry the strength the
    /// hash can claim. What this instance has absorbed plays no part.
    fn derive_internal(
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        output_key.zeroize();
        if len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if len > PARAMS::OUTPUT_LEN {
            return Err(KDFError::InvalidLength("a SHA-3 KDF derives at most one hash output"));
        }
        if len > output_key.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold len bytes"));
        }

        let mut credit = KdfCredit::new(SecurityStrength::from_bits(PARAMS::OUTPUT_LEN * 8 / 2));
        let mut hash = Self::new();
        for ikm in ikms {
            let prefix = len_prefix(*ikm)
                .map_err(|_| KDFError::InvalidLength("an input key longer than 2^32 - 1 bytes"))?;
            credit.credit(*ikm);
            hash.do_update(&prefix);
            hash.do_update(ikm.ref_to_bytes());
        }
        hash.do_update(fixed_info);

        let (key_type, strength) = credit.output(PARAMS::OUTPUT_LEN / 2, len);
        do_hazardous_operations(output_key, |output_key| {
            let written = hash.do_final_out(&mut output_key.ref_to_bytes_mut()?[..len]);
            output_key.set_key_len(written)?;
            output_key.set_key_type(key_type)?;
            output_key.set_security_strength(strength)
        })?;
        Ok(len)
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

    fn do_final_out(self, output: &mut [u8]) -> usize {
        // A whole-byte message is the zero-partial-bits case of the general finalization.
        self.do_final_bits_out(0, 0, output)
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let mut output: Vec<u8> = vec![0u8; PARAMS::OUTPUT_LEN];
        self.do_final_partial_bits_out(partial_byte, num_partial_bits, &mut output)?;
        Ok(output)
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        // A partial byte has at most 7 bits; 0 means the message ends on a byte boundary.
        if num_partial_bits > 7 {
            return Err(HashError::InvalidLength("num_partial_bits must be in the range [0,7]"));
        }
        // do_final_bits_out appends the SHA-3 `01` suffix, pads, and squeezes.
        Ok(self.do_final_bits_out(partial_byte, num_partial_bits, output))
    }
}

/// One hash of the length-prefixed inputs, `H(len(ikm) || ikm || fixed_info)`, from a fresh
/// sponge, with the entropy bookkeeping of [`KDF`]'s docs. The prefixes bind the keys and the
/// info: `[a, b]` is not `a || b`, and `(a, info)` is not `(a || info, "")`. This is not the
/// SP 800-56Cr2 Section 4.1 one-step KDF, `H(counter || Z || FixedInfo)` over a `Z` whose length
/// the scheme fixes; it has no parameters, so what the instance has absorbed plays no part.
impl<PARAMS: SHA3Params> KDF for SHA3Internal<PARAMS> {
    /// `H(len(ikm) || ikm || fixed_info)` truncated to `len`, at most one hash output.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_internal(&[ikm], fixed_info, len, output_key)
    }

    /// `H(len(ikm_1) || ikm_1 || .. || len(ikm_n) || ikm_n || fixed_info)`, each key credited.
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_internal(ikms, fixed_info, len, output_key)
    }
}

impl<PARAMS: SHA3Params> Suspendable<SUSPENDED_SHA3_STATE_LEN> for SHA3Internal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA3_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_SHA3_STATE_LEN];

        // insert the version tag
        let out: &mut [u8; SHA3_FAMILY_STATE_LEN] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        serialize_sha3_family_state(out, PARAMS::STATE_TAG, &self.keccak);

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
        let keccak = deserialize_sha3_family_state(input, PARAMS::STATE_TAG, rate)?;

        // A SHA3 is only ever suspended while absorbing: finalisation consumes it. A state in
        // the squeezing phase is not one this type produced, and every finalisation of it would
        // fail on absorb_bits' phase check, so refuse it here as SHAKE does.
        if keccak.squeezing {
            return Err(SuspendableError::InvalidData);
        }

        Ok(SHA3Internal { _params: core::marker::PhantomData, keccak })
    }
}

// The one-shot form: `Default` is the function itself.
impl<PARAMS: SHA3Params> HashOneShot for SHA3Internal<PARAMS> {}
