//! KMAC, the Keccak Message Authentication Code of NIST SP 800-185 Sec 4.

use crate::SHAKEParams;
use crate::cshake::CSHAKEInternal;
use crate::shake::SHAKEOutput;
use crate::xof_utils::right_encode;
use bouncycastle_core::errors::{HashError, KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, Hash, MAC, SecurityStrength, XOF, XofOutput};
use bouncycastle_utils::ct;

/// The function-name string every KMAC binds, per SP 800-185 Sec 4.3. Fixed by the specification:
/// it is what separates KMAC from any other cSHAKE-derived function.
const KMAC_FUNCTION_NAME: &[u8] = b"KMAC";

/// Internal struct for KMAC. Use [`crate::KMAC128`] or [`crate::KMAC256`].
///
/// KMAC is cSHAKE with the function name `"KMAC"`, the key bound to the front of the message and
/// the requested output length bound to the end (Sec 4.3):
///
/// ```text
/// KMAC128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(L),
///                                 L, "KMAC", S)
/// ```
///
/// # Two functions, not one function truncated
///
/// The output length is *absorbed*, so KMAC at one length is unrelated to KMAC at another --
/// Sec 1 puts it as "any change in the requested output length completely changes the function".
/// That is why [`Self::new_with_params`] takes the length up front and [`MAC::do_final`] produces
/// exactly that many bytes.
///
/// [`KMACXOFInternal`] is the separate function of Sec 4.3.1, KMACXOF, which binds
/// `right_encode(0)` instead and produces as much output as asked for. Its bytes are *not* a
/// prefix of the fixed-length KMAC over the same inputs, and are not meant to be.
pub struct KMACInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    output_len: usize,
    strength: SecurityStrength,
}

impl<PARAMS: SHAKEParams> Algorithm for KMACInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::KMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> KMACInternal<PARAMS> {
    /// A new KMAC with a customization string and an output length of the caller's choosing.
    ///
    /// `output_len` is `L` in bytes and is bound into the computation, so it must be the length the
    /// verifier will use. `customization` may be empty. [`MAC::new`] is this with no customization
    /// and the nominal output length.
    ///
    /// Sec 8.4.1 requires the key to be at least as long as the security strength for approved use;
    /// that is enforced through the key's [`SecurityStrength`] tag, exactly as `HMAC` does, and
    /// [`MAC::new_allow_weak_key`] is the escape hatch.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the key is not tagged as a MAC key, or -- unless
    /// `allow_weak_key` -- if it is tagged below this KMAC's security strength.
    pub fn new_with_params(
        key: &impl KeyMaterialTrait,
        customization: &[u8],
        output_len: usize,
        allow_weak_key: bool,
    ) -> Result<Self, MACError> {
        // Same stance as HMAC: an all-zero key is Zeroized rather than MACKey, and is allowed
        // through so callers are not forced to re-tag it.
        if !(key.key_type() == KeyType::Zeroized || key.key_type() == KeyType::MACKey) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }
        let strength = SecurityStrength::from_bits(PARAMS::SIZE as usize);
        if !allow_weak_key && key.security_strength() < strength {
            Err(KeyMaterialError::SecurityStrength(
                "KMAC::new(): provided key has a lower security strength than the instantiated KMAC",
            ))?
        }

        let mut cshake = CSHAKEInternal::<PARAMS>::new(KMAC_FUNCTION_NAME, customization);
        // Sec 4.3 step 1: bytepad(encode_string(K), rate), absorbed rather than materialised.
        crate::cshake::absorb_bytepad_strings(&mut cshake, &[key.ref_to_bytes()]);

        Ok(Self { cshake, output_len, strength })
    }

    /// Absorbs `right_encode(value)`, the length binding of Sec 4.3 step 1.
    fn absorb_right_encode(&mut self, value: u64) {
        let (buf, len) = right_encode(value);
        self.cshake.do_update(&buf[..len]);
    }
}

impl<PARAMS: SHAKEParams> MAC for KMACInternal<PARAMS> {
    /// A KMAC with no customization string, producing the nominal output length -- 32 bytes for
    /// KMAC128 and 64 for KMAC256. Use [`Self::new_with_params`] to choose either.
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let len = (PARAMS::SIZE as usize) / 4;
        Self::new_with_params(key, &[], len, false)
    }

    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let len = (PARAMS::SIZE as usize) / 4;
        Self::new_with_params(key, &[], len, true)
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    fn mac(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn mac_out(mut self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        self.do_update(data);
        self.do_final_out(out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.cshake.do_update(data);
    }

    fn do_final(mut self) -> Vec<u8> {
        let n = self.output_len;
        // Sec 4.3 step 1: the requested length is bound into the input before any output.
        self.absorb_right_encode((n as u64) * 8);
        self.cshake.into_output().do_output(n)
    }

    fn do_final_out(mut self, out: &mut [u8]) -> Result<usize, MACError> {
        if out.len() < self.output_len {
            return Err(MACError::InvalidLength(
                "output buffer is smaller than the KMAC output length",
            ));
        }
        let n = self.output_len;
        self.absorb_right_encode((n as u64) * 8);
        Ok(self.cshake.into_output().do_output_out(&mut out[..n]))
    }

    /// Compares in constant time, and only against the full output length: a caller must not be
    /// able to pass verification by supplying a shorter prefix.
    fn do_verify_final(self, mac: &[u8]) -> bool {
        if mac.len() != self.output_len {
            return false;
        }
        let computed = self.do_final();
        ct::ct_eq_bytes(&computed, mac)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        self.strength
    }
}

/// Internal struct for KMACXOF. Use [`crate::KMACXOF128`] or [`crate::KMACXOF256`].
///
/// KMACXOF is the arbitrary-output-length function of SP 800-185 Sec 4.3.1: KMAC with
/// `right_encode(0)` bound in place of the output length.
///
/// ```text
/// KMACXOF128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(0),
///                                    L, "KMAC", S)
/// ```
///
/// # Why this is a separate type from [`KMACInternal`]
///
/// The Recommendation defines them as two functions, and they are: over identical inputs KMAC and
/// KMACXOF produce unrelated output, which the published sample values demonstrate directly. They
/// also want different traits -- KMAC's length is fixed at construction and bound into the
/// computation, which is `MAC`; KMACXOF's is not bound at all, which is `XOF`. Since `MAC` and
/// `Hash` share five method names (`do_update`, `do_final`, `output_len` and two more), one type
/// implementing both would make every one of those calls ambiguous, so they are separate types.
///
/// Because the length is *not* bound here, output at one length really is a prefix of output at a
/// longer one -- the opposite of fixed-length KMAC -- so [`Hash::do_final`] is the first
/// [`Hash::output_len`] bytes of the same stream [`XOF::into_output`] produces.
#[derive(Clone)]
pub struct KMACXOFInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    strength: SecurityStrength,
}

impl<PARAMS: SHAKEParams> Algorithm for KMACXOFInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::KMACXOF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> KMACXOFInternal<PARAMS> {
    /// A new KMACXOF under `key`, optionally customized by `customization`.
    ///
    /// The key requirements are [`KMACInternal::new_with_params`]'s: tagged as a MAC key, and at
    /// least the security strength unless `allow_weak_key`.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the key is not a MAC key, or is tagged too weak.
    pub fn new(
        key: &impl KeyMaterialTrait,
        customization: &[u8],
        allow_weak_key: bool,
    ) -> Result<Self, MACError> {
        // The key binding is identical to KMAC's; only the length encoding differs, and that is
        // applied when output begins.
        let kmac = KMACInternal::<PARAMS>::new_with_params(key, customization, 0, allow_weak_key)?;
        Ok(Self { cshake: kmac.cshake, strength: kmac.strength })
    }

    /// Absorbs `right_encode(0)`, the Sec 4.3.1 length binding, ending the input phase.
    fn bind_zero_length(&mut self) {
        let (buf, len) = right_encode(0);
        self.cshake.do_update(&buf[..len]);
    }
}

impl<PARAMS: SHAKEParams> Hash for KMACXOFInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.cshake.block_bitlen()
    }

    /// The nominal length, 32 or 64 bytes. Unlike [`KMACInternal`] this is not bound into the
    /// computation -- it is only how many bytes [`Hash::do_final`] takes from the stream.
    fn output_len(&self) -> usize {
        self.cshake.output_len()
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        let n = self.output_len();
        self.do_update(data);
        self.into_output().do_output(n)
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.into_output().do_output_out(output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.cshake.do_update(data);
    }

    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_output().do_output(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        self.into_output().do_output_out(output)
    }

    /// # Errors
    /// Always [`HashError::InvalidLength`] for a non-zero `num_bits`: `right_encode(0)` has to
    /// follow the message, and a partial final byte would leave the sponge unable to absorb it
    /// byte-aligned. `num_bits` of 0 means the message ended on a byte boundary and is accepted.
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let n = self.output_len();
        let mut out = vec![0u8; n];
        self.do_final_partial_bits_out(partial_byte, num_bits, &mut out)?;
        Ok(out)
    }

    fn do_final_partial_bits_out(
        self,
        _partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "KMACXOF cannot take a partial final byte: right_encode(0) must follow the message",
            ));
        }
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        self.strength
    }
}

impl<PARAMS: SHAKEParams> XOF for KMACXOFInternal<PARAMS> {
    type Output = SHAKEOutput<PARAMS>;

    fn into_output(mut self) -> Self::Output {
        self.bind_zero_length();
        self.cshake.into_output()
    }

    fn into_output_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Output, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "KMACXOF cannot take a partial final byte: right_encode(0) must follow the message",
            ));
        }
        Ok(self.into_output())
    }

    fn hash_xof(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.do_update(data);
        self.into_output().do_output(result_len)
    }

    fn hash_xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.into_output().do_output_out(output)
    }
}
