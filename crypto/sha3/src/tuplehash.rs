//! TupleHash, the tuple-hashing function of NIST SP 800-185 Sec 5.

use crate::SHAKEParams;
use crate::cshake::{CSHAKEInternal, absorb_encoded_string_into};
use crate::shake::SHAKEOutput;
use crate::xof_utils::right_encode;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, XOF, XOFOutput};

/// The function-name string every TupleHash binds, per SP 800-185 Sec 5.3.
const TUPLEHASH_FUNCTION_NAME: &[u8] = b"TupleHash";

/// Internal struct for TupleHash. Use [`crate::TUPLEHASH128`] or [`crate::TUPLEHASH256`].
///
/// TupleHash hashes a *sequence of strings* unambiguously (Sec 5.1): each element is length-
/// prefixed with `encode_string` before absorption, so the boundaries between elements are part of
/// the computation. `("abc", "d")` and `("ab", "cd")` therefore hash differently, even though the
/// concatenations are identical -- which is the whole point of the function.
///
/// ```text
/// TupleHash128(X, L, S) = cSHAKE128(encode_string(X[0]) || ... || right_encode(L),
///                                   L, "TupleHash", S)
/// ```
///
/// # `do_update` appends an element, it does not append bytes
///
/// This is the one place TupleHash departs from the usual [`Hash`] contract. For every other hash,
/// feeding the input in pieces gives the same answer as feeding it at once; here each
/// [`Hash::do_update`] call is one tuple element, so the chunking *is* the input. It is worth
/// stating plainly, because code that treats a `TupleHash` as an interchangeable `Hash` and
/// re-chunks its input will silently compute something else.
///
/// [`TupleHashXOFInternal`] is the arbitrary-output-length function of Sec 5.3.1.
#[derive(Clone)]
pub struct TupleHashInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    output_len: usize,
}

impl<PARAMS: SHAKEParams> Algorithm for TupleHashInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::TUPLEHASH_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> TupleHashInternal<PARAMS> {
    /// A new TupleHash producing `output_len` bytes, optionally customized.
    ///
    /// `output_len` is `L` and is bound into the computation (Sec 5.3 step 4), so a different
    /// length is a different function rather than a longer or shorter view of the same one.
    pub fn new(customization: &[u8], output_len: usize) -> Self {
        Self { cshake: CSHAKEInternal::new(TUPLEHASH_FUNCTION_NAME, customization), output_len }
    }

    /// Hashes a whole tuple in one call, the shape the specification is written in.
    pub fn hash_tuple(mut self, tuple: &[&[u8]]) -> Vec<u8> {
        for element in tuple {
            self.do_update(element);
        }
        self.do_final()
    }
}

impl<PARAMS: SHAKEParams> Hash for TupleHashInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.cshake.block_bitlen()
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    /// Hashes `data` as a one-element tuple. For more than one element use
    /// [`Self::hash_tuple`] or successive [`Hash::do_update`] calls.
    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    /// Appends **one tuple element**. See the note on the type: this is not byte-wise streaming.
    fn do_update(&mut self, data: &[u8]) {
        absorb_encoded_string_into(&mut self.cshake, data);
    }

    fn do_final(mut self) -> Vec<u8> {
        let n = self.output_len;
        let (buf, len) = right_encode((n as u64) * 8);
        self.cshake.do_update(&buf[..len]);
        self.cshake.into_output().do_output(n)
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        let n = self.output_len;
        let (buf, len) = right_encode((n as u64) * 8);
        self.cshake.do_update(&buf[..len]);
        // Per Hash::do_final_out: a short buffer is filled and the digest truncated, a long one
        // takes the digest in its first output_len bytes and zeros after it. `n` is bound into the
        // computation either way -- the buffer's length never reaches right_encode above, so a
        // truncated read is this TupleHash cut short, not the TupleHash of a shorter length.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.cshake.into_output().do_output_out(&mut output[..written])
    }

    /// # Errors
    /// Always [`HashError::InvalidLength`] for a non-zero `num_bits`: `right_encode(L)` has to
    /// follow the tuple, which a partial final byte would prevent.
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let mut out = vec![0u8; self.output_len];
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
                "TupleHash cannot take a partial final byte: the length encoding must follow",
            ));
        }
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

/// Internal struct for TupleHashXOF. Use [`crate::TUPLEHASHXOF128`] or [`crate::TUPLEHASHXOF256`].
///
/// The arbitrary-output-length TupleHash of Sec 5.3.1: `right_encode(0)` in place of the length.
/// As with KMAC, it is a *different function* from the fixed-length one, not a longer view of it,
/// and it is a separate type for the same reason -- but here the length not being bound means
/// output at one length really is a prefix of output at a longer one.
///
/// [`Hash::do_update`] appends one tuple element, exactly as for [`TupleHashInternal`].
#[derive(Clone)]
pub struct TupleHashXOFInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
}

impl<PARAMS: SHAKEParams> Algorithm for TupleHashXOFInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::TUPLEHASHXOF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> TupleHashXOFInternal<PARAMS> {
    /// A new TupleHashXOF, optionally customized.
    pub fn new(customization: &[u8]) -> Self {
        Self { cshake: CSHAKEInternal::new(TUPLEHASH_FUNCTION_NAME, customization) }
    }

    /// Hashes a whole tuple and returns the output stream.
    pub fn output_for(mut self, tuple: &[&[u8]]) -> SHAKEOutput<PARAMS> {
        for element in tuple {
            self.do_update(element);
        }
        self.into_output()
    }
}

impl<PARAMS: SHAKEParams> Hash for TupleHashXOFInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.cshake.block_bitlen()
    }

    /// The nominal length, 32 or 64 bytes. Not bound into the computation -- see
    /// [`TupleHashXOFInternal`].
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

    /// Appends **one tuple element**.
    fn do_update(&mut self, data: &[u8]) {
        absorb_encoded_string_into(&mut self.cshake, data);
    }

    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_output().do_output(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        self.into_output().do_output_out(output)
    }

    /// # Errors
    /// Always [`HashError::InvalidLength`] for a non-zero `num_bits`; see
    /// [`TupleHashInternal::do_final_partial_bits`].
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
        _partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "TupleHashXOF cannot take a partial final byte: right_encode(0) must follow",
            ));
        }
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

impl<PARAMS: SHAKEParams> XOF for TupleHashXOFInternal<PARAMS> {
    type Output = SHAKEOutput<PARAMS>;

    fn into_output(mut self) -> Self::Output {
        // Sec 5.3.1 step 4: right_encode(0) rather than the length.
        let (buf, len) = right_encode(0);
        self.cshake.do_update(&buf[..len]);
        self.cshake.into_output()
    }

    fn into_output_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Output, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "TupleHashXOF cannot take a partial final byte: right_encode(0) must follow",
            ));
        }
        Ok(self.into_output())
    }
}
