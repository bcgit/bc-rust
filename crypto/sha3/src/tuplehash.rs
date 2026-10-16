//! TupleHash, the tuple-hashing function of NIST SP 800-185 Sec 5.
//!
//! # TupleHash
//! TupleHash is a [`Hash`] over a sequence of strings rather than one string: each
//! [`Hash::do_update`] call is one tuple element, so the chunking is part of the input.
//!
//! The advantage of TupleHash over straight SHAKE is that `TupleHash( ("ab", "cd") )` and `TupleHash( ("a", "bcd") )`
//! yield unrelated outputs.
//!
//! `TupleHash` has two interfaces: `.hash_tuple()` which takes an array-of-arrays, or successive calls to `.do_update()`.
//!```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sha3::tuplehash::TupleHash128;
//!
//! // .hash_tuple() takes tuples as an array of arrays
//! let tuple: [&[u8]; 2] = [b"user id", b"session"];
//! let output: Vec<u8> = TupleHash128::new(b"", 32).hash_tuple(&tuple);
//!
//! // The same computation, one element per .do_update()
//! let mut th = TupleHash128::new(b"", 32);
//! th.do_update(b"user id");
//! th.do_update(b"session");
//! assert_eq!(th.do_final(), output);
//! ```
//!
//! # TupleHashXOF
//! TupleHashXOF, is an arbitrary-output-length form of TupleHash and it implements the [`XOF`] trait.
//! It is a separate function from its fixed-length counterpart since its *final* read ([`XOF::xof`],
//! [`XOFSqueezer::do_output_final`]) binds its output length so that outputs of different lengths,
//! even over the same input, are completely unrelated (ie they don't have the problem that one is
//! a prefix of the other).
//!
//! See [`TupleHashXOF128`] for detail.
//!
//! Example of `KMACXOF128`:
//!```
//! use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
//! use bouncycastle_sha3::tuplehash::{TupleHash128, TupleHashXOF128};
//!
//! let mut tuplehash = TupleHashXOF128::new(b"");
//! tuplehash.do_update(b"Hello, world!");
//! let mut squeezer = tuplehash.into_squeezer();
//! let first: Vec<u8> = squeezer.do_output(16);
//! let more: Vec<u8> = squeezer.do_output(1024);
//!
//! let bound: Vec<u8> = TupleHashXOF128::new(b"").xof(b"Hello, world!", 32);
//! assert_eq!(bound, TupleHash128::new(b"", 32).hash(b"Hello, world!"));
//! assert_ne!(bound[..16], first[..]);
//! ```

use crate::cshake::{
    CSHAKE_COMPONENT_LEN, CSHAKEInternal, CSHAKESqueezer, absorb_encoded_string_into, right_encode,
};
use crate::{SHAKE128Params, SHAKE256Params, SHAKEParams};
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, Hash, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};

/// The name of the TupleHash128 algorithm (NIST SP 800-185 Sec 5).
pub const TUPLEHASH128_NAME: &str = "TupleHash128";
/// The name of the TupleHash256 algorithm (NIST SP 800-185 Sec 5).
pub const TUPLEHASH256_NAME: &str = "TupleHash256";
/// The name of the TupleHashXOF128 algorithm (NIST SP 800-185 Sec 5.3.1).
pub const TUPLEHASHXOF128_NAME: &str = "TupleHashXOF128";
/// The name of the TupleHashXOF256 algorithm (NIST SP 800-185 Sec 5.3.1).
pub const TUPLEHASHXOF256_NAME: &str = "TupleHashXOF256";

/// Length in bytes of the suspended state of TupleHash.
pub const SUSPENDED_TUPLEHASH_STATE_LEN: usize = LIB_VERSION_LEN + CSHAKE_COMPONENT_LEN + 8;
/// Length in bytes of the suspended state of TupleHashXOF.
pub const SUSPENDED_TUPLEHASHXOF_STATE_LEN: usize = LIB_VERSION_LEN + CSHAKE_COMPONENT_LEN;

/// The function-name string every TupleHash binds, per SP 800-185 Sec 5.3.
const TUPLEHASH_FUNCTION_NAME: &[u8] = b"TupleHash";

/// TupleHash128: the unambiguous tuple hash of NIST SP 800-185 Sec 5, 128-bit strength.
///
/// Each [`Hash::do_update`] call appends one *tuple
/// element*, not a run of bytes -- so unlike every other hash here, the chunking is part of the
/// input. See [`TupleHashInternal`].
pub type TupleHash128 = TupleHashInternal<SHAKE128Params>;
/// TupleHash256: see [`TupleHash128`].
pub type TupleHash256 = TupleHashInternal<SHAKE256Params>;
/// TupleHashXOF128: the arbitrary-output-length TupleHash of Sec 5.3.1.
pub type TupleHashXOF128 = TupleHashXOFInternal<SHAKE128Params>;
/// TupleHashXOF256: see [`TupleHashXOF128`].
pub type TupleHashXOF256 = TupleHashXOFInternal<SHAKE256Params>;

/// Internal struct for TupleHash. Use [`TupleHash128`] or [`TupleHash256`].
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

impl<PARAMS: SHAKEParams> SuspendableComponent for TupleHashInternal<PARAMS> {
    const STATE_LEN: usize = CSHAKE_COMPONENT_LEN + 8;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        let (cshake, rest) = out.split_at_mut(CSHAKE_COMPONENT_LEN);
        self.cshake.write_tagged(PARAMS::TUPLEHASH_STATE_TAG, cshake);
        let mut w = CursorMut::new(rest);
        w.u64(self.output_len as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], _key: &()) -> Result<Self, SuspendableError> {
        let (cshake, rest) = state.split_at(CSHAKE_COMPONENT_LEN);
        let cshake = CSHAKEInternal::read_tagged_customized(cshake, PARAMS::TUPLEHASH_STATE_TAG)?;
        let mut r = Cursor::new(rest);
        let output_len = bounded_usize(r.u64(), usize::MAX)?;
        debug_assert!(r.is_done());
        Ok(Self { cshake, output_len })
    }
}

/// Elements are absorbed whole, so a suspended TupleHash is always between elements.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_TUPLEHASH_STATE_LEN> for TupleHashInternal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_TUPLEHASH_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(
        state: [u8; SUSPENDED_TUPLEHASH_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
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
        self.cshake.into_squeezer().do_output(n)
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
        self.cshake.into_squeezer().do_output_out(&mut output[..written])
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

/// Internal struct for TupleHashXOF. Use [`TupleHashXOF128`] or [`TupleHashXOF256`].
///
/// The arbitrary-output-length TupleHash of Sec 5.3.1: `right_encode(0)` in place of the length.
/// As with KMAC, it is a *different function* from the fixed-length one, not a longer view of it,
/// and it is a separate type for the same reason -- but read as a stream
/// ([`XOFSqueezer::do_output`]) the length is not bound, so output at one length is a prefix of
/// output at a longer one.
///
/// A *final* read binds it, because a caller that names a length and will not be back has said
/// what `L` is: [`XOFSqueezer::do_output_final`] and [`XOF::xof`] produce the fixed-length
/// TupleHash of Sec 5.3 (see [`CSHAKESqueezer`]), and the [`Hash`] view -- [`Hash::do_final`],
/// [`Hash::hash`] and [`Hash::hash_out`] -- does the same at the nominal [`Hash::output_len`],
/// since a hash's output length is fixed by its type.
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
    pub fn output_for(mut self, tuple: &[&[u8]]) -> CSHAKESqueezer<PARAMS> {
        for element in tuple {
            self.do_update(element);
        }
        self.into_squeezer()
    }
}

impl<PARAMS: SHAKEParams> SuspendableComponent for TupleHashXOFInternal<PARAMS> {
    const STATE_LEN: usize = CSHAKE_COMPONENT_LEN;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        self.cshake.write_tagged(PARAMS::TUPLEHASHXOF_STATE_TAG, out)
    }

    fn read_state(state: &[u8], _key: &()) -> Result<Self, SuspendableError> {
        let cshake = CSHAKEInternal::read_tagged_customized(state, PARAMS::TUPLEHASHXOF_STATE_TAG)?;
        Ok(Self { cshake })
    }
}

// The absorbing phase, always between elements; the squeezing half is a LengthBoundSqueezer.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_TUPLEHASHXOF_STATE_LEN>
    for TupleHashXOFInternal<PARAMS>
{
    fn suspend(self) -> [u8; SUSPENDED_TUPLEHASHXOF_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(
        state: [u8; SUSPENDED_TUPLEHASHXOF_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
    }
}

impl<PARAMS: SHAKEParams> Hash for TupleHashXOFInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.cshake.block_bitlen()
    }

    /// The nominal length, 32 or 64 bytes: twice the security strength, the length at which the
    /// output carries that strength in full. Bound by the [`Hash`] view and not by the XOF one --
    /// see [`TupleHashXOFInternal`].
    fn output_len(&self) -> usize {
        self.cshake.output_len()
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    /// Appends **one tuple element**.
    fn do_update(&mut self, data: &[u8]) {
        absorb_encoded_string_into(&mut self.cshake, data);
    }

    /// A final read at the nominal length, so `L` is bound: this is the fixed-length TupleHash of
    /// Sec 5.3 at `n = ` [`Hash::output_len`], not a prefix of the TupleHashXOF stream.
    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_squeezer().do_output_final(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len();
        // Per Hash::do_final_out, as for the fixed-length form: a short buffer truncates this
        // TupleHash rather than computing the TupleHash of a shorter length, because `n` is what
        // reaches right_encode, not the buffer's length.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.into_squeezer().do_final_out_with_length((n as u64) * 8, &mut output[..written])
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
    type Squeezer = CSHAKESqueezer<PARAMS>;

    // The `right_encode` of Sec 5.3.1 step 4 is not absorbed here: whether it carries 0 or the
    // length of a final read is LengthBoundSqueezer's decision.
    fn into_squeezer(self) -> Self::Squeezer {
        CSHAKESqueezer::new(self.cshake)
    }

    fn into_squeezer_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "TupleHashXOF cannot take a partial final byte: right_encode(0) must follow",
            ));
        }
        Ok(self.into_squeezer())
    }
}
