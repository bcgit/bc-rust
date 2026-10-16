//! ParallelHash, the parallelisable hash of NIST SP 800-185 Sec 6.
//!
//! The purpose of ParallelHash10 is to support the efficient hashing of very long strings, by taking
//! advantage of the parallelism available in modern processors. ParallelHash supports the 128- and
//! 256-bit security strengths, and also provides variable-length output. Changing any input
//! parameter to ParallelHash, even the requested output length, will result in unrelated output. Like
//! the other functions defined in this document, ParallelHash also supports user-selected
//! customization strings.
//!
//! ParallelHash divides the input bit string X into a sequence of contiguous, non-overlapping
//! blocks, each of length B bytes, and then computes the hash value for each block separately.
//! Finally, these hash values are combined and passed to cSHAKE along with the function name
//! (N) of "ParallelHash", the optional customization string S, and some encoded integer values,
//! to generate the final hash value of the function.
//!
//! # ParallelHash
//!
//!```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sha3::parallelhash::ParallelHash128;
//!
//! let output: Vec<u8> = ParallelHash128::new(8192, b"", 32).hash(b"Hello, world!");
//! ```
//!
//! # ParallelHashXOF
//! ParallelHashXOF, is an arbitrary-output-length form of ParallelHash and it implements the [`XOF`] trait.
//! It is a separate function from its fixed-length counterpart since its *final* read ([`XOF::xof`],
//! [`XOFSqueezer::do_output_final`]) binds its output length so that outputs of different lengths,
//! even over the same input, are completely unrelated (ie they don't have the problem that one is
//! a prefix of the other).
//!
//! See [`ParallelHash128`] for detail.
//!
//! Example of `ParallelHash128`:
//! ```
//! use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
//! use bouncycastle_sha3::parallelhash::{ParallelHash128, ParallelHashXOF128};
//!
//! let mut parallelhash = ParallelHashXOF128::new(8192, b"");
//! parallelhash.do_update(b"Hello, world!");
//! let mut squeezer = parallelhash.into_squeezer();
//! let first: Vec<u8> = squeezer.do_output(16);
//! let more: Vec<u8> = squeezer.do_output(1024);
//!
//! let bound: Vec<u8> = ParallelHashXOF128::new(8192, b"").xof(b"Hello, world!", 32);
//! assert_eq!(bound, ParallelHash128::new(8192, b"", 32).hash(b"Hello, world!"));
//! assert_ne!(bound[..16], first[..]);
//! ```

use crate::cshake::{
    CSHAKE_COMPONENT_LEN, CSHAKEInternal, CSHAKESqueezer, absorb_left_encode_into, right_encode,
};
use crate::keccak::SHA3_FAMILY_STATE_LEN;
use crate::shake::SHAKEInternal;
use crate::{SHAKE128Params, SHAKE256Params, SHAKEParams};
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, Hash, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};

/// The name of the ParallelHash128 algorithm (NIST SP 800-185 Sec 6).
pub const PARALLELHASH128_NAME: &str = "ParallelHash128";
/// The name of the ParallelHash256 algorithm (NIST SP 800-185 Sec 6).
pub const PARALLELHASH256_NAME: &str = "ParallelHash256";
/// The name of the ParallelHashXOF128 algorithm (NIST SP 800-185 Sec 6.3.1).
pub const PARALLELHASHXOF128_NAME: &str = "ParallelHashXOF128";
/// The name of the ParallelHashXOF256 algorithm (NIST SP 800-185 Sec 6.3.1).
pub const PARALLELHASHXOF256_NAME: &str = "ParallelHashXOF256";

/// Length in bytes of the suspended state of ParallelHash.
pub const SUSPENDED_PARALLELHASH_STATE_LEN: usize = LIB_VERSION_LEN + PARALLEL_STATE_LEN + 8;
/// Length in bytes of the suspended state of ParallelHashXOF.
pub const SUSPENDED_PARALLELHASHXOF_STATE_LEN: usize = LIB_VERSION_LEN + PARALLEL_STATE_LEN;
/// The [`ParallelState`] layout: the outer cSHAKE, the inner SHAKE's family state, then
/// `block_size`, `block_fill` and `blocks` as `u64`s.
const PARALLEL_STATE_LEN: usize = CSHAKE_COMPONENT_LEN + SHA3_FAMILY_STATE_LEN + 24;

/// The function-name string every ParallelHash binds, per SP 800-185 Sec 6.3.
const PARALLELHASH_FUNCTION_NAME: &[u8] = b"ParallelHash";

/// ParallelHash128: the parallelisable hash of NIST SP 800-185 Sec 6, 128-bit strength.
///
/// The block size `B` is part of the function, not a tuning knob: the same message under a
/// different `B` hashes differently. See [`ParallelHashInternal`].
pub type ParallelHash128 = ParallelHashInternal<SHAKE128Params>;
/// ParallelHash256: see [`ParallelHash128`].
pub type ParallelHash256 = ParallelHashInternal<SHAKE256Params>;
/// ParallelHashXOF128: the arbitrary-output-length ParallelHash of Sec 6.3.1.
pub type ParallelHashXOF128 = ParallelHashXOFInternal<SHAKE128Params>;
/// ParallelHashXOF256: see [`ParallelHashXOF128`].
pub type ParallelHashXOF256 = ParallelHashXOFInternal<SHAKE256Params>;

/// The shared machinery of [`ParallelHashInternal`] and [`ParallelHashXOFInternal`]: the outer
/// cSHAKE, the block being filled, and the count of blocks hashed so far.
#[derive(Clone)]
struct ParallelState<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    block_size: usize,
    /// The block being filled, as the SHAKE over its bytes so far: each block's contribution is
    /// `SHAKE(block, 2c)`, so the sponge can take the bytes as they arrive. Holding the sponge
    /// rather than the bytes keeps this a fixed size whatever `B` is, which a suspended state
    /// needs.
    inner: SHAKEInternal<PARAMS>,
    /// Bytes of the current block absorbed into `inner` so far, always less than `block_size`.
    block_fill: usize,
    blocks: u64,
}

impl<PARAMS: SHAKEParams> ParallelState<PARAMS> {
    /// Each block is hashed to `2c` bits -- 256 for ParallelHash128, 512 for ParallelHash256
    /// (Sec 6.3 step 3, the `256` and `512` in the inner cSHAKE calls).
    const INNER_LEN: usize = (PARAMS::SIZE as usize) / 4;

    fn new(block_size: usize, customization: &[u8]) -> Self {
        assert!(block_size > 0, "SP 800-185 Sec 6.2: the block size B must be positive");
        let mut cshake = CSHAKEInternal::new(PARALLELHASH_FUNCTION_NAME, customization);
        // Step 2: z = left_encode(B).
        absorb_left_encode_into(&mut cshake, block_size as u64);
        Self { cshake, block_size, inner: SHAKEInternal::new(), block_fill: 0, blocks: 0 }
    }

    /// Step 3 for the block in `inner`: finish its digest and absorb it into the outer cSHAKE.
    ///
    /// The inner call is `cSHAKE(block, 2c, "", "")`, which by Sec 3.3 step 1 is plain SHAKE --
    /// so SHAKE is what is used here.
    fn absorb_block_digest(&mut self) {
        let mut digest = [0u8; 64];
        let digest = &mut digest[..Self::INNER_LEN];
        core::mem::replace(&mut self.inner, SHAKEInternal::new()).xof_out(&[], digest);
        self.cshake.do_update(digest);
        self.blocks += 1;
        self.block_fill = 0;
    }

    fn write_state(&self, tag: u8, out: &mut [u8]) {
        let (cshake, rest) = out.split_at_mut(CSHAKE_COMPONENT_LEN);
        self.cshake.write_tagged(tag, cshake);
        let (inner, rest) = rest.split_at_mut(SHA3_FAMILY_STATE_LEN);
        // The inner sponge is plain SHAKE and carries SHAKE's own tag; it is only ever read back
        // from inside this state, under the outer tag.
        self.inner.write_family_state(PARAMS::STATE_TAG, inner);
        let mut w = CursorMut::new(rest);
        w.u64(self.block_size as u64);
        w.u64(self.block_fill as u64);
        w.u64(self.blocks);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], tag: u8) -> Result<Self, SuspendableError> {
        let (cshake, rest) = state.split_at(CSHAKE_COMPONENT_LEN);
        let cshake = CSHAKEInternal::read_tagged_customized(cshake, tag)?;
        let (inner, rest) = rest.split_at(SHA3_FAMILY_STATE_LEN);
        let inner = SHAKEInternal::read_family_state(inner, PARAMS::STATE_TAG)?;
        if inner.is_squeezing() {
            return Err(SuspendableError::InvalidData);
        }
        let mut r = Cursor::new(rest);
        let block_size = bounded_usize(r.u64(), usize::MAX)?;
        // Sec 6.2: 0 < B. The fill is strictly inside the block, since a full block is absorbed
        // the moment it completes.
        if block_size == 0 {
            return Err(SuspendableError::InvalidData);
        }
        let block_fill = bounded_usize(r.u64(), block_size - 1)?;
        let blocks = r.u64();
        debug_assert!(r.is_done());
        Ok(Self { cshake, block_size, inner, block_fill, blocks })
    }

    fn do_update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (self.block_size - self.block_fill).min(data.len());
            let (now, rest) = data.split_at(take);
            self.inner.do_update(now);
            self.block_fill += take;
            data = rest;
            if self.block_fill == self.block_size {
                self.absorb_block_digest();
            }
        }
    }

    /// Flushes the short final block and binds the block count: step 3, and the `right_encode(n)`
    /// half of step 4.
    ///
    /// The `right_encode(L)` that completes step 4 is left to the caller, because which `L` it
    /// carries is not settled here: the fixed-length function knows it up front ([`Self::finish`]),
    /// and the XOF leaves it to the first read ([`CSHAKESqueezer`]).
    fn finish_blocks(mut self) -> CSHAKEInternal<PARAMS> {
        if self.block_fill > 0 {
            self.absorb_block_digest();
        }
        // Step 4: z = z || right_encode(n) ...
        let (buf, len) = right_encode(self.blocks);
        self.cshake.do_update(&buf[..len]);
        self.cshake
    }

    /// [`Self::finish_blocks`], then the `right_encode(L)` that completes step 4.
    ///
    /// `length_bits` is the requested output length of the fixed-length function of Sec 6.3.
    fn finish(self, length_bits: u64) -> CSHAKEInternal<PARAMS> {
        let mut cshake = self.finish_blocks();
        let (buf, len) = right_encode(length_bits);
        cshake.do_update(&buf[..len]);
        cshake
    }
}

/// Internal struct for ParallelHash. Use [`ParallelHash128`] or [`ParallelHash256`].
///
/// ParallelHash splits the message into `B`-byte blocks, hashes each independently, and hashes the
/// concatenated digests (Sec 6.1). The point is that the per-block hashes can be computed in
/// parallel on long inputs; this implementation is sequential, which gives identical output.
///
/// ```text
/// ParallelHash128(X, B, L, S) = cSHAKE128(left_encode(B) || SHAKE128(X[0], 256) || ...
///                                         || right_encode(n) || right_encode(L),
///                                         L, "ParallelHash", S)
/// ```
///
/// # The block size is part of the hash
///
/// `B` is bound by `left_encode(B)`, so the same message under a different block size gives an
/// unrelated result. It is a parameter of the function, not a tuning knob.
///
// Unlike TupleHash128, `do_update` here *is* ordinary byte-wise streaming: the block
// boundaries come from `B`, not from how the caller chunks its calls.
#[derive(Clone)]
pub struct ParallelHashInternal<PARAMS: SHAKEParams> {
    state: ParallelState<PARAMS>,
    output_len: usize,
}

impl<PARAMS: SHAKEParams> Algorithm for ParallelHashInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::PARALLELHASH_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> ParallelHashInternal<PARAMS> {
    /// A new ParallelHash over `block_size`-byte blocks, producing `output_len` bytes.
    ///
    /// # Panics
    /// If `block_size` is zero, which Sec 6.2 forbids (`0 < B`).
    pub fn new(block_size: usize, customization: &[u8], output_len: usize) -> Self {
        Self { state: ParallelState::new(block_size, customization), output_len }
    }
}

impl<PARAMS: SHAKEParams> SuspendableComponent for ParallelHashInternal<PARAMS> {
    const STATE_LEN: usize = PARALLEL_STATE_LEN + 8;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        let (state, rest) = out.split_at_mut(PARALLEL_STATE_LEN);
        self.state.write_state(PARAMS::PARALLELHASH_STATE_TAG, state);
        let mut w = CursorMut::new(rest);
        w.u64(self.output_len as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], _key: &()) -> Result<Self, SuspendableError> {
        let (parallel, rest) = state.split_at(PARALLEL_STATE_LEN);
        let state = ParallelState::read_state(parallel, PARAMS::PARALLELHASH_STATE_TAG)?;
        let mut r = Cursor::new(rest);
        let output_len = bounded_usize(r.u64(), usize::MAX)?;
        debug_assert!(r.is_done());
        Ok(Self { state, output_len })
    }
}

/// Suspends mid-block as well as between blocks: the block being filled travels as its sponge.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_PARALLELHASH_STATE_LEN>
    for ParallelHashInternal<PARAMS>
{
    fn suspend(self) -> [u8; SUSPENDED_PARALLELHASH_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(
        state: [u8; SUSPENDED_PARALLELHASH_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
    }
}

impl<PARAMS: SHAKEParams> Hash for ParallelHashInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.state.cshake.block_bitlen()
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.state.do_update(data);
    }

    fn do_final(self) -> Vec<u8> {
        let n = self.output_len;
        self.state.finish((n as u64) * 8).into_squeezer().do_output(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len;
        // Per Hash::do_final_out: a short buffer is filled and the digest truncated, a long one
        // takes the digest in its first output_len bytes and zeros after it. `n` is bound into the
        // computation either way -- the buffer's length never reaches the length encoding, so a
        // truncated read is this ParallelHash cut short, not the ParallelHash of a shorter length.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.state.finish((n as u64) * 8).into_squeezer().do_output_out(&mut output[..written])
    }

    /// # Errors
    /// Always [`HashError::InvalidLength`] for a non-zero `num_bits`: the block count and length
    /// encodings have to follow the message, which a partial final byte would prevent.
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
                "ParallelHash cannot take a partial final byte: the encodings must follow",
            ));
        }
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

/// Internal struct for ParallelHashXOF (Sec 6.3.1). Use [`ParallelHashXOF128`] or
/// [`ParallelHashXOF256`].
///
/// Binds `right_encode(0)` in place of the output length, so -- as for KMACXOF and TupleHashXOF --
/// it is a different function from the fixed-length one, and its output at one length is a prefix
/// of its output at a longer one.
#[derive(Clone)]
pub struct ParallelHashXOFInternal<PARAMS: SHAKEParams> {
    state: ParallelState<PARAMS>,
}

impl<PARAMS: SHAKEParams> Algorithm for ParallelHashXOFInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::PARALLELHASHXOF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> ParallelHashXOFInternal<PARAMS> {
    /// A new ParallelHashXOF over `block_size`-byte blocks.
    ///
    /// # Panics
    /// If `block_size` is zero (Sec 6.2).
    pub fn new(block_size: usize, customization: &[u8]) -> Self {
        Self { state: ParallelState::new(block_size, customization) }
    }
}

impl<PARAMS: SHAKEParams> SuspendableComponent for ParallelHashXOFInternal<PARAMS> {
    const STATE_LEN: usize = PARALLEL_STATE_LEN;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        self.state.write_state(PARAMS::PARALLELHASHXOF_STATE_TAG, out)
    }

    fn read_state(state: &[u8], _key: &()) -> Result<Self, SuspendableError> {
        Ok(Self { state: ParallelState::read_state(state, PARAMS::PARALLELHASHXOF_STATE_TAG)? })
    }
}

/// The absorbing phase, mid-block or not; the squeezing half is a [`CSHAKESqueezer`].
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_PARALLELHASHXOF_STATE_LEN>
    for ParallelHashXOFInternal<PARAMS>
{
    fn suspend(self) -> [u8; SUSPENDED_PARALLELHASHXOF_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(
        state: [u8; SUSPENDED_PARALLELHASHXOF_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
    }
}

impl<PARAMS: SHAKEParams> Hash for ParallelHashXOFInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.state.cshake.block_bitlen()
    }

    /// The nominal length, 32 or 64 bytes: twice the security strength, the length at which the
    /// output carries that strength in full. Bound by the [`Hash`] view and not by the XOF one.
    fn output_len(&self) -> usize {
        self.state.cshake.output_len()
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.state.do_update(data);
    }

    /// A final read at the nominal length, so `L` is bound: this is the fixed-length ParallelHash
    /// of Sec 6.3 at `n = ` [`Hash::output_len`], not a prefix of the ParallelHashXOF stream.
    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_squeezer().do_output_final(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len();
        // Per Hash::do_final_out, as for the fixed-length form: a short buffer truncates this
        // ParallelHash rather than computing the ParallelHash of a shorter length, because `n` is
        // what reaches right_encode, not the buffer's length.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.into_squeezer().do_final_out_with_length((n as u64) * 8, &mut output[..written])
    }

    /// # Errors
    /// Always [`HashError::InvalidLength`] for a non-zero `num_bits`; see
    /// [`ParallelHashInternal::do_final_partial_bits`].
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
                "ParallelHashXOF cannot take a partial final byte: the encodings must follow",
            ));
        }
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bits(PARAMS::SIZE as usize)
    }
}

impl<PARAMS: SHAKEParams> XOF for ParallelHashXOFInternal<PARAMS> {
    type Squeezer = CSHAKESqueezer<PARAMS>;

    // The block count of Sec 6.3.1 step 4 is bound here; the `right_encode` that follows it is
    // not, because whether it carries 0 or the length of a final read is
    // LengthBoundSqueezer's decision.
    fn into_squeezer(self) -> Self::Squeezer {
        CSHAKESqueezer::new(self.state.finish_blocks())
    }

    fn into_squeezer_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "ParallelHashXOF cannot take a partial final byte: the encodings must follow",
            ));
        }
        Ok(self.into_squeezer())
    }
}
