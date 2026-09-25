//! ParallelHash, the parallelisable hash of NIST SP 800-185 Sec 6.

use crate::SHAKEParams;
use crate::cshake::{CSHAKEInternal, absorb_left_encode_into};
use crate::length_bound_squeezer::LengthBoundSqueezer;
use crate::shake::SHAKEInternal;
use crate::xof_utils::right_encode;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, XOF, XOFSqueezer};

/// The function-name string every ParallelHash binds, per SP 800-185 Sec 6.3.
const PARALLELHASH_FUNCTION_NAME: &[u8] = b"ParallelHash";

/// The shared machinery of [`ParallelHashInternal`] and [`ParallelHashXOFInternal`]: the outer
/// cSHAKE, the block buffer, and the count of blocks hashed so far.
#[derive(Clone)]
struct ParallelState<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    block_size: usize,
    /// The partial block still being filled. Bounded by `block_size`, which the caller chooses at
    /// construction, so this cannot be a const-sized array.
    buffer: Vec<u8>,
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
        Self { cshake, block_size, buffer: Vec::new(), blocks: 0 }
    }

    /// Step 3 for one whole block: hash it and absorb the digest into the outer cSHAKE.
    ///
    /// The inner call is `cSHAKE(block, 2c, "", "")`, which by Sec 3.3 step 1 is plain SHAKE --
    /// so SHAKE is what is used here.
    fn absorb_block(&mut self, block: &[u8]) {
        let inner = SHAKEInternal::<PARAMS>::new().xof(block, Self::INNER_LEN);
        self.cshake.do_update(&inner);
        self.blocks += 1;
    }

    fn do_update(&mut self, mut data: &[u8]) {
        // Top up a partial block first, then take whole blocks straight from `data` so that a
        // caller feeding block-aligned input never copies.
        if !self.buffer.is_empty() {
            let need = self.block_size - self.buffer.len();
            let take = need.min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == self.block_size {
                let block = core::mem::take(&mut self.buffer);
                self.absorb_block(&block);
            }
        }
        while data.len() >= self.block_size {
            let (block, rest) = data.split_at(self.block_size);
            self.absorb_block(block);
            data = rest;
        }
        self.buffer.extend_from_slice(data);
    }

    /// Flushes the short final block and binds the block count: step 3, and the `right_encode(n)`
    /// half of step 4.
    ///
    /// The `right_encode(L)` that completes step 4 is left to the caller, because which `L` it
    /// carries is not settled here: the fixed-length function knows it up front ([`Self::finish`]),
    /// and the XOF leaves it to the first read ([`LengthBoundSqueezer`]).
    fn finish_blocks(mut self) -> CSHAKEInternal<PARAMS> {
        if !self.buffer.is_empty() {
            let block = core::mem::take(&mut self.buffer);
            self.absorb_block(&block);
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

/// Internal struct for ParallelHash. Use [`crate::PARALLELHASH128`] or [`crate::PARALLELHASH256`].
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
/// Unlike [`crate::TUPLEHASH128`], `do_update` here *is* ordinary byte-wise streaming: the block
/// boundaries come from `B`, not from how the caller chunks its calls.
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

/// Internal struct for ParallelHashXOF (Sec 6.3.1). Use [`crate::PARALLELHASHXOF128`] or
/// [`crate::PARALLELHASHXOF256`].
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
        self.into_squeezer().do_final(n)
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
    type Squeezer = LengthBoundSqueezer<PARAMS>;

    /// The block count of Sec 6.3.1 step 4 is bound here; the `right_encode` that follows it is
    /// not, because whether it carries 0 or the length of a final read is
    /// [`LengthBoundSqueezer`]'s decision.
    fn into_squeezer(self) -> Self::Squeezer {
        LengthBoundSqueezer::new(self.state.finish_blocks())
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
