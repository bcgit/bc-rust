//! The BLAKE3 tree hash (spec s. 2.1, 2.3-2.6) as an incremental hasher (spec s. 5.1).
//!
//! The structure -- `Output`, `ChunkState`, the CV stack, `parent_output` -- follows the reference
//! implementation that BLAKE3 spec s. 5.1 describes "as an aid to implementers", adapted to this
//! library's types: chaining values, buffered input and key words live in [`Secret`]s, and the
//! public types implement the `core` traits rather than the reference's `Hasher` API.

use crate::compress::{
    BLOCK_LEN, CHUNK_END, CHUNK_LEN, CHUNK_START, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL, IV,
    KEYED_HASH, PARENT, ROOT, compress, words_from_le_bytes,
};
use bouncycastle_core::direction::{Decrypting, Encrypting};
use bouncycastle_core::errors::{HashError, KeyMaterialError, MACError, SuspendableError};
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{
    Hash, HashOneShot, MACGenerator, MACVerifier, RNG, Suspendable, XOF, XOFSqueezer,
};
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_utils::{ct, min, secret::Secret};
use core::marker::PhantomData;

/// BLAKE3 spec s. 2.1: "The chaining value of the root node, encoded as 32 bytes in little-endian
/// order, is the default-length BLAKE3 hash of the input."
const OUT_LEN: usize = 32;

/// BLAKE3 spec s. 2.3: "The keyed_hash mode takes an input of any length together with a 256-bit
/// key."
const KEY_LEN: usize = 32;

/// BLAKE3 spec s. 5.4: "The maximum input size is 2^64 - 1 bytes, and the chunk size is 2^10
/// bytes, giving a maximum tree depth of 64 - 10 = 54. The CV stack thus requires 54 * 32 = 1728
/// bytes."
const MAX_DEPTH: usize = 54;

/// The first 8 words of a compression output: "The output of the compression function is most
/// often truncated to produce 256-bit chaining values" (s. 2.2).
#[inline]
fn first_8_words(words: &[u32; 16], cv: &mut [u32; 8]) {
    cv.copy_from_slice(&words[..8]);
}

/// Reads a little-endian u32 from exactly 4 bytes (serialized-state decoding).
#[inline]
fn u32_from_le(bytes: &[u8]) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(bytes);
    u32::from_le_bytes(b)
}

/// Reads a little-endian u64 from exactly 8 bytes (serialized-state decoding).
#[inline]
fn u64_from_le(bytes: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(bytes);
    u64::from_le_bytes(b)
}

/* ---------------------------------------------------------------------------------------------
 * Output: one compression held back until it is known whether it is the root (reference impl).
 * ------------------------------------------------------------------------------------------- */

/// The inputs of a single compression, captured "just prior to choosing between" producing an
/// 8-word chaining value and, with the ROOT flag, any number of output bytes (reference impl).
///
/// The incremental hasher cannot know whether a chunk or parent node is the root until the input
/// ends (s. 5.1.1, 5.1.2), so the last compression of each candidate is kept in this form.
#[derive(Clone)]
struct Output {
    /// h0 ... h7 for this compression.
    input_chaining_value: Secret<[u32; 8]>,
    /// m0 ... m15 for this compression.
    block_words: Secret<[u32; 16]>,
    /// t: the chunk index for a chunk's last block, 0 for a parent (s. 2.4, 2.5).
    counter: u64,
    /// b: the number of input bytes in the block.
    block_len: u32,
    /// d: every flag except ROOT, which is added only when the root is finalized.
    flags: u32,
}

impl Output {
    /// This node's chaining value, into `cv`: it is not the root, so ROOT is not set.
    fn chaining_value(&self, cv: &mut [u32; 8]) {
        let mut words = Secret::<[u32; 16]>::new();
        compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
            &mut words,
        );
        first_8_words(&words, cv);
    }

    /// One 64-byte block of root output, as 16 words into `out`.
    ///
    /// BLAKE3 spec s. 2.6: "This is done by repeating the root compression -- that is, the very
    /// last call to the compression function, which sets the ROOT flag -- with incrementing
    /// values of the counter t." and "the first root compression always uses the counter value
    /// t = 0 ... After the first root compression, as long as more output bytes are needed, t is
    /// incremented by 1, and the root compression is repeated on otherwise the same inputs."
    ///
    /// Mutants note: `self.flags` never contains ROOT (it is added only here), so `| ROOT` and
    /// `^ ROOT` are equivalent; a surviving `|`/`^` swap is an equivalent mutant.
    ///
    /// So `self.counter` is not used here: it is always 0 for a root (the root is either the only
    /// chunk, index 0, or a parent node, counter 0), and the output block counter replaces it.
    fn root_output_block(&self, output_block_counter: u64, out: &mut [u32; 16]) {
        compress(
            &self.input_chaining_value,
            &self.block_words,
            output_block_counter,
            self.block_len,
            self.flags | ROOT,
            out,
        )
    }
}

/// BLAKE3 spec s. 2.5: a parent node's single compression.
fn parent_output(
    left_child_cv: &[u32; 8],
    right_child_cv: &[u32; 8],
    key_words: &[u32; 8],
    flags: u32,
) -> Output {
    let mut input_chaining_value = Secret::<[u32; 8]>::new();
    // "The input chaining value h0 ... h7 is the key words k0 ... k7."
    input_chaining_value.copy_from_slice(key_words);

    let mut block_words = Secret::<[u32; 16]>::new();
    // "The message words m0 ... m7 are the chaining value of the left child, and the message
    // words m8 ... m15 are the chaining value of the right child."
    block_words[..8].copy_from_slice(left_child_cv);
    block_words[8..].copy_from_slice(right_child_cv);

    Output {
        input_chaining_value,
        block_words,
        // "The counter t for parent nodes is always 0."
        counter: 0,
        // "The number of bytes b for parent nodes is always 64."
        block_len: BLOCK_LEN as u32,
        // "Parent nodes set the PARENT flag." (ROOT is added by root_output_block if this
        // parent turns out to be the root.) `flags` carries the mode flag of s. 2.3.
        // Mutants note: `flags` is only ever a mode flag, never PARENT, so `|` and `^` are
        // equivalent here; a surviving swap is an equivalent mutant.
        flags: PARENT | flags,
    }
}

/* ---------------------------------------------------------------------------------------------
 * Chunk state (s. 2.4, 5.1.1)
 * ------------------------------------------------------------------------------------------- */

/// BLAKE3 spec s. 5.1.1: "The chunk state contains the 32-byte CV of the previous block and a
/// 64-byte input buffer for the next block, and typically also the compression function
/// parameters t and d."
#[derive(Clone)]
struct ChunkState {
    /// The CV of the previous block; the key words before the first block is compressed.
    chaining_value: Secret<[u32; 8]>,
    /// t: "the chunk index, i.e., 0 for all blocks in the first chunk, 1 for all blocks in the
    /// second chunk, and so on" (s. 2.4).
    chunk_counter: u64,
    /// The block not yet compressed. Only the first `block_len` bytes are meaningful.
    block: Secret<[u8; BLOCK_LEN]>,
    /// Number of meaningful bytes in `block`, 0..=64.
    block_len: u8,
    /// Number of blocks of this chunk already compressed, 0..=15 (the 16th block of a full chunk
    /// is never compressed early, see `update`).
    blocks_compressed: u8,
    /// The mode flag of s. 2.3 (0, KEYED_HASH or a DERIVE_KEY_* flag).
    flags: u32,
}

impl ChunkState {
    fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        let mut chaining_value = Secret::<[u32; 8]>::new();
        // s. 2.4: "The input chaining value h0 ... h7 for the first block of each chunk is
        // composed of the key words k0 ... k7."
        chaining_value.copy_from_slice(key_words);
        Self {
            chaining_value,
            chunk_counter,
            block: Secret::new(),
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    /// Number of input bytes absorbed into this chunk so far.
    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    /// s. 2.4: "The first block of each chunk sets the CHUNK_START flag".
    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 { CHUNK_START } else { 0 }
    }

    /// Absorbs `input`, which the caller guarantees fits in this chunk (`len() + input.len() <=
    /// CHUNK_LEN`).
    ///
    /// s. 5.1.1: "Input bytes from the caller are copied into the buffer until it is full. Then the
    /// buffer is compressed together with the previous CV, using the truncated compression
    /// function. The output CV overwrites the previous CV, and the buffer is cleared. ... the
    /// chunk state waits to compress the next block until both the buffer is full and the caller
    /// has supplied more input."
    fn update(&mut self, mut input: &[u8]) {
        let mut block_words = Secret::<[u32; 16]>::new();
        let mut words = Secret::<[u32; 16]>::new();
        while !input.is_empty() {
            // The buffer is full and more input is here, so this block is not the chunk's last:
            // no CHUNK_END, no ROOT.
            if self.block_len as usize == BLOCK_LEN {
                // s. 2.4: "Each block is parsed in little-endian order into message words m0 ...
                // m15 and compressed."
                words_from_le_bytes(&*self.block, &mut block_words);
                compress(
                    &self.chaining_value,
                    &block_words,
                    // s. 2.4: "The counter t for each block is the chunk index"
                    self.chunk_counter,
                    // s. 2.4: "The block length b is the number of input bytes in each block,
                    // i.e., 64 for all blocks except the last block of the last chunk"
                    BLOCK_LEN as u32,
                    // Mutants note: the mode flag and CHUNK_START are distinct bits, so `|` and
                    // `^` are equivalent here; a surviving swap is an equivalent mutant.
                    self.flags | self.start_flag(),
                    &mut words,
                );
                // s. 2.4: "The input chaining value for subsequent blocks in each chunk is the
                // output of the truncated compression function for the previous block."
                first_8_words(&words, &mut self.chaining_value);
                self.blocks_compressed += 1;
                // "the buffer is cleared": only the length is reset. The stale bytes are never
                // read, because `output` zero-pads everything past `block_len` itself.
                self.block_len = 0;
            }

            // Copy input bytes into the block buffer.
            let block_len = self.block_len as usize;
            let take = *min(&(BLOCK_LEN - block_len), &input.len());
            self.block[block_len..block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    /// The chunk's last compression, held back as an [`Output`].
    fn output(&self) -> Output {
        // s. 2.4: "The last block of the last chunk may be shorter, but not empty, unless the
        // entire input is empty. If necessary, the last block is padded with zeros to be 64
        // bytes."
        let block_len = self.block_len as usize;
        let mut padded = Secret::<[u8; BLOCK_LEN]>::new();
        padded[..block_len].copy_from_slice(&self.block[..block_len]);
        let mut block_words = Secret::<[u32; 16]>::new();
        words_from_le_bytes(&*padded, &mut block_words);

        let mut input_chaining_value = Secret::<[u32; 8]>::new();
        input_chaining_value.copy_from_slice(&*self.chaining_value);

        Output {
            input_chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            // s. 2.4: "the last block of each chunk sets the CHUNK_END flag. If a chunk contains
            // only one block, that block sets both CHUNK_START and CHUNK_END." ROOT is added by
            // root_output_block if this chunk turns out to be the root.
            // Mutants note: the mode flag, CHUNK_START and CHUNK_END are distinct bits, so `|` and
            // `^` are equivalent here; surviving swaps are equivalent mutants.
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

/* ---------------------------------------------------------------------------------------------
 * The incremental hasher: chunk state + CV stack (s. 5.1)
 * ------------------------------------------------------------------------------------------- */

/// Length of the chunk-state-and-CV-stack part of a serialized state; see
/// [`Blake3Core::write_state`].
const CORE_STATE_LEN: usize = 32 + 8 + BLOCK_LEN + 1 + 1 + 1 + MAX_DEPTH * 32;

/// BLAKE3 spec s. 5.1: "An incremental implementation of BLAKE3 has two major components: the
/// state of the current chunk and a stack of subtree chaining values (the "CV stack")."
///
/// Shared by all three modes, which differ only in `key_words` and `flags` (s. 2.3). `K` holds the
/// key words: owned by the unkeyed and derive_key hashers, borrowed from the key object by a
/// keyed_hash worker.
#[derive(Clone)]
struct Blake3Core<K: KeyWords = Secret<[u32; 8]>> {
    chunk_state: ChunkState,
    /// k0 ... k7 (s. 2.3).
    key_words: K,
    /// "Space for 54 subtree chaining values: 2^54 * CHUNK_LEN = 2^64" (reference impl).
    cv_stack: Secret<[[u32; 8]; MAX_DEPTH]>,
    cv_stack_len: u8,
    /// The mode flag of s. 2.3, set "for every compression".
    flags: u32,
}

/// Where a [`Blake3Core`] reads its key words from.
trait KeyWords {
    fn words(&self) -> &[u32; 8];
}

impl KeyWords for Secret<[u32; 8]> {
    fn words(&self) -> &[u32; 8] {
        self
    }
}

impl KeyWords for &Secret<[u32; 8]> {
    fn words(&self) -> &[u32; 8] {
        self
    }
}

impl Blake3Core {
    /// A core that owns a copy of `key_words`.
    fn new(key_words: &[u32; 8], flags: u32) -> Self {
        let mut kw = Secret::<[u32; 8]>::new();
        kw.copy_from_slice(key_words);
        Self::with_key_words(kw, flags)
    }

    /// The inverse of [`Blake3Core::write_state`], given the key words and mode flag.
    ///
    /// Rejects with [`SuspendableError::InvalidData`] any state the hasher could not have reached,
    /// where resuming it would index out of bounds or underflow the stack:
    /// * `block_len > 64`: the buffer is one block;
    /// * `blocks_compressed > 15`: a chunk is at most 16 blocks and its last block is never
    ///   compressed before the chunk is finalized (s. 5.1.1);
    /// * `cv_stack_len > 54`: s. 5.4's maximum tree depth;
    /// * `chunk_counter >= 2^54`: s. 2.1 caps the input below 2^64 bytes, i.e. 2^54 chunks. Without
    ///   this, a counter with 54 one-bits whose next chunk adds a 55th would overflow the stack;
    /// * `cv_stack_len != chunk_counter.count_ones()`: s. 5.1.2, "The entries in the CV stack
    ///   behave like the 1-bits in the binary representation of the total number of chunks so
    ///   far". This is what guarantees `add_chunk_chaining_value` never pops an empty stack;
    /// * `blocks_compressed > 0 && block_len == 0`: s. 5.1.1, a block is compressed only once "the
    ///   caller has supplied more input", so a compression is always followed by at least one
    ///   buffered byte. (Resuming such a state would finish the chunk on an empty block without
    ///   CHUNK_START, which no input produces.)
    /// * `chunk_counter > 0` with an empty chunk: s. 5.1.1, "chunk CVs are added only after the
    ///   caller supplies at least 1 byte for the following chunk", so a chunk after the first is
    ///   never empty. (Resuming it would merge an empty chunk into the tree.)
    ///
    /// While `blocks_compressed == 0` the chunk chaining value is taken from `key_words`
    /// unconditionally; the serialized bytes for it are never read.
    fn read_state(
        input: &[u8],
        key_words: &[u32; 8],
        flags: u32,
    ) -> Result<Self, SuspendableError> {
        debug_assert_eq!(input.len(), CORE_STATE_LEN);
        let chunk_counter = u64_from_le(&input[32..40]);
        let block_len = input[104];
        let blocks_compressed = input[105];
        let cv_stack_len = input[106];

        if block_len as usize > BLOCK_LEN
            || blocks_compressed > 15
            || cv_stack_len as usize > MAX_DEPTH
            || chunk_counter >= (1u64 << MAX_DEPTH)
            || chunk_counter.count_ones() != cv_stack_len as u32
            || (blocks_compressed > 0 && block_len == 0)
            || (chunk_counter > 0 && blocks_compressed == 0 && block_len == 0)
        {
            return Err(SuspendableError::InvalidData);
        }

        let mut core = Self::new(key_words, flags);
        let cs = &mut core.chunk_state;
        if blocks_compressed != 0 {
            words_from_le_bytes(&input[0..32], &mut cs.chaining_value);
        }
        // else: ChunkState::new already set the chaining value to the key words.
        cs.chunk_counter = chunk_counter;
        cs.block[..block_len as usize].copy_from_slice(&input[40..40 + block_len as usize]);
        cs.block_len = block_len;
        cs.blocks_compressed = blocks_compressed;

        for j in 0..cv_stack_len as usize {
            words_from_le_bytes(&input[107 + j * 32..107 + j * 32 + 32], &mut core.cv_stack[j]);
        }
        core.cv_stack_len = cv_stack_len;
        Ok(core)
    }
}

impl<K: KeyWords> Blake3Core<K> {
    fn with_key_words(key_words: K, flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words.words(), 0, flags),
            key_words,
            cv_stack: Secret::new(),
            cv_stack_len: 0,
            flags,
        }
    }

    fn push_stack(&mut self, cv: &[u32; 8]) {
        // The stack cannot overflow for any input BLAKE3 accepts: s. 2.1 caps the input at
        // ell < 2^64 bytes, i.e. fewer than 2^54 chunks, and s. 5.4 derives the depth bound of 54
        // from exactly that. Reaching this would need 2^64 bytes of input, so a debug assertion
        // is enough; in release the index below would panic rather than corrupt memory.
        debug_assert!((self.cv_stack_len as usize) < MAX_DEPTH, "BLAKE3 input exceeds 2^64 bytes");
        self.cv_stack[self.cv_stack_len as usize] = *cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self, cv: &mut [u32; 8]) {
        self.cv_stack_len -= 1;
        *cv = self.cv_stack[self.cv_stack_len as usize];
    }

    /// BLAKE3 spec s. 5.1.2, Listing 1: "For each trailing 0-bit in the new total number of chunks,
    /// pop a CV off the stack, and merge it with the new CV we were about to add. Finally, push the
    /// fully merged result onto the stack."
    fn add_chunk_chaining_value(&mut self, new_cv: &mut [u32; 8], mut total_chunks: u64) {
        // "The entries in the CV stack behave like the 1-bits in the binary representation of the
        // total number of chunks so far." Each trailing 0-bit of the new total is a completed
        // subtree whose left child is on top of the stack and whose right child is `new_cv`.
        let mut left_child_cv = Secret::<[u32; 8]>::new();
        while total_chunks & 1 == 0 {
            self.pop_stack(&mut left_child_cv);
            parent_output(&left_child_cv, new_cv, self.key_words.words(), self.flags)
                .chaining_value(new_cv);
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    fn update(&mut self, mut input: &[u8]) {
        let mut chunk_cv = Secret::<[u32; 8]>::new();
        while !input.is_empty() {
            // s. 5.1.1: "chunk CVs are added only after the caller supplies at least 1 byte for the
            // following chunk" -- so a full chunk is finalized here, where more input is known to
            // follow, and it is therefore not the root (s. 5.1.2: "we know that none of these
            // chunks or parent nodes is the root of the tree").
            if self.chunk_state.len() == CHUNK_LEN {
                self.chunk_state.output().chaining_value(&mut chunk_cv);
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(&mut chunk_cv, total_chunks);
                self.chunk_state =
                    ChunkState::new(self.key_words.words(), total_chunks, self.flags);
            }

            // Absorb as much as fits in the current chunk.
            let take = *min(&(CHUNK_LEN - self.chunk_state.len()), &input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// The root node's held-back compression.
    ///
    /// BLAKE3 spec s. 5.1.2: "Once we reach the end of the input, we can use a simpler algorithm
    /// to compute the root hash. Finalize the CV of the current chunk, which may be incomplete or
    /// empty. Then, merge that CV with every CV currently in the stack, regardless of the number
    /// of chunks so far. Set the ROOT flag for the last parent node to be merged. Or if there are
    /// no CVs in the stack, and thus no parents to merge, set the ROOT flag for chunk
    /// finalization instead." (ROOT itself is applied by [`Output::root_output_block`].)
    fn root_output(&self) -> Output {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len as usize;
        let mut cv = Secret::<[u32; 8]>::new();
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output.chaining_value(&mut cv);
            output = parent_output(
                &self.cv_stack[parent_nodes_remaining],
                &cv,
                self.key_words.words(),
                self.flags,
            );
        }
        output
    }

    /// Serializes the chunk state and CV stack (not `key_words` or `flags`, which each public type
    /// handles itself) into `CORE_STATE_LEN` bytes. All integers little-endian.
    ///
    /// ```text
    ///   [0    .. 32)    chunk chaining_value  [u32; 8], all zero when blocks_compressed == 0
    ///   [32   .. 40)    chunk_counter         u64
    ///   [40   .. 104)   block                 [u8; 64], zero past block_len
    ///   [104  .. 105)   block_len             u8 (0..=64)
    ///   [105  .. 106)   blocks_compressed     u8 (0..=15)
    ///   [106  .. 107)   cv_stack_len          u8 (0..=54, == chunk_counter.count_ones())
    ///   [107  .. 1835)  cv_stack              54 x [u32; 8], zero past cv_stack_len
    /// ```
    ///
    /// The chunk chaining value is omitted while no block of the chunk has been compressed,
    /// because it then *is* the key words (s. 2.4: "The input chaining value h0 ... h7 for the
    /// first block of each chunk is composed of the key words k0 ... k7"), and in keyed_hash mode
    /// those are the key. `read_state` restores it from the key words. Stale bytes past
    /// `block_len` and stale CVs past `cv_stack_len` are not written either.
    fn write_state(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), CORE_STATE_LEN);
        let cs = &self.chunk_state;
        if cs.blocks_compressed != 0 {
            for (i, word) in cs.chaining_value.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        out[32..40].copy_from_slice(&cs.chunk_counter.to_le_bytes());
        let block_len = cs.block_len as usize;
        out[40..40 + block_len].copy_from_slice(&cs.block[..block_len]);
        out[104] = cs.block_len;
        out[105] = cs.blocks_compressed;
        out[106] = self.cv_stack_len;
        for (j, cv) in self.cv_stack[..self.cv_stack_len as usize].iter().enumerate() {
            for (i, word) in cv.iter().enumerate() {
                let at = 107 + j * 32 + i * 4;
                out[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
    }
}

/* ---------------------------------------------------------------------------------------------
 * Partial-bit policy
 * ------------------------------------------------------------------------------------------- */

/// BLAKE3 is byte-oriented: s. 2.1 "BLAKE3 supports input of any byte length 0 <= ell < 2^64", and
/// the block length parameter b of s. 2.2 counts bytes. There is no defined encoding of a partial
/// final byte, so the partial-bit entry points accept only `num_bits == 0`.
///
/// This is the convention of this library's other byte-oriented XOFs, Ascon-XOF128/CXOF128:
/// `InvalidLength` for `num_bits > 7` (the trait's rule), `InvalidInput` for `1..=7`, and 0 is the
/// whole-byte call. KMACXOF differs: it returns `InvalidLength` for every non-zero `num_bits`.
fn check_partial_bits(num_bits: usize) -> Result<(), HashError> {
    if num_bits > 7 {
        return Err(HashError::InvalidLength("num_bits must be in the range [0,7]"));
    }
    if num_bits != 0 {
        return Err(HashError::InvalidInput(
            "BLAKE3 is byte-oriented: a partial final byte (num_bits in 1..=7) cannot be hashed",
        ));
    }
    Ok(())
}

/* ---------------------------------------------------------------------------------------------
 * BLAKE3: hash mode
 * ------------------------------------------------------------------------------------------- */

/// BLAKE3 in its `hash` mode (spec s. 2.3: "k0 ... k7 are the constants IV0 ... IV7, and no
/// additional flags are set"), usable as a [`Hash`] and as a [`XOF`].
///
/// As a [`Hash`] it produces the default 32-byte output; as a [`XOF`] any length, and "Shorter
/// outputs are prefixes of longer ones" (s. 2.6). For the keyed mode see [`BLAKE3KeyedHash`]; for
/// key derivation, [`BLAKE3DeriveKey`].
///
/// See the [crate-level documentation](crate) for usage.
#[derive(Clone)]
pub struct BLAKE3 {
    core: Blake3Core,
}

impl BLAKE3 {
    /// A new BLAKE3 in `hash` mode, ready for use.
    pub fn new() -> Self {
        // s. 2.3: "In the hash mode, k0 ... k7 are the constants IV0 ... IV7, and no additional
        // flags are set."
        Self { core: Blake3Core::new(&IV, 0) }
    }

    /// The engine in `derive_key` mode, for [`BLAKE3DeriveKey`] only: a `BLAKE3` value is
    /// [`Suspendable`], and a derive_key state would hold the key material.
    fn derive_key_mode(context: &[u8]) -> Self {
        // s. 2.3: "First the context string is hashed, with k0 ... k7 set to the constants
        // IV0 ... IV7, and the DERIVE_KEY_CONTEXT flag set for every compression."
        let mut context_hasher = Blake3Core::new(&IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context);

        // "Then the key material is hashed, with k0 ... k7 set to the first 8 output words of the
        // first stage, and the DERIVE_KEY_MATERIAL flag set for every compression." The first
        // 8 output words are the first 8 words of root output block 0 (s. 2.6).
        let mut first_stage_output = Secret::<[u32; 16]>::new();
        context_hasher.root_output().root_output_block(0, &mut first_stage_output);
        let mut context_key = Secret::<[u32; 8]>::new();
        first_8_words(&first_stage_output, &mut context_key);
        Self { core: Blake3Core::new(&context_key, DERIVE_KEY_MATERIAL) }
    }
}

impl Default for BLAKE3 {
    fn default() -> Self {
        Self::new()
    }
}

impl HashOneShot for BLAKE3 {}

impl Hash for BLAKE3 {
    /// BLAKE3 spec s. 2.2: the message block is 512 bits.
    fn block_bitlen(&self) -> usize {
        BLOCK_LEN * 8
    }

    /// The default output length, 32 bytes (s. 2.1). This is nominal: BLAKE3 does not bind the
    /// output length into the computation (s. 2.6), so use the [`XOF`] methods for other lengths.
    fn output_len(&self) -> usize {
        OUT_LEN
    }

    fn do_update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    fn do_final(self) -> Vec<u8> {
        let mut output = vec![0u8; OUT_LEN];
        self.do_final_out(&mut output);
        output
    }

    /// Writes `min(output.len(), 32)` bytes of the default-length hash and zeroizes the rest of
    /// `output`. To fill a longer buffer with extended output, use [`XOF::xof_out`] or
    /// [`XOFSqueezer::do_output_out`].
    fn do_final_out(self, output: &mut [u8]) -> usize {
        output.fill(0);
        let n = *min(&output.len(), &OUT_LEN);
        self.into_squeezer().do_output_out(&mut output[..n])
    }

    /// Only `num_bits == 0` is accepted (BLAKE3 is byte-oriented; s. 2.1): it is identical to
    /// [`Hash::do_final`] and `partial_byte` is ignored. `num_bits` in `1..=7` returns
    /// [`HashError::InvalidInput`], and larger values [`HashError::InvalidLength`].
    fn do_final_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        check_partial_bits(num_bits)?;
        Ok(self.do_final())
    }

    /// As [`Hash::do_final_partial_bits`]; `output` is zeroized first, so a rejected call leaves
    /// it all zeros.
    fn do_final_partial_bits_out(
        self,
        _partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        output.fill(0);
        check_partial_bits(num_bits)?;
        Ok(self.do_final_out(output))
    }
}

/// The absorb-then-squeeze rule is a compile error:
///
/// ```compile_fail
/// use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
/// use bouncycastle_blake3::BLAKE3;
///
/// let mut blake3 = BLAKE3::new();
/// blake3.do_update(b"abc");
/// let mut out = blake3.into_squeezer();
/// let _ = out.do_output(32);
/// blake3.do_update(b"more"); // `blake3` was moved by into_squeezer()
/// ```
impl XOF for BLAKE3 {
    type Squeezer = BLAKE3Squeezer;

    fn into_squeezer(self) -> Self::Squeezer {
        BLAKE3Squeezer::new(self.core.root_output())
    }

    /// Only `num_bits == 0` is accepted; see [`Hash::do_final_partial_bits`] on [`BLAKE3`].
    fn into_squeezer_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        check_partial_bits(num_bits)?;
        Ok(self.into_squeezer())
    }
}

/// Length in bytes of the serialized state of [`BLAKE3`].
// Layout (after the 3-byte library version header; all integers little-endian):
//   [0  .. 4)     flags       u32: always 0 (hash mode)
//   [4  .. 36)    key_words   [u32; 8]: always IV0 ... IV7
//   [36 .. 1871)  the chunk state and CV stack:
//     [36   .. 68)    chunk chaining_value  [u32; 8], all zero when blocks_compressed == 0
//     [68   .. 76)    chunk_counter         u64 (< 2^54)
//     [76   .. 140)   block                 [u8; 64], zero past block_len
//     [140  .. 141)   block_len             u8 (0..=64)
//     [141  .. 142)   blocks_compressed     u8 (0..=15)
//     [142  .. 143)   cv_stack_len          u8 (0..=54, == chunk_counter.count_ones())
//     [143  .. 1871)  cv_stack              54 x [u32; 8], zero past cv_stack_len
pub const SUSPENDED_BLAKE3_STATE_LEN: usize = 3 + 4 + 32 + CORE_STATE_LEN;

impl Suspendable<SUSPENDED_BLAKE3_STATE_LEN> for BLAKE3 {
    fn suspend(self) -> [u8; SUSPENDED_BLAKE3_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_BLAKE3_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_BLAKE3_STATE_LEN - 3 bytes.
        let out: &mut [u8; SUSPENDED_BLAKE3_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0..4].copy_from_slice(&self.core.flags.to_le_bytes());
        for (i, word) in self.core.key_words.iter().enumerate() {
            out[4 + i * 4..4 + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        self.core.write_state(&mut out[36..]);

        out_to_return
    }

    /// Rejects with [`SuspendableError::InvalidData`] a state no [`BLAKE3`] hasher reaches, which
    /// includes any state of a keyed_hash or derive_key computation.
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_BLAKE3_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_BLAKE3_STATE_LEN - 3
        // bytes.
        let input: &[u8; SUSPENDED_BLAKE3_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        let flags = u32_from_le(&input[0..4]);
        // s. 2.3: hash mode has "no additional flags" and k = IV. A keyed_hash or derive_key
        // state is never in this format (those modes are BLAKE3KeyedHash and BLAKE3DeriveKey).
        let mut iv_bytes = [0u8; 32];
        for (bytes, word) in iv_bytes.as_chunks_mut::<4>().0.iter_mut().zip(IV.iter()) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        if flags != 0 || !ct::ct_eq_bytes(&input[4..36], &iv_bytes) {
            return Err(SuspendableError::InvalidData);
        }

        let core = Blake3Core::read_state(&input[36..], &IV, 0)?;
        Ok(Self { core })
    }
}

/* ---------------------------------------------------------------------------------------------
 * The output phase
 * ------------------------------------------------------------------------------------------- */

/// The squeezing half of [`BLAKE3`]: what [`XOF::into_squeezer`] hands back.
///
/// It holds the root node's compression inputs and produces "outputs of any byte length
/// 0 <= ell < 2^64 ... by repeating the root compression ... with incrementing values of the
/// counter t" (s. 2.6). Successive reads continue one stream.
#[derive(Clone)]
pub struct BLAKE3Squeezer {
    /// The root compression (without ROOT, which `root_output_block` adds).
    root: Output,
    /// t for the next root compression.
    output_block_counter: u64,
    /// The current 64-byte output block. Derive_key output is a key, hence the `Secret`.
    buf: Secret<[u8; BLOCK_LEN]>,
    /// Bytes of `buf` already handed out, 0..=64; 64 means a new block is needed.
    buf_pos: u8,
}

impl BLAKE3Squeezer {
    fn new(root: Output) -> Self {
        Self { root, output_block_counter: 0, buf: Secret::new(), buf_pos: BLOCK_LEN as u8 }
    }
}

impl XOFSqueezer for BLAKE3Squeezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        // Zeroized first per the house rule, although every byte is then overwritten.
        output.fill(0);
        let mut written = 0;
        let mut words = Secret::<[u32; 16]>::new();
        while written < output.len() {
            if self.buf_pos as usize == BLOCK_LEN {
                // s. 2.6: "When building the output, BLAKE3 uses the full output of the
                // compression function (cf. s. 2.2). Each 16-word output is encoded as 64 bytes in
                // little-endian order."
                self.root.root_output_block(self.output_block_counter, &mut words);
                for (i, word) in words.iter().enumerate() {
                    self.buf[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                // "as long as more output bytes are needed, t is incremented by 1". This cannot
                // overflow: the counter starts at most at MAX_OUTPUT_BLOCKS (from_suspended
                // enforces it), and 2^64 - 2^58 further blocks would be far past ell < 2^64.
                self.output_block_counter += 1;
                self.buf_pos = 0;
            }
            // "If the target output length is not a multiple of 64, the final compression output
            // is truncated" -- the rest of the block stays buffered for the next read.
            let pos = self.buf_pos as usize;
            let take = *min(&(BLOCK_LEN - pos), &(output.len() - written));
            output[written..written + take].copy_from_slice(&self.buf[pos..pos + take]);
            self.buf_pos += take as u8;
            written += take;
        }
        written
    }
}

/// Length in bytes of the serialized state of [`BLAKE3Squeezer`].
// Layout (after the 3-byte library version header; all integers little-endian):
//   [0   .. 32)   root input_chaining_value  [u32; 8]
//   [32  .. 96)   root block_words           [u32; 16]
//   [96  .. 100)  root block_len             u32
//   [100 .. 104)  root flags                 u32 (without ROOT; never KEYED_HASH)
//   [104 .. 112)  output_block_counter       u64
//   [112 .. 113)  buffer position            u8 (0..=64)
// The root's own counter is not stored: s. 2.6, "the first root compression always uses the
// counter value t = 0", and the output block counter takes its place. The stream position is
// `64 * (output_block_counter - 1) + buffer position` once a block has been produced. The
// output buffer is not stored either: it is root output block `output_block_counter - 1`, and
// resuming recomputes it.
pub const SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN: usize = 3 + 113;

/// The most output blocks a squeezer can have produced: s. 2.6 bounds the output at
/// "0 <= ell < 2^64" bytes, which is 2^58 blocks of 64 bytes.
const MAX_OUTPUT_BLOCKS: u64 = 1 << 58;

/// A long output stream can be paused and resumed. Only the squeezer of [`BLAKE3`] implements
/// this; the keyed squeezer does not, see [`BLAKE3KeyedSqueezer`].
impl Suspendable<SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN> for BLAKE3Squeezer {
    fn suspend(self) -> [u8; SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly 113 bytes.
        let out: &mut [u8; 113] = add_lib_ver(&mut out_to_return).try_into().unwrap();

        for (i, word) in self.root.input_chaining_value.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        for (i, word) in self.root.block_words.iter().enumerate() {
            out[32 + i * 4..32 + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[96..100].copy_from_slice(&self.root.block_len.to_le_bytes());
        out[100..104].copy_from_slice(&self.root.flags.to_le_bytes());
        out[104..112].copy_from_slice(&self.output_block_counter.to_le_bytes());
        out[112] = self.buf_pos;

        out_to_return
    }

    /// Rejects with [`SuspendableError::InvalidData`] a state no [`BLAKE3Squeezer`] reaches, which
    /// includes any state of a keyed_hash or derive_key stream and a counter a resumed stream
    /// could wrap. The checks are listed in the body.
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly 113 bytes.
        let input: &[u8; 113] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        let buf_pos = input[112];
        let flags = u32_from_le(&input[100..104]);
        // Mutants note: the three node-type flags are distinct bits, so `|` and `^` build the same
        // mask; surviving swaps here are equivalent mutants.
        let mode_flags = flags & !(CHUNK_START | CHUNK_END | PARENT);
        let block_len = u32_from_le(&input[96..100]);
        let output_block_counter = u64_from_le(&input[104..112]);
        // A root is a parent node (s. 2.5: PARENT, b = 64) or the only chunk's last block (s. 2.4:
        // CHUNK_END, with CHUNK_START if it is also the first).
        let parent_root = flags == PARENT && block_len as usize == BLOCK_LEN;
        let chunk_root = flags & CHUNK_END != 0 && flags & PARENT == 0;
        if buf_pos as usize > BLOCK_LEN
            || mode_flags != 0
            || !(parent_root || chunk_root)
            || block_len as usize > BLOCK_LEN
            || (output_block_counter == 0 && (buf_pos as usize) < BLOCK_LEN)
            || output_block_counter > MAX_OUTPUT_BLOCKS
        {
            return Err(SuspendableError::InvalidData);
        }

        let mut input_chaining_value = Secret::<[u32; 8]>::new();
        words_from_le_bytes(&input[0..32], &mut input_chaining_value);
        let mut block_words = Secret::<[u32; 16]>::new();
        words_from_le_bytes(&input[32..96], &mut block_words);
        let root = Output { input_chaining_value, block_words, counter: 0, block_len, flags };
        let mut buf = Secret::<[u8; BLOCK_LEN]>::new();
        // Mutants note: `<` -> `<=` survives. At position 64 the buffer is never read, so it only
        // adds a compression; for a fresh squeezer (counter 0) it would also underflow the
        // subtraction below, which panics only where overflow checks are on, and the mutants
        // profile has them off.
        if (buf_pos as usize) < BLOCK_LEN {
            // The rest of block output_block_counter - 1 is still to be read (counter >= 1 here,
            // checked above), so compute it again rather than trust a stored copy.
            let mut words = Secret::<[u32; 16]>::new();
            root.root_output_block(output_block_counter - 1, &mut words);
            for (i, word) in words.iter().enumerate() {
                buf[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }

        Ok(Self { root, output_block_counter, buf, buf_pos })
    }
}

/* ---------------------------------------------------------------------------------------------
 * BLAKE3DeriveKey: derive_key mode
 * ------------------------------------------------------------------------------------------- */

/// BLAKE3 in its `derive_key` mode (spec s. 2.3), usable as a [`Hash`] and as a [`XOF`]: the
/// context string is hashed into a context key, the key material is then fed through
/// [`Hash::do_update`], and the output is the derived key.
///
/// The context string "should be hardcoded, globally unique, and application-specific" and "should
/// not contain variable data, like salts, IDs, or the current time" (s. 6.2).
///
/// It deliberately does **not** implement [`Suspendable`]: its state would contain the key
/// material, while [`Suspendable`] forbids a serialized private key. Its squeezer, [`BLAKE3DeriveKeySqueezer`], is not suspendable either.
///
/// ```compile_fail
/// use bouncycastle_blake3::BLAKE3DeriveKey;
/// use bouncycastle_core::traits::{Hash, Suspendable};
///
/// let mut kdf = BLAKE3DeriveKey::new(b"example.com 2019-12-25 16:18:03 session tokens v1");
/// kdf.do_update(&[0x0bu8; 32]);
/// let _ = kdf.suspend(); // not Suspendable
/// ```
#[derive(Clone)]
pub struct BLAKE3DeriveKey(BLAKE3);

impl BLAKE3DeriveKey {
    /// A new `derive_key` instance for the given context string.
    pub fn new(context: &[u8]) -> Self {
        Self(BLAKE3::derive_key_mode(context))
    }

    /// One-shot: the 32-byte derived key for the key material `data`. [`HashOneShot`] is for
    /// hashes that take no parameters; this one takes its context string at construction.
    pub fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    /// As [`Self::hash`], into `output`, which is zeroized first; returns the bytes written.
    pub fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }
}

impl Hash for BLAKE3DeriveKey {
    fn block_bitlen(&self) -> usize {
        self.0.block_bitlen()
    }

    /// The default output length, 32 bytes; use the [`XOF`] methods for other lengths.
    fn output_len(&self) -> usize {
        self.0.output_len()
    }

    fn do_update(&mut self, data: &[u8]) {
        self.0.do_update(data)
    }

    fn do_final(self) -> Vec<u8> {
        self.0.do_final()
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        self.0.do_final_out(output)
    }

    /// As on [`BLAKE3`]: only `num_bits == 0` is accepted.
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        self.0.do_final_partial_bits(partial_byte, num_bits)
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        self.0.do_final_partial_bits_out(partial_byte, num_bits, output)
    }
}

impl XOF for BLAKE3DeriveKey {
    type Squeezer = BLAKE3DeriveKeySqueezer;

    fn into_squeezer(self) -> Self::Squeezer {
        BLAKE3DeriveKeySqueezer(self.0.into_squeezer())
    }

    fn into_squeezer_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        Ok(BLAKE3DeriveKeySqueezer(self.0.into_squeezer_partial_bits(partial_byte, num_bits)?))
    }
}

/// The squeezing half of [`BLAKE3DeriveKey`]. Like [`BLAKE3KeyedSqueezer`] it is deliberately not
/// [`Suspendable`]: its state would contain the key material.
#[derive(Clone)]
pub struct BLAKE3DeriveKeySqueezer(BLAKE3Squeezer);

impl XOFSqueezer for BLAKE3DeriveKeySqueezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        self.0.do_output(num_bytes)
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.0.do_output_out(output)
    }
}

/* ---------------------------------------------------------------------------------------------
 * BLAKE3KeyedHash: keyed_hash mode
 * ------------------------------------------------------------------------------------------- */

/// A BLAKE3 `keyed_hash` key (spec s. 2.3): the key words k0 ... k7, "parsed in little-endian
/// order from the 256-bit key given by the caller".
///
/// Construction is [`FromAnyKeyMaterial`]: the material must be exactly 32 bytes, tagged
/// [`KeyType::MACKey`] (or [`KeyType::Zeroized`]). An empty key is refused like any other length;
/// unkeyed BLAKE3 is [`BLAKE3`]. The workers come from [`MacGenerationKey`] and
/// [`MacVerificationKey`], each borrowing the key.
#[derive(Clone)]
pub struct BLAKE3KeyedHashKey {
    key_words: Secret<[u32; 8]>,
}

impl BLAKE3KeyedHashKey {
    fn from_key_material_checked(
        key: &dyn KeyMaterialTrait,
        allow_weak_key: bool,
    ) -> Result<Self, MACError> {
        // Same stance as HMAC and KMAC: an all-zero key is `Zeroized` rather than `MACKey`, and is
        // let through so callers are not forced to re-tag it.
        if !(key.key_type() == KeyType::MACKey || key.key_type() == KeyType::Zeroized) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }
        // Strength before length, so that an under-strength key is reported as such whatever its
        // length (the shared key-construction suite relies on this).
        if !allow_weak_key && key.security_strength() < SecurityStrength::_128bit {
            return Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(
                "BLAKE3KeyedHashKey: the key's security strength is below 128 bits",
            )));
        }
        // s. 2.3: "a 256-bit key". BLAKE3 defines no way to use a key of any other length.
        if key.key_len() != KEY_LEN {
            return Err(MACError::InvalidLength("BLAKE3 keyed_hash requires a 32-byte key"));
        }
        let mut key_words = Secret::<[u32; 8]>::new();
        words_from_le_bytes(key.ref_to_bytes(), &mut key_words);
        Ok(Self { key_words })
    }
}

impl FromAnyKeyMaterial for BLAKE3KeyedHashKey {
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the material is not tagged [`KeyType::MACKey`] or
    /// [`KeyType::Zeroized`], or is tagged below 128-bit security; [`MACError::InvalidLength`] if
    /// it is not exactly 32 bytes.
    fn from_key_material(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::from_key_material_checked(key, false)
    }

    /// As [`from_key_material`](Self::from_key_material) without the strength check.
    fn from_key_material_allow_weak(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::from_key_material_checked(key, true)
    }

    /// Draws a 32-byte key from `rng`, tagged [`KeyType::MACKey`] at the RNG's strength.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the RNG fails, or with
    /// [`KeyMaterialError::SecurityStrength`] if its strength is below 128 bits.
    fn generate(rng: &mut dyn RNG) -> Result<Self, MACError> {
        // s. 2.3's 256-bit key, at the RNG's strength capped by the length.
        let key = KeyMaterial256::from_rng_as_type(rng, KEY_LEN, KeyType::MACKey)?;
        Self::from_key_material(&key)
    }
}

impl BLAKE3KeyedHashKey {
    fn worker<Dir>(&self) -> BLAKE3KeyedHash<'_, Dir> {
        // s. 2.3: "In the keyed_hash mode, k0 ... k7 are parsed ... from the 256-bit key ..., and
        // the KEYED_HASH flag is set for every compression." The worker reads them from the key.
        BLAKE3KeyedHash {
            core: Blake3Core::with_key_words(&self.key_words, KEYED_HASH),
            dir: PhantomData,
        }
    }
}

impl MacGenerationKey<OUT_LEN> for BLAKE3KeyedHashKey {
    type Generator<'k>
        = BLAKE3KeyedHash<'k, Encrypting>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        self.worker()
    }
}

impl MacVerificationKey<OUT_LEN> for BLAKE3KeyedHashKey {
    type Verifier<'k>
        = BLAKE3KeyedHash<'k, Decrypting>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        self.worker()
    }
}

/// BLAKE3 in its `keyed_hash` mode (spec s. 2.3): the worker a [`BLAKE3KeyedHashKey`] hands
/// out, borrowing it for `'k`. `Dir` is [`Encrypting`] for the generator, which implements [`MACGenerator`] and has
/// [`BLAKE3KeyedHash::into_squeezer`] for keyed output of any length, and [`Decrypting`] for the
/// verifier, which implements [`MACVerifier`]. Not `Clone`: a second worker comes from the key.
///
/// ```compile_fail
/// # use bouncycastle_core::direction::Encrypting;
/// # use bouncycastle_blake3::BLAKE3KeyedHash;
/// fn cloneable<T: Clone>() {}
/// cloneable::<BLAKE3KeyedHash<'static, Encrypting>>();
/// ```
pub struct BLAKE3KeyedHash<'k, Dir> {
    core: Blake3Core<&'k Secret<[u32; 8]>>,
    dir: PhantomData<Dir>,
}

impl BLAKE3KeyedHash<'_, Encrypting> {
    /// Ends the input and returns a squeezer for keyed output of any length (s. 2.6). Its first
    /// 32 bytes are the [`MACGenerator`] tag. No minimum length applies: choosing a safe output
    /// length is the caller's responsibility.
    pub fn into_squeezer(self) -> BLAKE3KeyedSqueezer {
        BLAKE3KeyedSqueezer(BLAKE3Squeezer::new(self.core.root_output()))
    }
}

impl MACGenerator<OUT_LEN> for BLAKE3KeyedHash<'_, Encrypting> {
    fn do_update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    fn do_final_out(self, out: &mut [u8; OUT_LEN]) -> usize {
        self.into_squeezer().do_output_out(out)
    }
}

impl MACVerifier<OUT_LEN> for BLAKE3KeyedHash<'_, Decrypting> {
    fn do_update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Recomputes the tag and compares it in constant time.
    fn do_verify_final(self, mac: &[u8; OUT_LEN]) -> Result<(), MACError> {
        // The recomputed tag is the valid tag of whatever message was absorbed, so it is kept
        // off the stack's leftovers.
        let mut computed: Secret<[u8; OUT_LEN]> = Secret::new();
        BLAKE3Squeezer::new(self.core.root_output()).do_output_out(&mut *computed);
        if ct::ct_eq_bytes(&*computed, mac) { Ok(()) } else { Err(MACError::VerificationFailed) }
    }
}

/// The squeezing half of [`BLAKE3KeyedHash`]: what [`BLAKE3KeyedHash::into_squeezer`] hands back.
///
/// It deliberately does **not** implement [`Suspendable`]: its state would contain the key.
///
/// There is no route to suspending it:
///
/// ```compile_fail
/// use bouncycastle_blake3::BLAKE3KeyedHashKey;
/// use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
/// use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
/// use bouncycastle_core::traits::Suspendable;
///
/// let material = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
/// let key = BLAKE3KeyedHashKey::from_key_material(&material).unwrap();
/// let _ = key.create_generator().into_squeezer().suspend(); // not Suspendable
/// ```
pub struct BLAKE3KeyedSqueezer(BLAKE3Squeezer);

impl XOFSqueezer for BLAKE3KeyedSqueezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        self.0.do_output(num_bytes)
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.0.do_output_out(output)
    }
}
