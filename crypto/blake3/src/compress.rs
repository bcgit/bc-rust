//! The BLAKE3 compression function and its constants (BLAKE3 spec s. 2.2).
//!
//! Everything in this module is a direct transcription of s. 2.2 and Tables 1-3. The structure
//! (`g`, `round`, `permute`, `compress`) follows the reference implementation that the spec's
//! s. 5.1 describes "as an aid to implementers".
//!
//! There are no data-dependent branches or table lookups here: the only indexing is by the
//! fixed `MSG_PERMUTATION` schedule and fixed state positions.

/// BLAKE3 spec s. 2.4: "Each block is parsed in little-endian order into message words m0 ... m15",
/// so a block is 16 x 4 = 64 bytes.
pub(crate) const BLOCK_LEN: usize = 64;

/// BLAKE3 spec s. 2.1: "The input of BLAKE3 is split into contiguous chunks of 1024 bytes".
pub(crate) const CHUNK_LEN: usize = 1024;

/// BLAKE3 spec s. 2.2, Table 1: "Constants IV0 ... IV7 used in the initialization of BLAKE3."
/// ("The IV0 ... IV7 constants are the same as in BLAKE2s".)
pub(crate) const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// BLAKE3 spec s. 2.2, Table 2: "Permutational key schedule for BLAKE3's keyed permutation."
/// Entry `i` names the message word that moves to position `i`.
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// BLAKE3 spec s. 2.2, Table 3: "Admissible values for input d in the BLAKE3 compression function."
// "The value of d is the sum of all the flags defined for a given compression."

/// Table 3: CHUNK_START = 2^0.
/// Mutants note: `1 << 0` and `1 >> 0` are both 1, so a surviving `<<`/`>>` swap here is an
/// equivalent mutant.
pub(crate) const CHUNK_START: u32 = 1 << 0;
/// Table 3: CHUNK_END = 2^1.
pub(crate) const CHUNK_END: u32 = 1 << 1;
/// Table 3: PARENT = 2^2.
pub(crate) const PARENT: u32 = 1 << 2;
/// Table 3: ROOT = 2^3.
pub(crate) const ROOT: u32 = 1 << 3;
/// Table 3: KEYED_HASH = 2^4.
pub(crate) const KEYED_HASH: u32 = 1 << 4;
/// Table 3: DERIVE_KEY_CONTEXT = 2^5.
pub(crate) const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
/// Table 3: DERIVE_KEY_MATERIAL = 2^6.
pub(crate) const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// BLAKE3 spec s. 2.2: the "quarter-round" G_i(a, b, c, d), where `mx` = m_{2i+0} and
/// `my` = m_{2i+1}. "+ denote addition modulo 2^32, >>> denote bitwise right rotation".
#[inline]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    // a <- a + b + m_{2i+0}
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    // d <- (d ^ a) >>> 16
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    // c <- c + d
    v[c] = v[c].wrapping_add(v[d]);
    // b <- (b ^ c) >>> 12
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    // a <- a + b + m_{2i+1}
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    // d <- (d ^ a) >>> 8
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    // c <- c + d
    v[c] = v[c].wrapping_add(v[d]);
    // b <- (b ^ c) >>> 7
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// BLAKE3 spec s. 2.2: "A round consists of the following 8 operations ... That is, a round
/// applies a G function to each column of the 4 x 4 state in parallel, and then to each of the
/// diagonals in parallel." G_i takes message words m_{2i} and m_{2i+1}.
#[inline]
fn round(v: &mut [u32; 16], m: &[u32; 16]) {
    // G0(v0, v4, v8, v12)   G1(v1, v5, v9, v13)   G2(v2, v6, v10, v14)   G3(v3, v7, v11, v15)
    g(v, 0, 4, 8, 12, m[0], m[1]);
    g(v, 1, 5, 9, 13, m[2], m[3]);
    g(v, 2, 6, 10, 14, m[4], m[5]);
    g(v, 3, 7, 11, 15, m[6], m[7]);
    // G4(v0, v5, v10, v15)  G5(v1, v6, v11, v12)  G6(v2, v7, v8, v13)   G7(v3, v4, v9, v14)
    g(v, 0, 5, 10, 15, m[8], m[9]);
    g(v, 1, 6, 11, 12, m[10], m[11]);
    g(v, 2, 7, 8, 13, m[12], m[13]);
    g(v, 3, 4, 9, 14, m[14], m[15]);
}

/// BLAKE3 spec s. 2.2: "After each round (except the last one where it would be useless), the
/// message words are permuted according to Table 2."
#[inline]
fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

/// The BLAKE3 compression function of spec s. 2.2.
///
/// Inputs, in the spec's words: "The input chaining value, h0 ... h7 (256 bits)", "The message
/// block, m0 ... m15 (512 bits)", "A 64-bit counter, t = t0, t1, with t0 the lower order word and
/// t1 the higher order word", "The number of input bytes in the block, b (32 bits)", and "A set
/// of domain separation bit flags, d (32 bits)".
///
/// Returns the full 16-word output h'0 ... h'15. "The output of the compression function is most
/// often truncated to produce 256-bit chaining values" -- callers that want a chaining value take
/// the first 8 words; the extendable output of s. 2.6 uses all 16.
///
/// The working state and the permuted message copy are ordinary stack locals and are not
/// zeroized; the persistent chaining values and buffers live in `Secret`s in the callers.
pub(crate) fn compress(h: &[u32; 8], m: &[u32; 16], t: u64, b: u32, d: u32) -> [u32; 16] {
    // t = t0, t1: "t0 the lower order word and t1 the higher order word".
    let t0 = t as u32;
    let t1 = (t >> 32) as u32;

    // "The compression function initializes its 16-word internal state v0 ... v15 as follows:"
    //   v0  v1  v2  v3       h0  h1  h2  h3
    //   v4  v5  v6  v7   <-  h4  h5  h6  h7
    //   v8  v9  v10 v11      IV0 IV1 IV2 IV3
    //   v12 v13 v14 v15      t0  t1  b   d
    #[rustfmt::skip]
    let mut v: [u32; 16] = [
        h[0],  h[1],  h[2],  h[3],
        h[4],  h[5],  h[6],  h[7],
        IV[0], IV[1], IV[2], IV[3],
        t0,    t1,    b,     d,
    ];

    // "The compression function applies a 7-round keyed permutation v' = E(m, v) to the state
    // v0 ... v15, keyed by the message m0 ... m15." The message is permuted between rounds but
    // not after the seventh ("except the last one where it would be useless").
    let mut m = *m;
    for _ in 0..6 {
        round(&mut v, &m);
        permute(&mut m);
    }
    round(&mut v, &m);

    // "The output of the compression function h'0 ... h'15 is defined as:"
    //   h'i     <- v'i ^ v'(i+8)    for i = 0..7
    //   h'(i+8) <- v'(i+8) ^ hi     for i = 0..7
    // The left column must read v'(i+8) before the right column overwrites it.
    for i in 0..8 {
        v[i] ^= v[i + 8];
        v[i + 8] ^= h[i];
    }
    v
}

/// BLAKE3 spec s. 2.4: "Each block is parsed in little-endian order into message words
/// m0 ... m15". Also used for the 32-byte key of s. 2.3 ("k0 ... k7 are parsed in little-endian
/// order from the 256-bit key").
#[inline]
pub(crate) fn words_from_le_bytes<const N: usize>(bytes: &[u8], words: &mut [u32; N]) {
    debug_assert_eq!(bytes.len(), 4 * N);
    let (chunks, _remainder) = bytes.as_chunks::<4>();
    for (word, four_bytes) in words.iter_mut().zip(chunks) {
        *word = u32::from_le_bytes(*four_bytes);
    }
}
