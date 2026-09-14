//! GHASH: the universal hash function GCM builds its authentication on (NIST SP 800-38D Sec 6.3,
//! 6.4), and the GF(2^128) multiplication it is defined over.
//!
//! This is the only genuinely new cryptographic code `gcm.rs` needs; everything else there is
//! plumbing around this and [`crate::Ctr`].
//!
//! # Field element representation
//!
//! A block of `GF(2^128)` is represented as `[u64; 2]`: `x[0]` is the first eight bytes of the
//! 16-byte block read big-endian, `x[1]` the last eight -- the same `asLongs`/`asBytes` convention
//! BC Java's `GCMUtil` uses. Sec 6.3 fixes the bit convention as "little endian": bit `x_0`, the
//! *leftmost* (most significant) bit of the first byte, is the coefficient of `u^0`. In this `u64`
//! pair form that means `x_0` is the *top* bit of `x[0]`, `x_63` is its bottom bit, `x_64` is the
//! top bit of `x[1]`, and `x_127` is its bottom bit. So Algorithm 1's "V >> 1" (discard the
//! rightmost bit of the whole 128-bit string, prepend a zero on the left) is a right shift across
//! the `x[0], x[1]` pair carrying the bottom bit of `x[0]` into the top bit of `x[1]`, and `R`
//! (`11100001 || 0^120`, Sec 6.3) is the block whose first byte is `0xE1` and the rest zero, i.e.
//! `[0xE1 << 56, 0]` in this representation.
//!
//! Getting this orientation right once, here, is worth the length of this comment: every GCM
//! implementation bug report in the wild is an orientation bug, and [`mul_reference`] exists so
//! [`mul`] can be checked against something whose correctness is visible by inspection of the spec
//! text above rather than by parity with another implementation.

use bouncycastle_utils::secret::Secret;

/// A block of `GF(2^128)`, in the two-`u64` form described in the module docs.
type Block = [u64; 2];

/// `R = 11100001 || 0^120` (Sec 6.3): first byte `0xE1`, the rest zero. Used only by
/// [`mul_reference`]: [`mul`] folds the same constant into its own reduction step directly, as
/// literal shift amounts rather than a named block.
#[cfg(test)]
const R: Block = [0xE100_0000_0000_0000, 0];

/// `x[0]` is the first eight bytes of `b` read big-endian, `x[1]` the last eight.
fn block_from_bytes(b: &[u8; 16]) -> Block {
    [
        u64::from_be_bytes(b[..8].try_into().expect("first half of a 16-byte block is 8 bytes")),
        u64::from_be_bytes(b[8..].try_into().expect("second half of a 16-byte block is 8 bytes")),
    ]
}

/// Inverse of [`block_from_bytes`].
fn block_to_bytes(x: &Block) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&x[0].to_be_bytes());
    out[8..].copy_from_slice(&x[1].to_be_bytes());
    out
}

/// Algorithm 1 (Sec 6.3), a direct transcription, computed bit-serially with masks so it is itself
/// constant time. This is the *oracle*: [`mul`] is checked against it in the test module below, and
/// it is never used outside `#[cfg(test)]`. Kept short and boring on purpose.
#[cfg(test)]
fn mul_reference(x: &Block, y: &Block) -> Block {
    // Step 2: Z_0 = 0^128, V_0 = Y.
    let mut z: Block = [0, 0];
    let mut v: Block = *y;
    // Step 3: for i = 0 to 127 ...
    for i in 0..128u32 {
        // Step 1 / step 3: bit x_i of X. x_0 is the top bit of x[0] (see module docs), so bit i
        // for i < 64 is bit (63 - i) of x[0], and for i >= 64 is bit (127 - i) of x[1].
        let bit = if i < 64 { (x[0] >> (63 - i)) & 1 } else { (x[1] >> (127 - i)) & 1 };
        // All-ones if x_i = 1, all-zero if x_i = 0 -- a constant-time select, standing in for the
        // spec's "Z_{i+1} = Z_i if x_i = 0; Z_i (+) V_i if x_i = 1".
        let m = 0u64.wrapping_sub(bit);
        z[0] ^= v[0] & m;
        z[1] ^= v[1] & m;

        // "V_{i+1} = V_i >> 1 if LSB_1(V_i) = 0; (V_i >> 1) (+) R if LSB_1(V_i) = 1." LSB_1 of the
        // 128-bit string V is the bottom bit of v[1]; ">> 1" is a right shift across the pair.
        let lsb = v[1] & 1;
        let lm = 0u64.wrapping_sub(lsb);
        let carry_in = v[0] & 1;
        v[0] >>= 1;
        v[1] = (v[1] >> 1) | (carry_in << 63);
        v[0] ^= R[0] & lm;
        v[1] ^= R[1] & lm;
    }
    // Step 4: return Z_128.
    z
}

/// The masked-lane carry-less multiply of two 64-bit halves.
///
/// Ported from BC Java's `GCMUtil.implMul64(long, long)`
/// (`crypto/modes/gcm/GCMUtil.java`). Four lane masks (`0x1111...`, `0x2222...`, `0x4444...`,
/// `0x8888...`) space the input bits four apart, so the sixteen masked products summed into each
/// output lane carry at most fifteen ways -- never enough for an integer carry to reach a live lane
/// -- which is what makes ordinary `u64` multiplication (relying on the CPU's integer multiplier
/// being constant time, the same assumption the rest of this library's constant-time code makes)
/// compute a carry-less (XOR-add) product on each lane. Masking again after summing discards the
/// garbage that leaked into the gaps between lanes.
fn impl_mul64(x: u64, y: u64) -> u64 {
    let x0 = x & 0x1111_1111_1111_1111;
    let x1 = x & 0x2222_2222_2222_2222;
    let x2 = x & 0x4444_4444_4444_4444;
    let x3 = x & 0x8888_8888_8888_8888;

    let y0 = y & 0x1111_1111_1111_1111;
    let y1 = y & 0x2222_2222_2222_2222;
    let y2 = y & 0x4444_4444_4444_4444;
    let y3 = y & 0x8888_8888_8888_8888;

    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);

    let z0 = z0 & 0x1111_1111_1111_1111;
    let z1 = z1 & 0x2222_2222_2222_2222;
    let z2 = z2 & 0x4444_4444_4444_4444;
    let z3 = z3 & 0x8888_8888_8888_8888;

    // The four lanes are disjoint (each mask owns one bit in every nibble), so `|` and `^` agree
    // here; `cargo mutants` is expected to report this substitution as a surviving, equivalent
    // mutant rather than a missing test.
    z0 | z1 | z2 | z3
}

/// The constant-time, table-free `GF(2^128)` product `x . y` (Sec 6.3's `*` operator).
///
/// Ported from BC Java's `GCMUtil.multiply(long[], long[])`: a "three-way recursion" (Karatsuba
/// over the two 64-bit halves, per Bernstein's "Batch binary Edwards") built on [`impl_mul64`], with
/// a bit-reversal trick (`rev(x)*rev(y) == rev((x*y) << 1)`) to reach the high 64 bits of each
/// 64x64 product without a 128-bit multiply, followed by the standard two-step reduction by `R`.
/// Variable names (`h0..h5`, `z0..z3`) match the Java source so the two can be diffed side by side.
pub(crate) fn mul(x: &Block, y: &Block) -> Block {
    let (x0, x1) = (x[0], x[1]);
    let (y0, y1) = (y[0], y[1]);
    let (x0r, x1r) = (x0.reverse_bits(), x1.reverse_bits());
    let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());

    let h0 = impl_mul64(x0r, y0r).reverse_bits();
    let h1 = impl_mul64(x0, y0) << 1;
    let h2 = impl_mul64(x1r, y1r).reverse_bits();
    let h3 = impl_mul64(x1, y1) << 1;
    let h4 = impl_mul64(x0r ^ x1r, y0r ^ y1r).reverse_bits();
    let h5 = impl_mul64(x0 ^ x1, y0 ^ y1) << 1;

    let z0 = h0;
    let mut z1 = h1 ^ h0 ^ h2 ^ h4;
    let mut z2 = h2 ^ h1 ^ h3 ^ h5;
    let z3 = h3;

    // Reduction by R, step 1: fold z3 into z1 and z2. The commented-out `(z3 << 63)` term in BC
    // Java's source is dropped because it is folded into the `z2 ^= ... (z3 << 62) ...` line below
    // instead: `z3 << 63` contributes only its bit 63 (all lower bits are shifted out), which is the
    // same single bit that `(z3 << 62) << 1`, i.e. bit 62 of `(z3 << 62)`, would carry forward one
    // more position -- BC Java's own comment marks this as the intentional omission.
    z1 ^= z3 ^ (z3 >> 1) ^ (z3 >> 2) ^ (z3 >> 7);
    z2 ^= (z3 << 62) ^ (z3 << 57);

    let mut z0 = z0;
    // Reduction by R, step 2: fold the now-complete z2 into z0 and z1.
    z0 ^= z2 ^ (z2 >> 1) ^ (z2 >> 2) ^ (z2 >> 7);
    z1 ^= (z2 << 63) ^ (z2 << 62) ^ (z2 << 57);

    [z0, z1]
}

/// The `GHASH` accumulator (Algorithm 2, Sec 6.4).
///
/// `Y_0 = 0^128` (step 2); each call to [`update`](Self::update) absorbs whole blocks via
/// `Y_i = (Y_{i-1} (+) X_i) . H` (step 3), buffering any partial block for the next call so that a
/// sequence of calls is equivalent to one call over the concatenation. [`finish`](Self::finish)
/// returns `Y_m` (step 4) after appending the 64-bit AAD- and data-bit-length block that Algorithm
/// 4 step 5 / Algorithm 5 step 6 fold into the same hash.
///
/// `H` and the running hash `Y` are the GCM intermediates Sec 5.3 requires to be secret ("the
/// intermediate values in the execution of the GCM functions shall be secret"), so both live in a
/// [`Secret`] and are zeroized on drop; the pending partial block is live plaintext-or-ciphertext
/// bytes still waiting to be absorbed and is wrapped for the same reason.
pub(crate) struct Ghash {
    /// The hash subkey `H = CIPH_K(0^128)`.
    h: Secret<Block>,
    /// `Y_i` of Algorithm 2.
    y: Secret<Block>,
    /// Bytes of the current block not yet absorbed.
    pending: Secret<[u8; 16]>,
    /// How many bytes of `pending` are meaningful, `0..=16`.
    pending_len: usize,
}

impl Ghash {
    /// `Y_0 = 0^128` (Algorithm 2 step 2), keyed by the hash subkey `H`.
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let mut hs: Secret<Block> = Secret::new();
        *hs = block_from_bytes(h);
        Self { h: hs, y: Secret::new(), pending: Secret::new(), pending_len: 0 }
    }

    /// `Y_i = (Y_{i-1} (+) X_i) . H` for one whole block `X_i`.
    fn absorb(&mut self, block: &[u8; 16]) {
        let xi = block_from_bytes(block);
        let mut acc = *self.y;
        acc[0] ^= xi[0];
        acc[1] ^= xi[1];
        *self.y = mul(&acc, &self.h);
    }

    /// Absorbs whole blocks of `data` immediately and buffers any remainder for the next call.
    /// Chunking-independent: a sequence of calls over pieces of a message is equivalent to one call
    /// over the whole message.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if self.pending_len > 0 {
            let need = 16 - self.pending_len;
            let take = need.min(data.len());
            (*self.pending)[self.pending_len..self.pending_len + take]
                .copy_from_slice(&data[..take]);
            self.pending_len += take;
            data = &data[take..];
            if self.pending_len < 16 {
                return;
            }
            let block = *self.pending;
            self.absorb(&block);
            self.pending_len = 0;
        }

        let (blocks, rest) = data.as_chunks::<16>();
        for block in blocks {
            self.absorb(block);
        }
        (*self.pending)[..rest.len()].copy_from_slice(rest);
        self.pending_len = rest.len();
    }

    /// The `0^v` / `0^u` zero-padding of Algorithm 4 step 5 / Algorithm 5 step 6: rounds the
    /// pending partial block up to a whole block with zero bytes and absorbs it. A no-op when
    /// nothing is pending, so it is safe to call unconditionally at a phase boundary.
    pub(crate) fn pad_to_block(&mut self) {
        if self.pending_len == 0 {
            return;
        }
        (*self.pending)[self.pending_len..].fill(0);
        let block = *self.pending;
        self.absorb(&block);
        self.pending_len = 0;
    }

    /// Appends `[aad_bits]_64 || [data_bits]_64` (Algorithm 4 step 5's final block) and returns
    /// `Y_m`, i.e. `S`.
    ///
    /// Takes `&mut self` rather than `self` -- `Gcm`'s verify-before-decrypt one-shot needs the rest
    /// of its own state (the `Ctr` field) after computing the tag, so consuming `Ghash` here would
    /// force that caller to reconstruct it. Nothing asserts a "was padded" flag: the caller is
    /// expected to have called [`pad_to_block`](Self::pad_to_block) for both the AAD and the data
    /// phase already (the `0^v` and `0^u` of step 5), so by the time `finish` runs there is nothing
    /// pending except this one final length block, and no caller should call `update` or
    /// `pad_to_block` again afterward.
    pub(crate) fn finish(&mut self, aad_bits: u64, data_bits: u64) -> [u8; 16] {
        debug_assert_eq!(
            self.pending_len, 0,
            "caller must pad_to_block before finish: nothing but the length block may be pending"
        );
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&data_bits.to_be_bytes());
        self.absorb(&len_block);
        block_to_bytes(&self.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal xorshift64* generator, so the >= 10000 pseudo-random test pairs below do not need
    /// the `rand` crate (CLAUDE.md: no new runtime dependency, and this is test-only anyway).
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn next_block(&mut self) -> Block {
            [self.next_u64(), self.next_u64()]
        }
    }

    /// The spec's `1`: `1 || 0^127`, the leftmost bit set and everything else zero. The
    /// multiplicative identity: `X . 1 == X` (Sec 6.3, "For a positive integer i, the ith power of a
    /// block X ... H^2 = H.H, H^3 = H.H.H").
    const ONE: Block = [0x8000_0000_0000_0000, 0];

    #[test]
    fn mul_matches_the_reference_on_zero() {
        let h: Block = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
        assert_eq!(mul(&[0, 0], &h), mul_reference(&[0, 0], &h));
        assert_eq!(mul(&h, &[0, 0]), mul_reference(&h, &[0, 0]));
    }

    #[test]
    fn mul_matches_the_reference_at_every_single_bit_position() {
        let h: Block = [0xdead_beef_cafe_babe, 0x0123_4567_89ab_cdef];
        for i in 0..128u32 {
            let x: Block = if i < 64 { [1u64 << (63 - i), 0] } else { [0, 1u64 << (127 - i)] };
            assert_eq!(mul(&x, &h), mul_reference(&x, &h), "bit position {i}");
        }
    }

    #[test]
    fn mul_matches_the_reference_on_all_ones() {
        let h: Block = [0xfeed_face_dead_beef, 0x0102_0304_0506_0708];
        let ones: Block = [u64::MAX, u64::MAX];
        assert_eq!(mul(&ones, &h), mul_reference(&ones, &h));
        assert_eq!(mul(&h, &ones), mul_reference(&h, &ones));
    }

    #[test]
    fn mul_matches_the_reference_on_ten_thousand_random_pairs() {
        let mut rng = Lcg(0x2545_f491_4f6c_dd1d);
        for _ in 0..10_000 {
            let x = rng.next_block();
            let y = rng.next_block();
            assert_eq!(mul(&x, &y), mul_reference(&x, &y), "x={x:?} y={y:?}");
        }
    }

    #[test]
    fn mul_by_one_is_the_identity() {
        let mut rng = Lcg(0x9e37_79b9_7f4a_7c15);
        for _ in 0..256 {
            let x = rng.next_block();
            assert_eq!(mul(&x, &ONE), x, "x . 1 == x for x={x:?}");
            assert_eq!(mul(&ONE, &x), x, "1 . x == x for x={x:?}");
        }
    }

    #[test]
    fn mul_is_commutative() {
        let mut rng = Lcg(0xbf58_476d_1ce4_e5b9);
        for _ in 0..256 {
            let x = rng.next_block();
            let y = rng.next_block();
            assert_eq!(mul(&x, &y), mul(&y, &x), "x={x:?} y={y:?}");
        }
    }

    /// A hand-checkable case for the oracle itself: `R . 1 == R`, the identity applied to the fixed
    /// reduction constant.
    #[test]
    fn reference_r_times_one_is_r() {
        assert_eq!(mul_reference(&R, &ONE), R);
    }

    /// `GHASH` over one, two and three blocks must equal folding [`mul_reference`] by hand, per
    /// Algorithm 2 step 3: `Y_i = (Y_{i-1} (+) X_i) . H`.
    #[test]
    fn ghash_matches_folding_the_reference_multiplier_by_hand() {
        let h_bytes = [0x42u8; 16];
        let h = block_from_bytes(&h_bytes);

        let blocks: [[u8; 16]; 3] = [[0x11; 16], [0x22; 16], [0x33; 16]];

        let mut y = [0u64, 0u64];
        for block in &blocks {
            let xi = block_from_bytes(block);
            y[0] ^= xi[0];
            y[1] ^= xi[1];
            y = mul_reference(&y, &h);
        }

        for n in 1..=3 {
            let mut g = Ghash::new(&h_bytes);
            for block in &blocks[..n] {
                g.update(block);
            }
            g.pad_to_block();
            // finish() also absorbs the zero-length block, so compare against one more fold step
            // over the all-zero length block for a fair comparison of the n-block prefix alone.
            let mut expected = [0u64, 0u64];
            for block in &blocks[..n] {
                let xi = block_from_bytes(block);
                expected[0] ^= xi[0];
                expected[1] ^= xi[1];
                expected = mul_reference(&expected, &h);
            }
            let zero_len_block = [0u8; 16];
            let xi = block_from_bytes(&zero_len_block);
            expected[0] ^= xi[0];
            expected[1] ^= xi[1];
            expected = mul_reference(&expected, &h);

            assert_eq!(block_to_bytes(&expected), g.finish(0, 0), "n={n}");
        }
        // Silence the unused full-message `y` computed above; it documents the general recurrence.
        let _ = y;
    }

    /// Chunking independence: absorbing a 100-byte message in one call must equal absorbing it in
    /// two pieces, at every possible split point.
    #[test]
    fn update_is_chunking_independent() {
        let h_bytes = [0x7eu8; 16];
        let data: [u8; 100] = core::array::from_fn(|i| i as u8);

        let mut whole = Ghash::new(&h_bytes);
        whole.update(&data);
        whole.pad_to_block();
        let expected = whole.finish(0, data.len() as u64 * 8);

        for split in 0..=data.len() {
            let mut g = Ghash::new(&h_bytes);
            g.update(&data[..split]);
            g.update(&data[split..]);
            g.pad_to_block();
            assert_eq!(g.finish(0, data.len() as u64 * 8), expected, "split at {split}");
        }
    }
}
