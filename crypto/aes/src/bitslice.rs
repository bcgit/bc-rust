//! Conversion between AES blocks and the bit-sliced representation the round functions act on.
//!
//! # What "bit-sliced" means here
//!
//! The round functions in [`crate::round`] and the S-box in [`crate::sbox`] do not operate on
//! bytes. They operate on eight *bit-planes*, `q[0]..q[7]`, where plane `q[k]` collects bit `k`
//! of every byte of the state. That is what lets the S-box be a Boolean circuit: one `&` or `^`
//! on a plane applies that gate to all sixteen byte positions at once, and no memory access is
//! ever indexed by a secret value.
//!
//! # The plane width is the number of blocks
//!
//! A block is 16 bytes, so a plane needs 16 bits per block. The planes are therefore generic
//! over their word type: `u16` planes hold one block, `u32` planes hold two and `u64` planes hold
//! four, and [`PlaneWord`] is the trait over those three widths. Block `b` occupies bits
//! `16b..16b + 16` of every plane -- its own 16-bit **lane** -- so a wider state is literally
//! several one-block states side by side, and every transformation written for one width serves
//! all three. The extra blocks come for free: the S-box circuit costs the same 113 gates on a
//! `u64` as on a `u16`, which is why [`crate::hazmat::AESInternal`] gives four blocks for the price of one.
//!
//! # The layout
//!
//! Within a block's lane, **bit `4r + c` of plane `q[k]` is bit `k` of `s[r,c]`**, with `r` and
//! `c` the row and column of FIPS 197 Eq (3.6) (`s[r,c] = in[r + 4c]`). Row `r` is the nibble
//! `r` of the lane, and the column is the bit within that nibble:
//!
//! ```text
//!            c=0   c=1   c=2   c=3
//!    r=0 |    0     1     2     3
//!    r=1 |    4     5     6     7      (bit position within the lane;
//!    r=2 |    8     9    10    11       add 16b for block b)
//!    r=3 |   12    13    14    15
//! ```
//!
//! Three things follow from this, and every mask in the crate is derived from one of them:
//!
//! * SHIFTROWS(), which only permutes within a row, becomes a rotation *within each nibble*, and
//!   MIXCOLUMNS(), which combines the four rows of a column, becomes rotations of each lane by 4
//!   (one row) and 8 (two rows). Both are derived from the table in [`crate::round`].
//! * A mask is a 16-bit pattern replicated into every lane, which is what
//!   [`PlaneWord::splat`] does; a rotation is one applied to every lane independently, which is
//!   [`PlaneWord::rotate_lanes_right`]. Those two methods are the only width-specific arithmetic
//!   the round functions need.
//! * A round key is the same for every block, so the round key at any width is the one-block
//!   `u16` form `splat` into every lane. That is why [`crate::schedule`] stores the schedule at
//!   `u16` width and why widening it costs one replication per plane.
//!
//! `test_layout_matches_the_documented_table` below pins the table exhaustively at every width;
//! every mask in this crate is only correct relative to it.
//!
//! # How the transpose produces it
//!
//! [`ortho`] transposes, within each *byte*-lane of the eight words, the 8x8 bit matrix indexed
//! by (word number, bit number within the byte):
//!
//! ```text
//! after ortho:  q[k] bit (8L + i)  ==  before ortho:  q[i] bit (8L + k)
//! ```
//!
//! So the byte at byte-lane `L` of word `i` before the transpose lands at bit `8L + i` of every
//! plane after it. Solving `8L + i = 16b + 4r + c` gives `L = 2b + (r div 2)` and
//! `i = 4 (r mod 2) + c`: word `i` must carry, in the two byte-lanes of block `b`'s 16-bit lane,
//! `s[r,c]` with `r = i div 4` and `c = i mod 4` in the low byte and `s[r + 2, c]` in the high
//! byte. [`block_to_words`] makes that placement for one block as eight `u16`s, and each width's
//! [`PlaneWord::pack`] puts every block's words into its lane and transposes all lanes at once.
//!
//! # Provenance
//!
//! The three-stage masked-swap transpose is translated from BearSSL `src/symcipher/aes_ct.c`
//! (`br_aes_ct_ortho`), by Thomas Pornin, MIT licensed. The block placement is not BearSSL's:
//! `aes_ct.c` interleaves its two blocks bit by bit (block A in the even bit positions of every
//! byte-lane, block B in the odd), which ties every mask to one width. Keeping each block in its
//! own lane instead is what lets one set of `u16` patterns serve `u16`, `u32` and `u64` planes.

pub(crate) use bouncycastle_utils::bitslice::{PlaneWord, Planes, ortho};

/// One 16-byte AES block, in the order of FIPS 197 Eq (3.6): `block[r + 4c] == s[r,c]`.
pub type Block = [u8; crate::AES_BLOCK_LEN];

/// What a plane word knows about AES blocks: how many a state of its width holds, and how to
/// load and unload them. The arithmetic the circuits need is the shared [`PlaneWord`]; this is
/// the part that knows a block is 16 bytes in FIPS 197's order. Each width is implemented
/// longhand below rather than through a macro, so that every placement is visible to
/// `cargo mutants` and to a reviewer.
pub(crate) trait BlockPlanes: PlaneWord {
    /// The blocks a state of this width holds: `[Block; N]` with `N` the word width divided by
    /// 16, so one, two or four.
    type Blocks: AsRef<[Block]> + AsMut<[Block]> + Default;

    /// Loads the blocks into bit-planes, block `b` into lane `b`.
    fn pack(blocks: &Self::Blocks) -> Planes<Self>;

    /// Reads the blocks back out of the bit-planes, in place; the exact inverse of
    /// [`PlaneWord::pack`]. Takes the planes mutably so the untranspose needs no copy of them.
    fn unpack(q: &mut Planes<Self>, blocks: &mut Self::Blocks);
}

/// The eight pre-transpose words of one block.
///
/// Word `i` holds `s[r,c]` in its low byte and `s[r + 2, c]` in its high byte, with `r = i div 4`
/// and `c = i mod 4`; after [`ortho`] that puts `s[r,c]` at bit `4r + c`. See the module docs
/// for the derivation.
#[inline(always)]
fn block_to_words(block: &Block) -> [u16; 8] {
    core::array::from_fn(|i| {
        let (r, c) = (i / 4, i % 4);
        u16::from_le_bytes([block[r + 4 * c], block[(r + 2) + 4 * c]])
    })
}

/// The inverse of [`block_to_words`].
#[inline(always)]
fn words_to_block(words: &[u16; 8], block: &mut Block) {
    for (i, word) in words.iter().enumerate() {
        let (r, c) = (i / 4, i % 4);
        let [lo, hi] = word.to_le_bytes();
        block[r + 4 * c] = lo;
        block[(r + 2) + 4 * c] = hi;
    }
}

impl BlockPlanes for u16 {
    type Blocks = [Block; 1];

    #[inline(always)]
    fn pack(blocks: &[Block; 1]) -> Planes<Self> {
        let mut q = block_to_words(&blocks[0]);
        ortho(&mut q);
        q
    }

    #[inline(always)]
    fn unpack(q: &mut Planes<Self>, blocks: &mut [Block; 1]) {
        ortho(q);
        words_to_block(q, &mut blocks[0]);
    }
}

impl BlockPlanes for u32 {
    type Blocks = [Block; 2];

    #[inline(always)]
    fn pack(blocks: &[Block; 2]) -> Planes<Self> {
        let a = block_to_words(&blocks[0]);
        let b = block_to_words(&blocks[1]);
        // Each block's words go into their own lane: the shifted operands are disjoint, so `|`
        // and `^` agree, which is why `cargo mutants` reports the `| -> ^` mutants here (and in
        // the `u64` version) as surviving.
        let mut q: Planes<Self> =
            core::array::from_fn(|i| u32::from(a[i]) | (u32::from(b[i]) << 16));
        ortho(&mut q);
        q
    }

    #[inline(always)]
    fn unpack(q: &mut Planes<Self>, blocks: &mut [Block; 2]) {
        ortho(q);
        // `as u16` truncates to the low lane, which is the intent.
        words_to_block(&core::array::from_fn(|i| q[i] as u16), &mut blocks[0]);
        words_to_block(&core::array::from_fn(|i| (q[i] >> 16) as u16), &mut blocks[1]);
    }
}

impl BlockPlanes for u64 {
    type Blocks = [Block; 4];

    #[inline(always)]
    fn pack(blocks: &[Block; 4]) -> Planes<Self> {
        let a = block_to_words(&blocks[0]);
        let b = block_to_words(&blocks[1]);
        let c = block_to_words(&blocks[2]);
        let d = block_to_words(&blocks[3]);
        let mut q: Planes<Self> = core::array::from_fn(|i| {
            u64::from(a[i])
                | (u64::from(b[i]) << 16)
                | (u64::from(c[i]) << 32)
                | (u64::from(d[i]) << 48)
        });
        ortho(&mut q);
        q
    }

    #[inline(always)]
    fn unpack(q: &mut Planes<Self>, blocks: &mut [Block; 4]) {
        ortho(q);
        // `as u16` truncates to the low lane, which is the intent.
        words_to_block(&core::array::from_fn(|i| q[i] as u16), &mut blocks[0]);
        words_to_block(&core::array::from_fn(|i| (q[i] >> 16) as u16), &mut blocks[1]);
        words_to_block(&core::array::from_fn(|i| (q[i] >> 32) as u16), &mut blocks[2]);
        words_to_block(&core::array::from_fn(|i| (q[i] >> 48) as u16), &mut blocks[3]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic byte generator, so the tests do not depend on an RNG crate.
    fn pseudo_random_block(seed: u32) -> Block {
        let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        let mut out = [0u8; 16];
        for byte in out.iter_mut() {
            // xorshift32; quality is irrelevant, only that it varies every bit position.
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state >> 24) as u8;
        }
        out
    }

    /// One distinct pseudo-random block per lane.
    fn pseudo_random_blocks<T: BlockPlanes>(seed: u32) -> T::Blocks {
        let mut blocks = T::Blocks::default();
        for (b, block) in blocks.as_mut().iter_mut().enumerate() {
            *block = pseudo_random_block(seed + 1000 * b as u32);
        }
        blocks
    }

    /// The number of blocks a state of width `T` holds.
    fn num_blocks<T: BlockPlanes>() -> usize {
        T::Blocks::default().as_ref().len()
    }

    /// The mask of block `b`'s 16-bit lane.
    fn lane<T: PlaneWord>(b: usize) -> T {
        // Lane 0 is every lane minus every lane but the first. The 16-bit shift is done in two
        // steps of 8, because a shift by 16 is the whole width of a `u16` and would panic.
        let lane0 = T::splat(0xFFFF) ^ ((T::splat(0xFFFF) << 8) << 8);
        lane0 << (16 * b as u32)
    }

    fn check_layout_matches_the_documented_table<T: BlockPlanes>() {
        // Pins the module doc table: bit (16b + 4r + c) of plane k is bit k of s[r,c] of block b.
        // Every mask in `round` depends on it. Done one bit at a time -- a block that is zero
        // except for bit k of byte j -- so a set bit must land as exactly one bit in exactly one
        // plane, which also rules out any leakage between lanes.
        for b in 0..num_blocks::<T>() {
            for j in 0..16 {
                let (r, c) = (j % 4, j / 4);
                for k in 0..8 {
                    let mut blocks = T::Blocks::default();
                    blocks.as_mut()[b][j] = 1 << k;
                    let q = T::pack(&blocks);
                    let expected = T::splat(1 << (4 * r + c)) & lane::<T>(b);
                    for (plane, &got) in q.iter().enumerate() {
                        let want = if plane == k { expected } else { T::splat(0) };
                        assert_eq!(
                            got, want,
                            "block {b}, byte {j} (r={r}, c={c}), bit {k}: plane {plane}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_layout_matches_the_documented_table() {
        check_layout_matches_the_documented_table::<u16>();
        check_layout_matches_the_documented_table::<u32>();
        check_layout_matches_the_documented_table::<u64>();
    }

    fn check_ortho_is_an_involution<T: BlockPlanes>() {
        let original = T::pack(&pseudo_random_blocks::<T>(3));
        let mut q = original;
        ortho(&mut q);
        assert_ne!(q, original, "ortho should actually move bits");
        ortho(&mut q);
        assert_eq!(q, original);
    }

    #[test]
    fn test_ortho_is_an_involution() {
        check_ortho_is_an_involution::<u16>();
        check_ortho_is_an_involution::<u32>();
        check_ortho_is_an_involution::<u64>();
    }

    fn check_unpack_inverts_pack<T: BlockPlanes>() {
        for seed in 0..64 {
            let blocks = pseudo_random_blocks::<T>(seed);
            let mut out = T::Blocks::default();
            T::unpack(&mut T::pack(&blocks), &mut out);
            assert_eq!(out.as_ref(), blocks.as_ref());
        }
    }

    #[test]
    fn test_unpack_inverts_pack() {
        check_unpack_inverts_pack::<u16>();
        check_unpack_inverts_pack::<u32>();
        check_unpack_inverts_pack::<u64>();
    }

    fn check_the_blocks_are_independent<T: BlockPlanes>() {
        // Each block's lane must depend on that block alone: packing all the blocks together
        // gives, lane by lane, exactly what packing each block on its own gives, and a block
        // packed on its own puts nothing outside its lane. This pins that the side-by-side
        // placement really is side by side and not overlapping.
        let blocks = pseudo_random_blocks::<T>(7);
        let all = T::pack(&blocks);
        for b in 0..num_blocks::<T>() {
            let mut only = T::Blocks::default();
            only.as_mut()[b] = blocks.as_ref()[b];
            let alone = T::pack(&only);
            for k in 0..8 {
                assert_eq!(all[k] & lane::<T>(b), alone[k], "block {b}, plane {k}");
                assert_eq!(alone[k] & !lane::<T>(b), T::splat(0), "block {b} leaked, plane {k}");
            }
        }
    }

    #[test]
    fn test_the_blocks_are_independent() {
        check_the_blocks_are_independent::<u16>();
        check_the_blocks_are_independent::<u32>();
        check_the_blocks_are_independent::<u64>();
    }

    #[test]
    fn test_lane_helper_selects_one_lane() {
        assert_eq!(lane::<u16>(0), 0xFFFF);
        assert_eq!(lane::<u32>(0), 0x0000_FFFF);
        assert_eq!(lane::<u32>(1), 0xFFFF_0000);
        assert_eq!(lane::<u64>(2), 0x0000_FFFF_0000_0000);
        assert_eq!(lane::<u64>(3), 0xFFFF_0000_0000_0000);
        assert_eq!(num_blocks::<u16>(), 1);
        assert_eq!(num_blocks::<u32>(), 2);
        assert_eq!(num_blocks::<u64>(), 4);
    }

    #[test]
    fn test_splat_replicates_into_every_lane() {
        assert_eq!(u16::splat(0x1234), 0x1234);
        assert_eq!(u32::splat(0x1234), 0x1234_1234);
        assert_eq!(u64::splat(0x1234), 0x1234_1234_1234_1234);
        assert_eq!(u64::splat(0xFFFF), u64::MAX);
        assert_eq!(u64::splat(0), 0);
    }

    #[test]
    fn test_rotate_lanes_right_rotates_each_lane_on_its_own() {
        // Rotating the sole lane of a u16 is a word rotation.
        assert_eq!(0x1234u16.rotate_lanes_right(4), 0x4123);
        assert_eq!(0x1234u16.rotate_lanes_right(8), 0x3412);
        // In a wider word, each lane rotates separately: nothing crosses the lane boundary.
        assert_eq!(0x1234_5678u32.rotate_lanes_right(4), 0x4123_8567);
        assert_eq!(0x1234_5678u32.rotate_lanes_right(8), 0x3412_7856);
        assert_eq!(0x1234_5678_9ABC_DEF0u64.rotate_lanes_right(4), 0x4123_8567_C9AB_0DEF);
        assert_eq!(0x1234_5678_9ABC_DEF0u64.rotate_lanes_right(8), 0x3412_7856_BC9A_F0DE);
        // Amounts 4 and 8 are the ones MIXCOLUMNS() uses, but the contract is any 0 < n < 16.
        assert_eq!(0x8001_0001u32.rotate_lanes_right(1), 0xC000_8000);
        assert_eq!(0x0001_0001_0001_0001u64.rotate_lanes_right(15), 0x0002_0002_0002_0002);
    }

    #[test]
    fn test_block_to_words_places_bytes_as_documented() {
        // Word i: s[i div 4, i mod 4] in the low byte, s[i div 4 + 2, i mod 4] in the high byte,
        // with s[r,c] = block[r + 4c].
        let block: Block = core::array::from_fn(|j| j as u8);
        let words = block_to_words(&block);
        for (i, &word) in words.iter().enumerate() {
            let (r, c) = (i / 4, i % 4);
            assert_eq!(word.to_le_bytes(), [(r + 4 * c) as u8, (r + 2 + 4 * c) as u8], "word {i}");
        }
        let mut back = [0u8; 16];
        words_to_block(&words, &mut back);
        assert_eq!(back, block);
    }
}
