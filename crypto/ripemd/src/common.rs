//! What the four RIPEMD functions share: the non-linear functions, the added constants, the
//! message-word selection and rotation tables of the designers' pseudo-code, the MD4-style
//! message buffering and padding, and the state every one of them keeps ([`Core`]).
//!
//! The tables are transcribed from the designers' pseudo-code files (`rmd128.txt`, `rmd160.txt`,
//! `rmd256.txt`, `rmd320.txt`; see the crate docs). The four files agree on every entry they
//! share: RIPEMD-128 and RIPEMD-256 use the first 64 entries of the RIPEMD-160 / RIPEMD-320 tables
//! `r`, `r'`, `s`, `s'`, the same `K(j)` for the first four rounds and the same `K'(j)` for the
//! first three.

use bouncycastle_core::errors::SuspendableError;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};

/// `f(j, x, y, z) = x XOR y XOR z` (`0 <= j <= 15`).
#[inline(always)]
pub(crate) const fn f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// `f(j, x, y, z) = (x AND y) OR (NOT(x) AND z)` (`16 <= j <= 31`).
///
/// The two operands of the `|` are disjoint (`x` selects one, `NOT x` the other), so `|` and `^`
/// compute the same function here; a surviving `| -> ^` mutant is an equivalence, not a gap.
#[inline(always)]
pub(crate) const fn f2(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// `f(j, x, y, z) = (x OR NOT(y)) XOR z` (`32 <= j <= 47`).
#[inline(always)]
pub(crate) const fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

/// `f(j, x, y, z) = (x AND z) OR (y AND NOT(z))` (`48 <= j <= 63`). Disjoint operands, as [`f2`].
#[inline(always)]
pub(crate) const fn f4(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

/// `f(j, x, y, z) = x XOR (y OR NOT(z))` (`64 <= j <= 79`, RIPEMD-160 and RIPEMD-320 only).
#[inline(always)]
pub(crate) const fn f5(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

/// `f(j, x, y, z)` for any step `j` in `0..80`: the five functions above, one per round of 16.
#[inline(always)]
pub(crate) const fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j / 16 {
        0 => f1(x, y, z),
        1 => f2(x, y, z),
        2 => f3(x, y, z),
        3 => f4(x, y, z),
        _ => f5(x, y, z),
    }
}

/// `K(j)`, the added constant of the left line, one per round: `0`, `int(2**30 x sqrt(2))`,
/// `int(2**30 x sqrt(3))`, `int(2**30 x sqrt(5))`, `int(2**30 x sqrt(7))`. RIPEMD-128 and
/// RIPEMD-256 use the first four.
pub(crate) const K_LEFT: [u32; 5] =
    [0x0000_0000, 0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xA953_FD4E];

/// `K'(j)` for RIPEMD-160 and RIPEMD-320, the right line: `int(2**30 x cbrt(2))`,
/// `int(2**30 x cbrt(3))`, `int(2**30 x cbrt(5))`, `int(2**30 x cbrt(7))`, `0`.
pub(crate) const K_RIGHT_160: [u32; 5] =
    [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x7A6D_76E9, 0x0000_0000];

/// `K'(j)` for RIPEMD-128 and RIPEMD-256: the same cube-root constants for three rounds, then `0`.
pub(crate) const K_RIGHT_128: [u32; 4] = [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x0000_0000];

/// `r(j)`, the message word selected by the left line at step `j`.
#[rustfmt::skip]
pub(crate) const R_LEFT: [usize; 80] = [
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
];

/// `r'(j)`, the message word selected by the right line at step `j`.
#[rustfmt::skip]
pub(crate) const R_RIGHT: [usize; 80] = [
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
];

/// `s(j)`, the left line's rotation amount at step `j`.
#[rustfmt::skip]
pub(crate) const S_LEFT: [u32; 80] = [
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
];

/// `s'(j)`, the right line's rotation amount at step `j`.
#[rustfmt::skip]
pub(crate) const S_RIGHT: [u32; 80] = [
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
];

/// The block length in bytes: 64 (a 16-word block of 32-bit words).
pub(crate) const BLOCK_LEN: usize = 64;

/// `X[i][0..15]`: one 64-byte block as sixteen little-endian 32-bit words. All four functions
/// read their input little-endian, as MD4 does (RFC 1320 Sec 2: "a sequence of bytes can be
/// interpreted as a sequence of 32-bit words, where each consecutive group of four bytes is
/// interpreted as a word with the low-order (least significant) byte given first").
#[inline(always)]
pub(crate) fn words(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let (chunks, _) = block.as_chunks::<4>();
    core::array::from_fn(|i| u32::from_le_bytes(chunks[i]))
}

/// The message buffer and byte count shared by all four functions, with MD4's padding.
///
/// The pseudo-code says only "Padding is identical to that of MD4"; MD4 is RFC 1320, whose
/// Sec 3.1 appends a single `1` bit and then `0` bits until the length is congruent to 448 mod
/// 512, and whose Sec 3.2 appends the 64-bit message length in bits, "low-order word first".
#[derive(Clone)]
struct Buffer {
    /// Bytes absorbed so far, modulo 2^64; the padding needs the message length in bits.
    byte_count: u64,
    /// The partial block waiting for more input. Zero past `x_buf_off` until `finish`: a
    /// completed block is cleared, so the suspended state is canonical and holds no message
    /// byte that has already been compressed.
    x_buf: Secret<[u8; BLOCK_LEN]>,
    /// How much of `x_buf` is filled; always below `BLOCK_LEN`.
    x_buf_off: usize,
}

impl Buffer {
    fn new() -> Self {
        Self { byte_count: 0, x_buf: Secret::new(), x_buf_off: 0 }
    }

    /// Absorbs `data`, calling `compress` for every completed block.
    fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; BLOCK_LEN])) {
        // RFC 1320 Sec 3.2: "In the unlikely event that b is greater than 2^64, then only the
        // low-order 64 bits of b are used", so the count wraps rather than being limited.
        self.byte_count = self.byte_count.wrapping_add(data.len() as u64);

        let available = BLOCK_LEN - self.x_buf_off;
        if data.len() < available {
            self.x_buf[self.x_buf_off..self.x_buf_off + data.len()].copy_from_slice(data);
            self.x_buf_off += data.len();
            return;
        }

        if self.x_buf_off != 0 {
            self.x_buf[self.x_buf_off..].copy_from_slice(&data[..available]);
            data = &data[available..];
            compress(&self.x_buf);
            // Once per call at most: whole blocks after this one are compressed from `data`.
            self.x_buf.fill(0);
        }

        let (blocks, remainder) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            compress(block);
        }
        self.x_buf[..remainder.len()].copy_from_slice(remainder);
        self.x_buf_off = remainder.len();
    }

    /// Pads and compresses the final block(s): RFC 1320 Sec 3.1 and Sec 3.2.
    ///
    /// `num_partial_bits` (0..=7, validated by the caller) trailing message bits follow the buffered
    /// whole bytes. They are the most significant bits of `partial_byte`, leading bit first: the
    /// ASN.1 BIT STRING order of X.690 s. 8.6.2.1, which is also RFC 1320 Sec 2's own bit order
    /// ("each consecutive group of eight bits is interpreted as a byte with the high-order (most
    /// significant) bit of each byte listed first"). The low `8 - num_partial_bits` bits are
    /// ignored. `num_partial_bits == 0` is the ordinary whole-byte case.
    ///
    /// Leaves the buffer holding the last padded block; the hash is finished and not used again.
    fn finish(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        mut compress: impl FnMut(&[u8; BLOCK_LEN]),
    ) {
        debug_assert!(num_partial_bits <= 7);
        // The length in bits of the message before padding (Sec 3.2's `b`): byte_count is a byte
        // counter, so the low three bits of byte_count << 3 are free for the partial bits.
        let bit_len = (self.byte_count << 3) | (num_partial_bits as u64);

        // Sec 3.1: "a single '1' bit is appended to the message, and then '0' bits are appended so
        // that the length in bits of the padded message becomes congruent to 448, modulo 512". The
        // final message byte is therefore [the top num_partial_bits bits of partial_byte] [1] [0...];
        // with no partial bits this is the familiar 0x80. The mask is built in u16 so that the 8-bit
        // shift for num_partial_bits == 0 cannot overflow (0xFF00 >> 0 truncates to 0x00). If fewer
        // than eight bytes remain for the length, the zeros run into a second block.
        // Mutants note: the masked message bits and the padding bit are disjoint, as are the two
        // halves of bit_len above, so a surviving `|` -> `^` in either is an equivalent mutant.
        let mask = (0xFF00u16 >> num_partial_bits) as u8;
        self.x_buf[self.x_buf_off] = (partial_byte & mask) | (0x80u8 >> num_partial_bits);
        self.x_buf_off += 1;
        if self.x_buf_off > 56 {
            self.x_buf[self.x_buf_off..].fill(0);
            compress(&self.x_buf);
            self.x_buf_off = 0;
        }
        self.x_buf[self.x_buf_off..56].fill(0);

        // Sec 3.2: "A 64-bit representation of b ... is appended ... appended low-order word
        // first", i.e. little-endian.
        self.x_buf[56..].copy_from_slice(&bit_len.to_le_bytes());
        compress(&self.x_buf);
    }
}

/// The state of any of the four functions: the chaining variable `h0, h1, ..` as `S` (four,
/// five, eight or ten words) and the message buffer. Which function it is lies in the initial
/// value given to [`Core::new`] and the `compress` passed to [`Core::update`] and
/// [`Core::finish`], which is applied to the chaining variable and one block.
#[derive(Clone)]
pub(crate) struct Core<S: ZeroizablePrimitive + AsRef<[u32]> + AsMut<[u32]>> {
    h: Secret<S>,
    buffer: Buffer,
}

impl<S: ZeroizablePrimitive + AsRef<[u32]> + AsMut<[u32]>> Core<S> {
    /// A state ready for use: the chaining variable holds the initial value `h0`.
    pub(crate) fn new(h0: S) -> Self {
        let mut h = Secret::<S>::new();
        *h = h0;
        Self { h, buffer: Buffer::new() }
    }

    /// Absorbs `data`.
    pub(crate) fn update(&mut self, data: &[u8], compress: impl Fn(&mut [u32], &[u8; BLOCK_LEN])) {
        let h = self.h.as_mut();
        self.buffer.update(data, |block| compress(h, block));
    }

    /// Pads and compresses the final block(s) (see [`Buffer::finish`]), then writes the first
    /// `output_len` bytes of the chaining variable as the digest.
    ///
    /// `output` is zeroized first. Returns the number of bytes written
    /// (`min(output.len(), output_len)`); a shorter output buffer truncates the digest, a longer
    /// one is left zero past the digest.
    pub(crate) fn finish(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output_len: usize,
        output: &mut [u8],
        compress: impl Fn(&mut [u32], &[u8; BLOCK_LEN]),
    ) -> usize {
        debug_assert!(num_partial_bits <= 7);
        output.fill(0);
        let n = output.len().min(output_len);

        let h = self.h.as_mut();
        self.buffer.finish(partial_byte, num_partial_bits, |block| compress(h, block));

        // The digest is h0 || h1 || ..., each word little-endian (RFC 1320 Sec 3.5: "we begin with
        // the low-order byte of A"), truncated to the caller's buffer.
        for (chunk, w) in output[..n].chunks_mut(4).zip(self.h.as_ref()) {
            chunk.copy_from_slice(&w.to_le_bytes()[..chunk.len()]);
        }
        n
    }

    /// The suspended state: the library version tag, the chaining variable little-endian, the
    /// byte count little-endian, the 64-byte buffer and its fill as one byte. `N` is those
    /// lengths' sum.
    ///
    /// The buffer is zero past its fill, so one message prefix has one encoding and no byte of
    /// a block already compressed is carried.
    pub(crate) fn suspend<const N: usize>(&self) -> [u8; N] {
        let mut out_to_return = [0u8; N];
        let out = add_lib_ver(&mut out_to_return);

        let words = self.h.as_ref();
        let n = 4 * words.len();
        for (chunk, w) in out[..n].as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *chunk = w.to_le_bytes();
        }
        out[n..n + 8].copy_from_slice(&self.buffer.byte_count.to_le_bytes());
        out[n + 8..n + 8 + BLOCK_LEN].copy_from_slice(&*self.buffer.x_buf);
        // The fill is always below BLOCK_LEN = 64, so one byte holds it.
        out[n + 8 + BLOCK_LEN] = self.buffer.x_buf_off as u8;

        out_to_return
    }

    /// The inverse of [`Self::suspend`], after checking the library version tag.
    pub(crate) fn resume<const N: usize>(
        serialized_state: &[u8; N],
    ) -> Result<Self, SuspendableError> {
        let input = check_lib_ver(serialized_state, None)?;

        let mut h = Secret::<S>::new();
        let n = 4 * h.as_ref().len();
        for (w, chunk) in h.as_mut().iter_mut().zip(input[..n].as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*chunk);
        }
        let mut buffer = Buffer::new();
        // infallible: an 8-byte slice into a [u8; 8]
        buffer.byte_count = u64::from_le_bytes(input[n..n + 8].try_into().unwrap());
        let fill = input[n + 8 + BLOCK_LEN] as usize;
        if fill >= BLOCK_LEN {
            return Err(SuspendableError::InvalidData);
        }
        // update keeps byte_count congruent to the fill modulo the block length (which divides
        // 2^64, so the wrap preserves it); a state in which they disagree describes no message
        // and must not resume.
        if buffer.byte_count % BLOCK_LEN as u64 != fill as u64 {
            return Err(SuspendableError::InvalidData);
        }
        // The buffer is zero past its fill (see `Buffer::x_buf`), so a state that is not
        // encodes nothing `suspend` writes.
        if input[n + 8 + fill..n + 8 + BLOCK_LEN].iter().any(|&b| b != 0) {
            return Err(SuspendableError::InvalidData);
        }
        buffer.x_buf.copy_from_slice(&input[n + 8..n + 8 + BLOCK_LEN]);
        buffer.x_buf_off = fill;

        Ok(Self { h, buffer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tables_are_permutations() {
        // Every round of r and r' selects each of the sixteen message words exactly once.
        for table in [&R_LEFT, &R_RIGHT] {
            for round in table.chunks(16) {
                let mut seen = [false; 16];
                for &w in round {
                    assert!(!seen[w], "word {w} selected twice in one round");
                    seen[w] = true;
                }
            }
        }
        // Rotation amounts are in 5..=15, as in the pseudo-code tables.
        for &s in S_LEFT.iter().chain(S_RIGHT.iter()) {
            assert!((5..=15).contains(&s), "rotation {s}");
        }
    }

    #[test]
    fn test_first_round_selects_words_in_order() {
        // r(j) = j for 0 <= j <= 15.
        for j in 0..16 {
            assert_eq!(R_LEFT[j], j);
        }
    }

    #[test]
    fn test_nonlinear_functions_against_truth_tables() {
        // Bit-level truth tables of the five functions, worked from the pseudo-code definitions,
        // indexed by the bits x, y, z as 4x + 2y + z.
        const F1: [bool; 8] = [false, true, true, false, true, false, false, true];
        const F2: [bool; 8] = [false, true, false, true, false, false, true, true];
        const F3: [bool; 8] = [true, false, false, true, true, false, true, false];
        const F4: [bool; 8] = [false, false, true, false, false, true, true, true];
        const F5: [bool; 8] = [true, false, true, true, false, true, false, false];
        let word = |bit: bool| if bit { u32::MAX } else { 0 };
        for i in 0..8 {
            let (x, y, z) = (word(i & 4 != 0), word(i & 2 != 0), word(i & 1 != 0));
            assert_eq!(f1(x, y, z), word(F1[i]), "f1 {i}");
            assert_eq!(f2(x, y, z), word(F2[i]), "f2 {i}");
            assert_eq!(f3(x, y, z), word(F3[i]), "f3 {i}");
            assert_eq!(f4(x, y, z), word(F4[i]), "f4 {i}");
            assert_eq!(f5(x, y, z), word(F5[i]), "f5 {i}");
        }
        // f(j) dispatches by round.
        let (x, y, z) = (0xF0F0_F0F0u32, 0xFF00_FF00u32, 0xFFFF_0000u32);
        assert_eq!(f(0, x, y, z), f1(x, y, z));
        assert_eq!(f(15, x, y, z), f1(x, y, z));
        assert_eq!(f(16, x, y, z), f2(x, y, z));
        assert_eq!(f(47, x, y, z), f3(x, y, z));
        assert_eq!(f(48, x, y, z), f4(x, y, z));
        assert_eq!(f(79, x, y, z), f5(x, y, z));
    }

    #[test]
    fn test_padding_lengths() {
        // Count the blocks the padding produces for every residue: one extra block when fewer
        // than nine bytes remain (message tail + 0x80 + 8 length bytes must fit), two otherwise.
        for len in 0..200usize {
            let mut b = Buffer::new();
            let mut blocks = 0;
            b.update(&vec![0xABu8; len], |_| blocks += 1);
            let before = blocks;
            b.finish(0, 0, |_| blocks += 1);
            let expected_total = (len + 1 + 8).div_ceil(BLOCK_LEN);
            assert_eq!(blocks, expected_total, "len {len}");
            assert_eq!(before, len / BLOCK_LEN, "len {len}");
        }
    }

    #[test]
    fn test_padding_content() {
        // A 3-byte message: 0x80, zeros, then the bit length 24 little-endian in the last 8 bytes.
        let mut b = Buffer::new();
        b.update(b"abc", |_| panic!("no block yet"));
        let mut last = None;
        b.finish(0, 0, |blk| last = Some(*blk));
        let last = last.unwrap();
        assert_eq!(&last[..3], b"abc");
        assert_eq!(last[3], 0x80);
        assert!(last[4..56].iter().all(|&x| x == 0));
        assert_eq!(&last[56..], &24u64.to_le_bytes());
        // 56 bytes: the 0x80 lands at offset 56, so the length goes into a second block.
        let mut b = Buffer::new();
        b.update(&[0x11u8; 56], |_| panic!("no block yet"));
        let mut seen = Vec::new();
        b.finish(0, 0, |blk| seen.push(*blk));
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0][56], 0x80);
        assert!(seen[0][57..].iter().all(|&x| x == 0));
        assert!(seen[1][..56].iter().all(|&x| x == 0));
        assert_eq!(&seen[1][56..], &(56u64 * 8).to_le_bytes());
    }

    #[test]
    fn test_padding_partial_bits() {
        // "abc" plus n trailing bits, the top n bits of 0xA5 (ASN.1 BIT STRING order): the final
        // message byte is those bits followed immediately by the "1" bit (RFC 1320 Sec 3.1), and the
        // length field is 24 + n bits (Sec 3.2). The unused low bits of the partial byte are ignored.
        for n in 1..=7usize {
            let mask = (0xFF00u16 >> n) as u8;
            let mut blocks = Vec::new();
            for partial_byte in [0xA5u8, 0xA5 & mask] {
                let mut b = Buffer::new();
                b.update(b"abc", |_| panic!("no block yet"));
                let mut last = None;
                b.finish(partial_byte, n, |blk| last = Some(*blk));
                blocks.push(last.unwrap());
            }
            assert_eq!(blocks[0], blocks[1], "n {n}: unused low bits must be ignored");
            let last = blocks[0];
            assert_eq!(&last[..3], b"abc");
            assert_eq!(last[3], (0xA5 & mask) | (0x80 >> n), "n {n}: pad byte");
            assert!(last[4..56].iter().all(|&x| x == 0));
            assert_eq!(&last[56..], &(24u64 + n as u64).to_le_bytes(), "n {n}: bit length");
        }
    }

    #[test]
    fn test_words_are_little_endian() {
        let mut block = [0u8; 64];
        block[..4].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        block[60..].copy_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE]);
        let w = words(&block);
        assert_eq!(w[0], 0x1234_5678);
        assert_eq!(w[15], 0xDEAD_BEEF);
    }
}
