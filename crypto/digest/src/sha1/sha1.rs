use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::traits::{FinishToken, Hash, HashOneShot, Suspendable};
use bouncycastle_utils::stack_wipe::wipe_stack_below;
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_utils::{min, secret::Secret};
use core::slice;

/// The digest length in bytes: FIPS 180-4 Figure 1, a 160-bit message digest.
const OUTPUT_LEN: usize = 20;

/// FIPS 180-4 s. 4.2.1 (4.14): the constants K_t, one for each twenty rounds.
const K_0_19: u32 = 0x5A827999;
const K_20_39: u32 = 0x6ED9EBA1;
const K_40_59: u32 = 0x8F1BBCDC;
const K_60_79: u32 = 0xCA62C1D6;

/// FIPS 180-4 Figure 1 and s. 6.1: SHA-1 is defined for a message of l bits where 0 <= l < 2^64,
/// so the longest whole-byte message it covers is 2^61 - 1 bytes.
const MAX_MESSAGE_BYTES: u64 = (1 << 61) - 1;

/// FIPS 180-4 s. 5.3.1: the initial hash value H(0).
const SHA1_H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// FIPS 180-4 s. 4.1.1 (4.1), 0 <= t <= 19: Ch(x, y, z) = (x AND y) XOR (NOT x AND z).
/// Mutants note: the two masks are disjoint, so `^` and `|` give identical results here; a
/// surviving `^`/`|` swap in this function is an equivalent mutant, not a missing test.
#[inline]
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// FIPS 180-4 s. 4.1.1 (4.1), 20 <= t <= 39 and 60 <= t <= 79: Parity(x, y, z) = x XOR y XOR z.
#[inline]
const fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// FIPS 180-4 s. 4.1.1 (4.1), 40 <= t <= 59: Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z).
/// Written in the equivalent form (x AND y) OR (z AND (x XOR y)), which saves an operation.
/// Mutants note: the two masks are disjoint, so `^` and `|` give identical results here, and
/// (x AND y) OR (z AND (x OR y)) is the majority too; a surviving `^`/`|` swap in this function
/// is an equivalent mutant, not a missing test.
#[inline]
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x ^ y))
}

/// FIPS 180-4 s. 6.1.2: each message block M(1), ..., M(N) is processed in order. Never inlined,
/// so that its frame lies below its caller's, where [`SHA1::compress`]'s wipe reaches it.
#[inline(never)]
fn compress_blocks(h: &mut [u32; 5], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(h, block);
    }
}

/// How much stack [`wipe_stack_below`] overwrites after [`compress_blocks`], in 64-bit words:
/// more than that frame, which calls nothing, uses (288 bytes with its return address in the
/// x86-64 release build), with room for a compiler that lays it out less tightly. An unoptimised
/// build's frame is not covered.
const COMPRESS_WIPED_STACK_WORDS: usize = 64;

/// FIPS 180-4 s. 6.1.2, one iteration of the outer loop: absorbs a single 512-bit message block
/// into the hash value `s` (H(i-1) in, H(i) out).
fn compress_block(s: &mut [u32; 5], block: &[u8; 64]) {
    // FIPS 180-4 s. 6.1.2 step 1: prepare the message schedule {W_t}.
    let mut w = [0u32; 80];
    // W_t = M_t(i) for 0 <= t <= 15 (s. 5.2.1: sixteen big-endian 32-bit words).
    let (words, _remainder) = block.as_chunks::<4>();
    for (w_t, word) in w.iter_mut().zip(words) {
        *w_t = u32::from_be_bytes(*word);
    }
    // W_t = ROTL1(W_t-3 XOR W_t-8 XOR W_t-14 XOR W_t-16) for 16 <= t <= 79.
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }

    // FIPS 180-4 s. 6.1.2 step 2: initialize the working variables a..e with H(i-1).
    let [mut a, mut b, mut c, mut d, mut e] = *s;

    // FIPS 180-4 s. 6.1.2 step 3: for t = 0 to 79. The branch is on the round number, which is
    // public.
    for (t, w_t) in w.iter().enumerate() {
        // f_t and K_t (s. 4.1.1 and s. 4.2.1).
        let (f_t, k_t) = match t {
            0..=19 => (ch(b, c, d), K_0_19),
            20..=39 => (parity(b, c, d), K_20_39),
            40..=59 => (maj(b, c, d), K_40_59),
            _ => (parity(b, c, d), K_60_79),
        };
        // T = ROTL5(a) + f_t(b, c, d) + e + K_t + W_t
        let t_word =
            a.rotate_left(5).wrapping_add(f_t).wrapping_add(e).wrapping_add(k_t).wrapping_add(*w_t);
        // e = d; d = c; c = ROTL30(b); b = a; a = T
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t_word;
    }

    // FIPS 180-4 s. 6.1.2 step 4: H_j(i) = (working variable j) + H_j(i-1).
    s[0] = s[0].wrapping_add(a);
    s[1] = s[1].wrapping_add(b);
    s[2] = s[2].wrapping_add(c);
    s[3] = s[3].wrapping_add(d);
    s[4] = s[4].wrapping_add(e);
}

/// SHA-1 (FIPS 180-4 s. 6.1). See the module docs before using it for anything new.
#[derive(Clone)]
pub struct SHA1 {
    h: Secret<[u32; 5]>,
    byte_count: u64,
    x_buf: Secret<[u8; 64]>,
    x_buf_off: usize,
}

impl SHA1 {
    /// Creates a new SHA1 instance, ready for use.
    pub fn new() -> Self {
        let mut h = Secret::<[u32; 5]>::new();
        // FIPS 180-4 s. 6.1.1 step 1: set the initial hash value H(0) (s. 5.3.1).
        h.copy_from_slice(&SHA1_H0);
        Self { h, byte_count: 0, x_buf: Secret::new(), x_buf_off: 0 }
    }

    /// Compresses `blocks` in a frame of its own and overwrites the stack that frame used: the
    /// message schedule and the working variables spilled there are the message and the
    /// chaining value of whatever is hashed.
    ///
    /// Takes the chaining value rather than `&mut self` so callers can pass `self.x_buf` as the
    /// block without a conflicting borrow.
    fn compress(h: &mut [u32; 5], blocks: &[[u8; 64]]) {
        // Only to save the wipe; mutants note: deleting it is an equivalent mutant.
        if blocks.is_empty() {
            return;
        }
        compress_blocks(h, blocks);
        wipe_stack_below::<COMPRESS_WIPED_STACK_WORDS>();
    }

    /// Pads and compresses the final block(s) as per FIPS 180-4 s. 5.1.1, then writes the digest.
    ///
    /// The `num_partial_bits` (0..=7, validated by the caller) trailing message bits are the most
    /// significant bits of `partial_byte`, leading bit first: the ASN.1 BIT STRING order of
    /// X.690 s. 8.6.2.1, which is also how FIPS 180-4 s. 3.1 numbers the bits of a message byte. So
    /// they are used in place, the low `8 - num_partial_bits` bits are ignored, and the mandatory
    /// "1" padding bit follows the message bits immediately in the same byte.
    ///
    /// Returns the number of bytes written (`min(output.len(), OUTPUT_LEN)`); a shorter output buffer
    /// truncates the digest, a longer one is zero-filled past the digest.
    fn do_final_internal(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> usize {
        debug_assert!(num_partial_bits <= 7);
        output.fill(0);

        let n = *min(&output.len(), &OUTPUT_LEN);

        // FIPS 180-4 s. 5.1.1: append the bit "1" to the end of the message. The message bits are the
        // top num_partial_bits bits of partial_byte, so the final message byte is [those bits] [1] [0...];
        // with no partial bits this is the familiar 0x80. The mask is built in u16 so that the 8-bit
        // shift for num_partial_bits == 0 cannot overflow (0xFF00 >> 0 truncates to 0x00).
        let mask = (0xFF00u16 >> num_partial_bits) as u8;
        // Mutants note: the masked message bits and the padding bit occupy disjoint bit positions, so
        // `|` and `^` give identical results here; a surviving `|`/`^` swap is an equivalent mutant.
        let pad_byte = (partial_byte & mask) | (0x80u8 >> num_partial_bits);

        self.x_buf[self.x_buf_off] = pad_byte;
        self.x_buf_off += 1;

        // FIPS 180-4 s. 5.1.1: if fewer than 64 bits remain for l, the k zero bits run into a second block.
        if self.x_buf_off > 56 {
            self.x_buf[self.x_buf_off..].fill(0x00);
            Self::compress(&mut self.h, slice::from_ref(&self.x_buf));
            self.x_buf_off = 0;
        }

        // FIPS 180-4 s. 5.1.1: k zero bits so that l + 1 + k = 448 mod 512, then the 64-bit big-endian
        // message length l in bits.
        self.x_buf[self.x_buf_off..56].fill(0x00);
        // byte_count is a byte counter, so l = (byte_count << 3) | num_partial_bits (the low three bits
        // of byte_count << 3 are zero).
        // Mutants note: the low three bits of byte_count << 3 are zero, so `|` and `^` give identical
        // results here; a surviving `|`/`^` swap is an equivalent mutant.
        let bit_len: u64 = (self.byte_count << 3) | (num_partial_bits as u64);
        self.x_buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.h, slice::from_ref(&self.x_buf));

        // FIPS 180-4 s. 6.1.2: the digest is H_0(N) || ... || H_4(N) (big-endian words), truncated
        // to the caller's buffer if that is shorter.
        let h = &self.h;
        for i in 0..(n / 4) {
            output[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        if !n.is_multiple_of(4) {
            output[((n / 4) * 4)..((n / 4) * 4) + (n % 4)]
                .copy_from_slice(&h[n / 4].to_be_bytes()[0..(n % 4)]);
        }

        n
    }
}

impl Default for SHA1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for SHA1 {
    /// As per FIPS 180-4 Figure 1
    fn block_bitlen(&self) -> usize {
        512
    }

    fn output_len(&self) -> usize {
        OUTPUT_LEN
    }

    fn do_update(&mut self, block: &[u8]) {
        let len = block.len();

        // FIPS 180-4 s. 5.1.1: do_final_internal encodes l in a 64-bit field as `byte_count << 3`,
        // and a left shift discards rather than panics, so past MAX_MESSAGE_BYTES the digest would
        // silently be that of a message 2^64 bits shorter. do_update returns (), hence debug-only.
        debug_assert!(
            self.byte_count.checked_add(len as u64).is_some_and(|total| total <= MAX_MESSAGE_BYTES),
            "message exceeds the FIPS 180-4 limit of {MAX_MESSAGE_BYTES} bytes for SHA-1"
        );
        self.byte_count += len as u64;

        let available = 64 - self.x_buf_off;

        if len < available {
            self.x_buf[self.x_buf_off..self.x_buf_off + len].copy_from_slice(block);
            self.x_buf_off += len;
            return;
        }

        let mut block = block;
        if self.x_buf_off != 0 {
            self.x_buf[self.x_buf_off..].copy_from_slice(&block[..available]);
            block = &block[available..];

            Self::compress(&mut self.h, slice::from_ref(&self.x_buf));
            // Not left where a clone or a suspended state would carry it. Once per call at
            // most: whole blocks after this one are compressed from `block`.
            self.x_buf.fill(0);
        }

        // FIPS 180-4 s. 5.2.1: the message is parsed into 512-bit blocks; a partial trailing block waits in x_buf.
        let (chunks, remainder) = block.as_chunks::<64>();

        Self::compress(&mut self.h, chunks);

        let remaining = remainder.len();
        self.x_buf[..remaining].copy_from_slice(remainder);
        self.x_buf_off = remaining;
    }

    fn finish_into(&mut self, _token: &FinishToken, output: &mut [u8]) -> usize {
        // A whole-byte message is the zero-partial-bits case of the general padding.
        self.do_final_internal(0, 0, output)
    }

    /// FIPS 180-4 s. 5.1: bit-oriented messages. The `num_partial_bits` most significant bits of
    /// `partial_byte` (ASN.1 BIT STRING order, leading bit first) are appended to the message before
    /// padding; the low bits are ignored. `num_partial_bits == 0` behaves exactly like
    /// [`Hash::do_final_out`].
    fn finish_partial_bits_into(
        &mut self,
        _token: &FinishToken,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        // Cleared before the check, so that a refused call leaves nothing stale in the buffer.
        output.fill(0);
        if num_partial_bits > 7 {
            return Err(HashError::InvalidLength("num_partial_bits must be in the range [0,7]"));
        }
        Ok(self.do_final_internal(partial_byte, num_partial_bits, output))
    }
}

/// Length in bytes of the serialized state of SHA1.
pub const SUSPENDED_SHA1_STATE_LEN: usize = 96;

impl Suspendable<SUSPENDED_SHA1_STATE_LEN> for SHA1 {
    fn suspend(self) -> [u8; SUSPENDED_SHA1_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_SHA1_STATE_LEN];

        // insert the version tag
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_SHA1_STATE_LEN - 3 = 93 bytes.
        let out: &mut [u8; 93] = add_lib_ver(&mut out_to_return).try_into().unwrap();

        // h: [u32; 5], 4 * 5 = 20
        for i in 0..5 {
            out[i * 4..(i * 4) + 4].copy_from_slice(&self.h[i].to_le_bytes());
        }

        // byte_count: u64
        out[20..28].copy_from_slice(&self.byte_count.to_le_bytes());

        // x_buf: [u8; 64]
        out[28..92].copy_from_slice(&*self.x_buf);

        // x_buf_off: usize; it is never larger than 63
        debug_assert!(self.x_buf_off < 64);
        out[92] = self.x_buf_off as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA1_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // check the version tag
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_SHA1_STATE_LEN - 3 = 93 bytes.
        let input: &[u8; 93] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        // h: [u32; 5]
        let mut h = Secret::<[u32; 5]>::new();
        for i in 0..5 {
            h[i] = u32::from_le_bytes(input[i * 4..(i * 4) + 4].try_into().unwrap());
        }

        // byte_count: u64
        let byte_count: u64 = u64::from_le_bytes(input[20..28].try_into().unwrap());

        // x_buf: [u8; 64]
        let mut x_buf = Secret::<[u8; 64]>::new();
        x_buf.copy_from_slice(&input[28..92]);

        // x_buf_off: usize
        let x_buf_off: usize = input[92] as usize;
        if x_buf_off >= 64 {
            return Err(SuspendableError::InvalidData);
        }
        // do_update keeps byte_count congruent to x_buf_off modulo the block length, so a state in
        // which they disagree describes no message and must not resume.
        if byte_count % 64 != x_buf_off as u64 {
            return Err(SuspendableError::InvalidData);
        }
        // FIPS 180-4 s. 5.1.1 encodes the length in a 64-bit block, so a longer message cannot be
        // finished correctly.
        if byte_count > MAX_MESSAGE_BYTES {
            return Err(SuspendableError::InvalidData);
        }

        Ok(SHA1 { h, byte_count, x_buf, x_buf_off })
    }
}

// The one-shot form: `Default` is the function itself.
impl HashOneShot for SHA1 {}
