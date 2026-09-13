use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Hash, SecurityStrength, Suspendable};
use bouncycastle_utils::{min, secret::Secret};
use core::slice;

/// GB/T 32905-2016 s. 4.1: initial value IV.
const SM3_IV: [u32; 8] = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
];

/// GB/T 32905-2016 s. 5.1: SM3 takes "a message m of length l (where l < 2^64) in bits", so the
/// longest whole-byte message it covers is 2^61 - 1 bytes.
const MAX_MESSAGE_BYTES: u64 = (1 << 61) - 1;

/// GB/T 32905-2016 s. 4.2: constants T_j = 79CC4519 for 0 <= j <= 15, 7A879D8A for 16 <= j <= 63.
/// The round function uses (T_j <<< (j mod 32)), which is precomputed here at compile time.
/// Mutants note: `u32::rotate_left` reduces its argument modulo 32 itself, so replacing `j % 32`
/// with `j + 32` is an equivalent mutant; and `+=` -> `*=` on the loop counter is an infinite loop
/// in `const` evaluation, reported as a build timeout.
const SM3_T: [u32; 64] = {
    let mut t = [0u32; 64];
    let mut j = 0;
    while j < 64 {
        let base: u32 = if j < 16 { 0x79CC4519 } else { 0x7A879D8A };
        t[j] = base.rotate_left((j % 32) as u32);
        j += 1;
    }
    t
};

/// GB/T 32905-2016 s. 4.3: boolean functions FF_j and GG_j for 0 <= j <= 15.
#[inline]
fn ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// GB/T 32905-2016 s. 4.3: FF_j for 16 <= j <= 63 (majority).
/// Mutants note: majority can be written with `|` or `^` between the three terms (FIPS 180-4 writes
/// Maj with XOR), so a surviving `|`/`^` swap in this function is an equivalent mutant.
#[inline]
fn ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

/// GB/T 32905-2016 s. 4.3: GG_j for 16 <= j <= 63 (choice).
/// Mutants note: the two masks are disjoint, so `|` and `^` give identical results here; a
/// surviving `|`/`^` swap in this function is an equivalent mutant.
#[inline]
fn gg1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// GB/T 32905-2016 s. 4.4: permutation P0(X) = X ^ (X <<< 9) ^ (X <<< 17).
#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// GB/T 32905-2016 s. 4.4: permutation P1(X) = X ^ (X <<< 15) ^ (X <<< 23).
#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// The SM3 cryptographic hash function (GB/T 32905-2016).
///
/// See the [crate-level documentation](crate) for usage.
#[derive(Clone)]
pub struct SM3 {
    /// Chaining value V^(i), 8 big-endian words.
    v: Secret<[u32; 8]>,
    /// Total number of message bytes absorbed so far. Supports messages up to 2^64 bytes.
    byte_count: u64,
    /// Buffered input that has not yet formed a whole block.
    x_buf: Secret<[u8; 64]>,
    /// Number of valid bytes in `x_buf` (always < 64).
    x_buf_off: usize,
}

impl SM3 {
    /// Creates a new SM3 instance, ready for use.
    pub fn new() -> Self {
        let mut v = Secret::<[u32; 8]>::new();
        v.copy_from_slice(&SM3_IV);
        Self { v, byte_count: 0, x_buf: Secret::new(), x_buf_off: 0 }
    }

    /// GB/T 32905-2016 s. 5.3: compression function V^(i+1) = CF(V^(i), B^(i)) for each block.
    ///
    /// Takes the chaining value rather than `&mut self` so callers can pass `self.x_buf` as the
    /// block without a conflicting borrow.
    fn compress(v: &mut [u32; 8], blocks: &[[u8; 64]]) {
        // s. 5.3.2 message expansion: W_0..W_67. W'_j = W_j ^ W_{j+4} is computed on the fly.
        let mut w = [0u32; 68];

        for block in blocks {
            let (chunks, _remainder) = block.as_chunks::<4>();
            for (wj, bytes) in w[..16].iter_mut().zip(chunks) {
                *wj = u32::from_be_bytes(*bytes);
            }
            for j in 16..68 {
                // W_j = P1(W_{j-16} ^ W_{j-9} ^ (W_{j-3} <<< 15)) ^ (W_{j-13} <<< 7) ^ W_{j-6}
                w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                    ^ w[j - 13].rotate_left(7)
                    ^ w[j - 6];
            }

            // s. 5.3.3 compression: ABCDEFGH <- V^(i)
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *v;

            // One round of s. 5.3.3. `$ff` / `$gg` select the boolean functions for the round range.
            macro_rules! sm3_round {
                ($j:expr, $ff:ident, $gg:ident) => {
                    // SS1 = ((A <<< 12) + E + (T_j <<< (j mod 32))) <<< 7
                    let a12 = a.rotate_left(12);
                    let ss1 = a12.wrapping_add(e).wrapping_add(SM3_T[$j]).rotate_left(7);
                    // SS2 = SS1 ^ (A <<< 12)
                    let ss2 = ss1 ^ a12;
                    // TT1 = FF_j(A,B,C) + D + SS2 + W'_j     where W'_j = W_j ^ W_{j+4}
                    let tt1 = $ff(a, b, c)
                        .wrapping_add(d)
                        .wrapping_add(ss2)
                        .wrapping_add(w[$j] ^ w[$j + 4]);
                    // TT2 = GG_j(E,F,G) + H + SS1 + W_j
                    let tt2 = $gg(e, f, g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[$j]);
                    // D = C; C = B <<< 9; B = A; A = TT1; H = G; G = F <<< 19; F = E; E = P0(TT2)
                    d = c;
                    c = b.rotate_left(9);
                    b = a;
                    a = tt1;
                    h = g;
                    g = f.rotate_left(19);
                    f = e;
                    e = p0(tt2);
                };
            }

            // Rounds 0..=15 use FF_0 = GG_0 = XOR (ff0 serves both).
            for j in 0..16 {
                sm3_round!(j, ff0, ff0);
            }
            // Rounds 16..=63 use the majority / choice functions.
            for j in 16..64 {
                sm3_round!(j, ff1, gg1);
            }

            // V^(i+1) = ABCDEFGH ^ V^(i)
            v[0] ^= a;
            v[1] ^= b;
            v[2] ^= c;
            v[3] ^= d;
            v[4] ^= e;
            v[5] ^= f;
            v[6] ^= g;
            v[7] ^= h;
        }
    }

    /// Pads and compresses the final block(s) as per GB/T 32905-2016 s. 5.2, then writes the digest.
    ///
    /// The `num_partial_bits` (0..=7, validated by the caller) trailing message bits are the most
    /// significant bits of `partial_byte`, leading bit first: the ASN.1 BIT STRING order of
    /// X.690 s. 8.6.2.1, which is also how GB/T 32905-2016 (like FIPS 180-4) numbers the bits of a
    /// message byte. So they are used in place, the low `8 - num_partial_bits` bits are ignored, and
    /// the mandatory "1" padding bit follows the message bits immediately in the same byte.
    ///
    /// Returns the number of bytes written (`min(output.len(), 32)`); a shorter output buffer
    /// truncates the digest, a longer one is zero-filled past the digest.
    fn do_final_internal(
        mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> usize {
        debug_assert!(num_partial_bits <= 7);
        output.fill(0);

        let n = *min(&output.len(), &32);

        // s. 5.2: final message byte = [the top num_partial_bits bits of partial_byte] [1] [0...]. With
        // no partial bits this is 0x80. The mask is built in u16 so that the 8-bit shift for
        // num_partial_bits == 0 cannot overflow (0xFF00 >> 0 truncates to 0x00).
        let mask = (0xFF00u16 >> num_partial_bits) as u8;
        // Mutants note: the masked message bits and the padding bit occupy disjoint bit positions, so
        // `|` and `^` give identical results here; a surviving `|`/`^` swap is an equivalent mutant.
        let pad_byte = (partial_byte & mask) | (0x80u8 >> num_partial_bits);

        self.x_buf[self.x_buf_off] = pad_byte;
        self.x_buf_off += 1;

        // ... then k zero bits so that l + 1 + k = 448 mod 512. If the 64-bit length field no longer
        // fits in this block, zero-fill and compress, then start a fresh block.
        if self.x_buf_off > 56 {
            self.x_buf[self.x_buf_off..].fill(0x00);
            Self::compress(&mut self.v, slice::from_ref(&self.x_buf));
            self.x_buf_off = 0;
        }
        self.x_buf[self.x_buf_off..56].fill(0x00);

        // ... then the 64-bit big-endian message length l in bits. byte_count is a byte counter, so
        // l = (byte_count << 3) | num_partial_bits (the low three bits of byte_count << 3 are zero).
        // Mutants note: the low three bits of byte_count << 3 are zero, so `|` and `^` give identical
        // results here; a surviving `|`/`^` swap is an equivalent mutant.
        let bit_len: u64 = (self.byte_count << 3) | (num_partial_bits as u64);
        self.x_buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.v, slice::from_ref(&self.x_buf));

        // s. 5.4: the digest is V^(n) as 8 big-endian words.
        let v = &self.v;
        for i in 0..(n / 4) {
            output[i * 4..i * 4 + 4].copy_from_slice(&v[i].to_be_bytes());
        }
        if !n.is_multiple_of(4) {
            output[((n / 4) * 4)..((n / 4) * 4) + (n % 4)]
                .copy_from_slice(&v[n / 4].to_be_bytes()[0..(n % 4)]);
        }

        n
    }
}

impl Default for SM3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for SM3 {
    /// GB/T 32905-2016 s. 5.2: 512-bit blocks.
    fn block_bitlen(&self) -> usize {
        512
    }

    fn output_len(&self) -> usize {
        32
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; 32];
        self.hash_out(data, &mut output);
        output
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, block: &[u8]) {
        let len = block.len();

        // GB/T 32905-2016 s. 5.2: do_final_internal encodes l in a 64-bit field as
        // `byte_count << 3`, and a left shift discards rather than panics, so past
        // MAX_MESSAGE_BYTES the digest would silently be that of a message 2^64 bits shorter.
        debug_assert!(
            self.byte_count.checked_add(len as u64).is_some_and(|total| total <= MAX_MESSAGE_BYTES),
            "message exceeds the SM3 limit of {MAX_MESSAGE_BYTES} bytes"
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
            Self::compress(&mut self.v, slice::from_ref(&self.x_buf));
        }

        let (chunks, remainder) = block.as_chunks::<64>();
        Self::compress(&mut self.v, chunks);

        let remaining = remainder.len();
        self.x_buf[..remaining].copy_from_slice(remainder);
        self.x_buf_off = remaining;
    }

    fn do_final(self) -> Vec<u8> {
        let mut output = vec![0u8; 32];
        self.do_final_out(&mut output);
        output
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        // A whole-byte message is the zero-partial-bits case of the general padding.
        self.do_final_internal(0, 0, output)
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let mut output = vec![0u8; 32];
        self.do_final_partial_bits_out(partial_byte, num_partial_bits, &mut output)?;
        Ok(output)
    }

    /// GB/T 32905-2016 s. 5.2: bit-oriented messages. The `num_partial_bits` most significant bits of
    /// `partial_byte` (ASN.1 BIT STRING order, leading bit first) are appended to the message before
    /// padding; the low bits are ignored. `num_partial_bits == 0` behaves exactly like
    /// [`Hash::do_final_out`].
    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        if num_partial_bits > 7 {
            return Err(HashError::InvalidLength("num_partial_bits must be in the range [0,7]"));
        }
        Ok(self.do_final_internal(partial_byte, num_partial_bits, output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::_128bit
    }
}

/// Length in bytes of the serialized state of SM3.
///
/// Layout (after the 3-byte library version header; all integers little-endian):
///   [0  .. 32)   v           [u32; 8]
///   [32 .. 40)   byte_count  u64
///   [40 .. 104)  x_buf       [u8; 64]
///   [104 .. 105) x_buf_off   u8 (always < 64)
pub const SUSPENDED_SM3_STATE_LEN: usize = 3 + 105;

impl Suspendable<SUSPENDED_SM3_STATE_LEN> for SM3 {
    fn suspend(self) -> [u8; SUSPENDED_SM3_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_SM3_STATE_LEN];

        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_SM3_STATE_LEN - 3 = 105 bytes.
        let out: &mut [u8; 105] = add_lib_ver(&mut out_to_return).try_into().unwrap();

        for i in 0..8 {
            out[i * 4..(i * 4) + 4].copy_from_slice(&self.v[i].to_le_bytes());
        }
        out[32..40].copy_from_slice(&self.byte_count.to_le_bytes());
        out[40..104].copy_from_slice(&*self.x_buf);
        debug_assert!(self.x_buf_off < 64);
        out[104] = self.x_buf_off as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SM3_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // check the version tag. At the moment, we have no not_before version to specify.
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_SM3_STATE_LEN - 3 = 105 bytes.
        let input: &[u8; 105] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        let mut v = Secret::<[u32; 8]>::new();
        for i in 0..8 {
            // infallible: a 4-byte slice into a [u8; 4]
            v[i] = u32::from_le_bytes(input[i * 4..(i * 4) + 4].try_into().unwrap());
        }
        // infallible: an 8-byte slice into a [u8; 8]
        let byte_count = u64::from_le_bytes(input[32..40].try_into().unwrap());

        let mut x_buf = Secret::<[u8; 64]>::new();
        x_buf.copy_from_slice(&input[40..104]);

        let x_buf_off = input[104] as usize;
        if x_buf_off >= 64 {
            return Err(SuspendableError::InvalidData);
        }

        Ok(SM3 { v, byte_count, x_buf, x_buf_off })
    }
}
