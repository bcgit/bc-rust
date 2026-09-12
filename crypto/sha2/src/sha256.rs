use crate::SHA256InitValue;
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, Suspendable};
use bouncycastle_utils::{min, secret::Secret};
use core::slice;

/// FIPS 180-4 s. 4.2.2: the sixty-four 32-bit constants K0..K63 shared by SHA-224 and SHA-256.
const SHA256_K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

/// FIPS 180-4 s. 5.3.2: the initial hash value H(0) for SHA-224.
pub(crate) const SHA224_H0: [u32; 8] = [
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
];

/// FIPS 180-4 s. 5.3.3: the initial hash value H(0) for SHA-256.
pub(crate) const SHA256_H0: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// FIPS 180-4 s. 4.1.2 (4.2) Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
/// Mutants note: the two masks are disjoint, so `^` and `|` give identical results here; a
/// surviving `^`/`|` swap in this function is an equivalent mutant, not a missing test.
#[inline]
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// FIPS 180-4 s. 4.1.2 (4.3) Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z).
/// Written in the equivalent form (x AND y) OR (z AND (x XOR y)), which saves an operation.
/// Mutants note: the two masks are disjoint, so `^` and `|` give identical results here; a
/// surviving `^`/`|` swap in this function is an equivalent mutant, not a missing test.
#[inline]
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x ^ y))
}

/// FIPS 180-4 s. 4.1.2 (4.4) Sigma0(x) = ROTR2(x) XOR ROTR13(x) XOR ROTR22(x)
#[inline]
const fn sum0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// FIPS 180-4 s. 4.1.2 (4.5) Sigma1(x) = ROTR6(x) XOR ROTR11(x) XOR ROTR25(x)
#[inline]
const fn sum1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// FIPS 180-4 s. 4.1.2 (4.6) sigma0(x) = ROTR7(x) XOR ROTR18(x) XOR SHR3(x)
#[inline]
const fn theta0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// FIPS 180-4 s. 4.1.2 (4.7) sigma1(x) = ROTR17(x) XOR ROTR19(x) XOR SHR10(x)
#[inline]
const fn theta1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// FIPS 180-4 s. 6.2.2, one iteration of the outer loop: absorbs a single 512-bit message block
/// into the hash value `s` (H(i-1) in, H(i) out).
///
/// Written as a `const fn` (hence `while` rather than `for` loops) to match the SHA-512 side, so the
/// two compression functions can be read side by side against s. 6.2.2 and s. 6.4.2.
#[inline]
const fn compress_block(s: &mut [u32; 8], block: &[u8; 64]) {
    // FIPS 180-4 s. 6.2.2 step 1: prepare the message schedule {W_t}.
    let mut x = [0u32; 64];
    // FIPS 180-4 s. 6.2.2 step 1: W_t = M_t(i) for 0 <= t <= 15 (s. 5.2.1: sixteen big-endian 32-bit words).
    let (words, _remainder) = block.as_chunks::<4>();
    let mut i = 0;
    while i < 16 {
        x[i] = u32::from_be_bytes(words[i]);
        i += 1;
    }
    // FIPS 180-4 s. 6.2.2 step 1: W_t = sigma1(W_t-2) + W_t-7 + sigma0(W_t-15) + W_t-16 for 16 <= t <= 63.
    while i < 64 {
        x[i] = theta1(x[i - 2])
            .wrapping_add(x[i - 7])
            .wrapping_add(theta0(x[i - 15]))
            .wrapping_add(x[i - 16]);
        i += 1;
    }

    // FIPS 180-4 s. 6.2.2 step 2: initialize the working variables a..h with H(i-1).
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;

    // FIPS 180-4 s. 6.2.2 step 3: for t = 0 to 63, one round. The spec rotates the working variables
    // (h = g, g = f, ...); here the rotation is done by renaming the variables passed to the macro
    // instead, eight rounds at a time, which is equivalent and avoids the moves. The spec's T1 lands
    // in the "$h" position, "$d" becomes d + T1, and T1 + T2 is then computed in place.
    macro_rules! sha256_round {
        ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident,$t:ident) => {
            // FIPS 180-4 s. 6.2.2 step 3: T1 = h + Sigma1(e) + Ch(e, f, g) + K_t + W_t
            $h = $h
                .wrapping_add(sum1($e))
                .wrapping_add(ch($e, $f, $g))
                .wrapping_add(SHA256_K[$t])
                .wrapping_add(x[$t]);
            // FIPS 180-4 s. 6.2.2 step 3: e = d + T1
            $d = $d.wrapping_add($h);
            // FIPS 180-4 s. 6.2.2 step 3: a = T1 + T2, where T2 = Sigma0(a) + Maj(a, b, c)
            $h = $h.wrapping_add(sum0($a)).wrapping_add(maj($a, $b, $c));
            $t += 1;
        };
    }

    let mut t: usize = 0;
    while t < 64 {
        sha256_round!(a, b, c, d, e, f, g, h, t);
        sha256_round!(h, a, b, c, d, e, f, g, t);
        sha256_round!(g, h, a, b, c, d, e, f, t);
        sha256_round!(f, g, h, a, b, c, d, e, t);
        sha256_round!(e, f, g, h, a, b, c, d, t);
        sha256_round!(d, e, f, g, h, a, b, c, t);
        sha256_round!(c, d, e, f, g, h, a, b, t);
        sha256_round!(b, c, d, e, f, g, h, a, t);
    }

    // FIPS 180-4 s. 6.2.2 step 4: H_j(i) = (working variable j) + H_j(i-1).
    s[0] = s[0].wrapping_add(a);
    s[1] = s[1].wrapping_add(b);
    s[2] = s[2].wrapping_add(c);
    s[3] = s[3].wrapping_add(d);
    s[4] = s[4].wrapping_add(e);
    s[5] = s[5].wrapping_add(f);
    s[6] = s[6].wrapping_add(g);
    s[7] = s[7].wrapping_add(h);
}

#[derive(Clone)]
pub(crate) struct Sha256State<PARAMS: SHA256InitValue> {
    _params: core::marker::PhantomData<PARAMS>,
    h: Secret<[u32; 8]>,
}

impl<PARAMS: SHA256InitValue> Sha256State<PARAMS> {
    pub(crate) fn new() -> Self {
        let mut h = Secret::<[u32; 8]>::new();
        // FIPS 180-4 s. 6.2.1 step 1: set the initial hash value H(0) (s. 5.3.3, or s. 5.3.2 for SHA-224).
        h.copy_from_slice(&PARAMS::H0);
        Self { _params: core::marker::PhantomData, h }
    }

    fn compress(&mut self, blocks: &[[u8; 64]]) {
        // FIPS 180-4 s. 6.2.2: each message block M(1), ..., M(N) is processed in order.
        for block in blocks {
            compress_block(&mut self.h, block);
        }
    }
}

/// Internal struct for SHA256.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// provided and NIST-approved parameters.
#[derive(Clone)]
pub struct SHA256Internal<PARAMS: SHA256InitValue> {
    _params: core::marker::PhantomData<PARAMS>,
    state: Sha256State<PARAMS>,
    byte_count: u64,
    x_buf: Secret<[u8; 64]>,
    x_buf_off: usize,
}

impl<PARAMS: SHA256InitValue> SHA256Internal<PARAMS> {
    /// Creates a new SHA256 instance, ready for use.
    pub fn new() -> Self {
        Self {
            _params: core::marker::PhantomData,
            state: Sha256State::<PARAMS>::new(),
            byte_count: 0,
            x_buf: Secret::new(),
            x_buf_off: 0,
        }
    }
}

impl<PARAMS: SHA256InitValue> SHA256Internal<PARAMS> {
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
        mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> usize {
        debug_assert!(num_partial_bits <= 7);
        output.fill(0);

        let n = *min(&output.len(), &PARAMS::OUTPUT_LEN);

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
            self.state.compress(slice::from_ref(&self.x_buf));
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
        self.state.compress(slice::from_ref(&self.x_buf));

        // FIPS 180-4 s. 6.2.2: the digest is H_0(N) || ... || H_7(N) (big-endian words), truncated to the
        // left-most OUTPUT_LEN bytes (s. 6.3 exception 2 for SHA-224), and further to the caller's
        // buffer if that is shorter.
        let h = &self.state.h;
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

impl<PARAMS: SHA256InitValue> Default for SHA256Internal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA256InitValue> Algorithm for SHA256Internal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHA256InitValue> Hash for SHA256Internal<PARAMS> {
    /// As per FIPS 180-4 Figure 1
    fn block_bitlen(&self) -> usize {
        512
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; PARAMS::OUTPUT_LEN];
        self.hash_out(data, &mut output);
        output
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, block: &[u8]) {
        let len = block.len();

        // byte_count is a u64 byte counter, so this supports messages up to 2^64 bytes (2^67 bits).
        // Exceeding it is infeasible in practice; in debug builds the add panics, in release it wraps.
        self.byte_count += len as u64;

        let available = 64 - self.x_buf_off;

        // TODO: mutants thinks you can replace < with <= without changing behaviour
        if len < available {
            self.x_buf[self.x_buf_off..self.x_buf_off + len].copy_from_slice(block);
            self.x_buf_off += len;
            return;
        }

        let mut block = block;
        if self.x_buf_off != 0 {
            self.x_buf[self.x_buf_off..].copy_from_slice(&block[..available]);
            block = &block[available..];

            self.state.compress(slice::from_ref(&self.x_buf));
        }

        // FIPS 180-4 s. 5.2.1: the message is parsed into 512-bit blocks; a partial trailing block waits in x_buf.
        let (chunks, remainder) = block.as_chunks::<64>();

        self.state.compress(chunks);

        let remaining = remainder.len();
        self.x_buf[..remaining].copy_from_slice(remainder);
        self.x_buf_off = remaining;
    }

    fn do_final(self) -> Vec<u8> {
        let mut output = vec![0u8; PARAMS::OUTPUT_LEN];
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
        let mut output = vec![0u8; PARAMS::OUTPUT_LEN];
        self.do_final_partial_bits_out(partial_byte, num_partial_bits, &mut output)?;
        Ok(output)
    }

    /// FIPS 180-4 s. 5.1: bit-oriented messages. The `num_partial_bits` most significant bits of
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
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/// Length in bytes of the serialized state of SHA224 and SHA256.
pub const SUSPENDED_SHA256_STATE_LEN: usize = 108;

impl<PARAMS: SHA256InitValue> Suspendable<SUSPENDED_SHA256_STATE_LEN> for SHA256Internal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA256_STATE_LEN] {
        debug_assert_eq!(SUSPENDED_SHA256_STATE_LEN, 108);

        let mut out_to_return = [0u8; SUSPENDED_SHA256_STATE_LEN];

        // insert the version tag
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_SHA256_STATE_LEN - 3 = 105 bytes.
        let out: &mut [u8; 105] = add_lib_ver(&mut out_to_return).try_into().unwrap();

        // state.h: [u32; 8]
        // 4 * 8 = 32
        for i in 0..8 {
            out[i * 4..(i * 4) + 4].copy_from_slice(&self.state.h[i].to_le_bytes());
        }

        // byte_count: u64
        out[32..40].copy_from_slice(&self.byte_count.to_le_bytes());

        // x_buf: [u8; 64]
        out[40..104].copy_from_slice(&*self.x_buf);

        // x_buf_off: usize
        // in general, a usize should be serialized into a u64, but in this case, it can't ever be larger than 64
        debug_assert!(self.x_buf_off < 64);
        out[104] = self.x_buf_off as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA256_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        debug_assert_eq!(SUSPENDED_SHA256_STATE_LEN, 108);

        // check the version tag
        // At the moment, we have no not_before version to specify.
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_SHA256_STATE_LEN - 3 = 105 bytes.
        let input: &[u8; 105] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        // state.h: [u32; 8]
        // 4 * 8 = 32
        let mut h = Secret::<[u32; 8]>::new();
        for i in 0..8 {
            h[i] = u32::from_le_bytes(input[i * 4..(i * 4) + 4].try_into().unwrap());
        }

        // byte_count: u64
        let byte_count: u64 = u64::from_le_bytes(input[32..40].try_into().unwrap());

        // x_buf: [u8; 64]
        let mut x_buf = Secret::<[u8; 64]>::new();
        x_buf.copy_from_slice(&input[40..104]);

        // x_buf_off: usize
        // in general, a usize should be serialized into a u64, but in this case, it can't ever be larger than 64
        let x_buf_off: usize = input[104] as usize;
        if x_buf_off >= 64 {
            return Err(SuspendableError::InvalidData);
        }

        // Construct the object
        let state = Sha256State { _params: core::marker::PhantomData, h };
        Ok(SHA256Internal {
            _params: core::marker::PhantomData,
            state,
            byte_count,
            x_buf,
            x_buf_off,
        })
    }
}
