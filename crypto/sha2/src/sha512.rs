use crate::Sha512Family;
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, Suspendable};
use bouncycastle_utils::{min, secret::Secret};
use core::slice;

/// FIPS 180-4 s. 4.2.3: the eighty 64-bit constants K0..K79 shared by SHA-384, SHA-512,
/// SHA-512/224 and SHA-512/256.
const SHA512_K: [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

/// FIPS 180-4 s. 5.3.4: the initial hash value H(0) for SHA-384.
pub(crate) const SHA384_H0: [u64; 8] = [
    0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
    0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
];

/// FIPS 180-4 s. 5.3.5: the initial hash value H(0) for SHA-512.
pub(crate) const SHA512_H0: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

/// FIPS 180-4 s. 5.3.6 "SHA-512/t IV Generation Function": computes the initial hash value H(0)
/// for SHA-512/t.
///
/// Quoting the procedure:
///
/// > Denote H(0)' to be the initial hash value of SHA-512 as specified in Section 5.3.5 above.
/// > Denote H(0)'' to be the initial hash value computed below. H(0)'' is the IV for SHA-512/t.
/// >
/// > For i = 0 to 7 { Hi(0)' = Hi(0)' xor a5a5a5a5a5a5a5a5 (in hex). }
/// >
/// > H(0)'' = SHA-512("SHA-512/t") using H(0)' as the IV, where t is the specific truncation value.
///
/// where, per the same section, "t is any positive integer without a leading zero such that t < 512,
/// and t is not 384", and "SHA-512/t" is the ASCII string with t written in decimal (so for t = 256
/// the message is the 11 bytes `53 48 41 2D 35 31 32 2F 32 35 36`).
///
/// This is a `const fn` so that the IV is computed at compile time; the results for t = 224 and
/// t = 256 are checked at compile time against the words listed in s. 5.3.6.1 and s. 5.3.6.2 (see
/// `lib.rs`). The message is at most 11 bytes, so the SHA-512 computation is always exactly one
/// padded block (s. 5.1.2).
pub(crate) const fn sha512t_h0(t: usize) -> [u64; 8] {
    // FIPS 180-4 s. 5.3.6: "t is any positive integer without a leading zero such that t < 512, and t is not 384".
    assert!(t > 0 && t < 512 && t != 384, "FIPS 180-4 s. 5.3.6: 0 < t < 512 and t != 384");

    // FIPS 180-4 s. 5.3.6: H(0)' = the SHA-512 initial hash value (s. 5.3.5), each word XOR a5a5a5a5a5a5a5a5.
    let mut h = SHA512_H0;
    let mut i = 0;
    while i < 8 {
        h[i] ^= 0xA5A5A5A5A5A5A5A5;
        i += 1;
    }

    // FIPS 180-4 s. 5.3.6: the message is the ASCII string "SHA-512/t" (at most 11 bytes, so one block).
    // It is built directly in its padded form (s. 5.1.2) inside a single 1024-bit block (s. 5.2.2).
    let mut block = [0u8; 128];
    let prefix = b"SHA-512/";
    let mut len = 0;
    while len < prefix.len() {
        block[len] = prefix[len];
        len += 1;
    }
    // FIPS 180-4 s. 5.3.6: t written in decimal "without a leading zero" (t < 512, so at most three digits).
    if t >= 100 {
        block[len] = b'0' + (t / 100) as u8;
        len += 1;
    }
    if t >= 10 {
        block[len] = b'0' + ((t / 10) % 10) as u8;
        len += 1;
    }
    block[len] = b'0' + (t % 10) as u8;
    len += 1;

    // FIPS 180-4 s. 5.1.2: append the bit "1", then k zero bits (the rest of the block is already zero).
    block[len] = 0x80;
    // FIPS 180-4 s. 5.1.2: the final 128 bits are the message length l in bits; l < 2^64 so bytes 112..120 stay 0.
    let bit_len = (len as u64) * 8;
    let bit_len_bytes = bit_len.to_be_bytes();
    let mut i = 0;
    while i < 8 {
        block[120 + i] = bit_len_bytes[i];
        i += 1;
    }

    // FIPS 180-4 s. 5.3.6: H(0)'' = SHA-512("SHA-512/t") using H(0)' as the IV, i.e. one pass of s. 6.4.2.
    compress_block(&mut h, &block);
    h
}

/// FIPS 180-4 s. 4.1.3 (4.8) Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
/// Mutants note: the two masks are disjoint, so `^` and `|` give identical results here; a
/// surviving `^`/`|` swap in this function is an equivalent mutant, not a missing test.
#[inline]
const fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

/// FIPS 180-4 s. 4.1.3 (4.9) Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z).
/// Written in the equivalent form (x AND y) OR (z AND (x XOR y)), which saves an operation.
/// Mutants note: the two masks are disjoint, so `^` and `|` give identical results here; a
/// surviving `^`/`|` swap in this function is an equivalent mutant, not a missing test.
#[inline]
const fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) | (z & (x ^ y))
}

/// FIPS 180-4 s. 4.1.3 (4.10) Sigma0(x) = ROTR28(x) XOR ROTR34(x) XOR ROTR39(x)
#[inline]
const fn sum0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// FIPS 180-4 s. 4.1.3 (4.11) Sigma1(x) = ROTR14(x) XOR ROTR18(x) XOR ROTR41(x)
#[inline]
const fn sum1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// FIPS 180-4 s. 4.1.3 (4.12) sigma0(x) = ROTR1(x) XOR ROTR8(x) XOR SHR7(x)
#[inline]
const fn theta0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

/// FIPS 180-4 s. 4.1.3 (4.13) sigma1(x) = ROTR19(x) XOR ROTR61(x) XOR SHR6(x)
#[inline]
const fn theta1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// FIPS 180-4 s. 6.4.2, one iteration of the outer loop: absorbs a single 1024-bit message block
/// into the hash value `s` (H(i-1) in, H(i) out).
///
/// This is a `const fn` (hence `while` rather than `for` loops) so that [`sha512t_h0`] can run it
/// at compile time. At runtime it is ordinary code, and is the hot path of every SHA-512 variant.
#[inline]
const fn compress_block(s: &mut [u64; 8], block: &[u8; 128]) {
    // FIPS 180-4 s. 6.4.2 step 1: prepare the message schedule {W_t}.
    let mut x = [0u64; 80];
    // FIPS 180-4 s. 6.4.2 step 1: W_t = M_t(i) for 0 <= t <= 15 (s. 5.2.2: sixteen big-endian 64-bit words).
    let (words, _remainder) = block.as_chunks::<8>();
    let mut i = 0;
    while i < 16 {
        x[i] = u64::from_be_bytes(words[i]);
        i += 1;
    }
    // FIPS 180-4 s. 6.4.2 step 1: W_t = sigma1(W_t-2) + W_t-7 + sigma0(W_t-15) + W_t-16 for 16 <= t <= 79.
    while i < 80 {
        x[i] = theta1(x[i - 2])
            .wrapping_add(x[i - 7])
            .wrapping_add(theta0(x[i - 15]))
            .wrapping_add(x[i - 16]);
        i += 1;
    }

    // FIPS 180-4 s. 6.4.2 step 2: initialize the working variables a..h with H(i-1).
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;

    // FIPS 180-4 s. 6.4.2 step 3: for t = 0 to 79, one round. The spec rotates the working variables
    // (h = g, g = f, ...); here the rotation is done by renaming the variables passed to the macro
    // instead, eight rounds at a time, which is equivalent and avoids the moves. The spec's T1 lands
    // in the "$h" position, "$d" becomes d + T1, and T1 + T2 is then computed in place.
    macro_rules! sha512_round {
        ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident,$t:ident) => {
            // FIPS 180-4 s. 6.4.2 step 3: T1 = h + Sigma1(e) + Ch(e, f, g) + K_t + W_t
            $h = $h
                .wrapping_add(sum1($e))
                .wrapping_add(ch($e, $f, $g))
                .wrapping_add(SHA512_K[$t])
                .wrapping_add(x[$t]);
            // FIPS 180-4 s. 6.4.2 step 3: e = d + T1
            $d = $d.wrapping_add($h);
            // FIPS 180-4 s. 6.4.2 step 3: a = T1 + T2, where T2 = Sigma0(a) + Maj(a, b, c)
            $h = $h.wrapping_add(sum0($a)).wrapping_add(maj($a, $b, $c));
            $t += 1;
        };
    }

    let mut t: usize = 0;
    while t < 80 {
        sha512_round!(a, b, c, d, e, f, g, h, t);
        sha512_round!(h, a, b, c, d, e, f, g, t);
        sha512_round!(g, h, a, b, c, d, e, f, t);
        sha512_round!(f, g, h, a, b, c, d, e, t);
        sha512_round!(e, f, g, h, a, b, c, d, t);
        sha512_round!(d, e, f, g, h, a, b, c, t);
        sha512_round!(c, d, e, f, g, h, a, b, t);
        sha512_round!(b, c, d, e, f, g, h, a, t);
    }

    // FIPS 180-4 s. 6.4.2 step 4: H_j(i) = (working variable j) + H_j(i-1).
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
pub(crate) struct Sha512State<PARAMS: Sha512Family> {
    _params: core::marker::PhantomData<PARAMS>,
    h: Secret<[u64; 8]>,
}

impl<PARAMS: Sha512Family> Sha512State<PARAMS> {
    pub(crate) fn new() -> Self {
        let mut h = Secret::<[u64; 8]>::new();
        // FIPS 180-4 s. 6.4.1 step 1: set the initial hash value H(0) (s. 5.3.4 / 5.3.5 / 5.3.6 per variant).
        h.copy_from_slice(&PARAMS::H0);
        Self { _params: core::marker::PhantomData, h }
    }

    fn compress(&mut self, blocks: &[[u8; 128]]) {
        // FIPS 180-4 s. 6.4.2: each message block M(1), ..., M(N) is processed in order.
        for block in blocks {
            compress_block(&mut self.h, block);
        }
    }
}

/// Internal struct for SHA512.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// provided and NIST-approved parameters.
#[derive(Clone)]
pub struct SHA512Internal<PARAMS: Sha512Family> {
    _params: core::marker::PhantomData<PARAMS>,
    state: Sha512State<PARAMS>,
    // NOTE: FIPS 180-4 allows messages up to 2^128 bits; this counter supports 2^67 bits (2^64 bytes).
    byte_count: u64,
    x_buf: Secret<[u8; 128]>,
    x_buf_off: usize,
}

impl<PARAMS: Sha512Family> SHA512Internal<PARAMS> {
    /// Creates a new SHA512 instance, ready for use.
    pub fn new() -> Self {
        Self {
            _params: core::marker::PhantomData,
            state: Sha512State::<PARAMS>::new(),
            byte_count: 0,
            x_buf: Secret::new(),
            x_buf_off: 0_usize,
        }
    }
}

impl<PARAMS: Sha512Family> SHA512Internal<PARAMS> {
    /// Pads and compresses the final block(s) as per FIPS 180-4 s. 5.1.2, then writes the digest.
    ///
    /// The `num_partial_bits` (0..=7, validated by the caller) trailing message bits are the most
    /// significant bits of `partial_byte`, leading bit first: the ASN.1 BIT STRING order of
    /// X.690 s. 8.6.2.1, which is also how FIPS 180-4 s. 3.1 numbers the bits of a message byte. So
    /// they are used in place, the low `8 - num_partial_bits` bits are ignored, and the mandatory
    /// "1" padding bit follows the message bits immediately in the same byte.
    ///
    /// Returns the number of bytes written (`min(output.len(), OUTPUT_LEN)`); a shorter output buffer
    /// truncates the digest, a longer one is zero-filled past the digest.
    fn finalize(mut self, partial_byte: u8, num_partial_bits: usize, output: &mut [u8]) -> usize {
        debug_assert!(num_partial_bits <= 7);
        output.fill(0);

        let n = *min(&output.len(), &PARAMS::OUTPUT_LEN);

        // FIPS 180-4 s. 5.1.2: append the bit "1" to the end of the message. The message bits are the
        // top num_partial_bits bits of partial_byte, so the final message byte is [those bits] [1] [0...];
        // with no partial bits this is the familiar 0x80. The mask is built in u16 so that the 8-bit
        // shift for num_partial_bits == 0 cannot overflow (0xFF00 >> 0 truncates to 0x00).
        let mask = (0xFF00u16 >> num_partial_bits) as u8;
        // Mutants note: the masked message bits and the padding bit occupy disjoint bit positions, so
        // `|` and `^` give identical results here; a surviving `|`/`^` swap is an equivalent mutant.
        let pad_byte = (partial_byte & mask) | (0x80u8 >> num_partial_bits);

        self.x_buf[self.x_buf_off] = pad_byte;
        self.x_buf_off += 1;

        // FIPS 180-4 s. 5.1.2: if fewer than 128 bits remain for l, the k zero bits run into a second block.
        if self.x_buf_off > 112 {
            self.x_buf[self.x_buf_off..].fill(0x00);
            self.state.compress(slice::from_ref(&self.x_buf));
            self.x_buf_off = 0;
        }

        // FIPS 180-4 s. 5.1.2: k zero bits so that l + 1 + k = 896 mod 1024, then the 128-bit big-endian
        // message length l in bits.
        self.x_buf[self.x_buf_off..112].fill(0x00);
        // byte_count is a byte counter, so the high 64 bits of l are byte_count >> 61 and the low 64
        // bits are (byte_count << 3) | num_partial_bits (the low three bits of byte_count << 3 are zero).
        let bit_len_hi: u64 = self.byte_count >> 61;
        // Mutants note: the low three bits of byte_count << 3 are zero, so `|` and `^` give identical
        // results here; a surviving `|`/`^` swap is an equivalent mutant.
        let bit_len_lo: u64 = (self.byte_count << 3) | (num_partial_bits as u64);
        self.x_buf[112..120].copy_from_slice(&bit_len_hi.to_be_bytes());
        self.x_buf[120..128].copy_from_slice(&bit_len_lo.to_be_bytes());
        self.state.compress(slice::from_ref(&self.x_buf));

        // FIPS 180-4 s. 6.4.2: the digest is H_0(N) || ... || H_7(N) (big-endian words), truncated to the
        // left-most OUTPUT_LEN bytes (s. 6.5 / 6.6 / 6.7 exception 2 for SHA-384, SHA-512/224 and SHA-512/256), and further to the caller's
        // buffer if that is shorter.
        let h = &self.state.h;
        for i in 0..(n / 8) {
            output[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
        }
        if !n.is_multiple_of(8) {
            output[((n / 8) * 8)..((n / 8) * 8) + (n % 8)]
                .copy_from_slice(&h[n / 8].to_be_bytes()[0..(n % 8)]);
        }

        n
    }
}

impl<PARAMS: Sha512Family> Default for SHA512Internal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: Sha512Family> Algorithm for SHA512Internal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: Sha512Family> Hash for SHA512Internal<PARAMS> {
    /// As per FIPS 180-4 Figure 1
    fn block_bitlen(&self) -> usize {
        1024
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; self.output_len()];
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

        let available = 128 - self.x_buf_off;
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
            //self.x_buf_off = 0;
        }

        // FIPS 180-4 s. 5.2.2: the message is parsed into 1024-bit blocks; a partial trailing block waits in x_buf.
        let (chunks, remainder) = block.as_chunks::<128>();

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
        self.finalize(0, 0, output)
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
        Ok(self.finalize(partial_byte, num_partial_bits, output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/// Length in bytes of the serialized state of SHA384, SHA512, SHA512/224 and SHA512/256.
pub const SUSPENDED_SHA512_STATE_LEN: usize = 204;

impl<PARAMS: Sha512Family> Suspendable<SUSPENDED_SHA512_STATE_LEN> for SHA512Internal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA512_STATE_LEN] {
        debug_assert_eq!(SUSPENDED_SHA512_STATE_LEN, 204);

        let mut out_to_return = [0u8; SUSPENDED_SHA512_STATE_LEN];

        // insert the version tag
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_SHA512_STATE_LEN - 3 = 201 bytes.
        let out: &mut [u8; 201] = add_lib_ver(&mut out_to_return).try_into().unwrap();

        // state.h: [u64; 8]
        // 8 * 8 = 64
        for i in 0..8 {
            out[i * 8..(i * 8) + 8].copy_from_slice(&self.state.h[i].to_le_bytes());
        }

        // byte_count: u64
        out[64..72].copy_from_slice(&self.byte_count.to_le_bytes());

        // x_buf: [u8; 128]
        out[72..200].copy_from_slice(&*self.x_buf);

        // x_buf_off: usize
        // in general, a usize should be serialized into a u64, but in this case, it can't ever be larger than 128
        debug_assert!(self.x_buf_off < 128);
        out[200] = self.x_buf_off as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA512_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // check the version tag
        // At the moment, we have no not_before version to specify.
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_SHA512_STATE_LEN - 3 = 201 bytes.
        let input: &[u8; 201] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        // state.h: [u64; 8]
        // 8 * 8 = 64
        let mut h = Secret::<[u64; 8]>::new();
        for i in 0..8 {
            h[i] = u64::from_le_bytes(input[i * 8..(i * 8) + 8].try_into().unwrap());
        }

        // byte_count: u64
        let byte_count: u64 = u64::from_le_bytes(input[64..72].try_into().unwrap());

        // x_buf: [u8; 128]
        let mut x_buf = Secret::<[u8; 128]>::new();
        x_buf.copy_from_slice(&input[72..200]);

        // x_buf_off: usize
        // in general, a usize should be serialized into a u64, but in this case, it can't ever be larger than 128
        let x_buf_off: usize = input[200] as usize;
        if x_buf_off >= 128 {
            return Err(SuspendableError::InvalidData);
        }

        // Construct the object
        let state = Sha512State { _params: core::marker::PhantomData, h };
        Ok(SHA512Internal {
            _params: core::marker::PhantomData,
            state,
            byte_count,
            x_buf,
            x_buf_off,
        })
    }
}
