use crate::sha2::SHA512InitValue;
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, FinishToken, Hash, HashOneShot, Suspendable};
use bouncycastle_utils::stack_wipe::wipe_stack_below;
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};
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
pub(in crate::sha2) const SHA384_H0: [u64; 8] = [
    0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
    0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
];

/// FIPS 180-4 s. 5.3.5: the initial hash value H(0) for SHA-512.
pub(in crate::sha2) const SHA512_H0: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

/// Rejects, at compile time, every `t` for which SHA-512/t is not defined or not representable
/// here. See [`sha512t_h0`] for where each rule comes from; the multiple-of-8 rule is this
/// module's, the rest are FIPS 180-4 s. 5.3.6's.
pub(in crate::sha2) const fn check_t(t: usize) {
    // FIPS 180-4 s. 5.3.6: "t is any positive integer ... such that t < 512".
    assert!(t > 0, "FIPS 180-4 s. 5.3.6: t must be a positive integer");
    assert!(t < 512, "FIPS 180-4 s. 5.3.6: t must be less than 512");
    // FIPS 180-4 s. 5.3.6: "and t is not 384". SHA-384 is its own algorithm (s. 5.3.4 / s. 6.5)
    // with an IV that is not the one this function would generate.
    assert!(t != 384, "FIPS 180-4 s. 5.3.6: t must not be 384 -- use SHA384 instead");
    // This module's restriction, not the standard's: the digest must be a whole number of bytes.
    assert!(t.is_multiple_of(8), "SHA-512/t here requires t to be a multiple of 8");
}

/// The number of decimal digits in `t`, i.e. the length of the "t" part of the ASCII string
/// "SHA-512/t" that FIPS 180-4 s. 5.3.6 hashes. `t < 512`, so one, two or three.
pub(in crate::sha2) const fn t_digits(t: usize) -> usize {
    if t >= 100 {
        3
    } else if t >= 10 {
        2
    } else {
        1
    }
}

/// This module's algorithm name for SHA-512/t, `"SHA512/t"` with `t` in decimal -- `"SHA512/224"`,
/// `"SHA512/256"`, `"SHA512/8"` -- returned NUL-padded to the longest form, with
/// [`alg_name_len`] giving the significant prefix. Two pieces because
/// [`Algorithm::ALG_NAME`](bouncycastle_core::traits::Algorithm::ALG_NAME) is a `&'static str` and
/// a const generic cannot size the buffer to the digit count.
///
/// Note this is *not* the s. 5.3.6 spelling: the string the IV Generation Function hashes is
/// "SHA-512/t", with the hyphen, and is built separately in [`sha512t_h0`]. This one follows the
/// module's existing names, [`SHA512_224_NAME`](crate::sha2::SHA512_224_NAME) and
/// [`SHA512_256_NAME`](crate::sha2::SHA512_256_NAME), which it has to keep reproducing exactly.
pub(in crate::sha2) const fn alg_name_bytes(t: usize) -> [u8; ALG_NAME_BUF_LEN] {
    let mut buf = [b'S', b'H', b'A', b'5', b'1', b'2', b'/', 0, 0, 0];
    let mut i = 7;
    if t >= 100 {
        buf[i] = b'0' + (t / 100) as u8;
        i += 1;
    }
    if t >= 10 {
        buf[i] = b'0' + ((t / 10) % 10) as u8;
        i += 1;
    }
    buf[i] = b'0' + (t % 10) as u8;
    buf
}

/// Size of the [`alg_name_bytes`] buffer: `"SHA512/"` plus the most digits `t` can have.
pub(in crate::sha2) const ALG_NAME_BUF_LEN: usize = 7 + 3;

/// The significant length of [`alg_name_bytes`]'s output for `t`.
pub(in crate::sha2) const fn alg_name_len(t: usize) -> usize {
    7 + t_digits(t)
}

/// FIPS 180-4 s. 5.3.6 "SHA-512/t IV Generation Function": computes the initial hash value H(0)
/// for SHA-512/t.
///
/// Quoting the procedure:
///
/// > Denote H(0)' to be the initial hash value of SHA-512 as specified in Section 5.3.5 above.
/// >
/// > Denote H(0)'' to be the initial hash value computed below.
/// >
/// > H(0) is the IV for SHA-512/t.
/// >
/// > For i = 0 to 7 { Hi(0)'' = Hi(0)' xor a5a5a5a5a5a5a5a5(in hex). }
/// >
/// > H(0) = SHA-512 ("SHA-512/t") using H(0)'' as the IV, where t is the specific truncation value.
///
/// where, per the same section, "t is any positive integer without a leading zero such that t < 512,
/// and t is not 384", and "SHA-512/t" is the ASCII string with t written in decimal (so for t = 256
/// the message is the 11 bytes `53 48 41 2D 35 31 32 2F 32 35 36`).
///
/// Deliberate deviation from s. 5.3.6: `t` must additionally be a multiple of 8. The section
/// allows "any positive integer" below 512, including values that are not a whole number of bytes,
/// but [`Hash`](bouncycastle_core::traits::Hash) is byte-oriented -- `OUTPUT_LEN` is a byte count
/// and `do_final_out` writes whole bytes -- so a t of, say, 100 bits has no representable digest
/// here. BC Java's `SHA512tDigest` imposes the same restriction ("bitLength needs to be a multiple
/// of 8"), so the two libraries accept exactly the same set of truncations.
///
/// This is a `const fn` so that the IV is computed at compile time, which is also what makes the
/// rules above compile errors rather than panics: an unusable `t` fails the build at the point the
/// parameter set is instantiated.
pub(in crate::sha2) const fn sha512t_h0(t: usize) -> [u64; 8] {
    check_t(t);

    // FIPS 180-4 s. 5.3.6: H(0)'' = H(0)', the SHA-512 initial hash value (s. 5.3.5), with each word XOR a5a5a5a5a5a5a5a5.
    let mut h = SHA512_H0;
    let mut i = 0;
    while i < 8 {
        h[i] ^= 0xA5A5A5A5A5A5A5A5;
        i += 1;
    }

    // FIPS 180-4 s. 5.3.6: the message is the ASCII string "SHA-512/t" (at most 11 bytes, so one
    // block). It is built directly in its padded form (s. 5.1.2) inside a single 1024-bit block
    // (s. 5.2.2).
    let mut block = [0u8; 128];
    let prefix = b"SHA-512/";
    let mut len = 0;
    while len < prefix.len() {
        block[len] = prefix[len];
        len += 1;
    }
    // FIPS 180-4 s. 5.3.6: t written in decimal "without a leading zero" ("t is 256, but not
    // 0256"). t < 512, so one, two or three digits, and the leading digit is emitted only when it
    // is significant -- writing a fixed three digits would produce the "0256" spelling the section
    // forbids, and hence the wrong IV, for every t below 100.
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

    // FIPS 180-4 s. 5.3.6: H(0) = SHA-512("SHA-512/t") using H(0)'' as the IV, i.e. one pass of s. 6.4.2.
    compress_block(&mut h, &block, &mut [0; 16]);
    h
}

/// FIPS 180-4 s. 4.1.3 (4.8) Ch(x, y, z) = (x AND y) XOR (NOT x AND z), written as
/// ((y XOR z) AND x) XOR z: each bit of x selects y (x = 1) or z (x = 0) either way.
#[inline(always)]
const fn ch(x: u64, y: u64, z: u64) -> u64 {
    ((y ^ z) & x) ^ z
}

// Sigma1, sigma0 and sigma1 below fold each sum of rotations into nested rotations, using
// ROTR^n(x) XOR ROTR^n(y) = ROTR^n(x XOR y): fewer instructions on a target whose rotate
// overwrites its operand, the same result. Sigma0 keeps the spec's form, which is faster on
// x86-64.

/// FIPS 180-4 s. 4.1.3 (4.10) Sigma0(x) = ROTR28(x) XOR ROTR34(x) XOR ROTR39(x)
#[inline(always)]
const fn sum0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// FIPS 180-4 s. 4.1.3 (4.11) Sigma1(x) = ROTR14(x) XOR ROTR18(x) XOR ROTR41(x)
/// = ROTR14(x XOR ROTR4(x XOR ROTR23(x)))
#[inline(always)]
const fn sum1(x: u64) -> u64 {
    ((x.rotate_right(23) ^ x).rotate_right(4) ^ x).rotate_right(14)
}

/// FIPS 180-4 s. 4.1.3 (4.12) sigma0(x) = ROTR1(x) XOR ROTR8(x) XOR SHR7(x)
/// = ROTR1(x XOR ROTR7(x)) XOR SHR7(x)
#[inline(always)]
const fn theta0(x: u64) -> u64 {
    (x.rotate_right(7) ^ x).rotate_right(1) ^ (x >> 7)
}

/// FIPS 180-4 s. 4.1.3 (4.13) sigma1(x) = ROTR19(x) XOR ROTR61(x) XOR SHR6(x)
/// = ROTR19(x XOR ROTR42(x)) XOR SHR6(x)
#[inline(always)]
const fn theta1(x: u64) -> u64 {
    (x.rotate_right(42) ^ x).rotate_right(19) ^ (x >> 6)
}

/// FIPS 180-4 s. 6.4.2 step 1 for 16 <= t <= 79: W_t = sigma1(W_t-2) + W_t-7 + sigma0(W_t-15) +
/// W_t-16, with its operands named by their offset from W_t-16.
#[inline(always)]
const fn schedule(w_t16: u64, w_t15: u64, w_t7: u64, w_t2: u64) -> u64 {
    theta1(w_t2).wrapping_add(w_t7).wrapping_add(theta0(w_t15)).wrapping_add(w_t16)
}

/// FIPS 180-4 s. 6.4.2 step 3, one round, with `kw` = K_t + W_t. The caller renames the working
/// variables instead of moving them (h = g, g = f, ...), so the spec's new e lands in `d` and its
/// new a in `h`.
///
/// Maj(a, b, c) is computed as ((a XOR b) AND (b XOR c)) XOR b: where a = b that is b, the
/// majority, and otherwise c, which breaks the tie. b XOR c is this round's `c_xor_b`, the a XOR b
/// that the previous round returned (its a and b are this round's b and c), and this round's
/// a XOR b is returned for the next.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
const fn round(
    a: u64,
    b: u64,
    c_xor_b: u64,
    d: &mut u64,
    e: u64,
    f: u64,
    g: u64,
    h: &mut u64,
    kw: u64,
) -> u64 {
    // T1 = h + Sigma1(e) + Ch(e, f, g) + K_t + W_t
    let t1 = h.wrapping_add(sum1(e)).wrapping_add(ch(e, f, g)).wrapping_add(kw);
    // e = d + T1
    *d = d.wrapping_add(t1);
    // a = T1 + T2, where T2 = Sigma0(a) + Maj(a, b, c)
    let a_xor_b = a ^ b;
    *h = t1.wrapping_add(sum0(a)).wrapping_add((a_xor_b & c_xor_b) ^ b);
    a_xor_b
}

/// FIPS 180-4 s. 6.4.2, one iteration of the outer loop: absorbs a single 1024-bit message block
/// into the hash value `s` (H(i-1) in, H(i) out), with `w` as the message schedule's storage.
///
/// This is a `const fn` (hence `while` rather than `for` loops) so that [`sha512t_h0`] can run it
/// at compile time. At runtime it is ordinary code, and is the hot path of every SHA-512 variant.
#[inline(always)]
const fn compress_block(s: &mut [u64; 8], block: &[u8; 128], w: &mut [u64; 16]) {
    // FIPS 180-4 s. 6.4.2 step 1: the message schedule {W_t}, held as the sixteen most recent
    // words: W_t is in w[t mod 16], and replaces W_t-16 there, which is the last word it depends
    // on. W_t = M_t(i) for 0 <= t <= 15 (s. 5.2.2: sixteen big-endian 64-bit words).
    let (words, _remainder) = block.as_chunks::<8>();
    let mut i = 0;
    while i < 16 {
        w[i] = u64::from_be_bytes(words[i]);
        i += 1;
    }

    // FIPS 180-4 s. 6.4.2 step 2: initialize the working variables a..h with H(i-1).
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;
    // b XOR c for the first round's Maj (see `round`).
    let mut bc = b ^ c;

    // FIPS 180-4 s. 6.4.2 step 3, eight rounds at a time: rounds t..t+7 read W_t..W_t+7 from one
    // half of `w`, `p`, and the other half, `q`, holds W_t-8..W_t-1. Before them, for t = 8 to 64,
    // the words W_t+8..W_t+15 that the next eight rounds read are computed into `q`, in place of
    // W_t-8..W_t-1, which are their W_t-16 terms; each of their operands is either in `p`, in `q`
    // and not yet overwritten, or computed earlier in the same batch. Computing them a batch
    // ahead, away from the rounds that read them, is what lets an out-of-order core run them
    // alongside the rounds.
    let mut t: usize = 0;
    while t < 80 {
        let p = t & 8;
        let q = p ^ 8;
        // Mutants note: `t < 72` to `t <= 72` survives: the extra batch writes W_88..W_95, which
        // nothing reads.
        if t >= 8 && t < 72 {
            w[q] = schedule(w[q], w[q + 1], w[p + 1], w[p + 6]);
            w[q + 1] = schedule(w[q + 1], w[q + 2], w[p + 2], w[p + 7]);
            w[q + 2] = schedule(w[q + 2], w[q + 3], w[p + 3], w[q]);
            w[q + 3] = schedule(w[q + 3], w[q + 4], w[p + 4], w[q + 1]);
            w[q + 4] = schedule(w[q + 4], w[q + 5], w[p + 5], w[q + 2]);
            w[q + 5] = schedule(w[q + 5], w[q + 6], w[p + 6], w[q + 3]);
            w[q + 6] = schedule(w[q + 6], w[q + 7], w[p + 7], w[q + 4]);
            w[q + 7] = schedule(w[q + 7], w[p], w[q], w[q + 5]);
        }
        bc = round(a, b, bc, &mut d, e, f, g, &mut h, SHA512_K[t].wrapping_add(w[p]));
        bc = round(h, a, bc, &mut c, d, e, f, &mut g, SHA512_K[t + 1].wrapping_add(w[p + 1]));
        bc = round(g, h, bc, &mut b, c, d, e, &mut f, SHA512_K[t + 2].wrapping_add(w[p + 2]));
        bc = round(f, g, bc, &mut a, b, c, d, &mut e, SHA512_K[t + 3].wrapping_add(w[p + 3]));
        bc = round(e, f, bc, &mut h, a, b, c, &mut d, SHA512_K[t + 4].wrapping_add(w[p + 4]));
        bc = round(d, e, bc, &mut g, h, a, b, &mut c, SHA512_K[t + 5].wrapping_add(w[p + 5]));
        bc = round(c, d, bc, &mut f, g, h, a, &mut b, SHA512_K[t + 6].wrapping_add(w[p + 6]));
        bc = round(b, c, bc, &mut e, f, g, h, &mut a, SHA512_K[t + 7].wrapping_add(w[p + 7]));
        t += 8;
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
pub(in crate::sha2) struct Sha512State<PARAMS: SHA512InitValue> {
    _params: core::marker::PhantomData<PARAMS>,
    h: Secret<[u64; 8]>,
}

impl<PARAMS: SHA512InitValue> Sha512State<PARAMS> {
    pub(in crate::sha2) fn new() -> Self {
        let mut h = Secret::<[u64; 8]>::new();
        // FIPS 180-4 s. 6.4.1 step 1: set the initial hash value H(0) (s. 5.3.4 / 5.3.5 / 5.3.6 per variant).
        h.copy_from_slice(&PARAMS::H0);
        Self { _params: core::marker::PhantomData, h }
    }

    /// Compresses `blocks` in a frame of its own and overwrites the stack that frame used: the
    /// message schedule and the working variables spilled there are the message and the
    /// chaining value of whatever is hashed, an HMAC key or a private key among them.
    fn compress(&mut self, blocks: &[[u8; 128]]) {
        // Only to save the wipe; mutants note: deleting it is an equivalent mutant.
        if blocks.is_empty() {
            return;
        }
        compress_blocks(&mut self.h, blocks);
        wipe_stack_below::<COMPRESS_WIPED_STACK_WORDS>();
    }
}

/// FIPS 180-4 s. 6.4.2: each message block M(1), ..., M(N) is processed in order. Never inlined,
/// so that its frame lies below its caller's, where [`Sha512State::compress`]'s wipe reaches it.
#[inline(never)]
fn compress_blocks(h: &mut [u64; 8], blocks: &[[u8; 128]]) {
    // The message schedule, zeroized on drop: it holds the last block's words (W_64..W_79).
    let mut w = Secret::<[u64; 16]>::new();
    for block in blocks {
        compress_block(h, block, &mut w);
    }
}

/// How much stack [`wipe_stack_below`] overwrites after [`compress_blocks`], in 64-bit words:
/// more than that frame uses for the working variables and other values it spills, measured at
/// 320 bytes with the return address and red zone on x86-64, 368 on thumbv6m and 444 on riscv32i
/// (464 at opt-level z; release and `mutants` profiles; nightly `-Zbuild-std=core` for the last
/// two), with room on riscv32i for a compiler that spills a few words more. An unoptimised
/// build's frame is not covered.
const COMPRESS_WIPED_STACK_WORDS: usize = 80;

/// Internal struct for SHA512.
/// This uses a private bound so that you cannot instantiate it directly and have to use the
/// parameter sets this module provides.
#[derive(Clone)]
pub struct SHA512Internal<PARAMS: SHA512InitValue> {
    _params: core::marker::PhantomData<PARAMS>,
    state: Sha512State<PARAMS>,
    // NOTE: FIPS 180-4 allows messages up to 2^128 bits; this counter supports 2^67 bits (2^64 bytes).
    byte_count: u64,
    x_buf: Secret<[u8; 128]>,
    x_buf_off: usize,
}

impl<PARAMS: SHA512InitValue> SHA512Internal<PARAMS> {
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

impl<PARAMS: SHA512InitValue> SHA512Internal<PARAMS> {
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
    fn do_final_internal(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> usize {
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

impl<PARAMS: SHA512InitValue> Default for SHA512Internal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA512InitValue> Algorithm for SHA512Internal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHA512InitValue> Hash for SHA512Internal<PARAMS> {
    /// As per FIPS 180-4 Figure 1
    fn block_bitlen(&self) -> usize {
        PARAMS::BLOCK_LEN * 8
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn do_update(&mut self, block: &[u8]) {
        let len = block.len();

        // FIPS 180-4 s. 5.1.2: do_final_internal writes the whole 128-bit field, carrying the top
        // three bits of byte_count in bit_len_hi, so unlike SHA-256 nothing is lost to the shift.
        // The limit is byte_count itself at 2^64 bytes, far inside the l < 2^128 bits of Table 1.
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
            // Not left where a clone or a suspended state would carry it. Once per call at
            // most: whole blocks after this one are compressed from `block`.
            self.x_buf.fill(0);
        }

        // FIPS 180-4 s. 5.2.2: the message is parsed into 1024-bit blocks; a partial trailing block waits in x_buf.
        let (chunks, remainder) = block.as_chunks::<128>();

        self.state.compress(chunks);

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

/// Length in bytes of the serialized state of SHA384, SHA512, SHA512/224 and SHA512/256.
pub const SUSPENDED_SHA512_STATE_LEN: usize = 204;

impl<PARAMS: SHA512InitValue> Suspendable<SUSPENDED_SHA512_STATE_LEN> for SHA512Internal<PARAMS> {
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
        // Resuming builds the state without the initial hash value, so evaluate it here: for
        // SHA-512/t that is what runs `check_t`, which makes an invalid `t` a compile error on
        // this path too.
        const { _ = PARAMS::H0 };
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
        // do_update keeps byte_count congruent to x_buf_off modulo the block length, so a state in
        // which they disagree describes no message and must not resume.
        if byte_count % 128 != x_buf_off as u64 {
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

// The one-shot form: `Default` is the function itself.
impl<PARAMS: SHA512InitValue> HashOneShot for SHA512Internal<PARAMS> {}
