//! Arithmetic modulo L, the order of the Ed25519 base point B (RFC 8032 Section 5.1, Table 1).
//!
//! Scalars cross this module as 32 little-endian octets or as four little-endian `u64` limbs.
//! [`reduce_512`], [`calculate_S`] and [`to_signed_digits`] are the signing path and are constant
//! time; everything named `_var` is verification and takes public input only. Following the
//! rule in `nat.rs`, the signing-path functions keep every secret-derived working value in a
//! [`Secret`] and write their result into the caller's buffer.

use crate::ed::{nat, wnaf};
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// Limbs in a scalar.
const SIZE: usize = 4;

/// L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032 Section 5.1, Table 1).
pub(super) const L: [u64; SIZE] =
    [0x5812631A5CF5D3ED, 0x14DEF9DEA2F79CD6, 0x0000000000000000, 0x1000000000000000];

/// L^2, where [`reduce_basis_var`] starts.
const L_SQ: [u64; SIZE * 2] = [
    0xE2EDF685AB128969, 0x680392762298A31D, 0x3DCEEC73D217F5BE, 0xA1B399411B7C309A,
    0xCB024C634B9EBA7D, 0x029BDF3BD45EF39A, 0x0000000000000000, 0x0100000000000000,
];

const M28: i64 = (1 << 28) - 1;

/// `L - 2^252` in signed radix-2^28 digits: `sum(L_DIGITS[i] * 2^(28 i))`. Since
/// `2^252 = -(L - 2^252) mod L`, a digit at weight `2^(28 (i + 9))` folds down as minus itself
/// times these, into digits `i..i + 5`.
const L_DIGITS: [i64; 5] = [-0x030A2C13, 0x012631A6, 0x079CD658, -0x006215D1, 0x000014DF];

/// The four limbs of the 32 little-endian octets `k`, written to the first four limbs of `n`.
pub(super) fn decode_into(k: &[u8; 32], n: &mut [u64]) {
    for (limb, octets) in n[..SIZE].iter_mut().zip(k.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*octets);
    }
}

/// The limbs of `S`, the second half of a signature, if it is in range: RFC 8032 Section 5.1.7,
/// step 1, decodes it "as an integer S, in the range 0 <= s < L". Variable time; `S` is public.
pub(super) fn decode_canonical_var(s: &[u8; 32]) -> Option<[u64; SIZE]> {
    let mut n = [0_u64; SIZE];
    decode_into(s, &mut n);
    nat::lt_var(&n, &L).then_some(n)
}

/// `n mod L`, for a 512-bit `n` in 64 little-endian octets, written to `r` in 32: how RFC 8032
/// Section 5.1.6 reduces the digests `r` and `k` (steps 3 and 5).
///
/// Constant time: a fixed sequence of shifts, masks and 64-bit multiplications by the digits of
/// L, with the final correction applied through a mask, on the assumption the `nat` module
/// header states for its own multiplications: a multiply whose time does not depend on its
/// operands. The working digits are wiped on return.
pub(super) fn reduce_512(n: &[u8; 64], r: &mut [u8; 32]) {
    /// `x[i]` goes away: its weight `2^(28 i)` is `2^252 * 2^(28 (i - 9))`.
    #[inline(always)]
    fn fold(x: &mut [i64; 19], i: usize) {
        let x_i = x[i];
        for (x_j, l_j) in x[i - 9..i - 4].iter_mut().zip(L_DIGITS) {
            *x_j -= x_i * l_j;
        }
    }

    /// Moves what `x[i]` holds above its low 28 bits into `x[i + 1]`.
    #[inline(always)]
    fn carry(x: &mut [i64; 19], i: usize) {
        x[i + 1] += x[i] >> 28;
        x[i] &= M28;
    }

    // n in radix 2^28, x[i] at weight 2^(28 i). To start with the even digits hold 32 bits,
    // overlapping the digit above by four, and the odd digits 24 bits moved up by four to make
    // room for them; x[18] is the last octet.
    let mut x = Secret::<[i64; 19]>::new();
    for j in 0..9 {
        let at = 7 * j;
        x[2 * j] = u32::from_le_bytes([n[at], n[at + 1], n[at + 2], n[at + 3]]) as i64;
        x[2 * j + 1] = (u32::from_le_bytes([n[at + 4], n[at + 5], n[at + 6], 0]) << 4) as i64;
    }
    x[18] = n[63] as i64;

    // Digits 18 down to 10 fold away, each brought back to 28 bits (when the folds above have
    // widened it) before it multiplies the digits of L, so that no digit outgrows an i64.
    fold(&mut x, 18);
    carry(&mut x, 16);
    fold(&mut x, 17);
    fold(&mut x, 16);
    carry(&mut x, 14);
    fold(&mut x, 15);
    fold(&mut x, 14);
    carry(&mut x, 12);
    fold(&mut x, 13);
    carry(&mut x, 11);
    fold(&mut x, 12);
    carry(&mut x, 10);
    fold(&mut x, 11);
    carry(&mut x, 9);
    fold(&mut x, 10);

    // Digit 9 is the multiple of 2^252 left. Rounding it up when bit 251 is set (t) leaves a
    // remainder within L/2 of zero either way.
    carry(&mut x, 7);
    carry(&mut x, 8);
    let t = (x[8] >> 27) & 1;
    x[9] += t;
    fold(&mut x, 9);

    for i in 0..8 {
        carry(&mut x, i);
    }
    x[9] = x[8] >> 28;
    x[8] &= M28;

    // The carry out less the rounding is 0, or -1 when the remainder is negative, and then L
    // goes back on, by mask.
    let negative = x[9] - t;
    debug_assert!(negative == 0 || negative == -1);
    for (x_j, l_j) in x[..5].iter_mut().zip(L_DIGITS) {
        *x_j += negative & l_j;
    }
    // L's 2^252, which L_DIGITS leaves out, is one unit of digit 9 and cancels the -1 there,
    // so digit 9 is zero either way and is not encoded.
    for i in 0..8 {
        carry(&mut x, i);
    }

    // Digits 0 to 7 pack in pairs into seven octets each; digit 8 is the last four.
    for j in 0..4 {
        let pair = (x[2 * j] | x[2 * j + 1] << 28) as u64;
        for (b, r_b) in r[7 * j..7 * j + 7].iter_mut().enumerate() {
            *r_b = (pair >> (8 * b)) as u8;
        }
    }
    r[28..].copy_from_slice(&(x[8] as u32).to_le_bytes());
}

/// `S = (r + k * s) mod L` (RFC 8032 Section 5.1.6, step 5), for `r` and `k` already reduced
/// and `s` the secret scalar, each in 32 octets.
///
/// Constant time: [`nat::mul_add_to`] and [`reduce_512`]. `r`, `s` and the 512-bit sum are
/// held in [`Secret`]s; `k` and `S` are public.
///
/// A `Secret` wipes the memory it names, and the compiler also keeps limbs of `s` and of the
/// sum in registers, which it spills to the frames of the computation: seen in a release
/// build, three limbs of `s` were left on the dead stack by every signature. So the
/// computation runs in a frame of its own and the stack it used is overwritten afterwards.
#[allow(non_snake_case)]
pub(super) fn calculate_S(r: &[u8; 32], k: &[u8; 32], s: &[u8; 32], S: &mut [u8; 32]) {
    calculate_S_in_own_frame(r, k, s, S);
    wipe_stack_below();
}

/// How much stack [`wipe_stack_below`] overwrites, in 64-bit words: more than
/// [`calculate_S_in_own_frame`] and everything it calls use, with room for a compiler that
/// lays the frames out less tightly.
const WIPED_STACK_WORDS: usize = 128;

/// Overwrites the stack that the previous call made from the caller's frame used, by taking a
/// frame of its own over the same memory and wiping it. Never inlined: the frame is the point.
#[inline(never)]
fn wipe_stack_below() {
    let mut scratch = Secret::<[u64; WIPED_STACK_WORDS]>::new();
    core::hint::black_box(&mut *scratch);
}

/// The computation of [`calculate_S`]. Never inlined, so that what it spills lies below its
/// caller's frame, where [`wipe_stack_below`] reaches it.
#[allow(non_snake_case)]
#[inline(never)]
fn calculate_S_in_own_frame(r: &[u8; 32], k: &[u8; 32], s: &[u8; 32], S: &mut [u8; 32]) {
    // t = r, widened to hold the sum
    let mut t = Secret::<[u64; SIZE * 2]>::new();
    decode_into(r, &mut *t);

    let mut k_limbs = [0_u64; SIZE];
    decode_into(k, &mut k_limbs);
    let mut s_limbs = Secret::<[u64; SIZE]>::new();
    decode_into(s, &mut *s_limbs);

    // t += k * s. No carry out: r, k < 2^253 and s < 2^255.
    let carry = nat::mul_add_to(&k_limbs, &*s_limbs, &mut *t);
    debug_assert_eq!(carry, 0);

    let mut wide = Secret::<[u8; 64]>::new();
    for (octets, limb) in wide.as_chunks_mut::<8>().0.iter_mut().zip(t.iter()) {
        *octets = limb.to_le_bytes();
    }
    reduce_512(&wide, S);
}

/// Recodes a scalar `z < 2^256 - L` for a multiplication by signed digits: on
/// return bit `i` of `z` stands for the digit `+1` when set and `-1` when clear, at weight
/// `2^i`, and the 256 digits sum to the scalar mod L.
///
/// An even `z` first has L added, which makes it odd without changing it mod L. An odd `z`
/// is `sum((2 b_i - 1) 2^i)` for `b = (z + 2^256 - 1) / 2`, which is `z` shifted down a bit
/// with a one coming in at the top. Constant time; `z` stays in the caller's buffer.
pub(super) fn to_signed_digits(z: &mut [u64; SIZE]) {
    let is_even = !Condition::<u64>::is_bit_set(z[0], 0);
    let carry = nat::cadd_to(is_even, &L, z);
    debug_assert_eq!(carry, 0);

    let out = nat::shift_down_bit(z, 1);
    debug_assert_eq!(out, 1 << 63);
}

/// The width-`width` wNAF of L, for the subgroup check of a public key.
pub(super) fn get_order_wnaf_var(width: usize, ws: &mut [i8; 253]) {
    wnaf::get_signed_var(&L, width, ws);
}

/// `x * y mod L` for `x < L` and a signed 128-bit `y` in two's complement. Variable time.
pub(super) fn multiply_128_var(x: &[u64; SIZE], y128: &[u64; 2]) -> [u64; SIZE] {
    // The product as if y were unsigned, in six limbs, widened to the eight reduce_512 takes.
    let mut tt = [0_u64; 8];
    nat::mul(x, y128, &mut tt[..6]);

    // A negative y was read 2^128 too high: take x * 2^128 back off, and add L * 2^128 so that
    // the total stays non-negative.
    if (y128[1] as i64) < 0 {
        nat::add_to(&L, &mut tt[2..6]);
        nat::sub_from(x, &mut tt[2..6]);
    }

    let mut wide = [0_u8; 64];
    for (octets, limb) in wide.as_chunks_mut::<8>().0.iter_mut().zip(tt) {
        *octets = limb.to_le_bytes();
    }
    let mut reduced = [0_u8; 32];
    reduce_512(&wide, &mut reduced);

    let mut z = [0_u64; SIZE];
    decode_into(&reduced, &mut z);
    z
}

/// Splits `k` into two signed 128-bit scalars `(v0, v1)`, in two's complement, such that
/// `v1 * k == v0 (mod L)` and `v1` is not zero, so that verification can run its three scalar
/// multiplications at half length. `None` if the reduction has not finished within its
/// iteration bound, which is not known to happen.
///
/// This is the lattice basis reduction of Pornin (<https://ia.cr/2020/454>), on the lattice
/// spanned by `u = (L, 0)` and `v = (k, 1)`. It carries the squared norms `nu`, `nv` and the
/// inner product `p` of the two vectors, and takes `2^s` times the shorter from the longer
/// until the shorter fits. Variable time: `k` is public.
pub(super) fn reduce_basis_var(k: &[u64; SIZE]) -> Option<([u64; 2], [u64; 2])> {
    /// The squared norm to stop at: both coordinates of `v` then fit 128 bits with their sign.
    const TARGET_LENGTH: usize = 254;

    let mut nu = L_SQ;

    let mut nv = [0_u64; SIZE * 2];
    nat::square(k, &mut nv);
    // v = (k, 1), so its squared norm is k^2 + 1. The 1 is not decoration: the loop stops on
    // the norm, and it is the norm being exact that bounds both coordinates of the result to
    // 128 bits. Without it the reduction still ends on a valid pair for the inputs tried, so no
    // test tells the difference; with a wrong norm the bound is no longer a proof.
    // A square is 0, 1 or 4 mod 8, so the addition cannot carry.
    debug_assert!(nv[0] & 7 < 7);
    nv[0] += 1;

    let mut p = [0_u64; SIZE * 2];
    nat::mul(&L, k, &mut p);

    // Only the low 128 bits of the coordinates are kept; the final ones fit them.
    let (mut u0, mut u1) = ([L[0], L[1]], [0_u64; 2]);
    let (mut v0, mut v1) = ([k[0], k[1]], [1_u64, 0]);

    // A conservative bound on the number of iterations.
    let mut iterations = TARGET_LENGTH * 4;
    // The highest limb of nu, nv and p in use.
    let mut last = SIZE * 2 - 1;
    let mut len_nv = bit_length_positive_var(&nv[..=last]);

    while len_nv > TARGET_LENGTH {
        if iterations == 0 {
            return None;
        }
        iterations -= 1;

        let s = bit_length_var(&p[..=last]).saturating_sub(len_nv);

        // u -= 2^s v when the inner product is positive, u += 2^s v when it is negative:
        //   nu' = nu -+ 2^s p -+ 2^s p',   p' = p -+ 2^s nv
        // with the old p in the first term and the new in the second.
        let subtract = (p[last] as i64) >= 0;
        add_shifted_var(subtract, last, s, &p, &mut nu);
        add_shifted_var(subtract, last, s, &nv, &mut p);
        add_shifted_var(subtract, last, s, &p, &mut nu);
        add_shifted_var(subtract, 1, s, &v0, &mut u0);
        add_shifted_var(subtract, 1, s, &v1, &mut u1);

        if nat::lt_var(&nu[..=last], &nv[..=last]) {
            core::mem::swap(&mut u0, &mut v0);
            core::mem::swap(&mut u1, &mut v1);
            core::mem::swap(&mut nu, &mut nv);

            last = len_nv >> 6;
            len_nv = bit_length_positive_var(&nv[..=last]);
        }
    }

    Some((v0, v1))
}

/// `z += x * 2^s`, or `z -= x * 2^s` when `subtract`, over limbs `0..=last` of both, modulo
/// `2^(64 (last + 1))`. Variable time.
fn add_shifted_var(subtract: bool, last: usize, s: usize, x: &[u64], z: &mut [u64]) {
    let (s_words, s_bits) = (s >> 6, s & 63);

    let mut cc = 0_i128;
    let mut prev = 0_u64;
    for i in s_words..=last {
        let next = x[i - s_words];
        let x_s = if s_bits == 0 { next } else { next << s_bits | prev >> (64 - s_bits) };
        prev = next;

        cc += z[i] as i128;
        if subtract {
            cc -= x_s as i128;
        } else {
            cc += x_s as i128;
        }
        z[i] = cc as u64;
        cc >>= 64;
    }
}

/// The bit length of the two's complement number `x`, without its sign: the position above
/// the highest bit that differs from the sign bit. Variable time.
fn bit_length_var(x: &[u64]) -> usize {
    let mut i = x.len() - 1;
    let sign = ((x[i] as i64) >> 63) as u64;
    while i > 0 && x[i] == sign {
        i -= 1;
    }
    i * 64 + 64 - (x[i] ^ sign).leading_zeros() as usize
}

/// The bit length of the non-negative number `x`. Variable time.
fn bit_length_positive_var(x: &[u64]) -> usize {
    let mut i = x.len() - 1;
    while i > 0 && x[i] == 0 {
        i -= 1;
    }
    i * 64 + 64 - x[i].leading_zeros() as usize
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    // Known answers from the prototype this module was ported from (bc-rust-nursery,
    // crates/ed25519, module `scalar_25519` and `calculate_S`): edge values around L and the
    // digit boundaries, the rest from splitmix64 with a fixed seed. Printed by the scratch
    // program described in `nat.rs` (`kat-gen scalar`, not in this repository), and checked
    // there against Python integers. Scalars are 32 little-endian octets in hexadecimal.

    // (n, n mod L)
    const REDUCE_KATS: &[(&str, &str)] = &[
        (
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903",
        ),
        (
            "edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ),
        (
            "eed3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "00000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000008",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff070000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07",
        ),
        (
            "00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000010",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
            "1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f",
        ),
        (
            "00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000",
            "1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f",
        ),
        (
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
            "77f1c8d07e3a0cfe0e98be05c38a76f232dffa0be93976e71e4d18be8da0cc09",
        ),
        (
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff",
            "988589995d1b18c129f0ec4531890a68a7c8dd455e871d91a369b460daa7e501",
        ),
        (
            "1dc09a0c5a5d5d0411e1c75c9c904e78183cef4734a876b1cabf73b89e368ef14bd6a9acbdac0cc06031a696db073b71b0a06003c0215e594d04352759e81acd",
            "67580988deed3e6d9f276d2ad8e61fa7b3aae1ae76241ed67d27250361f56404",
        ),
        (
            "dd77535a549fddd68daf0aca349b8b4aac78cb7dd63aec8f6035cb835f0d84f90c16b55f132014df8e66bd6f0ed0d1be51368d8004182c746b34876e461abcd2",
            "f87e35d6cc038fed8d864f7c3c2f7f9c1c5e2b31160397cb9d685e0fb383fd04",
        ),
        (
            "0d097b350cabaf81a64369de1e101281d6408c4995d4e43d789d07567f3b5ee2b3e17d17796b3d2687272e666d9959468c0f15bb8bba3a6889b5006806557bbf",
            "9f0076b4a4fe14eac1edea53eebdf2e051a90731c9a1660ede3dbd155fd1a307",
        ),
        (
            "164a03dce37faeffed1de73ff62fcf8f49347aeac572365d3223d82d0bfb449095c863c30e126a92dc874930bfc2cfb1e2ec3286a660384b53d2822b656e9e5c",
            "85d58737097514a2c602f8ce8a9c0a71039b15285fee61f2793233251db3e00b",
        ),
        (
            "1455ad6a9824864095b88e7bdbbbb603cdc1cc5345d18a27c8cf2a70ce61510ab60eed05996ae8800ce660c3e4e6177b8a5f5cd88445c5e3f6a3395000d4b0b6",
            "f65c343e1b122ebcec790ae345089b08ef6410f2427106a71a5b00cd58b0c607",
        ),
        (
            "fcc5e56da5d5a9365a5c6eb48206f9acb51501ec20c3cf37c25570b9a36cea392bf4e05b4afe11f579b6a543aa144d3958fbd316721a6e752be29187460389bb",
            "6da09a41ce71709333040e7dfa505218e7bcb764a5f1df3d1f567e505b6f2c02",
        ),
        (
            "093ac5df6bf7f6e491f085aa0b160a76746ec2365b7f474070ff6a03e2402786ebab4702705bef2dfe4570d9de2e00dd8b5f40936aa3f549025fc9402f1a9029",
            "6616444141fd0f86382c115c2c49fc2aaa330199bb944d66ed567b581e93a504",
        ),
        (
            "9bbbf475dabf3c837bf74a7baa7820de3bbbec6658ee9e6109efce4fe2e7e18f057481aaec006b05304f74a1245c03109d4c437eb1eb2d26b9eae991fbca7ae4",
            "c447ba381576c769a19d9baf5ed7e533cb8b11c4b2081859c7c2d5ab29f9090f",
        ),
        (
            "9c864e8e6df2050bd980657c1098597ce55372ba53e306d670c3d52fc9876904b8208bc5f914cb693c42ad8ece66797ebc3de662efdd2b25a87695a71c95b3d8",
            "e45bed35d5f858aa4b0840256f91f3928ed8a88c3b247794c9c22b9aecff5205",
        ),
        (
            "8267e6a5726ad6a42e4829bb610f0559ef0e04b53bb6fe99e0f83a6e21dd9040bc24737c94f2c2115261e69a5652fc9a58f91673bfaa522f86fdad8e2a505b77",
            "d94ef339049e498338b9c58175df45171b920bf07e9d1cb3e4974afc0a4a9409",
        ),
        (
            "cec641c546c717c566f6d75b439c5372a88f8fd274ce72e830f7d55b2b1758fc1ec9b6be586bbab4cbdda0c5a6acca9c803524bd22a4c7ffe551fbd18e1752f4",
            "c93779cf009aeba39f3f4863e4b427140e4d70073b8baf65d3c894ccd1d20509",
        ),
        (
            "cd784c980970a624c8e70ec30e9e5bb91633b139375ecad21e166b021400eed6c5117e1d4011434b5f067ad6192f943a16f84f994de1ae8b29d81760b1308852",
            "6008084a3ccadf1b76d949d58d882ab9a66d69dd887fe38a5d712d0fc6f60b0e",
        ),
    ];

    // (r, k, s, S = (r + k * s) mod L)
    const S_KATS: &[(&str, &str, &str, &str)] = &[
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "6f9faee7d21893c0b2e6bc17f5cef7a600000000000000000000000000000000",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ),
        (
            "4d05483204a3199c35a4f41de5fe03e4dccd2a154c3b7caab514873a94943805",
            "1f8d8333265ddbd0e750bd92feee407ce9b57d756e557e2320360a9ffa985a06",
            "f0c8ecabd49bd06b3e43b740b8db6fa1fedacca37e308acf6b0dfb729c923d42",
            "906da7409240f65b5f364532d6284ca45f402dce1eeeaa83cf5cf372a9d58e0e",
        ),
        (
            "9fecead6c72ccd51b66e5172611354687b546cdab7054e44d4ff28b2317d460a",
            "e510ce2b71f7dc05b7f39c9d879bb9b3f0d8c4faebfa419a01b9872f10b2b807",
            "80000ce149fc6e7df0f461f69a5f04e1234e6f108948d27f47d8f2d4d2c2715e",
            "34a634085016ba9561c91904c1de48e27146f719bfe76cd2c4a9d3969ff54109",
        ),
        (
            "1916616ba03d22b6875d569ec145f57d85b81cebc46083546454616a1e71d30b",
            "946523b40023f41b514fddbe0ff8b11150f030fcd31af118b617b0d43cab1f0f",
            "98404bb1a9bedf6b5b18eaba67b197448d1f0dce47ea2fac991c57d52fad6075",
            "f0c98729590dbde6efdd3204f7f9bfcaa7e53d940e26733f1a607b5828cf5c08",
        ),
        (
            "cfba80870748bde3ece884da3e1ac976255d2a86d7d6a7a89f286790566ceb08",
            "dcc930a05acb41fddfb78d37a3b8bc94b5adfdebec37124b93a6abefff5aa505",
            "f8b0293798d5de95efb2a5f41aff25e7cdd1158440e0edb347fabd6ecffed16b",
            "330c24c0a6a458f2cef3a8fa9959ac746676280645838d2e2eb7cf3933d25807",
        ),
        (
            "4e5f87d7bc14d16c13ee4a2ee66f23393046b10bb0d4097c9e14cc032ea7040d",
            "19938944a867a43b80aaa0ad1caf6ae3ff116bf20a8a8dba8afaa88e84b2430d",
            "28b5c8898970224c8281b3c6ee463e479f3506cd9e8a85b27ce18ab2c205cb71",
            "73f25159a1ece25e9217fb1d8350d0d5f6ab0dd4147ab3c516452bcdf366620b",
        ),
        (
            "bca3cca2af2865d6f3422f9b3e553bde02f10f6fc00419e4aafe9bc4a7ea810e",
            "257d89b909240defbaf3fd6b2b287bed8e0ff33dcc85e476287fc0145ea77e05",
            "30121aea5217ea19e500a9b63e1cc9a5a535e8ee65e914da2491df6a96786e45",
            "c3d8db3a70db51b876c0ce18146717277635b7b7a8aabdb7434c06e18bce9309",
        ),
        (
            "eaca7770be1c00c4b2f3bdd459a4c6cc8bd034c8c99779516e2e2a844d83e705",
            "022441ae00f24dae55842ec8eb3c1b66f2a8189309a02752c0d47e52baffb006",
            "b828170d90f6e2cc2202b048efb59f5ec3a0acb7244644d8b92619e196d45f49",
            "a5ac853fa559650c32e3792c25a192a8c40f7671b90673b6c9a8b5a53f946e09",
        ),
        (
            "998d329ca8ac6920119c24208999897b6fa47e325981570959f6e32b322a9f0a",
            "f81c16a477f141317e841cee3687b15231c23410f27a805536c088ef5a1b3305",
            "989681b493bfbc62f17ab6bd1b6018dee7f02c41992ec0bfb6ae47e7b91fc566",
            "6ea0d57e6ea90c1b155cef937e2611c5e08e4a66886b9b764e4659263889240d",
        ),
    ];

    // (z, z recoded)
    const SIGNED_DIGITS_KATS: &[(&str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f6e97a2e8d31092c6bce7b51ef7c6f0a00000000000000000000000000000088",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000090",
        ),
        (
            "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "f2e97a2e8d31092c6bce7b51ef7c6f0a000000000000000000000000000000c8",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000040",
            "f6e97a2e8d31092c6bce7b51ef7c6f0a000000000000000000000000000000a8",
        ),
        (
            "81ae4efa848049a86ecf681d8e5e67206e317ef72d26325849e10d0ca5524101",
            "4057277d42c02454b767b40e47af3310b718bffb161319aca4f0068652a9a080",
        ),
        (
            "d0131d082b6a310de452a787ae03fd97c1e8ada0379360bc516d6e29e7587450",
            "de7389b2a2e6a132dd774f95c6fe6dd660f456d09b4930dea836b794732c3ab0",
        ),
        (
            "96955ea63409250f32cae0050876347140f8bd3f251f2a52c7f5da1e06a25607",
            "c134aa8127b69b3384336c54f3b7094320fcde9f920f15a9e37a6d0f0351ab8b",
        ),
        (
            "2821fc77fb75177500026f4fdae59e947a1115d453e62dbbe6ee90000521f170",
            "8afa78ea8aec94666b4f3379dcefbe54bd880aea29f3965d73774880829078c0",
        ),
        (
            "29be97f7e5457be362d8e376d67df2471d02cde00ad7e674503409f95f9ddf0a",
            "14dfcbfbf2a2bd7131ec713beb3ef9a30e816670856b733a289a84fcafce6f85",
        ),
        (
            "7885d6384d0149b38e2c595b7c600de73eb04a01490d7a57ec70bc657e0ed15b",
            "b22ce6ca33b2ad85b264287f2d2df67d1f58a580a406bd2b7638de323f87e8b5",
        ),
        (
            "69d02f855b70119e142f560598a52915f00104d445a719713b2aaf4e668bfe09",
            "34e897c22db8084f8a17ab02ccd2940af80002eaa2d38cb81d955727b345ff84",
        ),
        (
            "285d14872d804215b002decb79815da8148d4bd66222d89022673e19a1203b66",
            "8a1805f2a371aa36c3cf6a37ac3d9e5e8ac6256b31116c4891339f8c50901dbb",
        ),
    ];

    // (x, y as 16 octets of two's complement, x * y mod L)
    const MULTIPLY_128_KATS: &[(&str, &str, &str)] = &[
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "ffffffffffffffffffffffffffffff7f",
            "eed3f55c1a631258d69cf7a2def9de94ffffffffffffffffffffffffffffff0f",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "00000000000000000000000000000080",
            "0000000000000000000000000000008000000000000000000000000000000000",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "ffffffffffffffffffffffffffffffff",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "01000000000000000000000000000000",
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "6af33d568e713bd6dd2416cf7c1457cb9a3888ac623b4789b1784fe158c68703",
            "b3e8e5e9875df4eee276be87aeb07cda",
            "91702c7f05aba251a6a119dbf72e5786ea51bf7bbc6287ef5d56834e43554e0c",
        ),
        (
            "771e629ce76e19a50b91e2b5d614315acd0cb41f0e732e1f4a72fb08bd6f0b09",
            "1fc1872f8795ffef5c7ebee492fc80b2",
            "b7e77ce8c1075da031bd72a735f9da3e25f37720b2874afcef451e50d8de1d0e",
        ),
        (
            "9c52b9d7e2bf07394fb622e8c7e8c2a136e683d7033db283554908b0e832ff01",
            "92d25dc3c06c54966ecef8af69ed1bd6",
            "1de4ff58c559a2b900fc0666728fe06b35ffa2b6d19541eb505d6cbda55ae80a",
        ),
        (
            "7c5ec3592f102307a678c211b2bc79dcc644fd949d2b2a2df6cbb0eb77196203",
            "f027aa5600e7b10cd0712d3de9fbf899",
            "b5e01b68de35358f2a98cca02978fbfa4336538b0283370a713c4747de5e640b",
        ),
        (
            "f60498029fb8149297f0743cd0ca45a1eaa3c7ce022bbc6d6ed815f052c74004",
            "cee5068c73ce1371e73e81048b329d7a",
            "5cb1ac3baddac40fa3630e29548db4be8f9397aba99f0f61ae6669ab8701a30a",
        ),
        (
            "9db4cd8de6a8c5bdcd9d65403982bebaf0d100ff4cbcea0123caec5eeeb3070b",
            "14ab1bf7348cb3a5411aa82c02a451e2",
            "ccf4d7faef86d6fdc027b6f234710df0fdec765422bd6ce662f78179f5626806",
        ),
        (
            "b07c025cbe99ffbb4a3475b77cbbcb37522897e4e9d844d2d541ebe72c351a04",
            "751ab7c46e5c83bc4760916ec2b77a9f",
            "a153935ad1fa5c7801284bf8f37e915e1d034501653934381bf5832bf1953001",
        ),
        (
            "1da087ac4ce66631510793452b4a09a07cf8d4c9a3cec77f7e63573f0dcc1f03",
            "497d8d231d41d29c3847a07cd467ed13",
            "a379496c41756ac6811244f67b5f6e772c8666cc9b1b8c62112955df15f2e107",
        ),
    ];

    // (k, v0, v1), v0 and v1 as 16 octets of two's complement
    const BASIS_KATS: &[(&str, &str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "01000000000000000000000000000000",
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "01000000000000000000000000000000",
            "01000000000000000000000000000000",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "01000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
        ),
        (
            "0000000000000000000000000000000001000000000000000000000000000000",
            "edd3f55c1a631258d69cf7a2def9de14",
            "000000000000000000000000000000f0",
        ),
        (
            "4eced26317e048e736ecdc94a5b1e7f0652a3b8612fbb23b31fa279dfcae5a0d",
            "02c1c6af0137a77bff1a76ee4b76b21b",
            "cde7db6b364f03ab593f9af8a3ec3a1b",
        ),
        (
            "895a83739cfedca6e2f76579fe53d4df9a0e3bf407bf46ddc461a25e8f5bf206",
            "2adc3bef5adc643e2e426b5afa018eb4",
            "8365d4994c1ffd96edf8d3e36cce9007",
        ),
        (
            "a33587742666b2b56808baffd987e0f97f403ee8a31aac24e6e511f6398fa70c",
            "7794cbf1ae16a5d85c4b0888d4f67a82",
            "c668dea9e399143f3d90658fdb11e3f6",
        ),
        (
            "eccc154579c9d034b359f56dd9c476dceb3321d2bf3b53f1bba9420045e4f40c",
            "75f011ee9f176ee90620b3cb7a93c353",
            "b5b6ba88b6df3d817188a501ff2949ec",
        ),
        (
            "68b2c87bf34c466c3fa8bdfbfed3463f49d261335a7adc92bec9e9b3fee9040b",
            "c7633efc73a74a7c1bd0652abcb442ab",
            "54244e1b7804f4d71ae85cc32fe851f9",
        ),
        (
            "332664e8e6c6de108ed5359bfe4c0213b6546527862165b69666e9f066362e01",
            "8641933cba2345bc305d1a16b19a4b30",
            "c17e3b37d44360437137a71304a3b604",
        ),
        (
            "cdf3c1b8e5727ba65f937b6ac130761d174cbf56007c3fc0a857ab64a8c2d408",
            "9c600377f9e22a357ada3d779143b45b",
            "33c0f1aa45c074527ed1ac6b3bda16f8",
        ),
        (
            "4c6b776f7dd466b9fd2f46fe2d2208e26e523b157c1d3ee7206d2c67f7d2aa06",
            "e8b9708aa9b61c69e9b8160e5bd0699f",
            "ffbc5b1d6913ccfe9b491de0185e1aef",
        ),
        (
            "c8f5898ebdb7e583eaa1b208809a77a42acaaa02fb5135cc87eebff90e7cc30e",
            "9f4a7e62ab0023f8c3f57950e75bbb8f",
            "40494b93d788dbe1956ed4f656712a09",
        ),
        (
            "40fa03b6ecf15bce5ca379f337f9f26433d30d06fad63f71b7c092a664282600",
            "3990f22b3f37fca0a4aa04630365323e",
            "5864984a128819359560f31a345e0216",
        ),
        (
            "8e3aaed9388cbca3b159a6159de8d584488154dfda5ad75e97498d89b5ec9903",
            "c5199687f7822527dcf0c3c88732f377",
            "fcdb3501dc0c6197b29deb6a15f15904",
        ),
        (
            "a0aae533afca274b441df261e02aaf977bc616a9d3fcec430f1a8906091dbf05",
            "4929bb62bd85250dee4e175db0f7206e",
            "292acc661bac954ea8e276ff4f2bb004",
        ),
    ];

    fn octets<const N: usize>(hex: &str) -> [u8; N] {
        bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn limbs(k: &[u8; 32]) -> [u64; SIZE] {
        let mut n = [0_u64; SIZE];
        decode_into(k, &mut n);
        n
    }

    fn to_octets(n: &[u64]) -> Vec<u8> {
        n.iter().flat_map(|limb| limb.to_le_bytes()).collect()
    }

    /// splitmix64: a fixed stream of test values.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn random_octets<const N: usize>(state: &mut u64) -> [u8; N] {
        core::array::from_fn(|_| next(state) as u8)
    }

    // An independent reference for arithmetic mod L: addition with one conditional
    // subtraction, and multiplication by doubling and adding, a bit at a time.

    /// `a + b mod L` for `a, b < L`.
    fn add_mod(a: &[u64; SIZE], b: &[u64; SIZE]) -> [u64; SIZE] {
        let mut sum = [0_u64; SIZE];
        let mut carry = 0_u128;
        for i in 0..SIZE {
            carry += a[i] as u128 + b[i] as u128;
            sum[i] = carry as u64;
            carry >>= 64;
        }
        assert_eq!(carry, 0);
        if sum.iter().rev().ge(L.iter().rev()) {
            let mut borrow = 0_i128;
            for i in 0..SIZE {
                borrow += sum[i] as i128 - L[i] as i128;
                sum[i] = borrow as u64;
                borrow >>= 64;
            }
        }
        sum
    }

    /// `a * b mod L` for `a < L` and `b` any number of little-endian octets.
    fn mul_mod(a: &[u64; SIZE], b: &[u8]) -> [u64; SIZE] {
        let mut acc = [0_u64; SIZE];
        for bit in (0..8 * b.len()).rev() {
            acc = add_mod(&acc, &acc);
            if (b[bit / 8] >> (bit % 8)) & 1 == 1 {
                acc = add_mod(&acc, a);
            }
        }
        acc
    }

    /// `n mod L`.
    fn mod_l(n: &[u8]) -> [u64; SIZE] {
        mul_mod(&[1, 0, 0, 0], n)
    }

    /// `-a mod L` for `a < L`.
    fn neg_mod(a: &[u64; SIZE]) -> [u64; SIZE] {
        let mut l_minus_1 = L;
        l_minus_1[0] -= 1;
        // -a = a * (L - 1)
        mul_mod(a, &to_octets(&l_minus_1))
    }

    /// A signed 128-bit number in two's complement, mod L.
    fn signed_128_mod(y: &[u64; 2]) -> [u64; SIZE] {
        let value = ((y[1] as u128) << 64 | y[0] as u128) as i128;
        let magnitude = mod_l(&value.unsigned_abs().to_le_bytes());
        if value < 0 { neg_mod(&magnitude) } else { magnitude }
    }

    #[test]
    fn the_constants_are_those_of_the_group_order() {
        // RFC 8032 Section 5.1, Table 1: L = 2^252 + 27742317777372353535851937790883648493.
        let low: u128 = 27742317777372353535851937790883648493;
        assert_eq!(L, [low as u64, (low >> 64) as u64, 0, 1 << 60]);

        let mut l_squared = [0_u64; SIZE * 2];
        nat::square(&L, &mut l_squared);
        assert_eq!(L_SQ, l_squared);

        let digits = L_DIGITS.iter().rev().fold(0_i128, |acc, &digit| (acc << 28) + digit as i128);
        assert_eq!(digits, low as i128);
        assert!(L_DIGITS.iter().all(|digit| digit.abs() < 1 << 27));
    }

    #[test]
    fn reduce_512_matches_the_prototype() {
        for (n, expected) in REDUCE_KATS {
            let mut r = [0xA5_u8; 32];
            reduce_512(&octets(n), &mut r);
            assert_eq!(r, octets::<32>(expected), "{n}");
        }
    }

    /// Against the bit-at-a-time reference: the known-answer inputs, multiples of L and their
    /// neighbours (where the final correction decides), single digits at each weight, and
    /// pseudo-random values.
    #[test]
    fn reduce_512_agrees_with_the_reference() {
        let mut inputs: Vec<[u8; 64]> = REDUCE_KATS.iter().map(|(n, _)| octets(n)).collect();

        // j * L - 1, j * L and j * L + 1 for multipliers j of every length up to 2^259.
        let mut state = 0x7265_6475_6365;
        for bits in (1..=259).step_by(7) {
            let mut j = random_octets::<33>(&mut state);
            for (i, octet) in j.iter_mut().enumerate() {
                if 8 * i >= bits {
                    *octet = 0;
                } else if 8 * i + 8 > bits {
                    *octet = (*octet | 0x80) >> (8 * i + 8 - bits);
                }
            }
            let mut multiple = [0_u64; 9];
            let j_limbs: Vec<u64> = j
                .iter()
                .chain(&[0_u8; 7])
                .copied()
                .collect::<Vec<u8>>()
                .chunks(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect();
            nat::mul(&L, &j_limbs, &mut multiple);
            assert_eq!(multiple[8], 0);
            let one = [1_u64, 0, 0, 0, 0, 0, 0, 0];
            let (mut below, mut above) = (multiple, multiple);
            nat::sub_from(&one, &mut below);
            nat::add_to(&one, &mut above);
            for n in [below, multiple, above] {
                inputs.push(to_octets(&n[..8]).try_into().unwrap());
            }
        }
        // 2^(28 i) - 1 and 2^(28 i): one digit, and every digit below it full.
        for i in 0..=18 {
            let mut power = [0_u8; 64];
            power[28 * i / 8] = 1 << (28 * i % 8);
            let mut below = [0_u8; 64];
            for bit in 0..28 * i {
                below[bit / 8] |= 1 << (bit % 8);
            }
            inputs.push(power);
            inputs.push(below);
        }
        for _ in 0..500 {
            inputs.push(random_octets(&mut state));
        }

        for n in &inputs {
            let mut r = [0x5A_u8; 32];
            reduce_512(n, &mut r);
            assert_eq!(limbs(&r), mod_l(n), "{n:02x?}");
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn calculate_S_matches_the_prototype_and_the_reference() {
        for (r, k, s, expected) in S_KATS {
            let mut S = [0xA5_u8; 32];
            calculate_S(&octets(r), &octets(k), &octets(s), &mut S);
            assert_eq!(S, octets::<32>(expected), "{r} {k} {s}");
        }

        let mut state = 0x5F53;
        for _ in 0..50 {
            let (mut r, mut k) = ([0_u8; 32], [0_u8; 32]);
            reduce_512(&random_octets(&mut state), &mut r);
            reduce_512(&random_octets(&mut state), &mut k);
            let s: [u8; 32] = random_octets(&mut state);
            let mut S = [0_u8; 32];
            // s is any 256-bit value here, wider than a pruned scalar; the sum still fits.
            let s = {
                let mut s = s;
                s[31] &= 0x7F;
                s
            };
            calculate_S(&r, &k, &s, &mut S);
            assert_eq!(limbs(&S), add_mod(&limbs(&r), &mul_mod(&limbs(&k), &s)));
        }
    }

    /// The recoded bits, read as digits of +1 and -1, sum to the scalar mod L.
    #[test]
    fn to_signed_digits_matches_the_prototype_and_recodes_the_same_scalar() {
        let mut two_256 = [0_u8; 33];
        two_256[32] = 1;
        for (z, expected) in SIGNED_DIGITS_KATS {
            let z: [u8; 32] = octets(z);
            let mut n = limbs(&z);
            to_signed_digits(&mut n);
            assert_eq!(to_octets(&n), octets::<32>(expected));

            // sum((2 b_i - 1) 2^i) = 2 b + 1 - 2^256
            let mut twice_plus_one = [0_u8; 33];
            let mut carry = 1_u8;
            for (out, octet) in twice_plus_one.iter_mut().zip(to_octets(&n)) {
                *out = octet << 1 | carry;
                carry = octet >> 7;
            }
            twice_plus_one[32] = carry;
            let sum = add_mod(&mod_l(&twice_plus_one), &neg_mod(&mod_l(&two_256)));
            assert_eq!(sum, mod_l(&z));
        }
    }

    #[test]
    fn decode_canonical_var_accepts_exactly_the_values_below_the_order() {
        let mut l_minus_1 = L;
        l_minus_1[0] -= 1;
        let accepted = [[0_u64; SIZE], [1, 0, 0, 0], l_minus_1, [u64::MAX, u64::MAX, 0, 0]];
        for n in accepted {
            let s: [u8; 32] = to_octets(&n).try_into().unwrap();
            assert_eq!(decode_canonical_var(&s), Some(n), "{n:x?}");
        }

        let mut l_plus_1 = L;
        l_plus_1[0] += 1;
        let rejected = [
            L,
            l_plus_1,
            [0, 0, 1, 1 << 60],       // above L in the third limb only
            [0, 0, 0, (1 << 60) + 1], // above L in the top limb only
            [L[0], L[1], 0, 1 << 61], // 2^252 + L, a small S with L added
            [u64::MAX; SIZE],
        ];
        for n in rejected {
            let s: [u8; 32] = to_octets(&n).try_into().unwrap();
            assert_eq!(decode_canonical_var(&s), None, "{n:x?}");
        }
    }

    #[test]
    fn multiply_128_var_matches_the_prototype_and_the_reference() {
        for (x, y, expected) in MULTIPLY_128_KATS {
            let x = limbs(&octets(x));
            let y: [u8; 16] = octets(y);
            let y = [
                u64::from_le_bytes(y[..8].try_into().unwrap()),
                u64::from_le_bytes(y[8..].try_into().unwrap()),
            ];
            let z = multiply_128_var(&x, &y);
            assert_eq!(to_octets(&z), octets::<32>(expected), "{x:x?} {y:x?}");
            assert_eq!(z, mul_mod(&signed_128_mod(&y), &to_octets(&x)), "{x:x?} {y:x?}");
        }
    }

    /// The outputs are the prototype's, and on those and further inputs `v1 * k == v0 (mod L)`
    /// with `v1` not zero and the vector short enough.
    #[test]
    fn reduce_basis_var_matches_the_prototype_and_satisfies_its_congruence() {
        let halves = |v: &str| {
            let v: [u8; 16] = octets(v);
            [
                u64::from_le_bytes(v[..8].try_into().unwrap()),
                u64::from_le_bytes(v[8..].try_into().unwrap()),
            ]
        };
        let mut ks: Vec<[u8; 32]> = Vec::new();
        for (k, v0, v1) in BASIS_KATS {
            let k = octets(k);
            assert_eq!(reduce_basis_var(&limbs(&k)), Some((halves(v0), halves(v1))), "{k:02x?}");
            ks.push(k);
        }
        let mut state = 0x0062_6173_6973;
        for _ in 0..200 {
            let mut k = [0_u8; 32];
            reduce_512(&random_octets(&mut state), &mut k);
            ks.push(k);
        }
        // Short scalars, which need few steps or none.
        for bits in [1, 64, 126, 127, 128, 129, 190] {
            let mut k = [0_u8; 32];
            k[bits / 8] = 1 << (bits % 8);
            ks.push(k);
        }

        for k in &ks {
            let (v0, v1) = reduce_basis_var(&limbs(k)).unwrap();
            assert_ne!(v1, [0, 0], "{k:02x?}");
            assert_eq!(mul_mod(&signed_128_mod(&v1), k), signed_128_mod(&v0), "{k:02x?}");
            // v0^2 + v1^2 has at most 254 bits, so each fits 128 bits with its sign.
            let mut norm = [0_u64; 5];
            for v in [v0, v1] {
                let magnitude = (((v[1] as u128) << 64 | v[0] as u128) as i128).unsigned_abs();
                let mut square = [0_u64; 4];
                nat::square(&[magnitude as u64, (magnitude >> 64) as u64], &mut square);
                norm[4] += nat::add_to(&square, &mut norm[..4]);
            }
            assert!(norm[4] == 0 && norm[3] >> 62 == 0, "{k:02x?}");
        }
    }

    /// The shifted addition and subtraction against `u128` arithmetic on two limbs, at shifts
    /// below, at and above a limb, with the limbs above `last` left alone.
    #[test]
    fn add_shifted_var_agrees_with_u128_arithmetic() {
        let value = |v: &[u64]| (v[1] as u128) << 64 | v[0] as u128;
        let mut state = 0x0073_6869_6674;
        for s in [0, 1, 17, 63, 64, 65, 100, 127] {
            for subtract in [false, true] {
                let x = [next(&mut state), next(&mut state), 0x1111];
                let mut z = [next(&mut state), next(&mut state), 0x2222];
                let shifted = value(&x) << s;
                let expected = if subtract {
                    value(&z).wrapping_sub(shifted)
                } else {
                    value(&z).wrapping_add(shifted)
                };
                add_shifted_var(subtract, 1, s, &x, &mut z);
                assert_eq!((value(&z), z[2]), (expected, 0x2222), "{s} {subtract}");
            }
        }
        // With last = 0 only the low limb moves.
        let mut z = [5, 7];
        add_shifted_var(false, 0, 4, &[u64::MAX, 9], &mut z);
        assert_eq!(z, [5_u64.wrapping_add(u64::MAX << 4), 7]);
    }

    #[test]
    fn bit_lengths() {
        assert_eq!(bit_length_positive_var(&[0, 0]), 0);
        assert_eq!(bit_length_positive_var(&[1, 0]), 1);
        assert_eq!(bit_length_positive_var(&[u64::MAX, 0]), 64);
        assert_eq!(bit_length_positive_var(&[0, 1]), 65);
        assert_eq!(bit_length_positive_var(&[7, 1 << 63]), 128);

        assert_eq!(bit_length_var(&[0, 0]), 0);
        assert_eq!(bit_length_var(&[5, 0]), 3);
        assert_eq!(bit_length_var(&[0, 2]), 66);
        // Negative: -1 has length 0, -2 length 1, -2^64 length 64, -2^64 - 1 length 65.
        assert_eq!(bit_length_var(&[u64::MAX, u64::MAX]), 0);
        assert_eq!(bit_length_var(&[u64::MAX - 1, u64::MAX]), 1);
        assert_eq!(bit_length_var(&[0, u64::MAX]), 64);
        assert_eq!(bit_length_var(&[u64::MAX, u64::MAX - 1]), 65);
        assert_eq!(bit_length_var(&[0, 1 << 63]), 127);
    }
}
