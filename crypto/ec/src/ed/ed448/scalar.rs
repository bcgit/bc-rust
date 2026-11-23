//! Arithmetic modulo L, the order of the Ed448 base point B (RFC 8032 Section 5.2, Table 2).
//!
//! Scalars cross this module as 57 little-endian octets, the last of which is zero, or as seven
//! little-endian `u64` limbs. [`reduce_912`], [`calculate_S`] and [`to_signed_digits`] are the
//! signing path and are constant time; everything named `_var` is verification and takes public
//! input only. Following the rule in `nat.rs`, the signing-path functions keep every
//! secret-derived working value in a [`Secret`] and write their result into the caller's
//! buffer.

use crate::ed::{nat, wnaf};
use crate::stack_wipe::wipe_stack_below;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// Limbs in a scalar.
const SIZE: usize = 7;

/// Octets in an encoded scalar (RFC 8032 Section 5.2.2: "a 57-octet string"). A scalar below
/// `2^448` has the last of them zero.
pub(super) const SCALAR_LEN: usize = 57;

/// The digits [`to_signed_digits`] recodes a scalar into, which is the length of the comb of
/// `point::scalar_mult_base`.
pub(super) const SIGNED_DIGITS: usize = 450;

/// L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
/// (RFC 8032 Section 5.2, Table 2).
pub(super) const L: [u64; SIZE] = [
    0x2378C292AB5844F3, 0x216CC2728DC58F55, 0xC44EDB49AED63690, 0xFFFFFFFF7CCA23E9,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF,
];

/// L^2, where [`reduce_basis_var`] starts.
const L_SQ: [u64; SIZE * 2] = [
    0xC1ADFBB81BA1FEA9, 0xB91BF53749E0A8B2, 0x4525492BE764D815, 0x4AE17CF6A2B8716D,
    0xF1A9CC14BA3C47C4, 0x92052BCB7E4D070A, 0xC3402A939F823B72, 0x91BC614955AC2279,
    0x10B6613946E2C7AA, 0xE2276DA4D76B1B48, 0xFFFFFFFFBE6511F4, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x0FFFFFFFFFFFFFFF,
];

const M26: i64 = (1 << 26) - 1;
const M28: i64 = (1 << 28) - 1;

/// `c = 2^446 - L` in radix-2^28 digits: `sum(C_DIGITS[i] * 2^(28 i))`. Since
/// `2^446 = c mod L`, a multiple of `2^446` folds down as itself times these.
const C_DIGITS: [i64; 8] = [
    0x04A7BB0D, 0x0873D6D5, 0x0A70AADC, 0x03D8D723, 0x096FDE93, 0x0B65129C, 0x063BB124, 0x08335DC1,
];

/// `4 c`, which is `2^448 mod L`, in radix-2^28 digits, the last of them 30 bits long: a digit
/// at weight `2^(28 (i + 16))` folds down as itself times these, into digits `i..i + 8`.
const C4_DIGITS: [i64; 8] = [
    0x029EEC34, 0x01CF5B55, 0x09C2AB72, 0x0F635C8E, 0x05BF7A4C, 0x0D944A72, 0x08EEC492, 0x20CD7705,
];

/// The seven limbs of the first 56 of the little-endian octets `k`, written to the first seven
/// limbs of `n`. The last octet is not read: every caller's scalar is below `2^448`.
pub(super) fn decode_into(k: &[u8; SCALAR_LEN], n: &mut [u64]) {
    for (limb, octets) in n[..SIZE].iter_mut().zip(k.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*octets);
    }
}

/// The limbs of `S`, the second half of a signature, if it is in range: RFC 8032 Section 5.2.7,
/// step 1, decodes it "as an integer S, in the range 0 <= s < L". Variable time; `S` is public.
pub(super) fn decode_canonical_var(s: &[u8; SCALAR_LEN]) -> Option<[u64; SIZE]> {
    // The limbs hold 448 bits; anything in the last octet is 2^448 or more.
    if s[SCALAR_LEN - 1] != 0 {
        return None;
    }
    let mut n = [0_u64; SIZE];
    decode_into(s, &mut n);
    nat::lt_var(&n, &L).then_some(n)
}

/// `n mod L`, for a 912-bit `n` in 114 little-endian octets, written to `r` in 57: how RFC 8032
/// Section 5.2.6 reduces the digests `r` and `k` (steps 3 and 5).
///
/// Constant time: a fixed sequence of shifts, masks and 64-bit multiplications by the digits of
/// `2^446 - L`, with the final correction applied through a mask, on the assumption the `nat`
/// module header states for its own multiplications: a multiply whose time does not depend on
/// its operands. The working digits are wiped on return.
pub(super) fn reduce_912(n: &[u8; 2 * SCALAR_LEN], r: &mut [u8; SCALAR_LEN]) {
    /// `x[i]` goes away, for `i >= 16`: its weight `2^(28 i)` is `2^448 * 2^(28 (i - 16))`.
    #[inline(always)]
    fn fold(x: &mut [i64; 33], i: usize) {
        let x_i = x[i];
        for (x_j, c4_j) in x[i - 16..i - 8].iter_mut().zip(C4_DIGITS) {
            *x_j += x_i * c4_j;
        }
    }

    /// Moves what `x[i]` holds above its low 28 bits into `x[i + 1]`.
    #[inline(always)]
    fn carry(x: &mut [i64; 33], i: usize) {
        x[i + 1] += x[i] >> 28;
        x[i] &= M28;
    }

    // n in radix 2^28, x[i] at weight 2^(28 i). To start with the even digits hold 32 bits,
    // overlapping the digit above by four, and the odd digits 24 bits moved up by four to make
    // room for them; x[32] is the last two octets. Every digit stays non-negative, and below
    // 2^60, until the final correction.
    let mut x = Secret::<[i64; 33]>::new();
    for j in 0..16 {
        let at = 7 * j;
        x[2 * j] = u32::from_le_bytes([n[at], n[at + 1], n[at + 2], n[at + 3]]) as i64;
        x[2 * j + 1] = (u32::from_le_bytes([n[at + 4], n[at + 5], n[at + 6], 0]) << 4) as i64;
    }
    x[32] = u16::from_le_bytes([n[112], n[113]]) as i64;

    // Digits 32 down to 17 fold away, each brought back to 28 bits (when it holds more) before
    // it multiplies the digits of 4 c, so that no digit outgrows an i64.
    fold(&mut x, 32);
    carry(&mut x, 30);
    fold(&mut x, 31);
    fold(&mut x, 30);
    carry(&mut x, 28);
    fold(&mut x, 29);
    fold(&mut x, 28);
    carry(&mut x, 26);
    fold(&mut x, 27);
    fold(&mut x, 26);
    carry(&mut x, 24);
    fold(&mut x, 25);
    for i in 20..24 {
        carry(&mut x, i);
    }
    fold(&mut x, 24);
    fold(&mut x, 23);
    fold(&mut x, 22);
    for i in 17..21 {
        carry(&mut x, i);
    }
    fold(&mut x, 21);
    fold(&mut x, 20);
    fold(&mut x, 19);
    for i in 14..18 {
        carry(&mut x, i);
    }
    fold(&mut x, 18);
    fold(&mut x, 17);

    // What is left at and above 2^446, the top two bits of digit 15 and digit 16, is q units
    // of 2^446. q + 1 times c goes on below: one c too many, which makes the sum reach 2^446
    // exactly when the remainder would otherwise have been L or more.
    let q = (x[16] << 2) + (x[15] >> 26);
    x[15] &= M26;
    for (x_j, c_j) in x[..8].iter_mut().zip(C_DIGITS) {
        *x_j += (q + 1) * c_j;
    }
    for i in 0..15 {
        carry(&mut x, i);
    }

    // The carry out at 2^446, less one, is 0 when the sum reached 2^446, and dropping that
    // 2^446 with the extra c has subtracted L; or -1 when it did not, and then the extra c
    // comes back off, by mask.
    let short = (x[15] >> 26) - 1;
    debug_assert!(short == 0 || short == -1);
    x[15] &= M26;
    for (x_j, c_j) in x[..8].iter_mut().zip(C_DIGITS) {
        *x_j -= short & c_j;
    }
    for i in 0..15 {
        carry(&mut x, i);
    }
    debug_assert_eq!(x[15] >> 26, 0);

    // Digits 0 to 15 pack in pairs into seven octets each; the last octet is zero.
    for j in 0..8 {
        let pair = (x[2 * j] | x[2 * j + 1] << 28) as u64;
        for (b, r_b) in r[7 * j..7 * j + 7].iter_mut().enumerate() {
            *r_b = (pair >> (8 * b)) as u8;
        }
    }
    r[SCALAR_LEN - 1] = 0;
}

/// `S = (r + k * s) mod L` (RFC 8032 Section 5.2.6, step 5), for `r` and `k` already reduced
/// and `s` the secret scalar, each in 57 octets with the last zero.
///
/// Constant time: [`nat::mul_add_to`] and [`reduce_912`]. `r`, `s` and the 896-bit sum are
/// held in [`Secret`]s; `k` and `S` are public.
///
/// A `Secret` wipes the memory it names, and the compiler also keeps limbs of `s` and of the
/// sum in registers, which it spills to the frames of the computation: Ed25519's version of
/// this function was seen to leave limbs of `s` on the dead stack that way. So the computation
/// runs in a frame of its own and the stack it used is overwritten afterwards.
#[allow(non_snake_case)]
pub(super) fn calculate_S(
    r: &[u8; SCALAR_LEN],
    k: &[u8; SCALAR_LEN],
    s: &[u8; SCALAR_LEN],
    S: &mut [u8; SCALAR_LEN],
) {
    calculate_S_in_own_frame(r, k, s, S);
    wipe_stack_below::<WIPED_STACK_WORDS>();
}

/// How much stack [`wipe_stack_below`] overwrites, in 64-bit words: more than
/// [`calculate_S_in_own_frame`] and everything it calls use, with room for a compiler that
/// lays the frames out less tightly.
const WIPED_STACK_WORDS: usize = 256;

/// The computation of [`calculate_S`]. Never inlined, so that what it spills lies below its
/// caller's frame, where [`wipe_stack_below`] reaches it.
#[allow(non_snake_case)]
#[inline(never)]
fn calculate_S_in_own_frame(
    r: &[u8; SCALAR_LEN],
    k: &[u8; SCALAR_LEN],
    s: &[u8; SCALAR_LEN],
    S: &mut [u8; SCALAR_LEN],
) {
    // t = r, widened to hold the sum
    let mut t = Secret::<[u64; SIZE * 2]>::new();
    decode_into(r, &mut *t);

    let mut k_limbs = [0_u64; SIZE];
    decode_into(k, &mut k_limbs);
    let mut s_limbs = Secret::<[u64; SIZE]>::new();
    decode_into(s, &mut *s_limbs);

    // t += k * s. No carry out: r, k < 2^446 and s < 2^448.
    let carry = nat::mul_add_to(&k_limbs, &*s_limbs, &mut *t);
    debug_assert_eq!(carry, 0);

    // The 896 bits of t, widened to the 912 that reduce_912 takes.
    let mut wide = Secret::<[u8; 2 * SCALAR_LEN]>::new();
    for (octets, limb) in wide.as_chunks_mut::<8>().0.iter_mut().zip(t.iter()) {
        *octets = limb.to_le_bytes();
    }
    reduce_912(&wide, S);
}

/// Recodes a scalar `z < 2^448`, in the low seven limbs of `z`, for a multiplication by
/// signed digits: on return bit `i` of `z` stands for the digit `+1` when set and `-1` when
/// clear, at weight `2^i`, and the [`SIGNED_DIGITS`] digits sum to the scalar mod L.
///
/// An even `z` first has L added, which makes it odd without changing it mod L. An odd `z`
/// is `sum((2 b_i - 1) 2^i)` over 450 digits for `b = (z + 2^450 - 1) / 2`, which is `z` with
/// bit 450 set, shifted down a bit. Constant time; `z` stays in the caller's buffer.
pub(super) fn to_signed_digits(z: &mut [u64; SIZE + 1]) {
    let is_even = !Condition::<u64>::is_bit_set(z[0], 0);
    // The sum is below 2^449, so the carry out of the seven limbs is its bit 448.
    let carry = nat::cadd_to(is_even, &L, z);
    z[SIZE] = (1 << (SIGNED_DIGITS - 64 * SIZE)) + carry;

    let out = nat::shift_down_bit(z, 0);
    debug_assert_eq!(out, 1 << 63);
}

/// The width-`width` wNAF of L, for the subgroup check of a public key.
pub(super) fn get_order_wnaf_var(width: usize, ws: &mut [i8; 447]) {
    wnaf::get_signed_var(&L, width, ws);
}

/// `x * y mod L` for `x < L` and a signed `y` in four limbs of two's complement. Variable
/// time.
pub(super) fn multiply_225_var(x: &[u64; SIZE], y225: &[u64; 4]) -> [u64; SIZE] {
    // The product as if y were unsigned, in eleven limbs.
    let mut tt = [0_u64; SIZE + 4];
    nat::mul(x, y225, &mut tt);

    // A negative y was read 2^256 too high: take x * 2^256 back off, and add L * 2^256 so that
    // the total stays non-negative.
    if (y225[3] as i64) < 0 {
        nat::add_to(&L, &mut tt[4..]);
        nat::sub_from(x, &mut tt[4..]);
    }

    // The 704 bits of tt, widened to the 912 that reduce_912 takes.
    let mut wide = [0_u8; 2 * SCALAR_LEN];
    for (octets, limb) in wide.as_chunks_mut::<8>().0.iter_mut().zip(tt) {
        *octets = limb.to_le_bytes();
    }
    let mut reduced = [0_u8; SCALAR_LEN];
    reduce_912(&wide, &mut reduced);

    let mut z = [0_u64; SIZE];
    decode_into(&reduced, &mut z);
    z
}

/// Splits `k` into two signed scalars `(v0, v1)` of at most 225 bits with their sign, in four
/// limbs of two's complement, such that `v1 * k == v0 (mod L)` and `v1` is not zero, so that
/// verification can run its three scalar multiplications at half length. `None` if the
/// reduction has not finished within its iteration bound, which is not known to happen.
///
/// This is the lattice basis reduction of Pornin (<https://ia.cr/2020/454>), on the lattice
/// spanned by `u = (L, 0)` and `v = (k, 1)`. It carries the squared norms `nu`, `nv` and the
/// inner product `p` of the two vectors, and takes `2^s` times the shorter from the longer
/// until the shorter fits. Variable time: `k` is public.
pub(super) fn reduce_basis_var(k: &[u64; SIZE]) -> Option<([u64; 4], [u64; 4])> {
    /// The squared norm to stop at: both coordinates of `v` are then below `2^224` in
    /// magnitude.
    const TARGET_LENGTH: usize = 447;

    let mut nu = L_SQ;

    let mut nv = [0_u64; SIZE * 2];
    nat::square(k, &mut nv);
    // v = (k, 1), so its squared norm is k^2 + 1. The 1 is not decoration: the loop stops on
    // the norm, and it is the norm being exact that bounds both coordinates of the result.
    // Without it the reduction still ends on a valid pair for the inputs tried, so no test
    // tells the difference; with a wrong norm the bound is no longer a proof.
    // A square is 0, 1 or 4 mod 8, so the addition cannot carry.
    debug_assert!(nv[0] & 7 < 7);
    nv[0] += 1;

    let mut p = [0_u64; SIZE * 2];
    nat::mul(&L, k, &mut p);

    // Only the low 256 bits of the coordinates are kept; the final ones fit them.
    let (mut u0, mut u1) = ([L[0], L[1], L[2], L[3]], [0_u64; 4]);
    let (mut v0, mut v1) = ([k[0], k[1], k[2], k[3]], [1_u64, 0, 0, 0]);

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
        add_shifted_var(subtract, 3, s, &v0, &mut u0);
        add_shifted_var(subtract, 3, s, &v1, &mut u1);

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
    // crates/ed448, module `scalar_448` and `calculate_S`): edge values around L and the digit
    // boundaries, the rest from splitmix64 with a fixed seed. Printed by a scratch program
    // (`kat-gen scalar`, not in this repository), and checked there against Python integers.
    // Scalars are little-endian octets in hexadecimal.

    // (n, n mod L)
    const REDUCE_KATS: &[(&str, &str)] = &[
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            concat!(
                "81dee731a93f88112e1dad8707160f80293ea637fb19e320c5b624bb85c972cf17ae447cc4a34bc1",
                "9c1aaf70d0e4b7bc522029b723f8392900",
            ),
        ),
        (
            concat!(
                "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
        ),
        (
            concat!(
                "f44458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000020000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000002000",
            ),
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "0cbba7546d3d87dcaa703a728d3d93de6fc92951b624b13b16dc3583000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000040000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "0dbba7546d3d87dcaa703a728d3d93de6fc92951b624b13b16dc3583000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "33ec9e52b5f51c72abc2e9c835f64c7abf25a744d992c4ee5870d70c020000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000010000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000",
            ),
            concat!(
                "34ec9e52b5f51c72abc2e9c835f64c7abf25a744d992c4ee5870d70c020000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000800000",
            ),
            concat!(
                "b0cd4d822bc9a9f1eccad8e0259679bd2c0c75c4116fb3061c6c722fb9e70b57223ee2d1a5604e8d",
                "573868f25b5e299094db11fc9c54011a00",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000080",
            ),
            concat!(
                "41eff398d41fc408978ed6c3038b07c0141fd39bfd8c7190625b92ddc264b9e70b57223ee2d1a560",
                "4e8d573868f25b5e299094db11fc9c1400",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000000000000000000000000000000000000000000000ff",
            ),
            concat!(
                "f28304cecfff139077b89b0659c740b5c9399a5b5022173aa7ac893abc56a3b76969c8b720588a24",
                "826b3ea0eb2cfb6932f771932bbe902600",
            ),
        ),
        (
            concat!(
                "1d1118ca4b60b04ddd8dac600c8e516b0da6d678b3878c8916ed493295dce2531495cdc8b60c8af6",
                "fc5ab5c22b79582b09917470ebfe8b029b7b3b0905309db99cd9e570b83cbca8822eefe0bc525886",
                "ce66a8301ecb80e5cdc8161ec55f16296472623e63d6ecea44fc63a10854ff64f53e",
            ),
            concat!(
                "e8280cecf8b8de328e0e34b2d188b57a79bb9700c16b35a45edeb119a01fc6133ff96048996308d5",
                "0228da52744539a1ad45bd8b7c8e9c3700",
            ),
        ),
        (
            concat!(
                "fe6bfdb1f61024bce1cd9c92e6aa73d419c987f02347042f9a5e7fb1e6d2f2cef8d30999d75b9f5b",
                "8d99c553bb9df39763524264bd7c29e69386ffefcd478b20baa608dbddafba6f20549b9149572e82",
                "9f7c36f7c9cd51d09983f7e546b34caabc7a34e5a52402d3a2f8c36b43ef03b81a31",
            ),
            concat!(
                "bc5819e08bba0bf538e36c40eed2e960094aee52c916e4a4d9b46319d784bc518c0226f0a986034b",
                "7857ee004f9978c301fe58c4e55fd81800",
            ),
        ),
        (
            concat!(
                "52625781be22c3b9a43aca4926a721bb50d07d98d9fd31db9ff1e7b6f235aac9d1cd19ead0e4c151",
                "8ddaece9b77b1fb32e007ae6451455e7656f016c788e3eeca9b973406cc4aff229b014224bc6d24f",
                "925da148b3e2f605ea7a82f154bc1f5c5ec87d9592b57ca5926e12ad8871eafa511a",
            ),
            concat!(
                "a65511d826f7cd806fbc0abbfd67e647ccedb07e62364b5679544d1a52490f8dfb7845bdf2786d57",
                "969469ebb61d22576882f42ee32e6f2b00",
            ),
        ),
        (
            concat!(
                "f0d055927601666d6f77cee74f59386bd51e1b2f14419a5772a96be7ec8b7547fe9b1dcf46b8edd0",
                "4938d290c04cd0d983426b534f877bcef312eca02a9e71144ace30edb6b87715785ac7874b090fce",
                "e0cc7146e44ce8637c6de3a1a6b5131dbe914574af50be1598636ced78369c9c7acc",
            ),
            concat!(
                "9471fc877c8b4ae407af75ae2b175a5e523cf80e1ddb1ece7575cc80156328f1ec5336dbfaed6eb6",
                "6c8ac10e3806c6337213ad950ca0b53a00",
            ),
        ),
        (
            concat!(
                "a3e62db30a92786ef3a03c96e3b56189b73fab4b8685347f65dd2b60f87da1c1d5297304aa227a7d",
                "2beced0277ad4937b56dcb4a86183812641d2f3c146c6a723b92909d43cf54b3c1d80fe21031a7a1",
                "544fbe0bbc41e12f0bedec34a4da9852aa3004b4a93730b058e0ad9a5229fe4b1d75",
            ),
            concat!(
                "b4af01de9479dc15970ace84571e718bda229b65f5e71b2e0f655ca614eea40673780e53daaaa495",
                "2b84875c87c6cc88e0f4a7d030c1710500",
            ),
        ),
        (
            concat!(
                "1c512f5eee4dde3519434b5db645ecddf73a23f85ebfa42d2538d6e419607287653b22df947f70f9",
                "3048f5999771674533381ef4d25330ef64c2e5c83f9871ea6dda29557e164e0de570016011e247cc",
                "1a0d7e4f34c1d0f820d7a0d5a6802cdb2d940c441ebbf3a48f5152ce05cec392d0de",
            ),
            concat!(
                "b8a4bf0fbb71eb32fc567392bf8426da982f25e5f5d2c95dd18d6903c0ea91b0fd71d2826cf6c3b0",
                "770c7a992af0446e66f8d21e1bee0b3600",
            ),
        ),
        (
            concat!(
                "1ef23059759b68c1feaf7f171e8ad0c870ef6e07dc3fcf51bc3fa5d9dda6eeff8011afc1e427b12e",
                "d67537fe65f4752a80532e97878e1ee78feae88ac72d26b5029ed58539f0685f0dcbb32b21679022",
                "a4e4c9fea1faadb55fecaa5ff15e629172e748d827685041ec2860959f70accf2765",
            ),
            concat!(
                "295a1edfaf4d684cce5b24d0fef8295629fe8b976b7c907f151a53a78ec69d78c07fcdaad82491a2",
                "4e3f044424a51fed2fe8bb34ff56022e00",
            ),
        ),
        (
            concat!(
                "a96c05b3be19bec506ac9b33d91ec332b63678df5a42797a8cf7bd4518053b41af01d92817d0588d",
                "d69cc6ab7d1cd32b63582ff92259891f125cb6898bc42cbb6495e9af90a36d93d1da9a136067ec61",
                "b307410d9d367c5a1c10ea93c0228bccda6ef248afdac9f3b648e5249e71b86b87cb",
            ),
            concat!(
                "ecab6436775891b0727795421859c94bddff52d1d476e783f607e7529b4c50163d2da8836a95c6bd",
                "1df45660d20bfb0b5e19636ac8b8d23c00",
            ),
        ),
        (
            concat!(
                "c9b6fe561efa947ad7c64c435452dd9ba773a33fe39ef80739c09ab743521c6e75d323c8e42fefdf",
                "663bff05c3e086aae01435d5c6430e9aab8acc7a86c78de834d76bab5c98162dd57e56542aeb51a6",
                "8806d6cb97db1487a1cb626267639abc072e737aa0bceb07ab96e99c5350b1212360",
            ),
            concat!(
                "3292a1da8599da30601b33f1ae03284bc6b650fb6cc0b3a7a9162e7ea7153d840fc940f3f4c1d7c5",
                "4bf2ccd2c2298cd91b9bc45baab19d0700",
            ),
        ),
        (
            concat!(
                "33ce7e9a44d934a6affeaa2aa84e7b849820f2d444653409513fa0b41ba777cf1a02342699a3af8a",
                "507e23dcb9efe1f742dc3d58eb10e28ca32324c6fe1c443647ab3fe5aedb7b142098d5ac030ef214",
                "9062c4af5be00b0b47705eff7cf120804b18dbc5ac3a110fa60ade1e19215f5a3cae",
            ),
            concat!(
                "f1192883423a5fc1dd8e276d8cfd28badeac6411d50179a635bc0dbfe27ae1ff0c28aca948e55c4a",
                "54f43dc049b3e148f4c79a52db5a403600",
            ),
        ),
        (
            concat!(
                "ec04783ccef7903c7c1d0c9d6c5ffa5d51474443ff26b291be7b9f67e31b39844bb84440cd379063",
                "384343e9f3a84b361abb01b2eb3b2d8bf2819cc1347f167143b8df85c6ad2df105a8f29c8acf5d60",
                "ec45d05260f24ab6cc6712feba6b420a3318fcf1366e85e76710d18fa94ebd07556d",
            ),
            concat!(
                "9e8e465dc401622c7d80ec41f1f94a04033e9801df670aa1093b9a8d5f265c74d596db01d81ebb62",
                "eaa75e740a74830565c1eb0c6235523c00",
            ),
        ),
        (
            concat!(
                "dbd3047e85a7e260fe047c4fdeaf9c5ae68b1f4dd3e53fb12172390386ec71c226f98c2f56c2f050",
                "040780002fc2f085f5dc1bb7a8013457fad6cf7149ca0f8386bf026d610120bf1e96d20ef79691eb",
                "0bc3e3f9e82260e51cb797fdd70711631f558feeae021142ea59e4f90d14caaafacf",
            ),
            concat!(
                "d8c262cb1420741b9d100f5b3c615e5e5e049cfd223350c87defa72cab4e6ba1ca099588d4eeb0fc",
                "5499535f2876be25f12ae193546e360900",
            ),
        ),
    ];

    // (r, k, s, S = (r + k * s) mod L)
    const S_KATS: &[(&str, &str, &str, &str)] = &[
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            concat!(
                "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            concat!(
                "c258b958ddcc5bb1a9ccdbc43ccc1fa7d0102f6a70488ad590b3f26ffdffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000008000",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            concat!(
                "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
        ),
        (
            concat!(
                "4bb16c9e282adecb6c2db248cace3a5f8b8643e39abde6e66e0b2a7f0e9b02d4b5bee56a0a318a42",
                "e0736a0cdd1cd5f5803cf0bbad33de1800",
            ),
            concat!(
                "eb84fe18303f37c99a6ad8f668b9b5e49cff87638f346c1cda81fc1f2fb08d8d1fb6e8f730f45c70",
                "47035b6c5408dd3e9905479c4b20662e00",
            ),
            concat!(
                "50e90f6d2c541e7c1af03706ff120464d1ab5add620d12343c96962a2573e9c4d79e79c14932552c",
                "4d85ee80c19806942198a41be96c3dbd00",
            ),
            concat!(
                "fdcf52e2bd0dc8765956d556b509768d0bcc66cac138aca5aabf99199c1b304106ba6adfc6a1eb83",
                "d531674e9708fb5f44d9d1bef8c7d22100",
            ),
        ),
        (
            concat!(
                "e3acc8d9c7b2a25029ecf8bf11852ffd4e1e2e5747693486c8449838e8a78b9c141b7527642242dd",
                "e710ea9e5b1d426fb6dbd4b781cd543000",
            ),
            concat!(
                "65806cebdf12492a1eed54a0edc90ecad4987944698e8ed137662f0aa88084a347c86a117d496f5a",
                "6e844714b20961f067a8970103f7f52b00",
            ),
            concat!(
                "7ca0b53b25e3038aa43f21f7dfbfdfd6f3de3fd7432eb2f8cb090a515ab0bf06fdb85e64d786a1a0",
                "0c07f021cc462d09d15f19cd73053b8200",
            ),
            concat!(
                "ea7536e13d57154563e9e147af26442912e742f6a0731cc1184cbc5cc1cf19b76ffc6bd1e34f5176",
                "97ac69979a46107c6344166a5897691b00",
            ),
        ),
        (
            concat!(
                "3a8d281dd0da3ffb409582b11ac694088814150f1aeee19ba7de9bc2ac46cc4d0ffc7815249485a1",
                "94251ab9cb87541ca0b67571e6ef6e1d00",
            ),
            concat!(
                "918a169be77d55275405cd4cd1cffe64d83dc17517bb811bc82efe15b4241fa9fee88ccf3de1a6e5",
                "9e231c5652f46c11c0e3e5fc3f12072d00",
            ),
            concat!(
                "b09508d591ebff0f93d54b1e017251d8f59db7b88037c18ae19c45b3efe6ff991c269d2277829a79",
                "8d7badee7abe73871dca0ea5cf94a6d900",
            ),
            concat!(
                "cf4366e82f9eed6e54c2de67630784f11c6128632c2fb83e00ebdc6e9cef17a1ea835709b65151aa",
                "06883af967e92a0a3d8ca7ce2596d93800",
            ),
        ),
        (
            concat!(
                "72cb9e98be1d3fa5156b509c5a4fc7fb3ae3a08af149a9c1672e9a56bd05329d0bea7281a736df3b",
                "1902b677119c9585f7d58970962dfe1700",
            ),
            concat!(
                "05e52642b957b9e48e4b7a7a9d91ecdccab2a1d18ac430573f594ab1126b6d1007f7d95ea7aef237",
                "bfde1858e1e61b1dfcc9fd5e946efc3000",
            ),
            concat!(
                "b82964af4cb1e24a719646c1c7e9faf5a2131be6d10251712c383ffef7555a9bbccbebd3c391824e",
                "f4d15b651c13f839a112734b77297c8900",
            ),
            concat!(
                "26d7def19cdafa007c8ec3ccd9f42a8c598ebf589583f312a0d0103ae188e64b0c468f839df450c1",
                "736311f5ef059d6b9522303b8e7ca21f00",
            ),
        ),
        (
            concat!(
                "b5c6ae299546ffacd559d8a87c212be3f086663fae056c9fa3e7055d9f1d7067e661d8812018f033",
                "b02a7c9db8c5a251bfe56740ba74a80500",
            ),
            concat!(
                "b53627d6b46f8cb5903fb89c9c1b18315095a008ed8bbb8e4a76d42dc1319bf07b6bdcfca36acfe5",
                "c6115d0e18930015a4e59ec70fdcad0d00",
            ),
            concat!(
                "d4af8624965dd64cefedeff474a9ce500584cf9e88e17fcb0a54592b728c406cbcb3986e31a5c024",
                "92a1ae4a6e968e2be3d2b3e1a454a0eb00",
            ),
            concat!(
                "0742484e5950c353b4804047d3053d31dad422de3dc21744ead75f218b2da8e7eda16636c6930226",
                "bf8f46a69989b302e094135d7bedca0700",
            ),
        ),
        (
            concat!(
                "10ec2fb872567b9e597e6bb5a40e36db31c5ce71931452b8a55edb4c0b11f5485e4a00a8d1587733",
                "5af111c274532166fafd661ab356c93a00",
            ),
            concat!(
                "dd4362e23887489aa4cfde062db6c0cf47ed31a75a215780e1acccfe88fcfcbe900b32533543f34c",
                "67a31b9427c32e11828ec4ee10498e1900",
            ),
            concat!(
                "20e0ca6fc7f929265a9027594fa41134fb64a4b52c79ca2200a0055d6705746dc627378824ba4244",
                "220533ec6dd820ad01af9d219ab410ef00",
            ),
            concat!(
                "02bee6fff3aadcf41db7a9aafaab743c505c5608e95de855b380a18aaba9eb74c90129ced7c41422",
                "d37d3192c2cb455804a1440026ff160600",
            ),
        ),
        (
            concat!(
                "cc3fea711973b1402238fb864bca8e5043729d15db2d73b5eb460e02bbf81f3b47143d1d55a7c9c4",
                "a403324d2d30e54c489d1eeeb238d32e00",
            ),
            concat!(
                "94c0bbdaa41ea8654ebf7f76fc7296a5bad9b3e7e5be56afe628a16a3735f93705066d47f867ec88",
                "337a939f86cba316de689a959852e22200",
            ),
            concat!(
                "80171063e1191ae155784c5e8f919476097579cbbb1fa1e3cb265a7ae7c597a9ea9f289b93b60736",
                "0a42c6769b93a482f4221282715adbe500",
            ),
            concat!(
                "0fd647ec7d35dd03497a079f7ce19a72fb25b7a1fbf96223287cbe2494538db9504c8a413e8fdb04",
                "b4c3714358da4029dd0a4481305eda3500",
            ),
        ),
        (
            concat!(
                "bc5d2076728a1ae5abd35c526f36b8fb12314c5ceb3b125bce901179d14491991120520ff6f10a21",
                "eb7323cf117cd9dcfcf4448d7b3b1f0b00",
            ),
            concat!(
                "f5bc35ebc243802c01256910e7cf5b1330db9b3a0dea501d1ef89fdf3ae0b61b6c28e67420062018",
                "ac5378772215589e95068c8e80c67d1700",
            ),
            concat!(
                "b0aac3378bc30286b817c81a6c5efd72d6a36ead4280ecce604d80cf19b3e49cc85865fc84ead141",
                "dcf466529fb04ba6a994bd9eb11ceaf000",
            ),
            concat!(
                "dddd38b8f413ff07d9dc86fb77a282d6ebff5328bc9fbaf3ca128e7ebb71e861bab508c4eef67a33",
                "16791346f4a0b2c633d6e2c910b8e30300",
            ),
        ),
    ];

    // (z in 56 octets, z recoded in 64)
    const SIGNED_DIGITS_KATS: &[(&str, &str)] = &[
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
            ),
            concat!(
                "7922ac554961bc91aac7e2463961b610481b6bd7a46d27e2f41165beffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff1f0200000000000000",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f",
            ),
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f0200000000000000",
            ),
        ),
        (
            concat!(
                "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff",
            ),
            concat!(
                "7722ac554961bc91aac7e2463961b610481b6bd7a46d27e2f41165beffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff9f0200000000000000",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000080",
            ),
            concat!(
                "7922ac554961bc91aac7e2463961b610481b6bd7a46d27e2f41165beffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff5f0200000000000000",
            ),
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff",
            ),
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff7f0200000000000000",
            ),
        ),
        (
            concat!(
                "16160b13fe8dbfa5d64b5124b022e64c716a49cb46b5126408cd339bd974fca7314964a02a895062",
                "6b5516b02bc0231cfa90093a00a3cc14",
            ),
            concat!(
                "84ad315f48289ce4956d0b59917229b780d00f3d48c8301479f8fe8b6c3afed398243250954428b1",
                "b52a0bd815e0110e7dc8041d8051662a0200000000000000",
            ),
        ),
        (
            concat!(
                "d890695f6cfc472e9cf48f7e897b5e57768dd3c67bb99f0ac4112185ebc771610e33723161f9d2ae",
                "9b945e0f3db2c37e2f4120df984bfcea",
            ),
            concat!(
                "e5ea60857f5fe0a8f8c12a06fe9e653c03e2d4ba624a77e7d69af580f5e3b8308719b998b07c69d7",
                "4d4aaf871ed961bf9720906fcc257e950200000000000000",
            ),
        ),
        (
            concat!(
                "63e4ba83c9bf2672fbd0087931efc6a4c8505eb11403e6b685311f4a23093d5200b7d5ee66cda0bb",
                "6fbcae06930b7454ab012881dfbdec3a",
            ),
            concat!(
                "3172ddc1e45f13b97d6884bc987763526428af588a0173dbc2980fa591841e2980db6a77b366d0dd",
                "375e5783c9053aaad50094c0ef5e761d0200000000000000",
            ),
        ),
        (
            concat!(
                "7ce6ec2643703fd9f4bd4f7583aaf0fb19e56fffe494c7f6b4cc863832efb70e87cd28bcfa19e7cc",
                "dec35698613c481c587166e1e38379d5",
            ),
            concat!(
                "b79522e96a195cfea4a68a017bb6ae0ed50d235717388b5d4f78a8da98f75b87c366145efd8c7366",
                "ef612bcc301e240eac38b3f0f1c1bc8a0200000000000000",
            ),
        ),
        (
            concat!(
                "a80c49d82433285757f9846eae7c3e9e906f139b53f99dcde9dee19fcda794dc2173ad126f7394eb",
                "feb02d471a4d7e16b202f8a64b88a620",
            ),
            concat!(
                "cda8d0c1db7a503d5644257e909fd55f10d3f4a44e6af6c86901568ee6534aee90b95689b739ca75",
                "7fd896238d263f0b59017cd3254453300200000000000000",
            ),
        ),
        (
            concat!(
                "b810fd8d25bf8cad83179ae1c34004dc8c5c1f95f2bc9193dce8b184074ecaf270e8fe12971b7d24",
                "0f5ff0bffc6e93fa0ce8f9838cacd2b3",
            ),
            concat!(
                "d5aaaa1cdcc082686cd3af379b81b87e8ec9fa211e4cf02b6306be800327657938747f89cb8d3e92",
                "872ff85f7eb7497d06f4fc414656e9790200000000000000",
            ),
        ),
        (
            concat!(
                "e7f78ecfd1fc5807ef76e3a8648bf2363241dc5dbf6d11ac9650a761f806f408e1d936a729c94303",
                "f20dba8c9ba55fe753b63bd88fd2ca19",
            ),
            concat!(
                "f37bc7e7687eac8377bb7154b245791b9920eeaedfb608564ba8d3307c037a84f06c9bd394e4a101",
                "f9065dc6cdd2aff329db1dec4769e50c0200000000000000",
            ),
        ),
        (
            concat!(
                "1c3e4ba1a28d6b5d6195b43b91b0162ac21af3f264c417194637ea4a527b15262ff055e260bc9919",
                "9834fb2ed2bcd93e5f791310a7d575f3",
            ),
            concat!(
                "87c151a61a2872405b12bde481b9c125a9a8e450d74fb3ee972ddae3a8bd0a9317f82a7130decc0c",
                "4c9a7d1769de6c9fafbc0988d3eaba990200000000000000",
            ),
        ),
    ];

    // (x, y as 32 octets of two's complement, x * y mod L)
    const MULTIPLY_225_KATS: &[(&str, &str, &str)] = &[
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000",
            concat!(
                "f44458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cfeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "00000000000000000000000000000000000000000000000000000000ffffffff",
            concat!(
                "00000000000000000000000000000000000000000000000000000000010000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "0100000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "00000000000000000000000000000000000000000000000000000000ffffffff",
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "6528979d9600c2d4ec5c25738990d6ccf27a2c76a28b020aa436fa159454e33ca55073c21c3d3baa",
                "d57a252dd1008c38c20b940c56820f1f00",
            ),
            "b561b762fc6275c8d8ebba0d3fa9cbc98b0b430e55ce7b72096936e300000000",
            concat!(
                "435de666baa1480cb62f6a6ff6729c34ad0c1cd85d5aaa9ddc9f9eb13fede424440b776c97596aaf",
                "4dc2f5c34ee5d0104ae0a61d128bf80e00",
            ),
        ),
        (
            concat!(
                "07fdb2be821dcf838b741750c33e01a174e035467513cb1592f717b8388c5fdc708826fe7b823296",
                "e8628232038354782822b21d2fa68a2500",
            ),
            "f132095baa376c967a0c794cce1b70eb38bffa561967115c2d4b6d5500000000",
            concat!(
                "341c9212afe6cb13cf7940f03ae84a88bf030deaa785c267d63afae92bc51dfc00d2a909c660de53",
                "f87b51b7c2be69a80d709359938b5d2900",
            ),
        ),
        (
            concat!(
                "5c4c0e015007268d682528fe188242a0b514e31f6780d09903f9c429a300e4f2a6f570c219ac5425",
                "aa1c8a3ea8020cdc6d3d11fd6858c53700",
            ),
            "18cab131b08ce3d68b1cca575c6b732b6b305f668e866c9af97a9a9d00000000",
            concat!(
                "572d026ced41c54cab4b90d402b7723f80854bf6cd9cb32d43f6b00336da85d8400eade2e6c4e159",
                "7ffb02e67add7cbe3130c69e5e31f22400",
            ),
        ),
        (
            concat!(
                "5cb99965a64e30f2cbf8b5394576302dea55fd79f735f11652a022d9471f149665e4f3c4142e618c",
                "caf5a0f667027bee7e0a9e8801f7621600",
            ),
            "5f984d7dbbce196817375a4b8266e14928d1bee7f688d8648dc34955ffffffff",
            concat!(
                "001ed39119abb6b0cd8922417eee97629e76461593dea58aa55bff329e18def9c669d9aa1c5cb0f0",
                "97cb8baaeb79d49a6b465bd151ff8b3700",
            ),
        ),
        (
            concat!(
                "ac05a37a9f727c577f0af9cc1f0910007192f4136bd017b38389ab1beca5fb27cbb5838fd8de52a1",
                "6ba567a267fc3c67997acbc9b3866e3d00",
            ),
            "f0d694fd88e4dbb8caa1bbec12891345afda746e390df3bf61ef3b0700000000",
            concat!(
                "79ba6f4cde2f1912d1618e88dd831fc78b38b3cbc91c8bb7bf6b4c0008cf1e58b0ca2b20d4e137eb",
                "0efb336cbcb0d6d9e94cbbf6e9a34d3600",
            ),
        ),
        (
            concat!(
                "4f9e123b51f2959f0e08eda06623b1d09f08a8e216b9883439f45f614d651383dd49544a282bbd95",
                "180d0ae159b74f9edbe5dfc38b0cdf1d00",
            ),
            "c11b56bb5768ecff3700e9f6c0bae9cc64a9576968f441a6c3d90b2200000000",
            concat!(
                "ee25a6dff72856c2de0695b93b912b2e0c6a853ec324120a5defef365b78501f6293154753df7389",
                "1c4463c69357855a9d60fa32a7d08f1300",
            ),
        ),
        (
            concat!(
                "b2dce7abbd84308595bbca9265f145c2e720cf5f7eef370f1db6d2661917cad19e964d234172cc4f",
                "85b50183a68c2664b3926c7283512c1800",
            ),
            "c1f892bf6d68ee7e1a4e890f5d5933c128c3705faf4360fa9c9858c000000000",
            concat!(
                "1762d68bc0a19f7e0bf7158c9af9ecb45ef41ec2bd2982b6809bd680478199df4d8e3d49162baee9",
                "0470629f56919be57774e56bde44061e00",
            ),
        ),
        (
            concat!(
                "0fcf0fa6d06ca25c2ee82c3b71ef981ea54bfb14240c9136411e0887a57f1b6d60f51e9ef09f644f",
                "8dc6d3dac201aa98184e2d1545f4c53500",
            ),
            "4455fdbe0bfde1ec74253a9dc3fd6168f0fe7d7aea6df14ac9ac804bffffffff",
            concat!(
                "1c581e33f16078dc005b2bf040bcf500f7b810b4fdea60606d45222fc654b5e7f31bea2ea06d4d09",
                "1c916509a41f5df3f50fa85f1258023400",
            ),
        ),
    ];

    // (k, v0, v1), v0 and v1 as 32 octets of two's complement
    const BASIS_KATS: &[(&str, &str, &str)] = &[
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000010000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7c00000000",
            "010000000000000000000000000000000000000000000000000000c0ffffffff",
        ),
        (
            concat!(
                "820b0f296bfaa00378289d66b0835034e39ce308fc0cf7b0b9409383ed2758dd36938e0c8a4998ba",
                "57e662775b2ff19129447d661a5ee11b00",
            ),
            "1f8d3c668b6271df16da1cadf1ea5830766b6a60e9e978d88e4ce03e00000000",
            "3be8cf6892ff9148756dcf1db1096ad8566e00e68d9c0c53ee54afd4ffffffff",
        ),
        (
            concat!(
                "e5f1dffa639fc3ef26da3af3fd22f1193a9824be82fe165bd869d0fa66b24c374a56905cc11a314d",
                "db616a27e3fea9cb95d6e53d1c531b0100",
            ),
            "31bf9d9e233d6ad1d9598310b66d0c351af147ebb25ea40e0de79b8900000000",
            "05fa06d1b520bced7f70fd7fb438a0562f8fc4d1100e0ec5dbd1152c00000000",
        ),
        (
            concat!(
                "ce78f2d3f737259d54761d473c6e04706a25d4ea0324338d929d739a915f8808e2ef83606802681b",
                "fe61e9bc9a8d3f805bf0de0cd984640600",
            ),
            "ab033a40a9a91da42e5cd4fcd6008634b56a636b7afa3dcc30884e6f00000000",
            "bed91101053c6c51fe2f43031171eba468ce861d4faafce937eb1e5400000000",
        ),
        (
            concat!(
                "1947cfb1eed0a5692a1e58d7c26f23929ee7584e82043558f49548ae1ecf0c07714d3cbd6bd13886",
                "55e23f6875559bc9629c02090622990e00",
            ),
            "6b0c95501e2919c322faee2c427db958e1312bad09aa1cbf84b57e3b00000000",
            "fed19f383ff24e6f3ebebee44ebebe597e70918c8dbb3658cc6f48c4ffffffff",
        ),
        (
            concat!(
                "46fc89c39c867447647bed7332d102ba134a0d3e4ca5e7f5e445f6260884795e7aa689e1a6c9d4ec",
                "d61937c567c8e439d1f55f53ba611c3a00",
            ),
            "6b0e9ad8807930f14579b07123111b2a294489f3c5709d310bc45793ffffffff",
            "0c674c85cc9d6c9f033468e378236066c8781e8efe2511fb3d047b2b00000000",
        ),
        (
            concat!(
                "d6855eef2cfd1d7b12aa64748989b2ae25c23453b15ba18478f7984ba33de878739494b288bec14e",
                "11f2e9e4b9af54227bdd9ceffd28e62e00",
            ),
            "114ceaf35551a5dc97c8aa71c7d401519c283337c7a1655c241538f9ffffffff",
            "2c3406e9728f92e0a8f0f46b71e80ec0f13a2179e62552361fcf282b00000000",
        ),
        (
            concat!(
                "7a68b46b7769cd3ea0c29004d9fa85780de02ed1dfea4c4bc5d260e4ac1c1eeb923780802c6a7b23",
                "de5c4a610a4d828f3a3105dd9cbdd03500",
            ),
            "dd5db26d0919f0b874a552488e8ce697eab9e64f855be66d0a698e2600000000",
            "ece4fb754b66b8f49c84e34819381ca91f35271650d233564d941a2200000000",
        ),
        (
            concat!(
                "7628f3f51333c4e676f3e6deabe419aee8829b49549c8336a3a460b061d6c5ab190440190ec77066",
                "1e728edebd917766a5b5ea73b5ddde1b00",
            ),
            "ffa3ce4f682a2dda15e50bcdb9df7a658143786e3562265292810577ffffffff",
            "fe5ef7fa79a837158364a0d6b24bef8786d4c3d03d0279e8bf5e25bfffffffff",
        ),
        (
            concat!(
                "7a5e6181e88d7540a3fac588ab0a27b67ad0a2919cec7d6702b50c1fb23701d330e14317953f0b15",
                "62b60b35899df266f70af427f8d7253c00",
            ),
            "1d5355f1b559e71483f165c1a42f31ecc223779112af0b5f9c7ee257ffffffff",
            "712f8a1f7bbe956f4d565c35e73aabc1e5b471b2d01d63b11f33fee2ffffffff",
        ),
        (
            concat!(
                "81e475aa97efa7f5402a921c8c50b44aa8575270d464e08e53ebfcff8578832bdd555be910a2add6",
                "0c8cad51226bca8828d47b088481013c00",
            ),
            "3d7f06ae53d17e1504626c3dec1b2d943b75108e55a9cad0049f4d2c00000000",
            "473b921a59625f6b1f0230c1689f9d5108b0ed2d2cf9c9cc0463831f00000000",
        ),
        (
            concat!(
                "d53d2f3e3c95c21f5ce40e7a635932e2ca48ab2bc5983c23ea16db37a40b9eb2bd781ccf61903b22",
                "55fb4027967c591935d4945343dd801200",
            ),
            "34d317c4e6ca07ff1df471e088255ae307b3ba2495fa738e889a1c0300000000",
            "6d11afca6a9f91cdaa0a5039cd7e75f9b9642d1c27af3ada1b69265100000000",
        ),
        (
            concat!(
                "c46f2775fdec3d9f03d788c47c7d54903c78fa441053645d20a8852074c2ec7c168d165ade5a158f",
                "8b22d8108426bdd0020545f4101b1b1500",
            ),
            "dbb75c029eec2c5d2ee21a5ae625f7677470a9d2df4a10b5085f420b00000000",
            "ccdace89e90a28c348fe80f2dd5b28b8ed59da44e5b2ed580ee778c0ffffffff",
        ),
    ];

    /// `2^446 - L`, in decimal (RFC 8032 Section 5.2, Table 2, lifted from the RFC text by
    /// script).
    const TWO_446_MINUS_L: &str =
        "13818066809895115352007386748515426880336692474882178609894547503885";

    fn octets<const N: usize>(hex: &str) -> [u8; N] {
        bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn limbs(k: &[u8; SCALAR_LEN]) -> [u64; SIZE] {
        let mut n = [0_u64; SIZE];
        decode_into(k, &mut n);
        n
    }

    fn to_octets(n: &[u64]) -> Vec<u8> {
        n.iter().flat_map(|limb| limb.to_le_bytes()).collect()
    }

    /// The limbs as an encoded scalar: 56 octets and a zero.
    fn scalar_octets(n: &[u64; SIZE]) -> [u8; SCALAR_LEN] {
        let mut k = [0_u8; SCALAR_LEN];
        k[..56].copy_from_slice(&to_octets(n));
        k
    }

    /// Little-endian octets, a multiple of eight of them, as limbs.
    fn to_limbs<const N: usize>(octets: &[u8]) -> [u64; N] {
        let (chunks, rest) = octets.as_chunks::<8>();
        assert!(rest.is_empty());
        core::array::from_fn(|i| u64::from_le_bytes(chunks[i]))
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

    fn random_reduced(state: &mut u64) -> [u8; SCALAR_LEN] {
        let mut r = [0_u8; SCALAR_LEN];
        reduce_912(&random_octets(state), &mut r);
        r
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
        mul_mod(&[1, 0, 0, 0, 0, 0, 0], n)
    }

    /// `-a mod L` for `a < L`.
    fn neg_mod(a: &[u64; SIZE]) -> [u64; SIZE] {
        let mut l_minus_1 = L;
        l_minus_1[0] -= 1;
        // -a = a * (L - 1)
        mul_mod(a, &to_octets(&l_minus_1))
    }

    /// The sign and the magnitude of a number in four limbs of two's complement.
    fn sign_and_magnitude(y: &[u64; 4]) -> (bool, [u64; 4]) {
        let negative = (y[3] as i64) < 0;
        let mut magnitude = *y;
        if negative {
            for limb in &mut magnitude {
                *limb = !*limb;
            }
            assert_eq!(nat::add_to(&[1, 0, 0, 0], &mut magnitude), 0);
        }
        (negative, magnitude)
    }

    /// A signed number in four limbs of two's complement, mod L.
    fn signed_256_mod(y: &[u64; 4]) -> [u64; SIZE] {
        let (negative, magnitude) = sign_and_magnitude(y);
        let reduced = mod_l(&to_octets(&magnitude));
        if negative { neg_mod(&reduced) } else { reduced }
    }

    /// A decimal number as limbs.
    fn decimal(digits: &str) -> [u64; SIZE] {
        let mut n = [0_u64; SIZE];
        for c in digits.bytes() {
            let mut carry = (c - b'0') as u128;
            for limb in &mut n {
                carry += *limb as u128 * 10;
                *limb = carry as u64;
                carry >>= 64;
            }
            assert_eq!(carry, 0);
        }
        n
    }

    /// Radix-2^28 digits as limbs: `sum(digits[i] * 2^(28 i))`.
    fn from_digits(digits: &[i64; 8]) -> [u64; SIZE] {
        let mut n = [0_u64; SIZE];
        for (i, &digit) in digits.iter().enumerate() {
            let (limb, shift) = (28 * i / 64, 28 * i % 64);
            let mut shifted = [0_u64; SIZE];
            let wide = (digit as u128) << shift;
            shifted[limb] = wide as u64;
            shifted[limb + 1] = (wide >> 64) as u64;
            assert_eq!(nat::add_to(&shifted, &mut n), 0);
        }
        n
    }

    #[test]
    fn the_constants_are_those_of_the_group_order() {
        // RFC 8032 Section 5.2, Table 2: L = 2^446 - 138180668098951153520073867485154268803366
        // 92474882178609894547503885.
        let c = decimal(TWO_446_MINUS_L);
        let mut sum = L;
        assert_eq!(nat::add_to(&c, &mut sum), 0);
        assert_eq!(sum, [0, 0, 0, 0, 0, 0, 1 << 62]);

        let mut l_squared = [0_u64; SIZE * 2];
        nat::square(&L, &mut l_squared);
        assert_eq!(L_SQ, l_squared);

        assert_eq!(from_digits(&C_DIGITS), c);
        assert!(C_DIGITS.iter().all(|digit| (0..1 << 28).contains(digit)));
        // 4 c, by adding c to itself twice over.
        let mut c4 = c;
        for _ in 0..2 {
            let addend = c4;
            assert_eq!(nat::add_to(&addend, &mut c4), 0);
        }
        assert_eq!(from_digits(&C4_DIGITS), c4);
        assert!(C4_DIGITS[..7].iter().all(|digit| (0..1 << 28).contains(digit)));

        assert_eq!((SCALAR_LEN, SIGNED_DIGITS), (57, 450));
    }

    #[test]
    fn reduce_912_matches_the_prototype() {
        for (n, expected) in REDUCE_KATS {
            let mut r = [0xA5_u8; SCALAR_LEN];
            reduce_912(&octets(n), &mut r);
            assert_eq!(r, octets::<SCALAR_LEN>(expected), "{n}");
        }
    }

    /// Against the bit-at-a-time reference: the known-answer inputs, multiples of L and their
    /// neighbours (where the final correction decides), single digits at each weight, and
    /// pseudo-random values.
    #[test]
    fn reduce_912_agrees_with_the_reference() {
        let mut inputs: Vec<[u8; 114]> = REDUCE_KATS.iter().map(|(n, _)| octets(n)).collect();

        // j * L - 1, j * L and j * L + 1 for multipliers j of every length up to 2^466.
        let mut state = 0x7265_6475_6365;
        for bits in (1..=466).step_by(5) {
            let mut j = random_octets::<64>(&mut state);
            for (i, octet) in j.iter_mut().enumerate() {
                if 8 * i >= bits {
                    *octet = 0;
                } else if 8 * i + 8 > bits {
                    *octet = (*octet | 0x80) >> (8 * i + 8 - bits);
                }
            }
            let mut multiple = [0_u64; 15];
            nat::mul(&L, &to_limbs::<8>(&j), &mut multiple);
            let mut one = [0_u64; 15];
            one[0] = 1;
            let (mut below, mut above) = (multiple, multiple);
            nat::sub_from(&one, &mut below);
            nat::add_to(&one, &mut above);
            for n in [below, multiple, above] {
                // 912 bits: fourteen limbs and two octets.
                assert_eq!(n[14] >> 16, 0);
                let mut input = [0_u8; 114];
                input.copy_from_slice(&to_octets(&n)[..114]);
                inputs.push(input);
            }
        }
        // 2^(28 i) - 1 and 2^(28 i): one digit, and every digit below it full.
        for i in 0..=32 {
            let mut power = [0_u8; 114];
            power[28 * i / 8] = 1 << (28 * i % 8);
            let mut below = [0_u8; 114];
            for bit in 0..28 * i {
                below[bit / 8] |= 1 << (bit % 8);
            }
            inputs.push(power);
            inputs.push(below);
        }
        for _ in 0..300 {
            inputs.push(random_octets(&mut state));
        }

        for n in &inputs {
            let mut r = [0x5A_u8; SCALAR_LEN];
            reduce_912(n, &mut r);
            assert_eq!(r[SCALAR_LEN - 1], 0);
            assert_eq!(limbs(&r), mod_l(n), "{n:02x?}");
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn calculate_S_matches_the_prototype_and_the_reference() {
        for (r, k, s, expected) in S_KATS {
            let mut S = [0xA5_u8; SCALAR_LEN];
            calculate_S(&octets(r), &octets(k), &octets(s), &mut S);
            assert_eq!(S, octets::<SCALAR_LEN>(expected), "{r} {k} {s}");
        }

        let mut state = 0x5F53;
        for _ in 0..40 {
            let (r, k) = (random_reduced(&mut state), random_reduced(&mut state));
            // s is any 448-bit value here, wider than a pruned scalar; the sum still fits.
            let mut s: [u8; SCALAR_LEN] = random_octets(&mut state);
            s[SCALAR_LEN - 1] = 0;
            let mut S = [0xA5_u8; SCALAR_LEN];
            calculate_S(&r, &k, &s, &mut S);
            assert_eq!(S[SCALAR_LEN - 1], 0);
            assert_eq!(limbs(&S), add_mod(&limbs(&r), &mul_mod(&limbs(&k), &s)));
        }
    }

    /// The recoded bits, read as 450 digits of +1 and -1, sum to the scalar mod L.
    #[test]
    fn to_signed_digits_matches_the_prototype_and_recodes_the_same_scalar() {
        let mut two_450 = [0_u8; 57];
        two_450[56] = 4;
        for (z, expected) in SIGNED_DIGITS_KATS {
            let z: [u8; 56] = octets(z);
            let mut n = [0_u64; SIZE + 1];
            n[..SIZE].copy_from_slice(&to_limbs::<SIZE>(&z));
            to_signed_digits(&mut n);
            assert_eq!(to_octets(&n), octets::<64>(expected));
            // No digit beyond the 450.
            assert_eq!(n[SIZE] >> (SIGNED_DIGITS - 448), 0);

            // sum((2 b_i - 1) 2^i) = 2 b + 1 - 2^450
            let mut twice_plus_one = [0_u8; 65];
            let mut carry = 1_u8;
            for (out, octet) in twice_plus_one.iter_mut().zip(to_octets(&n)) {
                *out = octet << 1 | carry;
                carry = octet >> 7;
            }
            twice_plus_one[64] = carry;
            let sum = add_mod(&mod_l(&twice_plus_one), &neg_mod(&mod_l(&two_450)));
            assert_eq!(sum, mod_l(&z));
        }
    }

    #[test]
    fn decode_canonical_var_accepts_exactly_the_values_below_the_order() {
        let mut l_minus_1 = L;
        l_minus_1[0] -= 1;
        let accepted = [
            [0_u64; SIZE],
            [1, 0, 0, 0, 0, 0, 0],
            l_minus_1,
            [u64::MAX, u64::MAX, u64::MAX, 0, 0, 0, 0],
        ];
        for n in accepted {
            assert_eq!(decode_canonical_var(&scalar_octets(&n)), Some(n), "{n:x?}");
        }

        let mut l_plus_1 = L;
        l_plus_1[0] += 1;
        let rejected = [
            L,
            l_plus_1,
            [0, 0, 0, 0, 1, 0, 1 << 62], // above L in the fifth limb only
            [0, 0, 0, 0, 0, 0, (1 << 62) + 1], // above L in the top limb only
            [L[0], L[1], L[2], L[3], L[4], L[5], L[6] + (1 << 62)], // 2^446 + L
            [u64::MAX; SIZE],
        ];
        for n in rejected {
            assert_eq!(decode_canonical_var(&scalar_octets(&n)), None, "{n:x?}");
        }

        // Anything in the last octet is 2^448 or more, whatever the limbs hold: 2^448 + S for
        // a small S, and the top bit alone.
        for last in [0x01, 0x80, 0xFF] {
            for n in accepted {
                let mut s = scalar_octets(&n);
                s[SCALAR_LEN - 1] = last;
                assert_eq!(decode_canonical_var(&s), None, "{n:x?} {last:#x}");
            }
        }
    }

    /// The width-5 wNAF of the order sums back to L, with every digit odd and below 16.
    #[test]
    fn the_order_wnaf_is_that_of_l() {
        let mut ws = [1_i8; 447];
        get_order_wnaf_var(5, &mut ws);
        assert!(ws.iter().all(|&w| w == 0 || (w & 1 == 1 && w.unsigned_abs() < 16)));

        // From the top down the running value 2 acc + w stays positive.
        let mut acc = [0_u64; SIZE];
        for &w in ws.iter().rev() {
            let copy = acc;
            assert_eq!(nat::add_to(&copy, &mut acc), 0);
            let digit = [w.unsigned_abs() as u64];
            if w < 0 {
                assert_eq!(sub_small(&digit, &mut acc), 0);
            } else {
                assert_eq!(add_small(&digit, &mut acc), 0);
            }
        }
        assert_eq!(acc, L);
    }

    /// `z += x` for a one-limb `x`, over the whole of `z`; the carry out.
    fn add_small(x: &[u64; 1], z: &mut [u64; SIZE]) -> u64 {
        let mut wide = [0_u64; SIZE];
        wide[0] = x[0];
        nat::add_to(&wide, z)
    }

    /// `z -= x` for a one-limb `x`, over the whole of `z`; the borrow out.
    fn sub_small(x: &[u64; 1], z: &mut [u64; SIZE]) -> i64 {
        let mut wide = [0_u64; SIZE];
        wide[0] = x[0];
        nat::sub_from(&wide, z)
    }

    #[test]
    fn multiply_225_var_matches_the_prototype_and_the_reference() {
        let mut rows: Vec<([u8; SCALAR_LEN], [u64; 4])> = Vec::new();
        for (x, y, expected) in MULTIPLY_225_KATS {
            let (x, y) = (octets(x), to_limbs::<4>(&octets::<32>(y)));
            let z = multiply_225_var(&limbs(&x), &y);
            assert_eq!(scalar_octets(&z), octets::<SCALAR_LEN>(expected), "{x:x?} {y:x?}");
            rows.push((x, y));
        }
        // Pseudo-random 225-bit multipliers of both signs.
        let mut state = 0x6D75_6C32_3235;
        for _ in 0..30 {
            let top = ((next(&mut state) as i64) >> 31) as u64;
            let y = [next(&mut state), next(&mut state), next(&mut state), top];
            rows.push((random_reduced(&mut state), y));
        }
        for (x, y) in &rows {
            let z = multiply_225_var(&limbs(x), y);
            assert_eq!(z, mul_mod(&signed_256_mod(y), &x[..56]), "{x:x?} {y:x?}");
        }
    }

    /// The outputs are the prototype's, and on those and further inputs `v1 * k == v0 (mod L)`
    /// with `v1` not zero and the vector short enough.
    #[test]
    fn reduce_basis_var_matches_the_prototype_and_satisfies_its_congruence() {
        let quarter = |v: &str| to_limbs::<4>(&octets::<32>(v));
        let mut ks: Vec<[u8; SCALAR_LEN]> = Vec::new();
        for (k, v0, v1) in BASIS_KATS {
            let k = octets(k);
            assert_eq!(reduce_basis_var(&limbs(&k)), Some((quarter(v0), quarter(v1))), "{k:02x?}");
            ks.push(k);
        }
        let mut state = 0x0062_6173_6973;
        for _ in 0..100 {
            ks.push(random_reduced(&mut state));
        }
        // Short scalars, which need few steps or none.
        for bits in [1, 64, 222, 223, 224, 225, 300] {
            let mut k = [0_u8; SCALAR_LEN];
            k[bits / 8] = 1 << (bits % 8);
            ks.push(k);
        }

        for k in &ks {
            let (v0, v1) = reduce_basis_var(&limbs(k)).unwrap();
            assert_ne!(v1, [0; 4], "{k:02x?}");
            assert_eq!(mul_mod(&signed_256_mod(&v1), &k[..56]), signed_256_mod(&v0), "{k:02x?}");
            // v0^2 + v1^2 has at most 447 bits, so each is below 2^224 in magnitude: 225 bits
            // with its sign, which is what the recoding of the multiplication has room for.
            let mut norm = [0_u64; 9];
            for v in [v0, v1] {
                let (_, magnitude) = sign_and_magnitude(&v);
                let mut square = [0_u64; 8];
                nat::square(&magnitude, &mut square);
                norm[8] += nat::add_to(&square, &mut norm[..8]);
                assert_eq!(magnitude[3] >> 32, 0, "{k:02x?}");
            }
            assert!(norm[8] == 0 && norm[7] == 0 && norm[6] >> 63 == 0, "{k:02x?}");
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
