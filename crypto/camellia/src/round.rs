//! The components of Camellia (RFC 3713 Sec 2.4) -- the F-function, the FL- and FLINV-functions
//! -- and the data randomizing part (Sec 2.3) that runs them, on four blocks at once.

use crate::LANES;
use crate::camellia::Block;
use crate::sbox::sboxes;

/// `F(F_IN, KE)` (Sec 2.4.1) on four blocks at once: `f_in[b]` is `F_IN` for block `b`, and
/// `ke` is the same 64-bit subkey for all four.
///
/// Line by line against Sec 2.4.1: `x = F_IN ^ KE`; `t1 .. t8` are the bytes of `x`, most
/// significant first, and go through `SBOX1, SBOX2, SBOX3, SBOX4, SBOX2, SBOX3, SBOX4, SBOX1`
/// respectively -- that is [`sboxes`], on all four blocks in one pass; `y1 .. y8` and `F_OUT`
/// are the linear map [`p`], per block. The blocks never mix.
pub(crate) fn f(f_in: &[u64; LANES], ke: u64) -> [u64; LANES] {
    // x = F_IN ^ KE
    let mut x = f_in.map(|d| d ^ ke);
    // t1 = SBOX1[t1]; ... t8 = SBOX1[t8]
    sboxes(&mut x);
    // y1 .. y8, F_OUT
    x.map(p)
}

/// `F(F_IN, KE)` on one 64-bit word, for the key schedule (Sec 2.2), where `F` is applied to
/// `D1`/`D2` with the `Sigma` constants as keys.
///
/// The circuit always processes four lanes; the one word is placed in every lane and lane 0 is
/// read back. All four lanes then hold the same result, which `test_f1_lanes_agree` checks.
pub(crate) fn f1(f_in: u64, ke: u64) -> u64 {
    f(&[f_in; LANES], ke)[0]
}

/// The linear part of the F-function, Sec 2.4.1's `y1 .. y8` from `t1 .. t8`:
///
/// ```text
/// y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
/// y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
/// y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
/// y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
/// F_OUT = (y1 << 56) | (y2 << 48) | ... | y8
/// ```
///
/// Computed on the two 32-bit halves `u = (t1, t2, t3, t4)` and `v = (t5, t6, t7, t8)` with five
/// rotations and four XORs instead of forty byte XORs. It is the same map: expanding the
/// rotations byte by byte gives exactly the eight sums above, and
/// `test_p_matches_the_rfc_formula` checks it on every single-bit input (which, `p` being linear,
/// determines it) and on random ones.
#[inline(always)]
fn p(t: u64) -> u64 {
    let (mut u, mut v) = ((t >> 32) as u32, t as u32);
    v = v.rotate_left(8);
    u ^= v;
    v = v.rotate_left(8) ^ u;
    u = u.rotate_right(8) ^ v;
    let hi = v.rotate_left(16) ^ u;
    let lo = u.rotate_left(8);
    ((hi as u64) << 32) | lo as u64
}

/// `FL(FL_IN, KE)` (Sec 2.4.2):
///
/// ```text
/// x1 = FL_IN >> 32;  x2 = FL_IN & MASK32;  k1 = KE >> 32;  k2 = KE & MASK32;
/// x2 = x2 ^ ((x1 & k1) <<< 1);
/// x1 = x1 ^ (x2 | k2);
/// FL_OUT = (x1 << 32) | x2;
/// ```
///
/// AND and OR with key words, and a rotation: no table and no branch, so constant-time as it
/// stands.
#[inline(always)]
pub(crate) fn fl(fl_in: u64, ke: u64) -> u64 {
    let (mut x1, mut x2) = ((fl_in >> 32) as u32, fl_in as u32);
    let (k1, k2) = ((ke >> 32) as u32, ke as u32);
    x2 ^= (x1 & k1).rotate_left(1);
    x1 ^= x2 | k2;
    ((x1 as u64) << 32) | x2 as u64
}

/// `FLINV(FLINV_IN, KE)` (Sec 2.4.2), the inverse of [`fl`]:
///
/// ```text
/// y1 = y1 ^ (y2 | k2);
/// y2 = y2 ^ ((y1 & k1) <<< 1);
/// ```
#[inline(always)]
pub(crate) fn flinv(flinv_in: u64, ke: u64) -> u64 {
    let (mut y1, mut y2) = ((flinv_in >> 32) as u32, flinv_in as u32);
    let (k1, k2) = ((ke >> 32) as u32, ke as u32);
    y1 ^= y2 | k2;
    y2 ^= (y1 & k1).rotate_left(1);
    ((y1 as u64) << 32) | y2 as u64
}

/// The data randomizing part (Sec 2.3.1 for 18 rounds, Sec 2.3.2 for 24) on four blocks at once,
/// with the subkeys supplied by three accessors: `kw(i)` for `kw1 .. kw4`, `k(i)` for
/// `k1 .. k_rounds`, and `ke(i)` for `ke1 .. ke_m` (`m = 4` or `6`), all 1-based as the RFC
/// numbers them. Encryption passes the schedule's own order; decryption passes the swapped order
/// of Sec 2.3.3 (see [`crate::Camellia::decrypt_4blocks`]).
///
/// Line by line against Sec 2.3.1 / 2.3.2:
///
/// * `D1 = M >> 64; D2 = M & MASK64` -- the block as two big-endian 64-bit words;
/// * `D1 = D1 ^ kw1; D2 = D2 ^ kw2` -- prewhitening;
/// * round `i`: `D2 = D2 ^ F(D1, k_i)` for odd `i`, `D1 = D1 ^ F(D2, k_i)` for even `i`;
/// * after rounds 6, 12 (and 18 when there are 24), `D1 = FL(D1, ke_{2m-1}); D2 = FLINV(D2, ke_{2m})`
///   for the `m`-th FL layer -- "FL- and FLINV-functions inserted every 6 rounds", but not after
///   the last round;
/// * `D2 = D2 ^ kw3; D1 = D1 ^ kw4` -- postwhitening;
/// * `C = (D2 << 64) | D1` -- the halves swap on output.
///
/// The RFC writes the 18 or 24 rounds out longhand; this is the same sequence as a loop over a
/// public round counter. The four blocks are processed together only because [`f`] is: the
/// F-function's argument is formed per block, all four go through the S-box layer in one pass,
/// and everything else is per block. `tests/rfc3713_tests.rs` pins the result in every lane.
pub(crate) fn rounds(
    blocks: &mut [Block; LANES],
    num_rounds: usize,
    kw: impl Fn(usize) -> u64,
    k: impl Fn(usize) -> u64,
    ke: impl Fn(usize) -> u64,
) {
    // D1 = M >> 64; D2 = M & MASK64, per block.
    let mut d1 = [0u64; LANES];
    let mut d2 = [0u64; LANES];
    for (b, block) in blocks.iter().enumerate() {
        // Sixteen bytes are exactly two eight-byte halves; the remainder is provably empty.
        let (halves, _) = block.as_chunks::<8>();
        d1[b] = u64::from_be_bytes(halves[0]);
        d2[b] = u64::from_be_bytes(halves[1]);
    }

    // Prewhitening.
    let (kw1, kw2) = (kw(1), kw(2));
    for b in 0..LANES {
        d1[b] ^= kw1;
        d2[b] ^= kw2;
    }

    for i in 1..=num_rounds {
        // Round i. Odd rounds write D2 from F(D1, k_i), even rounds write D1 from F(D2, k_i).
        if i % 2 == 1 {
            let f_out = f(&d1, k(i));
            for b in 0..LANES {
                d2[b] ^= f_out[b];
            }
        } else {
            let f_out = f(&d2, k(i));
            for b in 0..LANES {
                d1[b] ^= f_out[b];
            }
        }
        // FL / FLINV after every sixth round except the last.
        if i % 6 == 0 && i != num_rounds {
            let m = i / 6;
            let (ke1, ke2) = (ke(2 * m - 1), ke(2 * m));
            for b in 0..LANES {
                d1[b] = fl(d1[b], ke1);
                d2[b] = flinv(d2[b], ke2);
            }
        }
    }

    // Postwhitening, and C = (D2 << 64) | D1.
    let (kw3, kw4) = (kw(3), kw(4));
    for (b, block) in blocks.iter_mut().enumerate() {
        let (halves, _) = block.as_chunks_mut::<8>();
        halves[0] = (d2[b] ^ kw3).to_be_bytes();
        halves[1] = (d1[b] ^ kw4).to_be_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbox::tests::sboxes_table;

    /// Sec 2.4.1's `y1 .. y8`, written out literally, byte by byte.
    fn p_literal(x: u64) -> u64 {
        let [t1, t2, t3, t4, t5, t6, t7, t8] = x.to_be_bytes();
        let y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
        let y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
        let y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
        let y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
        let y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
        let y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
        let y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
        let y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
        u64::from_be_bytes([y1, y2, y3, y4, y5, y6, y7, y8])
    }

    /// Deterministic pseudo-random words (xorshift64), so the tests need no RNG crate.
    fn pseudo_random(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn test_p_matches_the_rfc_formula() {
        // p is linear, so agreement on the 64 unit vectors proves agreement everywhere; the random
        // words are a second, independent check of that reasoning.
        for i in 0..64 {
            assert_eq!(p(1 << i), p_literal(1 << i), "bit {i}");
        }
        let mut seed = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..1000 {
            let x = pseudo_random(&mut seed);
            assert_eq!(p(x), p_literal(x), "{x:#018x}");
        }
        assert_eq!(p(0), 0);
    }

    #[test]
    fn test_f_is_the_table_form_followed_by_p() {
        // F(F_IN, KE) = P(S(F_IN ^ KE)), per lane, against the table-driven S-box layer.
        let mut seed = 0x0123_4567_89AB_CDEF;
        for _ in 0..200 {
            let f_in: [u64; LANES] = core::array::from_fn(|_| pseudo_random(&mut seed));
            let ke = pseudo_random(&mut seed);
            let got = f(&f_in, ke);
            for b in 0..LANES {
                assert_eq!(got[b], p_literal(sboxes_table(f_in[b] ^ ke)), "lane {b}");
            }
        }
    }

    #[test]
    fn test_f1_lanes_agree() {
        // The single-word F fills all four lanes with the same word; every lane must come back
        // identical, or lane 0 would not be a valid answer.
        for (x, ke) in [(0u64, 0u64), (u64::MAX, 0), (0x0123_4567_89AB_CDEF, 0xA09E_667F_3BCC_908B)]
        {
            let all = f(&[x; LANES], ke);
            assert!(all.iter().all(|&w| w == all[0]), "lanes disagree for {x:#018x}");
            assert_eq!(f1(x, ke), all[0]);
            assert_eq!(f1(x, ke), p_literal(sboxes_table(x ^ ke)));
        }
    }

    #[test]
    fn test_flinv_inverts_fl() {
        // Sec 2.4.2: "FLINV-function is the inverse function of the FL-function."
        let mut seed = 0xDEAD_BEEF_CAFE_F00D;
        for _ in 0..1000 {
            let x = pseudo_random(&mut seed);
            let ke = pseudo_random(&mut seed);
            assert_eq!(flinv(fl(x, ke), ke), x);
            assert_eq!(fl(flinv(x, ke), ke), x);
        }
        // And neither is the identity in general.
        assert_ne!(fl(0, u64::MAX), 0);
    }

    #[test]
    fn test_fl_matches_a_hand_worked_value() {
        // x1 = 0x0000_0001, x2 = 0, k1 = 0xFFFF_FFFF, k2 = 0:
        //   x2 = 0 ^ ((0x0000_0001 & 0xFFFF_FFFF) <<< 1) = 0x0000_0002
        //   x1 = 0x0000_0001 ^ (0x0000_0002 | 0) = 0x0000_0003
        assert_eq!(fl(0x0000_0001_0000_0000, 0xFFFF_FFFF_0000_0000), 0x0000_0003_0000_0002);
        // The rotation wraps: x1 = 0x8000_0000 gives x2 = 0x0000_0001.
        assert_eq!(fl(0x8000_0000_0000_0000, 0xFFFF_FFFF_0000_0000), 0x8000_0001_0000_0001);
    }
}
