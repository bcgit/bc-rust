//! The components of ARIA (RFC 5794 Sec 2.4) -- the substitution layers `SL1` / `SL2`, the
//! diffusion layer `A`, the round functions `FO` / `FE` -- and the data randomizing part (Sec 2.3)
//! that runs them, on four blocks at once.
//!
//! # State layout
//!
//! A 16-byte block `x0 || x1 || ... || x15` is held as four big-endian 32-bit *row words*
//! `t[i] = x{4i} || x{4i+1} || x{4i+2} || x{4i+3}`. The substitution layers assign S-boxes by byte
//! position modulo four (Sec 2.4.2: `SB1, SB2, SB3, SB4` repeating in `SL1`, `SB3, SB4, SB1, SB2`
//! in `SL2`), so the bytes that share an S-box are one *column* of the 4x4 byte matrix --
//! `x{j} || x{j+4} || x{j+8} || x{j+12}`, the *class word* `j`. [`transpose`] converts between the
//! two views so that each S-box circuit can be run once on a whole class word from each block.

use crate::LANES;
use crate::aria::Block;
use crate::bitslice::{Planes, ortho};
use crate::sbox::{sb1, sb2, sb3, sb4};

/// One block as four big-endian 32-bit words. See the module docs.
pub(crate) type State = [u32; 4];

/// A round key, in the same layout as [`State`].
pub(crate) type RoundKey = State;

/// Transposes the 4x4 byte matrix of a block: row words `t[i] = x{4i} .. x{4i+3}` become class
/// words `c[j] = x{j} || x{j+4} || x{j+8} || x{j+12}`, and back -- it is its own inverse.
///
/// Two stages of masked swaps: 16-bit halves between words two apart, then bytes between
/// adjacent words. `test_transpose_is_the_byte_transpose` pins it against a byte-by-byte
/// rearrangement. The `|`s join disjoint bit ranges, so `|` and `^` compute the same function
/// here (surviving `cargo mutants` equivalences, not gaps).
pub(crate) fn transpose(t: &mut State) {
    let [t0, t1, t2, t3] = *t;
    // Stage 1: (x0 x1 x2 x3),(x8 x9 x10 x11) -> (x0 x1 x8 x9),(x2 x3 x10 x11); likewise t1, t3.
    let a0 = (t0 & 0xFFFF_0000) | (t2 >> 16);
    let a2 = (t0 << 16) | (t2 & 0x0000_FFFF);
    let a1 = (t1 & 0xFFFF_0000) | (t3 >> 16);
    let a3 = (t1 << 16) | (t3 & 0x0000_FFFF);
    // Stage 2: (x0 x1 x8 x9),(x4 x5 x12 x13) -> (x0 x4 x8 x12),(x1 x5 x9 x13); likewise a2, a3.
    t[0] = (a0 & 0xFF00_FF00) | ((a1 >> 8) & 0x00FF_00FF);
    t[1] = ((a0 << 8) & 0xFF00_FF00) | (a1 & 0x00FF_00FF);
    t[2] = (a2 & 0xFF00_FF00) | ((a3 >> 8) & 0x00FF_00FF);
    t[3] = ((a2 << 8) & 0xFF00_FF00) | (a3 & 0x00FF_00FF);
}

/// Applies one S-box to all four bytes of one class word from each of the four blocks.
///
/// Each word is split into its two 16-bit halves -- the high halves in plane words `0 .. 4`, the
/// low halves in `4 .. 8` -- the eight half-words are transposed into bit-planes, every byte
/// position is substituted by one pass of the circuit, the planes are transposed back and the
/// halves rejoined. The byte order is irrelevant to the S-box, which substitutes each byte
/// independently; [`ortho`] being its own inverse returns each byte to its place.
fn substitute(words: &mut [u32; LANES], sbox: fn(&mut Planes)) {
    let mut q: Planes = [0; 8];
    for b in 0..LANES {
        q[b] = (words[b] >> 16) as u16;
        q[LANES + b] = words[b] as u16;
    }
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    for b in 0..LANES {
        // Disjoint bit ranges: `|` and `^` agree (a surviving `cargo mutants` equivalence).
        words[b] = ((q[b] as u32) << 16) | q[LANES + b] as u32;
    }
}

/// A substitution layer on four blocks: class word `j` of every block goes through `sboxes[j]`.
fn substitution_layer(s: &mut [State; LANES], sboxes: [fn(&mut Planes); 4]) {
    for st in s.iter_mut() {
        transpose(st);
    }
    for (j, sbox) in sboxes.into_iter().enumerate() {
        let mut class: [u32; LANES] = core::array::from_fn(|b| s[b][j]);
        substitute(&mut class, sbox);
        for b in 0..LANES {
            s[b][j] = class[b];
        }
    }
    for st in s.iter_mut() {
        transpose(st);
    }
}

/// `SL1` (Sec 2.4.2): `y{4k} = SB1(x{4k}), y{4k+1} = SB2(x{4k+1}), y{4k+2} = SB3(x{4k+2}),
/// y{4k+3} = SB4(x{4k+3})`, on four blocks.
pub(crate) fn sl1(s: &mut [State; LANES]) {
    substitution_layer(s, [sb1, sb2, sb3, sb4]);
}

/// `SL2` (Sec 2.4.2): `y{4k} = SB3(x{4k}), y{4k+1} = SB4(x{4k+1}), y{4k+2} = SB1(x{4k+2}),
/// y{4k+3} = SB2(x{4k+3})`, on four blocks. `SL2` is the inverse of `SL1`.
pub(crate) fn sl2(s: &mut [State; LANES]) {
    substitution_layer(s, [sb3, sb4, sb1, sb2]);
}

/// The diffusion layer `A` (Sec 2.4.3) on one block.
///
/// Sec 2.4.3 gives `A` as sixteen equations, each output byte the XOR of seven input bytes. This
/// computes the same 16x16 binary matrix in three word-level steps, the way the 32-bit
/// implementations of ARIA (OpenSSL's `aria.c`, the designers' reference code) do:
///
/// 1. within each row word, replace every byte by the XOR of the *other three* bytes of the
///    word -- `b ^ (b0 ^ b1 ^ b2 ^ b3)` for each byte `b`;
/// 2. six word XORs: `t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2`;
/// 3. byte permutations: swap adjacent bytes in `t1` (`abcd -> badc`), rotate `t2` by 16 bits
///    (`abcd -> cdab`), reverse `t3` (`abcd -> dcba`);
/// 4. the six word XORs of step 2 again.
///
/// The decomposition was **verified, not recalled**: the generator that produced this crate's
/// S-box circuits also checked this sequence against the sixteen equations of Sec 2.4.3 on every
/// one of the 128 unit vectors (`A` is linear, so that determines it) and on 1000 random blocks,
/// and `test_diffusion_matches_the_rfc_equations` repeats the check in Rust. `A` is an involution
/// (Sec 2.4.3, "x = A(A(x))"), which `test_diffusion_is_an_involution` checks.
///
/// The multiplication by `0x0101_0101` in step 1 broadcasts the parity byte to all four byte
/// positions; it cannot carry, since the operand is below 256.
pub(crate) fn diffuse(t: &mut State) {
    // 1. b_i ^= b0 ^ b1 ^ b2 ^ b3, per word.
    for w in t.iter_mut() {
        let mut parity = *w ^ (*w >> 16);
        parity ^= parity >> 8;
        *w ^= (parity & 0xFF).wrapping_mul(0x0101_0101);
    }
    // 2.
    word_mix(t);
    // 3. badc, cdab, dcba. (The `|` joins disjoint byte positions, so `|` and `^` agree here -- a
    //    surviving `cargo mutants` equivalence, like those in `transpose`.)
    t[1] = ((t[1] << 8) & 0xFF00_FF00) | ((t[1] >> 8) & 0x00FF_00FF);
    t[2] = t[2].rotate_right(16);
    t[3] = t[3].swap_bytes();
    // 4.
    word_mix(t);
}

/// The six word XORs of [`diffuse`].
#[inline(always)]
fn word_mix(t: &mut State) {
    t[1] ^= t[2];
    t[2] ^= t[3];
    t[0] ^= t[1];
    t[3] ^= t[1];
    t[2] ^= t[0];
    t[1] ^= t[2];
}

/// `D ^ RK`: the key addition inside `FO`, `FE` and the final round, on one block.
#[inline(always)]
fn add_key(s: &mut State, rk: &RoundKey) {
    for (w, k) in s.iter_mut().zip(rk.iter()) {
        *w ^= k;
    }
}

/// `FO(D, RK) = A(SL1(D ^ RK))` (Sec 2.4.1) on four blocks.
pub(crate) fn fo(s: &mut [State; LANES], rk: &RoundKey) {
    for st in s.iter_mut() {
        add_key(st, rk);
    }
    sl1(s);
    for st in s.iter_mut() {
        diffuse(st);
    }
}

/// `FE(D, RK) = A(SL2(D ^ RK))` (Sec 2.4.1) on four blocks.
pub(crate) fn fe(s: &mut [State; LANES], rk: &RoundKey) {
    for st in s.iter_mut() {
        add_key(st, rk);
    }
    sl2(s);
    for st in s.iter_mut() {
        diffuse(st);
    }
}

/// `FO` on one 128-bit value, for the key schedule (Sec 2.2, `W1 = FO(W0, CK1) ^ KR` and
/// `W3 = FO(W2, CK3) ^ W1`): the value goes in every lane and lane 0 comes back.
pub(crate) fn fo1(d: State, rk: &RoundKey) -> State {
    let mut s = [d; LANES];
    fo(&mut s, rk);
    s[0]
}

/// `FE` on one 128-bit value, for the key schedule (`W2 = FE(W1, CK2) ^ W0`).
pub(crate) fn fe1(d: State, rk: &RoundKey) -> State {
    let mut s = [d; LANES];
    fe(&mut s, rk);
    s[0]
}

/// The data randomizing part (Sec 2.3.1 for encryption, Sec 2.3.2 for decryption) on four blocks
/// at once, with `num_rounds` rounds (12, 14 or 16) and `key(i)` supplying round key `i` in
/// `1 ..= num_rounds + 1`: `ek_i` for encryption, `dk_i` for decryption (see
/// [`crate::ARIA::decrypt_4blocks`]).
///
/// Line by line against Sec 2.3.1.1 (the 192- and 256-bit versions only add rounds):
///
/// * `P1 = FO(P, ek1)` -- round 1, and every odd round `i`: `P_i = FO(P_{i-1}, ek_i)`;
/// * `P2 = FE(P1, ek2)` -- and every even round before the last: `P_i = FE(P_{i-1}, ek_i)`;
/// * `C = SL2(P_{n-1} ^ ek_n) ^ ek_{n+1}` -- the last round (`n` is even) substitutes without
///   diffusing and adds the extra round key.
///
/// The RFC writes the rounds out longhand; this is the same sequence as a loop over a public round
/// counter. The four blocks are processed together only because the substitution layers are: the
/// S-box circuits take one class word from each block per pass, and everything else is per block.
pub(crate) fn rounds(
    blocks: &mut [Block; LANES],
    num_rounds: usize,
    key: impl Fn(usize) -> RoundKey,
) {
    // P as four big-endian row words per block.
    let mut s = [[0u32; 4]; LANES];
    for (st, block) in s.iter_mut().zip(blocks.iter()) {
        // Sixteen bytes are exactly four four-byte words; the remainder is provably empty.
        let (words, _) = block.as_chunks::<4>();
        for (w, bytes) in st.iter_mut().zip(words) {
            *w = u32::from_be_bytes(*bytes);
        }
    }

    // Rounds 1 .. n-1: FO on odd rounds, FE on even rounds.
    for i in 1..num_rounds {
        let rk = key(i);
        if i % 2 == 1 {
            fo(&mut s, &rk);
        } else {
            fe(&mut s, &rk);
        }
    }

    // Round n: C = SL2(P_{n-1} ^ ek_n) ^ ek_{n+1}.
    let rk_n = key(num_rounds);
    let rk_last = key(num_rounds + 1);
    for st in s.iter_mut() {
        add_key(st, &rk_n);
    }
    sl2(&mut s);
    for (st, block) in s.iter_mut().zip(blocks.iter_mut()) {
        add_key(st, &rk_last);
        let (words, _) = block.as_chunks_mut::<4>();
        for (bytes, w) in words.iter_mut().zip(st.iter()) {
            *bytes = w.to_be_bytes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbox::tests::{SB1, SB2, SB3, SB4};

    /// Sec 2.4.3, the sixteen equations, byte by byte. Each row is the seven `x` indices.
    const A_ROWS: [[usize; 7]; 16] = [
        [3, 4, 6, 8, 9, 13, 14],
        [2, 5, 7, 8, 9, 12, 15],
        [1, 4, 6, 10, 11, 12, 15],
        [0, 5, 7, 10, 11, 13, 14],
        [0, 2, 5, 8, 11, 14, 15],
        [1, 3, 4, 9, 10, 14, 15],
        [0, 2, 7, 9, 10, 12, 13],
        [1, 3, 6, 8, 11, 12, 13],
        [0, 1, 4, 7, 10, 13, 15],
        [0, 1, 5, 6, 11, 12, 14],
        [2, 3, 5, 6, 8, 13, 15],
        [2, 3, 4, 7, 9, 12, 14],
        [1, 2, 6, 7, 9, 11, 12],
        [0, 3, 6, 7, 8, 10, 13],
        [0, 3, 4, 5, 9, 11, 14],
        [1, 2, 4, 5, 8, 10, 15],
    ];

    fn a_literal(x: &[u8; 16]) -> [u8; 16] {
        core::array::from_fn(|p| A_ROWS[p].iter().fold(0u8, |acc, &q| acc ^ x[q]))
    }

    fn to_state(x: &[u8; 16]) -> State {
        let (w, _) = x.as_chunks::<4>();
        core::array::from_fn(|i| u32::from_be_bytes(w[i]))
    }
    fn to_bytes(s: &State) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (chunk, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(s.iter()) {
            *chunk = w.to_be_bytes();
        }
        out
    }

    /// Deterministic pseudo-random bytes (xorshift32), so the tests need no RNG crate.
    fn pseudo_random<const N: usize>(seed: &mut u32) -> [u8; N] {
        core::array::from_fn(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 17;
            *seed ^= *seed << 5;
            (*seed >> 24) as u8
        })
    }

    #[test]
    fn test_diffusion_matches_the_rfc_equations() {
        // Linear, so the 128 unit vectors determine it; random blocks are an independent check.
        for byte in 0..16 {
            for bit in 0..8 {
                let mut x = [0u8; 16];
                x[byte] = 1 << bit;
                let mut s = to_state(&x);
                diffuse(&mut s);
                assert_eq!(to_bytes(&s), a_literal(&x), "unit vector byte {byte} bit {bit}");
            }
        }
        let mut seed = 0x1234_5678;
        for _ in 0..1000 {
            let x: [u8; 16] = pseudo_random(&mut seed);
            let mut s = to_state(&x);
            diffuse(&mut s);
            assert_eq!(to_bytes(&s), a_literal(&x));
        }
    }

    #[test]
    fn test_diffusion_is_an_involution() {
        let mut seed = 0x0BAD_F00D;
        for _ in 0..1000 {
            let x: [u8; 16] = pseudo_random(&mut seed);
            let mut s = to_state(&x);
            diffuse(&mut s);
            assert_ne!(to_bytes(&s), x);
            diffuse(&mut s);
            assert_eq!(to_bytes(&s), x);
        }
    }

    #[test]
    fn test_transpose_is_the_byte_transpose() {
        let x: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut s = to_state(&x);
        transpose(&mut s);
        // c[j] = x_j || x_{j+4} || x_{j+8} || x_{j+12}
        assert_eq!(s, [0x0004_080C, 0x0105_090D, 0x0206_0A0E, 0x0307_0B0F]);
        transpose(&mut s);
        assert_eq!(s, to_state(&x), "transpose must be an involution");
        let mut seed = 0xC0FF_EE00;
        for _ in 0..200 {
            let x: [u8; 16] = pseudo_random(&mut seed);
            let mut s = to_state(&x);
            transpose(&mut s);
            let expected: [u8; 16] = core::array::from_fn(|k| x[4 * (k % 4) + k / 4]);
            assert_eq!(to_bytes(&s), expected);
        }
    }

    /// `SL1` / `SL2` written literally from the tables of Sec 2.4.2, on one block.
    fn sl_literal(x: &[u8; 16], type1: bool) -> [u8; 16] {
        let order: [&[u8; 256]; 4] =
            if type1 { [&SB1, &SB2, &SB3, &SB4] } else { [&SB3, &SB4, &SB1, &SB2] };
        core::array::from_fn(|p| order[p % 4][x[p] as usize])
    }

    #[test]
    fn test_substitution_layers_match_the_tables_in_every_lane() {
        let mut seed = 0x5EED_5EED;
        for _ in 0..200 {
            let xs: [[u8; 16]; LANES] = core::array::from_fn(|_| pseudo_random(&mut seed));
            let mut s: [State; LANES] = core::array::from_fn(|b| to_state(&xs[b]));
            sl1(&mut s);
            for b in 0..LANES {
                assert_eq!(to_bytes(&s[b]), sl_literal(&xs[b], true), "SL1 lane {b}");
            }
            sl2(&mut s);
            for b in 0..LANES {
                assert_eq!(to_bytes(&s[b]), xs[b], "SL2 must invert SL1, lane {b}");
            }
            let mut s: [State; LANES] = core::array::from_fn(|b| to_state(&xs[b]));
            sl2(&mut s);
            for b in 0..LANES {
                assert_eq!(to_bytes(&s[b]), sl_literal(&xs[b], false), "SL2 lane {b}");
            }
        }
    }

    #[test]
    fn test_fo1_and_fe1_lanes_agree() {
        // The single-value forms fill all four lanes; every lane must come back identical.
        let d: State = [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F];
        let rk: RoundKey = [0x517c_c1b7, 0x2722_0a94, 0xfe13_abe8, 0xfa9a_6ee0];
        let mut s = [d; LANES];
        fo(&mut s, &rk);
        assert!(s.iter().all(|x| *x == s[0]));
        assert_eq!(fo1(d, &rk), s[0]);
        let mut s = [d; LANES];
        fe(&mut s, &rk);
        assert!(s.iter().all(|x| *x == s[0]));
        assert_eq!(fe1(d, &rk), s[0]);
        // And they match the literal definitions FO = A(SL1(D ^ RK)), FE = A(SL2(D ^ RK)).
        let xored: State = core::array::from_fn(|i| d[i] ^ rk[i]);
        let mut lit = to_state(&sl_literal(&to_bytes(&xored), true));
        diffuse(&mut lit);
        assert_eq!(fo1(d, &rk), lit);
        let mut lit = to_state(&sl_literal(&to_bytes(&xored), false));
        diffuse(&mut lit);
        assert_eq!(fe1(d, &rk), lit);
    }
}
