//! RIPEMD-160 and its 320-bit extension RIPEMD-320: two parallel lines of five 32-bit words and
//! 80 steps per block, following the designers' pseudo-code (`rmd160.txt`, `rmd320.txt`).

use crate::common::{BLOCK_LEN, K_LEFT, K_RIGHT_160, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT, f, words};

/// One application of the compression function (the body of the pseudo-code's `for i` loop) to
/// the chaining variable `h` -- five words for RIPEMD-160, ten (left line, then right line) for
/// RIPEMD-320.
///
/// Line by line against `rmd160.txt` / `rmd320.txt`:
///
/// * `A := h0; B := h1; C := h2; D := h3; E := h4;` and `A' := h0 ..` (RIPEMD-160) or
///   `A' := h5 ..` (RIPEMD-320);
/// * for `j := 0 to 79`: `T := rol_s(j)(A [+] f(j, B, C, D) [+] X[i][r(j)] [+] K(j)) [+] E;
///   A := E; E := D; D := rol_10(C); C := B; B := T;` and the same on the primed line with
///   `f(79-j)`, `r'`, `s'`, `K'`;
/// * RIPEMD-320 only: after steps 15, 31, 47, 63 and 79, exchange `B`/`B'`, `D`/`D'`, `A`/`A'`,
///   `C`/`C'`, `E`/`E'` respectively;
/// * RIPEMD-160: `T := h1 [+] C [+] D'; h1 := h2 [+] D [+] E'; h2 := h3 [+] E [+] A';
///   h3 := h4 [+] A [+] B'; h4 := h0 [+] B [+] C'; h0 := T`; RIPEMD-320: `h0 := h0 + A; ..
///   h4 := h4 + E; h5 := h5 + A'; .. h9 := h9 + E'`.
///
/// The step is written once as a loop over the tables rather than unrolled; the tables are
/// public constants indexed by the step counter, so no index or branch depends on the data.
///
/// `extended` is `true` for RIPEMD-320 and `false` for RIPEMD-160.
pub(crate) fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN], extended: bool) {
    let x = words(block);

    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    let (mut aa, mut bb, mut cc, mut dd, mut ee) =
        if extended { (h[5], h[6], h[7], h[8], h[9]) } else { (h[0], h[1], h[2], h[3], h[4]) };

    for j in 0..80 {
        // T := rol_s(j)(A [+] f(j, B, C, D) [+] X[i][r(j)] [+] K(j)) [+] E;
        // A := E; E := D; D := rol_10(C); C := B; B := T;
        let t = a
            .wrapping_add(f(j, b, c, d))
            .wrapping_add(x[R_LEFT[j]])
            .wrapping_add(K_LEFT[j / 16])
            .rotate_left(S_LEFT[j])
            .wrapping_add(e);
        a = e;
        e = d;
        d = c.rotate_left(10);
        c = b;
        b = t;
        // T := rol_s'(j)(A' [+] f(79-j, B', C', D') [+] X[i][r'(j)] [+] K'(j)) [+] E'; ...
        let t = aa
            .wrapping_add(f(79 - j, bb, cc, dd))
            .wrapping_add(x[R_RIGHT[j]])
            .wrapping_add(K_RIGHT_160[j / 16])
            .rotate_left(S_RIGHT[j])
            .wrapping_add(ee);
        aa = ee;
        ee = dd;
        dd = cc.rotate_left(10);
        cc = bb;
        bb = t;
        // RIPEMD-320: exchange one word between the lines at the end of each round.
        if extended {
            match j {
                15 => core::mem::swap(&mut b, &mut bb),
                31 => core::mem::swap(&mut d, &mut dd),
                47 => core::mem::swap(&mut a, &mut aa),
                63 => core::mem::swap(&mut c, &mut cc),
                79 => core::mem::swap(&mut e, &mut ee),
                _ => {}
            }
        }
    }

    if extended {
        // h0 := h0 + A; .. h4 := h4 + E; h5 := h5 + A'; .. h9 := h9 + E';
        for (hi, v) in h.iter_mut().zip([a, b, c, d, e, aa, bb, cc, dd, ee]) {
            *hi = hi.wrapping_add(v);
        }
    } else {
        // T := h1 [+] C [+] D'; h1 := h2 [+] D [+] E'; h2 := h3 [+] E [+] A';
        // h3 := h4 [+] A [+] B'; h4 := h0 [+] B [+] C'; h0 := T;
        let t = h[1].wrapping_add(c).wrapping_add(dd);
        h[1] = h[2].wrapping_add(d).wrapping_add(ee);
        h[2] = h[3].wrapping_add(e).wrapping_add(aa);
        h[3] = h[4].wrapping_add(a).wrapping_add(bb);
        h[4] = h[0].wrapping_add(b).wrapping_add(cc);
        h[0] = t;
    }
}

/// Length in bytes of the serialized state of RIPEMD-160.
///
/// Layout (after the 3-byte library version header; all integers little-endian): the 5 words of
/// the chaining variable, the `u64` byte count, the 64-byte buffer (zero past its fill), and the
/// fill as one byte.
pub const SUSPENDED_RIPEMD160_STATE_LEN: usize = 3 + 20 + 8 + BLOCK_LEN + 1;
/// Length in bytes of the serialized state of RIPEMD-320: as
/// [`SUSPENDED_RIPEMD160_STATE_LEN`], with 10 words of chaining variable.
pub const SUSPENDED_RIPEMD320_STATE_LEN: usize = 3 + 40 + 8 + BLOCK_LEN + 1;
