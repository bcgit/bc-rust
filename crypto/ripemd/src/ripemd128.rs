//! RIPEMD-128 and its 256-bit extension RIPEMD-256: two parallel lines of four 32-bit words and
//! 64 steps per block, following the designers' pseudo-code (`rmd128.txt`, `rmd256.txt`).

use crate::common::{BLOCK_LEN, K_LEFT, K_RIGHT_128, R_LEFT, R_RIGHT, S_LEFT, S_RIGHT, f, words};

/// One application of the compression function (the body of the pseudo-code's `for i` loop) to
/// the chaining variable `h` -- four words for RIPEMD-128, eight (left line, then right line) for
/// RIPEMD-256.
///
/// Line by line against `rmd128.txt` / `rmd256.txt`:
///
/// * `A := h0; B := h1; C := h2; D := h3;` and `A' := h0 ..` (RIPEMD-128) or `A' := h4 ..`
///   (RIPEMD-256);
/// * for `j := 0 to 63`: `T := rol_s(j)(A [+] f(j, B, C, D) [+] X[i][r(j)] [+] K(j)); A := D;
///   D := C; C := B; B := T;` and the same on the primed line with `f(63-j)`, `r'`, `s'`, `K'`;
/// * RIPEMD-256 only: after steps 15, 31, 47 and 63, exchange `A`/`A'`, `B`/`B'`, `C`/`C'`,
///   `D`/`D'` respectively;
/// * RIPEMD-128: `T := h1 [+] C [+] D'; h1 := h2 [+] D [+] A'; h2 := h3 [+] A [+] B';
///   h3 := h0 [+] B [+] C'; h0 := T`; RIPEMD-256: `h0 := h0 + A; .. h3 := h3 + D;
///   h4 := h4 + A'; .. h7 := h7 + D'`.
///
/// The step is written once as a loop over the tables rather than unrolled; the tables are
/// public constants indexed by the step counter, so no index or branch depends on the data.
///
/// `extended` is `true` for RIPEMD-256 and `false` for RIPEMD-128.
pub(crate) fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN], extended: bool) {
    let x = words(block);

    let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
    let (mut aa, mut bb, mut cc, mut dd) =
        if extended { (h[4], h[5], h[6], h[7]) } else { (h[0], h[1], h[2], h[3]) };

    for j in 0..64 {
        // T := rol_s(j)(A [+] f(j, B, C, D) [+] X[i][r(j)] [+] K(j)); A := D; D := C; C := B; B := T;
        let t = a
            .wrapping_add(f(j, b, c, d))
            .wrapping_add(x[R_LEFT[j]])
            .wrapping_add(K_LEFT[j / 16])
            .rotate_left(S_LEFT[j]);
        a = d;
        d = c;
        c = b;
        b = t;
        // T := rol_s'(j)(A' [+] f(63-j, B', C', D') [+] X[i][r'(j)] [+] K'(j)); A' := D'; ...
        let t = aa
            .wrapping_add(f(63 - j, bb, cc, dd))
            .wrapping_add(x[R_RIGHT[j]])
            .wrapping_add(K_RIGHT_128[j / 16])
            .rotate_left(S_RIGHT[j]);
        aa = dd;
        dd = cc;
        cc = bb;
        bb = t;
        // RIPEMD-256: exchange one word between the lines at the end of each round.
        if extended {
            match j {
                15 => core::mem::swap(&mut a, &mut aa),
                31 => core::mem::swap(&mut b, &mut bb),
                47 => core::mem::swap(&mut c, &mut cc),
                63 => core::mem::swap(&mut d, &mut dd),
                _ => {}
            }
        }
    }

    if extended {
        // h0 := h0 + A; h1 := h1 + B; h2 := h2 + C; h3 := h3 + D;
        // h4 := h4 + A'; h5 := h5 + B'; h6 := h6 + C'; h7 := h7 + D';
        for (hi, v) in h.iter_mut().zip([a, b, c, d, aa, bb, cc, dd]) {
            *hi = hi.wrapping_add(v);
        }
    } else {
        // T := h1 [+] C [+] D'; h1 := h2 [+] D [+] A'; h2 := h3 [+] A [+] B';
        // h3 := h0 [+] B [+] C'; h0 := T;
        let t = h[1].wrapping_add(c).wrapping_add(dd);
        h[1] = h[2].wrapping_add(d).wrapping_add(aa);
        h[2] = h[3].wrapping_add(a).wrapping_add(bb);
        h[3] = h[0].wrapping_add(b).wrapping_add(cc);
        h[0] = t;
    }
}

/// Length in bytes of the serialized state of RIPEMD-128.
///
/// Layout (after the 3-byte library version header; all integers little-endian): the 4 words of
/// the chaining variable, the `u64` byte count, the 64-byte buffer (zero past its fill), and the
/// fill as one byte.
pub const SUSPENDED_RIPEMD128_STATE_LEN: usize = 3 + 16 + 8 + BLOCK_LEN + 1;
/// Length in bytes of the serialized state of RIPEMD-256: as
/// [`SUSPENDED_RIPEMD128_STATE_LEN`], with 8 words of chaining variable.
pub const SUSPENDED_RIPEMD256_STATE_LEN: usize = 3 + 32 + 8 + BLOCK_LEN + 1;
