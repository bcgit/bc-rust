//! Signed-window recoding of scalars, for the variable-time multiplications of EdDSA
//! verification.

/// Writes the width-`width` non-adjacent form of `n` to `ws`, one signed digit per bit position:
/// `n = sum(ws[i] * 2^i)`, where every non-zero digit is odd, lies strictly between
/// `-2^(width-1)` and `2^(width-1)`, and is followed by at least `width - 1` zero digits.
///
/// `n` is little-endian limbs read as a two's complement integer, so a set top bit makes it
/// negative. `width` is from 2 to 8. `ws` is cleared first and must reach the highest non-zero
/// digit, which `64 * n.len()` entries always do; fewer are enough when `n` is known to be
/// shorter, and a digit that does not fit panics on the index.
///
/// Variable time: the number of steps and the positions written depend on `n`, which must be
/// public.
pub(crate) fn get_signed_var(n: &[u64], width: usize, ws: &mut [i8]) {
    debug_assert!((2..=8).contains(&width));
    ws.fill(0);

    let top = n[n.len() - 1];
    let extension = ((top as i64) >> 63) as u64;
    let lead = 64 - width;
    let mut j = 0;
    let mut sign = 0_i64;

    // n is walked 32 bits at a time: step i looks at the 64 bits of n from bit 32 * i up
    // (sign-extended past the top), which is enough for a window that starts in its low half.
    for i in 0..2 * n.len() {
        let low = n[i >> 1];
        let word = if i & 1 == 0 {
            low
        } else {
            let high = if (i >> 1) + 1 < n.len() { n[(i >> 1) + 1] } else { extension };
            low >> 32 | high << 32
        };

        while j < 32 {
            let word32 = (word >> j) as i64;

            // `sign` is the carry from the digit before: all ones after a negative digit, when
            // the bits above it are read inverted. Skip to the next bit that differs from it.
            let skip = i64::trailing_zeros((sign ^ word32) | (1 << 32));
            if skip > 0 {
                j += skip as usize;
                continue;
            }

            // The window's `width` bits, made odd, sign-extended from its top bit.
            let digit = (word32 | 1) << lead;
            sign = digit >> 63;

            ws[(i << 5) + j] = (digit >> lead) as i8;

            j += width;
        }
        j -= 32;
    }

    debug_assert_eq!(sign, (top as i64) >> 63);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{vec, vec::Vec};

    // Known answers from the prototype this was ported from (bc-rust-nursery, crates/math,
    // `wnaf::get_signed_var`), as the non-zero digits and their positions: the two group orders
    // at the widths the prototype's order checks use, and positive, negative and extreme values
    // at the widths its Ed25519 and Ed448 verification use. Printed by the scratch program
    // described in `nat.rs` (`kat-gen nat`).

    /// One row: the limbs, the window width, and each non-zero digit as (position, digit).
    struct WnafKat {
        n: &'static [u64],
        width: usize,
        digits: &'static [(usize, i8)],
    }

    const WNAF_KATS: &[WnafKat] = &[
        WnafKat {
            n: &[0x5812631A5CF5D3ED, 0x14DEF9DEA2F79CD6, 0x0000000000000000, 0x1000000000000000],
            width: 4,
            digits: &[
                (0, -3),
                (4, -1),
                (10, 5),
                (14, 7),
                (18, -3),
                (24, -3),
                (29, 3),
                (33, -3),
                (37, -7),
                (42, -7),
                (47, 5),
                (52, 1),
                (59, -5),
                (63, -3),
                (67, -5),
                (72, -3),
                (77, -3),
                (83, -1),
                (88, 3),
                (93, 5),
                (97, -1),
                (101, -1),
                (105, -3),
                (112, -1),
                (117, 7),
                (122, 5),
                (252, 1),
            ],
        },
        WnafKat {
            n: &[
                0x2378C292AB5844F3, 0x216CC2728DC58F55, 0xC44EDB49AED63690, 0xFFFFFFFF7CCA23E9,
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF,
            ],
            width: 5,
            digits: &[
                (0, -13),
                (8, 5),
                (14, 1),
                (19, 11),
                (24, 11),
                (29, -11),
                (34, 5),
                (39, 5),
                (46, 3),
                (51, 15),
                (56, 3),
                (61, 9),
                (66, -11),
                (71, -1),
                (76, -7),
                (81, 3),
                (86, -9),
                (92, 9),
                (97, -7),
                (103, 5),
                (110, -13),
                (116, -9),
                (121, -15),
                (126, 1),
                (132, 9),
                (137, -5),
                (142, -7),
                (147, -5),
                (152, 15),
                (157, 13),
                (163, 9),
                (168, -5),
                (173, -9),
                (180, 5),
                (186, -15),
                (193, -11),
                (202, 9),
                (209, 5),
                (214, -13),
                (223, -1),
                (446, 1),
            ],
        },
        WnafKat {
            n: &[0x17FD92A0AA58CF92, 0x03EF811C51202ACC, 0x1B478A9E05C9EDA0, 0x00ADCC809127E8AA],
            width: 6,
            digits: &[
                (1, 9),
                (7, 31),
                (14, -29),
                (21, 19),
                (27, 21),
                (37, 21),
                (44, 25),
                (50, -1),
                (59, 3),
                (66, -13),
                (72, -21),
                (78, 1),
                (85, 9),
                (92, 5),
                (98, 7),
                (104, 1),
                (111, 31),
                (117, 31),
                (133, -19),
                (140, 31),
                (147, -7),
                (153, 3),
                (161, 15),
                (167, 21),
                (175, 15),
                (182, -19),
                (189, 17),
                (195, 21),
                (203, -3),
                (211, -27),
                (217, 9),
                (223, 1),
                (231, 25),
                (238, -9),
                (244, 11),
            ],
        },
        WnafKat {
            n: &[0xABE63178F218E0B2, 0x5F1F447FE30DBDD9],
            width: 4,
            digits: &[
                (1, -7),
                (6, 3),
                (13, 7),
                (19, 3),
                (25, -7),
                (32, -7),
                (39, 3),
                (44, 3),
                (49, 3),
                (53, -1),
                (58, -5),
                (62, 7),
                (67, -5),
                (73, -1),
                (78, 7),
                (82, 3),
                (88, 3),
                (93, -1),
                (103, -7),
                (107, -7),
                (111, -1),
                (117, -7),
                (125, 3),
            ],
        },
        WnafKat {
            n: &[0x9D76E51651958066, 0xA471A79B1FE80DF7],
            width: 4,
            digits: &[
                (1, 3),
                (5, 3),
                (15, -5),
                (19, 3),
                (23, 3),
                (28, 5),
                (33, -5),
                (37, -7),
                (41, 3),
                (45, 7),
                (49, -5),
                (55, -5),
                (61, -3),
                (67, -1),
                (73, 7),
                (83, -3),
                (93, -7),
                (98, 7),
                (103, -1),
                (107, 5),
                (111, 3),
                (116, 7),
                (122, -7),
                (126, -1),
            ],
        },
        WnafKat {
            n: &[
                0x7BEF9F541144765E, 0x3E133211BF8E0936, 0x48077BB6EC73FFAE, 0x027565C6A60CAC7C,
                0x020DB4DA48EB7D02, 0xF0F8F395E19783B3, 0x3513931F6C088BDA,
            ],
            width: 7,
            digits: &[
                (1, 47),
                (9, 59),
                (18, -47),
                (25, 9),
                (34, -43),
                (45, -3),
                (52, 63),
                (59, -49),
                (67, 39),
                (75, -63),
                (84, -7),
                (94, -57),
                (101, 17),
                (108, 51),
                (116, -31),
                (126, 57),
                (133, -3),
                (146, 29),
                (154, 59),
                (161, -37),
                (170, -33),
                (179, 1),
                (187, 9),
                (194, 31),
                (202, 43),
                (210, 3),
                (217, -45),
                (224, -57),
                (233, 51),
                (240, -11),
                (247, 5),
                (257, 1),
                (264, -3),
                (271, -41),
                (280, -55),
                (287, 53),
                (294, -45),
                (302, 55),
                (313, 1),
                (320, 51),
                (327, 7),
                (335, 47),
                (343, -61),
                (353, -53),
                (362, 61),
                (371, 31),
                (380, 47),
                (387, -5),
                (394, 35),
                (403, 1),
                (410, -37),
                (421, 25),
                (428, 57),
                (436, -47),
                (443, 7),
            ],
        },
        WnafKat { n: &[0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF], width: 2, digits: &[(0, -1)] },
        WnafKat { n: &[0x8000000000000000], width: 8, digits: &[(63, -1)] },
        WnafKat { n: &[0x0000000000000000, 0x0000000000000000], width: 4, digits: &[] },
    ];

    #[test]
    fn get_signed_var_matches_the_prototype() {
        for (i, kat) in WNAF_KATS.iter().enumerate() {
            // A dirty buffer: the digits not written must come out zero.
            let mut ws = vec![0x55_i8; 64 * kat.n.len()];
            get_signed_var(kat.n, kat.width, &mut ws);
            let mut expected = vec![0_i8; ws.len()];
            for &(position, digit) in kat.digits {
                expected[position] = digit;
            }
            assert_eq!(ws, expected, "case {i}");
        }
    }

    /// splitmix64: a fixed stream of test values.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `sum(ws[i] * 2^i)` as a two's complement integer of one limb more than `limbs`, which
    /// holds every partial sum exactly.
    fn reconstruct(ws: &[i8], limbs: usize) -> Vec<u64> {
        let mut total = vec![0_u64; limbs + 1];
        for (position, &digit) in ws.iter().enumerate() {
            // digit * 2^position, sign-extended to the top limb, then added in.
            let shifted = (digit as i128) << (position % 64);
            let at = position / 64;
            let mut term = vec![0_u64; limbs + 1];
            term[at] = shifted as u64;
            for (above, limb) in term[at + 1..].iter_mut().enumerate() {
                *limb = if above == 0 { (shifted >> 64) as u64 } else { (shifted >> 127) as u64 };
            }
            let mut carry = 0_u128;
            for (t, &add) in total.iter_mut().zip(&term) {
                carry += *t as u128 + add as u128;
                *t = carry as u64;
                carry >>= 64;
            }
        }
        total
    }

    /// For every width, over positive and negative values of one to four limbs: the digits add
    /// back up to the number, each non-zero digit is odd and inside the window, and the
    /// `width - 1` digits after it are zero.
    #[test]
    fn get_signed_var_digits_reconstruct_the_number() {
        let mut state = 0x776E_6166;
        for width in 2..=8 {
            for limbs in 1..=4 {
                for case in 0..12 {
                    let mut n: Vec<u64> = (0..limbs).map(|_| next(&mut state)).collect();
                    match case {
                        0 => n.fill(0),
                        1 => n.fill(u64::MAX),
                        2 => {
                            n.fill(0);
                            n[limbs - 1] = 1 << 63;
                        }
                        3 => {
                            n.fill(u64::MAX);
                            n[limbs - 1] = u64::MAX >> 1;
                        }
                        // A lone bit exactly 32 places above where a scan starts.
                        4 => {
                            n.fill(0);
                            n[0] = 1 << 32;
                        }
                        // A digit, then zeros to the end of the 64 bits in view and a bit
                        // just past them.
                        5 => {
                            n.fill(0);
                            n[0] = 1;
                            n[limbs - 1] |= 2;
                        }
                        _ => {}
                    }
                    let mut ws = vec![0x55_i8; 64 * limbs];
                    get_signed_var(&n, width, &mut ws);

                    let mut extended = n.clone();
                    extended.push(((n[limbs - 1] as i64) >> 63) as u64);
                    assert_eq!(reconstruct(&ws, limbs), extended, "width {width} {n:x?}");

                    let bound = 1_i16 << (width - 1);
                    for (position, &digit) in ws.iter().enumerate() {
                        if digit == 0 {
                            continue;
                        }
                        assert_eq!(digit & 1, 1, "width {width} {n:x?} position {position}");
                        assert!((digit as i16).abs() < bound, "width {width} {n:x?}");
                        let gap = &ws[position + 1..ws.len().min(position + width)];
                        assert!(gap.iter().all(|&d| d == 0), "width {width} {n:x?}");
                    }
                }
            }
        }
    }
}
