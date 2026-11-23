//! Known answers for [`bouncycastle_utils::montgomery`]'s generic `widening_mul`/`redc` at the
//! widths the brainpool curves instantiate it at, and `widening_square` and `widening_mul_into`
//! against `widening_mul`. The moduli and their Montgomery constants are written out here, each
//! computed in Python, so nothing is taken from a crate that uses the module. The cross-check
//! against the P-256 scalar field's hand-written arithmetic is in `bouncycastle-ec`'s
//! `tests/montgomery_tests.rs`.

use bouncycastle_utils::montgomery::{redc, widening_mul, widening_mul_into, widening_square};
use bouncycastle_utils::nat;

struct Xorshift64(u64);

impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_limbs(&mut self) -> [u64; 4] {
        [self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64()]
    }
}

/// `a * b mod n` via the generic module at any width, with the modulus and its Montgomery
/// constants passed in -- the shape the brainpool curves actually use the module in: both
/// operands into Montgomery form through `r_squared`, `widening_mul`, `redc`, and a last `redc`
/// with a zero high half to leave Montgomery form. `redc`'s `(high, extra)` result (`high +
/// extra*R`, `< 2n`) is reduced to the canonical value each time: `high + r_mod_n` if `extra == 1`,
/// otherwise `high`, minus `n` once if `high >= n`.
fn generic_mul_via_montgomery_form_at<const L: usize, const L2: usize, const L21: usize>(
    a: [u64; L],
    b: [u64; L],
    n: &[u64; L],
    n_prime: u64,
    r_mod_n: &[u64; L],
    r_squared: &[u64; L],
) -> [u64; L] {
    let reduce = |(high, extra): ([u64; L], u64)| -> [u64; L] {
        if extra == 1 {
            nat::add(&high, r_mod_n).0
        } else {
            let (diff, borrow) = nat::sub(&high, n);
            if borrow == 1 { high } else { diff }
        }
    };
    let to_montgomery = |x: [u64; L]| -> [u64; L] {
        reduce(redc::<L, L2, L21>(&widening_mul::<L, L2>(&x, r_squared), n, n_prime))
    };

    let product_montgomery = reduce(redc::<L, L2, L21>(
        &widening_mul::<L, L2>(&to_montgomery(a), &to_montgomery(b)),
        n,
        n_prime,
    ));
    let mut wide = [0u64; L2];
    wide[..L].copy_from_slice(&product_montgomery);
    reduce(redc::<L, L2, L21>(&wide, n, n_prime))
}

/// `n`, `-n^-1 mod 2^64`, `R mod n` and `R^2 mod n` for bp384r1's order (`R = 2^384`), each
/// computed directly in Python from the RFC 5639 value of `n`, not copied from the crate.
mod bp384r1_consts {
    pub const N_LIMBS: [u64; 6] = [
        0x3b883202e9046565, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    pub const N_PRIME: u64 = 0x5cfedd2a5cb5bb93;
    pub const R_MOD_N_LIMBS: [u64; 6] = [
        0xc477cdfd16fb9a9b, 0x30c5495094803cef, 0xe0e9919353fbda58, 0xead08ef612aba94c,
        0xf0a29081af19be20, 0x7346e17d5cc792d7,
    ];
    pub const R_SQUARED_LIMBS: [u64; 6] = [
        0xac4ed3a2de771c8e, 0x37264e202f2b6b6e, 0x2a927e3b9802688a, 0x574a74cb52d748ff,
        0x8f886dc965165fdb, 0x0ce8941a614e97c2,
    ];
}

/// The generic module at `L = 6`, the width bp384r1 instantiates it at: `(n-1)^2 == 1` and
/// `(n-1)(n-2) == 2` (the largest products two canonical values can form, which is where the
/// `2L+1`-limb accumulator and its tail carry loop matter), plus one pseudorandom pair
/// (`random.seed(6289)`) whose expected value is Python's `(a * b) % n`.
#[test]
fn generic_montgomery_known_answers_at_l_6() {
    use bp384r1_consts::*;
    let n_minus_1 = [
        0x3b883202e9046564, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    let n_minus_2 = [
        0x3b883202e9046563, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    let mul = |a, b| {
        generic_mul_via_montgomery_form_at::<6, 12, 13>(
            a, b, &N_LIMBS, N_PRIME, &R_MOD_N_LIMBS, &R_SQUARED_LIMBS,
        )
    };
    assert_eq!(
        mul(n_minus_1, n_minus_1),
        [
            0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000
        ],
        "(n-1)^2 == 1"
    );
    assert_eq!(
        mul(n_minus_1, n_minus_2),
        [
            0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000
        ],
        "(n-1)(n-2) == 2"
    );
    assert_eq!(
        mul(
            n_minus_1,
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000
            ]
        ),
        n_minus_1,
        "(n-1) * 1 == n-1"
    );
    assert_eq!(
        mul(
            [
                0x5f2ea6fdc5693ff0, 0x6ccf219bfc612a44, 0x00743629ae17c7b5, 0x69a1357a93b8b552,
                0x59f8cf15db16e623, 0x0694510ba9d9460b
            ],
            [
                0xa038bbdbedc6f313, 0xdacf95e9e2e5ebc0, 0xf0261bde3402723a, 0xad661e728082ef22,
                0xa97e814518d0015c, 0x6f81b8ea97e2b0c0
            ]
        ),
        [
            0xd72f0ce0ef2a841a, 0xbd07255c147f7805, 0x27f108c5cb9924ed, 0xda8440445f80d6b6,
            0x790c8ab40ef67fc3, 0x28b2b4a163ad74f8
        ]
    );
    assert_eq!(
        mul(
            [
                0xa038bbdbedc6f313, 0xdacf95e9e2e5ebc0, 0xf0261bde3402723a, 0xad661e728082ef22,
                0xa97e814518d0015c, 0x6f81b8ea97e2b0c0
            ],
            [
                0x5f2ea6fdc5693ff0, 0x6ccf219bfc612a44, 0x00743629ae17c7b5, 0x69a1357a93b8b552,
                0x59f8cf15db16e623, 0x0694510ba9d9460b
            ]
        ),
        [
            0xd72f0ce0ef2a841a, 0xbd07255c147f7805, 0x27f108c5cb9924ed, 0xda8440445f80d6b6,
            0x790c8ab40ef67fc3, 0x28b2b4a163ad74f8
        ],
        "commuted"
    );
}

/// `n`, `-n^-1 mod 2^64`, `R mod n` and `R^2 mod n` for bp512r1's order (`R = 2^512`), each
/// computed directly in Python from the RFC 5639 value of `n`, not copied from the crate.
mod bp512r1_consts {
    pub const N_LIMBS: [u64; 8] = [
        0xb58796829ca90069, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
        0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ];
    pub const N_PRIME: u64 = 0xad49541f0f1b7027;
    pub const R_MOD_N_LIMBS: [u64; 8] = [
        0x4a78697d6356ff97, 0xe24e2c7ef7a22522, 0xbe799ee68053efb8, 0xaac1a3beb356d9e6,
        0x299c63358fccf78f, 0x34cf724c4c362df1, 0xc02b1951cc3603f8, 0x5522624724163b74,
    ];
    pub const R_SQUARED_LIMBS: [u64; 8] = [
        0xd2a3681ecda81671, 0x0886b75895283ddd, 0x3ec64bd033b7627f, 0xa6f230c72f0207e8,
        0xd7f9cc263b790de3, 0x723c37a22f16bbdf, 0x95df1b4c194b2e56, 0xa794586a718407b0,
    ];
}

/// The generic module at `L = 8`, the width bp512r1 instantiates it at: `(n-1)^2 == 1` and
/// `(n-1)(n-2) == 2` (the largest products two canonical values can form, which is where the
/// `2L+1`-limb accumulator and its tail carry loop matter), plus one pseudorandom pair
/// (`random.seed(6289)`) whose expected value is Python's `(a * b) % n`.
#[test]
fn generic_montgomery_known_answers_at_l_8() {
    use bp512r1_consts::*;
    let n_minus_1 = [
        0xb58796829ca90068, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
        0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ];
    let n_minus_2 = [
        0xb58796829ca90067, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
        0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ];
    let mul = |a, b| {
        generic_mul_via_montgomery_form_at::<8, 16, 17>(
            a, b, &N_LIMBS, N_PRIME, &R_MOD_N_LIMBS, &R_SQUARED_LIMBS,
        )
    };
    assert_eq!(
        mul(n_minus_1, n_minus_1),
        [
            0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
        ],
        "(n-1)^2 == 1"
    );
    assert_eq!(
        mul(n_minus_1, n_minus_2),
        [
            0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
        ],
        "(n-1)(n-2) == 2"
    );
    assert_eq!(
        mul(
            n_minus_1,
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
            ]
        ),
        n_minus_1,
        "(n-1) * 1 == n-1"
    );
    assert_eq!(
        mul(
            [
                0x51474e476d3e8250, 0xc40f92fed2b6845d, 0x36304de017a709cd, 0x5ee1276b928987ca,
                0xf87746982a1c7de0, 0x6f0bf816e68a9e11, 0x22f9463eead00edb, 0x78e16f8183e1482c
            ],
            [
                0x71867f3260f10097, 0x3a070e67812e685d, 0xa66ec1f9c1388945, 0x4f6b9000c9f8b46f,
                0x1d964c0202ec66d3, 0xf53111408ef6534d, 0xc2702c675475b76d, 0x37b644bd7ac0cd7e
            ]
        ),
        [
            0x64cddde3d7e1ef15, 0x4e2ee5ed781ce49d, 0x4ec4b684d3baa7fc, 0x181b22cae55ce08f,
            0xb028dbb55501b1ee, 0x967989f61a2f39ee, 0x62b5711cdb6e1336, 0x5cadf0fb90459db1
        ]
    );
    assert_eq!(
        mul(
            [
                0x71867f3260f10097, 0x3a070e67812e685d, 0xa66ec1f9c1388945, 0x4f6b9000c9f8b46f,
                0x1d964c0202ec66d3, 0xf53111408ef6534d, 0xc2702c675475b76d, 0x37b644bd7ac0cd7e
            ],
            [
                0x51474e476d3e8250, 0xc40f92fed2b6845d, 0x36304de017a709cd, 0x5ee1276b928987ca,
                0xf87746982a1c7de0, 0x6f0bf816e68a9e11, 0x22f9463eead00edb, 0x78e16f8183e1482c
            ]
        ),
        [
            0x64cddde3d7e1ef15, 0x4e2ee5ed781ce49d, 0x4ec4b684d3baa7fc, 0x181b22cae55ce08f,
            0xb028dbb55501b1ee, 0x967989f61a2f39ee, 0x62b5711cdb6e1336, 0x5cadf0fb90459db1
        ],
        "commuted"
    );
}

/// `widening_square` is the one routine in the generic module nothing above reaches (the
/// brainpool `square`s call it, but only their own `square_agrees_with_mul` tests see it, and
/// only through a reduction). Pinned against `widening_mul` at every width the crate
/// instantiates, plus the all-ones known answer, whose doubling pass carries out of every limb.

#[test]
fn widening_square_agrees_with_widening_mul_and_the_all_ones_known_answer_at_l_4() {
    // (2^256 - 1)^2 = 2^512 - 2^257 + 1, computed in Python: limb 0 is 1, limb 4
    // is 2^64 - 2, and limbs 5..=7 are all ones.
    let all_ones = [u64::MAX; 4];
    let expected: [u64; 8] = [
        0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    ];
    assert_eq!(widening_square::<4, 8>(&all_ones), expected);
    assert_eq!(widening_mul::<4, 8>(&all_ones, &all_ones), expected);

    let mut rng = Xorshift64(0x5EED_0000_0000_0004);
    for _ in 0..2000 {
        let mut a = [0u64; 4];
        for limb in a.iter_mut() {
            *limb = rng.next_u64();
        }
        assert_eq!(widening_square::<4, 8>(&a), widening_mul::<4, 8>(&a, &a), "a = {a:x?}");
    }
}

#[test]
fn widening_square_agrees_with_widening_mul_and_the_all_ones_known_answer_at_l_6() {
    // (2^384 - 1)^2 = 2^768 - 2^385 + 1, computed in Python: limb 0 is 1, limb 6
    // is 2^64 - 2, and limbs 7..=11 are all ones.
    let all_ones = [u64::MAX; 6];
    let expected: [u64; 12] = [
        0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    ];
    assert_eq!(widening_square::<6, 12>(&all_ones), expected);
    assert_eq!(widening_mul::<6, 12>(&all_ones, &all_ones), expected);

    let mut rng = Xorshift64(0x5EED_0000_0000_0006);
    for _ in 0..2000 {
        let mut a = [0u64; 6];
        for limb in a.iter_mut() {
            *limb = rng.next_u64();
        }
        assert_eq!(widening_square::<6, 12>(&a), widening_mul::<6, 12>(&a, &a), "a = {a:x?}");
    }
}

#[test]
fn widening_square_agrees_with_widening_mul_and_the_all_ones_known_answer_at_l_8() {
    // (2^512 - 1)^2 = 2^1024 - 2^513 + 1, computed in Python: limb 0 is 1, limb 8
    // is 2^64 - 2, and limbs 9..=15 are all ones.
    let all_ones = [u64::MAX; 8];
    let expected: [u64; 16] = [
        0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    ];
    assert_eq!(widening_square::<8, 16>(&all_ones), expected);
    assert_eq!(widening_mul::<8, 16>(&all_ones, &all_ones), expected);

    let mut rng = Xorshift64(0x5EED_0000_0000_0008);
    for _ in 0..2000 {
        let mut a = [0u64; 8];
        for limb in a.iter_mut() {
            *limb = rng.next_u64();
        }
        assert_eq!(widening_square::<8, 16>(&a), widening_mul::<8, 16>(&a, &a), "a = {a:x?}");
    }
}

#[test]
fn widening_square_agrees_with_widening_mul_and_the_all_ones_known_answer_at_l_9() {
    // (2^576 - 1)^2 = 2^1152 - 2^577 + 1, computed in Python: limb 0 is 1, limb 9
    // is 2^64 - 2, and limbs 10..=17 are all ones.
    let all_ones = [u64::MAX; 9];
    let expected: [u64; 18] = [
        0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ];
    assert_eq!(widening_square::<9, 18>(&all_ones), expected);
    assert_eq!(widening_mul::<9, 18>(&all_ones, &all_ones), expected);

    let mut rng = Xorshift64(0x5EED_0000_0000_0009);
    for _ in 0..2000 {
        let mut a = [0u64; 9];
        for limb in a.iter_mut() {
            *limb = rng.next_u64();
        }
        assert_eq!(widening_square::<9, 18>(&a), widening_mul::<9, 18>(&a, &a), "a = {a:x?}");
    }
}

/// `widening_mul_into` owes the caller a full overwrite: a prefilled output must come out as
/// the product, not the product OR'd or added into what was there.
#[test]
fn widening_mul_into_overwrites_a_prefilled_output() {
    let mut rng = Xorshift64(0x5EED_0000_0000_0010);
    for _ in 0..500 {
        let a = rng.next_limbs();
        let b = rng.next_limbs();
        let mut out = [u64::MAX; 8];
        widening_mul_into::<4, 8>(&a, &b, &mut out);
        assert_eq!(out, widening_mul::<4, 8>(&a, &b), "a = {a:x?}, b = {b:x?}");
    }
    let mut out = [0x5A5A_5A5A_5A5A_5A5Au64; 8];
    widening_mul_into::<4, 8>(&[0u64; 4], &[u64::MAX; 4], &mut out);
    assert_eq!(out, [0u64; 8]);
}
