//! Known-answer tests for [`P384FieldElement`] arithmetic.
//!
//! `p = 2**384 - 2**128 - 2**96 + 2**32 - 1` has no dedicated NIST-published field-arithmetic KAT
//! suite (SP 800-186 gives only the domain parameters). Expected values computed independently in
//! Python (arbitrary-precision integers, not from recall):
//!
//! ```text
//! p = 2**384 - 2**128 - 2**96 + 2**32 - 1
//! random.seed(4384)
//! vals = [random.randrange(1, p) for _ in range(4)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % p, (vals[i]-vals[j]) % p, (vals[i]*vals[j]) % p
//! # for each i: (-vals[i]) % p, pow(vals[i], p-2, p) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::p384::P384FieldElement;

const VALS_0: [u64; 6] = [
    0xfbf0df09ff15d76c, 0xf5a7ffb01c944ad6, 0x59c184f6c245b0b0, 0xf42a4e0449f2cb85,
    0xc1b0f9376ef449ac, 0xb79e039ea01cee3b,
];
const VALS_1: [u64; 6] = [
    0x84e8350c9b1affa7, 0x836c0706d0c1f027, 0xede2c0b840684e77, 0x911bfe952a88e6e6,
    0xa445a43dfcf34065, 0x822c517432ee5368,
];
const VALS_2: [u64; 6] = [
    0x9a2952cc4df065e5, 0xb460151e3cb7e277, 0x8e0af308d3908b9f, 0x594193102e6ede9b,
    0x33c2fe4a458505c6, 0x30b0270c28a08938,
];
const VALS_3: [u64; 6] = [
    0xbe4717b569c8b2d8, 0x3af87fdc818bb903, 0x0dcbe57fa3200615, 0x42d228f2780bea9c,
    0x6c7715376e8b494b, 0xece924a7b60565e1,
];
const VALS_4: [u64; 6] = [0, 0, 0, 0, 0, 0];

const ADD_0_1: [u64; 6] = [
    0x80d914159a30d714, 0x791406b7ed563afe, 0x47a445af02adff29, 0x85464c99747bb26c,
    0x65f69d756be78a12, 0x39ca5512d30b41a4,
];
const SUB_0_1: [u64; 6] = [
    0x7708a9fd63fad7c5, 0x723bf8a94bd25aaf, 0x6bdec43e81dd6239, 0x630e4f6f1f69e49e,
    0x1d6b54f972010947, 0x3571b22a6d2e9ad3,
];
const MUL_0_1: [u64; 6] = [
    0xf7fbd6cf75cb7360, 0xd0645a1d358b9153, 0x96541a23ccd3920f, 0x5fc91f990afe4691,
    0xd092e11f0b646037, 0x45a3e82e6476e038,
];
const ADD_0_2: [u64; 6] = [
    0x961a31d64d063d51, 0xaa0814ce594c2d4e, 0xe7cc77ff95d63c50, 0x4d6be1147861aa20,
    0xf573f781b4794f73, 0xe84e2aaac8bd7773,
];
const SUB_0_2: [u64; 6] = [
    0x61c78c3db1257187, 0x4147ea91dfdc685f, 0xcbb691edeeb52511, 0x9ae8baf41b83ece9,
    0x8dedfaed296f43e6, 0x86eddc92777c6503,
];
const MUL_0_2: [u64; 6] = [
    0x0d1b9a600995e9f3, 0x2f955992a1ce1f1d, 0x3e9fc8f13dde2aa6, 0xf2b8d9a4a01b31f9,
    0xb5209e68ff2733ef, 0xd4a55d775b411e88,
];
const ADD_0_3: [u64; 6] = [
    0xba37f6be68de8a45, 0x30a07f8d9e2003da, 0x678d6a766565b6c7, 0x36fc76f6c1feb621,
    0x2e280e6edd7f92f8, 0xa48728465622541d,
];
const SUB_0_3: [u64; 6] = [
    0x3da9c755954d2493, 0xbaaf7fd29b0891d3, 0x4bf59f771f25aa9a, 0xb1582511d1e6e0e9,
    0x5539e40000690061, 0xcab4def6ea17885a,
];
const MUL_0_3: [u64; 6] = [
    0x620fac86075a7a88, 0x55db54965c181011, 0xdf5e8a59eb274264, 0x251a6622f5d8493c,
    0x5ab9e1da86a7a8c0, 0x11f5abc43555170c,
];
const ADD_1_2: [u64; 6] = [
    0x1f1187d8e90b658c, 0x37cc1c250d79d29f, 0x7bedb3c113f8da17, 0xea5d91a558f7c582,
    0xd808a2884278462b, 0xb2dc78805b8edca0,
];
const SUB_1_2: [u64; 6] = [
    0xeabee2404d2a99c2, 0xcf0bf1e8940a0daf, 0x5fd7cdaf6cd7c2d7, 0x37da6b84fc1a084b,
    0x7082a5f3b76e3a9f, 0x517c2a680a4dca30,
];
const MUL_1_2: [u64; 6] = [
    0x2f38a5f5405b8ced, 0x40c58768a17f4bb4, 0xb44f790257ca1450, 0x44a9e0c5370e1c23,
    0x1a8eeee6730680cc, 0x6ead85cd3d95d42b,
];
const ADD_1_3: [u64; 6] = [
    0x432f4cc104e3b280, 0xbe6486e4524da92b, 0xfbaea637e388548d, 0xd3ee2787a294d182,
    0x10bcb9756b7e89b0, 0x6f15761be8f3b94a,
];
const SUB_1_3: [u64; 6] = [
    0xc6a11d5831524cce, 0x487387294f363723, 0xe016db389d484861, 0x4e49d5a2b27cfc4a,
    0x37ce8f068e67f71a, 0x95432ccc7ce8ed87,
];
const MUL_1_3: [u64; 6] = [
    0xf756beef5623ee24, 0x0f1ac48fff29cbd6, 0x4a9c68fb8c339e00, 0x9c9ecd3db790c64a,
    0x5389750f737674d2, 0x4c9c4ded9b18f3c9,
];
const ADD_2_3: [u64; 6] = [
    0x58706a80b7b918be, 0xef5894fbbe439b7b, 0x9bd6d88876b091b5, 0x9c13bc02a67ac937,
    0xa03a1381b4104f11, 0x1d994bb3dea5ef19,
];
const SUB_2_3: [u64; 6] = [
    0xdbe23b17e427b30c, 0x79679540bb2c2973, 0x803f0d8930708589, 0x166f6a1db662f3ff,
    0xc74be912d6f9bc7b, 0x43c70264729b2356,
];
const MUL_2_3: [u64; 6] = [
    0xa502008901e5e6c3, 0x9f4e9af2f530b046, 0xbc62f2e34e01af89, 0x2a93834573a04635,
    0x9b858a58443f35cc, 0x1fe759c6c93919a2,
];

const NEG_0: [u64; 6] = [
    0x040f20f700ea2893, 0x0a58004ee36bb529, 0xa63e7b093dba4f4e, 0x0bd5b1fbb60d347a,
    0x3e4f06c8910bb653, 0x4861fc615fe311c4,
];
const INV_0: [u64; 6] = [
    0xdba830d9f72f1cd5, 0x7b8f2a45d29e6a64, 0x4c4b4f9d0fe87dfd, 0x0ad1ae03e3cf2e45,
    0x57a92ed46d39d475, 0x68cc63583d1a78f2,
];
const NEG_1: [u64; 6] = [
    0x7b17caf464e50058, 0x7c93f8f82f3e0fd8, 0x121d3f47bf97b187, 0x6ee4016ad5771919,
    0x5bba5bc2030cbf9a, 0x7dd3ae8bcd11ac97,
];
const INV_1: [u64; 6] = [
    0x1a054c214a83dd3c, 0xd666438735d7798f, 0x9b135a077beff004, 0xdb361fcd82e9f885,
    0xf081149c04286642, 0x5ff1a9098e3b2b6c,
];
const NEG_2: [u64; 6] = [
    0x65d6ad34b20f9a1a, 0x4b9feae0c3481d88, 0x71f50cf72c6f745f, 0xa6be6cefd1912164,
    0xcc3d01b5ba7afa39, 0xcf4fd8f3d75f76c7,
];
const INV_2: [u64; 6] = [
    0x10fd2156bb82cfc3, 0xd9255d4452084a1f, 0x6fcf54d367e4d052, 0x868b25caead5e3d6,
    0x322b760d45242df8, 0x4bcdfb88c7b2435a,
];
const NEG_3: [u64; 6] = [
    0x41b8e84b96374d27, 0xc50780227e7446fc, 0xf2341a805cdff9e9, 0xbd2dd70d87f41563,
    0x9388eac89174b6b4, 0x1316db5849fa9a1e,
];
const INV_3: [u64; 6] = [
    0xc166cb7ee36d7f0f, 0xfe7c840e3c545a8c, 0xa2a453ea31eefce0, 0x30ae03920d8a5dbe,
    0x414e93c1b106b959, 0x299cda10b995f6db,
];

fn fe(limbs: [u64; 6]) -> P384FieldElement {
    P384FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3].map(fe);
    let pairs: [(usize, usize, [u64; 6], [u64; 6], [u64; 6]); 6] = [
        (0, 1, ADD_0_1, SUB_0_1, MUL_0_1),
        (0, 2, ADD_0_2, SUB_0_2, MUL_0_2),
        (0, 3, ADD_0_3, SUB_0_3, MUL_0_3),
        (1, 2, ADD_1_2, SUB_1_2, MUL_1_2),
        (1, 3, ADD_1_3, SUB_1_3, MUL_1_3),
        (2, 3, ADD_2_3, SUB_2_3, MUL_2_3),
    ];
    for (i, j, a, s, m) in pairs {
        assert_eq!(vals[i].add(&vals[j]), fe(a), "add({i},{j})");
        assert_eq!(vals[j].add(&vals[i]), fe(a), "add is commutative ({j},{i})");
        assert_eq!(vals[i].sub(&vals[j]), fe(s), "sub({i},{j})");
        assert_eq!(vals[i].mul(&vals[j]), fe(m), "mul({i},{j})");
        assert_eq!(vals[j].mul(&vals[i]), fe(m), "mul is commutative ({j},{i})");
    }
    assert_eq!(vals[0].add(&P384FieldElement::ZERO), vals[0]);
    assert_eq!(vals[0].mul(&P384FieldElement::ZERO), P384FieldElement::ZERO);
}

#[test]
fn known_answer_negate_and_invert() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3];
    let negs = [NEG_0, NEG_1, NEG_2, NEG_3];
    let invs = [INV_0, INV_1, INV_2, INV_3];
    for i in 0..4 {
        assert_eq!(fe(vals[i]).negate(), fe(negs[i]), "negate({i})");
        assert_eq!(fe(vals[i]).invert(), fe(invs[i]), "invert({i})");
    }
    assert_eq!(P384FieldElement::ZERO.negate(), P384FieldElement::ZERO);
    assert_eq!(P384FieldElement::ZERO.invert(), P384FieldElement::ZERO);
}

#[test]
fn identities() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4].map(fe);
    for &v in &vals {
        assert_eq!(v.add(&P384FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P384FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P384FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P384FieldElement::ZERO, "x + (-x) == 0");
        if v != P384FieldElement::ZERO {
            assert_eq!(v.mul(&v.invert()), P384FieldElement::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), P384FieldElement::ZERO, "0^-1 == 0 by convention");
        }
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    assert_eq!(fe(bouncycastle_ec::p384::P_LIMBS), P384FieldElement::ZERO);
    let p_plus_1: [u64; 6] = [
        0x0000000100000000, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ];
    assert_eq!(fe(p_plus_1), P384FieldElement::ONE);

    // 2^384 - 1 (all-ones limb pattern) reduces to C - 1 (see the module's reduction constant).
    let all_ones = [u64::MAX; 6];
    let expected_c_minus_1 =
        fe([0xffffffff00000000, 0x00000000ffffffff, 0x0000000000000001, 0, 0, 0]);
    assert_eq!(fe(all_ones), expected_c_minus_1);
}

#[test]
fn to_limbs_round_trips() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4] {
        assert_eq!(fe(limbs).to_limbs(), limbs);
    }
}

#[test]
fn eq_detects_a_difference_in_any_limb() {
    let base = fe(VALS_0);
    assert_eq!(base, fe(VALS_0), "equal values must compare equal");
    for limb_idx in 0..6 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4];
    for i in 0..vals.len() {
        for j in (i + 1)..vals.len() {
            assert_ne!(fe(vals[i]), fe(vals[j]), "VALS_{i} must differ from VALS_{j}");
        }
    }
}

/// xorshift64* PRNG, fixed seed: same rationale as the P-256 field test's property check.
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

    fn next_limbs(&mut self) -> [u64; 6] {
        [
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
        ]
    }
}

#[test]
fn algebraic_identities_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0x243F6A8885A308D3);
    for _ in 0..5000 {
        let a = fe(rng.next_limbs());
        let b = fe(rng.next_limbs());
        let c = fe(rng.next_limbs());

        assert_eq!(a.add(&b), b.add(&a), "add is commutative");
        assert_eq!(a.mul(&b), b.mul(&a), "mul is commutative");
        assert_eq!(a.add(&b).add(&c), a.add(&b.add(&c)), "add is associative");
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)), "mul is associative");
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)), "mul distributes over add");
        assert_eq!(a.sub(&b).add(&b), a, "(a - b) + b == a");
        assert_eq!(a.add(&b).sub(&b), a, "(a + b) - b == a");
        if a != P384FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), P384FieldElement::ONE, "a * a^-1 == 1");
        }
    }
}

/// Products chosen to drive `reduce`'s seven-limb accumulator's top limb across every value it
/// can actually take (3 through 7 here; the bound proved in `reduce`'s own doc comment is 11),
/// so the top-limb fold and the final conditional subtraction are both exercised at their
/// extremes rather than only in the middle of their range. Ordinary pseudorandom operands almost
/// never reach the ends: these were found by searching ~1,000,000 products, including ones biased
/// towards all-ones high words. Expected values are Python's `(a * b) % p`, computed independently
/// of this crate's arithmetic.
///
/// This replaces the in-module `reduce_handles_the_rare_post_two_fold_extra_bit` unit test, which
/// pinned a failure mode of the previous iterated-fold reduction (a rare carry above `2^384` after
/// exactly two folds). That code path no longer exists, and that test's input -- a raw 12-limb
/// value close to `2^768` -- is outside the `t < p^2` precondition the current `reduce` documents,
/// so it could not be carried over unchanged.
#[test]
fn known_answer_mul_at_the_reduction_bounds() {
    let cases: [([u64; 6], [u64; 6], [u64; 6]); 5] = [
        // top limb 3
        (
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000,
            ],
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000,
            ],
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000,
            ],
        ),
        // top limb 4
        (
            [
                0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff,
            ],
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000,
            ],
            [
                0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff,
            ],
        ),
        // top limb 5
        (
            [
                0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff,
            ],
            [
                0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff,
            ],
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000,
            ],
        ),
        // top limb 6
        (
            [
                0xbacbeddb7eea0596, 0x7e8ea0660052d037, 0xf7aaf673fb46bcf4, 0x87098a5d9fa8e4f9,
                0xca88ea5329935120, 0xc366b9e6cd83ddc6,
            ],
            [
                0x580a12619c5075c3, 0x384a158341144e13, 0x6a422b3b33a87fe8, 0xd825ddd3778819a8,
                0x0ac1c96633471bc1, 0x80848cd3620a3f11,
            ],
            [
                0x808d58feda4b3613, 0x92636cea1ec2f04f, 0x32474225dd9fdf1e, 0x91bc9b99dc03254c,
                0xc64619e6770862bd, 0x19536cdb1e70ac25,
            ],
        ),
        // top limb 7
        (
            [
                0x20ed94753ac37e4e, 0x3124891b543422ac, 0xc79f52d2c078b659, 0xa41639f70ec6663a,
                0xe64693456b9add20, 0xc729a2c644808f93,
            ],
            [
                0x0d25af289450acfa, 0xa3e7f461767ab80d, 0x944c547f00d76385, 0xa40ce832090ac314,
                0x259aa3cdc6083ce9, 0xb7f1365bbe074ed1,
            ],
            [
                0xbb546ac08a86eb7d, 0xe1fae828114a744d, 0xb407f44e30b9bad9, 0x697806c9c6e74985,
                0xd370fd0722d05bd6, 0x29040a4e5bde6cb3,
            ],
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(fe(a).mul(&fe(b)), fe(expected), "a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(b).mul(&fe(a)), fe(expected), "commuted: a = {a:x?}, b = {b:x?}");
    }
}

/// `square` is a different routine from `mul`, not a wrapper around it (see the field module's
/// `widening_square`), so the property that makes it correct -- agreeing with `mul` on every
/// input -- is worth pinning directly rather than only through `invert`, which is the only
/// caller that would otherwise exercise it. Includes the values most likely to expose a carry
/// bug in the doubling or diagonal passes: zero, one, and all-ones limbs.
#[test]
fn square_agrees_with_mul() {
    let mut rng = Xorshift64(0xC0FFEE0000000005);
    for _ in 0..5000 {
        let a = fe(rng.next_limbs());
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul");
    }
    for limbs in [
        [0u64; 6],
        {
            let mut l = [0u64; 6];
            l[0] = 1;
            l
        },
        [u64::MAX; 6],
        {
            let mut l = [u64::MAX; 6];
            l[0] = 0;
            l
        },
    ] {
        let a = fe(limbs);
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul for {limbs:x?}");
    }
}

/// `is_zero` is the mask every exceptional-case select in this crate's point arithmetic keys
/// off (infinity detection, the `H == 0` / `R == 0` same-point and opposite-point cases), and
/// otherwise exercised only through those selects. Both truth values are pinned here, with
/// the nonzero side walked across every limb position so a mask that inspected only some limbs
/// would be caught.
#[test]
fn is_zero_distinguishes_zero_from_every_nonzero_limb_position() {
    assert!(P384FieldElement::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::p384::P_LIMBS).is_zero().to_bool(), "p reduces to 0");
    assert!(!P384FieldElement::ONE.is_zero().to_bool());
    for limb_idx in 0..6 {
        let mut limbs = [0u64; 6];
        limbs[limb_idx] = 1;
        assert!(!fe(limbs).is_zero().to_bool(), "a set bit in limb {limb_idx} must be seen");
    }
}

/// `add`'s carry-out correction and `sub`'s borrow correction, pinned at the operands that force
/// them: `(p-1) + (p-1)` is the largest sum two canonical elements can form, and `0 - 1` the
/// smallest difference. The expected values are `p - 2` and `p - 1` themselves (computed from
/// `p` in Python), so this is a check of the wrap-around handling, not of the digits of `p`.
#[test]
fn known_answer_add_carry_and_sub_borrow_at_the_extremes() {
    let p_minus_1 = fe([
        0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ]);
    let p_minus_2 = fe([
        0x00000000fffffffd, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ]);
    let two = fe([
        0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
    ]);

    assert_eq!(p_minus_1.add(&p_minus_1), p_minus_2, "(p-1) + (p-1) == p-2");
    assert_eq!(p_minus_1.add(&P384FieldElement::ONE), P384FieldElement::ZERO, "(p-1) + 1 == 0");
    assert_eq!(P384FieldElement::ZERO.sub(&P384FieldElement::ONE), p_minus_1, "0 - 1 == p-1");
    assert_eq!(P384FieldElement::ONE.sub(&p_minus_1), two, "1 - (p-1) == 2");
    assert_eq!(p_minus_1.negate(), P384FieldElement::ONE, "-(p-1) == 1");
    assert_eq!(P384FieldElement::ONE.invert(), P384FieldElement::ONE, "1^-1 == 1");
    assert_eq!(p_minus_1.invert(), p_minus_1, "(p-1)^-1 == p-1, since (p-1)^2 == 1");
}
