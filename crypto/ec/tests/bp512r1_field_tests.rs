//! Known-answer tests for [`Bp512r1FieldElement`] arithmetic. Expected values computed
//! independently in Python:
//!
//! ```text
//! p = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3
//! random.seed(512256)
//! vals = [random.randrange(1, p) for _ in range(3)]
//! ```

use bouncycastle_ec::bp512r1::Bp512r1FieldElement;

const VALS_0: [u64; 8] = [
    0x337b305d3dae11f7, 0x9a0e685d00e50ffb, 0x20de024e6e702163, 0xc6cbe74f04fffde6,
    0x1aa4a7e8de900164, 0x7020023b3948ad73, 0xe38738b2110eeb8a, 0x9ac32dabfdf6cc6a,
];
const VALS_1: [u64; 8] = [
    0xb5a040b9e9952d99, 0x8d4827f2d807fb55, 0xf6a40ce0710df9e9, 0xcc17138a5e9399a6,
    0xe8bcdbef0eaea63e, 0x2ccc1c0bbfca1304, 0x9c49d912867eb4fd, 0x5ca72cdde0671ebd,
];
const VALS_2: [u64; 8] = [
    0xcef9df78cab56bed, 0x7e73181220467918, 0x11e27aad93bf8bf2, 0xa7cb1c3a8e7a0340,
    0xdf0f27f3dec18923, 0xd8d645667d6eb048, 0xe8ff417831c028e4, 0x7a65f1457edd80cd,
];

const ADD_0_1: [u64; 8] = [
    0xc07110c0cf08f69d, 0xfed49120ab6a44cb, 0x68b46e03f8da9a66, 0x15955fd8c7cd2f4a,
    0x2cfde70d7d0b9f32, 0xd1bb90934548ee69, 0x3ffc2b1663c3a47f, 0x4c8cbcd10274269d,
];
const SUB_0_1: [u64; 8] = [
    0x7ddaefa35418e45e, 0x0cc6406a28dd14a5, 0x2a39f56dfd62277a, 0xfab4d3c4a66c643f,
    0x31e7cbf9cfe15b25, 0x4353e62f797e9a6e, 0x473d5f9f8a90368d, 0x3e1c00ce1d8fadad,
];
const MUL_0_1: [u64; 8] = [
    0x7fd7e4e5ba099749, 0xc172dfaab2d795bc, 0x52316d19b6ea8913, 0x3ba73c885e93ca3d,
    0x5a58f3dbbc4862ae, 0x030cfe3ae6b57e73, 0xec26fbc5794dbabd, 0x4e49089233647524,
];
const ADD_0_2: [u64; 8] = [
    0xd9caaf7fb02934f1, 0xefff813ff3a8c28e, 0x83f2dbd11b8c2c6f, 0xf1496888f7b398e3,
    0x235033124d1e8216, 0x7dc5b9ee02ed8bad, 0x8cb1937c0f051867, 0x6a4b8138a0ea88ad,
];
const SUB_0_2: [u64; 8] = [
    0x648150e472f8a60a, 0x1b9b504ae09e96e2, 0x0efb87a0dab09571, 0x1f00cb147685faa6,
    0x3b957ff4ffce7841, 0x9749bcd4bbd9fd2a, 0xfa87f739df4ec2a5, 0x205d3c667f194b9c,
];
const MUL_0_2: [u64; 8] = [
    0x8e044ad76f99bdd8, 0x42e41dbf91bec416, 0xe7de54a2bb0da823, 0xea4d40c0a249aa3e,
    0xefbb09a11cf5b168, 0xc9d10888667929b4, 0x656b4aed0849f1bd, 0x0f720ad097add84a,
];
const ADD_1_2: [u64; 8] = [
    0x5befbfdc5c105093, 0xe33940d5cacbade9, 0x59b8e6631e2a04f5, 0xf69494c4514734a4,
    0xf16867187d3d26f0, 0x3a71d3be896ef13e, 0x457433dc8474e1da, 0x2c2f806a835adb00,
];
const SUB_1_2: [u64; 8] = [
    0x0f50c197771a0a9f, 0x37570f0fe54448c2, 0x938f335dc3f1eedd, 0xa19992506bdffea9,
    0xe01150c5a020258c, 0x1f266458f62534ca, 0xf31f7e4888888820, 0x8d1ed9513d73627a,
];
const MUL_1_2: [u64; 8] = [
    0xa31a6937df4f002d, 0x330286cb160d2aab, 0x2cc9cedc00898bbf, 0x11cd54a8b7b446fb,
    0x54e88b2ce997ac41, 0x681379fa1ee294f9, 0xe97935422b763368, 0x454ccf8627e24388,
];

const NEG_0: [u64; 8] = [
    0xf52f2ff91a8c36fc, 0x8e7396d22c9db689, 0x8def9edc78335f82, 0xb681b3b196c66a5c,
    0xbbbef4e191a3070c, 0x5b108b787a81249b, 0x5c4dadfc22bb107d, 0x101a700cddf2f820,
];
const INV_0: [u64; 8] = [
    0x41ed9ee9edf1e127, 0x629b65e1983ad38d, 0x381369c6c22fc3eb, 0xf4434f36655e7b9b,
    0xc36a56c05b37b57b, 0x023e5b2381c593f8, 0x6c8d112743f7c34b, 0x9412b9a2e555f20d,
];
const NEG_1: [u64; 8] = [
    0x730a1f9c6ea51b5a, 0x9b39d73c557acb2f, 0xb829944a759586fc, 0xb13687763d32ce9b,
    0xeda6c0db61846232, 0x9e6471a7f3ffbf09, 0xa38b0d9bad4b470a, 0x4e3670dafb82a5cd,
];
const INV_1: [u64; 8] = [
    0xca11b244b43e0ae8, 0xe93482a21cb9770c, 0x3f62aaac168db6a0, 0x70de41428b5d1922,
    0x5a68aac40d187bf6, 0x0a009a925a7a6031, 0x78d4a9241ff9bf94, 0x94974ce662b85e02,
];
const NEG_2: [u64; 8] = [
    0x59b080dd8d84dd06, 0xaa0ee71d0d3c4d6c, 0x9ceb267d52e3f4f3, 0xd5827ec60d4c6502,
    0xf75474d691717f4d, 0xf25a484d365b21c5, 0x56d5a5360209d322, 0x3077ac735d0c43bd,
];
const INV_2: [u64; 8] = [
    0x5d7759458b030e5c, 0x881a07b802a6ba18, 0xfda20f60de456b62, 0xeaeae6130dc42c59,
    0x8d627e9151b969ea, 0x10ba57632a83524c, 0x6dd740d37a266bff, 0x773c96b9eaa954ac,
];

fn fe(limbs: [u64; 8]) -> Bp512r1FieldElement {
    Bp512r1FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2].map(fe);
    let pairs: [(usize, usize, [u64; 8], [u64; 8], [u64; 8]); 3] = [
        (0, 1, ADD_0_1, SUB_0_1, MUL_0_1),
        (0, 2, ADD_0_2, SUB_0_2, MUL_0_2),
        (1, 2, ADD_1_2, SUB_1_2, MUL_1_2),
    ];
    for (i, j, a, s, m) in pairs {
        assert_eq!(vals[i].add(&vals[j]), fe(a), "add({i},{j})");
        assert_eq!(vals[j].add(&vals[i]), fe(a), "add is commutative ({j},{i})");
        assert_eq!(vals[i].sub(&vals[j]), fe(s), "sub({i},{j})");
        assert_eq!(vals[i].mul(&vals[j]), fe(m), "mul({i},{j})");
        assert_eq!(vals[j].mul(&vals[i]), fe(m), "mul is commutative ({j},{i})");
    }
}

#[test]
fn known_answer_negate_and_invert() {
    let vals = [VALS_0, VALS_1, VALS_2];
    let negs = [NEG_0, NEG_1, NEG_2];
    let invs = [INV_0, INV_1, INV_2];
    for i in 0..3 {
        assert_eq!(fe(vals[i]).negate(), fe(negs[i]), "negate({i})");
        assert_eq!(fe(vals[i]).invert(), fe(invs[i]), "invert({i})");
    }
}

#[test]
fn identities() {
    let vals = [VALS_0, VALS_1, VALS_2].map(fe);
    for &v in &vals {
        assert_eq!(v.add(&Bp512r1FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Bp512r1FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Bp512r1FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Bp512r1FieldElement::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), Bp512r1FieldElement::ONE, "x * x^-1 == 1");
    }
    assert_eq!(
        Bp512r1FieldElement::ZERO.invert(),
        Bp512r1FieldElement::ZERO,
        "0^-1 == 0 by convention"
    );
}

#[test]
fn to_limbs_round_trips() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        assert_eq!(fe(limbs).to_limbs(), limbs);
    }
}

#[test]
fn eq_detects_a_difference_in_any_limb() {
    let base = fe(VALS_0);
    assert_eq!(base, fe(VALS_0));
    for limb_idx in 0..8 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    use bouncycastle_ec::bp512r1::P_LIMBS;
    // p itself must reduce to 0, and p+1 to 1.
    assert_eq!(fe(P_LIMBS), Bp512r1FieldElement::ZERO);
    assert_eq!(
        fe([
            0x28aa6056583a48f4, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
            0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b
        ]),
        Bp512r1FieldElement::ONE
    );

    // The maximum limb pattern, 2^512 - 1, is the widest input the single conditional
    // subtraction has to cover (it is < 2p, since p > 2^511); expected value is
    // 2^512 - 1 - p, computed in Python.
    assert_eq!(
        fe([u64::MAX; 8]),
        fe([
            0xd7559fa9a7c5b70c, 0xd77e00d0d27d397a, 0x51325ed5195c7f19, 0x82b264ff643997bd,
            0x299c63358fccf78e, 0x34cf724c4c362df1, 0xc02b1951cc3603f8, 0x5522624724163b74
        ])
    );
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

    fn next_limbs(&mut self) -> [u64; 8] {
        [
            self.next_u64(),
            self.next_u64(),
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
    let mut rng = Xorshift64(0xB512256B512256B5);
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
        if a != Bp512r1FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), Bp512r1FieldElement::ONE, "a * a^-1 == 1");
        }
    }
}

/// `square` is a different routine from `mul`, not a wrapper around it (see the field module's
/// `widening_square`), so the property that makes it correct -- agreeing with `mul` on every
/// input -- is worth pinning directly rather than only through `invert`, which is the only
/// caller that would otherwise exercise it. Includes the values most likely to expose a carry
/// bug in the doubling or diagonal passes: zero, one, and all-ones limbs.
#[test]
fn square_agrees_with_mul() {
    let mut rng = Xorshift64(0xC0FFEE0000000007);
    for _ in 0..5000 {
        let a = fe(rng.next_limbs());
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul");
    }
    for limbs in [
        [0u64; 8],
        {
            let mut l = [0u64; 8];
            l[0] = 1;
            l
        },
        [u64::MAX; 8],
        {
            let mut l = [u64::MAX; 8];
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
    assert!(Bp512r1FieldElement::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::bp512r1::P_LIMBS).is_zero().to_bool(), "p reduces to 0");
    assert!(!Bp512r1FieldElement::ONE.is_zero().to_bool());
    for limb_idx in 0..8 {
        let mut limbs = [0u64; 8];
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
        0x28aa6056583a48f2, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
        0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ]);
    let p_minus_2 = fe([
        0x28aa6056583a48f1, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
        0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ]);
    let two = fe([
        0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ]);

    assert_eq!(p_minus_1.add(&p_minus_1), p_minus_2, "(p-1) + (p-1) == p-2");
    assert_eq!(
        p_minus_1.add(&Bp512r1FieldElement::ONE),
        Bp512r1FieldElement::ZERO,
        "(p-1) + 1 == 0"
    );
    assert_eq!(Bp512r1FieldElement::ZERO.sub(&Bp512r1FieldElement::ONE), p_minus_1, "0 - 1 == p-1");
    assert_eq!(Bp512r1FieldElement::ONE.sub(&p_minus_1), two, "1 - (p-1) == 2");
    assert_eq!(p_minus_1.negate(), Bp512r1FieldElement::ONE, "-(p-1) == 1");
    assert_eq!(Bp512r1FieldElement::ONE.invert(), Bp512r1FieldElement::ONE, "1^-1 == 1");
    assert_eq!(p_minus_1.invert(), p_minus_1, "(p-1)^-1 == p-1, since (p-1)^2 == 1");
}

/// Products at the reduction's extremes rather than in the middle of its range, the same class
/// of check `p256_field_tests.rs`/`p384_field_tests.rs`/`sm2_field_tests.rs` already carry and
/// this curve did not: `(p-1)^2` and `(p-1)(p-2)` (the largest products two canonical elements
/// can form), operands within `2^64` of `p`, and operands with the top bit set. Expected values
/// are Python's `(a * b) % p`, computed independently of this crate's arithmetic
/// (`random.seed(20260918)` for the pseudorandom operands).
#[test]
fn known_answer_mul_at_the_reduction_bounds() {
    let cases: [([u64; 8], [u64; 8], [u64; 8]); 7] = [
        // (p-1)^2 == 1
        (
            [
                0x28aa6056583a48f2, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x28aa6056583a48f2, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
        ),
        // (p-1)(p-2) == 2
        (
            [
                0x28aa6056583a48f2, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x28aa6056583a48f1, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
        ),
        // (p-1) * 2^(bits-1) == p - 2^(bits-1)
        (
            [
                0x28aa6056583a48f2, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000,
            ],
            [
                0x28aa6056583a48f3, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0x2add9db8dbe9c48b,
            ],
        ),
        // both operands within 2^64 of p
        (
            [
                0x1b159ef51f1c31ba, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x4133222820236744, 0x2881ff2f2d82c684, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0xb1071c91f4e0f8f7, 0x0c478df11945c04d, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
        ),
        // both operands within 2^64 of p
        (
            [
                0x62ac133e50395289, 0x2881ff2f2d82c684, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x623bcfdeff7791a6, 0x2881ff2f2d82c684, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
                0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
            ],
            [
                0x2629eea844c3e3e2, 0x997832a10fbd8ca7, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
        ),
        // both operands with the top bit set
        (
            [
                0xbe535d1034b561c4, 0xa87a664d92a30a7c, 0x377af0518c372858, 0x88e45984ca23e7e7,
                0x24d89be08e24a733, 0x114eb63a3f93f12e, 0x0dfe4515f0c4913d, 0x910e948373cd463e,
            ],
            [
                0x531ae1b5518b6f90, 0x8610dc484a75b54f, 0x77614f1c416a4a75, 0x94a81f1a876316be,
                0x50babfc04b10be47, 0x5eb5adf69baf73cb, 0x545c70351b88e1b3, 0x918329026e50138d,
            ],
            [
                0x5ed4e9b6c60565dd, 0x17f28073cf6b3d64, 0x7276b4974f2527c1, 0x47a893403c53bd46,
                0xc7b0ae0b687b05b9, 0x88d85354bf92319a, 0xfba4bb8e9eba49cb, 0x92822cb5a91351a7,
            ],
        ),
        // both operands with the top bit set
        (
            [
                0x3321dbf084e48e4f, 0x145b706f1b5e50db, 0x712cccef3ba46161, 0xa8ffb21b1b668159,
                0x1962770441c58300, 0x29cf9eb19ee826bd, 0xa9f908bb470d2e17, 0xa8f73debe3d87f40,
            ],
            [
                0xaf588834885477cd, 0x76d4b6faa2e5a4b7, 0x7796e22eda5368f9, 0xf6b6487a2ecee85d,
                0xb348365113507314, 0xf8188df8d2f6ffd8, 0x28f96ea5a33fc277, 0x9bb18fdddce4f62e,
            ],
            [
                0xba5c5f288de9dea9, 0x10bc414bec68ac72, 0x6a393e92f54abad0, 0x1422fce8c87fa1f5,
                0x82b31aaf3bb909b6, 0xf6d57d61c836fc23, 0x25ad448d71a4dfce, 0x2c58b753d0cb00f0,
            ],
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(fe(a).mul(&fe(b)), fe(expected), "a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(b).mul(&fe(a)), fe(expected), "commuted: a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(a).square(), fe(a).mul(&fe(a)), "square at the same extreme: a = {a:x?}");
    }
}
