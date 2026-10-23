//! Known-answer tests for [`Sm2FieldElement`] arithmetic. Expected values computed independently
//! in Python:
//!
//! ```text
//! p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
//! random.seed(2025256)
//! vals = [random.randrange(1, p) for _ in range(3)]
//! ```

use bouncycastle_ec::sm2::Sm2FieldElement;

const VALS_0: [u64; 4] =
    [0xa5a1f45ea143fd85, 0xb169fcb29ca305fd, 0xb041efa5f7f9075e, 0x8273a708ddcf1813];
const VALS_1: [u64; 4] =
    [0x5d4318d45d5f398b, 0x66a31f481118c121, 0x9b935fea7664e927, 0x9c69a61bd28edef4];
const VALS_2: [u64; 4] =
    [0xd72fd065c85ddd2a, 0x054e35f32200b154, 0x4bf4e4bd8a7637ed, 0x0ffca7096cc68ba9];

const ADD_0_1: [u64; 4] =
    [0x02e50d32fea33711, 0x180d1bfbadbbc71e, 0x4bd54f906e5df086, 0x1edd4d25b05df708];
const SUB_0_1: [u64; 4] =
    [0x485edb8a43e4c3f9, 0x4ac6dd698b8a44dd, 0x14ae8fbb81941e37, 0xe60a00ec0b40391f];
const MUL_0_1: [u64; 4] =
    [0x22a1478fb52c780e, 0x784fac3d31786ba8, 0x42a03a2563709066, 0x4c3e29f24dca72aa];
const ADD_0_2: [u64; 4] =
    [0x7cd1c4c469a1daaf, 0xb6b832a5bea3b752, 0xfc36d463826f3f4b, 0x92704e124a95a3bc];
const SUB_0_2: [u64; 4] =
    [0xce7223f8d8e6205b, 0xac1bc6bf7aa254a8, 0x644d0ae86d82cf71, 0x7276ffff71088c6a];
const MUL_0_2: [u64; 4] =
    [0xd8a3fa50e531f3c2, 0xb93450874072c8b8, 0x8af50b9cd5261363, 0x17d5bc770d7fb2bf];
const ADD_1_2: [u64; 4] =
    [0x3472e93a25bd16b5, 0x6bf1553b33197276, 0xe78844a800db2114, 0xac664d253f556a9d];
const SUB_1_2: [u64; 4] =
    [0x8613486e95015c61, 0x6154e954ef180fcc, 0x4f9e7b2cebeeb13a, 0x8c6cff1265c8534b];
const MUL_1_2: [u64; 4] =
    [0x89f03ef7a609798b, 0x68d0d8512c1ba481, 0x8d119a103a42baf4, 0x7c08a7922d7bce22];

const NEG_0: [u64; 4] =
    [0x5a5e0ba15ebc027a, 0x4e96034c635cfa03, 0x4fbe105a0806f8a1, 0x7d8c58f62230e7ec];
const INV_0: [u64; 4] =
    [0x5251f7c6fd8bcb7a, 0x2d5d57166464d1b1, 0x993bb82ff6813b65, 0xb7a104986836f5a2];
const NEG_1: [u64; 4] =
    [0xa2bce72ba2a0c674, 0x995ce0b6eee73edf, 0x646ca015899b16d8, 0x639659e32d71210b];
const INV_1: [u64; 4] =
    [0x2bab29fd023acd08, 0xca14cd4dc683f729, 0xdbaacf938a4fce8e, 0x509a135380735a7c];
const NEG_2: [u64; 4] =
    [0x28d02f9a37a222d5, 0xfab1ca0bddff4eac, 0xb40b1b427589c812, 0xf00358f593397456];
const INV_2: [u64; 4] =
    [0xe8af5ae64649385b, 0x6a4ae6428703f329, 0xa3206cd2ad67c05f, 0x4af82ae209016e95];

fn fe(limbs: [u64; 4]) -> Sm2FieldElement {
    Sm2FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2].map(fe);
    let pairs: [(usize, usize, [u64; 4], [u64; 4], [u64; 4]); 3] = [
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
        assert_eq!(v.add(&Sm2FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Sm2FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Sm2FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Sm2FieldElement::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), Sm2FieldElement::ONE, "x * x^-1 == 1");
    }
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
    for limb_idx in 0..4 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    use bouncycastle_ec::sm2::P_LIMBS;
    assert_eq!(fe(P_LIMBS), Sm2FieldElement::ZERO);
}

/// xorshift64* PRNG, fixed seed: deterministic across runs, needs no external dependency.
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

#[test]
fn algebraic_identities_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0x5252525252525252);
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
        if a != Sm2FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), Sm2FieldElement::ONE, "a * a^-1 == 1");
        }
    }
}

/// Products chosen to drive `reduce`'s five-limb accumulator's top limb across every value
/// it can actually take (4 through 17 here; the bound proved in `reduce`'s own doc comment is
/// 18), so the top-limb fold and the final conditional subtraction are both
/// exercised at their extremes rather than only in the middle of their range. Ordinary
/// pseudorandom operands almost never reach the ends: these were found by searching ~900,000
/// products, including ones biased towards all-ones high words. Expected values are Python's
/// `(a * b) % p`, computed independently of this crate's arithmetic.
#[test]
fn known_answer_mul_at_the_reduction_bounds() {
    // (a, b, a*b mod p), one per reachable top-limb value, ascending.
    let cases: [([u64; 4], [u64; 4], [u64; 4]); 14] = [
        // top limb 4
        (
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        // top limb 5
        (
            [0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
            [0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff],
        ),
        // top limb 6
        (
            [0x33acc967df52efc7, 0x4fc1db5f2d8f3e07, 0x3be79cc15726eb41, 0x4acdf8fb1f50e4ee],
            [0xe698a0b713235314, 0x126146b6bd8dc7dc, 0x64b6da27c8fc0161, 0x40c2450df5c15810],
            [0x202c17c130933e53, 0x93bb3a5c05e5ec9b, 0xf355099dc623c874, 0xbcf5484c97d86554],
        ),
        // top limb 7
        (
            [0x7030a50db754f89a, 0x8769ca02ea303e0d, 0x65e987940ba28ac9, 0x16cabd95e22dbc49],
            [0xeaeecfb77a462a47, 0x200ada18f2088666, 0xd86c0bc0f4cee0ac, 0x58a43d2b2d2e7fc6],
            [0xee7ac5c13d33448a, 0x1e5ac068ced0478d, 0x8e405143688797e9, 0x723010bdf644c241],
        ),
        // top limb 8
        (
            [0xc79c6ae82a4ddcd8, 0x32edb25757d1a11b, 0x51f24f89eb9d46ea, 0xd60bec7706f8e4f3],
            [0x9b75cd625142260a, 0xbffedee5673265bf, 0x32737e9a11dd0076, 0x0c61cb71776a0c7d],
            [0xe5fe086f5e8659dd, 0xbadd10879dc3bcad, 0xfb842ae9198d41d5, 0xeda9e6e9234a4780],
        ),
        // top limb 9
        (
            [0x6c15a5b7a31b9a88, 0xad60872bf7608860, 0x614e0ac60406e6c8, 0x3f35c1e61fcd76ff],
            [0xfb2dc41468f25be3, 0x395bc78b8b245993, 0xff2fa10e3f16ca83, 0xfe188bb380f05577],
            [0x7264eb6ad238cd0e, 0x201c0d755c2682dd, 0x482b8e0a56ae3670, 0xa782a032109e3bf9],
        ),
        // top limb 10
        (
            [0x3b8104488f2d8e22, 0x598dd6fa99c39428, 0xc161a8733a085adb, 0xffe7bdaff61a76c4],
            [0xeb9029f855dc1b56, 0x38f25c15a4af1600, 0xa6f43ed979d8ede6, 0x2227407b18226e55],
            [0x1f56e64ff2e30e9b, 0x590c81056d431a75, 0x5c73a8e0a26cbc09, 0x3438eb3dafc32768],
        ),
        // top limb 11
        (
            [0x42c7f4e1c0e0861c, 0xef54ec651388b2e2, 0xf4de87fa4830146c, 0x71e39cf9a0ce11e0],
            [0xe949f0e05fd3df71, 0xa56faa8a75a9f029, 0xb642126f51468661, 0x82dc965565f17d15],
            [0x47f79ca7ce88003b, 0xdcd3336c11ea2ca5, 0x37e16c292ff9cf37, 0xb1d7dda6fa4fda60],
        ),
        // top limb 12
        (
            [0xd8c527101686c8dd, 0x3969aaaea1ef7f3d, 0x12340033bd89d876, 0xbd01b5599f65d691],
            [0xfad40f4becb9c562, 0xc31a25b3f569ad7e, 0xe1a9bf6a8a30bb6b, 0xbef2eb0a5a696886],
            [0xdb635b24042727b1, 0x632417b5038d7677, 0xc0a0d36d47d08092, 0x553574b2d67ef0b6],
        ),
        // top limb 13
        (
            [0x6c77da1c15ab106b, 0x45389e945635d4a8, 0x72330b666db8f163, 0xe094e7425acc5486],
            [0xf05a046171a9f871, 0xe41082c1e2b853a3, 0x68ed177d17a99c38, 0xc31c5e8e401cffae],
            [0xa120e10e9e05550e, 0x85c78a523499599d, 0x53fefd01687260e6, 0x4776539506828316],
        ),
        // top limb 14
        (
            [0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff],
            [0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        // top limb 15
        (
            [0x422e012c71efc130, 0xaf9f500c9b843cff, 0x35ed557e70de52b2, 0xf8117bd39a627a5d],
            [0xc5e7878d071a87d9, 0xa9661930992c7856, 0xcfe94313890735ba, 0xd7f003fcc8760cb4],
            [0xda27792522c7096a, 0x8d9c12d268e4bdd5, 0x78a6f489d79a2e93, 0x39c44b39d3676947],
        ),
        // top limb 16
        (
            [0x19f1eef25e979f0b, 0x98c338454a8ebf94, 0xd3ade626e6492ef2, 0xf6efa94e0854aa85],
            [0x39b0369ebeb3d1ae, 0x88ff2fa60a290270, 0x86b7590537824835, 0xc5a61e2646e26036],
            [0x9d545cf849a44895, 0x01a8480ed66873aa, 0x93408ccf38921617, 0x5f38ac6852629955],
        ),
        // top limb 17
        (
            [0x82b76b3e7be5d265, 0x53b7d7a65091ebbf, 0xd43a1492f17c0abc, 0xb44383d7925bfff9],
            [0x428a7dcb2f5f4779, 0x7904375252397080, 0x41a1d2610e45d683, 0xfee086171cf0cf63],
            [0x888fd29356771e3d, 0x4e88d54595b59b9a, 0x6e411bba9d44960d, 0x0c4c6fc746169b40],
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
    let mut rng = Xorshift64(0xC0FFEE0000000003);
    for _ in 0..5000 {
        let a = fe(rng.next_limbs());
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul");
    }
    for limbs in [
        [0u64; 4],
        {
            let mut l = [0u64; 4];
            l[0] = 1;
            l
        },
        [u64::MAX; 4],
        {
            let mut l = [u64::MAX; 4];
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
    assert!(Sm2FieldElement::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::sm2::P_LIMBS).is_zero().to_bool(), "p reduces to 0");
    assert!(!Sm2FieldElement::ONE.is_zero().to_bool());
    for limb_idx in 0..4 {
        let mut limbs = [0u64; 4];
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
    let p_minus_1 =
        fe([0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff]);
    let p_minus_2 =
        fe([0xfffffffffffffffd, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff]);
    let two = fe([0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000]);

    assert_eq!(p_minus_1.add(&p_minus_1), p_minus_2, "(p-1) + (p-1) == p-2");
    assert_eq!(p_minus_1.add(&Sm2FieldElement::ONE), Sm2FieldElement::ZERO, "(p-1) + 1 == 0");
    assert_eq!(Sm2FieldElement::ZERO.sub(&Sm2FieldElement::ONE), p_minus_1, "0 - 1 == p-1");
    assert_eq!(Sm2FieldElement::ONE.sub(&p_minus_1), two, "1 - (p-1) == 2");
    assert_eq!(p_minus_1.negate(), Sm2FieldElement::ONE, "-(p-1) == 1");
    assert_eq!(Sm2FieldElement::ONE.invert(), Sm2FieldElement::ONE, "1^-1 == 1");
    assert_eq!(p_minus_1.invert(), p_minus_1, "(p-1)^-1 == p-1, since (p-1)^2 == 1");
}
