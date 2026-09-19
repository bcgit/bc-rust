//! Known-answer tests for [`P256K1FieldElement`] arithmetic.
//!
//! `p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1` (SEC 2 v2 §2.4.1). Expected values
//! computed independently in Python:
//!
//! ```text
//! p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
//! random.seed(256257)
//! vals = [random.randrange(1, p) for _ in range(4)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % p, (vals[i]-vals[j]) % p, (vals[i]*vals[j]) % p
//! # for each i: (-vals[i]) % p, pow(vals[i], p-2, p) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::p256k1::P256K1FieldElement;

const VALS_0: [u64; 4] =
    [0x1d79dcf976de30b9, 0xc397f473860488a8, 0x71ee41064b94ee22, 0x250bcbb11b3bf238];
const VALS_1: [u64; 4] =
    [0x54f75f31db45259c, 0x6e4dc945e3e2cd85, 0x8931d88ee2f18ae1, 0xe157765b6787ae5a];
const VALS_2: [u64; 4] =
    [0xb5fc00c62432f002, 0x47d7278753fc4fd0, 0x177512e4169a1e3f, 0x694e99e39f271c59];
const VALS_3: [u64; 4] =
    [0x363bc43c067e7409, 0xc631034a05e67b84, 0x106a3de955343c4e, 0x2ee9135e80c0bdf8];
const VALS_4: [u64; 4] = [0, 0, 0, 0];

const ADD_0_1: [u64; 4] =
    [0x72713c2c52235a26, 0x31e5bdb969e7562d, 0xfb2019952e867904, 0x0663420c82c3a092];
const SUB_0_1: [u64; 4] =
    [0xc8827dc69b99074c, 0x554a2b2da221bb22, 0xe8bc687768a36341, 0x43b45555b3b443dd];
const MUL_0_1: [u64; 4] =
    [0x12b3df9da2d0f757, 0xba04254ab048cdaa, 0xc342d06ed5e2a7b8, 0x597190cde3062a98];
const ADD_0_2: [u64; 4] =
    [0xd375ddbf9b1120bb, 0x0b6f1bfada00d878, 0x896353ea622f0c62, 0x8e5a6594ba630e91];
const SUB_0_2: [u64; 4] =
    [0x677ddc3252ab3ce6, 0x7bc0ccec320838d7, 0x5a792e2234facfe3, 0xbbbd31cd7c14d5df];
const MUL_0_2: [u64; 4] =
    [0xac073780ea57fff0, 0x2a6a4a884c941e9c, 0x3c08757bb49d5c72, 0xe297b3604b6e4881];
const ADD_0_3: [u64; 4] =
    [0x53b5a1357d5ca4c2, 0x89c8f7bd8beb042c, 0x82587eefa0c92a71, 0x53f4df0f9bfcb030];
const SUB_0_3: [u64; 4] =
    [0xe73e18bc705fb8df, 0xfd66f129801e0d23, 0x6184031cf660b1d3, 0xf622b8529a7b3440];
const MUL_0_3: [u64; 4] =
    [0xfc5beeeb54d24c73, 0x779717b847d0819a, 0x2448529800ab9845, 0xa491eebb026bfed1];
const ADD_1_2: [u64; 4] =
    [0x0af35ff8ff78196f, 0xb624f0cd37df1d56, 0xa0a6eb72f98ba920, 0x4aa6103f06aecab3];
const SUB_1_2: [u64; 4] =
    [0x9efb5e6bb712359a, 0x2676a1be8fe67db4, 0x71bcc5aacc576ca2, 0x7808dc77c8609201];
const MUL_1_2: [u64; 4] =
    [0x59416a30b93e6b87, 0x405aef00f1c086d3, 0x72995268df93a337, 0xce46213e77403999];
const ADD_1_3: [u64; 4] =
    [0x8b33236ee1c39d76, 0x347ecc8fe9c94909, 0x999c16783825c730, 0x104089b9e8486c52];
const SUB_1_3: [u64; 4] =
    [0x1ebb9af5d4c6b193, 0xa81cc5fbddfc5201, 0x78c79aa58dbd4e92, 0xb26e62fce6c6f062];
const MUL_1_3: [u64; 4] =
    [0x7a070b0eeee214f2, 0x5c7da86c1035cd1c, 0xf83b70133a2410d3, 0x313edd0df41b5d3e];
const ADD_2_3: [u64; 4] =
    [0xec37c5022ab1640b, 0x0e082ad159e2cb54, 0x27df50cd6bce5a8e, 0x9837ad421fe7da51];
const SUB_2_3: [u64; 4] =
    [0x7fc03c8a1db47bf9, 0x81a6243d4e15d44c, 0x070ad4fac165e1f0, 0x3a6586851e665e61];
const MUL_2_3: [u64; 4] =
    [0x54156f3dc5daeeb9, 0x57a6a66eeb4ae815, 0xc028aa05849daab8, 0xef738698d341251a];

const NEG_0: [u64; 4] =
    [0xe28623058921cb76, 0x3c680b8c79fb7757, 0x8e11bef9b46b11dd, 0xdaf4344ee4c40dc7];
const INV_0: [u64; 4] =
    [0x51fbbe545c1fc928, 0xa473aac9d84c2261, 0xc983cfb518b3a5ae, 0x5c7cef3ed3fb59ef];
const NEG_1: [u64; 4] =
    [0xab08a0cd24bad693, 0x91b236ba1c1d327a, 0x76ce27711d0e751e, 0x1ea889a4987851a5];
const INV_1: [u64; 4] =
    [0xd9224b92d2ad8cec, 0x30f0064648dbd35b, 0xd4f070ef5468f757, 0x53a7541b1355bcdb];
const NEG_2: [u64; 4] =
    [0x4a03ff38dbcd0c2d, 0xb828d878ac03b02f, 0xe88aed1be965e1c0, 0x96b1661c60d8e3a6];
const INV_2: [u64; 4] =
    [0xb0c70ca88a757670, 0xd914ab32dd7a94d3, 0xdc060a4814c4e5d7, 0x1a8c4087423108d7];
const NEG_3: [u64; 4] =
    [0xc9c43bc2f9818826, 0x39cefcb5fa19847b, 0xef95c216aacbc3b1, 0xd116eca17f3f4207];
const INV_3: [u64; 4] =
    [0x07d325f509549337, 0x57e3d49afb2fbb81, 0xce4aabc4f0ecfafe, 0xb07744b63424bcec];

fn fe(limbs: [u64; 4]) -> P256K1FieldElement {
    P256K1FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3].map(fe);
    let pairs: [(usize, usize, [u64; 4], [u64; 4], [u64; 4]); 6] = [
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
}

#[test]
fn identities() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4].map(fe);
    for &v in &vals {
        assert_eq!(v.add(&P256K1FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P256K1FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P256K1FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P256K1FieldElement::ZERO, "x + (-x) == 0");
        if v != P256K1FieldElement::ZERO {
            assert_eq!(v.mul(&v.invert()), P256K1FieldElement::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), P256K1FieldElement::ZERO, "0^-1 == 0 by convention");
        }
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    assert_eq!(fe(bouncycastle_ec::p256k1::P_LIMBS), P256K1FieldElement::ZERO);
    let p_plus_1: [u64; 4] =
        [0xfffffffefffffc30, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
    assert_eq!(fe(p_plus_1), P256K1FieldElement::ONE);

    let all_ones = [u64::MAX; 4];
    let expected_c_minus_1 = fe([0x00000001000003d0, 0, 0, 0]);
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
    assert_eq!(base, fe(VALS_0));
    for limb_idx in 0..4 {
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

    fn next_limbs(&mut self) -> [u64; 4] {
        [self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64()]
    }
}

#[test]
fn algebraic_identities_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0x853C49E6748FEA9B);
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
        if a != P256K1FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), P256K1FieldElement::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE0000000002);
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
    assert!(P256K1FieldElement::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::p256k1::P_LIMBS).is_zero().to_bool(), "p reduces to 0");
    assert!(!P256K1FieldElement::ONE.is_zero().to_bool());
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
        fe([0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);
    let p_minus_2 =
        fe([0xfffffffefffffc2d, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);
    let two = fe([0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000]);

    assert_eq!(p_minus_1.add(&p_minus_1), p_minus_2, "(p-1) + (p-1) == p-2");
    assert_eq!(p_minus_1.add(&P256K1FieldElement::ONE), P256K1FieldElement::ZERO, "(p-1) + 1 == 0");
    assert_eq!(P256K1FieldElement::ZERO.sub(&P256K1FieldElement::ONE), p_minus_1, "0 - 1 == p-1");
    assert_eq!(P256K1FieldElement::ONE.sub(&p_minus_1), two, "1 - (p-1) == 2");
    assert_eq!(p_minus_1.negate(), P256K1FieldElement::ONE, "-(p-1) == 1");
    assert_eq!(P256K1FieldElement::ONE.invert(), P256K1FieldElement::ONE, "1^-1 == 1");
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
    let cases: [([u64; 4], [u64; 4], [u64; 4]); 7] = [
        // (p-1)^2 == 1
        (
            [0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        // (p-1)(p-2) == 2
        (
            [0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0xfffffffefffffc2d, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        // (p-1) * 2^(bits-1) == p - 2^(bits-1)
        (
            [0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000],
            [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff],
        ),
        // both operands within 2^64 of p
        (
            [0x602e662b710ddd97, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0xd50f78c27657bf0f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0xe3915864fb4e0b00, 0x1ace8c2a3ef88d00, 0x0000000000000000, 0x0000000000000000],
        ),
        // both operands within 2^64 of p
        (
            [0xfbce55e93e856489, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0xf0fc20c2dcd7c584, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
            [0x77ae56237cd04fe2, 0x003ef93483f7b6de, 0x0000000000000000, 0x0000000000000000],
        ),
        // both operands with the top bit set
        (
            [0xdfa7b2ef07145e3e, 0xc0a3b3952a340c8f, 0xb8032ba581982589, 0x83ecd0900edcab66],
            [0x1cfe03616a76bac0, 0xe47884359ee58544, 0xd9279db7cd8bdeac, 0xd007c87d51d030dd],
            [0x9bbe80289abe2572, 0x43e7c0d1df4dd384, 0x40ffed7a3158451b, 0x38af19b041b3c9c2],
        ),
        // both operands with the top bit set
        (
            [0xe76634fa4c5de998, 0x3ed37b9872aebec2, 0xb4ca47f81e911e82, 0xe6688cf86f78dd4b],
            [0xb5e03e4b503b7594, 0x0a20973673003543, 0x6f155ffa3ec1be68, 0xf95fc497ff1a57ee],
            [0x50b1b28cd4621d6d, 0x5de9bfa26a81ee07, 0xdcd792e32a10cd3e, 0xcdac627a36e71fd3],
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(fe(a).mul(&fe(b)), fe(expected), "a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(b).mul(&fe(a)), fe(expected), "commuted: a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(a).square(), fe(a).mul(&fe(a)), "square at the same extreme: a = {a:x?}");
    }
}
