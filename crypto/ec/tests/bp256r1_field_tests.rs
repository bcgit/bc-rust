//! Known-answer tests for [`Bp256r1FieldElement`] arithmetic. Expected values computed
//! independently in Python:
//!
//! ```text
//! p = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
//! random.seed(2560256)
//! vals = [random.randrange(1, p) for _ in range(3)]
//! ```

use bouncycastle_ec::bp256r1::Bp256r1FieldElement;

const VALS_0: [u64; 4] =
    [0xb4b76e9c3e0696d7, 0x6978c023e8559edd, 0x9929473357b901b0, 0x52ab03860069228e];
const VALS_1: [u64; 4] =
    [0x2d3cc3f5bb18a119, 0x2e88e3651dfa0ef6, 0x09778cd067fad368, 0x61d733f9016bb161];
const VALS_2: [u64; 4] =
    [0x124a5bf60cbb67a0, 0x521bc0efbdd51add, 0xe37d905da3bd5b7e, 0x97b610bcd35b4d14];

const ADD_0_1: [u64; 4] =
    [0xc1e0ea74d9b0e479, 0x29c5ad6531298dab, 0x643ac973223047a6, 0x0a86dfa35fe62a33];
const SUB_0_1: [u64; 4] =
    [0xa78df2c3a25c4935, 0xa92bd2e29f81b00f, 0xce17c4f38d41bbba, 0x9acf2768a0ec1ae9];
const MUL_0_1: [u64; 4] =
    [0x996756f13a9f75c2, 0x9ee4cb0249a9601e, 0x2fb3949c468534ed, 0x9dd8a748da7081fc];
const ADD_0_2: [u64; 4] =
    [0xa6ee82752b53ab00, 0x4d588aefd1049992, 0x3e40cd005df2cfbc, 0x4065bc6731d5c5e7];
const SUB_0_2: [u64; 4] =
    [0xc2805ac350b982ae, 0x8598f557ffa6a428, 0xf411c166517f33a4, 0x64f04aa4cefc7f35];
const MUL_0_2: [u64; 4] =
    [0x7b8209c92be4a50b, 0x90d24caa244a2bbc, 0x0a31c9ecd85c36cd, 0x2907d8ce540f36e0];
const ADD_1_2: [u64; 4] =
    [0x1f73d7cea865b542, 0x1268ae3106a909ab, 0xae8f129d6e34a174, 0x4f91ecda32d854b9];
const SUB_1_2: [u64; 4] =
    [0x3b05b01ccdcb8cf0, 0x4aa91899354b1441, 0x6460070361c1055c, 0x741c7b17cfff0e08];
const MUL_1_2: [u64; 4] =
    [0xea94aa665f314b4d, 0x3735e3f1265d9a91, 0x3608b85373a98110, 0x2e3e5cade58a3691];

const NEG_0: [u64; 4] =
    [0x6b5bd980e167bca0, 0x04c335ffecd0814a, 0xa53cc35d45ca8bc2, 0x57505455a185872d];
const INV_0: [u64; 4] =
    [0x024bfbb6bb50057e, 0x6999cac61dc2af6c, 0xb2db58c58538fe5d, 0x86005a26300178a7];
const NEG_1: [u64; 4] =
    [0xf2d684276455b25e, 0x3fb312beb72c1131, 0x34ee7dc03588ba0a, 0x482423e2a082f85b];
const INV_1: [u64; 4] =
    [0x19338439822f7dcb, 0x30c88a4091b117f2, 0xf89059499b3a1310, 0x10f0efcb8f77da09];
const NEG_2: [u64; 4] =
    [0x0dc8ec2712b2ebd7, 0x1c2035341751054b, 0x5ae87a32f9c631f4, 0x1245471ece935ca7];
const INV_2: [u64; 4] =
    [0x5c40b4ad887af6ac, 0x9149a743b580ec29, 0xe421eaa4e216daab, 0x60e61eb16f319668];

fn fe(limbs: [u64; 4]) -> Bp256r1FieldElement {
    Bp256r1FieldElement::from_limbs(limbs)
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
        assert_eq!(v.add(&Bp256r1FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Bp256r1FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Bp256r1FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Bp256r1FieldElement::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), Bp256r1FieldElement::ONE, "x * x^-1 == 1");
    }
    assert_eq!(
        Bp256r1FieldElement::ZERO.invert(),
        Bp256r1FieldElement::ZERO,
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
    for limb_idx in 0..4 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    use bouncycastle_ec::bp256r1::P_LIMBS;
    // p itself must reduce to 0, and p+1 to 1.
    assert_eq!(fe(P_LIMBS), Bp256r1FieldElement::ZERO);
    assert_eq!(
        fe([0x2013481d1f6e5378, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc]),
        Bp256r1FieldElement::ONE
    );

    // The maximum limb pattern, 2^256 - 1, is the widest input the single conditional
    // subtraction has to cover (it is < 2p, since p > 2^255); expected value is
    // 2^256 - 1 - p, computed in Python.
    assert_eq!(
        fe([u64::MAX; 4]),
        fe([0xdfecb7e2e091ac88, 0x91c409dc2ad9dfd7, 0xc199f56f627c728d, 0x5604a8245e115643])
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

    fn next_limbs(&mut self) -> [u64; 4] {
        [self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64()]
    }
}

#[test]
fn algebraic_identities_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0xB5A11E5A11E5B5A1);
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
        if a != Bp256r1FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), Bp256r1FieldElement::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE0000000004);
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
    assert!(Bp256r1FieldElement::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::bp256r1::P_LIMBS).is_zero().to_bool(), "p reduces to 0");
    assert!(!Bp256r1FieldElement::ONE.is_zero().to_bool());
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
        fe([0x2013481d1f6e5376, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc]);
    let p_minus_2 =
        fe([0x2013481d1f6e5375, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc]);
    let two = fe([0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000]);

    assert_eq!(p_minus_1.add(&p_minus_1), p_minus_2, "(p-1) + (p-1) == p-2");
    assert_eq!(
        p_minus_1.add(&Bp256r1FieldElement::ONE),
        Bp256r1FieldElement::ZERO,
        "(p-1) + 1 == 0"
    );
    assert_eq!(Bp256r1FieldElement::ZERO.sub(&Bp256r1FieldElement::ONE), p_minus_1, "0 - 1 == p-1");
    assert_eq!(Bp256r1FieldElement::ONE.sub(&p_minus_1), two, "1 - (p-1) == 2");
    assert_eq!(p_minus_1.negate(), Bp256r1FieldElement::ONE, "-(p-1) == 1");
    assert_eq!(Bp256r1FieldElement::ONE.invert(), Bp256r1FieldElement::ONE, "1^-1 == 1");
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
            [0x2013481d1f6e5376, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x2013481d1f6e5376, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        // (p-1)(p-2) == 2
        (
            [0x2013481d1f6e5376, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x2013481d1f6e5375, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        // (p-1) * 2^(bits-1) == p - 2^(bits-1)
        (
            [0x2013481d1f6e5376, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000],
            [0x2013481d1f6e5377, 0x6e3bf623d5262028, 0x3e660a909d838d72, 0x29fb57dba1eea9bc],
        ),
        // both operands within 2^64 of p
        (
            [0x42f16588ab38db81, 0x6e3bf623d5262027, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0xb88cd6435e191cfd, 0x6e3bf623d5262027, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x8ee275f9f3770f3c, 0x596cc43e62331583, 0x0000000000000000, 0x0000000000000000],
        ),
        // both operands within 2^64 of p
        (
            [0x7e6bee23576cad67, 0x6e3bf623d5262027, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0xeb8178c615941584, 0x6e3bf623d5262027, 0x3e660a909d838d72, 0xa9fb57dba1eea9bc],
            [0x55edac6f37c27130, 0x213210fdfaf3dd11, 0x0000000000000000, 0x0000000000000000],
        ),
        // both operands with the top bit set
        (
            [0x35a4fd8d5d0e0d44, 0x009a7390e7e34e82, 0x5d1f1b0f6be8d021, 0xa839e4d3b95980af],
            [0x5eb8baefb2b23ce5, 0x8409e6f65dd90b53, 0x9f0b5ec8807db146, 0x9fa88c95a7b0b5b2],
            [0xf9b64af6ceabe3b5, 0xaadf5792205e4ecc, 0xd860664d6031cc11, 0x7f1499cc8fd2f83e],
        ),
        // both operands with the top bit set
        (
            [0x1108e28819183525, 0x5f4239f80228423b, 0xd816dfd7771d5f7d, 0xa1fafce172bc1011],
            [0x913ab474603f4513, 0x3885cc6ffcb2a055, 0xe4fdc11a9ab24157, 0xa52f75124f2ff581],
            [0x90e40a31c6528827, 0xc40c43b69f963a52, 0x4a5b250f463bf3f7, 0x1f336e46db83d34a],
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(fe(a).mul(&fe(b)), fe(expected), "a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(b).mul(&fe(a)), fe(expected), "commuted: a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(a).square(), fe(a).mul(&fe(a)), "square at the same extreme: a = {a:x?}");
    }
}
