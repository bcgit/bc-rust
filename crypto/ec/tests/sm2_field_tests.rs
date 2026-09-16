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
