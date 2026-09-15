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
    assert_eq!(fe(P_LIMBS), Bp256r1FieldElement::ZERO);
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
