//! Known-answer tests for [`Bp384r1FieldElement`] arithmetic. Expected values computed
//! independently in Python:
//!
//! ```text
//! p = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53
//! random.seed(384256)
//! vals = [random.randrange(1, p) for _ in range(3)]
//! ```

use bouncycastle_ec::bp384r1::Bp384r1FieldElement;

const VALS_0: [u64; 6] = [
    0xe90f0d68176b0cc9, 0x271f0b47d6dacd22, 0xe4561568c8e4b445, 0xde8c273c4ad5adc5,
    0xc3b58c6c32d5e314, 0x560cf7adaef2d174,
];
const VALS_1: [u64; 6] = [
    0x931520ab505d451d, 0x9bcdf724ffd8834a, 0x65529eb4084ada66, 0xad9b03fc815ca29f,
    0x4fe04118812251d0, 0x803c39b51164dc37,
];
const VALS_2: [u64; 6] = [
    0x0c44eade679d0641, 0x5fb85ed8258f72e6, 0x8919a88f010cdfa3, 0x8d4a0c8146d4495f,
    0x9d112be8cf6abfea, 0x577a293dc1e0b7cb,
];

const ADD_0_1: [u64; 6] = [
    0xf4dd2e0036c06593, 0x16195b43469635fb, 0x36f6da0351787d88, 0x76f7ba2ededdf9b1,
    0x04385e066311f306, 0x499012e01d1f4084,
];
const SUB_0_1: [u64; 6] = [
    0xdd40eccff815b3ff, 0x3824bb4c671f6449, 0x91b550ce4050eb02, 0x46209449b6cd61da,
    0x8332bad20299d323, 0x6289dc7b40c66265,
];
const MUL_0_1: [u64; 6] = [
    0x16ab4196494bc886, 0xf9ffcf0c65de7c1a, 0x2efcf0c1d784d40d, 0xca93391ba1bfaa78,
    0xe850cc1f9e4abb0e, 0x5454c5b74eaab75b,
];
const ADD_0_2: [u64; 6] = [
    0x6e0cf8334e0026b7, 0xda03c2f66c4d2597, 0x5abde3de4a3a82c4, 0x56a6c2b3a455a071,
    0x516948d6b15a6120, 0x20ce0268cd9b1c18,
];
const SUB_0_2: [u64; 6] = [
    0x6411229ce0d5f2db, 0x743a5399416874ae, 0x6dee46f3478ee5c5, 0x66718bc4f155bb1a,
    0x3601d001b4516509, 0x8b4becf2904a86d1,
];
const MUL_0_2: [u64; 6] = [
    0xd55eb22ceb7b3edd, 0xc04e2d3e03f9cde5, 0x3e65bce2a2be0732, 0x889698f8c7184a34,
    0x5609874cc0afe05c, 0x713a84d1029c4523,
];
const ADD_1_2: [u64; 6] = [
    0x18130b7686f25f0b, 0x4eb2aed3954adbbf, 0xdbba6d2989a0a8e6, 0x25b59f73dadc954a,
    0xdd93fd82ffa6cfdc, 0x4afd4470300d26da,
];
const SUB_1_2: [u64; 6] = [
    0x86d035cce8c03edc, 0x3c15984cda491064, 0xdc38f625073dfac3, 0x2050f77b3a88593f,
    0xb2cf152fb1b791e6, 0x28c210774f84246b,
];
const MUL_1_2: [u64; 6] = [
    0x48159ae5c970da1d, 0x2304b7b61c54409f, 0xcc5d58ed1b043712, 0xe1342527d8b63815,
    0x9f40259285258008, 0x6a2d27fb82ae65c2,
];

const NEG_0: [u64; 6] = [
    0x9e37f2ab199cdf8a, 0x85b49be1b9424d4e, 0x2e5bc4b0b6d25cde, 0x36a349cda27ea8ee,
    0x4ba7e3121e105eca, 0x36ac26d4f4459bb3,
];
const INV_0: [u64; 6] = [
    0x5497899b46d8de80, 0x502b8865ff2d58be, 0x9c5bf2402a1b41ec, 0x51fd2c0170cb44d5,
    0x5e96ca30a78ff76a, 0x2ba42d9c14320fd7,
];
const NEG_1: [u64; 6] = [
    0xf431df67e0aaa736, 0x1105b00490449726, 0xad5f3b65776c36bd, 0x67946d0d6bf7b414,
    0xbf7d2e65cfc3f00e, 0x0c7ce4cd91d390f0,
];
const INV_1: [u64; 6] = [
    0xc7e57cb0e8d1c7c7, 0x7abbf2c650b96c6e, 0xc3fe516f3ac8d0ab, 0xd6d53abfd2a65751,
    0x10f52f8b187fb324, 0x0ebfbe830ce54e9f,
];
const NEG_2: [u64; 6] = [
    0x7b021534c96ae612, 0x4d1b48516a8da78b, 0x8998318a7eaa3180, 0x87e56488a6800d54,
    0x724c4395817b81f4, 0x353ef544e157b55c,
];
const INV_2: [u64; 6] = [
    0xfe45ef3f26ff6712, 0x2e87f5087bf83fc7, 0x07f45274b036d768, 0xdf7d46d6f954134b,
    0x67e4cd7fbae2e29e, 0x64458f53448d9fef,
];

fn fe(limbs: [u64; 6]) -> Bp384r1FieldElement {
    Bp384r1FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2].map(fe);
    let pairs: [(usize, usize, [u64; 6], [u64; 6], [u64; 6]); 3] = [
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
        assert_eq!(v.add(&Bp384r1FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Bp384r1FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Bp384r1FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Bp384r1FieldElement::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), Bp384r1FieldElement::ONE, "x * x^-1 == 1");
    }
    assert_eq!(
        Bp384r1FieldElement::ZERO.invert(),
        Bp384r1FieldElement::ZERO,
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
    for limb_idx in 0..6 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    use bouncycastle_ec::bp384r1::P_LIMBS;
    assert_eq!(fe(P_LIMBS), Bp384r1FieldElement::ZERO);
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
    let mut rng = Xorshift64(0xC384256C384256C3);
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
        if a != Bp384r1FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), Bp384r1FieldElement::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE0000000006);
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
