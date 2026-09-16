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
    assert_eq!(fe(P_LIMBS), Bp512r1FieldElement::ZERO);
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
