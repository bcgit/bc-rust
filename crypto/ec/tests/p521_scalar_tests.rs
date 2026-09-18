//! Known-answer tests for [`P521ScalarField`]/[`P521Scalar`]/[`P521PublicScalar`] arithmetic mod
//! `n`. Expected values computed independently in Python:
//!
//! ```text
//! n = 0x1ff...386409  (SP 800-186 S3.2.1.5)
//! random.seed(5219)
//! vals = [random.randrange(1, n) for _ in range(3)]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n)
//! ```

use bouncycastle_ec::p521_scalar::{N_LIMBS, P521PublicScalar, P521Scalar, P521ScalarField};

const VALS_0: [u64; 9] = [
    0x5ce2f91065c121a3, 0xc8e8826a5dcc634c, 0x4f47b2008123a7a7, 0xab27f49f94c37c7d,
    0x4a4c1bd63979854c, 0x3ce767e9c4382eec, 0x4959fc2dbe7df0bc, 0x129a79eb6fd54403,
    0x0000000000000102,
];
const VALS_1: [u64; 9] = [
    0x93985d64330b16c6, 0xa23434d4e6af01f9, 0x3ff355eb83baff0e, 0xdad0d0f13b77ff4d,
    0x17ba7558683f48d6, 0x6927b5c13d54de16, 0x62f5cbef7f9256c7, 0x0912c6abda627bac,
    0x00000000000001dd,
];
const VALS_2: [u64; 9] = [
    0xd99593ba9e8b62bc, 0x420bf9c9cd23eda2, 0x6b277737a52c9953, 0x021f3e401f9ecc08,
    0xbcceb29f4d04f8b2, 0x77af21289d42a7cc, 0xb09286a4f455bdbd, 0xcdfc2630981136b8,
    0x00000000000000c0,
];

const ADD_0_1: [u64; 9] = [
    0x350b9f560793d460, 0x2f66ed86badf1d97, 0x0f6f06a30dd500e6, 0x34723e0d110be55f,
    0x6206912ea1b8ce29, 0xa60f1dab018d0d02, 0xac4fc81d3e104783, 0x1bad40974a37bfaf,
    0x00000000000000df,
];
const SUB_0_1: [u64; 9] = [
    0x84ba52cac3ee6ee6, 0x626a174e00b9a901, 0x8f205d5df4724e69, 0x21ddab32187b139b,
    0x3291a67dd13a3c70, 0xd3bfb22886e350d6, 0xe664303e3eeb99f4, 0x0987b33f9572c856,
    0x0000000000000125,
];
const MUL_0_1: [u64; 9] = [
    0xc9fe37ec76abed5e, 0xf28c37faf99f76f9, 0xb7e359a692e7404c, 0xf085ef6f4e604369,
    0xca06c54beaf122b2, 0xad197cc87f2b61ce, 0x71d11f19a0c6737d, 0xbcbe539da7e29cce,
    0x000000000000004d,
];
const ADD_0_2: [u64; 9] = [
    0x36788ccb044c845f, 0x0af47c342af050ef, 0xba6f2938265040fb, 0xad4732dfb4624885,
    0x071ace75867e7dfe, 0xb4968912617ad6b9, 0xf9ec82d2b2d3ae79, 0xe096a01c07e67abb,
    0x00000000000001c2,
];
const SUB_0_2: [u64; 9] = [
    0x834d6555c735bee7, 0x86dc88a090a875a9, 0xe4203ac8dbf70e54, 0xa908b65f7524b074,
    0x8d7d6936ec748c9a, 0xc53846c126f5871f, 0x98c77588ca2832fe, 0x449e53bad7c40d4a,
    0x0000000000000041,
];
const MUL_0_2: [u64; 9] = [
    0xbc7c5b09c402fe98, 0x0796c9bff0a67848, 0x77f150e2bb527e58, 0x1b79203e4772b620,
    0xd0d31d5da56c8a22, 0x65d64f9ca9a18a00, 0xc65f22bc9cb803dd, 0x0c4039d6fc290863,
    0x000000000000004c,
];
const ADD_1_2: [u64; 9] = [
    0xb1be3a00405e1579, 0xa88a64e62a36a7ed, 0x2b4ecbda31ddf291, 0x8b6987ad9be734ea,
    0xd48927f7b544418e, 0xe0d6d6e9da9785e2, 0x1388529473e81484, 0xd70eecdc7273b265,
    0x000000000000009d,
];
const SUB_1_2: [u64; 9] = [
    0xba02c9a9947fb40a, 0x60283b0b198b1456, 0xd4cbdeb3de8e65bb, 0xd8b192b11bd93344,
    0x5aebc2b91b3a5024, 0xf1789498a0123649, 0xb263454a8b3c9909, 0x3b16a07b425144f3,
    0x000000000000011c,
];
const MUL_1_2: [u64; 9] = [
    0xecea78b68d157f8e, 0x750560668d085538, 0x8f38d46ed239d602, 0xddf7f7827c4b2d33,
    0x86254741e445d3f8, 0x08586a6147980a4a, 0x6fd47182d1ab49d9, 0xca6e20f84c4d9b99,
    0x000000000000016d,
];

const NEG_0: [u64; 9] = [
    0x5e8cbe0e2b774266, 0x72cd474e2bcfe462, 0x30844f4875e5fe28, 0xa65e92e42a6c19ee,
    0xb5b3e429c6867aad, 0xc31898163bc7d113, 0xb6a603d241820f43, 0xed658614902abbfc,
    0x00000000000000fd,
];
const INV_0: [u64; 9] = [
    0x93a286c6686a12b3, 0x3a981f3823b3cfeb, 0xb22f2f86b1262a22, 0xbc6587cf6e99f392,
    0xe1baa4dc8fa450b6, 0xdf84af5eae83aa5a, 0x0dffa9471e228b8f, 0x8d73ccc631cd5211,
    0x0000000000000059,
];
const NEG_1: [u64; 9] = [
    0x27d759ba5e2d4d43, 0x998194e3a2ed45b5, 0x3fd8ab5d734ea6c1, 0x76b5b69283b7971e,
    0xe8458aa797c0b723, 0x96d84a3ec2ab21e9, 0x9d0a3410806da938, 0xf6ed3954259d8453,
    0x0000000000000022,
];
const INV_1: [u64; 9] = [
    0x6bfe7b8ce691f33a, 0xcffacd5693bc23e3, 0xfd019050df92d40f, 0x8a8c89ab282b53f4,
    0xf174e0c3c827b21b, 0xa12189d8ca396fcf, 0x3bc42d335b0dc0a6, 0x19dd4775e6c38723,
    0x00000000000001bd,
];
const NEG_2: [u64; 9] = [
    0xe1da2363f2ad014d, 0xf9a9cfeebc785a0b, 0x14a48a1151dd0c7c, 0x4f6749439f90ca63,
    0x43314d60b2fb0748, 0x8850ded762bd5833, 0x4f6d795b0baa4242, 0x3203d9cf67eec947,
    0x000000000000013f,
];
const INV_2: [u64; 9] = [
    0x1d19864c85afbe2e, 0x69dec1d4f00a2a49, 0xae9d8cd7f679b1e0, 0x0ed53d62cfc273be,
    0xdefd40a242d40d95, 0xdd2cb3a608535d12, 0xeec21bcf59830179, 0x51806ff643fa3421,
    0x00000000000000e9,
];

fn fe(limbs: [u64; 9]) -> P521ScalarField {
    P521ScalarField::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2].map(fe);
    let pairs: [(usize, usize, [u64; 9], [u64; 9], [u64; 9]); 3] = [
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
        assert_eq!(v.add(&P521ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P521ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P521ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P521ScalarField::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), P521ScalarField::ONE, "x * x^-1 == 1");
    }
    assert_eq!(P521ScalarField::ZERO.invert(), P521ScalarField::ZERO, "0^-1 == 0 by convention");
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
    for limb_idx in 0..9 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    assert_eq!(fe(N_LIMBS), P521ScalarField::ZERO);
}

/// Regression test for a real bug: an earlier `from_limbs` reduced with a single conditional
/// subtraction, valid only for input `< 2n`. A raw `[u64; 9]` can represent values up to `2^576 -
/// 1`, some 55 bits more than `n`, so that assumption was false for genuinely wide input -- caught
/// not by this file's own (then top-limb-masked) property test, but by real ECDSA verification
/// math in the wycheproof P-521 suite. These two values -- computed independently in Python, not
/// from this crate -- are far outside the old single-subtraction's valid range.
#[test]
fn from_limbs_reduces_input_far_beyond_2n() {
    let all_ones = [u64::MAX; 9];
    let expected_all_ones: [u64; 9] = [
        0xfb7fffffffffffff, 0x28a2482470b763cd, 0x17e2251b23bb31dc, 0xca4019ff5b847b2d,
        0x02d73cbc3e206834, 0, 0, 0, 0,
    ];
    assert_eq!(fe(all_ones), fe(expected_all_ones));

    // 7*n + 12345, deliberately several multiples of n above the single-subtraction's range.
    let seven_n_plus: [u64; 9] = [
        0x200e01d5f88aec78, 0xa1f8840bc345f5c7, 0x7e9408fec14388b1, 0x3aadb49a3a4d1cf0,
        0xffffffffffffffd8, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0dff,
    ];
    assert_eq!(fe(seven_n_plus), fe([12345, 0, 0, 0, 0, 0, 0, 0, 0]));
}

#[test]
fn secret_scalar_reduces_and_round_trips() {
    let secret = P521Scalar::from_limbs(VALS_0);
    assert_eq!(P521ScalarField::from_secret(&secret), fe(VALS_0));
}

#[test]
fn secret_scalar_reduces_out_of_range_input() {
    let secret = P521Scalar::from_limbs(N_LIMBS);
    assert_eq!(P521ScalarField::from_secret(&secret), P521ScalarField::ZERO);
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        let secret = P521Scalar::from_limbs(limbs);
        let round_tripped = P521Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        assert_eq!(P521PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(P521PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0; 9]);
}

/// xorshift64* PRNG, fixed seed: same rationale as the P-256 field test's property check. Every
/// limb, including the top one, is left as a full random `u64`: `from_limbs` must correctly reduce
/// any of the `2^576` values a raw `[u64; 9]` can represent, not just those `< 2n` -- see
/// `from_limbs_reduces_input_far_beyond_2n`'s docs for the bug an earlier version had, which this
/// deliberately-unmasked generation is what would have caught.
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

    fn next_limbs(&mut self) -> [u64; 9] {
        let mut limbs = [0u64; 9];
        for l in limbs.iter_mut() {
            *l = self.next_u64();
        }
        limbs
    }
}

#[test]
fn algebraic_identities_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0xC2B2AE3D27D4EB4F);
    // 1000, not 5000 -- see p521_field_tests.rs's identical property test for why.
    for _ in 0..1000 {
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
        if a != P521ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), P521ScalarField::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE0000000010);
    for _ in 0..5000 {
        let a = fe(rng.next_limbs());
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul");
    }
    for limbs in [
        [0u64; 9],
        {
            let mut l = [0u64; 9];
            l[0] = 1;
            l
        },
        [u64::MAX; 9],
        {
            let mut l = [u64::MAX; 9];
            l[0] = 0;
            l
        },
    ] {
        let a = fe(limbs);
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul for {limbs:x?}");
    }
}

/// `zeroize` is the signing path's way of not leaving `d`, `k` or `k^-1` legible on the stack
/// (see the method's own docs for why this type is not wrapped in `Secret` instead). Whether the
/// volatile write survives optimization cannot be observed from Rust; that the value is actually
/// cleared can be, and is what would break if the method were ever reduced to a no-op.
#[test]
fn zeroize_clears_the_value() {
    let mut a = fe([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_ne!(a, P521ScalarField::ZERO, "precondition: the value starts non-zero");
    a.zeroize();
    assert_eq!(a, P521ScalarField::ZERO, "zeroize must leave the value at zero");

    // and it is idempotent, so a caller scrubbing twice on overlapping paths is harmless
    a.zeroize();
    assert_eq!(a, P521ScalarField::ZERO);
}
