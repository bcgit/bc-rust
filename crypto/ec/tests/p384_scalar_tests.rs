//! Known-answer tests for [`P384ScalarField`]/[`P384Scalar`]/[`P384PublicScalar`] arithmetic mod
//! `n`. Expected values computed independently in Python:
//!
//! ```text
//! n = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
//! random.seed(9384)
//! vals = [random.randrange(1, n) for _ in range(3)]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n)
//! ```

use bouncycastle_ec::p384_scalar::{N_LIMBS, P384PublicScalar, P384Scalar, P384ScalarField};

const VALS_0: [u64; 6] = [
    0xc77cb04de57e1b92, 0xb62c49f8ac3809de, 0x87c7a84903ab1b99, 0x68a2bfa3a261cea1,
    0x83e1fdb85f5da002, 0x9ebadd01adfd8d5f,
];
const VALS_1: [u64; 6] = [
    0x87f663fdd6bd5cd5, 0x2909e1888cbdf5e2, 0xbc34c1e9d91e04d6, 0x992805652379593a,
    0x2ef83809b8317ce8, 0x26afaaf741ce6162,
];
const VALS_2: [u64; 6] = [
    0x71e0e730aa68c466, 0x3b1c409aa40050d2, 0xdb1057a1a9aa7f4e, 0x6ae61f716faca098,
    0xcc1d72f963e6eee4, 0x6dbdf6f9b2684c20,
];

const ADD_0_1: [u64; 6] = [
    0x4f73144bbc3b7867, 0xdf362b8138f5ffc1, 0x43fc6a32dcc9206f, 0x01cac508c5db27dc,
    0xb2da35c2178f1ceb, 0xc56a87f8efcbeec1,
];
const SUB_0_1: [u64; 6] = [
    0x3f864c500ec0bebd, 0x8d2268701f7a13fc, 0xcb92e65f2a8d16c3, 0xcf7aba3e7ee87566,
    0x54e9c5aea72c2319, 0x780b320a6c2f2bfd,
];
const MUL_0_1: [u64; 6] = [
    0xdb53314a0c454697, 0x49175dd618eb8014, 0x63ee05b4dad0f31a, 0x38556f1911a87392,
    0x6f4c50aff5b83e01, 0xcbf09493939b36b3,
];
const ADD_0_2: [u64; 6] = [
    0x4c717e13c321b685, 0x992e7ce10787b336, 0x9b74b268b91e6d08, 0xd388df15120e6f3a,
    0x4fff70b1c3448ee6, 0x0c78d3fb6065d980,
];
const SUB_0_2: [u64; 6] = [
    0x559bc91d3b15572c, 0x7b10095e0837b90c, 0xacb750a75a009c4b, 0xfdbca03232b52e08,
    0xb7c48abefb76b11d, 0x30fce607fb95413e,
];
const MUL_0_2: [u64; 6] = [
    0x05cecf9406d1d6fa, 0xd342b24814030464, 0xb7a6b1f2265e9292, 0x9e77bf497f796523,
    0x193b612f3a494ef5, 0xfac75e0481d64319,
];
const ADD_1_2: [u64; 6] = [
    0xf9d74b2e8126213b, 0x6426222330be46b4, 0x9745198b82c88424, 0x040e24d69325f9d3,
    0xfb15ab031c186bcd, 0x946da1f0f436ad82,
];
const SUB_1_2: [u64; 6] = [
    0x03019637f919c1e2, 0x4607aea0316e4c8b, 0xa887b7ca23aab367, 0x2e41e5f3b3ccb8a1,
    0x62dac510544a8e04, 0xb8f1b3fd8f661541,
];
const MUL_1_2: [u64; 6] = [
    0xbb833806cd4db543, 0x241e4163ff6bf90f, 0x70892959a4f05521, 0xcd9551642d7a908c,
    0x5e99c1b61df8c0c6, 0xf7419ab4682320ae,
];

const NEG_0: [u64; 6] = [
    0x256f691ce7470de1, 0xa1edc3b99c789d9c, 0x3f9ba538f08c1245, 0x975d405c5d9e315e,
    0x7c1e0247a0a25ffd, 0x614522fe520272a0,
];
const INV_0: [u64; 6] = [
    0xb1f58808d22a26b3, 0xffca32fa8e1d9879, 0x0a44a0ec41e0054a, 0x4ede6c11a032a009,
    0x0d1688b0b0ebbde3, 0x53fda3065b0e5295,
];
const NEG_1: [u64; 6] = [
    0x64f5b56cf607cc9e, 0x2f102c29bbf2b198, 0x0b2e8b981b192909, 0x66d7fa9adc86a6c5,
    0xd107c7f647ce8317, 0xd9505508be319e9d,
];
const INV_1: [u64; 6] = [
    0x45fc1aeb26427fab, 0xbf3d4a75c92d09c8, 0xffc73cb11601001a, 0x63b7c81239d64bb3,
    0xdfb85303caeafa88, 0x1a3e4c9e01391dec,
];
const NEG_2: [u64; 6] = [
    0x7b0b323a225c650d, 0x1cfdcd17a4b056a8, 0xec52f5e04a8cae91, 0x9519e08e90535f66,
    0x33e28d069c19111b, 0x924209064d97b3df,
];
const INV_2: [u64; 6] = [
    0x7e91a30141508a8f, 0xdcd67e7cf7cb26ec, 0xe038bda04dbbbfd5, 0x207ef90b210da851,
    0xcd01c5c997c5371d, 0x2df22a92c65648b0,
];

fn fe(limbs: [u64; 6]) -> P384ScalarField {
    P384ScalarField::from_limbs(limbs)
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
        assert_eq!(v.add(&P384ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P384ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P384ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P384ScalarField::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), P384ScalarField::ONE, "x * x^-1 == 1");
    }
    assert_eq!(P384ScalarField::ZERO.invert(), P384ScalarField::ZERO, "0^-1 == 0 by convention");
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
    assert_eq!(fe(N_LIMBS), P384ScalarField::ZERO);
}

#[test]
fn secret_scalar_reduces_and_round_trips() {
    let secret = P384Scalar::from_limbs(VALS_0);
    assert_eq!(P384ScalarField::from_secret(&secret), fe(VALS_0));
}

#[test]
fn secret_scalar_reduces_out_of_range_input() {
    let secret = P384Scalar::from_limbs(N_LIMBS);
    assert_eq!(P384ScalarField::from_secret(&secret), P384ScalarField::ZERO);
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        let secret = P384Scalar::from_limbs(limbs);
        let round_tripped = P384Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        assert_eq!(P384PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(P384PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0; 6]);
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
    let mut rng = Xorshift64(0xBB67AE8584CAA73B);
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
        if a != P384ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), P384ScalarField::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE000000000D);
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

/// `zeroize` is the signing path's way of not leaving `d`, `k` or `k^-1` legible on the stack
/// (see the method's own docs for why this type is not wrapped in `Secret` instead). Whether the
/// volatile write survives optimization cannot be observed from Rust; that the value is actually
/// cleared can be, and is what would break if the method were ever reduced to a no-op.
#[test]
fn zeroize_clears_the_value() {
    let mut a = fe([1, 2, 3, 4, 5, 6]);
    assert_ne!(a, P384ScalarField::ZERO, "precondition: the value starts non-zero");
    a.zeroize();
    assert_eq!(a, P384ScalarField::ZERO, "zeroize must leave the value at zero");

    // and it is idempotent, so a caller scrubbing twice on overlapping paths is harmless
    a.zeroize();
    assert_eq!(a, P384ScalarField::ZERO);
}

/// `is_zero` on the scalar field, pinned for both truth values and across every limb position
/// (see the field test of the same name for why); it is the check behind `negate`'s `0 -> 0`
/// special case.
#[test]
fn is_zero_distinguishes_zero_from_every_nonzero_limb_position() {
    assert!(P384ScalarField::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::p384_scalar::N_LIMBS).is_zero().to_bool(), "n reduces to 0");
    assert!(!P384ScalarField::ONE.is_zero().to_bool());
    for limb_idx in 0..6 {
        let mut limbs = [0u64; 6];
        limbs[limb_idx] = 1;
        assert!(!fe(limbs).is_zero().to_bool(), "a set bit in limb {limb_idx} must be seen");
    }
}

/// `n - 1`, the largest canonical scalar, is the worst case for REDC's final conditional
/// subtraction and for `add`'s carry correction, and was absent from every known-answer set
/// above (whose values are pseudorandom, so never near `n`). Expected values follow from
/// `(n-1)^2 == 1` and `(n-1) + (n-1) == n - 2` in the field, computed from `n` in Python.
#[test]
fn known_answer_at_n_minus_1() {
    let n_minus_1_limbs: [u64; 6] = [
        0xecec196accc52972, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ];
    let n_minus_1 = fe(n_minus_1_limbs);
    let n_minus_2 = fe([
        0xecec196accc52971, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ]);

    assert_eq!(n_minus_1.to_limbs(), n_minus_1_limbs, "Montgomery round trip of n-1");
    assert_eq!(P384PublicScalar::from_limbs(n_minus_1_limbs).to_limbs(), n_minus_1_limbs);
    assert_eq!(n_minus_1.add(&n_minus_1), n_minus_2, "(n-1) + (n-1) == n-2");
    assert_eq!(n_minus_1.add(&P384ScalarField::ONE), P384ScalarField::ZERO, "(n-1) + 1 == 0");
    assert_eq!(P384ScalarField::ZERO.sub(&P384ScalarField::ONE), n_minus_1, "0 - 1 == n-1");
    assert_eq!(n_minus_1.mul(&n_minus_1), P384ScalarField::ONE, "(n-1)^2 == 1");
    assert_eq!(n_minus_1.square(), P384ScalarField::ONE, "(n-1)^2 == 1, via square");
    assert_eq!(n_minus_1.negate(), P384ScalarField::ONE, "-(n-1) == 1");
    assert_eq!(n_minus_1.invert(), n_minus_1, "(n-1)^-1 == n-1");
    assert_eq!(P384ScalarField::ONE.invert(), P384ScalarField::ONE, "1^-1 == 1");
}

/// The variable-time inverse on the public scalar type must agree with the constant-time
/// [`P384ScalarField::invert`] everywhere: on the known-answer values (whose inverses are pinned above
/// from Python), on `0` (both return `0` by convention), `1`, `n - 1`, and on pseudorandom
/// values -- including ones with long runs of zero bits, which are where the binary algorithm
/// takes its longest halving chains.
#[test]
fn public_scalar_invert_vartime_agrees_with_constant_time_invert() {
    let n_minus_1 = {
        let mut l = bouncycastle_ec::p384_scalar::N_LIMBS;
        l[0] -= 1;
        l
    };
    let mut one = [0u64; 6];
    one[0] = 1;
    // Values whose low limb is exactly 1 with higher limbs set: odd, so the binary algorithm must
    // not halve them, yet indistinguishable from `1` by their low limb alone. A halving test that
    // looked at more than the lowest bit (or at the wrong limb) breaks the `u == x1 * a` invariant
    // on exactly these and nowhere the pseudorandom inputs below would reach.
    let mut low_limb_one_a = [0u64; 6];
    low_limb_one_a[0] = 1;
    low_limb_one_a[1] = 1;
    let mut low_limb_one_b = [0u64; 6];
    low_limb_one_b[0] = 1;
    low_limb_one_b[5] = 1;
    let mut low_limb_one_c = [0u64; 6];
    low_limb_one_c[0] = 1;
    low_limb_one_c[1] = u64::MAX;
    let mut fixed: Vec<[u64; 6]> =
        vec![[0u64; 6], one, n_minus_1, low_limb_one_a, low_limb_one_b, low_limb_one_c];
    fixed.extend([VALS_0, VALS_1, VALS_2]);
    for limbs in fixed {
        assert_eq!(
            bouncycastle_ec::p384_scalar::P384PublicScalar::from_limbs(limbs).invert_vartime(),
            fe(limbs).invert(),
            "limbs = {limbs:x?}"
        );
    }
    assert_eq!(
        bouncycastle_ec::p384_scalar::P384PublicScalar::from_limbs([0u64; 6]).invert_vartime(),
        P384ScalarField::ZERO,
        "0^-1 == 0 by convention, matching invert"
    );

    let mut rng = Xorshift64(0x1AC0_B5EC_0000_0006);
    for i in 0..500 {
        let mut limbs = rng.next_limbs();
        if i % 4 == 0 {
            // Sparse values: clear the low half of each limb so `u`/`v` shed many bits per step.
            for limb in limbs.iter_mut() {
                *limb &= 0xffff_ffff_0000_0000;
            }
        }
        assert_eq!(
            bouncycastle_ec::p384_scalar::P384PublicScalar::from_limbs(limbs).invert_vartime(),
            fe(limbs).invert(),
            "limbs = {limbs:x?}"
        );
    }
}
