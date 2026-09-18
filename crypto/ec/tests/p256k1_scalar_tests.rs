//! Known-answer tests for [`P256K1ScalarField`]/[`P256K1Scalar`]/[`P256K1PublicScalar`] arithmetic
//! mod `n`. Expected values computed independently in Python:
//!
//! ```text
//! n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
//! random.seed(9384)
//! vals = [random.randrange(1, n) for _ in range(3)]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n)
//! ```

use bouncycastle_ec::p256k1_scalar::{
    N_LIMBS, P256K1PublicScalar, P256K1Scalar, P256K1ScalarField,
};

const VALS_0: [u64; 4] =
    [0xc77cb04de57e1b92, 0xb62c49f8ac3809de, 0x87c7a84903ab1b99, 0x68a2bfa3a261cea1];
const VALS_1: [u64; 4] =
    [0x83e1fdb85f5da003, 0x9ebadd01adfd8d5f, 0x87f663fdd6bd5cd4, 0x2909e1888cbdf5e2];
const VALS_2: [u64; 4] =
    [0xbc34c1e9d91e04d7, 0x992805652379593a, 0x2ef83809b8317ce8, 0x26afaaf741ce6162];

const ADD_0_1: [u64; 4] =
    [0x4b5eae0644dbbb95, 0x54e726fa5a35973e, 0x0fbe0c46da68786e, 0x91aca12c2f1fc484];
const SUB_0_1: [u64; 4] =
    [0x439ab29586207b8f, 0x17716cf6fe3a7c7f, 0xffd1444b2cedbec5, 0x3f98de1b15a3d8be];
const MUL_0_1: [u64; 4] =
    [0x2a5bc077905603d1, 0x0279a77a67d9f751, 0xe79bb660d346023f, 0x18a7b810e9f8c46b];
const ADD_0_2: [u64; 4] =
    [0x83b17237be9c2069, 0x4f544f5dcfb16319, 0xb6bfe052bbdc9882, 0x8f526a9ae4303003];
const SUB_0_2: [u64; 4] =
    [0x0b47ee640c6016bb, 0x1d04449388beb0a4, 0x58cf703f4b799eb1, 0x41f314ac60936d3f];
const MUL_0_2: [u64; 4] =
    [0x9149a980bb219504, 0x018fdddd856d04af, 0x9de5e0ad83e7b09b, 0x3d6ce1dc1e08b32e];
const ADD_1_2: [u64; 4] =
    [0x4016bfa2387ba4da, 0x37e2e266d176e69a, 0xb6ee9c078eeed9bd, 0x4fb98c7fce8c5744];
const SUB_1_2: [u64; 4] =
    [0xc7ad3bce863f9b2c, 0x0592d79c8a843424, 0x58fe2bf41e8bdfec, 0x025a36914aef9480];
const MUL_1_2: [u64; 4] =
    [0x2f36d4e288f5f11e, 0xc063c1277a4f5a4b, 0xa1cc3a541c11f76d, 0xb84da028335accb8];

const NEG_0: [u64; 4] =
    [0xf855ae3eeab825af, 0x048292ee0310965c, 0x783857b6fc54e465, 0x975d405c5d9e315e];
const INV_0: [u64; 4] =
    [0x5caf1566d4a30b98, 0x02516ac43cbc4edd, 0xf39fa3889f4727f5, 0x7b473842b2a3515e];
const NEG_1: [u64; 4] =
    [0x3bf060d470d8a13e, 0x1bf3ffe5014b12dc, 0x78099c022942a32a, 0xd6f61e7773420a1d];
const INV_1: [u64; 4] =
    [0x47d7cc33ae095bf8, 0xd67d5cc78acede87, 0xebba12ce17ad83be, 0x2f52e24b1ab3e925];
const NEG_2: [u64; 4] =
    [0x039d9ca2f7183c6a, 0x2186d7818bcf4701, 0xd107c7f647ce8316, 0xd9505508be319e9d];
const INV_2: [u64; 4] =
    [0x4087e71103f99cb2, 0xc0e93d9c142f8435, 0x51ede30026aea71a, 0x8eb5e166fb519e3a];

fn fe(limbs: [u64; 4]) -> P256K1ScalarField {
    P256K1ScalarField::from_limbs(limbs)
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
        assert_eq!(v.add(&P256K1ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P256K1ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P256K1ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P256K1ScalarField::ZERO, "x + (-x) == 0");
        assert_eq!(v.mul(&v.invert()), P256K1ScalarField::ONE, "x * x^-1 == 1");
    }
    assert_eq!(
        P256K1ScalarField::ZERO.invert(),
        P256K1ScalarField::ZERO,
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
    assert_eq!(fe(N_LIMBS), P256K1ScalarField::ZERO);
}

#[test]
fn secret_scalar_reduces_and_round_trips() {
    let secret = P256K1Scalar::from_limbs(VALS_0);
    assert_eq!(P256K1ScalarField::from_secret(&secret), fe(VALS_0));
}

#[test]
fn secret_scalar_reduces_out_of_range_input() {
    let secret = P256K1Scalar::from_limbs(N_LIMBS);
    assert_eq!(P256K1ScalarField::from_secret(&secret), P256K1ScalarField::ZERO);
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        let secret = P256K1Scalar::from_limbs(limbs);
        let round_tripped = P256K1Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2] {
        assert_eq!(P256K1PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(P256K1PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0; 4]);
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
        if a != P256K1ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), P256K1ScalarField::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE000000000A);
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

/// `zeroize` is the signing path's way of not leaving `d`, `k` or `k^-1` legible on the stack
/// (see the method's own docs for why this type is not wrapped in `Secret` instead). Whether the
/// volatile write survives optimization cannot be observed from Rust; that the value is actually
/// cleared can be, and is what would break if the method were ever reduced to a no-op.
#[test]
fn zeroize_clears_the_value() {
    let mut a = fe([1, 2, 3, 4]);
    assert_ne!(a, P256K1ScalarField::ZERO, "precondition: the value starts non-zero");
    a.zeroize();
    assert_eq!(a, P256K1ScalarField::ZERO, "zeroize must leave the value at zero");

    // and it is idempotent, so a caller scrubbing twice on overlapping paths is harmless
    a.zeroize();
    assert_eq!(a, P256K1ScalarField::ZERO);
}
