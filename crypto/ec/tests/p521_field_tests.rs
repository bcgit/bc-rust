//! Known-answer tests for [`P521FieldElement`] arithmetic.
//!
//! `p = 2**521 - 1` (a Mersenne prime). Expected values computed independently in Python:
//!
//! ```text
//! p = 2**521 - 1
//! random.seed(5521)
//! vals = [random.randrange(1, p) for _ in range(4)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % p, (vals[i]-vals[j]) % p, (vals[i]*vals[j]) % p
//! # for each i: (-vals[i]) % p, pow(vals[i], p-2, p) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::p521::P521FieldElement;

const VALS_0: [u64; 9] = [
    0xb08b02bcbe1a026f, 0x6ac488dbbc8cd11f, 0x003d56d89b9f4cbb, 0x4d4bb7d2842e9790,
    0xe86a5650cfe21007, 0x4c7042c229a92107, 0x91854abbc0616220, 0x873c6380b019c44f,
    0x0000000000000051,
];
const VALS_1: [u64; 9] = [
    0xed0a9b9aba01374f, 0x26374507740013c3, 0xdd87874ca2b46fb6, 0x22904689b624e3b5,
    0xca4770c12693afe9, 0x66fad105f7a891d9, 0xa51f452115f34715, 0x6eb27e737ad931f1,
    0x000000000000003b,
];
const VALS_2: [u64; 9] = [
    0x67b414d048d25b17, 0x311e0def6fc4e352, 0x779d713c52df9b16, 0xc947965c490081e6,
    0xf7036f209bcd40b9, 0x324fad803dbd6a0a, 0xa1980b35c1a2a7b0, 0x324eee29a82f54b1,
    0x00000000000000e6,
];
const VALS_3: [u64; 9] = [
    0x323abbc2772f3a85, 0x43e1ef8055199654, 0x2869ed6f16b488d7, 0x8ac5ece9e24296a5,
    0xceb010a6fdfe5509, 0x24bf4fe166fb3034, 0x31817bc54c7ce6e2, 0xcdbbe03f68211317,
    0x0000000000000001,
];
const VALS_4: [u64; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 0];

const ADD_0_1: [u64; 9] = [
    0x9d959e57781b39be, 0x90fbcde3308ce4e3, 0xddc4de253e53bc71, 0x6fdbfe5c3a537b45,
    0xb2b1c711f675bff0, 0xb36b13c82151b2e1, 0x36a48fdcd654a935, 0xf5eee1f42af2f641,
    0x000000000000008c,
];
const SUB_0_1: [u64; 9] = [
    0xc38067220418cb20, 0x448d43d4488cbd5b, 0x22b5cf8bf8eadd05, 0x2abb7148ce09b3da,
    0x1e22e58fa94e601e, 0xe57571bc32008f2e, 0xec66059aaa6e1b0a, 0x1889e50d3540925d,
    0x0000000000000016,
];
const MUL_0_1: [u64; 9] = [
    0x751afa5884d561d7, 0xe24d4d2f56f4c78a, 0xd1cd1c910b34e1b3, 0x1350bc38b5e023ce,
    0xa56bee5956ba51cf, 0xb39085c080f2c977, 0xf4dbcacd56201d75, 0x1f72ac36f2e48919,
    0x00000000000001d6,
];
const ADD_0_2: [u64; 9] = [
    0x183f178d06ec5d86, 0x9be296cb2c51b472, 0x77dac814ee7ee7d1, 0x16934e2ecd2f1976,
    0xdf6dc5716baf50c1, 0x7ebff04267668b12, 0x331d55f1820409d0, 0xb98b51aa58491901,
    0x0000000000000137,
];
const SUB_0_2: [u64; 9] = [
    0x48d6edec7547a757, 0x39a67aec4cc7edcd, 0x889fe59c48bfb1a5, 0x840421763b2e15a9,
    0xf166e7303414cf4d, 0x1a209541ebebb6fc, 0xefed3f85febeba70, 0x54ed755707ea6f9d,
    0x000000000000016b,
];
const MUL_0_2: [u64; 9] = [
    0x974b28754c14ae4c, 0x515e779315bd3f66, 0x432a322bfba84065, 0xd8d191310203997c,
    0xfb67175b539a5027, 0x4304dc1fb6b6ae93, 0x6724999eacc6ce8a, 0xd5b4ca2dc78b2653,
    0x0000000000000126,
];
const ADD_0_3: [u64; 9] = [
    0xe2c5be7f35493cf4, 0xaea6785c11a66773, 0x28a74447b253d592, 0xd811a4bc66712e35,
    0xb71a66f7cde06510, 0x712f92a390a4513c, 0xc306c6810cde4902, 0x54f843c0183ad766,
    0x0000000000000053,
];
const SUB_0_3: [u64; 9] = [
    0x7e5046fa46eac7ea, 0x26e2995b67733acb, 0xd7d3696984eac3e4, 0xc285cae8a1ec00ea,
    0x19ba45a9d1e3bafd, 0x27b0f2e0c2adf0d3, 0x6003cef673e47b3e, 0xb980834147f8b138,
    0x000000000000004f,
];
const MUL_0_3: [u64; 9] = [
    0x5295972e7ad4d804, 0xdfed3e64b6ce929f, 0x9ad22d437defbe30, 0x521340e6494bd3fe,
    0x029163ba5c7fc336, 0xd3d01c6dfb8df628, 0x883a1e7e946d9b55, 0xdd6972560ebfdafd,
    0x0000000000000199,
];
const ADD_1_2: [u64; 9] = [
    0x54beb06b02d39266, 0x575552f6e3c4f716, 0x5524f888f5940acc, 0xebd7dce5ff25659c,
    0xc14adfe1c260f0a2, 0x994a7e863565fbe4, 0x46b75056d795eec5, 0xa1016c9d230886a3,
    0x0000000000000121,
];
const SUB_1_2: [u64; 9] = [
    0x855686ca712edc37, 0xf5193718043b3071, 0x65ea16104fd4d49f, 0x5948b02d6d2461cf,
    0xd34401a08ac66f2f, 0x34ab2385b9eb27ce, 0x038739eb54509f65, 0x3c639049d2a9dd40,
    0x0000000000000155,
];
const MUL_1_2: [u64; 9] = [
    0xf23936889b0d7b35, 0x7e7fc75399fc5955, 0xf3c1cad740900842, 0x280ecdb8d49bb407,
    0x2033cd0cb97bd350, 0x63421fdca07c0475, 0xb5b19d6eec34dbc1, 0xdb7970cb51e54504,
    0x0000000000000029,
];
const ADD_1_3: [u64; 9] = [
    0x1f45575d313071d4, 0x6a193487c919aa18, 0x05f174bbb968f88d, 0xad56337398677a5b,
    0x98f78168249204f2, 0x8bba20e75ea3c20e, 0xd6a0c0e662702df7, 0x3c6e5eb2e2fa4508,
    0x000000000000003d,
];
const SUB_1_3: [u64; 9] = [
    0xbacfdfd842d1fcca, 0xe25555871ee67d6f, 0xb51d99dd8bffe6de, 0x97ca599fd3e24d10,
    0xfb97601a28955adf, 0x423b812490ad61a4, 0x739dc95bc9766033, 0xa0f69e3412b81eda,
    0x0000000000000039,
];
const MUL_1_3: [u64; 9] = [
    0xe0542c0bef81d68f, 0x9aabd78758e554a6, 0x89161b86be49be6f, 0x70b058b93b29953b,
    0x0ccdedc02b7622a3, 0x001097362623fc85, 0x82ab612506649a2c, 0x6eeddc31e40b1401,
    0x000000000000007a,
];
const ADD_2_3: [u64; 9] = [
    0x99eed092c001959c, 0x74fffd6fc4de79a6, 0xa0075eab699423ed, 0x540d83462b43188b,
    0xc5b37fc799cb95c3, 0x570efd61a4b89a3f, 0xd31986fb0e1f8e92, 0x000ace69105067c8,
    0x00000000000000e8,
];
const SUB_2_3: [u64; 9] = [
    0x3579590dd1a32092, 0xed3c1e6f1aab4cfe, 0x4f3383cd3c2b123e, 0x3e81a97266bdeb41,
    0x28535e799dceebb0, 0x0d905d9ed6c239d6, 0x70168f707525c0ce, 0x64930dea400e419a,
    0x00000000000000e4,
];
const MUL_2_3: [u64; 9] = [
    0x75131f7a45b9df1d, 0x935d6745d9ad16a0, 0x3a001f01b7fbd984, 0x6e5a0ebbc32d649f,
    0x5fac2ec6ffeceba1, 0x69bdddce48d4f3ae, 0xf8a3dba6043225a3, 0x934cecb643aa2a76,
    0x0000000000000048,
];

const NEG_0: [u64; 9] = [
    0x4f74fd4341e5fd90, 0x953b772443732ee0, 0xffc2a9276460b344, 0xb2b4482d7bd1686f,
    0x1795a9af301deff8, 0xb38fbd3dd656def8, 0x6e7ab5443f9e9ddf, 0x78c39c7f4fe63bb0,
    0x00000000000001ae,
];
const INV_0: [u64; 9] = [
    0x765019b3c416cef7, 0x937d091f336dbc98, 0x20610e6c269802ba, 0xbe8b78b421aa0f14,
    0xf428758f04375867, 0xe16a40104d9f0ca9, 0x75441de4778d185f, 0x0266bbcffa3397cf,
    0x0000000000000141,
];
const NEG_1: [u64; 9] = [
    0x12f5646545fec8b0, 0xd9c8baf88bffec3c, 0x227878b35d4b9049, 0xdd6fb97649db1c4a,
    0x35b88f3ed96c5016, 0x99052efa08576e26, 0x5ae0badeea0cb8ea, 0x914d818c8526ce0e,
    0x00000000000001c4,
];
const INV_1: [u64; 9] = [
    0xa9f7fdcc883d790a, 0x31dbfd751c4250f4, 0x0dfab71235deec59, 0x5c58a0d138d1d243,
    0x29f6cc72712e8c26, 0x712f07fc72de2218, 0x37a8288272a69641, 0x125028819eb3cf56,
    0x00000000000000d9,
];
const NEG_2: [u64; 9] = [
    0x984beb2fb72da4e8, 0xcee1f210903b1cad, 0x88628ec3ad2064e9, 0x36b869a3b6ff7e19,
    0x08fc90df6432bf46, 0xcdb0527fc24295f5, 0x5e67f4ca3e5d584f, 0xcdb111d657d0ab4e,
    0x0000000000000119,
];
const INV_2: [u64; 9] = [
    0x57373e572a80f5e9, 0x25eeb110d1fbe14a, 0x3524058a18e31a27, 0x22446ea205766379,
    0x22f1b87b4f317fb7, 0x6f76c35e81fd26fe, 0x88a2f7a3ce574c38, 0xa7799b1684813bca,
    0x0000000000000173,
];
const NEG_3: [u64; 9] = [
    0xcdc5443d88d0c57a, 0xbc1e107faae669ab, 0xd7961290e94b7728, 0x753a13161dbd695a,
    0x314fef590201aaf6, 0xdb40b01e9904cfcb, 0xce7e843ab383191d, 0x32441fc097deece8,
    0x00000000000001fe,
];
const INV_3: [u64; 9] = [
    0x1c82f93cb5d23d5a, 0x9dc8d98efc5b6c5c, 0x6aef6188770fabf2, 0x34f04ad0725ce874,
    0x0980ed475850ba6a, 0xc2ee047d658d2a3e, 0x3d20e88bbd169a35, 0x0fa60699685d41bb,
    0x00000000000000dc,
];

fn fe(limbs: [u64; 9]) -> P521FieldElement {
    P521FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3].map(fe);
    let pairs: [(usize, usize, [u64; 9], [u64; 9], [u64; 9]); 6] = [
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
        assert_eq!(v.add(&P521FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P521FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P521FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P521FieldElement::ZERO, "x + (-x) == 0");
        if v != P521FieldElement::ZERO {
            assert_eq!(v.mul(&v.invert()), P521FieldElement::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), P521FieldElement::ZERO, "0^-1 == 0 by convention");
        }
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    assert_eq!(fe(bouncycastle_ec::p521::P_LIMBS), P521FieldElement::ZERO);

    // p + 1 == 2^521: sets only bit 521 (limb 8's bit 9), the smallest value this type's spare
    // top-limb bits could silently lose if from_limbs simply masked them away instead of folding
    // them in via 2^521 == 1 (mod p).
    let p_plus_1: [u64; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 0x200];
    assert_eq!(fe(p_plus_1), P521FieldElement::ONE);

    // the maximum representable 9-limb value (2^576 - 1) must also reduce correctly: it folds to
    // lo (2^521 - 1, i.e. p itself) plus hi (2^55 - 1), and p + (2^55 - 1) reduces once more to
    // 2^55 - 1.
    let all_ones = [u64::MAX; 9];
    let expected = fe([0x007fffffffffffff, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fe(all_ones), expected);
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
    for limb_idx in 0..9 {
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

/// xorshift64* PRNG, fixed seed: same rationale as the P-256 field test's property check. Values
/// are masked to the top limb's 9 valid bits so every generated element is already `< 2^521`.
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
        limbs[8] &= 0x1ff;
        limbs
    }
}

#[test]
fn algebraic_identities_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0x9E3779B97F4A7C15);
    // 1000, not the 5000 used by the faster P-256/P-384 field tests: P-521's invert() does 521
    // repeated squarings per call (vs 256/384), and this loop calls it once per iteration, so
    // 5000 iterations would make this single test dominate the crate's whole test-suite runtime
    // (and, via cargo mutants, every mutant's timeout budget) for marginal extra coverage.
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
        if a != P521FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), P521FieldElement::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE0000000008);
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

/// `is_zero` is the mask every exceptional-case select in this crate's point arithmetic keys
/// off (infinity detection, the `H == 0` / `R == 0` same-point and opposite-point cases), and
/// otherwise exercised only through those selects. Both truth values are pinned here, with
/// the nonzero side walked across every limb position so a mask that inspected only some limbs
/// would be caught.
#[test]
fn is_zero_distinguishes_zero_from_every_nonzero_limb_position() {
    assert!(P521FieldElement::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::p521::P_LIMBS).is_zero().to_bool(), "p reduces to 0");
    assert!(!P521FieldElement::ONE.is_zero().to_bool());
    for limb_idx in 0..9 {
        let mut limbs = [0u64; 9];
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
    let p_minus_1 = fe([
        0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0x00000000000001ff,
    ]);
    let p_minus_2 = fe([
        0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0x00000000000001ff,
    ]);
    let two = fe([
        0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000,
    ]);

    assert_eq!(p_minus_1.add(&p_minus_1), p_minus_2, "(p-1) + (p-1) == p-2");
    assert_eq!(p_minus_1.add(&P521FieldElement::ONE), P521FieldElement::ZERO, "(p-1) + 1 == 0");
    assert_eq!(P521FieldElement::ZERO.sub(&P521FieldElement::ONE), p_minus_1, "0 - 1 == p-1");
    assert_eq!(P521FieldElement::ONE.sub(&p_minus_1), two, "1 - (p-1) == 2");
    assert_eq!(p_minus_1.negate(), P521FieldElement::ONE, "-(p-1) == 1");
    assert_eq!(P521FieldElement::ONE.invert(), P521FieldElement::ONE, "1^-1 == 1");
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
    let cases: [([u64; 9], [u64; 9], [u64; 9]); 7] = [
        // (p-1)^2 == 1
        (
            [
                0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000,
            ],
        ),
        // (p-1)(p-2) == 2
        (
            [
                0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000,
            ],
        ),
        // (p-1) * 2^(bits-1) == p - 2^(bits-1)
        (
            [
                0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000100,
            ],
            [
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000000ff,
            ],
        ),
        // both operands within 2^64 of p
        (
            [
                0xb122a0b01e939352, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0xd88def3c21b98f23, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0x31b01cefe60714ac, 0x0c26dd43c9f82aba, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000,
            ],
        ),
        // both operands within 2^64 of p
        (
            [
                0xf315ee0261d4b798, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0x64b1d0d0007c0705, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0x00000000000001ff,
            ],
            [
                0x9bf784140a1d7c96, 0x07d5aa976f3513e2, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000,
            ],
        ),
        // both operands with the top bit set
        (
            [
                0x6e63c6bbea7082bb, 0xd22cc93d5a21e76c, 0xa0dbe54bcdb2f7cb, 0xa8c5e4ca5347a8d3,
                0x5bad1998281ff5a4, 0xbd0325a0d3d545e4, 0x8c806bda1c0c4b43, 0x5e96526496fe66ac,
                0x000000000000011f,
            ],
            [
                0x37bb2c7c190c5b04, 0xdc528dfd30b9df11, 0x561993c90be7b6f0, 0x2ea5d8b1d76b6c45,
                0xda9b6732aab17048, 0x4a1aa8b29a612687, 0x3c3dd306f7772c1c, 0xa0ca82769b2831e8,
                0x00000000000001c2,
            ],
            [
                0x200dc6bca4512d5f, 0xa1d8fbb9571990d8, 0x5d1b9d6437792d0b, 0x997e20eb51eae882,
                0x3c3636ba1b5d85f8, 0x819b6bf32325eef8, 0x93dbeb22a8656147, 0xa1940a58dc0e865e,
                0x000000000000019e,
            ],
        ),
        // both operands with the top bit set
        (
            [
                0xaf7088097f55e903, 0x8e581673473c58f9, 0xaae64e123971ea1c, 0x7e9ad2be8bd62f1b,
                0x81a2b599fe27ff63, 0x8e426b5910999ef7, 0x337e0ac8281bf0fb, 0x3ea808d1210c096c,
                0x00000000000001a5,
            ],
            [
                0x28a550a89905d51d, 0x60c2abda1d6524d7, 0x6b3ff74c431643d4, 0x0f69fb5a42f1a376,
                0x4645b3fbe987802e, 0x8c1260cd82f83971, 0x2a1d57fa3de42173, 0x09a3149642f3827e,
                0x00000000000001e7,
            ],
            [
                0x5ae5c8c3efee0a33, 0x9995143d8f4bd505, 0xfea8df171b8bd60f, 0x264256831b8916b6,
                0xf4868cc125af95da, 0x9e2375949e1d32ad, 0x5ab64ea04020cd71, 0x7964125674dfcc19,
                0x0000000000000036,
            ],
        ),
    ];
    for (a, b, expected) in cases {
        assert_eq!(fe(a).mul(&fe(b)), fe(expected), "a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(b).mul(&fe(a)), fe(expected), "commuted: a = {a:x?}, b = {b:x?}");
        assert_eq!(fe(a).square(), fe(a).mul(&fe(a)), "square at the same extreme: a = {a:x?}");
    }
}
