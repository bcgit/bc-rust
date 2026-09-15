//! Known-answer tests for [`Bp256r1ScalarField`] arithmetic mod the brainpoolP256r1 curve order
//! `n`. Expected values computed independently in Python:
//!
//! ```text
//! n = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
//! random.seed(830256)
//! vals = [random.randrange(1, n) for _ in range(5)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::bp256r1_scalar::{
    Bp256r1PublicScalar, Bp256r1Scalar, Bp256r1ScalarField, N_LIMBS,
};

const VALS_0: [u64; 4] =
    [0xe620e95875efcc3f, 0x700c3605fe836b66, 0xe0cbcb49c993c600, 0x4bdef4899a7f5646];
const VALS_1: [u64; 4] =
    [0x873deeeb190e25ff, 0xd4d7aa54b1fa9ff4, 0xc05f5da448731369, 0x3e1a9d4df469bb69];
const VALS_2: [u64; 4] =
    [0x3ec10068454f360e, 0x80c71b38a1bfcb59, 0x3520b45d1fad38df, 0x4e1f91f936074c2c];
const VALS_3: [u64; 4] =
    [0x6f5d2ca4d7fbf544, 0x2dcbd43dd421b47e, 0xecd09a4a451a1170, 0x840aefc083787afa];
const VALS_4: [u64; 4] =
    [0xe354fd165a775408, 0xa3642d3d28489575, 0xcd328ff0de425666, 0x153500b5078a85e0];
const VALS_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

const ADD_0_1: [u64; 4] =
    [0x6d5ed8438efdf23e, 0x44e3e05ab07e0b5b, 0xa12b28ee1206d96a, 0x89f991d78ee911b0];
const SUB_0_1: [u64; 4] =
    [0x5ee2fa6d5ce1a640, 0x9b348bb14c88cb72, 0x206c6da58120b296, 0x0dc4573ba6159add];
const MUL_0_1: [u64; 4] =
    [0x13701529399da18c, 0x13d6a7943115c063, 0x6205ff1e0cd8b30b, 0x5147c3b6f9b973a3];
const ADD_0_2: [u64; 4] =
    [0x24e1e9c0bb3f024d, 0xf0d3513ea04336c0, 0x15ec7fa6e940fedf, 0x99fe8682d086a273];
const SUB_0_2: [u64; 4] =
    [0x377df772c7e8ecd8, 0x7b7e957112254705, 0xea11217d476a1a92, 0xa7baba6c0666b3d6];
const MUL_0_2: [u64; 4] =
    [0xd3360dd3e1591b94, 0x472f60b5a2625271, 0xcc6e9e97dd332e2b, 0x9956e96f71581f0a];
const ADD_0_3: [u64; 4] =
    [0xc560077ab6a36adc, 0x119e8fa01d4378ed, 0x8f365b03712a49ff, 0x25ee8c6e7c092785];
const SUB_0_3: [u64; 4] =
    [0x06e1cb36353c2da2, 0xce79dc6bdfc35de0, 0x32613b9021fd4201, 0x71cf5ca4b8f58508];
const MUL_0_3: [u64; 4] =
    [0x48cfaedd21d717fb, 0xeed244113445efc2, 0x5d21d877f2d54c25, 0x36a26d8c958d0f94];
const ADD_0_4: [u64; 4] =
    [0xc975e66ed0672047, 0x1370634326cc00dc, 0xadfe5b3aa7d61c67, 0x6113f53ea209dc27];
const SUB_0_4: [u64; 4] =
    [0x02cbec421b787837, 0xcca808c8d63ad5f1, 0x13993b58eb516f99, 0x36a9f3d492f4d066];
const MUL_0_4: [u64; 4] =
    [0xd1edf8719c5683eb, 0xd3753f7d32a9aeff, 0x8142806427a58141, 0x61768084d6871c30];
const ADD_0_5: [u64; 4] = VALS_0;
const SUB_0_5: [u64; 4] = VALS_0;
const MUL_0_5: [u64; 4] = [0, 0, 0, 0];
const ADD_1_2: [u64; 4] =
    [0xc5feef535e5d5c0d, 0x559ec58d53ba6b4d, 0xf580120168204c49, 0x8c3a2f472a710795];
const SUB_1_2: [u64; 4] =
    [0xd89afd056b074698, 0xe04a09bfc59c7b92, 0xc9a4b3d7c64967fb, 0x99f66330605118f9];
const MUL_1_2: [u64; 4] =
    [0x9d1f6e88be6ab453, 0x8b6cae940ca35981, 0xaf08588a481f31be, 0x6b35c3702ee45952];
const ADD_1_3: [u64; 4] =
    [0x667d0d0d59c1c49c, 0x766a03eed0baad7b, 0x6ec9ed5df0099768, 0x182a3532d5f38ca8];
const SUB_1_3: [u64; 4] =
    [0xa7fed0c8d85a8762, 0x334550ba933a926d, 0x11f4cdeaa0dc8f6b, 0x640b056912dfea2b];
const MUL_1_3: [u64; 4] =
    [0x54507e2e8377c6cf, 0xcebdcbaa4b5b3a52, 0x3a1d5f5fddf8ee5d, 0x45aaf54e256b2d16];
const ADD_1_4: [u64; 4] =
    [0x6a92ec0173857a07, 0x783bd791da43356a, 0x8d91ed9526b569d0, 0x534f9e02fbf4414a];
const SUB_1_4: [u64; 4] =
    [0xa3e8f1d4be96d1f7, 0x31737d1789b20a7e, 0xf32ccdb36a30bd03, 0x28e59c98ecdf3588];
const MUL_1_4: [u64; 4] =
    [0x3a77b655fc7b4bd1, 0xf083bd58c2a04360, 0xddac49a93c019759, 0x60fb6f9c9dcfe293];
const ADD_1_5: [u64; 4] = VALS_1;
const SUB_1_5: [u64; 4] = VALS_1;
const MUL_1_5: [u64; 4] = [0, 0, 0, 0];
const ADD_2_3: [u64; 4] =
    [0x1e001e8a8602d4ab, 0x225974d2c07fd8e0, 0xe38b4416c743bcde, 0x282f29de17911d6a];
const SUB_2_3: [u64; 4] =
    [0x5f81e246049b9771, 0xdf34c19e82ffbdd2, 0x86b624a37816b4e0, 0x740ffa14547d7aed];
const MUL_2_3: [u64; 4] =
    [0x2d38daccb08e4bcc, 0xf55b78e02cab2a30, 0xec519c89c4e11532, 0x4bd2892bbbcd8f94];
const ADD_2_4: [u64; 4] =
    [0x2215fd7e9fc68a16, 0x242b4875ca0860cf, 0x0253444dfdef8f46, 0x635492ae3d91d20d];
const SUB_2_4: [u64; 4] =
    [0x5b6c0351ead7e206, 0xdd62edfb797735e3, 0x67ee246c416ae278, 0x38ea91442e7cc64b];
const MUL_2_4: [u64; 4] =
    [0xe07ebe8d62690875, 0xce2b47ba6725fafe, 0x7d1af0658e8289e1, 0x39c4f2e8ec58cacc];
const ADD_2_5: [u64; 4] = VALS_2;
const SUB_2_5: [u64; 4] = VALS_2;
const MUL_2_5: [u64; 4] = [0, 0, 0, 0];
const ADD_3_4: [u64; 4] =
    [0x52b229bb3273494c, 0xd130017afc6a49f4, 0xba032a3b235c67d6, 0x993ff0758b0300db];
const SUB_3_4: [u64; 4] =
    [0x8c082f8e7d84a13c, 0x8a67a700abd91f08, 0x1f9e0a5966d7bb09, 0x6ed5ef0b7bedf51a];
const MUL_3_4: [u64; 4] =
    [0xe1955592a9a94d97, 0x505e6c124682c915, 0xcb9ec3ddc5ad25ac, 0xa107e6ff1d8dce50];
const ADD_3_5: [u64; 4] = VALS_3;
const SUB_3_5: [u64; 4] = VALS_3;
const MUL_3_5: [u64; 4] = [0, 0, 0, 0];
const ADD_4_5: [u64; 4] = VALS_4;
const SUB_4_5: [u64; 4] = VALS_4;
const MUL_4_5: [u64; 4] = [0, 0, 0, 0];

const NEG_0: [u64; 4] =
    [0xa9fd252a21588a68, 0x1c2d449db6de3b90, 0x5d9a3f46d3efc771, 0x5e1c6352076f5375];
const INV_0: [u64; 4] =
    [0x4f5f222f13a09abf, 0xdc003eb5adc28528, 0x68c08401d6ec6be5, 0x95e72034918aefe3];
const NEG_1: [u64; 4] =
    [0x08e01f977e3a30a8, 0xb761d04f03670703, 0x7e06acec55107a07, 0x6be0ba8dad84ee52];
const INV_1: [u64; 4] =
    [0x04a5002efe23ca71, 0x5bc05734856c9eaf, 0x592970a68de0a132, 0x44715491a82b9551];
const NEG_2: [u64; 4] =
    [0x515d0e1a51f92099, 0x0b725f6b13a1db9e, 0x094556337dd65492, 0x5bdbc5e26be75d90];
const INV_2: [u64; 4] =
    [0x168949a4d8dd2336, 0x61580e6e2be323af, 0x3f401a84279c021c, 0x665b5b540a107369];
const NEG_3: [u64; 4] =
    [0x20c0e1ddbf4c6163, 0x5e6da665e13ff279, 0x5195704658697c01, 0x25f0681b1e762ec1];
const INV_3: [u64; 4] =
    [0x81f1754ef639e429, 0x355607c4866fbfd0, 0xd839243b5d9715e2, 0x90189cde76dd48f2];
const NEG_4: [u64; 4] =
    [0xacc9116c3cd1029f, 0xe8d54d668d191181, 0x71337a9fbf41370a, 0x94c657269a6423db];
const INV_4: [u64; 4] =
    [0x690a944e60c54b8c, 0xc874c6e54f35caba, 0x59490d3736d0f8b5, 0x02646e0c805fb286];
const NEG_5: [u64; 4] = [0, 0, 0, 0];
const INV_5: [u64; 4] = [0, 0, 0, 0];

fn fe(limbs: [u64; 4]) -> Bp256r1ScalarField {
    Bp256r1ScalarField::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5].map(fe);
    let add: Vec<Vec<[u64; 4]>> = vec![
        vec![ADD_0_1, ADD_0_2, ADD_0_3, ADD_0_4, ADD_0_5],
        vec![ADD_1_2, ADD_1_3, ADD_1_4, ADD_1_5],
        vec![ADD_2_3, ADD_2_4, ADD_2_5],
        vec![ADD_3_4, ADD_3_5],
        vec![ADD_4_5],
    ];
    let sub: Vec<Vec<[u64; 4]>> = vec![
        vec![SUB_0_1, SUB_0_2, SUB_0_3, SUB_0_4, SUB_0_5],
        vec![SUB_1_2, SUB_1_3, SUB_1_4, SUB_1_5],
        vec![SUB_2_3, SUB_2_4, SUB_2_5],
        vec![SUB_3_4, SUB_3_5],
        vec![SUB_4_5],
    ];
    let mul: Vec<Vec<[u64; 4]>> = vec![
        vec![MUL_0_1, MUL_0_2, MUL_0_3, MUL_0_4, MUL_0_5],
        vec![MUL_1_2, MUL_1_3, MUL_1_4, MUL_1_5],
        vec![MUL_2_3, MUL_2_4, MUL_2_5],
        vec![MUL_3_4, MUL_3_5],
        vec![MUL_4_5],
    ];
    for i in 0..6 {
        for j in (i + 1)..6 {
            let expected_add = fe(add[i][j - i - 1]);
            let expected_sub = fe(sub[i][j - i - 1]);
            let expected_mul = fe(mul[i][j - i - 1]);
            assert_eq!(vals[i].add(&vals[j]), expected_add, "add({i},{j})");
            assert_eq!(vals[j].add(&vals[i]), expected_add, "add is commutative ({j},{i})");
            assert_eq!(vals[i].sub(&vals[j]), expected_sub, "sub({i},{j})");
            assert_eq!(vals[i].mul(&vals[j]), expected_mul, "mul({i},{j})");
            assert_eq!(vals[j].mul(&vals[i]), expected_mul, "mul is commutative ({j},{i})");
        }
    }
}

#[test]
fn known_answer_negate_and_invert() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5];
    let negs = [NEG_0, NEG_1, NEG_2, NEG_3, NEG_4, NEG_5];
    let invs = [INV_0, INV_1, INV_2, INV_3, INV_4, INV_5];
    for i in 0..6 {
        assert_eq!(fe(vals[i]).negate(), fe(negs[i]), "negate({i})");
        assert_eq!(fe(vals[i]).invert(), fe(invs[i]), "invert({i})");
    }
}

#[test]
fn to_limbs_round_trips() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        assert_eq!(fe(limbs).to_limbs(), limbs);
    }
}

#[test]
fn identities() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5].map(fe);
    for &v in &vals {
        assert_eq!(v.add(&Bp256r1ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Bp256r1ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Bp256r1ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Bp256r1ScalarField::ZERO, "x + (-x) == 0");
        if v != Bp256r1ScalarField::ZERO {
            assert_eq!(v.mul(&v.invert()), Bp256r1ScalarField::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), Bp256r1ScalarField::ZERO, "0^-1 == 0 by convention");
        }
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
    assert_eq!(fe(N_LIMBS), Bp256r1ScalarField::ZERO);
    let n_plus_1: [u64; 4] =
        [0x901e0e82974856a8, 0x8c397aa3b561a6f7, 0x3e660a909d838d71, 0xa9fb57dba1eea9bc];
    assert_eq!(fe(n_plus_1), Bp256r1ScalarField::ONE);
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        assert_eq!(Bp256r1PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(Bp256r1PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0, 0, 0, 0]);
    let n_plus_1: [u64; 4] =
        [0x901e0e82974856a8, 0x8c397aa3b561a6f7, 0x3e660a909d838d71, 0xa9fb57dba1eea9bc];
    assert_eq!(Bp256r1PublicScalar::from_limbs(n_plus_1).to_limbs(), [1, 0, 0, 0]);
}

#[test]
fn public_scalar_eq_detects_a_difference_in_any_limb() {
    let base = Bp256r1PublicScalar::from_limbs(VALS_0);
    assert_eq!(base, Bp256r1PublicScalar::from_limbs(VALS_0));
    for limb_idx in 0..4 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(
            base,
            Bp256r1PublicScalar::from_limbs(other),
            "a difference in limb {limb_idx} must be detected"
        );
    }
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4] {
        let secret = Bp256r1Scalar::from_limbs(limbs);
        let round_tripped = Bp256r1Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn secret_scalar_from_be_bytes_reduces_out_of_range_input() {
    let mut n_bytes = [0u8; 32];
    for (i, limb) in N_LIMBS.iter().rev().enumerate() {
        n_bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    assert_eq!(Bp256r1Scalar::from_be_bytes(&n_bytes), Bp256r1Scalar::from_limbs([0, 0, 0, 0]));
}

#[test]
fn scalar_field_from_secret_matches_from_limbs() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        let secret = Bp256r1Scalar::from_limbs(limbs);
        assert_eq!(Bp256r1ScalarField::from_secret(&secret), fe(limbs));
    }
}

/// xorshift64* PRNG, fixed seed: same rationale as the field-arithmetic property test.
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
    let mut rng = Xorshift64(0xB7A1E5B7A1E5B7A1);
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
        if a != Bp256r1ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), Bp256r1ScalarField::ONE, "a * a^-1 == 1");
        }
    }
}
