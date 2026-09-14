//! Known-answer tests for [`P256ScalarField`] arithmetic mod the P-256 curve order `n`.
//!
//! No NIST-published KAT exists for raw scalar-field arithmetic (only for signatures, which this
//! crate doesn't produce yet). Expected values were computed independently in Python:
//!
//! ```text
//! n = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
//! random.seed(99)
//! vals = [random.randrange(1, n) for _ in range(5)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::p256_scalar::{N_LIMBS, P256PublicScalar, P256Scalar, P256ScalarField};

const VALS_0: [u64; 4] =
    [0x61790134676b1b6a, 0x9974d75b333824fe, 0x3af27f802dc5fd3d, 0x221c4e003f9931ee];
const VALS_1: [u64; 4] =
    [0x162a01dec28753f9, 0xbaa1c6f1404b6eaf, 0x87e355b26210b784, 0xb35331ceaf2ed9dd];
const VALS_2: [u64; 4] =
    [0x16ff82e389e3995b, 0x9fb932d4f0397722, 0x331057ca7d411fab, 0xb8e3c71f6bf08d62];
const VALS_3: [u64; 4] =
    [0x96a1da2c9cfbba44, 0xcae8c077377925b3, 0xc9cf158de6e96d45, 0xd283eb3a5fbd238e];
const VALS_4: [u64; 4] =
    [0xdc8ac0bb635b4c42, 0x366c5acdaeafb905, 0x7623c4dd26fb984f, 0x2dd301c8a91afa5c];
const VALS_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

const ADD_0_1: [u64; 4] =
    [0x77a3031329f26f63, 0x54169e4c738393ad, 0xc2d5d5328fd6b4c2, 0xd56f7fceeec80bcb];
const SUB_0_1: [u64; 4] =
    [0x3f08ca18a146ecc2, 0x9bba0b179a0454d4, 0xb30f29cdcbb545b8, 0x6ec91c30906a5811];
const MUL_0_1: [u64; 4] =
    [0x9b957490b0b957fd, 0x363308dfb20a5e88, 0xc666ada84f2ce72c, 0xe85ab26303d4786c];
const ADD_0_2: [u64; 4] =
    [0x78788417f14eb4c5, 0x392e0a3023719c20, 0x6e02d74aab071ce9, 0xdb00151fab89bf50];
const SUB_0_2: [u64; 4] =
    [0x3e334913d9eaa760, 0xb6a29f33ea164c61, 0x07e227b5b084dd91, 0x693886dfd3a8a48d];
const MUL_0_2: [u64; 4] =
    [0xe0dcb929e7d8df8e, 0x7d7515aa7a46229e, 0x06d1248dded29839, 0x418877fe0e82e6a6];
const ADD_0_3: [u64; 4] =
    [0xf81adb610466d5ae, 0x645d97d26ab14ab1, 0x04c1950e14af6a83, 0xf4a0393a9f56557d];
const SUB_0_3: [u64; 4] =
    [0xbe90f1cac6d28677, 0x8b731191a2d69dcf, 0x712369f246dc8ff7, 0x4f9862c4dfdc0e60];
const MUL_0_3: [u64; 4] =
    [0xa9178f540ad740bc, 0xedda23c9d3d4b992, 0xdbb6d4ed821c6d0c, 0xc550c0b372ace280];
const ADD_0_4: [u64; 4] =
    [0x3e03c1efcac667ac, 0xcfe13228e1e7de04, 0xb116445d54c1958c, 0x4fef4fc8e8b42c4a];
const SUB_0_4: [u64; 4] =
    [0x78a80b3c0072f479, 0x1fef773b2ba00a7d, 0xc4cebaa306ca64ee, 0xf4494c36967e3792];
const MUL_0_4: [u64; 4] =
    [0xdc0ee445deb72aeb, 0xd73d662d513120c8, 0x9733e6b7ee202567, 0x5d5546a40a8b6232];
const ADD_0_5: [u64; 4] = VALS_0;
const SUB_0_5: [u64; 4] = VALS_0;
const MUL_0_5: [u64; 4] = [0, 0, 0, 0];
const ADD_1_2: [u64; 4] =
    [0x396fb9ff5007c803, 0x9d73ff18896d474c, 0xbaf3ad7cdf51d730, 0x6c36f8ef1b1f673e];
const SUB_1_2: [u64; 4] =
    [0xf2e449be3506dfef, 0xd7cf8ec9f7299611, 0x54d2fde7e4cf97d8, 0xfa6f6aae433e4c7c];
const MUL_1_2: [u64; 4] =
    [0xdf68307f79c99226, 0xd8af071df3bc3ab4, 0x5032a9e74ba6242e, 0x68e98c9aeca29515];
const ADD_1_3: [u64; 4] =
    [0xb9121148631fe8ec, 0xc8a38cbad0acf5dd, 0x51b26b4048fa24ca, 0x85d71d0a0eebfd6b];
const SUB_1_3: [u64; 4] =
    [0x7341f27521eebf06, 0xaca00127afe9e780, 0xbe1440247b274a3e, 0xe0cf46934f71b64f];
const MUL_1_3: [u64; 4] =
    [0xbcde5301d8a0ab88, 0x0b8706edf8da5fd4, 0xd38a80b07a8d3dc5, 0x0eec5530af2b75a3];
const ADD_1_4: [u64; 4] =
    [0xf2b4c29a25e2a03b, 0xf10e21beeefb27b4, 0xfe071a8f890c4fd3, 0xe12633975849d439];
const SUB_1_4: [u64; 4] =
    [0x399f41235f2c07b7, 0x84356c23919bb5a9, 0x11bf90d53b151f35, 0x858030060613df81];
const MUL_1_4: [u64; 4] =
    [0x41ce6159e83eec06, 0x95dadd4fd50ec42d, 0x7aa12baaa84bd66f, 0x380adf3eea5fe1ed];
const ADD_1_5: [u64; 4] = VALS_1;
const SUB_1_5: [u64; 4] = VALS_1;
const MUL_1_5: [u64; 4] = [0, 0, 0, 0];
const ADD_2_3: [u64; 4] =
    [0xb9e7924d2a7c2e4e, 0xadbaf89e809afe50, 0xfcdf6d58642a8cf1, 0x8b67b25acbadb0ef];
const SUB_2_3: [u64; 4] =
    [0x74177379e94b0468, 0x91b76d0b5fd7eff3, 0x6941423c9657b265, 0xe65fdbe40c3369d4];
const MUL_2_3: [u64; 4] =
    [0x1aabe983764c72ee, 0x360daf66df8a2dd9, 0x9c5bf9e6ed6fc2ef, 0x5a5175ed5133aa90];
const ADD_2_4: [u64; 4] =
    [0xf38a439eed3ee59d, 0xd6258da29ee93027, 0xa9341ca7a43cb7fa, 0xe6b6c8e8150b87be];
const SUB_2_4: [u64; 4] =
    [0x3a74c22826884d19, 0x694cd8074189be1c, 0xbcec92ed5645875c, 0x8b10c556c2d59305];
const MUL_2_4: [u64; 4] =
    [0x789cb76159b4f968, 0x3a51a7a176c4a3c5, 0xe6edf097f54c0ce4, 0xb6577b86fafd724c];
const ADD_2_5: [u64; 4] = VALS_2;
const SUB_2_5: [u64; 4] = VALS_2;
const MUL_2_5: [u64; 4] = [0, 0, 0, 0];
const ADD_3_4: [u64; 4] =
    [0x7f72d02503f3e135, 0x446e20973f114034, 0x3ff2da6b0de50595, 0x0056ed0408d81dea];
const SUB_3_4: [u64; 4] =
    [0xba17197139a06e02, 0x947c65a988c96cad, 0x53ab50b0bfedd4f6, 0xa4b0e971b6a22932];
const MUL_3_4: [u64; 4] =
    [0x0d92f75860a0f3db, 0xb6cf9a4444fab683, 0x8596eeb5b6fa4cdc, 0xf3cdc06731082412];
const ADD_3_5: [u64; 4] = VALS_3;
const SUB_3_5: [u64; 4] = VALS_3;
const MUL_3_5: [u64; 4] = [0, 0, 0, 0];
const ADD_4_5: [u64; 4] = VALS_4;
const SUB_4_5: [u64; 4] = VALS_4;
const MUL_4_5: [u64; 4] = [0, 0, 0, 0];

const NEG_0: [u64; 4] =
    [0x9240c98e94f809e7, 0x2372235273df7986, 0xc50d807fd23a02c2, 0xdde3b1fec066ce12];
const INV_0: [u64; 4] =
    [0x089842e0ace7c3d2, 0xfb2f2003985af5a0, 0x1e6d949e78e789fd, 0x74836b0dc09b705f];
const NEG_1: [u64; 4] =
    [0xdd8fc8e439dbd158, 0x024533bc66cc2fd5, 0x781caa4d9def487b, 0x4cacce3050d12623];
const INV_1: [u64; 4] =
    [0xf20be0b54e165e3a, 0xe05a8fadd40727b1, 0x8ef6950b8f2a8ba9, 0x04bd89fcbf71beec];
const NEG_2: [u64; 4] =
    [0xdcba47df727f8bf6, 0x1d2dc7d8b6de2762, 0xccefa83582bee054, 0x471c38df940f729e];
const INV_2: [u64; 4] =
    [0xd8ca063d9c9c1d74, 0x861819f986ae0cd4, 0x79070aae69e37c0b, 0x901e883cc3fb5f6a];
const NEG_3: [u64; 4] =
    [0x5d17f0965f676b0d, 0xf1fe3a366f9e78d1, 0x3630ea72191692b9, 0x2d7c14c4a042dc72];
const INV_3: [u64; 4] =
    [0xf116a77d8f241b5f, 0xefe7cb74c63638a3, 0xa1e0b03b62331768, 0xec7a0765c915659d];
const NEG_4: [u64; 4] =
    [0x172f0a079907d90f, 0x867a9fdff867e57f, 0x89dc3b22d90467b0, 0xd22cfe3656e505a4];
const INV_4: [u64; 4] =
    [0x627206b591d2b552, 0xea98323796b958c5, 0x8af6cfdf19ae033d, 0x6a1249e2f5e13abe];
const NEG_5: [u64; 4] = [0, 0, 0, 0];
const INV_5: [u64; 4] = [0, 0, 0, 0];

fn fe(limbs: [u64; 4]) -> P256ScalarField {
    P256ScalarField::from_limbs(limbs)
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
        assert_eq!(v.add(&P256ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P256ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P256ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P256ScalarField::ZERO, "x + (-x) == 0");
        if v != P256ScalarField::ZERO {
            assert_eq!(v.mul(&v.invert()), P256ScalarField::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), P256ScalarField::ZERO, "0^-1 == 0 by convention");
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
    assert_eq!(fe(N_LIMBS), P256ScalarField::ZERO);
    let n_plus_1: [u64; 4] =
        [0xf3b9cac2fc632552, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000];
    assert_eq!(fe(n_plus_1), P256ScalarField::ONE);
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        assert_eq!(P256PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    // out-of-range input must reduce, exactly like P256ScalarField::from_limbs.
    assert_eq!(P256PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0, 0, 0, 0]);
    let n_plus_1: [u64; 4] =
        [0xf3b9cac2fc632552, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000];
    assert_eq!(P256PublicScalar::from_limbs(n_plus_1).to_limbs(), [1, 0, 0, 0]);
}

#[test]
fn public_scalar_eq_detects_a_difference_in_any_limb() {
    let base = P256PublicScalar::from_limbs(VALS_0);
    assert_eq!(base, P256PublicScalar::from_limbs(VALS_0));
    for limb_idx in 0..4 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(
            base,
            P256PublicScalar::from_limbs(other),
            "a difference in limb {limb_idx} must be detected"
        );
    }
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4] {
        let secret = P256Scalar::from_limbs(limbs);
        let round_tripped = P256Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn secret_scalar_from_be_bytes_reduces_out_of_range_input() {
    let mut n_bytes = [0u8; 32];
    for (i, limb) in N_LIMBS.iter().rev().enumerate() {
        n_bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    assert_eq!(P256Scalar::from_be_bytes(&n_bytes), P256Scalar::from_limbs([0, 0, 0, 0]));
}

#[test]
fn scalar_field_from_secret_matches_from_limbs() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        let secret = P256Scalar::from_limbs(limbs);
        assert_eq!(P256ScalarField::from_secret(&secret), fe(limbs));
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
    let mut rng = Xorshift64(0x9E3779B97F4A7C15);
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
        if a != P256ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), P256ScalarField::ONE, "a * a^-1 == 1");
        }
    }
}
