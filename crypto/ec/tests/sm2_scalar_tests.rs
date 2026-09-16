//! Known-answer tests for [`Sm2ScalarField`] arithmetic mod the SM2 curve order `n`.
//! Expected values computed independently in Python:
//!
//! ```text
//! n = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
//! random.seed(830917)
//! vals = [random.randrange(1, n) for _ in range(5)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::sm2_scalar::{N_LIMBS, Sm2PublicScalar, Sm2Scalar, Sm2ScalarField};

const VALS_0: [u64; 4] =
    [0x9faa8edecf05b151, 0x737180b1df95b1df, 0x5e15f338e5ade727, 0x99f78f956c6fcbdb];
const VALS_1: [u64; 4] =
    [0xa532d66b2b815019, 0x631e855da126849b, 0x509db3d2fe8976fd, 0x9621cdb0ea646d19];
const VALS_2: [u64; 4] =
    [0x0a849fb061ae1a7d, 0x69263174952f9abb, 0xabd3f5fdfb0dfaa2, 0xab1c24ac2d175095];
const VALS_3: [u64; 4] =
    [0xf4566b478fa51f10, 0x42170adca9ddf2aa, 0xa537081998f3fdb5, 0x5a4b600da638c009];
const VALS_4: [u64; 4] =
    [0x3f4c26b6409b4c74, 0x5e8741237b04a245, 0xa65df2b6a3eac017, 0xf6f405237452f7b9];
const VALS_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

const ADD_0_1: [u64; 4] =
    [0xf1217140c0b1c047, 0x648c26a45ef6314f, 0xaeb3a70be4375e25, 0x30195d4756d438f4];
const SUB_0_1: [u64; 4] =
    [0xfa77b873a3846138, 0x1052fb543e6f2d43, 0x0d783f65e724702a, 0x03d5c1e4820b5ec2];
const MUL_0_1: [u64; 4] =
    [0x54cb882bb2dfde33, 0x3cdac7e002f2c830, 0x17fe944cc047de08, 0xe184473303a91459];
const ADD_0_2: [u64; 4] =
    [0x56733a85f6de8aab, 0x6a93d2bb52ff476f, 0x09e9e936e0bbe1ca, 0x4513b44299871c71];
const SUB_0_2: [u64; 4] =
    [0xe8e1e337a72cd7f7, 0x7c4f2ea86c2c1c4f, 0xb241fd3aea9fec84, 0xeedb6ae83f587b45];
const MUL_0_2: [u64; 4] =
    [0xce133b263051f295, 0x7f5b2d9353ea9817, 0x2978d2df1490a72e, 0x70113776167bd6dd];
const ADD_0_3: [u64; 4] =
    [0x9400fa265eaad061, 0xb5888b8e8973a48a, 0x034cfb527ea1e4dc, 0xf442efa312a88be5];
const SUB_0_3: [u64; 4] =
    [0xab5423973f609241, 0x315a75d535b7bf34, 0xb8deeb1f4cb9e972, 0x3fac2f87c6370bd1];
const MUL_0_3: [u64; 4] =
    [0x77ada45169fc56f9, 0x288058969837995a, 0xe4bcd09a9541d039, 0xbf67f4e573635ca4];
const ADD_0_4: [u64; 4] =
    [0x8b3ac18bd5cbbca2, 0x5ff4e26a38d44ef9, 0x0473e5ef8998a73f, 0x90eb94b9e0c2c395];
const SUB_0_4: [u64; 4] =
    [0xb41a5c31c83fa600, 0x86ee1ef9865714c5, 0xb7b8008241c3270f, 0xa3038a70f81cd421];
const MUL_0_4: [u64; 4] =
    [0xaa2eb00b9c2752d5, 0xa43cfb914ecdfcf8, 0xd794ba4aedb3c049, 0x0919562951b398cf];
const ADD_0_5: [u64; 4] =
    [0x9faa8edecf05b151, 0x737180b1df95b1df, 0x5e15f338e5ade727, 0x99f78f956c6fcbdb];
const SUB_0_5: [u64; 4] =
    [0x9faa8edecf05b151, 0x737180b1df95b1df, 0x5e15f338e5ade727, 0x99f78f956c6fcbdb];
const MUL_0_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
const ADD_1_2: [u64; 4] =
    [0x5bfb8212535a2973, 0x5a40d76714901a2b, 0xfc71a9d0f99771a0, 0x413df25e177bbdae];
const SUB_1_2: [u64; 4] =
    [0xee6a2ac403a876bf, 0x6bfc33542dbcef0b, 0xa4c9bdd5037b7c5a, 0xeb05a903bd4d1c83];
const MUL_1_2: [u64; 4] =
    [0x06211f16fe8ed084, 0x1f1baabebaab43c3, 0xe9cdb399af16bd7c, 0xf0f1114db3eb8930];
const ADD_1_3: [u64; 4] =
    [0x998941b2bb266f29, 0xa535903a4b047746, 0xf5d4bbec977d74b2, 0xf06d2dbe909d2d22];
const SUB_1_3: [u64; 4] =
    [0xb0dc6b239bdc3109, 0x21077a80f74891f0, 0xab66abb965957948, 0x3bd66da3442bad0f];
const MUL_1_3: [u64; 4] =
    [0x544725d8c7df5421, 0xf57246593505ede9, 0x6d9f55a3a04d7f64, 0xe4068115f983aa92];
const ADD_1_4: [u64; 4] =
    [0x90c3091832475b6a, 0x4fa1e715fa6521b5, 0xf6fba689a2743715, 0x8d15d2d55eb764d2];
const SUB_1_4: [u64; 4] =
    [0xb9a2a3be24bb44c8, 0x769b23a547e7e781, 0xaa3fc11c5a9eb6e5, 0x9f2dc88c7611755f];
const MUL_1_4: [u64; 4] =
    [0x13a0fedb78ae289b, 0xc4854ff70c07d775, 0xdd5522338712cc46, 0x02173884bed9fb54];
const ADD_1_5: [u64; 4] =
    [0xa532d66b2b815019, 0x631e855da126849b, 0x509db3d2fe8976fd, 0x9621cdb0ea646d19];
const SUB_1_5: [u64; 4] =
    [0xa532d66b2b815019, 0x631e855da126849b, 0x509db3d2fe8976fd, 0x9621cdb0ea646d19];
const MUL_1_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
const ADD_2_3: [u64; 4] =
    [0xab1f16eeb77df86a, 0x39395ce61d47883a, 0x510afe179401f858, 0x056784bad350109f];
const SUB_2_3: [u64; 4] =
    [0x162e3468d208fb6d, 0x270f2697eb51a810, 0x069cede46219fced, 0x50d0c49e86de908c];
const MUL_2_3: [u64; 4] =
    [0xd26214a5d839f771, 0xa0c0afc2633c9d1e, 0x6087bd93952d10d0, 0x0af1b9e483c6fb5b];
const ADD_2_4: [u64; 4] =
    [0xf614d25d687425ce, 0x55a9932cee6e37d4, 0x5231e8b49ef8baba, 0xa21029d0a16a484f];
const SUB_2_4: [u64; 4] =
    [0x1ef46d035ae80f2c, 0x7ca2cfbc3bf0fda1, 0x0576034757233a8a, 0xb4281f87b8c458dc];
const MUL_2_4: [u64; 4] =
    [0xe0cc8dd68a636466, 0xee4b443dd28b0dbd, 0x8966f3eeede019c2, 0x1bf819d9696a2c83];
const ADD_2_5: [u64; 4] =
    [0x0a849fb061ae1a7d, 0x69263174952f9abb, 0xabd3f5fdfb0dfaa2, 0xab1c24ac2d175095];
const SUB_2_5: [u64; 4] =
    [0x0a849fb061ae1a7d, 0x69263174952f9abb, 0xabd3f5fdfb0dfaa2, 0xab1c24ac2d175095];
const MUL_2_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
const ADD_3_4: [u64; 4] =
    [0xdfe69df4966b2a61, 0x2e9a6c95031c8fc4, 0x4b94fad03cdebdcd, 0x513f65321a8bb7c3];
const SUB_3_4: [u64; 4] =
    [0x08c6389a88df13bf, 0x5593a924509f5591, 0xfed91562f5093d9d, 0x63575ae931e5c84f];
const MUL_3_4: [u64; 4] =
    [0xc63c7d29a151abd6, 0xa6db469c668c47d2, 0xf8fb94f011c0703f, 0x27e44d445af9d9b0];
const ADD_3_5: [u64; 4] =
    [0xf4566b478fa51f10, 0x42170adca9ddf2aa, 0xa537081998f3fdb5, 0x5a4b600da638c009];
const SUB_3_5: [u64; 4] =
    [0xf4566b478fa51f10, 0x42170adca9ddf2aa, 0xa537081998f3fdb5, 0x5a4b600da638c009];
const MUL_3_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
const ADD_4_5: [u64; 4] =
    [0x3f4c26b6409b4c74, 0x5e8741237b04a245, 0xa65df2b6a3eac017, 0xf6f405237452f7b9];
const SUB_4_5: [u64; 4] =
    [0x3f4c26b6409b4c74, 0x5e8741237b04a245, 0xa65df2b6a3eac017, 0xf6f405237452f7b9];
const MUL_4_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

const NEG_0: [u64; 4] =
    [0xb411652a6acf8fd2, 0xfe925eb94230534b, 0xa1ea0cc71a5218d7, 0x6608706993903424];
const INV_0: [u64; 4] =
    [0xefae022b331945ff, 0x633474b3ff271f73, 0x6bd2639865f9b139, 0xab1ae1671e8da2ee];
const NEG_1: [u64; 4] =
    [0xae891d9e0e53f10a, 0x0ee55a0d809f808f, 0xaf624c2d01768902, 0x69de324e159b92e6];
const INV_1: [u64; 4] =
    [0x40cea9ee7d9d71e2, 0x7d60f6fa1fc0f1c0, 0x3a7f4fca4e1523fa, 0xe71dbb4c556050ec];
const NEG_2: [u64; 4] =
    [0x49375458d82726a6, 0x08ddadf68c966a70, 0x542c0a0204f2055d, 0x54e3db52d2e8af6a];
const INV_2: [u64; 4] =
    [0x6bc83663ebfca2c2, 0xe203bf0c8aa60602, 0xa3ba8ea3f5edaa75, 0x673f78118100331a];
const NEG_3: [u64; 4] =
    [0x5f6588c1aa302213, 0x2fecd48e77e81280, 0x5ac8f7e6670c024a, 0xa5b49ff159c73ff6];
const INV_3: [u64; 4] =
    [0xf0cfb12c2f88d2d0, 0x22d44d518ea40181, 0x3c9a9ffc42c0f0e2, 0xebb4349fb0d891f7];
const NEG_4: [u64; 4] =
    [0x146fcd52f939f4af, 0x137c9e47a6c162e6, 0x59a20d495c153fe8, 0x090bfadb8bad0846];
const INV_4: [u64; 4] =
    [0xd042e6c194809037, 0x6b61a6a776549a7a, 0xe367516d6fe2c106, 0xd25dabfa3f2f3a4e];
const NEG_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
const INV_5: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

fn fe(limbs: [u64; 4]) -> Sm2ScalarField {
    Sm2ScalarField::from_limbs(limbs)
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
        assert_eq!(v.add(&Sm2ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Sm2ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Sm2ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Sm2ScalarField::ZERO, "x + (-x) == 0");
        if v != Sm2ScalarField::ZERO {
            assert_eq!(v.mul(&v.invert()), Sm2ScalarField::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), Sm2ScalarField::ZERO, "0^-1 == 0 by convention");
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
    assert_eq!(fe(N_LIMBS), Sm2ScalarField::ZERO);
    let n_plus_1: [u64; 4] =
        [0x53bbf40939d54124, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff];
    assert_eq!(fe(n_plus_1), Sm2ScalarField::ONE);
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        assert_eq!(Sm2PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(Sm2PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0, 0, 0, 0]);
    let n_plus_1: [u64; 4] =
        [0x53bbf40939d54124, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff];
    assert_eq!(Sm2PublicScalar::from_limbs(n_plus_1).to_limbs(), [1, 0, 0, 0]);
}

#[test]
fn public_scalar_eq_detects_a_difference_in_any_limb() {
    let base = Sm2PublicScalar::from_limbs(VALS_0);
    assert_eq!(base, Sm2PublicScalar::from_limbs(VALS_0));
    for limb_idx in 0..4 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(
            base,
            Sm2PublicScalar::from_limbs(other),
            "a difference in limb {limb_idx} must be detected"
        );
    }
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4] {
        let secret = Sm2Scalar::from_limbs(limbs);
        let round_tripped = Sm2Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn secret_scalar_from_be_bytes_reduces_out_of_range_input() {
    let mut n_bytes = [0u8; 32];
    for (i, limb) in N_LIMBS.iter().rev().enumerate() {
        n_bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    assert_eq!(Sm2Scalar::from_be_bytes(&n_bytes), Sm2Scalar::from_limbs([0, 0, 0, 0]));
}

#[test]
fn scalar_field_from_secret_matches_from_limbs() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        let secret = Sm2Scalar::from_limbs(limbs);
        assert_eq!(Sm2ScalarField::from_secret(&secret), fe(limbs));
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
    let mut rng = Xorshift64(0x1917201720172017);
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
        if a != Sm2ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), Sm2ScalarField::ONE, "a * a^-1 == 1");
        }
    }
}
