//! Known-answer tests for [`P256FieldElement`] arithmetic.
//!
//! `p = 2**256 - 2**224 + 2**192 + 2**96 - 1` has no dedicated NIST-published field-arithmetic KAT
//! suite (SP 800-186 gives only the domain parameters; `nist_ecc.txt`'s KATs are point multiples,
//! not raw field operations). The expected values below were computed independently in Python
//! (arbitrary-precision integers, not from recall), by:
//!
//! ```text
//! p = 2**256 - 2**224 + 2**192 + 2**96 - 1
//! random.seed(42)
//! vals = [random.randrange(1, p) for _ in range(6)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % p, (vals[i]-vals[j]) % p, (vals[i]*vals[j]) % p
//! # for each i: (-vals[i]) % p, pow(vals[i], p-2, p) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::p256::P256FieldElement;

const VALS_0: [u64; 4] =
    [0x1c80317fa3b1799e, 0xbdd640fb06671ad1, 0x3eb13b9046685257, 0x23b8c1e9392456de];
const VALS_1: [u64; 4] =
    [0x1a3d1fa7bc8960aa, 0xbd9c66b3ad3c2d6d, 0x8b9d2434e465e150, 0x972a846916419f82];
const VALS_2: [u64; 4] =
    [0x0822e8f36c03119a, 0x17fc695a07a0ca6e, 0x3b8faa1837f8a88b, 0x9a1de644815ef6d1];
const VALS_3: [u64; 4] =
    [0x8fadc1a606cb0fb4, 0xb74d0fb132e70629, 0xb38a088ca65ed389, 0x6b65a6a48b8148f6];
const VALS_4: [u64; 4] =
    [0x72ff5d2a386ecbe1, 0x4737819096da1dac, 0xde8a774bcf36d58b, 0xc241330b01a9e71f];
const VALS_5: [u64; 4] =
    [0x28df6ec4ce4a2bbe, 0x6c307511b2b9437a, 0x47229389571aa876, 0x371ecd7b27cd8130];
const VALS_6: [u64; 4] =
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

const ADD_0_1: [u64; 4] =
    [0x36bd5127603ada48, 0x7b72a7aeb3a3483e, 0xca4e5fc52ace33a8, 0xbae346524f65f660];
const SUB_0_1: [u64; 4] =
    [0x024311d7e72818f3, 0x0039da48592aed64, 0xb314175b62027107, 0x8c8e3d7f22e2b75c];
const MUL_0_1: [u64; 4] =
    [0x1d498e4226541916, 0xa3a2af11401c3eaf, 0xb8b424088cb8c1fd, 0x126c3f0c9d0773ed];
const ADD_0_2: [u64; 4] =
    [0x24a31a730fb48b38, 0xd5d2aa550e07e53f, 0x7a40e5a87e60fae2, 0xbdd6a82dba834daf];
const SUB_0_2: [u64; 4] =
    [0x145d488c37ae6803, 0xa5d9d7a1fec65063, 0x032191780e6fa9cc, 0x899adba3b7c5600e];
const MUL_0_2: [u64; 4] =
    [0xdf30423481f7198f, 0x2df6ba6df741535f, 0xdc109c36de71409a, 0x092f3ed335b6eca9];
const ADD_0_3: [u64; 4] =
    [0xac2df325aa7c8952, 0x752350ac394e20fa, 0xf23b441cecc725e1, 0x8f1e688dc4a59fd4];
const SUB_0_3: [u64; 4] =
    [0x8cd26fd99ce669e9, 0x0689314ad38014a7, 0x8b273303a0097ece, 0xb8531b43ada30de8];
const MUL_0_3: [u64; 4] =
    [0x881a465ba587986c, 0x11a4b476c261c091, 0xb72ee7a8ac8176ac, 0xfbf5f90d5f0ce475];
const ADD_0_4: [u64; 4] =
    [0x8f7f8ea9dc20457f, 0x050dc28b9d41387d, 0x1d3bb2dc159f27e3, 0xe5f9f4f43ace3dfe];
const SUB_0_4: [u64; 4] =
    [0xa980d4556b42adbc, 0x769ebf6b6f8cfd24, 0x6026c44477317ccc, 0x61778edd377a6fbf];
const MUL_0_4: [u64; 4] =
    [0x610d4195b1cf6321, 0x5ad6afddd9b6d95b, 0xb2e3da7fc0dd0f06, 0xd8d65ef5e833bfff];
const ADD_0_5: [u64; 4] =
    [0x455fa04471fba55c, 0x2a06b60cb9205e4b, 0x85d3cf199d82face, 0x5ad78f6460f1d80e];
const SUB_0_5: [u64; 4] =
    [0xf3a0c2bad5674ddf, 0x51a5cbea53add756, 0xf78ea806ef4da9e1, 0xec99f46d1156d5ae];
const MUL_0_5: [u64; 4] =
    [0x4dd8c536b142c4fd, 0x052580f7ef851245, 0x31aac471aea9b11d, 0x21fa0b52a0c75353];
const ADD_0_6: [u64; 4] = VALS_0;
const SUB_0_6: [u64; 4] = VALS_0;
const MUL_0_6: [u64; 4] = [0, 0, 0, 0];
const ADD_1_2: [u64; 4] =
    [0x2260089b288c7245, 0xd598d00cb4dcf7db, 0xc72cce4d1c5e89db, 0x31486aae97a09652];
const SUB_1_2: [u64; 4] =
    [0x121a36b450864f0f, 0xa59ffd5aa59b62ff, 0x500d7a1cac6d38c5, 0xfd0c9e2394e2a8b2];
const MUL_1_2: [u64; 4] =
    [0x8584d1073c9a7562, 0x2f835ac0a1032cee, 0xa4a1e78000501c71, 0xd18e1d03521d8a24];
const ADD_1_3: [u64; 4] =
    [0xa9eae14dc354705f, 0x74e97663e0233396, 0x3f272cc18ac4b4da, 0x02902b0ea1c2e878];
const SUB_1_3: [u64; 4] =
    [0x8a8f5e01b5be50f6, 0x064f57027a552743, 0xd8131ba83e070dc7, 0x2bc4ddc48ac0568b];
const MUL_1_3: [u64; 4] =
    [0x3c069230362b4f5e, 0x5c13926318333ff5, 0xff785333b1899926, 0x5c7b8e512999745f];
const ADD_1_4: [u64; 4] =
    [0x8d3c7cd1f4f82c8c, 0x04d3e84344164b19, 0x6a279b80b39cb6dc, 0x596bb77517eb86a1];
const SUB_1_4: [u64; 4] =
    [0xa73dc27d841a94c8, 0x7664e52416620fc0, 0xad12ace9152f0bc5, 0xd4e9515d1497b863];
const MUL_1_4: [u64; 4] =
    [0xf7b6bdb56011d920, 0xeac8a5b5fc56e9c7, 0xf35c056382048027, 0x621421739d4404a4];
const ADD_1_5: [u64; 4] =
    [0x431c8e6c8ad38c68, 0x29ccdbc55ff570e7, 0xd2bfb7be3b8089c7, 0xce4951e43e0f20b2];
const SUB_1_5: [u64; 4] =
    [0xf15db0e2ee3f34ec, 0x516bf1a1fa82e9f2, 0x447a90ab8d4b38da, 0x600bb6edee741e52];
const MUL_1_5: [u64; 4] =
    [0x7aefe2a7380cb984, 0x276651ef59a69959, 0xd5f63204a5a0805d, 0x3a460936b7b1fb61];
const ADD_1_6: [u64; 4] = VALS_1;
const SUB_1_6: [u64; 4] = VALS_1;
const MUL_1_6: [u64; 4] = [0, 0, 0, 0];
const ADD_2_3: [u64; 4] =
    [0x97d0aa9972ce214f, 0xcf49790a3a87d097, 0xef19b2a4de577c14, 0x05838cea0ce03fc6];
const SUB_2_3: [u64; 4] =
    [0x7875274d653801e6, 0x60af59a8d4b9c444, 0x8805a18b9199d501, 0x2eb83f9ff5ddadda];
const MUL_2_3: [u64; 4] =
    [0xdead4cd976d54360, 0xe597ff5ff7898b58, 0x321ea3afaf4b9da9, 0x1c328f4a59c7d411];
const ADD_2_4: [u64; 4] =
    [0x7b22461da471dd7c, 0x5f33eae99e7ae81a, 0x1a1a2164072f7e16, 0x5c5f19508308ddf0];
const SUB_2_4: [u64; 4] =
    [0x95238bc9339445b8, 0xd0c4e7ca70c6acc1, 0x5d0532cc68c1d2ff, 0xd7dcb3387fb50fb2];
const MUL_2_4: [u64; 4] =
    [0x87d707c1e728f0ce, 0x859152342746f588, 0xd8921a986f162a54, 0xb3e69f5315d84b38];
const ADD_2_5: [u64; 4] =
    [0x310257b83a4d3d58, 0x842cde6bba5a0de8, 0x82b23da18f135101, 0xd13cb3bfa92c7801];
const SUB_2_5: [u64; 4] =
    [0xdf437a2e9db8e5dc, 0xabcbf44854e786f3, 0xf46d168ee0de0014, 0x62ff18c9599175a0];
const MUL_2_5: [u64; 4] =
    [0xa2b4c338c1505d38, 0x27a89e17c7e8bc51, 0x871497c2958968b8, 0x65fe83f8c19119df];
const ADD_2_6: [u64; 4] = VALS_2;
const SUB_2_6: [u64; 4] = VALS_2;
const MUL_2_6: [u64; 4] = [0, 0, 0, 0];
const ADD_3_4: [u64; 4] =
    [0x02ad1ed03f39db96, 0xfe849140c9c123d6, 0x92147fd87595a914, 0x2da6d9b08d2b3015];
const SUB_3_4: [u64; 4] =
    [0x1cae647bce5c43d2, 0x70158e219c0ce87d, 0xd4ff9140d727fdfe, 0xa924739889d761d7];
const MUL_3_4: [u64; 4] =
    [0x3551ad12eda55b13, 0xc13f202fb88dd5b2, 0xcd395f9e7f76d48f, 0xf9843ab669fa865c];
const ADD_3_5: [u64; 4] =
    [0xb88d306ad5153b72, 0x237d84c2e5a049a3, 0xfaac9c15fd797c00, 0xa284741fb34eca26];
const SUB_3_5: [u64; 4] =
    [0x66ce52e13880e3f6, 0x4b1c9a9f802dc2af, 0x6c6775034f442b13, 0x3446d92963b3c7c6];
const MUL_3_5: [u64; 4] =
    [0x5af0d58f0d336fc8, 0x321953464e5b34c2, 0x0a1c94751c6fb8f4, 0xd0bbeabe359ddd16];
const ADD_3_6: [u64; 4] = VALS_3;
const SUB_3_6: [u64; 4] = VALS_3;
const MUL_3_6: [u64; 4] = [0, 0, 0, 0];
const ADD_4_5: [u64; 4] =
    [0x9bdecbef06b8f79f, 0xb367f6a249936126, 0x25ad0ad526517e01, 0xf960008629776850];
const SUB_4_5: [u64; 4] =
    [0x4a1fee656a24a023, 0xdb070c7ee420da32, 0x9767e3c2781c2d14, 0x8b22658fd9dc65ef];
const MUL_4_5: [u64; 4] =
    [0xb576898b24ce8b26, 0xfd21ab2dcc5953ea, 0x6cf35cb991b41507, 0x8d202ebbbb3cfb5c];
const ADD_4_6: [u64; 4] = VALS_4;
const SUB_4_6: [u64; 4] = VALS_4;
const MUL_4_6: [u64; 4] = [0, 0, 0, 0];
const ADD_5_6: [u64; 4] = VALS_5;
const SUB_5_6: [u64; 4] = VALS_5;
const MUL_5_6: [u64; 4] = [0, 0, 0, 0];

const NEG_0: [u64; 4] =
    [0xe37fce805c4e8661, 0x4229bf05f998e52e, 0xc14ec46fb997ada8, 0xdc473e15c6dba922];
const INV_0: [u64; 4] =
    [0xb1050be5937e81ae, 0xbd6f1a6f49282e49, 0x728211695c8fa4df, 0x7c5a33c130de7334];
const NEG_1: [u64; 4] =
    [0xe5c2e05843769f55, 0x4263994d52c3d292, 0x7462dbcb1b9a1eaf, 0x68d57b95e9be607e];
const INV_1: [u64; 4] =
    [0xe551f2c212d76de6, 0x74ce654bfd807ed6, 0x4667b16ceb7fbc0d, 0x247a2cc9257ab640];
const NEG_2: [u64; 4] =
    [0xf7dd170c93fcee65, 0xe80396a6f85f3591, 0xc47055e7c8075774, 0x65e219ba7ea1092f];
const INV_2: [u64; 4] =
    [0xdda48d116061f542, 0xdb447add6ba832fe, 0x517b7972a38c436e, 0x5fd58edb3e7c89e9];
const NEG_3: [u64; 4] =
    [0x70523e59f934f04b, 0x48b2f04fcd18f9d6, 0x4c75f77359a12c76, 0x949a595a747eb70a];
const INV_3: [u64; 4] =
    [0x5756b86453511e12, 0x50d7c62b470504f5, 0xbe27831882095df9, 0x8869ace893e5a982];
const NEG_4: [u64; 4] =
    [0x8d00a2d5c791341e, 0xb8c87e706925e253, 0x217588b430c92a74, 0x3dbeccf3fe5618e1];
const INV_4: [u64; 4] =
    [0xb6840a3a64de01e9, 0x9703e1fddd33be42, 0x30d83be306042cc4, 0x246672da71956f4a];
const NEG_5: [u64; 4] =
    [0xd720913b31b5d441, 0x93cf8aef4d46bc85, 0xb8dd6c76a8e55789, 0xc8e13283d8327ed0];
const INV_5: [u64; 4] =
    [0xd542799f6b30bfad, 0x7d06ddeac9155583, 0x6743bc828194d6c9, 0x95520c6c86007aa4];
const NEG_6: [u64; 4] = [0, 0, 0, 0];
const INV_6: [u64; 4] = [0, 0, 0, 0];

fn fe(limbs: [u64; 4]) -> P256FieldElement {
    P256FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5, VALS_6].map(fe);
    let add: Vec<Vec<[u64; 4]>> = vec![
        vec![ADD_0_1, ADD_0_2, ADD_0_3, ADD_0_4, ADD_0_5, ADD_0_6],
        vec![ADD_1_2, ADD_1_3, ADD_1_4, ADD_1_5, ADD_1_6],
        vec![ADD_2_3, ADD_2_4, ADD_2_5, ADD_2_6],
        vec![ADD_3_4, ADD_3_5, ADD_3_6],
        vec![ADD_4_5, ADD_4_6],
        vec![ADD_5_6],
    ];
    let sub: Vec<Vec<[u64; 4]>> = vec![
        vec![SUB_0_1, SUB_0_2, SUB_0_3, SUB_0_4, SUB_0_5, SUB_0_6],
        vec![SUB_1_2, SUB_1_3, SUB_1_4, SUB_1_5, SUB_1_6],
        vec![SUB_2_3, SUB_2_4, SUB_2_5, SUB_2_6],
        vec![SUB_3_4, SUB_3_5, SUB_3_6],
        vec![SUB_4_5, SUB_4_6],
        vec![SUB_5_6],
    ];
    let mul: Vec<Vec<[u64; 4]>> = vec![
        vec![MUL_0_1, MUL_0_2, MUL_0_3, MUL_0_4, MUL_0_5, MUL_0_6],
        vec![MUL_1_2, MUL_1_3, MUL_1_4, MUL_1_5, MUL_1_6],
        vec![MUL_2_3, MUL_2_4, MUL_2_5, MUL_2_6],
        vec![MUL_3_4, MUL_3_5, MUL_3_6],
        vec![MUL_4_5, MUL_4_6],
        vec![MUL_5_6],
    ];
    for i in 0..7 {
        for j in (i + 1)..7 {
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
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5, VALS_6];
    let negs = [NEG_0, NEG_1, NEG_2, NEG_3, NEG_4, NEG_5, NEG_6];
    let invs = [INV_0, INV_1, INV_2, INV_3, INV_4, INV_5, INV_6];
    for i in 0..7 {
        assert_eq!(fe(vals[i]).negate(), fe(negs[i]), "negate({i})");
        assert_eq!(fe(vals[i]).invert(), fe(invs[i]), "invert({i})");
    }
}

#[test]
fn identities() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5, VALS_6].map(fe);
    for &v in &vals {
        assert_eq!(v.add(&P256FieldElement::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&P256FieldElement::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), P256FieldElement::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), P256FieldElement::ZERO, "x + (-x) == 0");
        if v != P256FieldElement::ZERO {
            assert_eq!(v.mul(&v.invert()), P256FieldElement::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), P256FieldElement::ZERO, "0^-1 == 0 by convention");
        }
    }
}

#[test]
fn from_limbs_reduces_out_of_range_input() {
    // p itself must reduce to 0, and p+1 to 1.
    assert_eq!(fe(bouncycastle_ec::p256::P_LIMBS), P256FieldElement::ZERO);
    let p_plus_1: [u64; 4] =
        [0x0000000000000000, 0x0000000100000000, 0x0000000000000000, 0xffffffff00000001];
    assert_eq!(fe(p_plus_1), P256FieldElement::ONE);

    // the maximum u64 limb pattern (2^256 - 1) must also reduce correctly:
    // 2^256 - 1 - p == C - 1 (see the module's reduction constant).
    let all_ones = [u64::MAX; 4];
    let expected_c_minus_1 = fe([0, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe]);
    assert_eq!(fe(all_ones), expected_c_minus_1);
}

#[test]
fn to_limbs_round_trips() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5, VALS_6] {
        assert_eq!(fe(limbs).to_limbs(), limbs);
    }
}

#[test]
fn eq_detects_a_difference_in_any_limb() {
    let base = fe(VALS_0);
    assert_eq!(base, fe(VALS_0), "equal values must compare equal");
    for limb_idx in 0..4 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1; // flip the lowest bit of just this limb
        assert_ne!(base, fe(other), "a difference in limb {limb_idx} must be detected");
    }
    // and distinct KAT values must never be considered equal to one another
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5, VALS_6];
    for i in 0..vals.len() {
        for j in (i + 1)..vals.len() {
            assert_ne!(fe(vals[i]), fe(vals[j]), "VALS_{i} must differ from VALS_{j}");
        }
    }
}

/// xorshift64* PRNG, fixed seed: deterministic across runs, needs no external dependency, and
/// exercises far more of the input space than the hand-picked KATs above.
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
    let mut rng = Xorshift64(0x243F6A8885A308D3);
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
        if a != P256FieldElement::ZERO {
            assert_eq!(a.mul(&a.invert()), P256FieldElement::ONE, "a * a^-1 == 1");
        }
    }
}
