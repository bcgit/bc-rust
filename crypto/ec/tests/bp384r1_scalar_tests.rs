//! Known-answer tests for [`Bp384r1ScalarField`] arithmetic mod the brainpoolP384r1 curve
//! order `n`. Expected values computed independently in Python:
//!
//! ```text
//! n = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565
//! random.seed(830384)
//! vals = [random.randrange(1, n) for _ in range(5)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::bp384r1_scalar::{
    Bp384r1PublicScalar, Bp384r1Scalar, Bp384r1ScalarField, N_LIMBS,
};

const VALS_0: [u64; 6] = [
    0x69369a243277814a, 0xede0d2c1b43ac22d, 0x17aaa9a41227ccd6, 0x3203a19dc7d3ce1d,
    0x84019677cea14e16, 0x36c75dc0ce981d6e,
];
const VALS_1: [u64; 6] = [
    0x6935e6c751b6ae73, 0x7dc31215cf5f922e, 0xdec4eb2c5423ea30, 0xeb5b4727ca0d7793,
    0xc1f5e7167ab259df, 0x63ec108aea10824b,
];
const VALS_2: [u64; 6] = [
    0x36684ffecee01f87, 0xda14ecd2a6850941, 0xb75599c6b4b705f5, 0x94fed47d75f29d1a,
    0x5f1cdd331e5b957e, 0x76cddcd6665f46c3,
];
const VALS_3: [u64; 6] = [
    0x797e37ad048c98f2, 0x7d74a6fe383fea19, 0x43c8e04f1f09e5ff, 0xbd38b843a82e8f65,
    0x7600ed2f7ba5343c, 0x08c8e3d7089398b1,
];
const VALS_4: [u64; 6] = [
    0x55bdbf0a3b847e80, 0xbed32140bf5ce4d5, 0x6a14533e3da9e911, 0x848a618a268b1b0f,
    0x402db6ac1b0c3e26, 0x31bcb6616eb97973,
];
const VALS_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];

const ADD_0_1: [u64; 6] = [
    0x96e44ee89b29ca58, 0x9c692e28181a914b, 0xd7592663ba47915f, 0x082f77bba48ceefd,
    0x369a0e0ff86d6617, 0x0dfa4fc915703292,
];
const SUB_0_1: [u64; 6] = [
    0x3b88e55fc9c5383c, 0x3f58775b505af30f, 0x57fc2ce46a08084e, 0x5bd7cb7feb1aad3c,
    0xd1691edfa4d53615, 0x5f946bb887c0084a,
];
const MUL_0_1: [u64; 6] = [
    0xe11d34d8fd807429, 0xbe521073885f1101, 0x3ec19ff2381d7aed, 0x40b18dc0ade49761,
    0x3856a13b9d1b9835, 0x7c473fd290aeba15,
];
const ADD_0_2: [u64; 6] = [
    0x6416b82018533b6c, 0xf8bb08e4ef40085e, 0xafe9d4fe1adaad24, 0xb1d3051150721484,
    0xd3c1042c9c16a1b5, 0x20dc1c1491bef709,
];
const SUB_0_2: [u64; 6] = [
    0x6e567c284c9bc728, 0xe3069c9e79357bfc, 0x7f6b7e4a0974ec88, 0xb2343e2a3f3587b5,
    0x344228c3012bfa76, 0x4cb29f6d0b7143d3,
];
const MUL_0_2: [u64; 6] = [
    0x9df905a6a9a845e0, 0x2d536f240d439a9c, 0x9fee897ffb91f9f8, 0x3dac0f49231c02a3,
    0x943570b62be7fbb5, 0x26aab1f615dcfc71,
];
const ADD_0_3: [u64; 6] = [
    0xe2b4d1d137041a3c, 0x6b5579bfec7aac46, 0x5b7389f33131b2d6, 0xef3c59e170025d82,
    0xfa0283a74a468252, 0x3f904197d72bb61f,
];
const SUB_0_3: [u64; 6] = [
    0xefb862772deae858, 0x706c2bc37bfad813, 0xd3e1c954f31de6d7, 0x74cae95a1fa53eb7,
    0x0e00a94852fc19d9, 0x2dfe79e9c60484bd,
];
const MUL_0_3: [u64; 6] = [
    0x1c4a55020bb0d8fa, 0x77be98f314d4d002, 0xaedc180d60ab43cf, 0xb674a1f0a3603c22,
    0x94414cb9445eee81, 0x5594058d72c9406a,
];
const ADD_0_4: [u64; 6] = [
    0xbef4592e6dfbffca, 0xacb3f4027397a702, 0x81befce24fd1b5e8, 0xb68e0327ee5ee92c,
    0xc42f4d23e9ad8c3c, 0x688414223d5196e1,
];
const SUB_0_4: [u64; 6] = [
    0x1378db19f6f302ca, 0x2f0db180f4dddd58, 0xad965665d47de3c5, 0xad794013a148b30d,
    0x43d3dfcbb3950fef, 0x050aa75f5fdea3fb,
];
const MUL_0_4: [u64; 6] = [
    0xe70d39dc9f46cd70, 0xb3e217c09067341c, 0xd9a8bc2a1147239d, 0x6e007b9384ec7b1c,
    0xfb3d187dfabe316c, 0x4252262c93ad11dd,
];
const ADD_0_5: [u64; 6] = [
    0x69369a243277814a, 0xede0d2c1b43ac22d, 0x17aaa9a41227ccd6, 0x3203a19dc7d3ce1d,
    0x84019677cea14e16, 0x36c75dc0ce981d6e,
];
const SUB_0_5: [u64; 6] = [
    0x69369a243277814a, 0xede0d2c1b43ac22d, 0x17aaa9a41227ccd6, 0x3203a19dc7d3ce1d,
    0x84019677cea14e16, 0x36c75dc0ce981d6e,
];
const MUL_0_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];
const ADD_1_2: [u64; 6] = [
    0x641604c337926895, 0x889d48390a64d85f, 0x770416865cd6ca7e, 0x6b2aaa9b52abbdfb,
    0x11b554cb4827ad7f, 0x4e00cedead375be7,
];
const SUB_1_2: [u64; 6] = [
    0x6e55c8cb6bdaf451, 0x72e8dbf2945a4bfd, 0x4685bfd24b7109e2, 0x6b8be3b4416f312c,
    0x72367961ad3d0640, 0x79d7523726e9a8b0,
];
const MUL_1_2: [u64; 6] = [
    0x3d78c22f27964af7, 0xe4c5115fbdd2ce40, 0xf64661a7d508f39a, 0x13209addbd589b79,
    0x86e3e27286a9000e, 0x3f322171bc63e9d7,
];
const ADD_1_3: [u64; 6] = [
    0xe2b41e7456434765, 0xfb37b914079f7c47, 0x228dcb7b732dd02f, 0xa893ff6b723c06f9,
    0x37f6d445f6578e1c, 0x6cb4f461f2a41afd,
];
const SUB_1_3: [u64; 6] = [
    0xefb7af1a4d2a1581, 0x004e6b17971fa814, 0x9afc0add351a0431, 0x2e228ee421dee82e,
    0x4bf4f9e6ff0d25a3, 0x5b232cb3e17ce99a,
];
const MUL_1_3: [u64; 6] = [
    0x347b76fb0367c4f2, 0xe0d206cb5fbd5f3e, 0x6400b012b3b24187, 0xe5421fdda01ca282,
    0x0a793ebfe7944964, 0x697eb58f73796c7b,
];
const ADD_1_4: [u64; 6] = [
    0x836b73cea436c78e, 0x6d5b7ca7233cb3f3, 0x29c2cffde5c9ad9a, 0x5ab637a803443bf0,
    0xf2c62e4444d85627, 0x08efa869b5918e96,
];
const SUB_1_4: [u64; 6] = [
    0x137827bd16322ff3, 0xbeeff0d51002ad59, 0x74b097ee167a011e, 0x66d0e59da3825c84,
    0x81c8306a5fa61bb9, 0x322f5a297b5708d8,
];
const MUL_1_4: [u64; 6] = [
    0xd04963394556111c, 0xdc540104a0ae6765, 0x425da4fb66d41e65, 0xff1ac49c5880543e,
    0xac2fc4bb0076dfce, 0x0d763005c3fe70b6,
];
const ADD_1_5: [u64; 6] = [
    0x6935e6c751b6ae73, 0x7dc31215cf5f922e, 0xdec4eb2c5423ea30, 0xeb5b4727ca0d7793,
    0xc1f5e7167ab259df, 0x63ec108aea10824b,
];
const SUB_1_5: [u64; 6] = [
    0x6935e6c751b6ae73, 0x7dc31215cf5f922e, 0xdec4eb2c5423ea30, 0xeb5b4727ca0d7793,
    0xc1f5e7167ab259df, 0x63ec108aea10824b,
];
const MUL_1_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];
const ADD_2_3: [u64; 6] = [
    0xafe687abd36cb879, 0x578993d0dec4f35a, 0xfb1e7a15d3c0ebf5, 0x52378cc11e212c7f,
    0xd51dca629a00c9bb, 0x7f96c0ad6ef2df74,
];
const SUB_2_3: [u64; 6] = [
    0xbcea1851ca538695, 0x5ca045d46e451f27, 0x738cb97795ad1ff6, 0xd7c61c39cdc40db5,
    0xe91bf003a2b66141, 0x6e04f8ff5dcbae11,
];
const MUL_2_3: [u64; 6] = [
    0x046c3ad519bc030d, 0xd7f6399596b469c6, 0x77a3462d720f2b14, 0xfe2e84ec1666608d,
    0x5d8082a3cef65f56, 0x2184eeccb18a9427,
];
const ADD_2_4: [u64; 6] = [
    0x509ddd06216038a2, 0xc9ad5763fa622b06, 0x02537e98465cc95f, 0x0459c4fdaf296177,
    0x8fed2460e88191c6, 0x1bd174b531e0530e,
];
const SUB_2_4: [u64; 6] = [
    0xe0aa90f4935ba107, 0x1b41cb91e728246b, 0x4d414688770d1ce4, 0x107472f34f67820b,
    0x1eef2687034f5758, 0x45112674f7a5cd50,
];
const MUL_2_4: [u64; 6] = [
    0x0901add57f46737f, 0x6963846e362647ed, 0xa263e90a586b4d67, 0xd136f5b490ba6a6d,
    0x80cf588957238523, 0x386fb27fa2d1b928,
];
const ADD_2_5: [u64; 6] = [
    0x36684ffecee01f87, 0xda14ecd2a6850941, 0xb75599c6b4b705f5, 0x94fed47d75f29d1a,
    0x5f1cdd331e5b957e, 0x76cddcd6665f46c3,
];
const SUB_2_5: [u64; 6] = [
    0x36684ffecee01f87, 0xda14ecd2a6850941, 0xb75599c6b4b705f5, 0x94fed47d75f29d1a,
    0x5f1cdd331e5b957e, 0x76cddcd6665f46c3,
];
const MUL_2_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];
const ADD_3_4: [u64; 6] = [
    0xcf3bf6b740111772, 0x3c47c83ef79cceee, 0xaddd338d5cb3cf11, 0x41c319cdceb9aa74,
    0xb62ea3db96b17263, 0x3a859a38774d1224,
];
const SUB_3_4: [u64; 6] = [
    0x5f48aaa5b20c7fd7, 0x8ddc3c6ce462c854, 0xf8cafb7d8d642295, 0x4dddc7c36ef7cb08,
    0x4530a601b17f37f5, 0x63c54bf83d128c66,
];
const MUL_3_4: [u64; 6] = [
    0xfd2b75fc2f61086e, 0xadb4e00e5af1807a, 0x74dd012bf60c72e0, 0xe91d5fa5d0778d96,
    0xfff730f0b6c6eb6b, 0x2524434185f031fc,
];
const ADD_3_5: [u64; 6] = [
    0x797e37ad048c98f2, 0x7d74a6fe383fea19, 0x43c8e04f1f09e5ff, 0xbd38b843a82e8f65,
    0x7600ed2f7ba5343c, 0x08c8e3d7089398b1,
];
const SUB_3_5: [u64; 6] = [
    0x797e37ad048c98f2, 0x7d74a6fe383fea19, 0x43c8e04f1f09e5ff, 0xbd38b843a82e8f65,
    0x7600ed2f7ba5343c, 0x08c8e3d7089398b1,
];
const MUL_3_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];
const ADD_4_5: [u64; 6] = [
    0x55bdbf0a3b847e80, 0xbed32140bf5ce4d5, 0x6a14533e3da9e911, 0x848a618a268b1b0f,
    0x402db6ac1b0c3e26, 0x31bcb6616eb97973,
];
const SUB_4_5: [u64; 6] = [
    0x55bdbf0a3b847e80, 0xbed32140bf5ce4d5, 0x6a14533e3da9e911, 0x848a618a268b1b0f,
    0x402db6ac1b0c3e26, 0x31bcb6616eb97973,
];
const MUL_4_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];

const NEG_0: [u64; 6] = [
    0xd25197deb68ce41b, 0xe159e3edb74500e2, 0x076bc4c899dc58d0, 0xe32bcf6c25808896,
    0x8b5bd9068244f3c8, 0x55f1c0c1d4a04fb9,
];
const INV_0: [u64; 6] = [
    0x15df5ebf73423af2, 0x138f0302e987287d, 0x4b1051978e508fa3, 0x3b727dbac59d9be4,
    0xf07850e679687ce9, 0x69447f8f8d46773a,
];
const NEG_1: [u64; 6] = [
    0xd2524b3b974db6f2, 0x5177a4999c2030e1, 0x4051834057e03b77, 0x29d429e22346df1f,
    0x4d678867d633e7ff, 0x28cd0df7b927eadc,
];
const INV_1: [u64; 6] = [
    0x20cb4a67f98f7e5b, 0x8324617080bf855c, 0x46b40ba8c1bbe78e, 0x3d2b8ce9d2810ccf,
    0xc56b8a7d57d3a159, 0x5f9a4005d1ceabc2,
];
const NEG_2: [u64; 6] = [
    0x051fe2041a2445de, 0xf525c9dcc4fab9cf, 0x67c0d4a5f74d1fb1, 0x80309c8c7761b998,
    0xb040924b328aac60, 0x15eb41ac3cd92664,
];
const INV_2: [u64; 6] = [
    0x60f459a1ed5b8d11, 0x17055ca7bc3134b8, 0x1cd5b832e7a489a8, 0x2561aade21101a4a,
    0x1d7c33d4df3a6167, 0x4e20b90d93dc3f4b,
];
const NEG_3: [u64; 6] = [
    0xc209fa55e477cc73, 0x51c60fb1333fd8f6, 0xdb4d8e1d8cfa3fa8, 0x57f6b8c64525c74d,
    0x995c824ed5410da2, 0x83f03aab9aa4d476,
];
const INV_3: [u64; 6] = [
    0xe89844a1165efa81, 0xec528b21d9ee9849, 0x059fc442e439053e, 0xa97b4d45fde3019c,
    0x34724e6c836c64a8, 0x633c113394fea608,
];
const NEG_4: [u64; 6] = [
    0xe5ca72f8ad7fe6e5, 0x1067956eac22de3a, 0xb5021b2e6e5a3c96, 0x90a50f7fc6c93ba3,
    0xcf2fb8d235da03b8, 0x5afc6821347ef3b4,
];
const INV_4: [u64; 6] = [
    0xf4d0f4066e1297f1, 0x91b9f7a9bc88454e, 0xf68d9c99331a4c98, 0x93d7a2861b555358,
    0xd8292b0f92b99914, 0x5690c604fdfec994,
];
const NEG_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];
const INV_5: [u64; 6] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];

fn fe(limbs: [u64; 6]) -> Bp384r1ScalarField {
    Bp384r1ScalarField::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5].map(fe);
    let add: Vec<Vec<[u64; 6]>> = vec![
        vec![ADD_0_1, ADD_0_2, ADD_0_3, ADD_0_4, ADD_0_5],
        vec![ADD_1_2, ADD_1_3, ADD_1_4, ADD_1_5],
        vec![ADD_2_3, ADD_2_4, ADD_2_5],
        vec![ADD_3_4, ADD_3_5],
        vec![ADD_4_5],
    ];
    let sub: Vec<Vec<[u64; 6]>> = vec![
        vec![SUB_0_1, SUB_0_2, SUB_0_3, SUB_0_4, SUB_0_5],
        vec![SUB_1_2, SUB_1_3, SUB_1_4, SUB_1_5],
        vec![SUB_2_3, SUB_2_4, SUB_2_5],
        vec![SUB_3_4, SUB_3_5],
        vec![SUB_4_5],
    ];
    let mul: Vec<Vec<[u64; 6]>> = vec![
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
        assert_eq!(v.add(&Bp384r1ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Bp384r1ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Bp384r1ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Bp384r1ScalarField::ZERO, "x + (-x) == 0");
        if v != Bp384r1ScalarField::ZERO {
            assert_eq!(v.mul(&v.invert()), Bp384r1ScalarField::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), Bp384r1ScalarField::ZERO, "0^-1 == 0 by convention");
        }
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
    assert_eq!(fe(N_LIMBS), Bp384r1ScalarField::ZERO);
    let n_plus_1: [u64; 6] = [
        0x3b883202e9046566, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    assert_eq!(fe(n_plus_1), Bp384r1ScalarField::ONE);
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        assert_eq!(Bp384r1PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(Bp384r1PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0, 0, 0, 0, 0, 0]);
    let n_plus_1: [u64; 6] = [
        0x3b883202e9046566, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    assert_eq!(Bp384r1PublicScalar::from_limbs(n_plus_1).to_limbs(), [1, 0, 0, 0, 0, 0]);
}

#[test]
fn public_scalar_eq_detects_a_difference_in_any_limb() {
    let base = Bp384r1PublicScalar::from_limbs(VALS_0);
    assert_eq!(base, Bp384r1PublicScalar::from_limbs(VALS_0));
    for limb_idx in 0..6 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(
            base,
            Bp384r1PublicScalar::from_limbs(other),
            "a difference in limb {limb_idx} must be detected"
        );
    }
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4] {
        let secret = Bp384r1Scalar::from_limbs(limbs);
        let round_tripped = Bp384r1Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn secret_scalar_from_be_bytes_reduces_out_of_range_input() {
    let mut n_bytes = [0u8; 48];
    for (i, limb) in N_LIMBS.iter().rev().enumerate() {
        n_bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    assert_eq!(
        Bp384r1Scalar::from_be_bytes(&n_bytes),
        Bp384r1Scalar::from_limbs([0, 0, 0, 0, 0, 0])
    );
}

#[test]
fn scalar_field_from_secret_matches_from_limbs() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        let secret = Bp384r1Scalar::from_limbs(limbs);
        assert_eq!(Bp384r1ScalarField::from_secret(&secret), fe(limbs));
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
    let mut rng = Xorshift64(0xB384256B384256B3);
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
        if a != Bp384r1ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), Bp384r1ScalarField::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE000000000E);
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
    assert_ne!(a, Bp384r1ScalarField::ZERO, "precondition: the value starts non-zero");
    a.zeroize();
    assert_eq!(a, Bp384r1ScalarField::ZERO, "zeroize must leave the value at zero");

    // and it is idempotent, so a caller scrubbing twice on overlapping paths is harmless
    a.zeroize();
    assert_eq!(a, Bp384r1ScalarField::ZERO);
}

/// `is_zero` on the scalar field, pinned for both truth values and across every limb position
/// (see the field test of the same name for why); it is the check behind `negate`'s `0 -> 0`
/// special case.
#[test]
fn is_zero_distinguishes_zero_from_every_nonzero_limb_position() {
    assert!(Bp384r1ScalarField::ZERO.is_zero().to_bool());
    assert!(fe(bouncycastle_ec::bp384r1_scalar::N_LIMBS).is_zero().to_bool(), "n reduces to 0");
    assert!(!Bp384r1ScalarField::ONE.is_zero().to_bool());
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
        0x3b883202e9046564, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    let n_minus_1 = fe(n_minus_1_limbs);
    let n_minus_2 = fe([
        0x3b883202e9046563, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ]);

    assert_eq!(n_minus_1.to_limbs(), n_minus_1_limbs, "Montgomery round trip of n-1");
    assert_eq!(Bp384r1PublicScalar::from_limbs(n_minus_1_limbs).to_limbs(), n_minus_1_limbs);
    assert_eq!(n_minus_1.add(&n_minus_1), n_minus_2, "(n-1) + (n-1) == n-2");
    assert_eq!(n_minus_1.add(&Bp384r1ScalarField::ONE), Bp384r1ScalarField::ZERO, "(n-1) + 1 == 0");
    assert_eq!(Bp384r1ScalarField::ZERO.sub(&Bp384r1ScalarField::ONE), n_minus_1, "0 - 1 == n-1");
    assert_eq!(n_minus_1.mul(&n_minus_1), Bp384r1ScalarField::ONE, "(n-1)^2 == 1");
    assert_eq!(n_minus_1.square(), Bp384r1ScalarField::ONE, "(n-1)^2 == 1, via square");
    assert_eq!(n_minus_1.negate(), Bp384r1ScalarField::ONE, "-(n-1) == 1");
    assert_eq!(n_minus_1.invert(), n_minus_1, "(n-1)^-1 == n-1");
    assert_eq!(Bp384r1ScalarField::ONE.invert(), Bp384r1ScalarField::ONE, "1^-1 == 1");
}
