//! Known-answer tests for [`Bp512r1ScalarField`] arithmetic mod the brainpoolP512r1 curve
//! order `n`. Expected values computed independently in Python:
//!
//! ```text
//! n = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069
//! random.seed(830512)
//! vals = [random.randrange(1, n) for _ in range(5)] + [0]
//! # for each pair (i, j) with i < j: (vals[i]+vals[j]) % n, (vals[i]-vals[j]) % n, (vals[i]*vals[j]) % n
//! # for each i: (-vals[i]) % n, pow(vals[i], n-2, n) if vals[i] != 0 else 0
//! ```

use bouncycastle_ec::bp512r1_scalar::{
    Bp512r1PublicScalar, Bp512r1Scalar, Bp512r1ScalarField, N_LIMBS,
};

const VALS_0: [u64; 8] = [
    0xfe0a77c2a06c4222, 0xfc97dd8974930a3c, 0xbe7a0837a055f066, 0x5aabde57ce7eeb85,
    0x8528df7738313dc2, 0x2e2c027dd4f86ed6, 0x0055d5619a9a9691, 0x69b3c457f3d5201e,
];
const VALS_1: [u64; 8] = [
    0xf9d09068277a5920, 0x8bd21c72c1ad0315, 0x2f498000b2d67897, 0x97eb6b41f1a7fc72,
    0x0563331ae3d365ad, 0x3a2d9b815b72e631, 0xb0484c83fc6e9b74, 0x6060f39adf676da4,
];
const VALS_2: [u64; 8] = [
    0x0323b915f0a14117, 0x234f534c87e9cc42, 0xf6aea69a237a2ff9, 0x06f062d59ac95de5,
    0xb2c8accb4dee1b9f, 0x034f02cfe3fdf48f, 0x8b3b34575e1809c6, 0x32873537150568b5,
];
const VALS_3: [u64; 8] = [
    0xd76804f2f1e81b80, 0x5b1290b8d7accb6a, 0xca4cbddd4d8b743a, 0xbd754e0cb7e64fcc,
    0xb7acdd72b5cfcb01, 0x31aa1f252466b32f, 0xae3fe91854e97b8c, 0x84b2fe72174c46b9,
];
const VALS_4: [u64; 8] = [
    0x43c9d15ffb05bfda, 0x2060aa26716afeb8, 0x38584661d9c8a19d, 0x5e6e9225b3229aac,
    0xc17b7826b9aa9b40, 0xcb2478003de57db1, 0x8287c262f12e2847, 0x205ded5753d56738,
];
const VALS_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];

const ADD_0_1: [u64; 8] = [
    0x425371a82b3d9ad9, 0x6ab8267b2de23275, 0xac3d271ed38058b7, 0x9d58ed58737dc1de,
    0xb42875c7abd19aff, 0x9d29104b7ca182f8, 0x70c93b37633f35fd, 0x1f371a39f752c937,
];
const SUB_0_1: [u64; 8] = [
    0x0439e75a78f1e902, 0x70c5c116b2e60727, 0x8f308836ed7f77cf, 0xc2c07315dcd6ef13,
    0x7fc5ac5c545dd814, 0xf3fe66fc798588a5, 0x500d88dd9e2bfb1c, 0x0952d0bd146db279,
];
const MUL_0_1: [u64; 8] = [
    0xc44d671d5b410039, 0xa2ee104f20255893, 0xd7599f2fe454d9d2, 0x2bc875c982b5ebb9,
    0x5beeab35b6a749c4, 0x971dea48a356f807, 0xe8d27dfc3e79f1db, 0x5ffdb2e752cb0ac5,
];
const ADD_0_2: [u64; 8] = [
    0x012e30d8910d8339, 0x1fe730d5fc7cd67f, 0xb528aed1c3d02060, 0x619c412d6948496b,
    0x37f18c42861f5961, 0x317b054db8f66366, 0x8b9109b8f8b2a057, 0x9c3af98f08da88d3,
];
const SUB_0_2: [u64; 8] = [
    0xfae6beacafcb010b, 0xd9488a3ceca93dfa, 0xc7cb619d7cdbc06d, 0x53bb7b8233b58d9f,
    0xd26032abea432223, 0x2adcffadf0fa7a46, 0x751aa10a3c828ccb, 0x372c8f20decfb768,
];
const MUL_0_2: [u64; 8] = [
    0x8180ae76f33246ac, 0x8f7feda2a40391c5, 0xbfe1555f8b512431, 0x7e19d29f54c55c94,
    0xf2bf9f3e117cc4e4, 0xccf58e4f6efe0413, 0xe527a360b681c55a, 0x92e7e2047d478b7f,
];
const ADD_0_3: [u64; 8] = [
    0x1feae632f5ab5d39, 0x39f89ac143e1faca, 0x474064fb6e35545a, 0xc2e2d02339bc1539,
    0x6672201f7dce0053, 0x94a593ef45954ff7, 0x6ec0d7cbbbba1615, 0x438925112f37a24c,
];
const SUB_0_3: [u64; 8] = [
    0xdc2a09524b2d270b, 0xbf372051a54419af, 0x35b3ab73d2768c73, 0xf274ec8c6341c1d2,
    0xa3df9ecef2947b30, 0xc7b2710c645b8db5, 0x91ead2f7797b170c, 0x8fde639eb8729def,
];
const MUL_0_3: [u64; 8] = [
    0xf17d8127c96aa632, 0x6dea1a537962aec1, 0x1bb094dfadbe777e, 0x2604a8dad54e6a41,
    0x6b138d7203451d2c, 0x42b8ead58f7850c3, 0xe1c9170567fde334, 0x7c8b11d749303c98,
];
const ADD_0_4: [u64; 8] = [
    0x41d449229b7201fc, 0x1cf887afe5fe08f5, 0xf6d24e997a1e9204, 0xb91a707d81a18631,
    0x46a4579df1dbd902, 0xf9507a7e12ddec88, 0x82dd97c48bc8bed8, 0x8a11b1af47aa8756,
];
const SUB_0_4: [u64; 8] = [
    0xba40a662a5668248, 0xdc37336303280b84, 0x8621c1d5c68d4ec9, 0xfc3d4c321b5c50d9,
    0xc3ad67507e86a281, 0x63078a7d9712f124, 0x7dce12fea96c6e49, 0x4955d7009fffb8e5,
];
const MUL_0_4: [u64; 8] = [
    0x478aff9e19b22d0e, 0x2a204c4536c2f0db, 0x84c23a2f2c17a4be, 0xc445536b2d8884e8,
    0xd210ea515d10cdc2, 0xcf1616d9d9dc8259, 0x16862a6e82ff3566, 0x906228935627ebb4,
];
const ADD_0_5: [u64; 8] = [
    0xfe0a77c2a06c4222, 0xfc97dd8974930a3c, 0xbe7a0837a055f066, 0x5aabde57ce7eeb85,
    0x8528df7738313dc2, 0x2e2c027dd4f86ed6, 0x0055d5619a9a9691, 0x69b3c457f3d5201e,
];
const SUB_0_5: [u64; 8] = [
    0xfe0a77c2a06c4222, 0xfc97dd8974930a3c, 0xbe7a0837a055f066, 0x5aabde57ce7eeb85,
    0x8528df7738313dc2, 0x2e2c027dd4f86ed6, 0x0055d5619a9a9691, 0x69b3c457f3d5201e,
];
const MUL_0_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const ADD_1_2: [u64; 8] = [
    0xfcf4497e181b9a37, 0xaf216fbf4996cf57, 0x25f8269ad650a890, 0x9edbce178c715a58,
    0xb82bdfe631c1814c, 0x3d7c9e513f70dac0, 0x3b8380db5a86a53a, 0x92e828d1f46cd65a,
];
const SUB_1_2: [u64; 8] = [
    0xf6acd75236d91809, 0x6882c92639c336d3, 0x389ad9668f5c489e, 0x90fb086c56de9e8c,
    0x529a864f95e54a0e, 0x36de98b17774f1a1, 0x250d182c9e5691ae, 0x2dd9be63ca6204ef,
];
const MUL_1_2: [u64; 8] = [
    0x6845eed377e37a21, 0xf41e07ef4414cad5, 0x046b3d96efb2d6c2, 0xf1197444817e68a6,
    0x3b7307b86fd9d64f, 0x470a947da9794c7b, 0x64a1cc6cd8d606e9, 0x1c2f97c872041289,
];
const ADD_1_3: [u64; 8] = [
    0x1bb0fed87cb97437, 0xc932d9aa90fbf3a3, 0xb80fdcc480b5dc8a, 0x00225d0d5ce52625,
    0xe6ac73c32970283f, 0xa0a72cf2cc0fc751, 0x1eb34eee1d8e1af8, 0x3a3654541ac9efd3,
];
const SUB_1_3: [u64; 8] = [
    0xd7f021f7d23b3e09, 0x4e715f3af25e1288, 0xa683233ce4f714a4, 0x2fb47976866ad2be,
    0x2419f2729e36a31c, 0xd3b40a0fead60510, 0x41dd4a19db4f1bef, 0x868b92e1a404eb76,
];
const MUL_1_3: [u64; 8] = [
    0xbb8ee703b432dfe3, 0x2502d4dd4282d4bb, 0x713006f11083811a, 0x81c1905cbc10da5d,
    0x8d459675929e9106, 0x2580ad27e06fc742, 0x713f180420ed013d, 0x187e94edabfa2b3f,
];
const ADD_1_4: [u64; 8] = [
    0x3d9a61c8228018fa, 0xac32c699331801ce, 0x67a1c6628c9f1a34, 0xf659fd67a4ca971e,
    0xc6deab419d7e00ed, 0x05521381995863e2, 0x32d00ee6ed9cc3bc, 0x80bee0f2333cd4dd,
];
const SUB_1_4: [u64; 8] = [
    0xb606bf082c749946, 0x6b71724c5042045d, 0xf6f1399ed90dd6fa, 0x397cd91c3e8561c5,
    0x43e7baf42a28ca6d, 0x6f0923811d8d687f, 0x2dc08a210b40732c, 0x400306438b92066c,
];
const MUL_1_4: [u64; 8] = [
    0x0b22faf1ed9a838c, 0xc9c0d1f9686b8229, 0xb26912c687eef4b3, 0x3a9c1083c845fdbc,
    0xcbfde3e01746c306, 0x495ecb7619d0ff32, 0x7acf5e29e34b486b, 0x545373c3a56cb77a,
];
const ADD_1_5: [u64; 8] = [
    0xf9d09068277a5920, 0x8bd21c72c1ad0315, 0x2f498000b2d67897, 0x97eb6b41f1a7fc72,
    0x0563331ae3d365ad, 0x3a2d9b815b72e631, 0xb0484c83fc6e9b74, 0x6060f39adf676da4,
];
const SUB_1_5: [u64; 8] = [
    0xf9d09068277a5920, 0x8bd21c72c1ad0315, 0x2f498000b2d67897, 0x97eb6b41f1a7fc72,
    0x0563331ae3d365ad, 0x3a2d9b815b72e631, 0xb0484c83fc6e9b74, 0x6060f39adf676da4,
];
const MUL_1_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const ADD_2_3: [u64; 8] = [
    0x2504278645e05c2e, 0x60b010845738bccf, 0x7f75035df15993ec, 0x6f2754a106068799,
    0x9411ed73938ade30, 0x69c89441549ad5b0, 0xf9a636c17f37894a, 0x0c5c95f05067eae3,
];
const SUB_2_3: [u64; 8] = [
    0xe1434aa59b622600, 0xe5ee9614b89adbb4, 0x6de849d6559acc05, 0x9eb9710a2f8c3432,
    0xd17f6c230851590d, 0x9cd5715e7361136e, 0x1cd031ed3cf88a41, 0x58b1d47dd9a2e687,
];
const MUL_2_3: [u64; 8] = [
    0x14f86b797c43eede, 0x5c254f9c1cc5d82b, 0xa3d47228f954a4a2, 0xb22ff597a11f3a8c,
    0x96a5ac0fafc8f2a2, 0xf077bb2f3a2b4ef4, 0xe231cb40916b0c59, 0x1098e308ae2103ef,
];
const ADD_2_4: [u64; 8] = [
    0x46ed8a75eba700f1, 0x43affd72f954cafa, 0x2f06ecfbfd42d196, 0x655ef4fb4debf892,
    0x744424f20798b6df, 0xce737ad021e37241, 0x0dc2f6ba4f46320d, 0x52e5228e68dacfee,
];
const SUB_2_4: [u64; 8] = [
    0xbf59e7b5f59b813d, 0x02eea926167ecd89, 0xbe56603849b18e5c, 0xa881d0afe7a6c339,
    0xf14d34a49443805e, 0x382a8acfa61876dd, 0x08b371f46ce9e17e, 0x122947dfc130017d,
];
const MUL_2_4: [u64; 8] = [
    0x5c49ff018d923f27, 0x6e0712f807fcafd5, 0xff29918a7c7af2df, 0x559b5b32a2562215,
    0x75d30700543df145, 0xe195bbe82ae60c2d, 0xc4795323d3898989, 0x243ca49474e5bbb8,
];
const ADD_2_5: [u64; 8] = [
    0x0323b915f0a14117, 0x234f534c87e9cc42, 0xf6aea69a237a2ff9, 0x06f062d59ac95de5,
    0xb2c8accb4dee1b9f, 0x034f02cfe3fdf48f, 0x8b3b34575e1809c6, 0x32873537150568b5,
];
const SUB_2_5: [u64; 8] = [
    0x0323b915f0a14117, 0x234f534c87e9cc42, 0xf6aea69a237a2ff9, 0x06f062d59ac95de5,
    0xb2c8accb4dee1b9f, 0x034f02cfe3fdf48f, 0x8b3b34575e1809c6, 0x32873537150568b5,
];
const MUL_2_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const ADD_3_4: [u64; 8] = [
    0x1b31d652eceddb5a, 0x7b733adf4917ca23, 0x02a5043f275415d7, 0x1be3e0326b08ea79,
    0x792855996f7a6642, 0xfcce9725624c30e1, 0x30c7ab7b4617a3d3, 0xa510ebc96b21adf2,
];
const SUB_3_4: [u64; 8] = [
    0x939e3392f6e25ba6, 0x3ab1e6926641ccb2, 0x91f4777b73c2d29d, 0x5f06bbe704c3b520,
    0xf631654bfc252fc1, 0x6685a724e681357d, 0x2bb826b563bb5344, 0x6455111ac376df81,
];
const MUL_3_4: [u64; 8] = [
    0x2d530772ccc014ca, 0x14d205116d45f4eb, 0x45f3323ee5d7c2cb, 0xb5c58fc93d3f16b7,
    0xec8b52c106a193c8, 0x686c87342340a269, 0xfddd204258f3a319, 0x0007cd0826e5e07b,
];
const ADD_3_5: [u64; 8] = [
    0xd76804f2f1e81b80, 0x5b1290b8d7accb6a, 0xca4cbddd4d8b743a, 0xbd754e0cb7e64fcc,
    0xb7acdd72b5cfcb01, 0x31aa1f252466b32f, 0xae3fe91854e97b8c, 0x84b2fe72174c46b9,
];
const SUB_3_5: [u64; 8] = [
    0xd76804f2f1e81b80, 0x5b1290b8d7accb6a, 0xca4cbddd4d8b743a, 0xbd754e0cb7e64fcc,
    0xb7acdd72b5cfcb01, 0x31aa1f252466b32f, 0xae3fe91854e97b8c, 0x84b2fe72174c46b9,
];
const MUL_3_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const ADD_4_5: [u64; 8] = [
    0x43c9d15ffb05bfda, 0x2060aa26716afeb8, 0x38584661d9c8a19d, 0x5e6e9225b3229aac,
    0xc17b7826b9aa9b40, 0xcb2478003de57db1, 0x8287c262f12e2847, 0x205ded5753d56738,
];
const SUB_4_5: [u64; 8] = [
    0x43c9d15ffb05bfda, 0x2060aa26716afeb8, 0x38584661d9c8a19d, 0x5e6e9225b3229aac,
    0xc17b7826b9aa9b40, 0xcb2478003de57db1, 0x8287c262f12e2847, 0x205ded5753d56738,
];
const MUL_4_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];

const NEG_0: [u64; 8] = [
    0xb77d1ebffc3cbe47, 0x2119f5f793cad0a0, 0x830c58e1df561fe0, 0xfa927de97e2a3a93,
    0x513abd533801caad, 0x9d048b35ded16338, 0x3f7f114c992f6576, 0x4129d960e814a46d,
];
const INV_0: [u64; 8] = [
    0x4888528c419d8136, 0x2e38aed6b7ddfc2c, 0xa3cdc7065e7fe91f, 0x8947feb85a876491,
    0x7a162a6b60cd70c6, 0xb3346c8750e24000, 0x3f7315b921b97fa4, 0x5c1238c85f010c93,
];
const NEG_1: [u64; 8] = [
    0xbbb7061a752ea749, 0x91dfb70e46b0d7c7, 0x123ce118ccd597af, 0xbd52f0ff5b0129a7,
    0xd10069af8c5fa2c2, 0x9102f2325856ebdd, 0x8f8c9a2a375b6093, 0x4a7caa1dfc8256e6,
];
const INV_1: [u64; 8] = [
    0xd9fc225e3d64eb64, 0x568d31f24cf0613c, 0x1fb09034e0680459, 0xa6323d11c8344562,
    0x93fc50d18b72839f, 0x6c5b909740271afe, 0x21f0c45f3fe09a3c, 0x72d4e2b8688faccc,
];
const NEG_2: [u64; 8] = [
    0xb263dd6cac07bf52, 0xfa62803480740e9b, 0x4ad7ba7f5c31e04d, 0x4e4df96bb1dfc833,
    0x239aefff2244ecd1, 0xc7e18ae3cfcbdd7f, 0xb499b256d5b1f241, 0x78566881c6e45bd5,
];
const INV_2: [u64; 8] = [
    0xa7a0aaaf9c3338b0, 0xed1dffa3e22564de, 0xacda55f15a91ba74, 0x13d6f903015777c2,
    0x25d7548e679c3b0c, 0x498ecce06da075f1, 0xb1cd41f93f3fecc5, 0x419bd9cfae0f0263,
];
const NEG_3: [u64; 8] = [
    0xde1f918faac0e4e9, 0xc29f42c830b10f72, 0x7739a33c32209c0c, 0x97c90e3494c2d64c,
    0x1eb6bf57ba633d6e, 0x99866e8e8f631edf, 0x9194fd95dee0807b, 0x262a9f46c49d7dd1,
];
const INV_3: [u64; 8] = [
    0xef71511cf959f418, 0x6b63b4320ef080a5, 0x72c9abfe5b88e25b, 0xa0942c73caf1ce92,
    0x03dacc2c6e03b48f, 0xd97b6fc2334e23d8, 0x68a1965566ce906b, 0x827d87eab47bbb4d,
];
const NEG_4: [u64; 8] = [
    0x71bdc522a1a3408f, 0xfd51295a96f2dc25, 0x092e1ab7a5e36ea9, 0xf6cfca1b99868b6d,
    0x14e824a3b6886d2f, 0x000c15b375e4545d, 0xbd4d244b429bd3c0, 0x8a7fb06188145d52,
];
const INV_4: [u64; 8] = [
    0xa288e451c768d4fc, 0xbb5c0754e0912954, 0x1517c339f229a54a, 0x4efb46a5834f30b5,
    0x4f2aa0e3e3ec32da, 0x390309223a05b860, 0x536e0da9977db4e5, 0x598c8870a9711616,
];
const NEG_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const INV_5: [u64; 8] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];

fn fe(limbs: [u64; 8]) -> Bp512r1ScalarField {
    Bp512r1ScalarField::from_limbs(limbs)
}

#[test]
fn known_answer_pairwise_add_sub_mul() {
    let vals = [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5].map(fe);
    let add: Vec<Vec<[u64; 8]>> = vec![
        vec![ADD_0_1, ADD_0_2, ADD_0_3, ADD_0_4, ADD_0_5],
        vec![ADD_1_2, ADD_1_3, ADD_1_4, ADD_1_5],
        vec![ADD_2_3, ADD_2_4, ADD_2_5],
        vec![ADD_3_4, ADD_3_5],
        vec![ADD_4_5],
    ];
    let sub: Vec<Vec<[u64; 8]>> = vec![
        vec![SUB_0_1, SUB_0_2, SUB_0_3, SUB_0_4, SUB_0_5],
        vec![SUB_1_2, SUB_1_3, SUB_1_4, SUB_1_5],
        vec![SUB_2_3, SUB_2_4, SUB_2_5],
        vec![SUB_3_4, SUB_3_5],
        vec![SUB_4_5],
    ];
    let mul: Vec<Vec<[u64; 8]>> = vec![
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
        assert_eq!(v.add(&Bp512r1ScalarField::ZERO), v, "x + 0 == x");
        assert_eq!(v.mul(&Bp512r1ScalarField::ONE), v, "x * 1 == x");
        assert_eq!(v.sub(&v), Bp512r1ScalarField::ZERO, "x - x == 0");
        assert_eq!(v.add(&v.negate()), Bp512r1ScalarField::ZERO, "x + (-x) == 0");
        if v != Bp512r1ScalarField::ZERO {
            assert_eq!(v.mul(&v.invert()), Bp512r1ScalarField::ONE, "x * x^-1 == 1");
        } else {
            assert_eq!(v.invert(), Bp512r1ScalarField::ZERO, "0^-1 == 0 by convention");
        }
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
    assert_eq!(fe(N_LIMBS), Bp512r1ScalarField::ZERO);
    let n_plus_1: [u64; 8] = [
        0xb58796829ca9006a, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
        0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ];
    assert_eq!(fe(n_plus_1), Bp512r1ScalarField::ONE);
}

#[test]
fn public_scalar_round_trips_and_reduces() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        assert_eq!(Bp512r1PublicScalar::from_limbs(limbs).to_limbs(), limbs);
    }
    assert_eq!(Bp512r1PublicScalar::from_limbs(N_LIMBS).to_limbs(), [0, 0, 0, 0, 0, 0, 0, 0]);
    let n_plus_1: [u64; 8] = [
        0xb58796829ca9006a, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
        0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ];
    assert_eq!(Bp512r1PublicScalar::from_limbs(n_plus_1).to_limbs(), [1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn public_scalar_eq_detects_a_difference_in_any_limb() {
    let base = Bp512r1PublicScalar::from_limbs(VALS_0);
    assert_eq!(base, Bp512r1PublicScalar::from_limbs(VALS_0));
    for limb_idx in 0..8 {
        let mut other = VALS_0;
        other[limb_idx] ^= 1;
        assert_ne!(
            base,
            Bp512r1PublicScalar::from_limbs(other),
            "a difference in limb {limb_idx} must be detected"
        );
    }
}

#[test]
fn secret_scalar_be_bytes_round_trip() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4] {
        let secret = Bp512r1Scalar::from_limbs(limbs);
        let round_tripped = Bp512r1Scalar::from_be_bytes(&secret.to_be_bytes());
        assert_eq!(round_tripped, secret);
    }
}

#[test]
fn secret_scalar_from_be_bytes_reduces_out_of_range_input() {
    let mut n_bytes = [0u8; 64];
    for (i, limb) in N_LIMBS.iter().rev().enumerate() {
        n_bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    assert_eq!(
        Bp512r1Scalar::from_be_bytes(&n_bytes),
        Bp512r1Scalar::from_limbs([0, 0, 0, 0, 0, 0, 0, 0])
    );
}

#[test]
fn scalar_field_from_secret_matches_from_limbs() {
    for limbs in [VALS_0, VALS_1, VALS_2, VALS_3, VALS_4, VALS_5] {
        let secret = Bp512r1Scalar::from_limbs(limbs);
        assert_eq!(Bp512r1ScalarField::from_secret(&secret), fe(limbs));
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
    let mut rng = Xorshift64(0xB512256B384256B3);
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
        if a != Bp512r1ScalarField::ZERO {
            assert_eq!(a.mul(&a.invert()), Bp512r1ScalarField::ONE, "a * a^-1 == 1");
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
    let mut rng = Xorshift64(0xC0FFEE000000000F);
    for _ in 0..5000 {
        let a = fe(rng.next_limbs());
        assert_eq!(a.square(), a.mul(&a), "square disagrees with mul");
    }
    for limbs in [
        [0u64; 8],
        {
            let mut l = [0u64; 8];
            l[0] = 1;
            l
        },
        [u64::MAX; 8],
        {
            let mut l = [u64::MAX; 8];
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
    let mut a = fe([1, 2, 3, 4, 5, 6, 7, 8]);
    assert_ne!(a, Bp512r1ScalarField::ZERO, "precondition: the value starts non-zero");
    a.zeroize();
    assert_eq!(a, Bp512r1ScalarField::ZERO, "zeroize must leave the value at zero");

    // and it is idempotent, so a caller scrubbing twice on overlapping paths is harmless
    a.zeroize();
    assert_eq!(a, Bp512r1ScalarField::ZERO);
}
