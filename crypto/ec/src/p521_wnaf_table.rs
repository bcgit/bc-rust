//! The checked-in odd multiples of the base point `G` for [`crate::p521_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and SP 800-186 §3.2.1.5's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 9]; 32] = [
    [
        0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de, 0xa14b5e77efe75928,
        0xf828af606b4d3dba, 0x9c648139053fb521, 0x9e3ecb662395b442, 0x858e06b70404e9cd,
        0x00000000000000c6,
    ],
    [
        0xa5919d2ede37ad7d, 0xaeb490862c32ea05, 0x1da6bd16b59fe21b, 0xad3f164a3a483205,
        0xe5ad7a112d7a8dd1, 0xb52a6e5b123d9ab9, 0xd91d6a64b5959479, 0x3d352443de29195d,
        0x00000000000001a7,
    ],
    [
        0xd5ab5096ec8f3078, 0x29d7e1e6d8931738, 0x7112feaf137e79a3, 0x383c0c6d5e301423,
        0xcf03dab8f177ace4, 0x7a596efdb53f0d24, 0x3dbc3391c04eb0bf, 0x2bf3c52927a432c7,
        0x0000000000000065,
    ],
    [
        0x01cead882816ecd4, 0x6f953f50fdc2619a, 0xc9a6df30dce3bbc4, 0x8c308d0abfc698d8,
        0xf018d2c2f7114c5d, 0x5f22e0e8f5483228, 0xeeb65fda0b073a0c, 0xd5d1d99d5b7f6346,
        0x0000000000000056,
    ],
    [
        0x1f45627967cbe207, 0x4f50babd85cd2866, 0xf3c556df725a318f, 0x7429e1396134da35,
        0x2c4ab145b8c6b665, 0xed34541b98874699, 0xa2f5bf157156d488, 0x5389e359e1e21826,
        0x0000000000000158,
    ],
    [
        0xecc0e02dda0cdb9a, 0x015c024fa4c9a902, 0xd19b1aebe3191085, 0xf3dbc5332663da1b,
        0x43ef2c54f2991652, 0xed5dc7ed7c178495, 0x6f1a39573b4315cf, 0x75841259fdedff54,
        0x000000000000008a,
    ],
    [
        0x1887848d32fbcda7, 0x4bec3b00ab38eff8, 0x3550a5e79ab88ee9, 0x32c45908e03c996a,
        0x4eedd2beaf5b8661, 0x93f736cde1b4c238, 0xd7865d2b4924861a, 0x3e98f984c396ad9c,
        0x000000000000007e,
    ],
    [
        0xe9afe337bcb8db55, 0x9b8d96981e3f92bd, 0x7875bd1c8fc0331d, 0xb91cce27dbd00ffe,
        0xd697b532df128e11, 0xb8fbcc30b40a0852, 0x41558fc546d4300f, 0x6ad89abcb92465f0,
        0x000000000000006b,
    ],
    [
        0x76f817a853110ae0, 0xf8c3042af0d1a410, 0xdf4e799b5681380f, 0x760a69e674fe0287,
        0xd66524f269250858, 0x99ee9e269fa2b3b4, 0xa0b874645923906a, 0x0ddb707f130eda13,
        0x00000000000001b0,
    ],
    [
        0x78ff0b2418d6a19b, 0xfecf431e725bbde4, 0x9232557d7a45970d, 0xfa3b309636266967,
        0xfff0acdb3790e7f1, 0x45b77e0755df547e, 0xc0f948c2d5a1a072, 0x8dcce486419c3487,
        0x0000000000000099,
    ],
    [
        0x42ef399693c8c9ed, 0x37ac920393a46d2d, 0xd9497eaed827d75b, 0x46257eae4d62a309,
        0x19523e759c467fa9, 0x268bb98c2ed15e98, 0x3cc8550859ed3b10, 0xcbb2c11a742bd2fb,
        0x00000000000001a1,
    ],
    [
        0xa1c6a5ece2af535c, 0x07e1f1ac26ae5806, 0xe9e3f8e9a5ec53e2, 0x1f6f83fc9af5b0af,
        0x490d234d0cdd4510, 0xee7a39ba785fb282, 0xdb1cacec5f547b8e, 0x0b275d7290159376,
        0x00000000000001ae,
    ],
    [
        0x3f8c2460bf70ace0, 0xe41e0eb1c25d3fb1, 0x56e87e2aa648ff27, 0xa91856917c36ee4d,
        0x1c772c8c5499994a, 0x0073102651b107b1, 0xa35874a6f5dff9d2, 0xe84c6d5c5a9a1834,
        0x0000000000000154,
    ],
    [
        0x357643017002d68b, 0xb215604492ec4568, 0x51353aeda0d3163c, 0x80b2123da719d483,
        0x33f35187e135854d, 0x8739535d0e4f862c, 0x62a4d4eb889e646f, 0x373edf8218f9b6a7,
        0x0000000000000160,
    ],
    [
        0x2c3927618eda25dc, 0xf33d8595d51f6d96, 0x4003ab8e847ffb9e, 0x5ca9bc06876d7291,
        0x28bef38f7664a130, 0xf9f45131e86265ec, 0xb3c1fbfcb65a085f, 0xc644d6c94b68287d,
        0x0000000000000174,
    ],
    [
        0x2257d0e0c16a8803, 0x0dcfb5e488e24812, 0xfc14c1ac09cd6b22, 0xd65543a904c9d429,
        0x7260a83ca5e7726c, 0xb574589657c2a661, 0x006a58cdb7307b7d, 0xe9920cf30f0c6615,
        0x00000000000000d8,
    ],
    [
        0x5ea2e1fc649f308d, 0xa5ec59186b2ed12d, 0xe9a519a57aa53ac2, 0xabdbea7e2b77ef1a,
        0xf381421a74236df0, 0x52086d482be92613, 0x8c76eb4e3c76f58e, 0x4195f0978fb969e6,
        0x0000000000000028,
    ],
    [
        0xdc1039c9ccd7d718, 0xa92ff614b5dcc8d8, 0xee4a618608f6b2ce, 0xb4806c84fda74023,
        0xc4a780b56f97392b, 0xa267a642b593e0bf, 0x398b62069e0ba392, 0xc300757549630a78,
        0x00000000000000dd,
    ],
    [
        0xf1ac4d59b557a36f, 0x8c64e76ae4780273, 0x0e58e26ee0980df2, 0xbd445763a2885604,
        0x29ed0ae6af9d5749, 0xc35c5d56c1d59e42, 0x39e798352ded5867, 0x4f64a6c21832b671,
        0x0000000000000094,
    ],
    [
        0x0b704119ee33b77c, 0x5b4fa1d48083af67, 0xac0bf434e5fa3179, 0x256b0cc58626a1e2,
        0x38d9fd62359c6ea7, 0x9e9661a49b5b9072, 0x5264126356a49902, 0xa0b8f411fbad6075,
        0x0000000000000124,
    ],
    [
        0x8e00ce952624381e, 0xddfda1a522cc2af6, 0x4c08c3ddc8297bfa, 0x16b931eaf495ccce,
        0x85b85f23864a60c8, 0x52a523e4b28998a6, 0x63ebfd9d28830825, 0xa140ed79e85e24a7,
        0x0000000000000175,
    ],
    [
        0x713e3083224f497e, 0x51f0b62fdee07d20, 0xa3a74e7a9b3d85ca, 0xfc66ad7aed7d37dd,
        0x8ef0f94438fea396, 0x70678aa2ec1419af, 0xd55022d90544d8a0, 0x0148a165ec58e4fe,
        0x000000000000018c,
    ],
    [
        0xa32dec600fc95c1a, 0xc2954607b66b70c4, 0xdc8ea1ace5703f0f, 0x79189b7df8a1f2d9,
        0x7b2df5e3f1972867, 0x7a58f7f28c147cc0, 0x79596b8fff2bc020, 0x69d186aca09e53b8,
        0x0000000000000049,
    ],
    [
        0x2fda63c9abd59d11, 0x0a56a130d1ecbb67, 0x9cee75a3a9c4dd66, 0x381864a0b9e922ac,
        0x97233106c71dd0b2, 0xe4e4fe2714033ff8, 0x9cf5083ecc35882c, 0xe31f8907048afd5f,
        0x00000000000000af,
    ],
    [
        0x0c8cb45049efc0ad, 0x7258dab1ac4c04ca, 0x91d8c84e2e345fa8, 0x6bc2a2df52f62842,
        0xf581b8b111dea9eb, 0x9d45c347ae499839, 0xcba40a63bbaba0d3, 0xcb98fa3c0b8c1d57,
        0x00000000000000a5,
    ],
    [
        0xa8d916fffbcc9504, 0xfba689ef1d7be2dd, 0x1321ae1b1054cbc0, 0xc2edfe6af07390df,
        0x3ba316cbf9beea26, 0xfdf9f5bde34fe9ba, 0x025d93b68145f3cc, 0x395ba51e278415a2,
        0x0000000000000168,
    ],
    [
        0x6285684cccb69906, 0x08153da9c9880816, 0xd3af581fba4fe12b, 0x4e210e637209a78e,
        0x27e82f6f948100c4, 0xf8688be916895fb7, 0x7b3d0ffd310306df, 0xf6e249195ee693f7,
        0x0000000000000143,
    ],
    [
        0x84ad7ccebd470f5e, 0x7fe9ab4bda96ac4e, 0xbe17486b1e0b549a, 0x8cca93917cad27e6,
        0x6472d4028e8da1a1, 0x7cb03e9fd9d0a79d, 0xb551e4155c6daca9, 0x52fc4b6d310ce7c4,
        0x000000000000004b,
    ],
    [
        0x3475330a4e9a13e2, 0x8372c8fff95c8450, 0xf66fd5bc64b8a520, 0x4af300bbde9118b2,
        0xef3c6d77a521b9f8, 0x5a8defe72e6dbf85, 0x4463da75efb25ffa, 0x53c3e7fcf3c902e0,
        0x00000000000000dc,
    ],
    [
        0x63be8a26eb16686b, 0xcba8524ec3472088, 0x1a90342d64373a8a, 0x055693c9b1344c69,
        0xaae5c2934c222920, 0xc7223c5d98901999, 0x063c60342df29ead, 0xaeb454ad31876773,
        0x0000000000000035,
    ],
    [
        0xcb53d8cfcfc376a1, 0x952bad1671543c41, 0xa5e7fce59a7b32d7, 0x7193c11a77dc0b39,
        0x4cd724b1be8b1717, 0x8b6cd17d5b660d1a, 0x92ca7c732a1c7d8f, 0x544c4a011407425c,
        0x0000000000000115,
    ],
    [
        0x0f5beb6fce8888e5, 0x75af7d025770ac8d, 0xc63996847586265e, 0x3ae99661308e125e,
        0xe7f54fe4d51b0845, 0x1ca21b5affa0ddc1, 0xe82f799acb0a6e8e, 0x32753b64640c457f,
        0x00000000000001c1,
    ],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 9]; 32] = [
    [
        0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761, 0x97ee72995ef42640,
        0x17afbd17273e662c, 0x98f54449579b4468, 0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004,
        0x0000000000000118,
    ],
    [
        0x5f588ca1ee86c0e5, 0xf105c9bc93a59042, 0x2d5aced1dec3c70c, 0x2e2dd4cf8dc575b0,
        0xd2f8ab1fa355ceec, 0xf1557fa82a9d0317, 0x979f86c6cab814f2, 0x9b03b97dfa62ddd9,
        0x000000000000013e,
    ],
    [
        0x173cc3e8deb090cb, 0xd1f007257354f7f8, 0x311540211cf5ff79, 0xbb6897c9072cf374,
        0xedd817c9a0347087, 0x1cd8fe8e872e0051, 0x8a2b73114a811291, 0xe6ef1bdd6601d6ec,
        0x000000000000015b,
    ],
    [
        0x5c6b8bc90525251b, 0x9e76712a5ddefc7b, 0x9523a34591ce1a5f, 0x6bd0f293cdec9e2b,
        0x71dbd98a26cbde55, 0xb5c582d02824f0dd, 0xd1d8317a39d68478, 0x2d1b7d9baaa2a110,
        0x000000000000003d,
    ],
    [
        0x3aa0ea86b9ad2a4e, 0x736c2ae928880f34, 0x0ff56ecf4abfd87d, 0x0d69e5756057ac84,
        0xc825ba263ddb446e, 0x3088a654ee1cebb6, 0x0b55557a27ae938e, 0x2e618c9a8aedf39f,
        0x000000000000002a,
    ],
    [
        0x58874f92ce48c808, 0xdcac80e3f4819b5d, 0x3892331914a95336, 0x1bc8a90e8b42a4ab,
        0xed2e95d4e0b9b82b, 0x3add566210bd0493, 0x9d0ca877054fb229, 0xfb303fcbba212984,
        0x0000000000000096,
    ],
    [
        0x291a01fb022a71c9, 0x6199eaaf9117e9f7, 0x26dfdd351cbfbbc3, 0xc1bd5d5838bc763f,
        0x9c7a67ae5c1e212a, 0xced50a386d5421c6, 0x1a1926daa3ed5a08, 0xee58eb6d781feda9,
        0x0000000000000108,
    ],
    [
        0x56343480a1475465, 0x46fd90cc446abdd9, 0x2148e2232c96c992, 0x7e9062c899470a80,
        0x4b62106997485ed5, 0xdf0496a9bad20cba, 0x7ce64d2333edbf63, 0x68da271571391d6a,
        0x00000000000001b4,
    ],
    [
        0x35b9cb7c70e64647, 0xe6905594c2b755f5, 0xd2f6757f16adf420, 0xf9da564ef6dd0bf0,
        0x8d68ac2b22a1323d, 0xb799534cf69910a9, 0xc111d4e4aeddd106, 0x683f1d7db16576db,
        0x0000000000000085,
    ],
    [
        0xa9091a695bfd0575, 0xf5a4d89ea9fbfe44, 0xb0ec39991631c377, 0x73ad963ff2eb8cf9,
        0xcc50eee365457727, 0x67d28aee2b7bcf4a, 0xc3942497535b245d, 0xd5da0626a021ed5c,
        0x0000000000000137,
    ],
    [
        0xe60bc43c9cba4df5, 0x7c9b0f17649ccb61, 0xbeb43a372c63eec5, 0xdf741a53da483295,
        0x180a296f6bafa7f7, 0xe83c0059c5193e6c, 0x2c12da7c5e40ce62, 0x209d7d4f8eeb3d48,
        0x000000000000011a,
    ],
    [
        0xd815c3536fa0d000, 0x213b4450a8d23856, 0x3c27b27bb07dd0c2, 0x10843361ee97fcf4,
        0xb431647844c2dc0e, 0x7d759ff890d05832, 0x68a2858fc068471c, 0xc97a825e53853806,
        0x00000000000000f2,
    ],
    [
        0x4325bce404c78230, 0xeede2a54672e6b6d, 0xd1e2370a6a5972f5, 0xdee3543572fbc1a0,
        0xf66c2888151666a6, 0x15a923eb0022a0c7, 0xe22a28f80bb60d3f, 0x0fdce9171910473a,
        0x00000000000000cd,
    ],
    [
        0xf3e6aeca5d90b740, 0x463ffe709d45acb3, 0x13b874f4a8bb572e, 0x1efa491ed92ebc54,
        0x4a56f78e1a1b2201, 0x9fd193c5cf52c3bb, 0xe5828401ac06a3fa, 0x597050014dcfe1c5,
        0x00000000000000f1,
    ],
    [
        0x187bbbc4821a0c30, 0x0679927c26ebbfbd, 0x50c2732d706d303f, 0xbe0e21952ce0d90b,
        0xb5cf5eb795ad34b7, 0x0233ef8fcb6441fc, 0x05acc95b41b7b782, 0xf3a7c2f87f419e68,
        0x000000000000011a,
    ],
    [
        0xca4677c739792d19, 0xaa1bd97c7b54318a, 0x139a868cae4cc263, 0xf76b8c3244d14790,
        0x0aefb72cbed1aa30, 0x8b5406328f10c806, 0xdf09c13a214a30ec, 0xb023b5454a663987,
        0x0000000000000127,
    ],
    [
        0x6be95a3dd3e11c4d, 0x88effd5c228b58f3, 0x00bd7216c16deb3a, 0xe7656ecbf3d138bf,
        0x9e016769614ac5f2, 0x24d513abe063c663, 0x7b7a3bc869056d3a, 0x43eb08c656dc636b,
        0x000000000000007e,
    ],
    [
        0x3eb1d3ef241e07f4, 0xdeba4db422640a4d, 0x5c212522ee69e797, 0x9ab1178bd2c70142,
        0x462796591a31db50, 0xa510936cb5d85bcf, 0x1b83431f0c30dbbf, 0xbd2d07f6ac7fc5cc,
        0x00000000000000c1,
    ],
    [
        0x312bf98394fb2a03, 0x31a4be4056988296, 0xb85c564995a057c3, 0xdcbdbc2471c83f81,
        0x26317da6b7991305, 0xfe4e6ff21865f859, 0x0c4b9624f26cb192, 0xb7ee1b02028ab741,
        0x0000000000000150,
    ],
    [
        0xd8dcdc61228b61a6, 0xf212e74b698e40ab, 0xa3caf2415944e762, 0x18dc59feb96825aa,
        0xdc0b1240c690db48, 0x68937baa8796154c, 0x602a9a406bbd399c, 0x29616edc7335dce3,
        0x0000000000000010,
    ],
    [
        0xebeb760ec1028ecf, 0xf75dd758e7f3a3ec, 0x052a6e551fa28ebd, 0xb39e0e11ecf327da,
        0x23de821b22c82111, 0xab59e580e9ee5632, 0x36f21343ca399be7, 0x9696d71855e2d4ed,
        0x00000000000001b0,
    ],
    [
        0x895829067683adbf, 0x94edb92f76b688d2, 0x932d602b547ce17a, 0x67fd6098879b1cf1,
        0x7a3037819f1a0bec, 0x2677e91db1d144cd, 0xebf7a83c7aa3bf24, 0xbbaa1f099e78869a,
        0x000000000000010a,
    ],
    [
        0x9498a7cd000903a9, 0x3463f5d90b37564f, 0xe6ed9e879be328e1, 0xb8d5b2802eadae85,
        0x35584a1bbcdb40a9, 0x15862a4232708841, 0x4d6ac21f3149fc7b, 0x1ec9b50cd8d3847d,
        0x00000000000001e8,
    ],
    [
        0xd3065d2f1d90e1d6, 0x11ca41599f10673b, 0xebb760f478d825e7, 0x9276080b904982a6,
        0xecea7f3276f06497, 0x605f079349209f88, 0xb4290cbbb54ff69a, 0xf95dc8657275fe9d,
        0x0000000000000012,
    ],
    [
        0x0b9bf46a2c8884b4, 0x4b963fbfb0b88b1d, 0x0c10f2ceebb72bb4, 0x5dd9775543d575c2,
        0xb072c39d9da8bf83, 0x749ee467877e5b7e, 0x1409b01bf72e151b, 0xdc95654090d77b97,
        0x0000000000000015,
    ],
    [
        0x8eb9c45edd5c087b, 0x0600aabed3a89e18, 0x849c36096e3aeba5, 0x97bc2b68badb600c,
        0x24e5b174adeb9b3c, 0x52dd878f21c480ce, 0x39d9531942d3f579, 0xcc10f3ca041a2456,
        0x0000000000000071,
    ],
    [
        0xfd6ddaddd40c7861, 0x040a3dfbc4abee6a, 0x0f6a7a9de3b4cf8c, 0x4fdf64f503cf3bb3,
        0x35437e8053d10cb1, 0x7dc73fdde42c2169, 0xc5611a0257510987, 0x3e8fcc9618eb2a74,
        0x0000000000000105,
    ],
    [
        0x7a196cd230a36ef2, 0xfa03a23006a096ea, 0xd69609e345b53586, 0x10aa85895c5a084c,
        0x00fb114a7dbae155, 0x619f44311a16a0b6, 0x385ea7907a1a7b2e, 0x85e54fe81461ae21,
        0x0000000000000035,
    ],
    [
        0x33ad7f7fd9c4248f, 0xa9493190c62a5532, 0x4a3f82056a929f73, 0x3482530d0d3bd86a,
        0xb62e7eb390dff3ea, 0xb13d0dd2caf9d989, 0x68073ee6c4d4f8f7, 0xe88fccd4fdbd992b,
        0x0000000000000074,
    ],
    [
        0xcf4aa03c5381fa2e, 0xfd82c38cfaffe51a, 0xc9fd5fddd64ffec3, 0xb8cf8c44bc83d0b8,
        0xe22f2ef3cb6efd45, 0x15a48db3660903f4, 0xdb0b0ca0aff1ba7f, 0x7ecbec147e7e43b4,
        0x0000000000000018,
    ],
    [
        0xb8eff8cd4a17604b, 0x56f22ee9c3fe5e24, 0xa834ff603afa032b, 0x03f78d54b7f553a8,
        0xec097a3aed58c6a0, 0x79af485fef422cbf, 0x07996d2a399c872c, 0x3df9c6c0ac6485b3,
        0x0000000000000115,
    ],
    [
        0xe9d15ad2a03dba15, 0xaf657b5bf664a2ac, 0x13f78f82f0071283, 0x05d3dbdcec1896bc,
        0x595e8c353aa22380, 0x1a9e093286414006, 0x6d81ac89b205d796, 0x47e184197a053817,
        0x0000000000000153,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p521::P521FieldElement;
    use crate::p521_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::p521_point::P521JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = P521JacobianPoint::from_affine(
            P521FieldElement::from_limbs(G_X_LIMBS),
            P521FieldElement::from_limbs(G_Y_LIMBS),
        );
        let two_g = g.double();
        let mut cur = g;
        for i in 0..32 {
            let (x, y) = cur.to_affine().expect("an odd multiple of G below n is never infinity");
            assert_eq!(x.to_limbs(), G_ODD_MULTIPLES_X[i], "entry {i}: x of {}G", 2 * i + 1);
            assert_eq!(y.to_limbs(), G_ODD_MULTIPLES_Y[i], "entry {i}: y of {}G", 2 * i + 1);
            cur = cur.add_vartime(&two_g);
        }
    }
}
