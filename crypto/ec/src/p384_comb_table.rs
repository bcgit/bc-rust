//! The checked-in fixed-base comb table for `[k]G` (P-384's base point `G`), width 6, same choice
//! as [`crate::p256_comb_table`] (bc-java's `FixedPointUtil` width for fields over 250 bits). See
//! [`crate::p384_comb`] for the multiplier that uses this table.
//!
//! `COMB_TABLE_X[i]`/`COMB_TABLE_Y[i]` are the affine `(x, y)` coordinates of the `i`-th table
//! entry, as little-endian `u64` limbs; entry `0` is the point at infinity (`x = y = 0`).
//!
//! Regenerated and compared against these checked-in values by this module's own `tests`
//! submodule below -- see [`crate::p256_comb_table`]'s docs for why this is a unit test, not an
//! integration test.

pub(crate) const COMB_TABLE_X: [[u64; 6]; 64] = [
    [0, 0, 0, 0, 0, 0],
    [
        0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98,
        0x8eb1c71ef320ad74, 0xaa87ca22be8b0537,
    ],
    [
        0x06ba5918d74d9642, 0x92dd9cdedfa0f56d, 0x74c1ac3d8cbae3ef, 0x2fce93bf5f6f39bf,
        0xff348797e2cfe67c, 0x079dc566510cc718,
    ],
    [
        0x371fdb782c009246, 0xbcb6f706b7ebf317, 0xe753edd8cf2cbc3d, 0x852cc3aba37b7552,
        0xac8476f641789de5, 0xbda8cbb352e85654,
    ],
    [
        0x84a2ae350020362e, 0xea2b1df419bf5f49, 0x2bb64e18287c9b53, 0x11c2df652b7b03e9,
        0x23a42ea485d5a524, 0xe10cb36d11cd506e,
    ],
    [
        0x981ffb59ae569de6, 0x586ea8878091accf, 0x67fc329408a70830, 0x7e6ee5f4849e299f,
        0xc79cf82450b92155, 0xde3e77fbc2010434,
    ],
    [
        0xf6da53e1780e56f3, 0xfd5f2fb0af4d2766, 0x52922de8e383bf0d, 0x1c92aba058ee4ddc,
        0x3b2384c0238e7643, 0x2d350fa20d6ac898,
    ],
    [
        0x16273979b29adc60, 0xa30c604d3be4714f, 0x5a2a19fa4019bd55, 0xef8d50a1431ef84d,
        0x581b7cfa417c18a3, 0xadd3b7e9c4245900,
    ],
    [
        0xa628b09aaa03bd53, 0xba065458a4f52d78, 0xdb2987894d10ddea, 0xb42a31af8a3e297d,
        0x40f7f9e706421279, 0xc19e0b4c800119c4,
    ],
    [
        0x30991560aa133909, 0x9097dbb1c6cb0017, 0xd37de424b860fae6, 0x9bb183b270b375dd,
        0x567a6233cd6ce3a3, 0xaab8bb9f0fdc3088,
    ],
    [
        0xf5b4350f4ab018d9, 0x03d42bfa4f890f56, 0xa59802ab472abcbe, 0xc49dc552ab00b039,
        0x5bdbfa1b4905edeb, 0x8b714479aadaf829,
    ],
    [
        0x50e97c63b6d82f46, 0xde6337d914b98cd9, 0x387bcead46b80210, 0x2333e9a7662d4782,
        0x4fb348a89493f992, 0x1a2f720851ac4ae9,
    ],
    [
        0x50938b9b09331ee2, 0xb5ea6c1801c84dea, 0xbe617a0fd5a6bd1f, 0x78bb665f8f79292b,
        0xb942f76558e00408, 0xf8b838b2866f2b6e,
    ],
    [
        0x4a286f3303034968, 0xfb4df38c05a7db5d, 0x3b640deca8b1928e, 0x5d1b884bd0fdfc4e,
        0xf57371ce69519c83, 0x5f63461a23145ab8,
    ],
    [
        0x06f6cff74fee705e, 0x315fc16f4b772c5b, 0x4b2fdf3568592ff1, 0x0ad35e83e9bcbebb,
        0x1bbcc1e0690b01a1, 0x69f7b65f0774ea13,
    ],
    [
        0x0b68515ff756ac51, 0x03ac4e13bc1de0c6, 0xcbba88d2e6c5f5b7, 0xeefa675823280efa,
        0xe415dfc4d84b809e, 0x03c2592ce6580ef1,
    ],
    [
        0x31efc1321a9bb0aa, 0xda74bdf2bb0f6ca7, 0x1af000f8cd3d0497, 0x39acb8f22aaa3451,
        0x23eaf4cdedfb898d, 0xe7b3f42dcad3d109,
    ],
    [
        0xf2977c54d2529ad2, 0xc55087d9ed6e33e0, 0xb8831540167e355a, 0xfeea9103aba42b33,
        0x90d05905ef3947c1, 0xaf085311760d24bf,
    ],
    [
        0x1d12ee6d45f5b090, 0x4b71091f485b3a1f, 0x86d41f81f5b0b2a7, 0x0b230b2a2613a770,
        0x57d0106cd7c428db, 0xf277b4bc9df04a3c,
    ],
    [
        0x56c0cb845615db79, 0x9ed4f5c9080edb56, 0x07d5137c1ad062e6, 0xc0a02132e053ad7d,
        0xbbd20e23218138c5, 0x71a9821ed005511c,
    ],
    [
        0xcd8127fdabe86f94, 0x1d082a02c4aa703d, 0xe4c033a6856805e7, 0x7f9803ea4cffcbdf,
        0x08f01be4456f325c, 0x14e4e4d056899a2c,
    ],
    [
        0x63b6db017dfa617b, 0x2382c6f43958c611, 0xd8aacd08807a5a47, 0xf468a53c3fc68cda,
        0x8ad836ae17d5f5bb, 0x91da6c57c592adc7,
    ],
    [
        0xbb31f60387667e11, 0xfd4f93f57e745458, 0xbf08a73c309a7d39, 0xe7e2eef323ad2f18,
        0x0cad330540360944, 0xa2b3aca748664803,
    ],
    [
        0x5cbc04229d6b0c98, 0xde8a0e6a2f796386, 0x747f91b8023f6729, 0x506bf433a06414fc,
        0x453f88b88771441c, 0x155344c505852b1b,
    ],
    [
        0xad7f8aec9e3303a4, 0xadcbca0ffb283ba5, 0x7ba9925103fd29c7, 0x2e31cf2a735503ef,
        0x60d66a8a5dad58fc, 0x9c05081572f7fc70,
    ],
    [
        0x698fe08d110ec812, 0xb1bcb75f6c797f59, 0x96eebb123c83e188, 0x17b971411bc4c22a,
        0xf28850891dbbeeb0, 0x3f92deeb74551cfc,
    ],
    [
        0xb5406aebffdcdece, 0x505d7d431ac67153, 0xd4cd49910433839b, 0x3d981f0054540a3f,
        0x055f14e6036e1cf2, 0xfc45acb0c33a23e5,
    ],
    [
        0xfaff6b3f0aacbdbe, 0x711d70d91474e4e0, 0x2b9618d8bb71b0f2, 0x01eeb5809019b8da,
        0x6f034817a6202191, 0xf13420946dbb1de3,
    ],
    [
        0xd165cd219c8e4278, 0xd464f8babe3074cf, 0xe880163d596c7e37, 0xff21cf573b71cdbf,
        0x104c1028abb38eac, 0x86d1bdcf092ee0c5,
    ],
    [
        0x6d0c4d55c2ce683e, 0x47aed6903293209b, 0xae73eb9e43ab78dd, 0xbff13ca683c397ed,
        0x4bfa26086625250f, 0xac3bec825d44fb41,
    ],
    [
        0x9857f321b002667c, 0x9fc753065f935341, 0xff0b96fa7469adf5, 0xb409ff5bfaab0698,
        0x39e820326d15c913, 0x86dc3fa0eb2cfb46,
    ],
    [
        0x2c06d1a84f70bddb, 0x50fa35fc682e4e19, 0xebc25ff2ed755360, 0x9322e2059f6b8739,
        0x7c6d9e03b7a81a4f, 0x3a9e39a88869d0cb,
    ],
    [
        0x110162f2968b4a5f, 0x1323feffba0f8b3d, 0x89acc4c0b1666eaa, 0x85dfb3833007a482,
        0x5f5449e75c7a9ba1, 0x38174a006bfcf21e,
    ],
    [
        0x94971913df13f515, 0xfe21826633b3f908, 0x0e7643231639fcf5, 0x2f1c9564a1254809,
        0x28a0ded95715ac43, 0xcc2491483db85f16,
    ],
    [
        0x3741a3d0daf70cc5, 0x4f89c2561949dca9, 0x84d76e8e4209b8bb, 0x89d03a2861aa033d,
        0x2bb8225a62eb53a5, 0xf16caec4dd131005,
    ],
    [
        0x564f510b12cd19bd, 0x055916a4243d4b30, 0x017c752e59d3ebac, 0x4c292ed9a5b4b98c,
        0xee06b30275051686, 0x234ff191799f7cab,
    ],
    [
        0x0a289321ae3c5c76, 0xd35fbdc6a1a23a44, 0x72bd5e9127340d10, 0x38df4f70fca6aa42,
        0xd9f2612f50546b32, 0xc38197025c98fdf6,
    ],
    [
        0x1e9910c1370fe603, 0xfea601805d9dad61, 0xeb38209d2a100fb0, 0x32a7a05acecb606c,
        0x2d74e5bfdf14cfba, 0xc65d0259dd1a12b5,
    ],
    [
        0x217affc5535b9874, 0xd0f3da4ad7396b2b, 0xc2f3120a5189f1d9, 0x640d40a513be9d9d,
        0xc65aeec07ea25c0b, 0x148ac3c9ac1b42f6,
    ],
    [
        0x54372e4324c2bb10, 0x3ff377fc35cef78a, 0x6b9d764ad5963475, 0x220b12a8ea0f3bb8,
        0xfb9ed41c2d5d3f66, 0xdcafab6ec7dd2e7d,
    ],
    [
        0x69fe6de0f2185961, 0xac246678cab2f970, 0xeaa8fdc7d1fa56cb, 0xf46115f695e4ca40,
        0x408b8231884b0b69, 0x740a16f9861cc448,
    ],
    [
        0x605ae87e66b45964, 0xdac9d9adb27e5ca5, 0x2e078313a3499782, 0x6bb00d3513c7265a,
        0x2c18934bfaab601e, 0xae61e44c311c2d54,
    ],
    [
        0xa7336b4c292db8d6, 0x0d03e76ffb3f71a7, 0xcff0e362b272dedf, 0xba4575e346e3fe2c,
        0xb38acd7ae7055f43, 0x8510fd43612db2a9,
    ],
    [
        0xb69e1a4130295b6d, 0x42cba75b3183ca76, 0x8931644d44504121, 0x183ca5975dc284cf,
        0x2c475a8efda50ff0, 0xba0bb1402d02587c,
    ],
    [
        0x9cb262051d808bf2, 0x82dfbf8d7fa50c45, 0xf7615a8bfe6665b4, 0xfd616cc2b0ceb476,
        0xd1bbf01d0b9af731, 0x2d429b8f322c4cc3,
    ],
    [
        0x3c8aef7b50558a7e, 0xb691632348231bfe, 0x9ac79b243c54040d, 0x499ffffb84c33825,
        0xcb5c8a686de02a66, 0x63af0da1855393c4,
    ],
    [
        0x94dc664cef74f723, 0x7bc91861cbbaff21, 0x2690c7841ae6dfc8, 0x4df56fbcdf65ae68,
        0xdcb40a65a3730712, 0x2827bf67b51d6a88,
    ],
    [
        0x1cb12191b59f7464, 0xc1af45ef11e1ed1e, 0x1f6572bcb2be31e0, 0xb5421ece778c4bb1,
        0x559986d9b9aac9ff, 0x6d0b354ec6802365,
    ],
    [
        0x2fdcb3139de8a87c, 0x5b9307385a427d95, 0xa2b8e9aa5b8cd3f8, 0xeb1c24abc983dfc7,
        0xfb9fd3ce88113586, 0x66c8e65285121157,
    ],
    [
        0x495175cd522a423f, 0xefc6442b04e53690, 0x30b583071316ee5c, 0xc6d30519a2c65976,
        0xd6eab70916a88bb6, 0xefd0fdb5af14ee70,
    ],
    [
        0xe5b1a0d57852a8b0, 0xd2e22ec0d0ff8140, 0x0da6b7a875476490, 0x53120134da4a513c,
        0x78fbb953aff54c16, 0x3bd530a3e2a40faa,
    ],
    [
        0xc0e60ab1664aa28d, 0xceb2995e9d940c86, 0x5530b3b2ca4003ad, 0x42e21e3427487874,
        0x82e36dc1ac5b72ae, 0x0b4b5eeacb46ab57,
    ],
    [
        0x253e8c05193f489a, 0x24bdf941188e2307, 0xa6ccfb9bd2a64c9b, 0x26e0868d1a71a7e6,
        0x89a2a4fd1d99dfe4, 0xa012e8cb12095cf4,
    ],
    [
        0x657e15732740d819, 0xd4c8400f7e53bbf6, 0x045e5aef731937ea, 0x5c97ac7e492b739c,
        0x21d2e70e1ec3b215, 0x3ed621acddd6088a,
    ],
    [
        0xfaf24e1d21228ab2, 0x78debe84e1452df2, 0xbef7d9249e7f135a, 0x149f1f4ae7f8d0e0,
        0x128b813d2762544e, 0xebda14bf9c390a58,
    ],
    [
        0x9369aae4484ce8d6, 0x7b1a9637fc277a27, 0x5c4613cfa530e76f, 0x84564d2374afd88c,
        0xf083971b14443d32, 0xf73898fd5fd747fa,
    ],
    [
        0x81a55fa1241f665b, 0xa0ea609264634b7e, 0xd0c389c4eb475504, 0x2cd1c98f8d1e0203,
        0xf359afab84a47688, 0x59bcd3467a41c64c,
    ],
    [
        0xacd8e2510d46066d, 0xa6cda0796f1d5714, 0x419ef5adca36fbdf, 0xdc48951d9e1d7a6f,
        0xc6c22c15b7a52681, 0xb6c9dc11aa724286,
    ],
    [
        0x7765ebe9b0e01600, 0x1492ac1925c62afc, 0xf914062a16db2db3, 0x2c552735f9417106,
        0x675b4089945f1dca, 0x1cb8dfe59590219d,
    ],
    [
        0xc12065e71ca916b6, 0x2cbda6c0f8325358, 0x6f26cc3157e6f0b7, 0xbc17d3341c54e327,
        0x9f1ee7cdfbedaef5, 0xb61f0040341c165a,
    ],
    [
        0x34c95b844bfb949b, 0x4a1156c02f8bac59, 0xbfb266eb95f2a511, 0x333c1450528f0a1d,
        0xc23dc688361d12b2, 0x6575994a3bc7fa44,
    ],
    [
        0xef16edc565994991, 0x2b6f4ea7f39a4279, 0x55074ed7c07e0a7b, 0x3415b9a669317ad6,
        0x0cf8b93fa472e0a8, 0x1237dea28532752b,
    ],
    [
        0xedfa66b6ebc7a05a, 0xe12f0b82d005432c, 0xefbc796e9051e2a6, 0xc6658e671a964862,
        0xc2b421592d6041d1, 0xc0f39509557cca45,
    ],
    [
        0x03995fe72c3fc486, 0xff565aadb6b72bf0, 0xbfbae8c848a40004, 0x9c99cd5a13b5a1e8,
        0xfee77ee2fcad95b0, 0x0b63539934d16b96,
    ],
];
pub(crate) const COMB_TABLE_Y: [[u64; 6]; 64] = [
    [0, 0, 0, 0, 0, 0],
    [
        0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
        0x5d9e98bf9292dc29, 0x3617de4a96262c6f,
    ],
    [
        0xa0ecd5d0c16bb523, 0x29f49d50cc51c42f, 0x36275538892459a9, 0x626377708484b5f1,
        0x89a8437e5c806f88, 0xa64da09a5d9087bc,
    ],
    [
        0xda1b89b6a4aef26d, 0x4c50f67c1cce0f01, 0x7ad4c74de690eb4c, 0x946099018a2d49d1,
        0xd907b06a9b9b805f, 0x23bc95be59eea2c2,
    ],
    [
        0xe5f50bfe2adaefc2, 0x64666b5536adb53e, 0x7768fb7fe90ed2a4, 0x425d781706cc84c0,
        0x52ec806a31d6ab0b, 0xd7e679724697d363,
    ],
    [
        0xa6ec9dc7e3ee3800, 0x8e5e92fa43cf88b6, 0x757e493bf843cae9, 0xe1c2864517ebe71c,
        0x00d19ce032576992, 0xe30df4b84db810d9,
    ],
    [
        0x2929929efb35aa8b, 0xa8743694a6e54797, 0x67f4174cc525c526, 0x8cf8b3c9e0e2f34d,
        0x80ccbce70b8f32ee, 0xf15779e6689de2fa,
    ],
    [
        0xb76f4554633d01bb, 0x34421d86a319b27b, 0x711a529218870284, 0xfe371b185db1186c,
        0x3040af18ba6174f4, 0x6fb0070f523c7dda,
    ],
    [
        0x822d0fc5e6c88c41, 0xaf68aa6de639d858, 0xc1c7cad135f6ebf2, 0x577a30eae3567af9,
        0xe5a0191d1f5b77f6, 0x16f3fdbf0356b301,
    ],
    [
        0x16c5b981600ad5a6, 0xebdf73f2d62faa44, 0x6d955bb3c9747bf3, 0xf6005fc815eb04ac,
        0xf0af01d1282050b5, 0x48942f81314f6d28,
    ],
    [
        0xb69f612110903577, 0xffcf3103caa17043, 0x194befcc12b7d6f0, 0xc2315ca244fa539f,
        0x330a336c27d7aa39, 0xd67b41415e7e1a8e,
    ],
    [
        0x9778e181f9a0adda, 0x171a79bad8639a3a, 0x2d7d5d5a7a7b3134, 0xb7e009194b129683,
        0xec7e6e4eee578a55, 0x08d8dab3dc699d11,
    ],
    [
        0x2a518d483780eda2, 0x2a58627f5f9fcb09, 0x48f510fa8eb96eb4, 0x97dded6d15802f8f,
        0xe75cd28daaaba84b, 0xacd28afa7ede1244,
    ],
    [
        0xedefcd1844704cbc, 0x924d7e7e64dd49c2, 0x2cd63fd0097c32a2, 0x3e547a0c654fe06d,
        0x8c5a79b44afbfa16, 0x749abcda2b1b5d04,
    ],
    [
        0xeaa68fc868fbc242, 0x749fa4694c78bcf9, 0xcf3af279cbbdfc33, 0x50f52cde020525cc,
        0xcebe195964cbedc0, 0x1d8d9c443df78387,
    ],
    [
        0x0b222b169927269b, 0x38fc9b2ac38ff3ba, 0x1b3c9efe3d832efc, 0xb53849c12dcd5708,
        0x01ea1f89338b4295, 0xeb3ebb50d7131daa,
    ],
    [
        0x98ca61b55e695394, 0x6f5911020e70a633, 0x80a93ec7216b71d5, 0xbbb25c8fc463e3b8,
        0xb18e3fba8615e7a5, 0x5a5d5c5ffc212920,
    ],
    [
        0xe5b14850bddd2f1f, 0xf6eb147855841c80, 0x04c7f6afa63e5ed9, 0x3b9541ca65e211e7,
        0x2d06224de6d883ae, 0x974628aa2a257ffa,
    ],
    [
        0xfc506e660a32a7e5, 0x846ce285d317047c, 0xceb4d115cc394c36, 0xef860bec97182db4,
        0x772d38d72f49ed16, 0x0cc65d7427e042ea,
    ],
    [
        0xb9b7aac6bf27c3a7, 0x461746b9df4565cb, 0x1cca5db1b23f38f5, 0xb848d7e9636c2988,
        0x9905c28c99d7f1bc, 0xd57ee56d825ee66d,
    ],
    [
        0xc220c4e368450d6a, 0x7100595d348c7c8a, 0x42734e23260eb12a, 0x6d1b51f85c2db9e8,
        0x983e3bafda5a3ab7, 0x997c7daa8e12b7e4,
    ],
    [
        0x848c7840c01767e8, 0xb27e5cdaaaf49f7e, 0x67a064723e42db96, 0xa8e8e3431741f927,
        0x0305167e43ccdd66, 0xe590418f48cf4b36,
    ],
    [
        0x87675ce3ba1fce75, 0xbb409ff64d64d1cd, 0x0f13e3e4de117c49, 0x31d85ebc7414266b,
        0x8ca52dd3271ab0fe, 0xc22174f5964295df,
    ],
    [
        0x2ee3731cd1fe2b3e, 0xd29d1c69d3a13366, 0x04941baeb6ba5ae0, 0x453ab0575c9074af,
        0x8d1d542420932fdd, 0x98495d67719d78fa,
    ],
    [
        0x35f5c4f6c76bfe85, 0xbb04ba184cafb0e7, 0x8d19a621828c22d7, 0x50e7bd15fdef9916,
        0x2185491f8b0c751c, 0x1cf397cddb05f5aa,
    ],
    [
        0xb2b3d0190692389c, 0x81c1e25fa326992a, 0x8f2426b6c3fdfc75, 0x964b64b749e7adaf,
        0x30b6fe07ad954e6c, 0x1008a9192de7154f,
    ],
    [
        0x04b8d16b1d129997, 0x086062f1bb8b42c8, 0xaebcf8a040aeccee, 0x139ccdbfb96d5265,
        0xba4828740134a1d2, 0xce949a4c5f0e60e7,
    ],
    [
        0xe2be4e8e4b678259, 0x2d2b5523f877dabe, 0x51742d3525de025c, 0x04adba390bb80cd0,
        0x1be43de14d280ea6, 0xb08dc4b8d40aec5d,
    ],
    [
        0x48f6c554cd619224, 0xcbdda09fc9b564e6, 0xd016002040245ee6, 0x058df586386aae10,
        0x8052fb318fcf7688, 0xf957daebea5b86c3,
    ],
    [
        0x69d09904b5ea9058, 0x8745fdeba022f24a, 0x5beefafc3281a45d, 0x1d5c41776aa4bb27,
        0x50b310f04faa1ea1, 0xe6d7909e14137409,
    ],
    [
        0x69bee69d3e1e3fd2, 0x2cdbf99d66c61037, 0x223fa09fc1b13717, 0x1d4e2d2073840224,
        0xf8d1807f18b74223, 0x107a3bd91190c01c,
    ],
    [
        0x150824ecfe68eff8, 0x7434b70d924b06a1, 0x45e44aa01addf43e, 0xd3d6bbce4f4f63c3,
        0xacb7733fdf8deecd, 0x53d9814d80b606df,
    ],
    [
        0x9f7dc2544f0474fc, 0x13f390d740cb718b, 0xe6091c183a45ad17, 0x9b795d801605976d,
        0xe0bcd7af2055ee90, 0xd637fbf692ee7c2e,
    ],
    [
        0xc4bd32d154c8f22d, 0x20f4d89daaf03b8a, 0x2d25ac666cbbc34f, 0x1dde41e1b210256f,
        0x982abc37b830e83c, 0x859f781e4a0157ba,
    ],
    [
        0xfb3da605b3f85850, 0xa894e8519705c612, 0xd3c477f5b6e52255, 0x275b8dc4609de217,
        0x836e288617ccd6d8, 0xbefeb4747626b688,
    ],
    [
        0x7730ffe1847c9865, 0xcdbd40555fc2e271, 0x5724c2c43f876569, 0x4824d115600a300e,
        0x1dafb1aeb6d99957, 0xf3b9740fa2ee809b,
    ],
    [
        0x6a2544df7476a566, 0x5df6ecff9a396e7f, 0x4522f408ead8f18c, 0xcbf8cda23a8c0e3e,
        0x3be9abf251c4a7d1, 0x634cd141ad0790ea,
    ],
    [
        0x7b4d13b6f5f8c9c8, 0xdc79a2b393b145ed, 0xcc9c29e6f7cff674, 0x590a59bc80655087,
        0x0cf046a23524f00e, 0x676256619dc026bd,
    ],
    [
        0x949c94d47c4c23e0, 0x4c25d7a675b629e8, 0xbaa85bfcfa279b86, 0x3e066e812a18aafd,
        0x9f3ab93d51bbaead, 0x1665215e095c11e2,
    ],
    [
        0x598e839a0c7bb28c, 0xc319327992905130, 0x8fa52ccfd0f989ee, 0x819d4150de21507b,
        0xe3a8959d9e2b7de0, 0xaa5f97888720a5d8,
    ],
    [
        0x7c2024cde63b89dd, 0x4339955515b8bc28, 0x3a25efb9e993ccad, 0x0e01859a35dbb862,
        0x916982ea3521322c, 0xd25b20d619f5f297,
    ],
    [
        0xc5916e59511e4dde, 0x60cc36ed514d5438, 0xc5332778c756a818, 0xbc6ac88bc995b742,
        0xeef9e1b39613e95e, 0x050394c35eb046f5,
    ],
    [
        0x189c8dcd9bc4aad3, 0xdb5d782bcbfb868a, 0x5b915b8e37ef7c9a, 0x05698ebc702c0828,
        0x687beab162d4bf9f, 0x3f00c98a66f63c3e,
    ],
    [
        0x994323ce678c33da, 0x2a5b1f4472475384, 0x18638850a4d9c1ae, 0x31c400736975f27c,
        0x69d8001adf1d904b, 0xef6270a84889b105,
    ],
    [
        0x8b877cc0943b6ffb, 0x931b079026857e49, 0x61613d737db914fc, 0xe7c95092325e0b06,
        0x4236049c91c5a80c, 0x8a6c523ced476d14,
    ],
    [
        0x5106d00b4c95881b, 0xe0b4c8a2498daf92, 0xca87438809537675, 0x0ab4215e3f77a490,
        0x77c191cc64869e35, 0xb15b7dc3cb5617c1,
    ],
    [
        0xd7acb37483dfac3c, 0x45b47c9cc9c0488c, 0x5c9bac550913903c, 0xba001680669f2bc7,
        0xed4e6d4e187805ae, 0xca2e18bd98eabbc9,
    ],
    [
        0x231d32390aa2d847, 0x054a9a12f186c861, 0x01bc8e70aa7cf18d, 0xc8a58bdd8f470162,
        0x96f5c7abf42108db, 0x1d880fc495a5760a,
    ],
    [
        0xd83be65684a0210f, 0x590340619535d285, 0x18caf84784061f0e, 0xbab7a9a860314751,
        0x93a603c9e22cd7be, 0x1eea699752b5e890,
    ],
    [
        0x75666e3e71ca7c18, 0x7fc491e53f0e31be, 0x2b5837953ec23d8e, 0x66eeeff303021f01,
        0x24e8cd38fc1a5b28, 0x716821c685425712,
    ],
    [
        0xa46d2742087f83d8, 0xc47f329c7ce1bc46, 0x68c4944fca917d28, 0xe0d8b028ee1c8c08,
        0xed86abe020dbf9be, 0xd8b9040a7aae428a,
    ],
    [
        0x522a9f514ead08fc, 0x02ddcfd64c7d5c68, 0x7cd9108be02676d8, 0x1742d25f4e23a730,
        0x28342177eca4e5d1, 0x2fc3854aea65145c,
    ],
    [
        0x425a5c1b1bd5ee20, 0x429411f5212c5b5b, 0x100fb60f7d1a996e, 0xd429d128ed4e5b27,
        0x1261f141cda181a2, 0x763abfc494c8b1bb,
    ],
    [
        0x3f38f26d6dbe26a9, 0x893a5049a7316c08, 0x5a30c2d2f5c699c3, 0xb2e9978b8bf6e42a,
        0x0b5415fc0db721dd, 0xf29d6bcda41c8365,
    ],
    [
        0xf4c4561f2d14fe1b, 0xae8cfc1cb3f24f5e, 0x68e81b1e9b76389a, 0x8f9ddd405e63e131,
        0x3fdf4533734115cd, 0xf2b4af6d2d23cafe,
    ],
    [
        0x15c17bfd366473a3, 0x2d899447d2325dea, 0x0465c806ac30e951, 0x534961f71bb96cfa,
        0xb1a6da804332ffd7, 0x21ce35950104f8ac,
    ],
    [
        0x3aa100e8e64bc28e, 0x6e9eea3fd156e143, 0x9c5a311dc8c5471f, 0xf0e607ebe8940bf8,
        0x4cdd06d1c47a8f0b, 0x5106caa8cd527795,
    ],
    [
        0xd4ab3c62a7646c3f, 0x80a8c060d8446a48, 0x46893c5712587682, 0x2cd0b8cbce834f82,
        0xdffaebadb004849a, 0x3e654e4441c3a434,
    ],
    [
        0xcef9bdca41fab175, 0x349aa2d4e236b88d, 0x07aaeab6466b69d0, 0xb899491cc27dd5d2,
        0x81f425475099c372, 0x5d60f35e510ef1a2,
    ],
    [
        0x091a3bd4c200326a, 0x44164a0c8f99e034, 0x622994d41b187383, 0x6732749db12da429,
        0x668b62370cb1f4bf, 0x42b6a335e2daffc9,
    ],
    [
        0xc45d8db0c2cce9ed, 0x14d197feded49c21, 0x56c11eb8b2c46c12, 0x6b7f93718add12fc,
        0xc3c27c163b5bd8e4, 0xad81ee0340d43df2,
    ],
    [
        0xf4a44125cf0dc0bc, 0x4b8385c348b2fc9b, 0x629a7a2d580bbe2b, 0x2c4f741b1881f3c5,
        0x1ea38b160aa343e2, 0x7735a28d7b81184a,
    ],
    [
        0x42486f739509f4ce, 0xfa10ba0dd60fb23c, 0xf55a55a922d97e5c, 0x8ef47b078d750955,
        0x1e61b4103f540aa1, 0xfa6f0eb0c56b7257,
    ],
    [
        0x2801ab2b5d778a19, 0x604d8349d5d0854e, 0x7aaf003b3091c681, 0xc9e2b6e10761ae3a,
        0xa5f0b69bfe414395, 0x419e8889adae97b4,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p384::P384FieldElement;
    use crate::p384_point::P384JacobianPoint;

    const G_X: [u64; 6] = [
        0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98,
        0x8eb1c71ef320ad74, 0xaa87ca22be8b0537,
    ];
    const G_Y: [u64; 6] = [
        0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
        0x5d9e98bf9292dc29, 0x3617de4a96262c6f,
    ];

    const WIDTH: usize = 6;
    const BITS: usize = 384;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic. See [`crate::p256_comb_table`]'s identical test for the construction.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = P384JacobianPoint::from_affine(
            P384FieldElement::from_limbs(G_X),
            P384FieldElement::from_limbs(G_Y),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [P384JacobianPoint::INFINITY; TABLE_SIZE];
        for bit in (0..WIDTH).rev() {
            let step = 1usize << bit;
            let pw = pow2[bit];
            let mut i = step;
            while i < TABLE_SIZE {
                table[i] = table[i - step].add(&pw);
                i += 2 * step;
            }
        }

        for (idx, point) in table.iter().enumerate() {
            if idx == 0 {
                assert!(point.is_infinity().to_bool(), "table[0] must be infinity");
                assert_eq!(COMB_TABLE_X[0], [0, 0, 0, 0, 0, 0]);
                assert_eq!(COMB_TABLE_Y[0], [0, 0, 0, 0, 0, 0]);
            } else {
                let (x, y) = point
                    .to_affine()
                    .unwrap_or_else(|| panic!("regenerated table[{idx}] is unexpectedly infinity"));
                assert_eq!(x.to_limbs(), COMB_TABLE_X[idx], "table[{idx}].x mismatch");
                assert_eq!(y.to_limbs(), COMB_TABLE_Y[idx], "table[{idx}].y mismatch");
            }
        }
    }
}
