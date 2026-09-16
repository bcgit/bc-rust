//! The checked-in fixed-base comb table for `[k]G` (brainpoolP512r1's base point `G`), width 6,
//! matching this crate's other curves' choice for fields over 250 bits. See
//! [`crate::bp512r1_comb`] for the multiplier that uses this table and the algorithm it
//! implements.
//!
//! `COMB_TABLE_X[i]`/`COMB_TABLE_Y[i]` are the affine `(x, y)` coordinates of the `i`-th table
//! entry, as little-endian `u64` limbs; entry `0` is the point at infinity (`x = y = 0`, which is
//! not a valid affine coordinate pair for any point on the curve, so it's an unambiguous sentinel
//! here).
//!
//! Regenerated and compared against these checked-in values by this module's own `tests`
//! submodule below, using the same construction a (not checked in) scratch example used -- so a
//! hand-edit or transcription error in this file cannot survive `cargo test`. A unit test rather
//! than an integration test because the table is deliberately `pub(crate)`, not exposed outside
//! the crate: see [`crate::p256_comb_table`]'s docs for the same reasoning.

pub(crate) const COMB_TABLE_X: [[u64; 8]; 64] = [
    [
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ],
    [
        0x8b352209bcb9f822, 0x7c6d5047406a5e68, 0x50d1687b93b97d5f, 0xff3b1f78e2d0d48d,
        0xb43b62eef4d0098e, 0x85ed9f70b5d916c1, 0x5a21322e9c4c6a93, 0x81aee4bdd82ed964,
    ],
    [
        0x718a222379fedb80, 0x5e718bba486ed3a6, 0x51ea652c9a5ca86a, 0xb0ce40b08f8cee45,
        0x9b3214ef84f947c1, 0xea23653b16e4932e, 0x19c66049496a01c7, 0x7d81895c231c6afe,
    ],
    [
        0x43889d6f8c6be9ea, 0x37d156a796864fbb, 0xa60ef5a7eefaab9d, 0x3332d66d9eef40e3,
        0x698d1a571456ede3, 0x6b7571fa3a4deda4, 0xcdb5be141c76c566, 0x1c521d36e7cb5ae1,
    ],
    [
        0xbcec2d9b99071f60, 0x443156e201e36ec3, 0x3859994cf9827f70, 0x0c53c0526806c675,
        0xbcdbe046f48c633a, 0xbba3700941c13193, 0xa4a156e162583419, 0x2e0e5761ae2c15dc,
    ],
    [
        0x782da580cda93652, 0x9b0cff71ceab4491, 0x9332215a35582418, 0x8bae977af828a61b,
        0x0955c947fa08e784, 0xc452f5a4842eac8d, 0xbf71c8a79d0558d9, 0x6bec92c192b492b3,
    ],
    [
        0x46984b0f71b15e63, 0x8ccca95b3a73b2d6, 0x0c8f5165e95b51f7, 0xae8d451aa0fe1ad2,
        0x48ecffc90b042255, 0x19798ca8b25a0c42, 0x413a0198d613ff54, 0x55af1359c95d3e54,
    ],
    [
        0xfe57b0ce54d82b7e, 0x5d3c03039ef8b08a, 0xbf70f30029290e93, 0x4bfe5d000e993354,
        0xf403cf3259f22d46, 0x5bd1ef0cae72c93b, 0x51f9452fbf275ab6, 0x881e5bff2ce5bed4,
    ],
    [
        0x2e87e27be62c9807, 0xbea2d0e92e6aef48, 0xaa2f9c9efcced921, 0x76f5953ca0bd6986,
        0x290c525e01abd581, 0xeacf8ff3980407ff, 0x875e9e2f61bf83ee, 0x9c91c0e5e291fa52,
    ],
    [
        0x3c0eabc5875e0efe, 0xf12a4c24805ff9b9, 0x6a8d8492542115de, 0xf8b142dc74478aa8,
        0x5b0c9bc1fd30f781, 0xd5a9e3c5dfcc6c4e, 0x4054515c105967d6, 0x8e6378b06efb37a0,
    ],
    [
        0x3609651b25ea5449, 0x53bf195878385f46, 0x0a60e21349538c84, 0x29978d0a9934f8f7,
        0x42eb4d7b1971823c, 0x2a3254aefe35cbef, 0x649e416aab15b1b9, 0x2a831c9dfefb2a19,
    ],
    [
        0x906373ad12052537, 0xb194e757860799c7, 0x6aefa918bfa54b00, 0xaa0c2ff209c44cfa,
        0xb9916c89ea043a8c, 0x7b24eca3e73a6c7d, 0x40b9e3042126a116, 0xa2cd89c27b4b7153,
    ],
    [
        0x7dfeb414d0bb060b, 0x4c38733b567f1a26, 0x03be9eb11bdc403a, 0x48f662b97be4187b,
        0xa10467531c3cf0f3, 0x2497eab7b44fb5b0, 0x2ef91d7d196e5e17, 0x9d1d208eecdcb407,
    ],
    [
        0xa4c2930271b11838, 0x685ee71fe24089c9, 0xeb0cd40189ae8e50, 0x5fe4f2247058daae,
        0x4f666f4ad61dc76f, 0x3becca2c4a7e1d92, 0x4ed3e499a87f06a1, 0x4936585edf5a1d2a,
    ],
    [
        0x84a4eeca0826786c, 0xac66f1779ffa6a9c, 0x44b1c81942aa4628, 0xd13ebaeb371dfa1a,
        0x6883d07dd86181a9, 0xcdbf9436a85510e1, 0x8f4709c2a09e4dac, 0x26c793ab3b55e4e7,
    ],
    [
        0xd386796507ea92eb, 0xc90ac5d37513b7ff, 0x74f90c1fe1fa9e26, 0xdd09e9215ced8cb4,
        0x3936f6c418d84df4, 0xa0a469fa5cacc9c7, 0x5836717b1c948c6b, 0x5e9c1db7ce46bd7c,
    ],
    [
        0x3d41c00cb2286588, 0xf21f57ddac6ebd21, 0xc14e1b86f1234198, 0xfea78e61c10bc4e9,
        0x777246f83e3f310c, 0xed25fd8b6b38426b, 0x8d6d5fd9a71f5524, 0x68c1cc8a2814c34f,
    ],
    [
        0xc9eb7b8788f9de10, 0x17a63ddafadab866, 0x035532538262f0a0, 0x109c11194a32a52f,
        0x2d059075e927b316, 0x1b85017748901c63, 0x28c5d7a8849bd6c7, 0x99d74611b3cb7ae1,
    ],
    [
        0xce5aa2aecad2e950, 0x31ccd860960573c8, 0xebc0271dbfdf899b, 0xb5c93008199e12cc,
        0x15fee0975950ba3e, 0xf665d82d34b0cb09, 0xcdf9140aea81d510, 0x37a7e0ad7e0ee8af,
    ],
    [
        0x65770e983c9eddc0, 0x4a257487d301ab6c, 0xbd12874376e3a387, 0x5498eb66603bb154,
        0x69ca754ed7c878d2, 0xb53607e71971df07, 0xb247bf915fa8c96d, 0x01fab61896589680,
    ],
    [
        0x85c2a9808dc5252b, 0xbb9290cfbdb1a9e0, 0xfcae32af9515d1f1, 0x735d3dedad27d706,
        0x6ce9db35e8e38c28, 0xa4c1b306a9dd3ccb, 0x928bdf0183a33d8e, 0x004a26804882adc7,
    ],
    [
        0x836abd096300dab2, 0x17f7b705486ed40f, 0x7a27154a00d74d14, 0x2418342737aa153a,
        0x05ba881b842c203a, 0x728460a204d609ac, 0xdb47edd4089404c8, 0x42355bb93ee4f38b,
    ],
    [
        0xe30320d45b69c573, 0xc72bfde4694d9b51, 0x56e5ce703ac828e3, 0x353fd7a02d94eb02,
        0x7ee58a9364caf828, 0x04f190d21334b9aa, 0xdc1164585a9b0499, 0x9e569fe08c6ce19d,
    ],
    [
        0xc0b474b2d9b027ac, 0x9236649f6fb9a6ea, 0xa97b2b0540782b2e, 0xb8dbe24ab63a68b3,
        0xef45258b34d7331e, 0x7b0efb01c9a8ce89, 0xe4609f124c51f9e2, 0x4439843730bd8567,
    ],
    [
        0x61b7f5d803eaf5c7, 0x1dd21753775ae8e5, 0xc38e7be7759cd365, 0xb6d5cf08eb6b182c,
        0xf48e7802d2e7ff42, 0x9992dab9a0fe3d7a, 0xf42468b7d91d9f42, 0x4247ee54390d2eae,
    ],
    [
        0x1956f7009c9d0761, 0x5d660c15f987bafb, 0xf50d47b028c11f7e, 0x892b234bee27ca96,
        0xaac35d17c868b57e, 0x64ea9d20ee080217, 0xa0cf5f7dd45014a7, 0x8c14dcc6a7f8fad5,
    ],
    [
        0xc3f1bfd066a0ddfb, 0xdb1c92153d03510c, 0x3785bd5d386f45dc, 0x780a234131208e17,
        0xe34e7bfc6e83a7d4, 0x89c798bb8b3cacc8, 0xa83891e20529fda0, 0x1ace5d8552af7150,
    ],
    [
        0xd25363f3ccf0d620, 0x96ad0dbd46dc5a27, 0xea4a511560112f21, 0x0daa83d53893e333,
        0x0f1abbfdb1cca690, 0x591a796f54c8543b, 0x7f9d979228da4a3f, 0x3466c552c7db4bd6,
    ],
    [
        0x2c7df41b07afabe1, 0xf687fab088590cdd, 0x6948b0cbf23107cd, 0x7703266941c4f997,
        0x7dd440bcb14616da, 0xfaeac7bcf3c68d35, 0xc26a143495d8a405, 0x246864f8b05ce64f,
    ],
    [
        0xa82dd7f408b78bb2, 0x4908714502302bc7, 0x8c19c2f650ca3a97, 0x491d95733e9bb917,
        0xaad6d8cb485960b6, 0xf8a899ab896cb9f0, 0x99ec19064e8ba1ef, 0x02b394d5cf049570,
    ],
    [
        0x1ccf73ecc8e27725, 0x6c28c540c90df9dc, 0x54730b2f03deca09, 0x414f1cd8b0271bb9,
        0x499ccab0016fe2d1, 0xe18e2b3e13b8fa42, 0x51246cfc62a44940, 0x228cacbb0d3cff9f,
    ],
    [
        0xaae90ee9c141aaac, 0x490aede84b9ccf0a, 0xe49c0a460cca733d, 0x6d6344febc9ee199,
        0x5c8cc1f8ee714331, 0x1a71bd2569f04b6a, 0xeec1c1e782fe9afd, 0x8d356a975e6e5afc,
    ],
    [
        0xd69c8a26d4cb9b77, 0xa15e315da57d71cb, 0xaec28beabcf73fd0, 0x6bf8aee97cb00805,
        0xb0512bdd5e128f6a, 0xfd3c2764177486b8, 0xe1e6f4b4a1725623, 0x740234794c273cb9,
    ],
    [
        0xd089ed21de19c767, 0x2aa79debaea6be2f, 0x3bc357861e130e04, 0x52ecc15246304b1f,
        0x27263b963144d56e, 0x68e8397867a86877, 0x3db658f2ddb7788e, 0xa58c2cc426b33c81,
    ],
    [
        0x818e4f94e5319572, 0x854c80e808d3364d, 0x31dade37628a6fa5, 0x07cf4155b6d15cf6,
        0xfc9b9deb559c1cac, 0xca880dc040500b2d, 0xdf4558724143b846, 0x1ad76a1ca4a2469e,
    ],
    [
        0x814524b88018ce5c, 0xecf76406b80309f1, 0x2e12716d10b126f1, 0x80c36a1e6ec612ad,
        0x5c046bd8de0ad3e5, 0xc5c03cdbae5b8796, 0x7ebb899ac1f9f58e, 0x111332ae8b7269ed,
    ],
    [
        0x44fc4ad43ec1aeef, 0xcbee9c5b6185d14c, 0xe3790ecafa176363, 0x5686d266fcf3b4cd,
        0xba454b5baedd7bfe, 0xcaddb51a3f4a2e48, 0xbd3c3e60b7613e5a, 0x425e9e23793fec55,
    ],
    [
        0x355731efe8952213, 0x14477caffe53882d, 0xc48c9fe879ccce0e, 0x97738a6e77dd16db,
        0xa85ff83b219707c0, 0x9fe7f08481d2b5c6, 0xad530e6a09758fcb, 0x3f7dacc797704fe6,
    ],
    [
        0x776fb580d84dba86, 0x153a581dd9b0afd8, 0x364771703cceafed, 0x8cd5ea0c637a5e39,
        0x466bf14beb8d0e7b, 0x86a27b04e98253e3, 0x0e5cdde4f8b30b42, 0x4b546aea0716cacc,
    ],
    [
        0x691b037305fa6625, 0x4c027b961266a411, 0xa8d5d1986ddeb544, 0x058cf68eb844f5e2,
        0xdfe549bc722b1568, 0x808deb8fdfd7446c, 0x1d70e4b7aa886405, 0x5d65b99be9bb149c,
    ],
    [
        0x0e2a706f47b580a8, 0xf8acbec34bb52ecd, 0x90dcbf2a968035f6, 0x9493ca7edc43778a,
        0x8dff00be8b4dec5a, 0xe028d793dcc7c618, 0xc48511886a29e5d4, 0x5a9fc332e945ec0d,
    ],
    [
        0xd5c5039bfdab07ac, 0x73730cf21db0bec7, 0xe2fd34d3877be799, 0xdc538336c73d259a,
        0xb011125563cf7c22, 0x1618ac92274d34c0, 0x1613ff2e9d614298, 0x0abc0d576592def4,
    ],
    [
        0x99e5700d0d8d975e, 0x013ce65eea9ba2d9, 0xdcbc0bda9737d945, 0xd7b3e09377c62cbc,
        0x444bb01770512e6e, 0x7a4d19229e78ce29, 0x8f52c4f96ab0b3e6, 0x7e7af8bc0f9a5264,
    ],
    [
        0xd2b1c4c22b8b06f6, 0x12296a03c0a1f5fa, 0x6b9f1ab655efa9f5, 0xfdb54306be32549b,
        0x1bd4be8920d9d6f7, 0x7988b4ce109526e8, 0xc7bdba32ac27a6e6, 0x63a1be7b9caea6a3,
    ],
    [
        0xe4c88208671dbfa6, 0xd921d95f88286235, 0x2cdee0bc3298f5fa, 0x5a99ecca94c0758b,
        0xabb4abb5cb1333a5, 0xfa764ad90a664b5d, 0x4d6ce94227cdc197, 0x182b8f210e53156f,
    ],
    [
        0xa59cf2cb1e159780, 0xad13ad70f3bbd12b, 0x57d5da5ec5a496d8, 0x4547766665e98107,
        0xd234cf73068735c9, 0x425b79a24215815a, 0xaec66414097da208, 0x24e9d6f1edc46d5e,
    ],
    [
        0xf04deae2e232be5a, 0x1a3e7cda2aa4195f, 0x6e3d51644675c083, 0xbbb6a73ca97d51b8,
        0x58749685747c204a, 0x0b72d4b9dde231f7, 0xfd960d71bea42c50, 0x19fb4817f2025d18,
    ],
    [
        0xa40a88918a1730a4, 0x5ffc59aca4187d05, 0xdc9a3965258b31a4, 0x2f1359ba684b1615,
        0x5e8cc956c5d3fd8d, 0x01b4f7e6f49fc6bc, 0x7bd89f2600037c2d, 0x936e00b9006e1d24,
    ],
    [
        0x1e2f4226c5c5e9fe, 0xae52187f568eb96c, 0xb3c43aee36c355b2, 0xc90fa74de7b0565e,
        0xdedfd37dbd3468bb, 0xad78f2cbf0cd1ee7, 0x3c2c81f08027ff80, 0xa0c7610c7a72ccc9,
    ],
    [
        0x70c2e6587f4f2b37, 0xb8803c35a7d54337, 0xa6e67b00124b6d1a, 0x81aaca9bd0bd1537,
        0x537a608be39ccecf, 0x22438da7034bda0c, 0x6822f0322b00af57, 0x3e9943be9999d9dc,
    ],
    [
        0x243f8a5b3e0759c2, 0x56b6b9377982e13c, 0xaf52a311c9780125, 0x563b6505100a0dec,
        0xba0a1f76989dab7a, 0x9fe005ab7198e1cb, 0x550391105c126540, 0x51c29f959497a323,
    ],
    [
        0xdb46d4e5a3a66b68, 0x34247b7c84dc3e23, 0xca576c07867fed14, 0x5669791252fe0695,
        0x84c33a215f44d184, 0xac17ab75c04ad95e, 0xc36f6b80b69481ff, 0x3e1ebcaaa58ebe07,
    ],
    [
        0x282631602e935ab1, 0x400d33c3f2ddbf04, 0xa8dbe47cbf2c0a9c, 0x0d5cdac7bcc5fd0a,
        0x4070b733caedf941, 0x5ea4d9076941ba82, 0xcc97d8ab04173a8c, 0xa46734203bbda59d,
    ],
    [
        0x0f4d0fc9b5a2078c, 0x71eb46f1e6671de3, 0xdd10e0e7952341d7, 0xb65fc68c68fe69be,
        0x1ad84fd23d2bb9e3, 0x5791f6cf5ff509a3, 0xb6f3b56d6b421565, 0x9b13caffc59d56bf,
    ],
    [
        0x262bdfeebf961ec2, 0x326b66050c2f3bb5, 0xeba56b68c487478a, 0x5a1d702023a98544,
        0xd7755ce80c9c50c8, 0x3a14523af1ad4e81, 0xfc81a2bdf4d09934, 0x4d2809f0496057fb,
    ],
    [
        0x051173f00e22c110, 0x1266611856a4aeb2, 0xb05138840872fb79, 0xc3299931b9a886da,
        0x3a6fc7b342c3fb8a, 0x22b075be09e1f8d8, 0xab13fc99f4ff7d5a, 0x3dc6224281841be6,
    ],
    [
        0x937d121bc4771127, 0x84e718a117b56ffe, 0x633579ce1ef7a831, 0x78364b8592af35a4,
        0x2d27507cdd486422, 0x94bdf5c28fc78966, 0xf94ba30d953f3c59, 0xa4ca848e6be00a71,
    ],
    [
        0x4272728069454710, 0x398048db59991170, 0xbff41537fc3d6e75, 0x20288d35a65bbb17,
        0x2daad38f2c3b1aab, 0x417bd902f81a1c55, 0xa1143154f8ac69af, 0x7ac4b958dee68a41,
    ],
    [
        0x0df5c962d5ec5e6c, 0x94d5074f5f691b0c, 0xd5021e6b92598ba4, 0xe9df5f80af387fc8,
        0x0e13773313b48101, 0xabb2c26f21d448a4, 0x93cfb5484233c206, 0x01a6361a4bf8157c,
    ],
    [
        0xd605f96633ddf187, 0xaa4248bd796be51d, 0xd450b453e35214d1, 0x0a20b2dacf6c8432,
        0xce7029e2e51ad670, 0xfed18221bbfe61d5, 0x0630421a8b9cf02c, 0x90d0f1928149d643,
    ],
    [
        0xf568648ac5df5e8a, 0x4617ea08aa569a3e, 0xe16b8d06d516f663, 0xaf2bffa89a68be38,
        0x53020b5eb31fa5e9, 0x24f3181770de2ac8, 0x76c0b60ce41ee449, 0xa877c40c18ac0f34,
    ],
    [
        0xb3ab62de4fe6c0ab, 0x4593160f1cb348a4, 0x985650161fbd6377, 0x7b9a1c27e9bc065d,
        0xfde15539c521fef8, 0x84b2b50e96d0a8f6, 0x5bc90c11f34be73d, 0x18faee7187c43a43,
    ],
    [
        0x3f5142125cbea51e, 0x9efbdeb62fd9bbfc, 0x26bcee2c75c2e9ce, 0xe4622f8e7d6ba352,
        0xd3725a15c452d99e, 0xf8838921f45770b3, 0x727fe62814b18792, 0x50effc48e4c28dd7,
    ],
    [
        0x631ea2bfcdc9b0e8, 0xbbe8ea9b22864fdd, 0x0a2d82b943df4650, 0x8eae41954ef13207,
        0xebdc90d3fc269352, 0x93895af9ca450504, 0x083a1d554e6382c5, 0x3457ede94952697c,
    ],
];

pub(crate) const COMB_TABLE_Y: [[u64; 8]; 64] = [
    [
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ],
    [
        0x78cd1e0f3ad80892, 0xd1ca2b2fa8f05406, 0x5bca4bd88a2763ae, 0xb2dcde494a5f485e,
        0xa000c55b881f8111, 0xf209f70024a57b1a, 0xc0eabfa9cf7822fd, 0x7dde385d566332ec,
    ],
    [
        0x5bdd7095d4885960, 0x16b33f068a346e27, 0x964320386101fe2d, 0x30341b850799dcf9,
        0x0f1a7c953f7bf01e, 0x6750ed0eacc54360, 0x2ab0c607acaeb4c5, 0x141d802070d55dc9,
    ],
    [
        0xb0d58ba3eb7a8d6b, 0x74ab9eacf841a31f, 0x2b09fe1c0d65e312, 0xec7ef9c53f13ca3f,
        0x91d389a628635d2c, 0xe377d4827a3f95c9, 0x4266f4003292bb34, 0x222a9f17d13158ba,
    ],
    [
        0x57ccf52502877a21, 0xe18fed4b2203db8b, 0xa9bb5d5815065deb, 0x44c28d42f31ea9ea,
        0x228c078d2f2318c9, 0x970dc27735d8c29e, 0x2ee07e0c1c143bbd, 0xa0498b49bfcd4dd4,
    ],
    [
        0x69e5585e792d484a, 0x06d46ee9ec2685b4, 0x0bd2a23887266898, 0x6fa5f875ce6017f7,
        0x15f187aea9db5120, 0xb0f596193b9249dd, 0xfafdce8c5252d5c4, 0x4108aef6e60a1824,
    ],
    [
        0x46ed8dfb92f37489, 0x2d40e7d42b218fdc, 0x7a603a86cf8beed4, 0xeda4b2edf378685a,
        0x41c6adb984b3ccbf, 0x003fccd1dac369b4, 0xecf52a033db7a344, 0xaa3041953cd6d0d3,
    ],
    [
        0xf646c283d8bbacaa, 0x46cfefb415cedccf, 0x7ab20b31945edb46, 0x1e417111e3e3b93c,
        0xbe65bc7db701e336, 0xe348e8a7876507fc, 0x6cb48e30d48f4866, 0x3656bf1ebe73e086,
    ],
    [
        0x9629051d87f42d2c, 0xd23cb4f32a695290, 0x78453e4a0fe0ea27, 0x0f3ab1d7e83767a9,
        0xcd29328e4bb53243, 0x032c337096b6ff90, 0xc39a8d773a4feb52, 0x1e387c4ea5a2709e,
    ],
    [
        0x6646f12039c4efa5, 0xe9e2e410ffae62e2, 0x82e589222ef55cff, 0x65dbae62a8290c89,
        0x7b6f2a87ca0f9ed7, 0x27add4659f9bdcce, 0xf4e967cf0f08c3ed, 0x26cb9c41ffd75c92,
    ],
    [
        0xfb0040abe4ba5397, 0x241f6bb4859acfeb, 0x5ddc0ce1ce7b7f82, 0xfc163011c51a42af,
        0xea9eddfb532597f7, 0xde2356e2557085b3, 0xa2108ecaa07faeeb, 0x999a2b847db17651,
    ],
    [
        0x1f3a00fd9da8b9b7, 0x741fca5abb6c4163, 0xc948a76b6ce2d72a, 0x6e4f7ec1a7ad191e,
        0x3a2c74063c19f7d1, 0x4a80b0090c4f23c5, 0xdda37e440834744e, 0x0b3de16e128dccfb,
    ],
    [
        0xec7cbdf7f796a244, 0xbf9cfd8a24ff2d4b, 0x2f8aed9ce489e1be, 0x764e6b983bf434d9,
        0x5c3fa90cdb9809c1, 0x94127d7ff40b08c0, 0xefa9a69df68210dc, 0x6e1b0a14b87f46a6,
    ],
    [
        0xb32a721f6932b99c, 0xa8aa353903e2731c, 0xf530aeef485d5eeb, 0xfc9decaf19607f77,
        0x5f15561be419d9ca, 0x2c59431f5933d7bc, 0xd4637fa4caeecec6, 0x20438919f6c040bd,
    ],
    [
        0x5ae1f8c545fc5e16, 0x2285d04dc72e0d00, 0x6a42776ca9ad2f41, 0xe25af08e00887a59,
        0x948ea859eea359c2, 0xd0ebad6680022e1e, 0x317faebe3b8e9031, 0x9befacd063fd4706,
    ],
    [
        0xe5eb47a64b96d6ea, 0x666f99de155ff15f, 0x0bc0e6b804e5bd21, 0xdb05e40004f0d349,
        0x73eaff1aa306f396, 0x34b6093399aa3208, 0x9431421061fcef6e, 0x9c9028cf33f4f134,
    ],
    [
        0xa70565dea819445d, 0xf8bf9fc253e72ebc, 0x1041bb9a1eb90332, 0x467dbf47cb9f7992,
        0xde17ac6962c5a880, 0xdbadcce0973b6c7b, 0xdf064409d5fb3509, 0x3d8dc63f138c920f,
    ],
    [
        0x9095a17575bf238b, 0xbe03a913345d664b, 0x62e144d25f9d8029, 0x1f25b4bfa8bd5d96,
        0xe7db57f1531f996a, 0x9b4c0b51c5e57c21, 0x1f32b0169c1ab06b, 0x337bb448ddcfe3f4,
    ],
    [
        0x7215331e80e444d4, 0x8eda53d34b90de99, 0x7f6c3d748c970f2d, 0x8d21677488a6753c,
        0x6593666a9f25e0f6, 0xde319609defc5f94, 0xd2823d794e140475, 0x6ee0da1a0f561a9c,
    ],
    [
        0x4c0cdb869ba92dd0, 0x8a93d34a562d0be4, 0xb20e861265e215b5, 0xd7c3e4cbc14d41b4,
        0x2683aca3ca10536a, 0xdb69ad109622013e, 0xf39dd6ead84e4642, 0x14d08062627f2f43,
    ],
    [
        0x410a149bd7f63cc8, 0x0a6bc34cd81e94fa, 0xc9b6b958920263da, 0x31452493d4628f4c,
        0x8c9d2bd33511ce46, 0x4704e4ee6a17e690, 0xd0bd31ff561e78e5, 0x1b002fbbbe814e77,
    ],
    [
        0xdd30f1d680b6d85f, 0x61d8a7ee85a614d6, 0xec2de97c1e2a49e4, 0x554d77039156873a,
        0xc5b0faf7aad4520e, 0xad76e7b139115d04, 0xc2cd745d37bc13d6, 0x3746f830231448c9,
    ],
    [
        0xa3b931dbc4b7d1d7, 0xe93e7eb17ee32fa3, 0x3aa19b102d19dad4, 0x84a3686f2195f2a7,
        0xa194b516548d19d1, 0xe335d364e9512c2a, 0xd17cff876c9c9b55, 0x1537ef13af000833,
    ],
    [
        0x3ccc2eb82eaf3326, 0x4a090c4e5973b1a4, 0x6ebbff128189248a, 0x9bb6edee661a3771,
        0x95bffb5d2004bd16, 0x92de45ffa334f8a0, 0xeb582532f173189b, 0x120f409ee314c163,
    ],
    [
        0xe7e8a9a3a3afba55, 0x38f99690c9021617, 0x4d32770a79147b6e, 0x0c26d11aa5c7ee81,
        0xa961d9629fec17c9, 0x4263caa2d106ee78, 0xf15725f9d73f0305, 0x632a9c89d4e6d547,
    ],
    [
        0xb0dc98181a0abd76, 0xc65a5bd5b7026363, 0x5d6139154bd7b151, 0x51ce1b709ee1325c,
        0xa26d9b528318d864, 0xfceaa434195655a4, 0x8b3615e38055a930, 0x16ad0d171dc806bb,
    ],
    [
        0x3808f057005f9aed, 0xcdafc60342cf8f2f, 0xa856d8e8a5190006, 0xbda540aa952e0189,
        0x8fce584cc5e9fce6, 0x18781afc74acd7ce, 0x7430aac0a10ed2cd, 0x2751ec6336e8eb52,
    ],
    [
        0xfffd933053927e05, 0x52b40a91b16a16a0, 0x4601f1e33f409d6d, 0xed4c8e11edd80e13,
        0xe7298ddf881b4a86, 0x628177ab11212397, 0xe76340bafa11af0b, 0x44f567df808d6f2b,
    ],
    [
        0x0926cda3e8344d0a, 0x36217d5aca3a42fe, 0x05b3ec352bbeaf66, 0x1c2b277ea893c18b,
        0xad7741b0d8daf42e, 0x03ae990a27a9c49a, 0xaf5e1c26a43e83dc, 0x0c90d408379ee139,
    ],
    [
        0x1b9eb8b37c933529, 0x0f8175bf7e5c45c4, 0xb97d2fecdf24e8dc, 0x4fe0a09b6ad58bf2,
        0x4bcaddde8227e332, 0x2e010605465657a7, 0x4f2c6be247a73574, 0x2b75111fec4c9d38,
    ],
    [
        0x0d3e73f0176c1193, 0x22e03a191834c29f, 0x0cf298260e03b94d, 0xe9cb7cc17136069d,
        0x4a77873a67d7cf6d, 0x8fc9aefa9cfc7446, 0xd60a48c1ad22e546, 0x57a574c971725887,
    ],
    [
        0x32579eb87e6c18a2, 0x32fb78fed0c1b935, 0x7f7aea3446ae087c, 0x9ed43718a9561ce8,
        0xc13c38b60ae96328, 0x522331856ea44f3e, 0x821c4bb1c3c4ad0d, 0x2c6f6bb3384a5630,
    ],
    [
        0x8f59c5f759daa0c0, 0xa069da37b7bc6b07, 0x03956a019069a441, 0xe23ac2b6becc4918,
        0x7667f366335c55d1, 0x852a60f39609d940, 0xaaf43775b3dc0022, 0x5793aecfc949c2dc,
    ],
    [
        0xa9029aee73e524b9, 0xe9e362f360656ad9, 0x9f65463be68407fb, 0x9d8204e1b00c8fe1,
        0x74a248a03dbf13eb, 0xe8290bab74762608, 0xce387c34035f6e30, 0x7cbca43c3bf9724d,
    ],
    [
        0x22b80cb2f1a975e3, 0x1eaa6bc721eca6bb, 0x398456538b6e7ba7, 0x475e8d236dd7c396,
        0x4fec1b14da2469c8, 0x16cc9d83a5178efc, 0x3eb0a98efcceb3d4, 0x443c766122fd4ca3,
    ],
    [
        0xe8cf4cfa500716f9, 0xdf7eecdee92150f8, 0x0e650b3083e82f7c, 0x2a6cbac9ac990ba5,
        0xad089e7b0d5a59a7, 0xed67ce90dcb29134, 0x172f1fd70c6093e3, 0x547a78f8409d7f19,
    ],
    [
        0x3b9018d9c178ee7c, 0x2bbf7a88bfc52b99, 0x8a429813c394ef41, 0x2af8b3db88cabd59,
        0xe9db92ea5bde1431, 0x3c857c7f454f6db6, 0xad4773c8e9a1fe57, 0x9fe86533c33ef9ba,
    ],
    [
        0x1dc8a910b46a3cf9, 0x25acb81669d6c5ee, 0x5f5d5448ebdc44ac, 0x8aa46972d79b486f,
        0x24ec0b669a360db4, 0x3ac3e560b6d4c6be, 0x3e7cfd9de04229ba, 0x5d383bbc55ba1043,
    ],
    [
        0x28471dc257a1c112, 0x95ded7822e7ccb56, 0xcaef5c323e63be05, 0x87517baff92e77ea,
        0x1771b5aab5543f91, 0x1b663f69690f1e53, 0xefff97330d5ed882, 0x0d59aae84321eed6,
    ],
    [
        0xa289c1f1f5888e66, 0xb4822dfbe6533016, 0xc2ab7931baffe4a7, 0x904c7809b7f70945,
        0x477817dc44c2ae10, 0x239e74194317d4c7, 0x762799a2733b6415, 0x31b114d35f367405,
    ],
    [
        0x05c3d4ee3b3ff7bc, 0x0d8c829fa92ede1c, 0x8ab43ac8c7e5f214, 0x8431fb706d94f3c1,
        0xd3540966e380a228, 0x680a77e8926e4add, 0x7e57fc4418ed1c0a, 0x389977d95c1059ff,
    ],
    [
        0x0a74212ac66e7bef, 0xe5ef36294d53a737, 0x5350ad99c741d6e1, 0xf1864cfb9f41ac99,
        0x1eebaa2825e6bb8b, 0xcc8a08aac3a20492, 0x34ea768de25b2b5a, 0x8ee3624d21d233b3,
    ],
    [
        0x280f797ae6b6396b, 0x9795a028747f2204, 0x6e6dfc0a652d92b3, 0x245d08d6238396c6,
        0xb8229ec368e71de1, 0xc6133820dee92135, 0xda00e99f72047a7a, 0x002b8ae716e7ba52,
    ],
    [
        0x7dbb96df3d4dcd8b, 0x81310ecc0611a777, 0xeff15f7badf4e420, 0xdf47038af4be54e4,
        0xa6688ab07f0053b4, 0xc30e5b6f73b116a0, 0xfbfb756443e3322a, 0x54356e4e8a5518a0,
    ],
    [
        0x826e0126fafcd410, 0x553ffda0d223c5c4, 0x68791e0c0e53db56, 0x5d43483c52c76c68,
        0x99aeb54489fdcffe, 0xf6a73add0d3c039e, 0xb7a1a0fa5af206a4, 0x1dbcefca5a4daf31,
    ],
    [
        0x88a3dda325bbd5b4, 0x93738f396768f246, 0xdfe032ad892876f0, 0x75c9aa5857cc90f8,
        0x08a05eced243d75e, 0x8626969ea4b8b033, 0xca605e65f31d6194, 0x206007cfed651ec7,
    ],
    [
        0xed1e9e6887d34f37, 0xd21f17b004f45dc1, 0x7c350090a0c3cf67, 0x0fb6ce1629e00570,
        0x8d523d9ab193d40a, 0x44e65f9eafc7de66, 0xd304041ffcc4444b, 0x38546f86cbce4763,
    ],
    [
        0xfe0bd52b03da6375, 0xf2aef047c8e2fc46, 0x2a06480c50f74c51, 0x41617e0e98322bdf,
        0x24df8675fe27025d, 0x24fe1b3222b1302b, 0xe4fdd76f78f727c2, 0x442450c0eacc78a0,
    ],
    [
        0x94c947e038556ab7, 0x3ead23886d69b940, 0xa2adfb17d78c777d, 0x80bba4d91e93297c,
        0x60a8c22ede5efd9a, 0xa315184d7205b080, 0x90e47f5eef2e8dcf, 0x26660790f92e541d,
    ],
    [
        0x36ddfdb5f441711f, 0x061f2ed14c20e29d, 0x87ac498a76484396, 0x7557d4a3a8551a0c,
        0x60bb13c93984a67c, 0xc9dd83de70a9fad9, 0x7b6891443ed9c9ec, 0x823654f76d859fb6,
    ],
    [
        0x14217281437eedf0, 0xf5c7bea0561bff8e, 0xfb55caf1b7f75bcd, 0x5ed5c31bba595b2b,
        0xb51e90ec4eb391d1, 0xfe9adf741468992a, 0xe8ce10329f18d3f8, 0x30c55a4e8ae20044,
    ],
    [
        0x52b19b59a685c789, 0xf794dffbd140ce1c, 0x2d2da845bf5eb818, 0x79b957a91b069c98,
        0x3ca174d3a2cee953, 0x143aaedb78345faa, 0x0f436a683e84327d, 0x11bbc5a43639bc8c,
    ],
    [
        0x47f3eb9d657eea4e, 0xb29ac2efd38350c3, 0x8bdcc89ec3cd5135, 0xc71ebf2129aea98b,
        0x000a749dd2b4d84c, 0x7cc08ac6a671cdaf, 0x3c6bd426bdd97129, 0x69e68a9edb2871c1,
    ],
    [
        0xca3c486323e6384d, 0x823be93bd13c68d2, 0x134546d1495408b5, 0x955ec4796e527007,
        0xd3da81325ae8df36, 0x0a9f35b55b942d3c, 0x2ab23636c38d122a, 0x354c185b38222f39,
    ],
    [
        0xc7f7403581ed441d, 0xca1386983080b5a6, 0xa1a8fc8b8ae469fa, 0xc9ee4c184245bd22,
        0x59bc1c218a290b22, 0xbee95f2aadcf95f8, 0xb9b243b9008e74ca, 0x8f21deacd50894e6,
    ],
    [
        0x7f382fa0a437e021, 0x7a3c392f40b73dd0, 0x7a4940ae518a3b7a, 0xc777d0a9dd9f2036,
        0x7dc753a0da641d78, 0x4451d19455667b37, 0xc04035385bb5a90e, 0x61437973f00fc9c8,
    ],
    [
        0x06e888518b4b307f, 0x0feede58d8c8ee9b, 0x2e13b19ca54d5492, 0x83d9cf812bfd3188,
        0xea553fbb7fa9560b, 0xc9e1435309e52222, 0x87468979c61edfc8, 0x46950a399b065bbb,
    ],
    [
        0x1fe97bf9fe528357, 0x3ac149154655a207, 0xf49cb9bd915cbc1d, 0x53ee745f4eb1fdbb,
        0x961b73178bd88bb1, 0xcd25ad0667d79222, 0x8b5f27e224800f01, 0x0bd4ca67d0ce1c61,
    ],
    [
        0xf100a0a7098a9f30, 0x96269497ed901840, 0x3135a34d4f4900f3, 0x156ff09fe4dbf60f,
        0xf58a9ce1521e178f, 0xcb62c5b979288c20, 0x4fa7559a4bf14815, 0x67e22559ab79f5ca,
    ],
    [
        0xd6e922a66a9391c9, 0xec7d951169c3dc09, 0xa241645e879da31c, 0x8d3c6ebd155a87be,
        0x0b8fb7cfcc508dd0, 0x1368f13031cd6538, 0x9557309267665c10, 0x0dd18b203d019b23,
    ],
    [
        0x52d1e73f157e7e0d, 0x5f7048cb60c88b7d, 0x3d659814676d3be0, 0xc76df29925013183,
        0x3a4016b46fc1a190, 0xada0e1945ad9574d, 0xa5327e92d773ca9e, 0x14f7547d62a602a0,
    ],
    [
        0x4bea965e81ee77a7, 0x43b27c4ff4a9dfee, 0x8a25476335dfd49f, 0x1195c302a4ff3da5,
        0x0ebeb72bd17810d5, 0xbcfcd8e0f957e90a, 0xe278e7b4d601c4f3, 0x6f6de8a413b96c02,
    ],
    [
        0xc23d355b2a10f887, 0x23d89fd92aec37d3, 0x69b857fcf974f97c, 0x3ee15700d6c3ca48,
        0xf6b13c3e7c5b0f06, 0x55a8e48f06441e3e, 0x0e95af68770652f3, 0x910a74c5f94c7a17,
    ],
    [
        0x25ea4a4cace96470, 0x2ca9f9e7990be9e9, 0xb1b6078df4c10c24, 0xd9ae9ee435fa68ad,
        0x63e2028e131a2df0, 0xe13a7b4686283827, 0xc402f90a59644c3f, 0x42efd5c3a2234f41,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp512r1::Bp512r1FieldElement;
    use crate::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::bp512r1_point::Bp512r1JacobianPoint;

    const WIDTH: usize = 6;
    const BITS: usize = 512;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic, per this module's construction: `pow2[i] = 2^(i*D) * G`, then
    /// `table[idx] = sum of pow2[b] for each bit b set in idx`.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = Bp512r1JacobianPoint::from_affine(
            Bp512r1FieldElement::from_limbs(G_X_LIMBS),
            Bp512r1FieldElement::from_limbs(G_Y_LIMBS),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [Bp512r1JacobianPoint::INFINITY; TABLE_SIZE];
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
                assert_eq!(COMB_TABLE_X[0], [0, 0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(COMB_TABLE_Y[0], [0, 0, 0, 0, 0, 0, 0, 0]);
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
