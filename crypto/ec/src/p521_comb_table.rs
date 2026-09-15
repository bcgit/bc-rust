//! The checked-in fixed-base comb table for `[k]G` (P-521's base point `G`), width 6, same choice
//! as [`crate::p256_comb_table`] (bc-java's `FixedPointUtil` width for fields over 250 bits). See
//! [`crate::p521_comb`] for the multiplier that uses this table.
//!
//! `COMB_TABLE_X[i]`/`COMB_TABLE_Y[i]` are the affine `(x, y)` coordinates of the `i`-th table
//! entry, as little-endian `u64` limbs; entry `0` is the point at infinity (`x = y = 0`).
//!
//! Regenerated and compared against these checked-in values by this module's own `tests`
//! submodule below -- see [`crate::p256_comb_table`]'s docs for why this is a unit test, not an
//! integration test.

pub(crate) const COMB_TABLE_X: [[u64; 9]; 64] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0],
    [
        0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de, 0xa14b5e77efe75928,
        0xf828af606b4d3dba, 0x9c648139053fb521, 0x9e3ecb662395b442, 0x858e06b70404e9cd,
        0x00000000000000c6,
    ],
    [
        0xb4c52f11f3d7286a, 0xec47cb5cbbf67a41, 0x89d3382eaafb10a4, 0x4afd876806222b90,
        0xfa16b295feb5416d, 0x0946f9d45d095b7c, 0x18526b28ff975e3d, 0x259cec2fb2f1c609,
        0x0000000000000104,
    ],
    [
        0xdae82f27eb2db12f, 0x675f5cdb25444b98, 0x3234752e78288513, 0x53e37a78730f5769,
        0xabad04dadcecd88d, 0x29d87958f3098a34, 0x00567f1a50cb0363, 0x400b67853878a6f6,
        0x0000000000000183,
    ],
    [
        0x0cfa67a640b0a066, 0xe97c179e8057a710, 0xb69d285227cce600, 0xf7dde8c5419687d1,
        0xdbcb15185d5b039e, 0x3e47772fd99abbe0, 0x71c9c23ab2a9c6a0, 0x5af10b9b94496951,
        0x0000000000000152,
    ],
    [
        0x36005a37c7b848a0, 0xbac203eee032cc07, 0x8d20246ee4c229c4, 0x13b8b0f97b7f6b06,
        0x0223a119e13c7b1d, 0xa91307c053c2e32a, 0xce595e9f3536fe07, 0xc2a2efbc8489551d,
        0x0000000000000019,
    ],
    [
        0xfd0c67177af706c0, 0xc500416552ebdf4a, 0x332675708ff0bf03, 0x3f282dddd2cdcf58,
        0x93b60398bf766c2f, 0x124f1fd970748a8c, 0x05422ecb20ef5bad, 0x9fef00a63eafb2dc,
        0x00000000000001d8,
    ],
    [
        0xa7b7271a71b90b8c, 0xbdc1bcdad12ca22a, 0x52a5f2901f10a310, 0xf5c070c0f420fb28,
        0xdd09d3a5f099a78f, 0xaf60cbbe3914e826, 0xeac320c9a914d69f, 0x78bc962dfd5ba85d,
        0x00000000000001c0,
    ],
    [
        0xc2453d609102b570, 0x70840e5c142c3e23, 0x7294b1f1c30037d9, 0xa2500f121dbf5ab6,
        0x03eceb67c9c8ee6e, 0xa19c319330820abb, 0x7aad59e87da6b820, 0xe97823f8c38d842f,
        0x000000000000006d,
    ],
    [
        0x5ba6aa8d478bab98, 0x849ddc2dbcf097c4, 0x67f6f4b274b08601, 0xb15c438fe3acbdac,
        0x0bcd49256ee2c337, 0xd15facb9b3085e64, 0xc8e919dcf4d1b708, 0x6eed3e36e1fae449,
        0x000000000000000a,
    ],
    [
        0xe2fa0b39d0851f6a, 0x2f7f00e5263539c6, 0x46a066b81f107130, 0xe7cc14f87dbe9579,
        0x61f1e5c2d0607b55, 0x539a9c4d07a4c0b8, 0x9b6893829fdc8d6f, 0x684725a9847245fc,
        0x0000000000000020,
    ],
    [
        0xa732fe002dcd1035, 0x034d6ff8da1f6ee4, 0x2103d3e5097d7909, 0xcc496507dfbec358,
        0x27044faeef335708, 0xf685e6bffe9be99a, 0x57b8c6c406aababd, 0xb8e751f6a901830c,
        0x000000000000011b,
    ],
    [
        0x689a234ba08e3299, 0x941f6f05c4cf87aa, 0x3a98121b9ffdcb65, 0x3252b8481623b72c,
        0x65f531b5c6bae311, 0x4c5005a1c383df2c, 0x13c011795826c457, 0x90ea82a2ee3b03de,
        0x00000000000001d3,
    ],
    [
        0x4ab1603c78f459e6, 0x7d9af2dc6a84373e, 0x2d2be036159a9a40, 0x82371e3d509c38ec,
        0x82188bf292f079b7, 0xd74b82801e82e017, 0x4041778a6b59bbfa, 0x40cf824ab8d4f9a7,
        0x000000000000005d,
    ],
    [
        0x0eedf7150a80f0b9, 0x7f78ee5beb322905, 0x15d5375783498544, 0xff081204b66d249a,
        0xb95434862bd0d1fc, 0x6404f1321899b952, 0x1de3aa0ccdd8789c, 0x8b6f01381a7153a4,
        0x00000000000001be,
    ],
    [
        0x5141181078303dc6, 0x93d1836de01c1d96, 0x98046c2ff50b037b, 0xeb3a5b31fcd53e6c,
        0x3976f8fefb2f8250, 0xd193f5369cda2685, 0xc609817dd26ee74c, 0xeea2244858f903d3,
        0x00000000000000e9,
    ],
    [
        0x1e2df23635210df1, 0x387b5c569aace566, 0xdd8152c9ee401323, 0x56fe9ec99cac0076,
        0x88ed7fc1e1a9f782, 0x6551487d681f0428, 0xeaacc10197689006, 0x626bcad13b7e7fe6,
        0x000000000000015e,
    ],
    [
        0x66bd9a0dcd698697, 0x0e7d8559bbbc1758, 0xe072a980ac76a88d, 0x3cf9af4de2c17874,
        0x85b24bc4748e97ad, 0xe5522faff3f6d8ea, 0x60ed43eecef45795, 0x1859fd20de38467d,
        0x00000000000001d7,
    ],
    [
        0x6fa722771bac59f3, 0x72358865520791ad, 0x8da1c8c4e32463d8, 0xe0e75863d41001a5,
        0xcea164f748e602db, 0x93cb5f21cc294cfe, 0x28a3168a941cbefa, 0x018fff3bab807177,
        0x00000000000001e0,
    ],
    [
        0x728e1148bdbc363a, 0xdfbf9e0bf7a1bbab, 0xd6fcfc8fa2e12868, 0x3969e7e50a19fe81,
        0xf104d3bef512cd5e, 0x9879c459810da8f5, 0xad31c365924bf3a3, 0xb2e2d4914d4fb575,
        0x0000000000000151,
    ],
    [
        0x954376cee18bd1d3, 0x350613fc9c8e4d95, 0xa60d595673323968, 0x4f6ac836a044cdbc,
        0xf38d747b881b8e40, 0x79f7faf00426afe2, 0xf6e7403d2ae12787, 0x721445a6726ae667,
        0x0000000000000141,
    ],
    [
        0x55a5e8f4641b7e08, 0xe1e589f3caa920f7, 0x07b90ad9abfced83, 0x05ff78cd7c466f08,
        0x2020ab945a71ab69, 0xd3ad1f5787ee2ec2, 0x078ba17efb3d4c91, 0xcf3753ba8607cf69,
        0x0000000000000138,
    ],
    [
        0x071492bba1e06f89, 0x6f3f72de734cc62a, 0xb50a11309d477637, 0x5f6b0546a5ce54f0,
        0xc1cde769698626ed, 0xe43af79564ade3d0, 0x3067161797a20d2b, 0xdf5821678c48495b,
        0x0000000000000129,
    ],
    [
        0x2fdf67bf4f6f867e, 0x56f6ea005f1e2bf2, 0xa7d7c0d8896ab990, 0x589102a023329acb,
        0xbb8b6a64156a7f42, 0xfbb556a95882578a, 0xa82481cc609250dd, 0x573e51d9daad3d36,
        0x000000000000005d,
    ],
    [
        0xd3a8c547c7d40b83, 0xd9fd110285002a83, 0x4bd9516c97f61840, 0x8c628537448c4851,
        0x5cae5aa1c90925ad, 0x356195c572319740, 0x8cb6e19ba2b5be38, 0x68626a4b6d9c8c33,
        0x00000000000001c5,
    ],
    [
        0xdb0fa258898a19c2, 0x26346630974ccc01, 0x135ec9db1f1e6a83, 0x9bac9c9bff494d1b,
        0x78d21ad4f24be4d7, 0x3249c89f61e8dacd, 0x528df6852df2cb51, 0x4f0ec6792ccdc5b7,
        0x00000000000001db,
    ],
    [
        0xdf886f2283fe19b9, 0x740586885dba4f8e, 0x3c04af37a13f8dc7, 0x21771e2b3b99dcbc,
        0x1e77950d55c5b6a7, 0x20a6975b1b1338e1, 0x4956e06bd276d114, 0x56686808b0d3b14c,
        0x000000000000016c,
    ],
    [
        0x953bb441f640de23, 0x5d35f0a9e1e08dc6, 0x323a1bcc7bbad4e6, 0x4dc31447742e5ad0,
        0xca0e8e15068bf07d, 0xfc317d5097ebd2b5, 0xf5447997db4c9342, 0xf98a3ac80ba0a29c,
        0x0000000000000061,
    ],
    [
        0xa2d5fdb981e3d610, 0x0127b05c456ddf1c, 0x29e247d9bd5bd8a4, 0x5758d126f5959d68,
        0x9b0fb7fb2b28eb19, 0x1d8aa23a1d312140, 0xf8b9e467281b4d2c, 0xea57464cda959b8f,
        0x0000000000000028,
    ],
    [
        0xa15c4a20a5eff951, 0x1baa735b49f4f32f, 0xab53ad000feaf2c6, 0x354c2bc4ed66b803,
        0x587fd2379ac12f3a, 0x3837c9643881a729, 0x1d8bd95b9f6c3bbe, 0x237ed2d808d914b6,
        0x000000000000001c,
    ],
    [
        0x3f621de51cf1a11f, 0x18b004fd0658152d, 0x1bc8a9455df479b5, 0x901719473da586ac,
        0x06fe325baa2f052f, 0x4a2fc982b6323a69, 0xa975e8bcd4f0b34c, 0xfe3f271914ed1d56,
        0x000000000000001f,
    ],
    [
        0xb7f2a894410a34a1, 0xca6d4597f0e4d4f6, 0x84c4a0fe6d4d1f8f, 0x42d465bb405c281d,
        0x44893a203587a898, 0xc0d0d12dab4ffdd6, 0xd5f85269fc00e886, 0xd93f9cdce1999ae1,
        0x0000000000000199,
    ],
    [
        0x3a44dde085f45edd, 0xc543bb6498309156, 0x82d1ce827597d0d0, 0xb2dc0f228106ca3e,
        0x66f394472c3a313a, 0xd8f6fcdaa6cf2e03, 0xed6e0e279e6bf40b, 0x7dcd3a305b9a41af,
        0x0000000000000095,
    ],
    [
        0xaff40f1bb5598dcc, 0xef04d8e02cd12fd9, 0xc97ea3b0bad7f4ac, 0x336776a6565108cd,
        0x71d9d056fe63178c, 0x31a7c54714c3f6aa, 0x5da757a2f6804c72, 0x7b3ee12ff87bb311,
        0x00000000000001fa,
    ],
    [
        0xffef7d4f0399f8cc, 0x1e2708d99da4c3fa, 0x5792ebd0a9474303, 0x21aa73f56812a436,
        0xf61f60fbc052973d, 0x7061be89fc874833, 0xe65c7ebe2638329d, 0xe728d78b032852d9,
        0x00000000000001e5,
    ],
    [
        0x94de21d800df95b9, 0x5d5301b2c33c47f7, 0xf271cabd2343171e, 0xbe5441dc4f0fba70,
        0x11183253702639d6, 0x01e0573a97074632, 0x268025dfce4f92d6, 0x47d14b05039a6f5b,
        0x000000000000015d,
    ],
    [
        0x0b7a0b9ebb82fc5d, 0x7f2e7af14ff667a2, 0x5cc3df3907a17aec, 0x91465af2398fb92a,
        0x785b749098cf002e, 0xfe22218f7380cfb0, 0x32bd17997f4f03a8, 0x1c78bd791209f39a,
        0x00000000000000e4,
    ],
    [
        0x5658a9eb87400032, 0xb3513556ff0b51af, 0x99ecda719408ac7b, 0x5e8d8b317bc54d5f,
        0x8f178f9e3ef10515, 0xfc49ad94624b9cf0, 0x344433fd8fc6c90f, 0x0df7be427f17965f,
        0x00000000000000d4,
    ],
    [
        0x5ba4b10081d6751d, 0xeb0319dcb96a5495, 0x56407c25654729d3, 0x3de520199330d3fc,
        0xb3f8a00e28998bc4, 0xeeea220977ddd518, 0xc1429a49cb758f5e, 0xa86982a271834361,
        0x0000000000000040,
    ],
    [
        0xebc08efd502a4e76, 0x4589d863767c0f52, 0xcf85eef44eb92dec, 0x0b59aa5d965c95c1,
        0x60945a8e68d2dbca, 0xc94cb99f77bf02d9, 0x6cc41e81cfc0dc2d, 0x7264e2dc8637cc2b,
        0x00000000000000d5,
    ],
    [
        0x2cd49af1f76d4173, 0x269b00cea89acef1, 0xb60e2977a015990b, 0xbe86499685f72cef,
        0x4e23b9db4d5b0156, 0xfa92c71c6bb926ba, 0xf4a8ff2fe2f815b2, 0x543eee4aa5cd2e72,
        0x000000000000003a,
    ],
    [
        0x036735d2ff9ed76d, 0x8653e8e35d154fca, 0x6811cba29824f792, 0x96a3c594e1252e06,
        0xb02543e7ba6e82e0, 0x5435187349b46518, 0xb7c14c8662bc5b59, 0x6535a2bba295f29b,
        0x00000000000000bf,
    ],
    [
        0x042191fad75cf083, 0xaffc08409bd72c49, 0x8f5b9e3f67faf055, 0xa99fa2dfc9794f77,
        0x1ccbe885a9ef6764, 0x5fd1e3d66880eb3c, 0xbef622be06fd7bfa, 0x80d418fe9b10c7f8,
        0x00000000000001a9,
    ],
    [
        0x8e846df2fa327b1c, 0x6755220d1d0321a0, 0xbacbc29c0342f918, 0xbe6f119dd996a1f8,
        0x11c02d40eb5740ff, 0x28a8232f4fbb962f, 0x066250a52185293a, 0xf9220c87cf927dc9,
        0x00000000000001c9,
    ],
    [
        0xd63c86d1774512bf, 0x1524c2d8624719e4, 0x2f7568d486d00e48, 0x02140d74cb9cf033,
        0x3fff92dd0cae0cce, 0x7ec6068613941889, 0x791633ac5b8bf2b0, 0x43c98854ca54ea3d,
        0x0000000000000027,
    ],
    [
        0xc8bc017afba4114a, 0x8e2791028d7327cd, 0xb95bfa6bddf662a4, 0xd828f02c44a2caef,
        0xc6504c42a27af13c, 0x67f79cab503e832d, 0x42da6976cb78ed1d, 0xda6e4727431e01db,
        0x0000000000000094,
    ],
    [
        0x407a70134deacc7c, 0xa2540e3c94faf272, 0x4246beb934b43fa8, 0x157b03f43ba9f184,
        0xf7898d60b939ba99, 0x0f7e245e3a5f62b4, 0x2db5a341eaf7a575, 0xd3adea091278c0f7,
        0x00000000000000d2,
    ],
    [
        0x6e60bc8cbebdd14b, 0xfe195cae8c57a662, 0x41e77bd8d9e4437a, 0x20fc2e7c85e4b9ed,
        0x97be566d2a012e02, 0x433786ae9b250c6a, 0x9eb76699cbb3224a, 0xf727091bf090f756,
        0x00000000000000c8,
    ],
    [
        0xf29780090fd83acc, 0x247593df630645db, 0x171e6b9f9e2db252, 0x3a6342a3c30aec58,
        0x23524040fdd7151c, 0x2589b6988b15fee7, 0xca588f0a17dca917, 0xb2cf2fe7677cad49,
        0x00000000000001dc,
    ],
    [
        0x5a0e940caa2f106a, 0x7c55eb23418781b7, 0xcc6cebb679cc53b8, 0x7f6f64fc9d7377f4,
        0x1571161c6de3403c, 0xd7a52f1cff1bf45a, 0xaf938df4110b0e06, 0x9bf219246f64c558,
        0x000000000000001c,
    ],
    [
        0x3340fb54f31cb1da, 0xc1e88317e1752360, 0x183ae7f8121667b1, 0x1f271fa2bfd7bae9,
        0xb31175b92b745d3d, 0x22250cc540b13e3e, 0x63aabbb70d01026f, 0xab63c0f1b428cd91,
        0x0000000000000018,
    ],
    [
        0x0801a2cf5f0f872a, 0x67a587356ec8c90c, 0xf21e24aba0913e94, 0x985fc1703502bcb9,
        0x8552800450a05926, 0x65918c8f426e56f8, 0x382414dea5cba2ac, 0xc3e7a7e62874cb00,
        0x000000000000005f,
    ],
    [
        0x24b42a1c35c6448e, 0x129a536e1f4e7b86, 0x7ca12db87e48d8f6, 0xa827acf3587d6577,
        0xfc62bf4bb1cce77e, 0x702ee5800f45a823, 0xb4989843cc7a73a3, 0x3d49a2326c0afb5b,
        0x00000000000000a6,
    ],
    [
        0xea6e991125fdd488, 0x4ea556fb3d0183b0, 0xe8cfd7c274dc3ac2, 0xe20307a3ddf1bd8f,
        0xfc6684582ee9be7b, 0x64a60b7937782071, 0x612fc9c865acf2e3, 0xcbb8c60c0de59326,
        0x000000000000009c,
    ],
    [
        0xe51f8aca27806255, 0xcb4da51a101b2dbc, 0x27b8a0dfe08b3553, 0x6e2a0d066ad56ac8,
        0xa751cbedec44486d, 0xf574538ec5b2ae67, 0x64e1e3c3827536e2, 0x652fa060707a8b39,
        0x0000000000000170,
    ],
    [
        0x5c7f569ad5fd84e2, 0xf84d6e126fa4bb7c, 0x7b74629c82a1081d, 0x7935151d0522589e,
        0x94fb78055ccf889a, 0xec677309792f6bac, 0x42fbece8d880a0d8, 0xd97b4881b70be7f5,
        0x00000000000000e3,
    ],
    [
        0xa18a458f1bb9a390, 0x916fc4b62062e5d6, 0x7040176be16db823, 0x25de966301177efe,
        0x2b679ddeb778335c, 0x6ecf1689862622eb, 0xa191ffb5cb8a74eb, 0x4cc26680019ff743,
        0x0000000000000047,
    ],
    [
        0xc8cd8f5d80a2aa22, 0xb73c67a164793948, 0x55abac7fff49c73d, 0xb5bc3df0833e5481,
        0xf6ab8a42384a9287, 0xbea5929eee4f0be7, 0x2e6bf0f29619ddba, 0x224ce58ab2ddfcbe,
        0x00000000000001d4,
    ],
    [
        0x140767d0bcd89552, 0x31548634f10fdf7f, 0x2c4cdccc210355fc, 0x4929888955704a76,
        0x7102e8820f1d3e5e, 0x4afc588292691f55, 0x4cff09ede9e34260, 0x49d3a32932cd76cc,
        0x0000000000000063,
    ],
    [
        0xaed91dc9263f94d8, 0x40f3c1cd20289709, 0x74dc1e9b60b5c995, 0xf08cb2a07d5bb95b,
        0xbb6d3339e642d133, 0x3c3e5d14d2fcc05d, 0xcf159316403e4a78, 0xd84be52727c124fa,
        0x00000000000000d4,
    ],
    [
        0x140ce283ea9f1213, 0x2326ce38af8d7bc8, 0x90d21012914ac8b5, 0x0b07cea5e255c0e1,
        0x93cc5e972dcccb43, 0xb89b14f2ee9885ef, 0xa35afc40dc56967c, 0x8125d749ee2e3671,
        0x0000000000000101,
    ],
    [
        0x66e566e3d3a87a30, 0x325081762cc44c2f, 0xdcaf7c52b80871ee, 0xdad02ffbdd245945,
        0xb9e691ace956cdb7, 0xdfefe49fc62064e5, 0xc322f6978c8f2c6d, 0x68a5d7a8aa88f4ac,
        0x00000000000000de,
    ],
    [
        0xb72859988df31c84, 0x0489bf6fcf37c1c3, 0x4ccd18d9e4c102d7, 0x8b1d6c45ac3e23c9,
        0x7b7d259a5744d781, 0xa0033649b4778129, 0x5c7414d99fbf3e2c, 0xfa78a7fe20774c25,
        0x0000000000000043,
    ],
    [
        0x272883fb34c28cb6, 0x22b00e9e5e7d03a4, 0x23bbacb97f4602a2, 0x27564d96c248ed06,
        0x9b7e1ce6d1c5b544, 0xb3d77b2d71182e92, 0xb18e78aade9d46ab, 0xde48d9e12e69d74d,
        0x00000000000001fb,
    ],
];

pub(crate) const COMB_TABLE_Y: [[u64; 9]; 64] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0],
    [
        0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761, 0x97ee72995ef42640,
        0x17afbd17273e662c, 0x98f54449579b4468, 0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004,
        0x0000000000000118,
    ],
    [
        0x545642a062e36127, 0xc3e4c6f71c38e6f5, 0x1d0e02c41bf9d6c4, 0x8a7a6fb6483ba43d,
        0x7104aee9cf390b9c, 0x4acdccdf2578e2fb, 0xc17af6df73b3feb4, 0x2fb789d77977fa95,
        0x00000000000001d6,
    ],
    [
        0xba3b00c422d2d58a, 0x06c351857b0e93d5, 0x78810249545fa63d, 0x1d72e7923a6be922,
        0xe38827919e285f6f, 0x3212ca84b33128ef, 0x41640a1022acf93d, 0xbf1819691f33c6e9,
        0x00000000000001be,
    ],
    [
        0x0f96137f2c91f83a, 0x1f743fa449f15b33, 0xd43b3ec0ccb4c1b1, 0x895a3be3cfeea9b0,
        0x27c3b4959eefee4d, 0xf1b4212712e344ee, 0x023afa76ff929c1e, 0x3078097686d07325,
        0x0000000000000166,
    ],
    [
        0xed22e7b467081afd, 0xda1c5f3c81df2676, 0x48f406480ad04de0, 0x8d7720d1f7391873,
        0x111178cb13448f78, 0x39087943ea49e233, 0x692f712c73d8d101, 0xca20ab46f4e7e521,
        0x000000000000005a,
    ],
    [
        0xcd2d1f04e4d1ae24, 0x099afd68e44bae9a, 0x669b9ba3a4880b2a, 0x5608536cab513fcb,
        0xfd7de6a330d8ace2, 0xebc44b8deb95e59e, 0x2302405e64969883, 0xbea96ff09b276f35,
        0x00000000000001b6,
    ],
    [
        0xf69575cebe45049d, 0x418d09354958dacc, 0x142da6f236c0f076, 0x51d23cfba83dfce7,
        0x2df0421809714d01, 0x1260496a9ecec18d, 0xb4317aa1f700b1ad, 0x86174a20cd86c341,
        0x000000000000016c,
    ],
    [
        0xce5bb75ea7b6bb9e, 0x9090358d569c9edd, 0xa8b5ec369cd0c065, 0xb2b5ac1cf81c82b8,
        0x8feb364c3ffceb86, 0x355ed9ecdf4f9f7e, 0x6f2efe425ce12ff4, 0xb23168780155070d,
        0x0000000000000035,
    ],
    [
        0x5103486e84926700, 0x1c6b82b28fef959e, 0xb309fe2355b9fa8d, 0xdb35d40e4b8579ef,
        0xad5288e08145279a, 0x92b15dbc4ba26317, 0xda42d33ed9838c28, 0xd13ae9ba313a0399,
        0x0000000000000047,
    ],
    [
        0x98dd1588d9de1e07, 0xbe9ed1154f6dc491, 0xd4605724f2b85d2b, 0xf94da3ba93aa2d3f,
        0x81229b618d489608, 0xb7e6a31ed9eaf52c, 0x787d526dab03e098, 0xc16ee426e5b06c1b,
        0x0000000000000171,
    ],
    [
        0x87101fab8e15a6b9, 0xf5ad21a11a270874, 0x5d9a90506e900902, 0x15a2f5a1d7fe9a86,
        0x7ba4fb21dce37de8, 0x7751df45ff07bfb9, 0x12089b6202345c0b, 0x46f675ec6a9ace86,
        0x000000000000006d,
    ],
    [
        0x582b79258c0a1261, 0x859c8a11788ba98e, 0x693c1e149a3ad4f7, 0xd3f4b8032d62063c,
        0x6affccfa0ddc5607, 0x63a3cd821eb6c797, 0xa94ce4ae6fb0c290, 0xce9479c1612cf5d1,
        0x0000000000000190,
    ],
    [
        0xf9f79e729bc88c1e, 0x8459190a77e9ceb8, 0xdcb44b726a41a19d, 0xe30dbe8ce243350b,
        0xa168a6a9f3adebc1, 0x421fdb0c48e22f81, 0x3cc1d22a9b601ed1, 0x226ef6f6d2b564c0,
        0x0000000000000170,
    ],
    [
        0x12d645e1fe536313, 0x14f4969e373af74b, 0xa56f032a30d498cc, 0xf30e4fe50a666b8c,
        0xfb42284e3fb31a5e, 0x065215a7efba6b77, 0x217ca76c6fa31b46, 0x13a6f6f91fc38bfd,
        0x0000000000000007,
    ],
    [
        0xc4f3956b8e0c791b, 0x68cf3903875c10f4, 0x3ff4a407c1f7f0ad, 0x3672c4658902e832,
        0xdf5d0b6796ea88b4, 0x68df74bda86075a8, 0xe6d2d0675071e56e, 0x8c7fb077c7e5fcd5,
        0x00000000000001f1,
    ],
    [
        0xe1b3574a7acb23ca, 0xadda7c9e3636a1c2, 0xfc998cf89f3d947c, 0x38ee4df41ba0511b,
        0x1f40cc1403e4694b, 0xccecf4e0800fb6d9, 0x021f708ae1665d06, 0x2bcd7975c492d329,
        0x0000000000000063,
    ],
    [
        0xe62c76b958e8181c, 0x3731bcc7fee454ed, 0x2cb0b570ee89f8f5, 0x0a38b9539a262283,
        0x46887e748c19a774, 0x1dbea5dae80adab4, 0x09fb720cb1f75c90, 0x91e0b746e723e278,
        0x00000000000001c5,
    ],
    [
        0x3da709346a145377, 0x1fb17f7fd16e2b7c, 0xef6432fcc0469077, 0x62a59a97d6660f5e,
        0x8ddc75505e2a0275, 0x2e65b1f75b88dce7, 0x0f4283da066f2c44, 0x561b9e15ce4b84a2,
        0x00000000000000ce,
    ],
    [
        0x330d4d1d79410972, 0x7e6ef2a0ba1831bb, 0xa18cc9af4f4d5b93, 0x29d8de68069c9948,
        0xb8bc009db5e104a0, 0x4237d3728d929561, 0xa126a4e8a2274bab, 0x85ba9fcba99c454f,
        0x00000000000000cb,
    ],
    [
        0x9e0d2f66306787cb, 0xe2e3c834fce146f5, 0x4b62143f2fdbe2b4, 0x19dab7745acb5238,
        0xee46bfcd7e138359, 0x29dbfa6675966b0f, 0xcde19c032d601936, 0xf7daf7b4f2aa4f6f,
        0x000000000000019c,
    ],
    [
        0xb5e391e2b9b22600, 0xd20b3d088454c979, 0x4c9945642f77a85d, 0x972896db1f169687,
        0xd3554fa2ff8d2b83, 0x57123d99bd48e671, 0x1266b6b9da59843f, 0x633ff4df9241786d,
        0x000000000000011f,
    ],
    [
        0x544a65284790d91f, 0xf71c90983f2924bd, 0xd5adb1d63e5c39e1, 0xeba20528d8cacd81,
        0xac72518ac728e735, 0x789a0bdf565cc9a0, 0x4b320c80c922bce2, 0x99b26c84e458f8ad,
        0x0000000000000138,
    ],
    [
        0x7e2ede0bb08ffeec, 0xa37176acefbed279, 0x5acafeac0b72e855, 0x4c7c3ce3fcc75bad,
        0x2fc0939bb9a704a1, 0x6bf0c5328e4b4841, 0x5b72f1f2c10742b0, 0xaa62d2889c54371e,
        0x00000000000001c1,
    ],
    [
        0xa0c846a9ed58b48c, 0xebe6013ae2590d05, 0x60c5d677da2fc481, 0xb6a0897b9252e895,
        0xb84595be218bf72d, 0xf1c527960dd1b9b1, 0x3f1583a86d38442a, 0xcda593dec4de5fdf,
        0x000000000000010a,
    ],
    [
        0x789f22f80f551d73, 0x42ec3257e7ba5676, 0x3f52c4094cc69a65, 0xafdd277df46f1eb6,
        0xaead8379ec161194, 0xdc657d191f924e46, 0xe43263451578ff09, 0x4750da5878d091bf,
        0x0000000000000173,
    ],
    [
        0x08f3f2a25182063f, 0xdea422b775992149, 0x845260b0d5cd158c, 0x6e0768e07c353c5a,
        0x5718a1c23afa81ca, 0x522f094d3ca2a17c, 0x96a361f77d93ebfd, 0x75c32db595c76942,
        0x0000000000000095,
    ],
    [
        0x4ccb1f249e925079, 0x97af5a3dc5c916d3, 0x7ef650a8e497e318, 0x0d49927842975745,
        0xcf328ffb2462eba5, 0x8ee8e88f6e360cf3, 0xe15c3f8dc77cd3c2, 0x5ab87910736a646a,
        0x00000000000001cb,
    ],
    [
        0x8e118540a87d4633, 0x3af88a0815200b8c, 0xca1806b488f790e1, 0x605032a919cd9554,
        0xf671627867d0cefd, 0xb58e8671d1676085, 0x51098dc308decf4c, 0x5a6cb932a50e312d,
        0x00000000000001fb,
    ],
    [
        0xcde7b0d13de67115, 0xe645422dec23815b, 0x286703896b445b51, 0x11be335a80ae2784,
        0x9185d3df1a64b6e3, 0xa0ccbdd0ba228c67, 0x6bc79dff3a013cf7, 0x229f4e59b464c70c,
        0x0000000000000185,
    ],
    [
        0xeb6045d192f826d9, 0xbd7c962e5facf02f, 0x87a5cfbd35fa1278, 0xfd1ff1cbdeda7159,
        0x1b0f6638a1287202, 0x861e7cbae1fcd5de, 0x33709b6bb9822a98, 0x171b15ba8b2ae55d,
        0x0000000000000130,
    ],
    [
        0xa9d573cad9980812, 0x87d7913ea7e02cb9, 0xb772f40954b00468, 0x207850e8cc28eec8,
        0x772468db7603910d, 0xb5d3125db256e07a, 0xbeb567df8b59420d, 0xb3467a5331e5ccd1,
        0x00000000000001da,
    ],
    [
        0x0a870cec12be5b78, 0x912c21c51406e140, 0x977417fdd5e13ca1, 0x9edbae8ab9e21e28,
        0x9fce45ea13b2f069, 0x25bd760b84f3cbf2, 0x29e0c3ce2489fd01, 0xe16d31c1ec62a766,
        0x0000000000000061,
    ],
    [
        0x30df907b6bf9f426, 0xca534ca162ef821f, 0x540f8dba017699e6, 0x7cddfe567358f4af,
        0x5bc334a1e8f9cef6, 0x427fd83d6adc5f09, 0x2fd7c1b8b851f4c2, 0x234d1bd4d1587dae,
        0x00000000000000d3,
    ],
    [
        0xb633df4e27c9f6a6, 0xdea08843cc406457, 0x75f688183cb011bc, 0x234d1b4ad5603044,
        0x2a156ae5b6a4d089, 0x9021af3b95e9f0f1, 0x90e987df968be7d3, 0x0821a4d3781ef8ab,
        0x0000000000000027,
    ],
    [
        0x2051179030720125, 0xee2db45c6541fb74, 0x07bbcc41aacdcd66, 0xffa2e9630a08ced4,
        0x819b5b7a7f21a83d, 0x5f857f0a44896b10, 0x6126655c197cde7d, 0x81d0f14a2962acd7,
        0x0000000000000138,
    ],
    [
        0x90389734e8b69225, 0x26dc02b5fc69c2f9, 0x37eeea93ff349339, 0x642556bfc05ec9e4,
        0xaa5744b64bd93ef1, 0xc29f3c91bfe9d602, 0x399cbf01aea4f871, 0xc02b2b1cf485b047,
        0x00000000000000be,
    ],
    [
        0x47918d08133929fb, 0xd6cf0aa92ff979f6, 0xad55ab19a37a87ab, 0x9e9d1956c5010be8,
        0x8c0bd3ea3b82de19, 0x6c87820ff3c76b65, 0x70499d39f2232ed8, 0x70dab0ee7aafde31,
        0x0000000000000163,
    ],
    [
        0x7472fd7ac36a0150, 0xfb61ab940138d406, 0x0cef5dd5b30829f5, 0xa8ea3257aef599f4,
        0x593011df7fa063bc, 0xea4c19ced774cb2c, 0xad0eeee6b85e8883, 0xb5ef126b2aba018b,
        0x000000000000014d,
    ],
    [
        0x28989d2059b1302c, 0xba90dc20f89d0c77, 0xa29e9c3ee7f4a0b1, 0x332ecd54b0a225b5,
        0x38a3b080b042d9ea, 0x6d27ff408d9dfe9f, 0x146f8b3a88a69d3a, 0x634fb13f1fee39b6,
        0x0000000000000031,
    ],
    [
        0x9cf75fb5ecb67b4b, 0x0132019091a51dbc, 0x0557fcd377225c2b, 0xe2e69807eec94860,
        0x58ccae9fe6c35624, 0xeca667a6e8c2ff7c, 0xf6939f23a37b64a3, 0x2eaabbb70d225b40,
        0x00000000000001e7,
    ],
    [
        0xd8b41e4bb0625972, 0x1063ba69b0ce550d, 0x64687d34db86696e, 0xba2b364455ca06da,
        0xa4699ecd3dc4d46c, 0x9f40e631bfe4443f, 0x0e97fbe375fa4f7e, 0xd026b0481cbdc008,
        0x00000000000001d2,
    ],
    [
        0x6637732018148fce, 0x9655f8b345c2a46f, 0xdc2952408caf763d, 0x4313d4b72816a721,
        0x6ff4aa0a50da95ed, 0x66cbcad2d4f9e551, 0x0ff11d35e6993438, 0x93dab445b9a4f5f1,
        0x00000000000000b4,
    ],
    [
        0xd59cdf5b32a50e5a, 0xa13035882c379627, 0x0894c6ebff69b440, 0x881458aaad6055c9,
        0x27d9a7d5b2f2ff3c, 0x15f33160d254ae2d, 0x6e8342f1e38392bb, 0x7d7f4576b7c8d249,
        0x0000000000000104,
    ],
    [
        0x15a79b14e40eb5e3, 0xccbbb5c75eeb2285, 0xc67c8dff5686232d, 0x8b45a2c1a83196ef,
        0xa274bf939b2acfb3, 0x35c2b5486e56b741, 0xc93963b24c1f5672, 0xbe9d6f8edf0e741b,
        0x00000000000001ca,
    ],
    [
        0x44d5bd3eb9544fd3, 0x329d747f694035c9, 0x104d2b68676f065a, 0xc8e81e7cfc4165c6,
        0x4cdad2fdaf3779f2, 0xa3e4a4625669a833, 0xa281178a21737142, 0x86f7afb87b8f5514,
        0x00000000000001aa,
    ],
    [
        0x2cba440ada687094, 0x3b478947767e75d2, 0x07c7de48078f23a0, 0xca6d86d8d7252108,
        0x5fd954fc6a7fbe1a, 0x4d552bbec9a2a901, 0x71ab270159e75804, 0x294298fa5413091c,
        0x0000000000000149,
    ],
    [
        0x31496439ef08161c, 0x265407a997e3a008, 0x2088210700e2ffcd, 0x27426c055359fd16,
        0x03e836825c39f78f, 0x380743a8e2a8832e, 0x8739d8ed792bafe6, 0x6cef07c47a912015,
        0x0000000000000128,
    ],
    [
        0x14332d38c8573626, 0xd4fe66fd4adedd4d, 0xc5d8f397bb83b706, 0x00aacee43aa8a4c9,
        0xe90383ff107c81a9, 0x6cf1fb2f18abdf47, 0x9bf5444df17c55ba, 0x8251ec253659322a,
        0x00000000000001de,
    ],
    [
        0xe15e4f0ea5afb352, 0x9ff6c56df2ca770f, 0xe0e86c68338e1890, 0x96907f1990808bfc,
        0xd0d47de2686b805b, 0x2fbfcb72b367c12a, 0x800a58141dd3d54f, 0x2f4b07b398657a79,
        0x00000000000001f3,
    ],
    [
        0x7435eaf9988d425a, 0xf9f323c7fcc441f4, 0x8de16b8c3e4de08e, 0x2e603853e495b0f0,
        0x204602204b3f0024, 0x8aff3f40b43cdb09, 0x409df7af4d00e185, 0xc681d091f1637f16,
        0x000000000000019f,
    ],
    [
        0x96630e9e8fa87335, 0xdcf938c1c7771bc8, 0xc4f3d77aa8cf3cd8, 0x931ae9adc99a5fdd,
        0xa89581d55e2bcffc, 0xd0c7c71f29758819, 0x4ef995634d5aa9d8, 0xc6de91cd8f04cdeb,
        0x0000000000000171,
    ],
    [
        0x7055c61255086dc5, 0x0622af5a3cf49868, 0x113dc4cbe695b064, 0x65b33365479ff727,
        0x156ab542336bc622, 0xf5a2ef703014770d, 0x486f74556ded88ee, 0xbb4619488c8a7452,
        0x000000000000005a,
    ],
    [
        0x250e6112195cad69, 0x81cd7e491f0b4f39, 0x9b6808db61302e46, 0xe569c108b3af7841,
        0x34d86f57c15d5fc4, 0xb3e586fdf76ad338, 0x6de8477b70bd63a8, 0xa52b119d7ec86218,
        0x00000000000000b6,
    ],
    [
        0xe17a85d7684c6e53, 0xc957477272d0d747, 0xf892866558d12edb, 0x7fb212c8c815db67,
        0x44b676eff3e66186, 0x15b57bb3998ef4d3, 0xb71f3b8e815c5036, 0x3fe9796573bcb190,
        0x0000000000000162,
    ],
    [
        0x85d79261eda953e8, 0x35894e9b5dd94926, 0x95c1cbc99aeb12b8, 0x017029fe1695dc35,
        0x36e2b978d6b13364, 0xb86b7afdc388ce34, 0x2d25b1af1e501e40, 0xf9127abdd5d7e7c1,
        0x0000000000000031,
    ],
    [
        0xfa5b847e047d9854, 0x6151153b6527d4d7, 0xf72721185bdda4c9, 0xdde383c5f17c7e63,
        0xc44040392a82edb4, 0xd1355d9781853b97, 0xcb503386b211c3b0, 0x0f9dbd602c17c154,
        0x0000000000000107,
    ],
    [
        0x12f87e99ac4906b7, 0xe752f6ea5101c876, 0xa32a9b1f2b668943, 0x9e6e6c2b07950fdf,
        0x72a31f91bbb4c324, 0x2e799c7b28546e5f, 0x7183a2daa6ff4503, 0xe2cb8237178fdeeb,
        0x0000000000000030,
    ],
    [
        0x6adbd32efbdc0c1e, 0xe3fe998b0ebefe86, 0x78099d79bc2a7085, 0x333c30095adeab44,
        0x45e4d96f07ae4b5f, 0x4bd1f0d29de88636, 0x8c7e69d7bf2020a9, 0x126a5886c3c5a340,
        0x0000000000000000,
    ],
    [
        0xbb2246c1bcd8501d, 0x86d450b3a1600ead, 0x6f5a476db626b180, 0x01f4b93e3511ac45,
        0xd813396bbbfa9758, 0xc69b8e7512347b15, 0x108defb629cd9e2c, 0x4778bb2725e9ac47,
        0x000000000000012f,
    ],
    [
        0x1855e97a55902052, 0x8a572e69e6f0db6c, 0xb1bb6014fcfa3f3c, 0xe77eb435f5b2440b,
        0x9045dd302df3f74a, 0x7853068b590ee6e0, 0x5714e1f03b9ddec5, 0x9810d77586086f6b,
        0x0000000000000008,
    ],
    [
        0xee5555b183ae6c21, 0x895c837c478467b0, 0xe6b06030dd4d105b, 0x9d9f32247636a759,
        0x68132ea4fb8142dd, 0x6109a099ff919487, 0x775c37af76a1835d, 0x4279a9c48604a81e,
        0x0000000000000093,
    ],
    [
        0x9b46685f8e69fd50, 0x2632cf3c3e47d4de, 0x44fd8f9f0238fed0, 0x2fbc3f42e03f169d,
        0x0c9df28eb7dcd132, 0x5deae7cc3d18592a, 0x3034fb93406adf0b, 0xbf5a3a75ae059280,
        0x000000000000010a,
    ],
    [
        0x8de62222099effaf, 0x2212621b1328146c, 0x05f3c0b003677fcc, 0xf43e4825fb0fc3c0,
        0x94d3b33698536e0b, 0x22c1cca4225481eb, 0x2b8668dfa9fcbaf5, 0x51e858f2c30e9271,
        0x00000000000001e9,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p521::P521FieldElement;
    use crate::p521_point::P521JacobianPoint;

    const G_X: [u64; 9] = [
        0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de, 0xa14b5e77efe75928,
        0xf828af606b4d3dba, 0x9c648139053fb521, 0x9e3ecb662395b442, 0x858e06b70404e9cd,
        0x00000000000000c6,
    ];
    const G_Y: [u64; 9] = [
        0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761, 0x97ee72995ef42640,
        0x17afbd17273e662c, 0x98f54449579b4468, 0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004,
        0x0000000000000118,
    ];

    const WIDTH: usize = 6;
    const BITS: usize = 521;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic. See [`crate::p256_comb_table`]'s identical test for the construction.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = P521JacobianPoint::from_affine(
            P521FieldElement::from_limbs(G_X),
            P521FieldElement::from_limbs(G_Y),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [P521JacobianPoint::INFINITY; TABLE_SIZE];
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
                assert_eq!(COMB_TABLE_X[0], [0, 0, 0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(COMB_TABLE_Y[0], [0, 0, 0, 0, 0, 0, 0, 0, 0]);
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
