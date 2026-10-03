//! The checked-in fixed-base comb table for `[k]G` (brainpoolP384r1's base point `G`), width 6,
//! matching this crate's other curves' choice for fields over 250 bits. See
//! [`crate::bp384r1_comb`] for the multiplier that uses this table and the algorithm it
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

pub(crate) const COMB_TABLE_X: [[u64; 6]; 64] = [
    [
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
    ],
    [
        0xef87b2e247d4af1e, 0xe826e03436d646aa, 0xdb7fcafe0cbd10e8, 0x8847a3e77ef14fe3,
        0xa2a63a81b7c13f6b, 0x1d1c64f068cf45ff,
    ],
    [
        0xdbce90c1cff67b5a, 0xa15109d050f83b66, 0x6786308c6d245def, 0x14377653cb5449d2,
        0x929fee2ea24eef97, 0x542f5fdb7f38e86a,
    ],
    [
        0x1d6bd641548ad893, 0x034b2dfd22f13be2, 0x5a5273f033e35501, 0xa3527fca26303fc1,
        0x314a2ad59b176ed3, 0x2e1d0703e56bda86,
    ],
    [
        0xbd4219127ede4cf0, 0xfb6868cc8ba66e80, 0xc216a9ed38a58c5d, 0x3d8f6ee85649482b,
        0x4d6dddc0370f0a15, 0x1e1ce71e1fd0110f,
    ],
    [
        0x4db104322e289294, 0xbf550d7643448225, 0xfe4ede4689ffe35b, 0x27ee811a67bb225b,
        0xd02cdaae7ae254c8, 0x5fcc8b6eaa909a74,
    ],
    [
        0x11ae4e3b923c900f, 0x13d0fcae9624402e, 0xaed4ac03ebea5ce4, 0xad0fc2f8b1ea0018,
        0x1cbcd25d7700f4fd, 0x2fcf74dd73039e64,
    ],
    [
        0xc85b5e4b38ce17c8, 0x08627c9d610a0e60, 0xd726177f7198f025, 0x820770f03cfad383,
        0x1565b743095c4729, 0x22ecf3fa3ea7a90e,
    ],
    [
        0x6bf550b04d994b04, 0x02a353bc5345a946, 0xe18a5d2d02c7f727, 0xdf4ddaccbb1fdc04,
        0x8974b5688e81af98, 0x2369dbb6397c99f1,
    ],
    [
        0xe96b8c7bc4dcecf2, 0x97d9ee5ad31cbb2b, 0x9d41b2f75e305d64, 0x626441c61a0fceed,
        0x4b661582e3e118f2, 0x7ca039720424e29b,
    ],
    [
        0xf57b4bab12814202, 0x5993c9ec22243468, 0x94dbf68f85e0793e, 0xf29a3297aac80aaf,
        0xd5467a9f997b3042, 0x592f6079c13ea154,
    ],
    [
        0xa1887b696fafd72d, 0xc1b547a230e413af, 0xf23c1c8addc0d20f, 0xcf6d8bba4cb38cf9,
        0xf14f3c6ea8a1c76b, 0x82016f03c8974a94,
    ],
    [
        0x22bd1e659415536d, 0x64fbc7fcd5609eaf, 0xaa84507650c3ae51, 0x43a458129e8107e3,
        0xb79a2f005755a48f, 0x860349cb087a89d1,
    ],
    [
        0xbdb166076a427950, 0xa14c099265625345, 0x9b2df4f603c3af06, 0xc99b69a2d941cae8,
        0x7661aae18da6b24b, 0x7ef3beb6124dba11,
    ],
    [
        0x34739ba22d274bad, 0xc1a4157902e1bf4a, 0xc96e13d9302e8b7e, 0x457fdf7eb669756e,
        0x37395c031556809a, 0x877d4b7e33312983,
    ],
    [
        0x5760d7bb03601f94, 0x61e99571dd623c72, 0x90c581685f7a5bb0, 0xa5284298b9b5af1e,
        0x20d7b449118e290c, 0x03cabaa130d23e9b,
    ],
    [
        0x0741134c03240074, 0xb78fcf8ef053b378, 0xecda8220c87b35b5, 0x7c4e4f34a327a8d1,
        0x68b242c5d5e83a85, 0x55798b8bbb576379,
    ],
    [
        0x4e3849cafbfd9037, 0x118cfff0ddc6cfc3, 0xb4e9335fbd9d69d7, 0x23401cac3d821947,
        0xbe0077144602c740, 0x395c663a77f205c9,
    ],
    [
        0x4537b39cbe4e22e8, 0x3dd59c12ced99b0a, 0xaf11f84b3a097d7f, 0xee4e0824f2d7f07f,
        0xead691d94287872d, 0x4aa61d005d9ef614,
    ],
    [
        0xdfc80567dc28efbe, 0x0fbca04985c3780b, 0xf57ad4cfa02d3e10, 0xe2996eb360fe9336,
        0xe35eaf49e704ad62, 0x3109189ea6ed7a54,
    ],
    [
        0xcb75c6d4670366c9, 0x7cba9d4146cc5b21, 0xe3ccfa7731578e10, 0x80ea978e3ecd782d,
        0x9b42f8c8fdeb6ecd, 0x56bb773fe76a5043,
    ],
    [
        0x0457f1ccc2c6732a, 0x5eb682702773edb6, 0xa6eaf4cf3aacba0b, 0x5e2c080e8fb1d699,
        0x07f3a10e2f8fe317, 0x28f60a299b7cf51a,
    ],
    [
        0x68f01f444e069d41, 0xe10822ffa6101371, 0xf64852aacdabcae6, 0x43afea6d7923890b,
        0xd6b5bca66855541a, 0x408eca247d71047b,
    ],
    [
        0x554811720120dcc3, 0x9ff03d62f87bc41e, 0x894aa3522e3dc2e8, 0xcef8215e4653e2ce,
        0x3a324226a98fc7c2, 0x03199a4b8da0a6fb,
    ],
    [
        0x10ba98863c18097b, 0xc32a4840f5164490, 0x7ce704ae62a4a4d7, 0xa48c4c964933a977,
        0x40a6146e1adc9af6, 0x3bb2d9c42f8150b8,
    ],
    [
        0x0c935a6cca116def, 0x9830e42faf2696eb, 0x045c1f30c64cc135, 0x6c63eb35fce8b359,
        0x964b3650fcca1d9c, 0x312debaf5b230ee4,
    ],
    [
        0x032b04fff6e21b60, 0x01ea6bf5471accf6, 0xf6eb38fe3cf3185d, 0x2d62c022d46c3145,
        0xb72c042800bdcbee, 0x69abfd5af715b98d,
    ],
    [
        0xd96bc43978cd1d99, 0xe35daa2fb8c74581, 0x4bdbb224a36e8c33, 0xaf8a9bc7f1d92d69,
        0x75913740b92ce167, 0x2faf2b0323b52c81,
    ],
    [
        0xc2a3d1f2693d4017, 0x8d3d63a3dc971b5e, 0xa0eeaeae7837c04c, 0x1f8ab8107f64007b,
        0x5c73f1e8548d4f8f, 0x3ded37333192674d,
    ],
    [
        0x504d414b9b45addf, 0x29e934357fab5d1b, 0x874af3443478be73, 0xebf90beec4e3defb,
        0x4174b8324816865e, 0x55e381bdba7ceef2,
    ],
    [
        0x8ebff5fcba1c1313, 0x1cb95a1ba6bc7111, 0x1b4a649a07fad6cb, 0xcd41794b688e00db,
        0xd963e85703b4fcc6, 0x2e164d7bea3e14b9,
    ],
    [
        0x1445beb558025db8, 0xac322a4d908eefad, 0x368f330a5c759948, 0xdaebf31fd4956cc8,
        0xeb25f320914ce4c2, 0x8134206f29eb95f1,
    ],
    [
        0x8fa269c78a553306, 0x01bf5e77329bac74, 0xdd8d066bf36baca8, 0xeecd692c2ff2c76d,
        0xdc00da176ad0418d, 0x3d717023b2a4ed70,
    ],
    [
        0x228ba6db10550345, 0xca431dc978ae174e, 0x208d8447d449354e, 0xb318b4bcea2f95f3,
        0x893d65f589ae48d4, 0x635075d1202bf286,
    ],
    [
        0x5b92e6137e5e242a, 0x10094a30fee7da2e, 0x02c4de54cf1c51cf, 0xd84e05a5999b6f5c,
        0x5ba718a3947d1805, 0x2d943ac7feeb3ea7,
    ],
    [
        0xcbb04a4bdfde7d43, 0xdf85e2c1948c4eb0, 0x10ef709bb5eaf04f, 0x2cd92cf35d39c256,
        0x8087542fcc2e1c0d, 0x7784a350b5c772b0,
    ],
    [
        0xf4c850c15ff897be, 0x5482c61dc4afa2df, 0xa93cc0023525181b, 0xbf2611bf7f5148fc,
        0xefd9450dd2ea8fe7, 0x17b7a3e3d5a6fc61,
    ],
    [
        0x62a1110e2de6e191, 0xd183e3e632a8e274, 0x6f672bb7cde55650, 0x8ee1876d65c9ede5,
        0xa3fa0e539afd8e50, 0x01fa8423e24a4c49,
    ],
    [
        0x72bf673237927cc3, 0x14a9d5ddf49bb744, 0x57c8e11c99ba5e26, 0x0e7146f4c9dd7991,
        0x4c6f13496828140c, 0x8687485bdc573053,
    ],
    [
        0x243969a697f16db1, 0xec26a13bff99410b, 0xcb1b4a1280952f95, 0xcfda2daeaa51bfea,
        0x86d4493652b31c0c, 0x1a5c3ed33a1fc199,
    ],
    [
        0x42991703c34edd18, 0xb72099a30b9e4f7e, 0x6a0549b1ed596731, 0x0fb3a1bd1c60ce98,
        0x1221409543a6811d, 0x5d131a037b032b08,
    ],
    [
        0xedf6ca05053cec0c, 0x633c16125102cd48, 0x7cb2dd7b43b3eba8, 0x91f5e4db41905900,
        0x2f7c835a2a180ed0, 0x79632ff10da137e1,
    ],
    [
        0x9043705dde010b2d, 0xba2804b36438c1e3, 0xf3dcde4dd71d8893, 0x65829075e753eda2,
        0x200636bf16a0d16f, 0x730aa91a585eb5c9,
    ],
    [
        0x4eebde11d879d54d, 0xa83474da6aa4461c, 0xaefeee14f5d3bd1e, 0x94f8654371a34c19,
        0xe2d82590fa356c72, 0x4d0343a1968434bb,
    ],
    [
        0x75c76717a4917753, 0x44be92951fa6038e, 0x245114b7a030e570, 0x846f4ab5f50e6c21,
        0x3b8c8ef2d93d2e79, 0x2c5a41973796de48,
    ],
    [
        0x01ff5079644b2ffc, 0xf3e73b3957ed36d4, 0x52a0c0d635ea85f1, 0x02461c22cc3a89ba,
        0x5562691ba1b07a6c, 0x880d85186c8ab857,
    ],
    [
        0xb4799b45153f2064, 0x7981504dc89088a5, 0xa495645a3ea21ed7, 0x054d6343cdfb7b98,
        0x23833772bd1cfbf8, 0x3ec97938bf9ffe2c,
    ],
    [
        0x227f2744a50b06f8, 0x61134fcc0fac7430, 0x1d1ca54997bfb1fd, 0xf877cc0f7b68648a,
        0x96f69c844ef939bb, 0x2bf92da1e26dcfbc,
    ],
    [
        0x44cb5fad40c0fac6, 0x5f0c4f1a3b4f147e, 0x6977a2e82c4f6a50, 0x60555559d375c138,
        0x30a5d4716bdf41a6, 0x68f110e6d45a333c,
    ],
    [
        0xca81622a38d26672, 0xa781a3285e20c8c5, 0x45877deaf1a43120, 0x2feb636f09992c8f,
        0xa2debe061ada7673, 0x422d3039752e0929,
    ],
    [
        0xd48e40b4dd48e221, 0xd049cefdc69d6f0d, 0x90996e8386454565, 0x1809b82b81b09c5c,
        0x81c646274b120122, 0x575ac42f5870ac4a,
    ],
    [
        0x59644f166c2a37ca, 0xf7bc9ab490a3ce5a, 0x186e3a1d63553827, 0x2c89452299aab437,
        0xe83ea73da68c7cb7, 0x12c6e3a6dc420670,
    ],
    [
        0xbfe37a90c7c42a75, 0x32c3344635133ad9, 0x5c660bf167219be8, 0x1b58799cf86079a6,
        0xf88524c61a8f1960, 0x88fb61fdd27a25c4,
    ],
    [
        0x987443988d21eb29, 0xe3a6bb08d814cc88, 0x9eddc3186af298c4, 0x6204f203a09138c7,
        0x747013fbfde8af7a, 0x1200e04a988793d0,
    ],
    [
        0xdf9d3a10d71b3803, 0xc256969cd5161c62, 0xebe1ea373cbc8e0b, 0xd91cb7a90d4f5007,
        0x9275ec059416bae6, 0x1804bed44f3cb49d,
    ],
    [
        0x3bee2d61ef36168e, 0x23f71213a0885f45, 0x5b01074a4aadc6a9, 0x6bd5bdeb4fb174b8,
        0xbcd74f06a271f957, 0x6afb98e0484d8bff,
    ],
    [
        0x8c58fd46b5d9b25c, 0xf831513f569d2a7e, 0x99e944753aed5a51, 0x60baf65ac0ca9f42,
        0x4d1a31b76f396c61, 0x85de59d8b54393c9,
    ],
    [
        0x47876bbb7fc8cc5b, 0x5057387d693c21c0, 0x6d48a5533c184c52, 0x156dc4db4564c321,
        0x2d34b817bbd1cc49, 0x3d4a28a0fa71696c,
    ],
    [
        0x6b923d562e6e14e9, 0x54cdf8604c0d88c0, 0x3486f0467c4bc710, 0x7ab27b82a4fe6528,
        0xc9a060ca2cdcf710, 0x0109c6381553b4ee,
    ],
    [
        0xea7f72a9bbef2f55, 0x2ac3e7b912b734b5, 0x6e710c7742d91df8, 0x8d910356a75901ec,
        0x13ef3e303399916c, 0x70f166549a5ac987,
    ],
    [
        0x93ddc881f814962c, 0x133ca295520a70d7, 0x59bba31fcaf99771, 0x28d380dc534900b1,
        0xb477956db3c31fcc, 0x1f01e3bf4ba1af17,
    ],
    [
        0x76d668e83158eeae, 0xcad49f09b7482ed2, 0xc95d4364e75ca934, 0x6dff68ab509f589e,
        0x7d8dbf12ba2d8887, 0x7355a475b36fdfd4,
    ],
    [
        0xd5e25ca4985d0af8, 0x7452d9a2108ec042, 0x087763cfd74bd2d9, 0xda8059eb21199363,
        0x2ec2dca012b45805, 0x02608b187ba04463,
    ],
    [
        0x100263974a137a68, 0x64eeb98f03061ebc, 0xcedb70a9898bee68, 0x32628d70c9817b15,
        0x55be3af9f846da75, 0x0ffaeb62977a9c9f,
    ],
];

pub(crate) const COMB_TABLE_Y: [[u64; 6]; 64] = [
    [
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
    ],
    [
        0x42820341263c5315, 0x0e46462177918111, 0xe19c054ff9912928, 0x62b70b29feec5864,
        0x5cb1eb8e95cfd552, 0x8abe1d7520f9c2a4,
    ],
    [
        0x543a4b582c0a8325, 0x06b539da86540019, 0xa9e059588394aab5, 0xca174329b65a54d8,
        0xbbc43d7c85646c64, 0x7811a0441ba94648,
    ],
    [
        0x19f6a4e398af7a51, 0xd2473b4051fe7dec, 0xa4cb8fe2c4ec88fc, 0x9aeb504e2d88e230,
        0x043a7ff45e945413, 0x63f80fbde11c07cd,
    ],
    [
        0x766f59437b4f2813, 0x49be01e073609367, 0xb65023f5548367ca, 0xb47aa2a5e0ae2047,
        0x9c0602b7f8767c97, 0x24c5e0596e369143,
    ],
    [
        0xac87377dedac4016, 0x42048c4c80b1f898, 0xc0356930ad2c98c2, 0xc0f08c442f002e32,
        0x5ba160cdd7075816, 0x73795e05037bfbaf,
    ],
    [
        0x9048d117445504a1, 0x29103c110e905f68, 0xffbb7066cf091c51, 0xbd09036e96d6cda2,
        0xe361ce28b5db4d74, 0x28a74cb3ebbb074c,
    ],
    [
        0xaafa71582b2278da, 0x834fb0b36ace3000, 0xe765c223a92095cf, 0xbb44808a5b03cf55,
        0x81eaedd5f791f85c, 0x172aac2510165b40,
    ],
    [
        0x0ee188bb14504c85, 0x43f143e6500cb2c1, 0xcd41cae93334ce66, 0x127368f10742fa8f,
        0x93b08775925ff0a8, 0x6f47b11daa3b124f,
    ],
    [
        0x02e1628858a2512b, 0x30824ce91465d258, 0x7a1a31ae87ace1dc, 0x2bc37a851e964f85,
        0x7b089dc0f0bb86f0, 0x68ef9180090353bd,
    ],
    [
        0x6342eb9b66eee47d, 0xb21242539d98b348, 0xdd77d3338ff852e1, 0x53cfbb1921561cc7,
        0x97379ed34f76fd7e, 0x471e5e9cce2e8380,
    ],
    [
        0x2622d539a9121874, 0x38788d9dbdc0a747, 0xde30d0df7fd0b3a9, 0x7c1da8ec96732537,
        0xdfcfd9dc6665d191, 0x2dbee2ad377bed95,
    ],
    [
        0xaf4bfde410969a85, 0x2b82da08a2362198, 0xd9247a906111cb2b, 0x8e9467abbf8fb817,
        0x946df98ae471b321, 0x6502c8760ec7ce30,
    ],
    [
        0x26c9ce072292d9ca, 0xe5f732db917ca162, 0x3b70d9fb6d4b496d, 0x1d81665e4c4efb1c,
        0x58ccd9b700e1b3a5, 0x30fd2039c48b36f3,
    ],
    [
        0x263a81d7ace67bc8, 0xfa7680474e276a91, 0x2b8161eed090294a, 0xe80480f78f7bbb59,
        0x1ca490df21d700d4, 0x8924c236bc1359e8,
    ],
    [
        0x41e5032f44643729, 0x065f1aa2ffbc424a, 0x2aad24e004ab041d, 0xf8533e1f6717453d,
        0x03c254571bb30fed, 0x30fa9b1bc4f8d359,
    ],
    [
        0x7f53b9e7bebd6493, 0x633561381757deb9, 0x15fd404b9ea99a00, 0x13f6df8a11170217,
        0xe049a0802cfa693f, 0x0d21c5552054bf26,
    ],
    [
        0xb8e5a1b2de17e61e, 0x66d4f5d89dec71c7, 0xd0ba18e75e42c6aa, 0x17d7fb265a6821c5,
        0x75ec348aba5c0026, 0x3565e853af3c9cc3,
    ],
    [
        0x0b1b68ec18e66047, 0xbbd4bbc24adb9058, 0xe8f3398716c7a875, 0xe138d24b664a7c50,
        0x58529d1d89a3a365, 0x7d1a84751e938267,
    ],
    [
        0x9485b8dc449405e8, 0xda157550c237b714, 0xe83e91a9b20fc6d6, 0x157326a125ad81b9,
        0x138f767c61d1f1fd, 0x0b48a714ff4adb06,
    ],
    [
        0xf5aa9339c44aa4a3, 0x1c422eda1459b571, 0x4c956480ede2c307, 0x268146125518634a,
        0xee70989517c9ec74, 0x695d96ff8859f3f4,
    ],
    [
        0xafa315344717eebd, 0xdebba2e74888befb, 0xc10f376165dcadc5, 0x78911c3aa2ad67fa,
        0x28136e413a0c0755, 0x61dd14aaed7ebd73,
    ],
    [
        0xae76105e763b5441, 0x635a4902354ef7d3, 0xd547dfb4a55bad33, 0x5068006c55876a95,
        0x4c1f391f232f1094, 0x7c66a84398032ed1,
    ],
    [
        0x0c60eefb1e6dabea, 0x1c79105dc53c56b6, 0xf902ef719f41bc25, 0xfc329b88d0c436a2,
        0x2c22e639175dd49c, 0x279c4abece01267b,
    ],
    [
        0x92158c384787fa39, 0xe7856c2eb7ffd20d, 0xc5ec98b236845bda, 0xaa049a7e0c4492b2,
        0x14d51c738494c5ed, 0x7a4ee1c2fc32b3e8,
    ],
    [
        0xb6234a74d7b688c6, 0x554fa629bbe266ef, 0x9414a06e687e6fe9, 0x0df65babe8d4733b,
        0xade99500243ce046, 0x003ff2d0814f0d37,
    ],
    [
        0x829023eb7d7dd4bd, 0xa3d879460d27a2ab, 0x33c3d5e42691b7d1, 0x599a4de400d65214,
        0x566765953c0132ed, 0x87a10c2084d089ab,
    ],
    [
        0xda84a910205a9d2f, 0xcab2e91320893061, 0xa61f1803eb526eb6, 0xc7699287351c9e6c,
        0x72836cc6af88c9a1, 0x6fb69934547ad5cb,
    ],
    [
        0xd26e6a119c086656, 0x30c9437ff8f3fd2e, 0xa2a6b7d784eba398, 0x832626c3de4ad701,
        0x43af1289c5aa38a1, 0x6686e32ab51a45a0,
    ],
    [
        0x14d5b8da84fa6af8, 0x0b1a2e1bd58a9fb2, 0xd5e65bffe2610c5f, 0xa3921b5387c1620e,
        0x280e0c6ad1009054, 0x78a0b5443bb52e8b,
    ],
    [
        0x2f5871127b4f1cf2, 0x518d43dff81ca4ac, 0xcc6db38fa525f5a3, 0xb9e37b7a3ac2682d,
        0x12e31cf33016b926, 0x471f4e421670eae0,
    ],
    [
        0xad8b647e13e5152d, 0xfa9e377e180dbca7, 0x52777a2df72082e8, 0xa56fe67adba229cb,
        0xbd4fe6bc5c50c6a0, 0x30b73dc5e8d59f1e,
    ],
    [
        0x3f508154cd49b977, 0x14725315bb3306f9, 0x346e09135acfba88, 0x799c0d02f296cd4e,
        0x86056b6ccd86d677, 0x876ccd183a19910e,
    ],
    [
        0x2ddf7de02c5ce6ad, 0x05b6189fce3e073e, 0x6d1d42fad5f0f89a, 0x2f2b0ec9031d6c41,
        0x06e163b4a5521843, 0x546016fdc4d90ab7,
    ],
    [
        0x6fb224391b1f16e7, 0x991b56ba2309e571, 0x2a8952998b85d110, 0x1a0b553bdafd75b9,
        0x246a8086ffc8ad1e, 0x715170e957f3ff5c,
    ],
    [
        0xfa5d8bb4a9afd1b7, 0x5ea556c38a52f6c8, 0x83774205eaff523b, 0xb8c3c48672900829,
        0xd5c66716f1f8154d, 0x8183ec718fac8775,
    ],
    [
        0xe30a43f96e28e9dd, 0xc30a9c29c4c63108, 0x69454106d72553ee, 0x63882a57e4266744,
        0x7524d0d1a19bce77, 0x6f88821c0a71b23f,
    ],
    [
        0x7cf43ed18149feb4, 0x6f3eb80defe07245, 0x2c7260ce5f0f003c, 0xcd5a6e0703d8ccb7,
        0x5fca1f4e50353a27, 0x7f056ebd5588ea58,
    ],
    [
        0x2eab4eeb51013a79, 0x9f71c30121cfcd10, 0x71d12400e2fe6d78, 0x47b5d2f682d53915,
        0xc6b653a242ccfa48, 0x89061bd5cd036241,
    ],
    [
        0x15a7a9c82bf75173, 0x03b06641987f4e12, 0x2bc3f8cd42c01d91, 0x41cc8bcc7d9141cc,
        0xabc51856ed76ae2a, 0x1f10657fa3066aab,
    ],
    [
        0xe09279097e45558e, 0x50fdcac85da18f1f, 0x4f54f4ac1f474f73, 0x12401b63d6a856c7,
        0xda5065a94045fb19, 0x389aee4a9b1ab933,
    ],
    [
        0xeccf671f6ffac021, 0x899bf9f4bb453498, 0xb98f641d67fe69f5, 0x8aadc7b3d8bf39db,
        0xf639fa28f3ff938c, 0x89887a2685c3f9fa,
    ],
    [
        0xb3fa384c8b94f2ac, 0x654b4c8e95cc03f4, 0xbdeb2383746fd7ec, 0x985ef24bcb97358a,
        0xed3135c3af1f87f6, 0x1eb9098e1503bcd0,
    ],
    [
        0x42f259ca2f3b3bf1, 0xa39072d8742448cd, 0x3d19526f8c744283, 0x2f4c786863419e40,
        0x9fa852386bb69453, 0x686e6fa193253081,
    ],
    [
        0x07e433f43701e5fd, 0x9e37d0607b767812, 0xc886816c1991b120, 0x80c99a2d4b7c4173,
        0x02770d5e84a2d7da, 0x2354178d542d162a,
    ],
    [
        0x07e87f4ee950b6fd, 0xd89a114bd15c5b92, 0x9cec9c5174562596, 0x6a103acb8ab67f55,
        0xe65949e901073360, 0x446332baf22ea5c6,
    ],
    [
        0xbde327227dcdbc46, 0xb0559d0597656d18, 0xe16217733f46bc8e, 0x40690e99e8bc5649,
        0x7d2a488b15eaf967, 0x4b9982565256d24d,
    ],
    [
        0x5e0501315790c495, 0xe37ca498bfbb1ecc, 0x3f9a39cdb2a0e389, 0x52b598897a603492,
        0xac5a8f043a3d208d, 0x590f9c0949b626a3,
    ],
    [
        0xed4ed0cd912c4299, 0x434f13ed1ebf188c, 0xc67d4cdae448825e, 0x7a9eb2b82356d96e,
        0x4bd2e317b493d442, 0x2457344a424caa5c,
    ],
    [
        0x318cc3175ac19b41, 0xd460ab3d4d948d58, 0x629dae430f1efdff, 0x41b7aa1b20f3f28e,
        0x71e33b90f4a45b9d, 0x010b0965bd7278f7,
    ],
    [
        0x3fea803384f5ca88, 0xd11f71a1cf81ea8e, 0x85fff84c5d4e454d, 0x5993450a81908a50,
        0x380b424c2ca3f02b, 0x48a23ad7bc1adb2b,
    ],
    [
        0xeb7c31475d3d8c55, 0x4104137e46ee8546, 0xf6f5742e438b3c9e, 0x26030829078e88ba,
        0xb543e808eb899bea, 0x186f73d9fd670717,
    ],
    [
        0x016dab4ea28f2df0, 0x2796b012efc71244, 0xedaff0e9f860e3a9, 0xe793f8b750207d08,
        0xaf338c9ca92e6bc7, 0x03bfd6bdc6db9d7c,
    ],
    [
        0x3f032da29c692e97, 0xee2a85c1b9f3fe79, 0xb741bfcdb186fdce, 0xf1cbfef3219ad8a0,
        0x84a2a9b760047895, 0x8bbd51542a661ee8,
    ],
    [
        0x2f84f1f40f034308, 0x35f19d80414a5a69, 0x758a59ddbc4ec094, 0xef1377feca60f859,
        0xbf189ff64132d431, 0x77ae2f7db656e6f1,
    ],
    [
        0x3aac520da310bac4, 0x303a07e636e0d011, 0xdd4b2249aaf0807e, 0x4024cd891cabc7ff,
        0x4996456db3fc2a82, 0x19b4c43f52dbe463,
    ],
    [
        0xb4f726cd1ab0f453, 0xd1c91535c7e3e798, 0xe96dcf5d5eea6143, 0x821a99455815032e,
        0x3a54ecd8023ed4e8, 0x7611baf1b3a9cd0a,
    ],
    [
        0xdb388dea399ee8ed, 0xb7ee1a80cdbb9ccc, 0x321122d9bf45a0bc, 0xf5699fc0d95c7cda,
        0xd5b9354e79a68abc, 0x1028b8a13e9a8bcc,
    ],
    [
        0x5815ad5c79adc16b, 0xb6fb56de6c1ecd9b, 0xa85a4518d8ab38b5, 0x0c8389d6c4544048,
        0x48b2665e184bb945, 0x70bec8ec1118331b,
    ],
    [
        0x30357d716eb72c64, 0x2f63992dd1ef0d1a, 0xaec2c6c92daf31e4, 0xf3acc45480dfc019,
        0xc831f79684a06be3, 0x6a7545417a7ce293,
    ],
    [
        0x542d9e1e9c71f5ca, 0x0263d99828f20d37, 0xa78c69447157a541, 0xd058bf0840f3b157,
        0x25d6c1fbb2412b14, 0x359178ba867312de,
    ],
    [
        0x6f3713b73992176d, 0x321b17caa771435e, 0x83daa0ef78b0b9e7, 0x1fb6a2850ff2849a,
        0x3c4cb9456e2e6572, 0x223696772b8c6afe,
    ],
    [
        0xf92e19d5da0e2196, 0xd953b0814573801c, 0xc7a1d1a292c579fa, 0xcc87acff091cb84d,
        0x740476bd7800ee3b, 0x58489336c25345a2,
    ],
    [
        0x659e27463c3d03b2, 0x40e9af25d51c08a4, 0x1f7c8af459dc69fe, 0xe34e0c21997a9afc,
        0x1082aaac5f85cef5, 0x3f53f37690695783,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp384r1::Bp384r1FieldElement;
    use crate::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::bp384r1_point::Bp384r1JacobianPoint;

    const WIDTH: usize = 6;
    const BITS: usize = 384;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic, per this module's construction: `pow2[i] = 2^(i*D) * G`, then
    /// `table[idx] = sum of pow2[b] for each bit b set in idx`.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = Bp384r1JacobianPoint::from_affine(
            Bp384r1FieldElement::from_limbs(G_X_LIMBS),
            Bp384r1FieldElement::from_limbs(G_Y_LIMBS),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [Bp384r1JacobianPoint::INFINITY; TABLE_SIZE];
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
