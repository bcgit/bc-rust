//! The checked-in fixed-base comb table for `[k]G` (P-256's base point `G`), width 6, the standard
//! choice for fields over 250 bits. See [`crate::p256_comb`] for the multiplier that uses this
//! table and the algorithm it implements.
//!
//! `COMB_TABLE_X[i]`/`COMB_TABLE_Y[i]` are the affine `(x, y)` coordinates of the `i`-th table
//! entry, as little-endian `u64` limbs; entry `0` is the point at infinity (`x = y = 0`, which is
//! not a valid affine coordinate pair for any point on the curve, so it's an unambiguous sentinel
//! here).
//!
//! Regenerated and compared against these checked-in values by this module's own `tests`
//! submodule below, using the same construction `examples/generate_p256_comb_table.rs` does -- so
//! a hand-edit or transcription error in this file cannot survive `cargo test`. A unit test rather
//! than an integration test because the table is deliberately `pub(crate)`, not exposed outside
//! the crate (it's an implementation detail of [`crate::p256_comb`]'s multiplier, not something a
//! caller should ever need directly), so an external integration test cannot reach it --
//! QUALITY_AND_STYLE's stated exception for high-risk code unreachable through the public API.

pub(crate) const COMB_TABLE_X: [[u64; 4]; 64] = [
    [0, 0, 0, 0],
    [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247],
    [0xcd013f88b049e7cd, 0xe8f9257ae57fdc00, 0x3be71969fc3a9301, 0x987f256d58cff937],
    [0x59db167c5a1c3fb1, 0x98b3ce2abf318eb2, 0x2df1c41ed2bc2fa6, 0xefcc2c436ed1b2af],
    [0xfdc73e83bf780c2c, 0xffdc67942d666817, 0xc14b66dd02436893, 0x6eec95670d54650c],
    [0xaec902647318188e, 0x410bec28ca167099, 0xbf664d2f099c202b, 0x13ccca3455fa625c],
    [0xaca2fa084862c5db, 0xddffc222a1717f8a, 0xab839a14e4e09fd2, 0xf86a9078980330f5],
    [0xd3b22809cbdb1c78, 0x5591c8eb30f6cda4, 0xb6e28740bfe80f8b, 0x0f74342a40e7e7e7],
    [0xeb0421211a6b665e, 0x802f779ea7f6803a, 0x47501f2a3c0804c3, 0xa263919b4945a1d4],
    [0x2b52c47d8b21aa51, 0x0f5036295a7e870d, 0xbaa9281488b45127, 0x27d6451ec402e050],
    [0xd8142dff5788c0f6, 0x89bf5229247fde25, 0x5c971ddb14e2280f, 0x785b7e9109904e3f],
    [0x73b7c5502195a979, 0x2d7ed474b8dd5813, 0xc0b9ecd2e104e9ac, 0xdc90d975a2bd0ed8],
    [0xe4b541b6cf9a3ca9, 0x1c65058708b49b2f, 0xb95f91b3f552641e, 0xbddc23ac5c301277],
    [0xcb4dc35b1703406d, 0x4fd3afc975dac54c, 0x112321eb29f02878, 0xafb18d2fad6b225f],
    [0xff0e1f34e834a3c4, 0x0d59b6ae1c4ab236, 0x10eb194a015a211b, 0xed6e13e03892ddc5],
    [0x2dc61e1b336aaf40, 0x897e87bd4251f5b7, 0x2fb320236511b370, 0x460fa9cf2341f499],
    [0x3cd5f4e4a9aa52df, 0x18c452b1b42a627f, 0x6dbc4189d991ece6, 0x45a511c97f608bf7],
    [0xc6e4b6d0016476ea, 0x71b9a7e5d4ec2510, 0x1975b71ecbe490d2, 0xdf6b472fb52acd25],
    [0x86a38d54c219c20b, 0xafcdd2cab50a4733, 0xf4cf879772096638, 0xd949caa224ce0e94],
    [0x41e9420620b4d697, 0xa10fd0d929fa0df9, 0xf11eb0a776022c38, 0xffcb7ddca5621c63],
    [0x48d63748b56bc451, 0x0544de81a939440a, 0xda24eb0b664ec19c, 0x4fb6e56241f42bf6],
    [0x546a08e7f119b8cc, 0x03b7d5238afc696a, 0x0a896132459f70b4, 0x57a46257a86a9116],
    [0x6dd25e26e83cfa35, 0x61e44da01ff3bddc, 0xb7b67b02121733fa, 0x7c48f60dfcd798ca],
    [0xf41e030756c8815e, 0xbaf647e37d37a2f1, 0x7791eb36fefafbf5, 0x158262fb35b7f606],
    [0x9d7f749e7fd58ae5, 0xc78ba26337ea57a2, 0xb5c051274f5ab5b7, 0x6fd3f54d5f2d643b],
    [0x5b2911dd4d6a3def, 0x4bedd07cb96008f1, 0xee748a6fe36e7d64, 0xbfc499344bbf5cf4],
    [0x75ea69cbe76ccbc0, 0xc9736051a762deb7, 0xa720d4c6af2bff4c, 0x8e4c7b10be6d6dba],
    [0x9cdda82186eb7815, 0x8c003612ce413265, 0x8bce1fab91b577f5, 0x0f3f29ff488f730c],
    [0x6c10cdd296bf8ea5, 0xe28c488ae8cd868f, 0xba9226c346442d00, 0x9125caedfa1f864b],
    [0x0d17ff3970514a21, 0xd2a7b5badadd80ee, 0x941e33c38126c8c4, 0xb9e156d01d57c1de],
    [0xe0cb10291b20d599, 0x7b1ed83d10a5fba0, 0x7d5fb32b04007713, 0x93bab59079c82639],
    [0xf197735bc05131cd, 0x0565076822beb567, 0xdbf2b189f7f55b1f, 0xaa144c82132c2614],
    [0xf0f679f10b79847d, 0x3719a8b66bb19be6, 0x2ddb6c3ddc7f43d5, 0x2800043ada0982e2],
    [0x12416a5c5f3f5b80, 0x58e903dbda522422, 0x18cc80f14291867e, 0xb2035cf87a152c2b],
    [0x1caab0ba6aa2b49d, 0x6a75a7686f7fc502, 0x6a5ea5a857ea120f, 0x998cd5f9db6bdf96],
    [0x40429d1bfea77b0c, 0x4651a4dc595e9a31, 0x8900aab1e712693a, 0x90ea776784bf612d],
    [0x7a2f10b25ac0b3db, 0xe6deffa0f0b98928, 0xb4b2939be6b0b01a, 0xa03e1d520a3f2ca8],
    [0x6890b26ce62da069, 0xa57023197c586265, 0xe64e19bf865672ab, 0xa66503f5a07d9893],
    [0x74814e1c89806e19, 0x9135fc8df9ec85de, 0x0ee660a609afd25b, 0x943de3b76740a284],
    [0xa3c9d614c4e48158, 0xb26b4a98ae8fc508, 0x44ef8be038b68e18, 0xbe9cf596db271fcd],
    [0x0abfa3ee2d00715b, 0xf3f65dc1c8297b47, 0x4199b65900669e85, 0x7588df7f23c09567],
    [0xc0b161fbf77cf152, 0x243c4fed8ce30043, 0xb1b4a2d0050e20df, 0x5a61a286c34999ae],
    [0xa6bcc84d016f613c, 0xae5ce038c2ec4e56, 0xad80f035f8be76b4, 0x00456c5c84642dd4],
    [0xc79e3178966d28dd, 0x67ba868689f8a2c1, 0xaf1f9c6d4acf8d42, 0x2d2b4273e0847f7d],
    [0x2a675b54620c767b, 0xf1235f085ae6598e, 0x3cf6a1cd48a35e9b, 0xf11a113ed8a1b5f8],
    [0x1c12b5cbd84a37de, 0x56d66db4c7b1ea1a, 0x852be4202ce31e9a, 0x17be9c2de40faf48],
    [0x422618c90ccf3981, 0x7f5f96108dab3936, 0xca4ab7508e0a6a28, 0x8266e2fed5bab133],
    [0x54b44d3300b16f35, 0x59988ef3002d5707, 0x256fe1ebd0494f94, 0xaef841697f710de4],
    [0xb246602701feea35, 0xea17f580317c61f1, 0x8d71eaba786aaceb, 0x7de7454a1cc47dab],
    [0x6033d113edab9cb9, 0x1df87ba3e69d45ee, 0x93436236e4d65a03, 0x5893f6f93f98a508],
    [0x1c1dd91a68c28f39, 0xfa494334f35669ca, 0x77b40abd51abb743, 0xee7400bae7873a25],
    [0x3276c5a4c52427d8, 0x66958243f5a34b64, 0x04166798f36e0d92, 0x43e33927c6e9e63f],
    [0xe17f627b98a174fc, 0x5ebce1ff4dfa285e, 0xc95fe23d54c5f925, 0x5ea59a093188ba78],
    [0xce46a1650758035b, 0xb33df1ade070a0c9, 0xbf01fb38686934c9, 0x1cba6257f0f16ed0],
    [0xbf93cda851a03105, 0xb14f4a607be433ed, 0x0aa4c4c3fa1c97a1, 0xfe1a6375bced726e],
    [0xfe702b4b27ade63f, 0x5df11a33a105673a, 0x0d33cb80a362b9ce, 0xa7bb42f5855bb209],
    [0x252566b651ff89bb, 0x453c333edb973ddc, 0xfbcd5a09d83f2cc2, 0x187818ec3121dbd5],
    [0x2096d6762da7eb49, 0x6e04768efb775e41, 0xc3349c3daf24f76c, 0xe6db6ccade0c90f6],
    [0xeaf7623ce4976dd8, 0x92528b1ae29bd0b4, 0x78158ecd645cec2a, 0x3265ead8b11325e9],
    [0x8e35bf16b3571976, 0xe2eb0c63346864e7, 0x2b7b57e07e9b6c7f, 0x3157cf6f70b35a98],
    [0x3c3d8c9b6c38b3da, 0x80818302754433e3, 0xfe68ab07e29e542a, 0x81a25a61d12cbb2c],
    [0xf3f4e3fefcf866b9, 0x152a0807e18b0ad5, 0x2ec4c7061b9b2e7b, 0x41d7e92bdadd006f],
    [0x651ebb868916a00d, 0xba4d2da9001e908d, 0x5f2b68e61684fcb0, 0xc3ff8d7510ac6edf],
    [0xb9e437f4afcc2bef, 0x4f1fb2d63ada2b53, 0xe6c0e12dbb580c9a, 0x2518373433c7546d],
];

pub(crate) const COMB_TABLE_Y: [[u64; 4]; 64] = [
    [0, 0, 0, 0],
    [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b],
    [0xb7254bbc6efa35d6, 0x47b4605207aaffdb, 0xe860ebd60007e39e, 0x8e92695694ec505c],
    [0x17fe07f197b25513, 0x468245333734a589, 0xa5384a77ed34f543, 0xf3684f9c8d9f3863],
    [0x089ec1a1edbfcd32, 0x79ab66153a07ff89, 0xfc281de065ea0105, 0x14bb5350997732c2],
    [0xaa84c23105421c0c, 0x6b6475216cdb0d71, 0xe90446b1fb216a5e, 0x4b5ba5a5af46893d],
    [0x6890f24cc1dd7dcc, 0xf75dccfaea6efd98, 0xba2612b8ff9a093b, 0x20347d0c2568653c],
    [0xd2968e87351c51f2, 0x65c5c581f5e17b5e, 0x6f58f02a9d994e2e, 0x531c0b00f5c1ec07],
    [0x9ee4040030bcdcfb, 0xac3f83df4c00efe2, 0x2e9d3c9de60d60c5, 0x873200bd2aed20fc],
    [0x5c96ec145567432d, 0xcdeb98290f4150c7, 0x5d91740ccdeef566, 0x2a58fa5e1be9e583],
    [0x445e45192e7e6f0b, 0x8789440e4ce293dd, 0x96b84f57c797be30, 0x6b44059dfa3ea32d],
    [0x9fb552034dd6eb2e, 0x50d554bbc01dfde8, 0x4cfd3277f0977a30, 0xc87ce232815374c4],
    [0x519d070004daba43, 0xc003dcc38450cfa2, 0x73a1c8f54e48efde, 0x7d0ca9425b04f761],
    [0xddf58273f1776a67, 0x96889755f6b96c2f, 0x31a8d66322208ffb, 0x5ed81c10fcca4877],
    [0xac88df04fb3f678d, 0x6f0fbf44544026a9, 0xcde8cd7a619cecba, 0x02f322e580d9a8cc],
    [0x03e63b79cbaf01a7, 0x937e123f44157434, 0x9d59226e809e4a1a, 0x18d6f63a41775e62],
    [0x7b52bd12125ec16c, 0x5a919b27d22955ce, 0x3fe3337fcb625ad2, 0x73be0ec773ea9b6d],
    [0xf1738716784055eb, 0xccc7b0b3b87d399e, 0x3c9a13371bb51119, 0xb42639e1a88fd593],
    [0x678664ae96f9ae13, 0x00ef5ba9c984de46, 0x622abc7f8d549567, 0x673ed50057db924d],
    [0x24e37b1b0927965a, 0x8d9fc102bd2c199e, 0x862de75e907f3f85, 0xd39851295a9c778e],
    [0x21b2c80e66bb5d6b, 0xa4123924d25bd41b, 0x6f95f5f2bce2d418, 0xa92327764d6d91d8],
    [0xfaa56fefbb314c65, 0xf4e61f4074795c6d, 0x1a3c5652437850d6, 0x7c4b127d6621ec11],
    [0x244d234a090f5154, 0x93b7f2fb8cae33bb, 0x158bf2f6426d1516, 0xa8a947a8a801e86e],
    [0xf6c3225532dce9e5, 0x6c7cd4ce361b4780, 0xe5be5e703f85288f, 0x4c281aa3c98e624a],
    [0x3428e3112116b8ce, 0xc52d1d2471b28987, 0x87f70be98299421f, 0x0a5fd09864f49798],
    [0x55c6f62d8e74750f, 0x22639f8748919902, 0xfa01aa94958a248f, 0x2743ae8aed51aa40],
    [0xaf5c0efe2f128433, 0x834cbf1fa1fe85ec, 0xd321c5a62685f018, 0xb5b09cf6717a5340],
    [0xebb08063e6960d55, 0x1a9699e2aecbf467, 0x6b1564a44ce5761b, 0x08f00ea581382996],
    [0xf33bd66e2e21b4af, 0x12dc553768dbe58c, 0xd9b85123e5353044, 0xf4925bde07bc6b60],
    [0x220d500dea8105ad, 0x6a2aa4620202f3ae, 0x450056ab3dc96356, 0x506ab6aa452142c3],
    [0x977fa5a649b97d9d, 0xa35923333551254a, 0x8f277388a9f7a3eb, 0x36aba935e3026e2c],
    [0xf41cbe14b3822251, 0xb1ce72b2ffd0afbe, 0x01a14d18844743fa, 0xc1d89fe3923739b8],
    [0xfe5b0083908d9eda, 0xa87058dbb8513ae9, 0xb6c0796584a4dc3b, 0x0f99174667e82909],
    [0x7112569195c80ede, 0xbfe02568af97c5b0, 0x603e1dc58a14e493, 0xf12f359c749680de],
    [0xd2d7ba4c467184a9, 0xbe178e5425c03723, 0x6bfc1707bc389ef3, 0x3256a8a07b7d9fb3],
    [0xbdd104250d02f2b6, 0xf5583bccfb4d594f, 0x757544625ba7b6a1, 0xd1a321d3101e86f4],
    [0xfc7795312cbead24, 0xe8362908d30fa3f9, 0x6f29d6f4f23b00bb, 0xea1ad22febb82e0a],
    [0xe4deb7c021fe4743, 0x3bae847d7d7100be, 0x1769fca7e17b1d29, 0xadba60ec320afc60],
    [0xdba0327f622227d9, 0xa524c6d6d4c486e8, 0x217fb7797134581a, 0xafa3b65fe4254a7e],
    [0x737b653e8e6f95ad, 0x73dbe6ff9b9e4d0a, 0x4b772a8ca4139f59, 0xa1f335e566c67e8a],
    [0xabdf62fa868d3227, 0xa0844d348099a8fc, 0x3361b9c03babbc72, 0xbb0357a46d5bf03b],
    [0x8c7baf6870214eb7, 0x975bca7df2c261fe, 0x03c6df311ed91ae8, 0xe8cfaaada1380d38],
    [0x0ef7079fde3648c8, 0x7bf0b3ab68d0a170, 0xa85c96b856c684e3, 0xfd39b0f291d65c88],
    [0x1d9e1a9069130cec, 0x95cb10fd9383e7b5, 0x73438a2644cc71ae, 0x37eaeb101ee4ea49],
    [0xa401985d1742a887, 0x3f83bd07b6a73d9b, 0x3c7307a082736067, 0x64a1a66d1f12fbb6],
    [0x735b3ccb38cc8797, 0x1f8d9d8034b1093e, 0xd8cc6e86e75b81c0, 0x6914bf943fdbe697],
    [0xfaa7545bab5500f6, 0xa91edaeb5d994d86, 0x0a5b194b67fb462d, 0x089cfd68287178ce],
    [0xca38fb1f8bd49604, 0xaec9daaebfa0b15c, 0x1551365e642cf6dd, 0x75b8b0fa160e8fff],
    [0x10b69d62ff1b1266, 0xe22cc59bb9ab079c, 0x9a57e43f42b2d441, 0x22340fece8c85f85],
    [0xb3832e15aad54fab, 0x3277ff0d6bc7365e, 0xe8301118200c4fb8, 0x26e471bcd4e9384d],
    [0xf15d9bf5ed2309d9, 0x8a90d13f3da8785a, 0x7e4fb96c1be8b67d, 0x196c1ba4cae9ed81],
    [0x899aed76f0ca8d2b, 0x43b89cde0af50dd8, 0x805ea21e5951e13b, 0xe210daa428413043],
    [0x6615bb542d2d8163, 0x37be4a1e5db03d95, 0xc51b56924fc47762, 0xb994ca42d142931d],
    [0xe538a9b6ee93409c, 0xd82429a14a6b38da, 0x1488770da5c215b1, 0x4ade1f8e891d7658],
    [0x4db682870409c304, 0x08fb9622ebf37af4, 0x677003ecf6abdff4, 0xe6b2e8723fb7cc37],
    [0xfdcc6096c95fe575, 0xff0e08d72351dec6, 0xa3323ff5bb6a5b28, 0x2caa2dae89f7a2ab],
    [0xaea1b45f3b46b949, 0x4231462355f753e0, 0xd59ab00bb09991fa, 0xee05650d0ae0c8d7],
    [0x98aa01f5a416fd87, 0x84c3270b781ec427, 0x37680f04021034b2, 0xeb90fe3c654bf735],
    [0x1ca27af8c04780b7, 0x14ef08452465867d, 0xb45c18872feefe38, 0x7c4d96bc5d8730e9],
    [0xfec24c145ac49ea5, 0xc20c56906b1a32ae, 0xeaef7b4e345fa335, 0xb4c9655d4077475f],
    [0x559948a78f685647, 0xe14ebcf683a56574, 0x1a6066327a77db0f, 0xf49d838f0892ce93],
    [0xff0a8a791d4b6ef7, 0x02344dffb2aa2f47, 0x1726d704357a0681, 0x4ce6bb77c1bc85f4],
    [0x6997e3eaf5c49a61, 0x8f4ff372b1a4dc68, 0xbea7ce04c95c2db2, 0x2accb4f49d10f761],
    [0xab12d90fbfd92fb9, 0x2cb9b9b3a185ae46, 0x2a0c7a7e9ce6f49f, 0x531f307fb48f21f2],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256::P256FieldElement;
    use crate::p256_point::P256JacobianPoint;

    const G_X: [u64; 4] =
        [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247];
    const G_Y: [u64; 4] =
        [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b];

    const WIDTH: usize = 6;
    const BITS: usize = 256;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic, per this module's construction: `pow2[i] = 2^(i*D) * G`, then
    /// `table[idx] = sum of pow2[b] for each bit b set in idx`.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = P256JacobianPoint::from_affine(
            P256FieldElement::from_limbs(G_X),
            P256FieldElement::from_limbs(G_Y),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [P256JacobianPoint::INFINITY; TABLE_SIZE];
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
                assert_eq!(COMB_TABLE_X[0], [0, 0, 0, 0]);
                assert_eq!(COMB_TABLE_Y[0], [0, 0, 0, 0]);
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
