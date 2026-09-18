//! The checked-in odd multiples of the base point `G` for [`crate::bp512r1_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and RFC 5639 §3.4's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 8]; 32] = [
    [
        0x8b352209bcb9f822, 0x7c6d5047406a5e68, 0x50d1687b93b97d5f, 0xff3b1f78e2d0d48d,
        0xb43b62eef4d0098e, 0x85ed9f70b5d916c1, 0x5a21322e9c4c6a93, 0x81aee4bdd82ed964,
    ],
    [
        0x5d4abf882ccb8d94, 0xf56e34abfa9ac720, 0x4780ae53e1853d62, 0xc1f6fb975ceecade,
        0x09c09cefd830151b, 0x907c80ef3bc24593, 0x36cdd42543f20afe, 0x08dd87e12b0a4cc4,
    ],
    [
        0x500d6f7d9d9aaa5c, 0x17bc4f43d413540b, 0xc393c273727cf25d, 0xaadc73e8d9472bb0,
        0xae0ff1c9461693d2, 0x0a4abf8dd044a3c1, 0xe3c9bc8c2bf17781, 0x8672838ed83a55b9,
    ],
    [
        0xbecedb316e1d30fa, 0xb55b556c926f2a3d, 0xc1df5ccd7685cf85, 0x8ee59581616f83f9,
        0x40ce49b6a78fc195, 0x3bcb810dfd2826b5, 0x783b62c3ef7f473c, 0x74a4bbc7d1a22ea7,
    ],
    [
        0x973c40b0fbd92c64, 0xa0bcaae472b75daa, 0x71d60de7d7a6fb36, 0x4492eb78493d9671,
        0xd9cd604c8aac2275, 0xdcc04fd8188cbfdf, 0xcfe49337d863265d, 0x595b061e1aa360e8,
    ],
    [
        0xa1eb911c7353e301, 0x9e29656152501da4, 0x289f56a5eee69428, 0x12082c66a9ef7c94,
        0x780f003411642093, 0xa0f3f87b3053606d, 0xe5359be155a58d80, 0x9018d91a9ef584e5,
    ],
    [
        0x9fed7e841e9a3ef1, 0x74c799aa8c04c090, 0xb67b5b9c96c4e3ad, 0x17f711874b8f5ec2,
        0x5c371d5c62e68e9a, 0x9aea9422f84b88dc, 0x5c38e8e42f1993c8, 0x661dafd56964ecae,
    ],
    [
        0x66b47ddf2d5721fe, 0xd9a221da4d35ce21, 0x50fdea5ecd222628, 0x1006bca2508be5bc,
        0x21f05845db650dbc, 0x864f46510c00c7a5, 0xcab2c7b55991b47f, 0x77bea740013fc519,
    ],
    [
        0x4633f02af2e5904e, 0x82b69de20e152e71, 0x2e893e5ef66f8f39, 0x86c02d4b2e082217,
        0x6ae78e6f6e3c6e2d, 0x56f7c50386366654, 0x71e963451a74e855, 0x7e8ec7d1a5bc63e3,
    ],
    [
        0xac9bf8a861653328, 0x24f8d90a4cad66b6, 0xcf40e4483230c621, 0x75ba5ae7e60f1de7,
        0x649e56cbf76666d1, 0x1e6f73a9e0de7706, 0xf1bc383341fcb4f4, 0x5fa0c675339433e1,
    ],
    [
        0x303626d1fa158c1e, 0x656079973d1ed6e5, 0x1bbd991b1862dac6, 0x4a0217dceebfa7d7,
        0xda130d566e059b61, 0x105f057fe5a4578f, 0xdf516dc53e0c9ad2, 0x89c3f72f8d12832e,
    ],
    [
        0x969d49e509075319, 0x6c501dd070b6d60e, 0xe98af9cac2f0788d, 0x01d8b0541d51f710,
        0xce49a22c22aa773b, 0x17eae42154dc622e, 0x02a03155a9fa145d, 0xa2016a80603e2f70,
    ],
    [
        0x9463bad3b32f7e84, 0x4498fdfdf738d903, 0x77a018be9f77f288, 0xaec2367dad248030,
        0xc54491ac984bb270, 0xae05b12c2a2d6910, 0xd857cf8a5d858d7f, 0x6bcd80cf6403d095,
    ],
    [
        0x211200d41ef2dbd1, 0x4d421be9021efcdf, 0xb21f06dfcd5affef, 0x10dd934b5ed331d4,
        0x870f281c8f869afe, 0xe3e1e88b70c89c47, 0xf1f5662b66ed8e9c, 0x29ce5366e6aa2bbe,
    ],
    [
        0x505b17e3aafb1c73, 0xfa33db5607a037f3, 0x4fa488cab8d11be2, 0xea1d3dbb87674eb5,
        0x102b4e800cc433ee, 0x4ffe1d1c71d7b90b, 0x759af1f7c28eda71, 0x8b1cadae1645d48e,
    ],
    [
        0x7d126bf535d8db28, 0x53c8a025b81eebe7, 0xbb0a16b0b0f57294, 0x83de23fc3efbb330,
        0x81814d53ccf861ef, 0x1eb5a6221df34f16, 0x0b831add9a5aca78, 0x017f2c8f9c76e54c,
    ],
    [
        0x102154e35b6f0e1f, 0x1bfb7ba06ba1b048, 0xdccb2d2d0460bdde, 0x5c964b8f4bef47cd,
        0xb8d1a28e7f4dc306, 0x6277ed0057de7fe3, 0xfee290555f0b13e6, 0x79b00304cce8b7f3,
    ],
    [
        0x3f5cb20ada9456b8, 0x1d13ca2c631a3797, 0x7a2a3b649a0aaa68, 0x04c3b7c624243ba1,
        0x18cb4ef474808b81, 0xd2c21628441536be, 0xa2e91b0d421ac1da, 0x10a4c8f9f50fd4a0,
    ],
    [
        0x1b24a1c56fe1941a, 0xcdf29dcaa4572c44, 0x9340ced846de478a, 0x4da8f41d415d4934,
        0x9f25446b6cb4de22, 0xb62a0cb22a4c6ecb, 0xd5200a3dc99cfb9a, 0x158186e7d0ac1874,
    ],
    [
        0x747d2ec171a65853, 0x2462ab88f85d3912, 0xf7d0597d7d47e5f4, 0x01fe17dd3d4bff64,
        0x4b2b2244cc0a404a, 0x45d54199b7786f50, 0x762388a0f9f1a184, 0x94bfaf82cc18a657,
    ],
    [
        0x22ac7c6e28a0492f, 0xb0b27b6bf0b0c5c9, 0x66d8e34befaf2736, 0x569429b0e8fbdc16,
        0xc189e5da5396294f, 0x562c6ba7eacc934d, 0x319409a4b3a9d13f, 0x7a8b9d1e1aa42de1,
    ],
    [
        0x4e262fb1e9df618f, 0xf61b0c2874a6f96f, 0x0fdf9d3ca7d5a03b, 0x67fb947628145c0f,
        0x6c31be69f57b1bde, 0x849022b8a03cc33b, 0xf8104510faac810a, 0x058fa41066f8cd35,
    ],
    [
        0x890b29dbd092ee23, 0x6a272ebaedb8ee70, 0xbb2d16948e0181e6, 0xac7af3e7b5b668c6,
        0x43d48e5c8361d46f, 0x4df5023131ec940a, 0x92618b52ecd754f9, 0x2b7c188fa7ff9fb6,
    ],
    [
        0xda76b7936242c769, 0xbe4983fb4ffb491e, 0x5b75d82c9c21ded1, 0x89303f79fde816bf,
        0x93e41685754c71cc, 0x329574b737bb1dd8, 0xc3effb75ddf74b56, 0x9e0a451f50d1fb25,
    ],
    [
        0xd65193332300ed9b, 0x5d8489b59ee166fb, 0xd01950844e867ecc, 0x82716249a41e4af3,
        0x8c458e673597c950, 0x5218af3541b88884, 0xe59d65779dd0a4ef, 0x8d001732b8386361,
    ],
    [
        0x63c419b19c42dbb4, 0x4f9d981e0dc5edbe, 0x9ac5d8ef17158db8, 0x47b1fbcb4e6143f9,
        0xd48970aa9b7fef47, 0x6fdd83e67c5536b5, 0x098ead28a40f14f8, 0x7a4d965c0391815a,
    ],
    [
        0x5b35e0346f98e025, 0x3531acd7b4ee413c, 0x78c512947909ef05, 0x903cbcfe3524e59a,
        0x19a5ccf6d3f997fa, 0x91a0af321de97712, 0xfae3059f30a459e2, 0x81f7f38b0ca3022a,
    ],
    [
        0x3090557814c9e668, 0x5cbe71832d62452d, 0xe05386f839803196, 0x4e27d3216cb59599,
        0x038e3d801d352e87, 0x7b82a9046adca6c8, 0xede44e0fdcfbb301, 0x6290831bdedf66b0,
    ],
    [
        0x16eb282f0e26f3ea, 0xe6e83ad8fac91978, 0xa50b0c06131c394e, 0x09ee51315f805928,
        0xdd063a439a29a40c, 0x0fb4b082a2801a19, 0xf559c8b5fda613d1, 0x713b2f6c827e5b15,
    ],
    [
        0xdf9b5de1c78b84ac, 0x4235623822b16814, 0x375c37732584ffc2, 0x43bd0c1ac08d7801,
        0xf91d21e6dcf1f344, 0xc17d7aba2e600760, 0x9c2c8508cdd8e504, 0x6650e7aeb003aeb2,
    ],
    [
        0xfaf6c30996ba2b5b, 0x63b5301ecca640cf, 0xdd8ee4fd6fabf753, 0xe67639bf11913dfd,
        0xeeb77a9533ea933e, 0x3f40596c341f5630, 0x60bce0116590a8eb, 0x0780ce8523d0ae7a,
    ],
    [
        0x38638c9cce7ffc55, 0xa9322c197da0e86b, 0xe8d61ca0ec012213, 0x115a137415fabf7f,
        0x07b77747baf33081, 0x9c5d4c012d3ceef9, 0xb96e1c8629f8c07f, 0x5156adced9997afb,
    ],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 8]; 32] = [
    [
        0x78cd1e0f3ad80892, 0xd1ca2b2fa8f05406, 0x5bca4bd88a2763ae, 0xb2dcde494a5f485e,
        0xa000c55b881f8111, 0xf209f70024a57b1a, 0xc0eabfa9cf7822fd, 0x7dde385d566332ec,
    ],
    [
        0x5cdeafba05b02c37, 0x8cce5bc75d8de649, 0xfebfcb69c0f37c5f, 0xacdab8eb772327b3,
        0xba0b382e1716d843, 0x43d903b4a6334c4b, 0x756ff0067376fa75, 0x026ef5c6e1dab71d,
    ],
    [
        0x62f8a1c2b51f7f35, 0xdb58bb174dcc0c77, 0xfa11d3cc5b06c0df, 0xa5a88c91f28d09eb,
        0xe1b69903a8863d2f, 0xea9d3a0a7a668f1e, 0x52b7a5643c936c09, 0x151d93c1de2ed9ee,
    ],
    [
        0x1b031a2415c8761e, 0xdbb183a1fff72bda, 0xe9a929aead052089, 0x007dbc9e60fd30af,
        0xe68c55af183e3430, 0xb7a2e873ce087973, 0x17495d11b106ae2b, 0x73d3c07ba1bf2908,
    ],
    [
        0x904d51202dd6a26c, 0x0ac0cd086e05b92f, 0xd2a2cb6fa4d26a1e, 0x44b2058b82bf9cab,
        0x88a0a9fbde5bda3c, 0x611a61ccb943a004, 0x2a410f997aa69880, 0x6a3fe9031a5472af,
    ],
    [
        0xea4749c79c5f39b2, 0xd134521b4ff7d351, 0xfb571e45527fdf79, 0x06cc328709eefba9,
        0x26709006a1dfaac0, 0xcb5d48a02b86241f, 0xf9e48f7c68dd11bf, 0x30b56337977ca5c1,
    ],
    [
        0xf250dc39c61c556c, 0x4d84dcea90a1f58d, 0x19b39c3eb5447e71, 0x768ff6c863f41a25,
        0x151618f233bdfc03, 0x567c143080f6b686, 0xb3088f186faa284e, 0x91c294bcca5a4acc,
    ],
    [
        0x49a4fe7242c58aa1, 0x33ab304fadbbe334, 0x41a4c84c80e3d9d9, 0xd2a9885975db218f,
        0x2de9aecd4db65dbe, 0x9eb524baa6808c61, 0x273c6f76e838e4f9, 0x15b48320c1a04c2a,
    ],
    [
        0xfb4118e0663c185d, 0xc7dc76af0beec3fe, 0xcd19de87b4ea3dc2, 0x4b8aa9c481570d9e,
        0x0a1ea8b7bda4434a, 0x95fecb9a53add1f7, 0xa087ada1fe365cb8, 0x06b2a67269285258,
    ],
    [
        0xda4f480a2b2e1414, 0x9f3a16da9ddcc559, 0x11544dd5031a227f, 0xa097b83f9e611903,
        0xc9d7f4a3e973fb44, 0x19ec9382352b2300, 0x39ca172334288e78, 0x7205c29f436390ce,
    ],
    [
        0x8a6e017443af9cc0, 0x7157dc468b7b961d, 0x3a2b978fabf13a26, 0x414918db498cf95d,
        0xa447acde5d328385, 0x0722a0e1d71413b4, 0xd60b3ddb4f8e26d4, 0x085a88a71275a7f5,
    ],
    [
        0x4bc4e04766b2d6dc, 0xa880e625ee4801aa, 0xbb12805a9cc2190d, 0xf709c3906dc9cad0,
        0xd588a15f9962ff5c, 0x519a0b14d8f0670b, 0x311214f093546346, 0x757702e3f163c8f7,
    ],
    [
        0x16358adec9825713, 0x883589b5f1de4cc3, 0x88f5ea39f5b43f5c, 0xdba9cbb60c559ed7,
        0x9444d62a11cf9e7d, 0x29af23a230b91ed0, 0xc9e558cc02703ca1, 0x325e3b5a446a0a8c,
    ],
    [
        0xe94bd5b1d3137aa0, 0x69c623628317df8f, 0x3bc260ab8312f776, 0x42f49c623f3772bf,
        0xa8f6677f60f56943, 0xfd1c0f1b72c56679, 0x43e9082618c23fe6, 0x6432b5cd342338d3,
    ],
    [
        0x76ddf6df23e3022b, 0x359c1249a81525bc, 0xfd0dc499fb4bc509, 0xe6a16cbfd9c0572b,
        0xe9aae4b69e6ad24c, 0xcc77edf608a25dbe, 0x78f7dd40cf18146b, 0xa89818ba6a6494ac,
    ],
    [
        0x1d7d8c426fbc0514, 0x6a61f9798fda995e, 0xc0d413c1d1327a76, 0x8a3d024cb84b2fa4,
        0xee75fcbc79a5a85a, 0x78966d2f86f1c2fb, 0x690f0656e2e6cd53, 0x3229e04fd2dfd0da,
    ],
    [
        0x45151d9fa02df8ea, 0x82335cb555322db3, 0x867c89a3134daee6, 0x041ee264ea8923fe,
        0x1e1bf782a33410b3, 0xaff0badfe0b00077, 0xa8b0f225c99c6cde, 0x64b23a99f243c935,
    ],
    [
        0x2ab0b85f36acfe52, 0x0f3ca4fd7d1e64ee, 0x193b47e6b481d6d3, 0xea807b48720ec5f2,
        0xd4997da426b66a5e, 0x88d3d03b7bb10c17, 0xdcef5568bd74d15e, 0x9db8016e59ea3516,
    ],
    [
        0x7e7fbf680ec23f31, 0x3024346db8337e9d, 0x55c9eded125dc470, 0x0ed224e77f5e6466,
        0x031501550e4aac3f, 0xa17f0e219bc671f9, 0x27a3bbda7b6f916d, 0x3865aaca06756578,
    ],
    [
        0x5a11320a12bf40d9, 0x6c4705c545c09fb8, 0xb6603d2ba3307cd9, 0xeb6b3c521ba039ab,
        0xaea8b174d0957ff7, 0x20852aceceddae30, 0x03dc2a22ab90d72c, 0x077e7de8dbf8bf1d,
    ],
    [
        0xb9ec5c2c63ee15c6, 0x903999f8161cfcc3, 0xfe9a9d8dc8aebe6d, 0x529faa430bffbd64,
        0x2f35412b19a54192, 0xbeb4d71ce395cb43, 0x797409d1001c3cd7, 0x798b61785b623b5e,
    ],
    [
        0x4afecb12fefb01ac, 0x1e6e9069597db7b4, 0xa9707e4b41802457, 0x3d62e8e3e94cd132,
        0x9084da1c25eeec03, 0xd17b6ab1816f5d47, 0xfa787156d1a865bf, 0x8536ac25f5b9801a,
    ],
    [
        0xc23e0d1131523bee, 0x5db90b4d2dab3c39, 0x12bdee37e1933b29, 0x24a81c1d000e7e7a,
        0x9644ab761851400f, 0x254288c6adbbe4e5, 0xd2333add90575470, 0x270b58fd8ddb2447,
    ],
    [
        0x0f5e450a34e71f8b, 0x744e1a3d1ee317f0, 0xd71c96423f610a6e, 0x78506947f64386c4,
        0x73873d4efc817278, 0xc3d828b25e8f1da4, 0xa4ddc128da101684, 0x04fb93ebaa1c02fb,
    ],
    [
        0x1c72bf3812e95f21, 0xc9eab9679727356a, 0x322a0235d7b36071, 0x6587663c2e1a8c06,
        0xd4ef9bb50628b1ab, 0xee15c736267745a7, 0xfcaa2834de84f935, 0x66691b2aae64991b,
    ],
    [
        0xe0b81dabc7a99b97, 0xc51251dcdbec2702, 0x46f1457afdf97344, 0xc8779f0997ee9f34,
        0x2681bf58d93aed44, 0xd9bb1eea95b8b1a4, 0x7eeb72c5d46f8fd6, 0x4cf57b66f4a98326,
    ],
    [
        0x8967560bc3c2fd7d, 0x06828c4b80608cc7, 0x2f934cfccabb7fc8, 0xadd93a2304b79344,
        0x3f3093f65168efd8, 0xcf4093bd36146e00, 0x2ef0cc858b14d3d3, 0x1f578dc4ddb66dfd,
    ],
    [
        0x587e9e9a66632d34, 0x292544a030d592cd, 0xe8b0ef01d22abefb, 0xff90df5d283eec02,
        0x66c89fa311c41617, 0x0b61a9e0807ad00f, 0x78893bf6bef530e5, 0x513613bdc1ff37d4,
    ],
    [
        0x6b3f4b8c0b1f6ee1, 0xa2159c852bffce0b, 0x9bc839e3fb2e22f8, 0x39d20cea0256cd91,
        0x77fabc576ba41582, 0x2cfb90f5fffd8ab3, 0x51c05946dc87171d, 0xaa6524356cff292f,
    ],
    [
        0x741114bf7442c847, 0x2789116bc42351dd, 0x90e5ca7d8c3b7d7a, 0x018f871d527055a2,
        0x90af1aec4bb109f1, 0xd29e7d46744616b4, 0x36221d3e19998454, 0x26884506891976e2,
    ],
    [
        0x2ac11915752a463e, 0x4651fcf9c9ffeb58, 0x9ce8970604326060, 0x591b0982c65653bc,
        0xa96ed6c7fb75192b, 0x9ca69b4d5af033e8, 0x1e1ca93515609b39, 0x7f238102bf71dfba,
    ],
    [
        0x8add896b45b74a66, 0xbd57fb04a5550de0, 0x72310307d27ce1e1, 0xd4eec5d101929d96,
        0x23b6ab98106bd881, 0x5421eea261fc3d87, 0xb5a0549c79b7ca09, 0x1eeb61365df768bf,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp512r1::Bp512r1FieldElement;
    use crate::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::bp512r1_point::Bp512r1JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = Bp512r1JacobianPoint::from_affine(
            Bp512r1FieldElement::from_limbs(G_X_LIMBS),
            Bp512r1FieldElement::from_limbs(G_Y_LIMBS),
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
