//! The checked-in odd multiples of the base point `G` for [`crate::bp384r1_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and RFC 5639 §3.4's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 6]; 32] = [
    [
        0xef87b2e247d4af1e, 0xe826e03436d646aa, 0xdb7fcafe0cbd10e8, 0x8847a3e77ef14fe3,
        0xa2a63a81b7c13f6b, 0x1d1c64f068cf45ff,
    ],
    [
        0x7d7cc85b3035f11f, 0x3c11ef6596a3b889, 0x3ee1b6fcc7463bbe, 0x3df581348c6949f8,
        0x3b17452b6a27ebf5, 0x7b63205bf00ddae7,
    ],
    [
        0x2cebab9fd2412dfb, 0xfbc1247651c2770d, 0x0ac96ddf237f84f4, 0x465848a4b4fbb608,
        0x5100dabea7b5f59f, 0x0d3ec4dfce264772,
    ],
    [
        0x0c76dc7302bcf181, 0x44ae054e91e8aa16, 0xff47be522f7f7582, 0x747781bc8956c1e5,
        0xf7393081ddf04a64, 0x6460f955efdcbf3b,
    ],
    [
        0xbe9a6fa4d102fdcc, 0x2ca04884153f3ca5, 0xcb8050cb12ff55d0, 0xa92b638fab9b5123,
        0xaba57e45a1b99b3d, 0x318ccbf708397f07,
    ],
    [
        0xe1ebfa3ebd501097, 0x019ed5e75838a2e1, 0xf650cdce31a1f42a, 0x9504ee698d6ce046,
        0x8222a33a24cfcc95, 0x29d17c36e8fac6be,
    ],
    [
        0x68724ba7654b8a97, 0xe866314f4cfcdecc, 0xee6435aabfce8519, 0x4f4fe2951e9b2fc9,
        0xa4ac0d1499008c7b, 0x746f20945a91d52b,
    ],
    [
        0x7ecd1fd73d60e639, 0x313c2f19665476b1, 0xee00e1e96d82bb00, 0xde83d467f4a6e8e0,
        0x992302c3873505a1, 0x08d2819ad4b10108,
    ],
    [
        0x4b857eab44faa702, 0x87e9b66563d3af2f, 0xca9d72edc36ce5b3, 0x388f576ac92467f7,
        0x268c0a910c4f9601, 0x4d0bfeac9bfd1564,
    ],
    [
        0xc425f5660ea7b13b, 0x5dc8ae531f363c8a, 0x63112206ed0aeefa, 0x247c7f08393c0d9b,
        0x62655a825de14c70, 0x0fa18c9d90660371,
    ],
    [
        0x5fa49a306129c5a8, 0x002a1f492e05a1e2, 0xe2f7ee1ab0a0f04e, 0xd1cc2f930bd09ce4,
        0xa3837062b081fa95, 0x76b1435dfe9593e9,
    ],
    [
        0xde197ba7ff56e4a0, 0x6d74b82c3e3bcb4c, 0x01a3095802f41f23, 0x1ce3bc2c1bbf9809,
        0xf6848e7c1537435e, 0x512d6e4cab98bcec,
    ],
    [
        0xef26e5109e68c1ad, 0xc508fef7ab757246, 0xef25a686d306e678, 0x41db4bb1e7a2d007,
        0xcf4a5a1cd62d25cc, 0x1828eed92586c516,
    ],
    [
        0x350c9b20a68701d9, 0x548141489f31bd76, 0x6335948783dcc764, 0x99a1864afcc4df50,
        0x9fc89759d2da9602, 0x864075be72641d40,
    ],
    [
        0xd60bc4a028f5ef5e, 0x311eaa0253480042, 0x6218cd9304e6a9fd, 0xfb78c6501abf6ee7,
        0x53608540cee9b15c, 0x4d9e97892bb92bc1,
    ],
    [
        0x3cd3b35ad044b8b5, 0xb80a0e697e151608, 0xbf951564da15b170, 0xeba9f4d5aa5522da,
        0x1d703a8b1f354ad3, 0x715331344c20c113,
    ],
    [
        0x49b8776ccdd681b4, 0x62625aff6ff00d7b, 0xe2cbce4635f7ef14, 0x6965f865e663a9c7,
        0x0955e043e0260433, 0x6592ec00e8448e38,
    ],
    [
        0xd1b8638422ddbf53, 0x4c1dbac3644a6de3, 0xb68fd3d42aabd573, 0x813a7b714cc04826,
        0xd46123371908db0f, 0x7accbee3d9de6f7f,
    ],
    [
        0xb377753962b0f6a4, 0xd2023707a506223b, 0xdf58914907a96210, 0x87891acb2256ed0f,
        0xf5330894cde848ca, 0x46bcb4c4b855c5c8,
    ],
    [
        0xa30d79d4be6cb9e1, 0x131ce7e75ef22663, 0x8176426e3a39b4d4, 0xf307a79a469dc34a,
        0x20e2891bc2959318, 0x4eb2a12680dc6da8,
    ],
    [
        0x4a56076ff524e52d, 0x75e39095521de54d, 0x9523333f125ab6e4, 0x5dd6186cc057c443,
        0xa96a394779313f2e, 0x1b5803cf5e30ce9a,
    ],
    [
        0x9c1eb513fd3a8c88, 0xf869b3a8c2146a48, 0x920cb3d46378687c, 0x2304bddd14f91460,
        0xddb55bb66b90c290, 0x1abcd5b3dac35310,
    ],
    [
        0x2fb0e74ff9e39af0, 0x3414fb037953f4e0, 0x291efcbb48050622, 0xd1cbea8558b9299c,
        0xd93978d75f699681, 0x69789931ea39499d,
    ],
    [
        0xfa4648fd14a9df01, 0x0a9edfc3a00ec4b4, 0xee0777889441d1bf, 0x02fffc36323f5f41,
        0xe828f7efcc8f31ba, 0x1f2454cfedc10870,
    ],
    [
        0xe5b52d1b688d8072, 0xf2150431c53cb738, 0xd9c11ab98bb65356, 0x8498238378d999c5,
        0x9363c441e05b635f, 0x0c33a611cd1aad6f,
    ],
    [
        0xcade407bdce76153, 0x76390f9a86932823, 0x6629757e8294e260, 0xa98fbd9606b94567,
        0x1d57554f06d3256d, 0x629f9daacab8290d,
    ],
    [
        0x5b0760e175c606d0, 0x603d557dd09b4585, 0x5709548326e1fc9b, 0x857ad401f1e9ffda,
        0x6f6b7d5d7838083a, 0x35e3fd760543127d,
    ],
    [
        0xe5de463f798a94d8, 0x948e59dd9d09bef4, 0xef0d195615912f2c, 0x4d53d652db6c872d,
        0x8130e8d3a7635465, 0x6a8e60d7d7a1f129,
    ],
    [
        0x5c6337fca731dc8a, 0x0745617435b19e28, 0xacd7ba39cd4c7e92, 0x6092fbc21f2baa7a,
        0x3ed42f37d00eefdf, 0x0565a2736ce6cec7,
    ],
    [
        0x29e7dd7bd308a5c0, 0x3d5d429bf606b2b5, 0x871fd71f44c606f0, 0xe7718c407c50acd5,
        0xc1c4f6801061d8f4, 0x5d366e5549e4918c,
    ],
    [
        0x0a71a864717ae742, 0xf2e905d2524a22fe, 0x01aff9a430ae8498, 0xd5f6bf18ce2d080d,
        0x2e2802037ccc9b53, 0x54ea3a73ea7e2e78,
    ],
    [
        0x497a316cac025cb7, 0xb71a1a6b8f0c1db2, 0x7aa370615947d231, 0x5ec073a832bb299d,
        0x6947ca0f1c6b0b5b, 0x1953c08930606436,
    ],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 6]; 32] = [
    [
        0x42820341263c5315, 0x0e46462177918111, 0xe19c054ff9912928, 0x62b70b29feec5864,
        0x5cb1eb8e95cfd552, 0x8abe1d7520f9c2a4,
    ],
    [
        0x81d7129d48772eb3, 0x73c0edaea3b8f593, 0x7b2bd39462363e03, 0x7b2eb481ead16a5c,
        0x5521a326bc02baaf, 0x761d3a4a5f809377,
    ],
    [
        0x3f9b162e47634690, 0xe059c219dfbbc32b, 0x97495c4579bb950c, 0x39f00d1d90ed0c6d,
        0xebaa167fa90635f9, 0x20168ac65e9bb101,
    ],
    [
        0xfc54207824db4187, 0xed3ca9972dd90da5, 0x85f51eae54657c72, 0x5c17b17dcad568ef,
        0x33be0b515a36f3c9, 0x7a30d2af9219e43d,
    ],
    [
        0x5f0c4d7c799bdd7a, 0x8a892df80129727a, 0x6519b9cb144a5af6, 0xa0a7709206e67fcd,
        0xa6f5562626e4cf07, 0x06c64153906e5540,
    ],
    [
        0xa82289c636e2ab45, 0x68d387929464d8ce, 0x3f35b03f2ad19d67, 0x8687d57dfb2b569c,
        0x8c059e4d23214fb2, 0x6aaeed397a139d1e,
    ],
    [
        0x83e0a265dfb80ec6, 0x7fe3e4fd4ed3b16d, 0xd7f5363e477661d1, 0x818a8375ea30532d,
        0xb613ef8f694bfb3b, 0x199ed4b68437e1af,
    ],
    [
        0x36e616af3f89ae04, 0xb288a5f22a0f4bb4, 0x319433829876bbfd, 0xa9f3130ea86756e9,
        0x3c5833c41c2b396e, 0x802e50b2b2cb8001,
    ],
    [
        0xc2568ca0ae0cb469, 0x52e1e0726b03b4fe, 0x9539d69bdada4475, 0x702a753f8dc81bca,
        0xe349008bcaca8e78, 0x43c90643ba2e1abc,
    ],
    [
        0x4e30db44ace2b7e1, 0x5974b54ded8d1500, 0x36a74ab166c817d9, 0x7b8292d43fc931c2,
        0xb8598ad06eac656b, 0x77e37b2e05d34057,
    ],
    [
        0xd02dbf4d060f1856, 0x35d7944a4b08d8d0, 0x28b6eb4b2a158679, 0xcbd279fd72ff59e9,
        0x1caf1e0133bd1851, 0x13f9e594293a1ae7,
    ],
    [
        0xa34f659012e404ce, 0xdaf764151fd328de, 0xd17a69cfd8b5b382, 0x663c5cf9a5838118,
        0x384547679d43b3da, 0x58ead2105db25530,
    ],
    [
        0x22616b8a1e25fa41, 0x136447f1c70e60f5, 0x6811ef5772c7bcf2, 0x28ebebc2317e4205,
        0x4d8bdf66eda511da, 0x21ffcde21119d54d,
    ],
    [
        0xf92d711cf11588f8, 0x0d68626e726978de, 0xa392a608da4ca07a, 0x7bae3915529c333e,
        0xcc8c4e65b1c6728e, 0x20da57cba5fc807e,
    ],
    [
        0x45d1177bd6890868, 0xfb1e072defa74b35, 0xff0ded350077ba0a, 0xcbd24ee331732c74,
        0x13197ee866275e56, 0x5bc21d5beb68cd9c,
    ],
    [
        0xe8b632bd5cf75a37, 0xbe3b0a6e9e21266b, 0x905f2de6bc5d4726, 0x8d68bfbc1829c2ec,
        0x19b727c972e47e45, 0x30713bacd795b3d3,
    ],
    [
        0xdfc383f3a139e49d, 0x27eb9bdf9d2d9a50, 0x42076b0c11b48068, 0x63ef0bcce201d73c,
        0x6b5dd074aa7cfc68, 0x59456d9b2168b074,
    ],
    [
        0x41dae3f8c4c83463, 0x7b2532543f434c45, 0x616b42288152d3f2, 0x77f7a6051d33b75a,
        0x0b68f4a9c562646c, 0x50bb913c74071f19,
    ],
    [
        0xcce5321d43af162c, 0xac2d7ec249d81b1e, 0xa47fc93768d95c53, 0x55eafe015fc4561e,
        0xb5a0af4d5c3fc466, 0x5ad7892ac34eb0c3,
    ],
    [
        0xd407e76f1cc78a7a, 0x0ffffa94df79cc22, 0x169b810043f73941, 0xc935f71ee84fc015,
        0xde823aecbde36fa4, 0x24ed3f2c6ef8a0d1,
    ],
    [
        0xff45d5b7ba624762, 0xe4095c2f823f3691, 0x7f8954bcadfd3608, 0x2483d04d81d48b54,
        0x433c3429a4098798, 0x34a408ddc23db969,
    ],
    [
        0xfab423b0881eec42, 0x2745146681c29a41, 0x90124b5f170a8f70, 0xda84fc410f93a63d,
        0x1f9ecc36a881beb9, 0x3439891de5a0edbd,
    ],
    [
        0x218eba637db7c485, 0xfb6058b133dbae72, 0x5061f7bc1333f7e9, 0x6bcc8f8f9f9b004b,
        0xd51975849e83afa7, 0x070262c15afbf4de,
    ],
    [
        0xc6a35b9ecfcf2d90, 0x5937da89c065167b, 0xe40b3d966de93f71, 0x5de7e85c3cc39119,
        0x578ec623c0ed834e, 0x2e68be167b28853d,
    ],
    [
        0xab9aa52dcd061f67, 0x498fdd525cad6c3e, 0xa9737984797cb78b, 0x829856974fec01da,
        0x96c5e4662fb1b4e9, 0x6b07f87f238402b1,
    ],
    [
        0x0d14399ea04d8803, 0x1e4ed3c73ad35389, 0xa27e797a75d7cbf2, 0x258a859ba3daef2f,
        0x7317264bb383e607, 0x3f6945a7b6b9c622,
    ],
    [
        0x2b57e4adb8b67396, 0x8c36728d85d71b6e, 0xcb2196230a39304c, 0x039b6f21836d4453,
        0xb59593a70dd01e57, 0x44baf1708afe6315,
    ],
    [
        0xd0ef4fc975c215da, 0x8837531bd90f8b34, 0x172798b455b9b874, 0x6b01f605aa7a2e7a,
        0xbd8c9f68b42af78e, 0x449b2d5a9ebed76c,
    ],
    [
        0x5fab2e365a322843, 0x5d69b405e257687c, 0xb6786a3e907bce1b, 0xa2d931b58d5d530f,
        0xb9c45b2f66c004f2, 0x0607bae27d0472c3,
    ],
    [
        0x97b58a2d6203eaea, 0x627331345d95d1f6, 0xbefd0d3e05daa8bd, 0x49588f7ea4b26330,
        0x72d183e87baa07f3, 0x11070c4be1965861,
    ],
    [
        0x9b7a5113bcbed2c8, 0x35f943977b8cbde6, 0xf557393785ddfd21, 0xa01d5589f576493c,
        0x3f42abd03078b397, 0x6f96025e27203f86,
    ],
    [
        0x76b5b5b49b903e2d, 0x4d04a45969a28f81, 0xa271f2c49793102b, 0x425f51369fbdba22,
        0x8f767e9ecde7963c, 0x0c01f832eb9ad49e,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp384r1::Bp384r1FieldElement;
    use crate::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::bp384r1_point::Bp384r1JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = Bp384r1JacobianPoint::from_affine(
            Bp384r1FieldElement::from_limbs(G_X_LIMBS),
            Bp384r1FieldElement::from_limbs(G_Y_LIMBS),
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
