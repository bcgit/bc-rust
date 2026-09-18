//! The checked-in odd multiples of the base point `G` for [`crate::p384_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and SP 800-186 §3.2.1.4's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 6]; 32] = [
    [
        0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98,
        0x8eb1c71ef320ad74, 0xaa87ca22be8b0537,
    ],
    [
        0x02d7e5c70500c831, 0xb408bbae5026580d, 0xbea4f240d3566da6, 0xcb9d3910202dcd06,
        0x64793c7e5fdc7d98, 0x077a41d4606ffa14,
    ],
    [
        0x0abcdbc3836d84bc, 0x37882f4a1ca297e6, 0x4f6661cbe56583b0, 0xf208e51dbff98fc5,
        0x573cac5ea025e467, 0x11de24a2c251c777,
    ],
    [
        0x040f05b48fb6d0e1, 0x8b05526f55b9ebb2, 0x2d58cc9dfa7b1c50, 0xad6fe997fbea5ffa,
        0xf29f8ebf234edffe, 0x283c1d7365ce4788,
    ],
    [
        0x5c55e4461079118b, 0xc388528bfee2b953, 0xc6cb1ee285fb6e21, 0x2216f7291e6fd3ba,
        0xf1bf29b8b025b78f, 0x8f0a39a4049bcb3e,
    ],
    [
        0x26356f3b55b4ddd8, 0x4749b66e3afb81d6, 0x56c9fd14892d3f8c, 0x7fe935ed5837c374,
        0xda1eeec2904816c5, 0x099056e27da7b998,
    ],
    [
        0xaaf1ca1e3b5cbce7, 0x9ee5f441abd99f1b, 0x6267bcd1f0f11c13, 0x9632bff9f01f873f,
        0xafdaf5002ffcc6ab, 0xa567ba97b67aea5b,
    ],
    [
        0x4b88701a9606860b, 0xa849557a10b6383b, 0x5b21f9f7da7c4e9c, 0x22a94156fff01c20,
        0x8cc15c11d8135255, 0xb3d13fc8b32b0105,
    ],
    [
        0xcaf3a9add9ffcc03, 0x17012a991af1f486, 0xdcc614e42e5805f8, 0x692befb0733b41e6,
        0x00a5ebbcb13e1a32, 0x4099952208b48896,
    ],
    [
        0x9599e68713f5d41b, 0x59c8651060801c0e, 0x12390b430467aabf, 0xe07dbecca86cd9b0,
        0x16858a211d750b77, 0x8d481dab912bc8ab,
    ],
    [
        0x626b4c175eb77422, 0x46a37313df88fd64, 0xf9936136bf42cdb7, 0x606290985f8283f5,
        0xc7817121057d46e1, 0x27935df4e25c6f47,
    ],
    [
        0x1e555ebc684aac81, 0x84a900a91f7c4ab5, 0xa68749c30c7f9aa4, 0x22c0102fd4293a78,
        0xe741a4a8000d5eb8, 0x3cb647a5df014c23,
    ],
    [
        0x46f41be83716be9a, 0x31a8a58b3dcb2ca4, 0x555746bd28fda974, 0x07c4d76fab5ce0a3,
        0x9ee9eb5267946762, 0xe4c6d5cb9183a670,
    ],
    [
        0x6b4eedfa23e2e546, 0x20761bc15898e1b0, 0x4acb49c0d7ba04e2, 0x08e3acaa2b4a8d3a,
        0x3c316d5a82c8b705, 0x9c5fa2c13f418e62,
    ],
    [
        0x977bb83b1eb1a373, 0xad69e407f57b1e27, 0xfa46d04f4d4dfca2, 0x6e0af4f41cbcde50,
        0xd7b75810ce554ee5, 0xf1bc35f9656c6eea,
    ],
    [
        0x0c8361dba9eb28b9, 0x061fa485bd1b8a65, 0x9d3993124d374e62, 0xc73e3336394c98c5,
        0x04fcfa12c087d446, 0xf2e6f06f0ea533e8,
    ],
    [
        0xaefd7fec482c802a, 0x631eaed97add3fe2, 0xaf246b3f70bec90d, 0x55492715879f54bd,
        0xa92758f2773bb6c9, 0x38dbd58238c21bbc,
    ],
    [
        0x29e4ae10ae1410ea, 0xc998b7fd7b3813ca, 0x55a0270e5859145d, 0xc3675bf4f728f3ac,
        0x9b9863d46535a5ab, 0x77c12dceca498ff9,
    ],
    [
        0x2a07272d05de389d, 0xe56ba2d9cafcb448, 0x41c36c0122a10654, 0xd850ac1e45c8fcb9,
        0xfdb4300af2deaadc, 0x1221b1e1be96dfe8,
    ],
    [
        0x15ac797ea8f8fedb, 0x4983e9bc8a47b24d, 0x35b72c15f264347c, 0x31c65d0bd2d3642c,
        0x8224c2dcc11702de, 0x9bc6b65436262167,
    ],
    [
        0x10f3f39e87c76293, 0x077b05ca6a94f76d, 0x10d10234b609b8c7, 0x5185d456b279a184,
        0x411a5ed920a88b09, 0x2ce37b2917ad0d5c,
    ],
    [
        0x80dddc249a26a33d, 0xaa49a4148fbebc67, 0xaba8ddfa4745a605, 0x4de52ef9689a5eb5,
        0xa5a2ff485cf5a64f, 0x9c3adb9111fe252c,
    ],
    [
        0xa5b68a56bbfef50f, 0xb03d491de84ea016, 0x258449c2e28cd17c, 0xadd9c644fd8393e3,
        0x3bce43bec4f4609e, 0x6ce3bf11431d1d9c,
    ],
    [
        0xd5254db0689a30fe, 0x21e9e8ccc22e6b2c, 0xe2a9530742a384f1, 0xc870bf64c76762c0,
        0xa06f4ca5fa30e0bc, 0x1273f595eaba5df1,
    ],
    [
        0x9da43e8e5a0e8cf2, 0x8828f5b191d03d1c, 0xdd74d976a4911734, 0x7486cc53003ed182,
        0xf504f32fc1211afd, 0xa6c36459d1243ff7,
    ],
    [
        0xffe06fbae0068fb0, 0xa618a8cc08d1b992, 0x7126ed3b510b0341, 0x0b4a2a1247e8f2cc,
        0xa86d2c9e23c2f5bc, 0x8bc6057da46fdafb,
    ],
    [
        0x90903c9d776e9fa3, 0xff2ca2a90bdc08ac, 0x8f41cbe07c3e20b6, 0x88e935bdd5f169ba,
        0x92288353932cf408, 0xa0e5cd10144167c5,
    ],
    [
        0x3bb25771ff2b4f85, 0x30d0a0e2e2ee7c87, 0xf22f519eeae1eb01, 0xf36d925a4f0112f5,
        0x307d064e7750ab08, 0xa059cd75571b3507,
    ],
    [
        0x709d6a38b6ecb8bd, 0x07fd3823a2b10416, 0x78baa65996532279, 0x6c3eb8b272461fc7,
        0x4f1cec9879cabece, 0x8654ddc7eb10d5a8,
    ],
    [
        0xba77d70f99fe20b0, 0xbbf7b15b29f59772, 0xa2b93e41e5a75d8a, 0x91e7691569202b98,
        0x4296f482176d1b01, 0xcc42cb6ad9f7161a,
    ],
    [
        0x5c24cc10bda2cc75, 0xb5e5a6d1fb4071db, 0xa92542dbf5872edc, 0x5f729644b4fa011f,
        0x870b7900c1c47689, 0x0a12151e620a81a2,
    ],
    [
        0xafd574f7e008f8af, 0x941560583def5431, 0x3c968cfbb83c8f7b, 0xac334769de358b33,
        0x2cae508f5164ca6c, 0xb32e89eb942aab11,
    ],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 6]; 32] = [
    [
        0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
        0x5d9e98bf9292dc29, 0x3617de4a96262c6f,
    ],
    [
        0xb65f28600a2f1df1, 0xc24abd6be4b5d298, 0xf7684c0edc111eac, 0x8520b41c85115aa5,
        0x7d0bbe9602a9fc99, 0xc995f7ca0b0c4283,
    ],
    [
        0x184414abe6c1713a, 0x3177686d0ae8fb33, 0x8c986533b6901aeb, 0x284b447754d5dee8,
        0x0f5837e90a00e7c5, 0x8fa696c77440f92d,
    ],
    [
        0x64664cdac512ef8c, 0x30d84ede32a78f9e, 0xd9c92cd01dbd2256, 0x1a61d867ed799729,
        0xba52efdb8c169047, 0x9475c99061e41b88,
    ],
    [
        0x262da4f9ac664af8, 0x9e743efedfd51b68, 0xb7678854aed9b302, 0x9a9b3d7ca3c400c6,
        0x452c4a5322c3a979, 0x62c77e1438b601d6,
    ],
    [
        0x7d5dba8138c5e0bb, 0x5466d51263aaff35, 0x43ff93f41b52a325, 0x6fc4eed8dfc363fd,
        0x688505544ac5e039, 0x2e4c0c234e30ab96,
    ],
    [
        0x6423a12736f429cc, 0x776bcb8272218a7d, 0x86329be057857d66, 0x5185595046932ec0,
        0x644e4147af164ecc, 0xde1b38b3989f3318,
    ],
    [
        0x985d588d33f7bd62, 0x838d24f8b284af50, 0x84d1114373dfbfd9, 0xeebac4a11d749af4,
        0x1b049b2536164b1b, 0x152919e7df9162a6,
    ],
    [
        0xfa650ef5e23b09a0, 0x04da4d2faa9680ec, 0x9b797d277f2388b3, 0x163ad3f8008ad0cd,
        0x39474594af603598, 0x5ecf947778330598,
    ],
    [
        0x6995b07e75e52245, 0x11ffba5608004e64, 0x594b32fd7adc0e8c, 0xb2291b68a1039aa0,
        0x7be99f2a60669050, 0xa1592ff012146085,
    ],
    [
        0x9d5606eb10c69f84, 0x2b6f8d9838ef0c13, 0x585d9c4e6c615b53, 0xa4f2d4aec079c6b7,
        0x9ab1a3798d1e3524, 0x380a1a3b4898d4cd,
    ],
    [
        0x79b65fea0d5a2b14, 0x09be21f6414b9be2, 0x7afbf0557ead6368, 0x6103c7b0218bc837,
        0x4966f85ebdc18cb4, 0x28300479a8f88dd0,
    ],
    [
        0xffaf54d7e6aac897, 0x09a957bbac49722c, 0x6280b8afe5d6a5a2, 0x5942e18d15922f20,
        0xc0027f165dd74ca9, 0xa37245523aa57845,
    ],
    [
        0x529fb56479f48752, 0x0ef2c4b2213f519b, 0x6f015651bd9218e3, 0x94fdf1b7da9e5955,
        0x5afe81503cb7bf61, 0xf641de0cb075851a,
    ],
    [
        0x53e0d05ef28faf29, 0x3ffe8f5147848a0e, 0x531f70960a30e838, 0x8d7aec776d94fc70,
        0xf733c547c0f2b3dc, 0x2458497a559bcdcc,
    ],
    [
        0x3152f5ba7852680c, 0x3e8802c6d2fc9ebf, 0x3fb0b9ac114251cd, 0x4a041a8651780d31,
        0xf9e442612fcffbd1, 0x8f86e464c200bc46,
    ],
    [
        0x599a066726d333bb, 0xd3145ea7abbf4370, 0x7b86f2aba9bd9527, 0xeff54a716511f5f1,
        0x12a77e148373d30f, 0x828c26694df81889,
    ],
    [
        0x35747e089cbeef77, 0xc20c5f0bbef22673, 0x00487a48cee2b22c, 0x396e7fb8964f4304,
        0xd302f0d0bd10269e, 0xeee351bc34276d3a,
    ],
    [
        0x533ffb21939dd273, 0x5f4f2a9231bf6723, 0xb233124188d17ebb, 0x059953dd8965d97d,
        0x1ad8460e2e216618, 0x50b225fa8a5ed838,
    ],
    [
        0xc0979304abbcfcd4, 0x6ad799aed585d888, 0x22e5893043a248bf, 0xdba18218185770c7,
        0x7147eed091efb368, 0x4482f093849864ec,
    ],
    [
        0xcf8a7d7be2a7607e, 0x4dda48b4fa5d1dfd, 0x8208f6db859227bb, 0xbab5b7b88f803547,
        0xdabde6f484adc04f, 0xbf27e3e07ba0ebb9,
    ],
    [
        0x344000dc47355061, 0xdbae5b8175af7420, 0x4c69c4c0108a6a32, 0x69dcb8452f057663,
        0x50b9f80b22b4829a, 0x83e8d95f813af4db,
    ],
    [
        0x36dde9917c570471, 0x8105da32421e5cfe, 0x58d74fe2bc8777e0, 0x918800e37b4e4aa8,
        0x7c76075539542abd, 0xc3325e274b23604e,
    ],
    [
        0xcbdaf9963d58f4ce, 0xa7147a032edfc8b0, 0x13cce2421581486c, 0xa1afe32ae0ca83c2,
        0xa0db552ca682b49f, 0x62737fc8fe0818cb,
    ],
    [
        0x2e6ddb768c63b40a, 0x38a1bc0bc57b89f6, 0x22899f57821ad25b, 0x0bd72553fa3365b4,
        0x1cebd105c28a71d0, 0x58279fcdf96c71d9,
    ],
    [
        0x6cb597b8e22c2ce9, 0x54c6d084dd6077f5, 0x42fed20299ce9705, 0x777fe7595994ae0d,
        0xfbf2a22fd1f1985d, 0xfea19f27f6881a60,
    ],
    [
        0xfc5c555ade9e587e, 0x0c9dcbea9d4197aa, 0xe7dbf0ae17f7fd0a, 0xd6396c943a16024e,
        0xaa542f5c1e7ce4be, 0x120de79718d154fe,
    ],
    [
        0xaec87aa569c8d6cc, 0xa880c76b8849bcd5, 0x0fa0147d878235aa, 0xfc311351556408ff,
        0x026d8cebfcdfc32e, 0x40f6ae62c5a75f70,
    ],
    [
        0xb867bea8e3578549, 0x88d6dbd5abb99b51, 0x7d1d13d1aa1c7e40, 0x742599e648fd7ea4,
        0x830567af763ec9d0, 0x3127066c11092e88,
    ],
    [
        0xda74d5345e24d63f, 0x182916746338781d, 0xc23168cdfb54deb9, 0xea4223f449e3895e,
        0x91646e65069fa685, 0xbbd6bb6bad8516d3,
    ],
    [
        0xa13e157ec5a3e83c, 0x84fb986767fb8c48, 0xcf6593451a9a0698, 0x4479d4c75bb1d9f1,
        0xe15002475bc0a80c, 0x857c802960eaebb7,
    ],
    [
        0xc81abe0944e11e2c, 0x35daedff59e74a1a, 0x79cddd7a04990095, 0xa770fc48b73edc06,
        0x24e2bf69603ffd5b, 0xb1e3ae7166d97103,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p384::P384FieldElement;
    use crate::p384_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::p384_point::P384JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = P384JacobianPoint::from_affine(
            P384FieldElement::from_limbs(G_X_LIMBS),
            P384FieldElement::from_limbs(G_Y_LIMBS),
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
