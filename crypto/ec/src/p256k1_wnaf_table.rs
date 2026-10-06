//! The checked-in odd multiples of the base point `G` for [`crate::p256k1_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and SEC 2 v2 §2.4.1's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 4]; 32] = [
    [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac],
    [0x8601f113bce036f9, 0xb531c845836f99b0, 0x49344f85f89d5229, 0xf9308a019258c310],
    [0xcba8d569b240efe4, 0xe88b84bddc619ab7, 0x55b4a7250a5c5128, 0x2f8bde4d1a072093],
    [0xe92bddedcac4f9bc, 0x3d419b7e0330e39c, 0xa398f365f2ea7a0e, 0x5cbdf0646e5db4ea],
    [0xc35f110dfc27ccbe, 0xe09796974c57e714, 0x09ad178a9f559abd, 0xacd484e2f0c7f653],
    [0xbbec17895da008cb, 0x5649980be5c17891, 0x5ef4246b70c65aac, 0x774ae7f858a9411e],
    [0xdeeddf8f19405aa8, 0xb075fbc6610e58cd, 0xc7d1d205c3748651, 0xf28773c2d975288b],
    [0x44adbcf8e27e080e, 0x31e5946f3c85f79e, 0x5a465ae3095ff411, 0xd7924d4f7d43ea96],
    [0x66e4faa04a2d4a34, 0xeb9898ae79b97687, 0xa420fee807eacf21, 0xdefdea4cdb677750],
    [0x7475656138385b6c, 0xf06acfebd7e86d27, 0x93ef5cff444f4979, 0x2b4ea0a797a443d2],
    [0x81340aef25be59d5, 0x1d9ad40271f81071, 0x4f93fa332ce33330, 0x352bbf4a4cdd1256],
    [0xdc9cdadd4ecacc3f, 0xe42ab8dfeff5ff29, 0x0230010559879124, 0x2fa2104d6b38d11b],
    [0x69ca0cd7f5453714, 0x263c3d84e09572e2, 0xab21a9b066edda83, 0x9248279b09b4d68d],
    [0x7e996d443dee8729, 0x2f570e144bf615c0, 0x8e70132fb0beb752, 0xdaed4f2be3a8bf27],
    [0xe6a3b5e87d22e7db, 0x11ecd9e9fdf281b0, 0x8acf28d7cbb19f90, 0xc44d12c7065d812e],
    [0xb61c65cbd269e6b4, 0x152b695336c28063, 0xc89a20cfded60853, 0x6a245bf6dc698504],
    [0xf95ae57f0d0bd6a5, 0xce13300b0bec1146, 0xc077e3d2fe541084, 0x1697ffa6fd9de627],
    [0xf982345ef27a7479, 0x9deb8360ffb7f61d, 0x986d0f07e834cb0d, 0x605bdb019981718b],
    [0xfe31c7e9d87ff33d, 0xdcb01c354959b10c, 0x7402fdc45a215e10, 0x62d14dab4150bf49],
    [0x5e555c2f86308b6f, 0x2c50e9f56b9b8b42, 0xde5b4b06c408e56b, 0x80c60ad0040f27da],
    [0x9d5eabb0fa03c8fb, 0x4cc5dc9487d84704, 0xaa74c6348cc54d34, 0x7a9375ad6167ad54],
    [0x4bb51f459bc3ffc9, 0xbb408ec39b68df50, 0x907a9ed045447a79, 0xd528ecd9b696b54c],
    [0x87231808f8b45963, 0x5266115e4a7ecb13, 0xea25f514e8ecdad0, 0x049370a4b5f43412],
    [0xf1c13eb1fc345d74, 0x881d811e0e1498e2, 0xd73df930d64702ef, 0x77f230936ee88cbb],
    [0xeb28531b7739f530, 0x58c80074ab9d4dba, 0xea44887e5c7c0bce, 0xf2dac991cc4ce4b9],
    [0xbcba4850c690d45b, 0x5a216cdfc9dae3de, 0x1b4be8fbbe252012, 0x463b3d9f662621fb],
    [0xa32496b49998f247, 0x6b98fac14328a2d1, 0x09232d4aff3b5997, 0xf16f804244e46e2a],
    [0x369e15f7151d41d1, 0x5d245315ace27c65, 0xb0352b7a14311af5, 0xcaf754272dc84563],
    [0x24497bc86f082120, 0x44a09c07cb86d7c1, 0xf85d0f1709979d8b, 0x2600ca4b282cb986],
    [0xc602a7746998e435, 0x01c48685e24f7dc8, 0x338ec53cd12220bc, 0x7635ca72d7e8432c],
    [0xc1a50743bf56cc18, 0xb7f2b33479d468fb, 0xdbbf4a87deee8a66, 0x754e3239f325570c],
    [0x9fe2694691d9b9e8, 0x330800661d1c952f, 0xff57859c82d570f0, 0xe3e6bd1071a1e96a],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 4]; 32] = [
    [0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465],
    [0x6cb9fd7584b8e672, 0x6500a99934c2231b, 0x0fe337e62a37f356, 0x388f7b0f632de814],
    [0xdca87d3aa6ac62d6, 0xf788271bab0d6840, 0xd4dba9dda6c9c426, 0xd8ac222636e5e3d6],
    [0xa5082628087264da, 0xa813d0b813fde7b5, 0xa3178d6d861a54db, 0x6aebca40ba255960],
    [0x05cc262ac64f9c37, 0xadd888a4375f8e0f, 0x64380971763b61e9, 0xcc338921b0a7d9fd],
    [0x301d74c9c953c61b, 0x372db1e2dff9d6a8, 0x0243dd56d7b7b365, 0xd984a032eb6b5e19],
    [0x29b5cb52db03ed81, 0x3a1a06da521fa91f, 0x758212eb65cdaf47, 0x0ab0902e8d880a89],
    [0xc504dc9ff6a26b58, 0xea40af2bd896d3a5, 0x83842ec228cc6def, 0x581e2872a86c72a6],
    [0xcfb199f69e56eb77, 0xced1f4a04a95c0f6, 0xe997b0ead2a93dae, 0x4211ab0694635168],
    [0xb570c854e5c09b7a, 0x1a01f60c50269763, 0xb343083b5a1c8613, 0x85e89bc037945d93],
    [0x67bd3d8bcf81998c, 0x4a1b3b2e71b1039c, 0xd59c18259dda3e1f, 0x321eb4075348f534],
    [0x423ba76b532b7d67, 0x181d70ecfc882648, 0xb64569335bd5dd80, 0x02de1068295dd865],
    [0xe54a32ce97cb3402, 0x3fc0de2a887912ff, 0x5d1aa71bdea2b1ff, 0x73016f7bf234aade],
    [0xab40e52290be1c55, 0x3f83c230f3afa726, 0xd4a1aca87ef8d700, 0xa69dce4a7d6c98e8],
    [0xa039063f0e0e6482, 0x0e106e861edf61c5, 0x76c45926c982fdac, 0x2119a460ce326cdc],
    [0xfd5e6348100d8a82, 0x8b33ba48d0423b6e, 0x8b3f5126f16a24ad, 0xe022cf42c2bd4a70],
    [0xadee9d63d01b2396, 0xa2cf15009e498ae7, 0x27561506e4557433, 0xb9c398f186806f5d],
    [0x3b01e1e9056b8c49, 0xc26bfae84fb14db4, 0x81a78d93ec96fe23, 0x02972d2de4f8d206],
    [0x35f5642483b25eaf, 0x01aa132967ab4722, 0x98088a1950eed0db, 0x80fc06bd8cc5b010],
    [0x1aa01f56430bd57a, 0xa65eed4cbe7024eb, 0x26e66bad7fe72f70, 0x1c38303f1cc5c30f],
    [0x02d499ec224dc7f7, 0xbdc59ea10c70ce2b, 0x09559e0d79269046, 0x0d0e3fa9eca87269],
    [0x063465b521409933, 0xbc4345405c520dbc, 0x9966f21881fd656e, 0xeecf41253136e5f9],
    [0xb653052a12949c9a, 0x54c3f3afbb5b6764, 0x8b3081b0512fd62a, 0x758f3f41afd6ed42],
    [0xbe8eb3c7671c60d6, 0x96c95330d97077cb, 0x0a08266e9ba1b378, 0x958ef42a7886b640],
    [0x1a117dba703a3c37, 0x9eb5fbeb0598e4fd, 0x4da1f32dec2531df, 0xe0dedc9b3b2f8dad],
    [0x1cb377b01af7307e, 0xc622e27c970a1de3, 0x43114306dd8622d7, 0x5ed430d78c296c35],
    [0xd6579962c4e31df6, 0x2a6c53c26e5cce26, 0x13d206fcdf4e33d9, 0xcedabd9b82203f7e],
    [0xc32f908318a04476, 0x5f4fa9b7962232a5, 0xa41b643fa5e46057, 0xcb474660ef35f5f2],
    [0x4b0be9475a7e4b40, 0x5ac6be74ab5f0ef4, 0xa693b03fcddbb45d, 0x4119b88753c15bd6],
    [0xd9e76f302c5b9c61, 0x4ecfc061d57048ba, 0x3d1d5e590f78e6d7, 0x091b649609489d61],
    [0x0c5d98093c536683, 0x23ee33d0197a695d, 0xb3cd0ed304ea49a0, 0x0673fb86e5bda30f],
    [0x67002af4920e37f5, 0xa5a2283993e90c41, 0x40c0aa58379a3cb6, 0x59c9e0bba394e76f],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256k1::P256K1FieldElement;
    use crate::p256k1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::p256k1_point::P256K1JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = P256K1JacobianPoint::from_affine(
            P256K1FieldElement::from_limbs(G_X_LIMBS),
            P256K1FieldElement::from_limbs(G_Y_LIMBS),
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
