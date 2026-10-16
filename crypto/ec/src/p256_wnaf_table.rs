//! The checked-in odd multiples of the base point `G` for [`crate::p256_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and SP 800-186 §3.2.1.3's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 4]; 32] = [
    [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247],
    [0xfb41661bc6e7fd6c, 0xe6c6b721efada985, 0xc8f7ef951d4bf165, 0x5ecbe4d1a6330a44],
    [0x21554a0dc3d033ed, 0xef8c82fd1f5be524, 0xd784c85608668fdf, 0x51590b7a515140d2],
    [0x300628703187b2a3, 0x7ef9f8b8a80fef5b, 0x25bb30667c01fb60, 0x8e533b6fa0bf7b46],
    [0xd79e8a4b90949ee0, 0x9e0acb8c2c6df8b3, 0x878938d51d71f872, 0xea68d7b6fedf0b71],
    [0x433391d374bc21d1, 0x16742ed0255048bf, 0x0638379db0c21cda, 0x3ed113b7883b4c59],
    [0x98e15d9d46072c01, 0x792e284b65ead58a, 0x61805df2d85ee2fc, 0x177c837ae0ac495a],
    [0x63668c63e59b9d5f, 0xae03af92de3a0ef1, 0xadfb378999888265, 0xf0454dc6971abae7],
    [0xba1abce34738a73e, 0x5fa68678f0d64af8, 0x9c0984b66f75301a, 0x47776904c0f1cc3a],
    [0xc1fc7b74ab03ed83, 0x782c452257884895, 0xce39b7c17108c507, 0xcb6d2861102c0c25],
    [0xfd76364e67399e83, 0x3a582139f42b1523, 0x2e4ac86eb473bca5, 0x3250fcf686637c7b],
    [0x672e573045ca7896, 0x3c0bc0a5df64a4fe, 0xd28a3e39d4583fa6, 0x0e91c7239c2640d7],
    [0x84a4dc45f200d687, 0x41652fc5b76f1b24, 0x85f4f52d8c07fa84, 0x3a67e2554b0c0bb6],
    [0xf2e201173b0883d1, 0x576355bd683e54ab, 0xdeba2fac4611f378, 0x184ffa5819d80d51],
    [0xdedd693d1c784def, 0xfd8cd1c688b58a41, 0xa7c36da090853b8c, 0xd6d33adefa195b07],
    [0x3e3f9aa0a1b45b8b, 0xfac9db7d52a95b3e, 0xa85da026a7ae9aa0, 0x301d9e502dc7e05d],
    [0x65c100f3cb2cd793, 0xa03b0a533aa872fd, 0xfa9aa25b89d9d34e, 0x9807d699fcd81356],
    [0xa12d389033bb291a, 0x94e8e1fe92af9700, 0x8ffa3ad7326c48ca, 0xd58d4a589ed27d16],
    [0x73a92894502b3348, 0xe0d21379246bfd44, 0xd6b0978611a826aa, 0x419a6a646ddb817d],
    [0xa0c199ddfb2776c4, 0x547b942dd2d138d4, 0x42014976a179046e, 0x22a682f7c3996d4d],
    [0x3a7de694995d2fa2, 0x6067c5c3d4175a59, 0x1cf258d2e6cfe8aa, 0x67a6bec240dee065],
    [0x7544dc129b82d28d, 0x8f4bc4c6d009b30f, 0xd04230861d8f4b49, 0x986ae2506f1ff104],
    [0x79c78080fae0ba03, 0x0f5f609edd29d6d9, 0x3ecd0f5ddff0672e, 0xa891d06670bde99b],
    [0x51d689227b1c0d7c, 0xdd5b31583e19066d, 0x595361ea83071bbc, 0x42c315cc48958708],
    [0x7d228ce6a5674455, 0x28fb7ea9758fd4fd, 0xbb22b146866e6c05, 0xf785b0e098068875],
    [0x044360f0018e22b1, 0x95f7eb56e81008ff, 0xaadee6863c1d68bc, 0x672c4a514d9de43e],
    [0xf126ec9f7449d036, 0x982b1ca78de9b983, 0x5a47802254b88039, 0x6f01bd49c9d95245],
    [0xdec1dff7df6e60a0, 0xc2a595b762c1eada, 0x7571a109fe7fea2c, 0x079dba7ba068c926],
    [0x8abd97b1d0f56077, 0x289d406e2d6c6bd8, 0x126d45a8ea907f86, 0xc116e30ebb4d2865],
    [0xa2b6ea0e0faa4b45, 0xe50941119e8dc8ec, 0x765b2784fca9bdf7, 0x665f1a6ffe0c6437],
    [0x5939ac380d32af0e, 0x3e7910a08b724fd5, 0x2d3a6b3d8d990001, 0x059ccb19edd3da9a],
    [0x32a290825d8bdac1, 0xdf53c8af01a7cd38, 0x2a1f28a08acc7d8f, 0x6a9501d85bf5dc80],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 4]; 32] = [
    [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b],
    [0x9a79b127a27d5032, 0xd82ab036384fb83d, 0x374b06ce1a64a2ec, 0x8734640c4998ff7e],
    [0xd1d0bb44fda16da4, 0x0d012f00d4d80888, 0x8ae1bf36bf8a7926, 0xe0c17da8904a727d],
    [0xc55e1a86c1f400b4, 0x53c73633cb041b21, 0x6d069f83a6f59000, 0x73eb1dbde0331836],
    [0xe85a224a4dd048fa, 0x4d714feaa4de823f, 0x87014a964a8ea0c8, 0x2a2744c972c9fce7],
    [0xe2f8eefce82a3740, 0x090d04da5e9889da, 0x24c843afa4f4c68a, 0x9099209accc4c8a2],
    [0x9c43bbe2efc7bfd8, 0x26ee14c3a1fb4df3, 0xa24091adb40f4e72, 0x63bb58cd4ebea558],
    [0x47e59cde0d034f36, 0x2a3b21ce75b5fa3f, 0x4e6594e51f9643e6, 0xb5b93ee3592e2d1f],
    [0x32f787ff71f1fcdc, 0x81b2804428d5733f, 0x6231856577648e83, 0xaa005ee6b5b95728],
    [0xe39150752bcecdaa, 0xa496716e30fa3e03, 0x5c35e7100d6d6ce4, 0x58d7614b24d9ef51],
    [0x15de24a071d48c09, 0x897cd3c33b566a82, 0x97b3090d1d7eb88c, 0x42e7c342667d3593],
    [0x138046543140ad55, 0x7e68833575e7a5ae, 0x1a22733bb8e0bd6d, 0x5df65c3b550dba22],
    [0xa9ed16b302f79324, 0x8c188af735a7618a, 0x26daf267163afb0d, 0x27d0f1872f1fcf43],
    [0x20d242c260906e6f, 0x45bdeccc63f04916, 0xa4c6d90826cb9995, 0xc0a66e276688f359],
    [0x550c124593d1bca6, 0x09a166ab4b95eded, 0x3f78245f558a5dcb, 0x84aaba16ee195d7e],
    [0xd58db6aea17ee267, 0x298d9ae46887ca61, 0xe0d23c026b017d72, 0x6551b6f6b3061223],
    [0x2f6bf92479634af4, 0xffe630b96c587853, 0x86a01a4d1d091b2f, 0xc2a59cdccab11bf2],
    [0xa5b0c9c6f586b9d5, 0x67271c163b034979, 0x76ea92632dc7fef6, 0xd45514d102726b85],
    [0xdb1d6c81b09214b2, 0x13c6d072f3dee1e2, 0x545c9fb1954c2fd5, 0x332544cf1102f584],
    [0x5347f649cbaa285d, 0x979dcc310265b068, 0xb918c9835a54356c, 0x4f4606b0102223ee],
    [0x49c24ce1441feed5, 0x1542c7ee209aca6c, 0x6c249b49464d4499, 0xde692b7022d13158],
    [0x25110c441bb07e97, 0xd86fc6289c189f25, 0xe328a4d97d3c7b61, 0x003cccc0a6460e0a],
    [0xefc3edc8166934ae, 0x1c6b38f0feb0f2cc, 0x419a88c4033c1ce7, 0xb596cd922cbfa1c1],
    [0xd6c4a72bb2f9b1b9, 0x74f1a1e1eb87f164, 0x2914d1dfbb7a7990, 0x649a61ce571b9585],
    [0xe7bc490c10d62408, 0x4b04b6fd5f3aa60a, 0xe15c767f0d9f5b41, 0x73fdb0bf6080da6e],
    [0x9935399191f37104, 0x136246589704d941, 0x611de5a4ace203f7, 0x548c7e9196a25bfe],
    [0x360233dd989e17db, 0xa78551bfc3749b08, 0x11a0f21a608776ce, 0x1562080ff1d5deab],
    [0xfb0da5aeb4824dea, 0x83eb2df35751a397, 0x1d223f9d2a9588ab, 0xdc1e19b743d4d181],
    [0x313fd7fda410c206, 0x7d5bd5e89e59c8c5, 0xb8b16d9bb13b8765, 0xe9478823c35b30c2],
    [0x6e25a6602b7f4ccf, 0x7dede5bf81e215bc, 0x6e8cca29f7eac37f, 0x490e2ca49ffd18c2],
    [0x928e1e3c97fe91d1, 0x1621f7a33956cecd, 0xda65281b9345638e, 0xbb6ad7eccad49159],
    [0x30aff53d5f1ef1a3, 0xf8461b5c697a6f35, 0x81c6c6e44a3c56a3, 0xca640ad193473743],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256::P256FieldElement;
    use crate::p256_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::p256_point::P256JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = P256JacobianPoint::from_affine(
            P256FieldElement::from_limbs(G_X_LIMBS),
            P256FieldElement::from_limbs(G_Y_LIMBS),
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
