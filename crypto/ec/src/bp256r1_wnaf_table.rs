//! The checked-in odd multiples of the base point `G` for [`crate::bp256r1_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and RFC 5639 §3.4's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 4]; 32] = [
    [0x3a4453bd9ace3262, 0xb9de27e1e3bd23c2, 0x2c4b482ffc81b7af, 0x8bd2aeb9cb7e57cb],
    [0x6b91e2ad25cae39d, 0xd2aa843d0c0fca01, 0xd6624c3ab4f6cc16, 0xa8f217b77338f1d4],
    [0x32f95f7c85fe101d, 0x7cf41589c0d8c3fb, 0xa5f863e8b69fc147, 0x855433a3a4c8e334],
    [0x02295ecd04e9de4c, 0xd432568e24e5fb57, 0x4d3300afbc27257b, 0x6b8bb7f53e36b682],
    [0x420d27d6784f8f12, 0xd283bd714a67c06a, 0x0811364099019b7c, 0x8b5fa06d31d59d69],
    [0x3406afffde3eeed0, 0x80c350b1e1db41b0, 0x8ddc9c5870ea1631, 0x50ea43e33d2d4897],
    [0x62c969c86253556b, 0x3439bbf4e2b459b6, 0x7862ac771ce2cb74, 0x8d4243f928ee1b6a],
    [0x7a309a0b21557a8e, 0x48e0917a7d5edc4b, 0xc6e07a490cee9078, 0x04306f8d5631ee7a],
    [0x0b73fcb1a0c86824, 0xda7b65585bfbaada, 0xc3663e5f98b9dafa, 0x884d1f975768ce45],
    [0xa58eab8ab0afbae7, 0x20411e949b5343f7, 0x8c6280c5f7796cdb, 0x09a299ed5649e1ea],
    [0x237e790bb1a5b4ce, 0x3b759efc62bb5f35, 0x3df3221040023c85, 0x570308793e0c5eba],
    [0xbe3b17da81484ed7, 0xabb09f7acc59db53, 0x7fa1ffadda5f3a40, 0x41c849b05a0d6a54],
    [0xf2cf3ad83fa052c9, 0xca2fbfe7d1cf4e00, 0x2185ad28fb5fa0fa, 0x4e71767e126fd5f7],
    [0xe2382f79baecc1e1, 0x0094f1814ba94c4a, 0x15b8777a954bcc12, 0x0274efabe5807d45],
    [0x46359d211ac38cc5, 0x80cc84e37da25cc7, 0x50a3f267e294dabe, 0x7a55f5b14ca5987c],
    [0x30ef11e45497bac8, 0xf01c0500489b5ccb, 0x76b7c208ad20eab9, 0x260f6273e0bb1dd8],
    [0xd41037567accf8c7, 0xfe8ef690ae1eac5a, 0x7aa6f2cb689b376f, 0x4e8a6fb1464a8518],
    [0x2ea157f038125580, 0x3fdc2bd0dfd3d44e, 0xfa072c5c90ca7465, 0x6f32d5afbb348dfa],
    [0x43fc7544333f3428, 0x0f4531ed41d2adc4, 0x8529a7f04da9ed69, 0x17eb6c733c9784ef],
    [0x9d581ef650cc6c04, 0x1756302344392682, 0x99285b38fafc2729, 0x88194fc15da5ecda],
    [0xf3eee50460f0ee5d, 0x9f4fc06ae23480c0, 0x070ab8859b446ccd, 0x8c37a6089a705fc1],
    [0xa0763644c6db33da, 0x177c596229b13603, 0xde882c05ab7a5053, 0x19640edeefc6afc5],
    [0x2e9f0135784895cf, 0xbfd264c269ed642a, 0x93d20af87c0adbfa, 0x0458eb7922078146],
    [0xf26f04d92940040e, 0x2feb9c8e911770b6, 0x0ed998e878d374d3, 0x47ac5f13da531200],
    [0x4fd996642445cb4d, 0xe65418c7b7f9f4ec, 0x9dec0ebef91c595c, 0x3d7189f40aeb6063],
    [0xa78381d11da54849, 0xc5b8caaf04ef1669, 0xd0d0e21d220cedc1, 0x9be3f9be5ff16ae8],
    [0xf1f1e73b8e32065e, 0x85530598ae2af728, 0x83daf96c3b24bc90, 0x0fcbc30b72dc3e2c],
    [0xb35ce8ffd1f97eb4, 0x83d561f5301ec598, 0xb5d449a454cb7242, 0x7b36877eabe731f9],
    [0xd30ceea4d5193f47, 0x39b19246e1f92c95, 0x668a8f09295e9cb7, 0xa27bdb6299aa1753],
    [0x845dd1b1e33c6da6, 0x28a1dfc821d87a4e, 0xe2cc6eb2ddc002cd, 0x9f98f97d6b809cb0],
    [0x1d44cce166c0742d, 0xa03b399a33e4c3e0, 0xb61889c37cd95949, 0x226f783772b52dd3],
    [0x58e6031bb4a5e4fc, 0x7e53f9040ffacb9a, 0x13a28e3ad3515448, 0x8daf7dc659e90919],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 4]; 32] = [
    [0x5c1d54c72f046997, 0xc27745132ded8e54, 0x97f8461a14611dc9, 0x547ef835c3dac4fd],
    [0x7e65cc5602b74f9d, 0xfac10e4589348fb7, 0x0aa2a6850a1b40f5, 0x4b49cafc7dac26bb],
    [0xef9e224a5fd8814c, 0x097082129591c88b, 0xd7e172e40350d911, 0xa50c95efc2ad06c4],
    [0x7252376bfc79ebf0, 0x646067c55b1a928f, 0x0965a09661223af5, 0x382f9af51ce9a3d3],
    [0x42be764f293b3348, 0x146f15eea266b228, 0xae64ed13d26d038e, 0x41e0e0c34464b5c7],
    [0x23af9bdadf6fbd40, 0x951970a9b39a21f9, 0x782129d70ceeb10f, 0x4685dceca1753941],
    [0x616a664e902cb740, 0xf5c5afbb15e5c033, 0xc257d5e888eb9dad, 0x6cb4b54150658725],
    [0x9377c731f7e833bd, 0xa510f13a83e146a2, 0x3aa032daf9ffd870, 0x2ab9e5213104bc7f],
    [0x6205d05254c57ad7, 0x0f42120813fc7e96, 0x601705fe7f902e37, 0x569ea2dd9a21654f],
    [0x14f5e940d854688a, 0x899aded511795131, 0xf82c6eb87b8812ea, 0x3ee027407a6089df],
    [0xe7310d4c9ad17277, 0x02c6b0cc03e52178, 0x80dcefccfac71135, 0x4a2afc2717cbee53],
    [0x6feea011fae28d88, 0xc2a8d275e501b318, 0x8fb15b04fc432fb9, 0x03f86f1566d23ff1],
    [0xc7164f4db751f8f4, 0xb6d936b56f8ac707, 0x2c9eb4b82368af89, 0x6827f6a39886c9f8],
    [0x4fc43228cb5be420, 0x109430909dc5454e, 0x3aae77d7197ac174, 0x9d81f55342ffe3fa],
    [0xdd9924f09f478511, 0x0334cbf9014205e6, 0x30835f439129c742, 0x38f6f28e41e896c1],
    [0x8ec0586d55f3a86a, 0x8afd97c0055dd2f4, 0x871017b8d86eccae, 0x6ebea505dc4e8a4f],
    [0xa0633cdbd18858fc, 0xa024299cc4d2b54d, 0x49918b696473edc5, 0x50d931a544455a96],
    [0xd4b2100477c436ac, 0xd48b49fb5dbbda9c, 0x1ef9f1f84331a57d, 0x5e7c2c02d8a53f05],
    [0x3b72575e59ccfb75, 0x273f8849e60b8533, 0x07b2e53cecc34e82, 0x223e3e99fa8c7fc0],
    [0xe7ba3b187454d62a, 0x8a86bd3fccf5fa6d, 0x189d8736683669ff, 0x2632e118005c0edc],
    [0xa203d5682e4475b9, 0x98ac080c6ffc2adc, 0xf42e1a1de7fcc5fa, 0x685fa8d530d90f6f],
    [0x9112c55e26717fa3, 0xbfa4c5e7044ff7b4, 0x23b70c0202174d77, 0xa8879bd92ba6a910],
    [0x5b4dc05151f0fa08, 0x0661062acd60dc00, 0xfda33eac1ddd8d75, 0x64f15229d1edc963],
    [0x186bd111c7da9fc4, 0x62106edf21b5bedf, 0x3580c7bb212b64db, 0x3117a2ce36cb6f90],
    [0x84834d5ba8cbe26f, 0xf9a163bb2377d06e, 0x8e5fa5fd48471ef8, 0x1ab4a6eb82e36b8a],
    [0xfab56200ee41e549, 0x79c97210d8925021, 0x137b0a84c93c4e5b, 0xa0e10494e748130a],
    [0x7f9936771ec9a332, 0x3d3995d253730a86, 0x431b62fe6f2374b6, 0x37cce18a2c2a03f0],
    [0x5c43dd1f9804f327, 0x7a9e378b3f12900b, 0xaa542e02960da127, 0x0dd61f45b230d121],
    [0xb1539320dbf6474b, 0x940f9d84099b431d, 0xd9274ed922662c03, 0x4b1f12933e05cc11],
    [0x6c38d88b1d2ddd50, 0x85040dcff7646ac9, 0x89e78260a3d3e596, 0x0594f4ce1f9c4e7d],
    [0x61121c4be0575357, 0x90d9c3536c909029, 0xf441e7936cce52ee, 0x7c49c4aafe5ba327],
    [0x71f7e4b9a4870fb5, 0xf3fce697d4d312f3, 0x240641d1fedc3aff, 0x6248a2224d790442],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp256r1::Bp256r1FieldElement;
    use crate::bp256r1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::bp256r1_point::Bp256r1JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = Bp256r1JacobianPoint::from_affine(
            Bp256r1FieldElement::from_limbs(G_X_LIMBS),
            Bp256r1FieldElement::from_limbs(G_Y_LIMBS),
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
