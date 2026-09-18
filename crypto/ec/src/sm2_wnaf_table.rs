//! The checked-in odd multiples of the base point `G` for [`crate::sm2_wnaf`]'s fixed side:
//! `G_ODD_MULTIPLES_X[i]`/`G_ODD_MULTIPLES_Y[i]` are the affine coordinates of `(2i + 1) G`, for
//! `i` in `0..32`, as little-endian `u64` limbs -- the table a width-7 wNAF over `G` indexes.
//! `Q`'s table is built at run time because `Q` is the signer's key; `G` is the curve's constant,
//! so its table need not be.
//!
//! Generated in Python from the affine group law (SP 800-186 Appendix A.1.1) and draft-shen-sm2-ecdsa-02 Appendix D's `G`,
//! independently of this crate's arithmetic, and checked there by `n * G == infinity`; this
//! module's own test regenerates every entry with the crate's point arithmetic and compares.

/// `x` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_X: [[u64; 4]; 32] = [
    [0x715a4589334c74c7, 0x8fe30bbff2660be1, 0x5f9904466a39c994, 0x32c4ae2c1f198119],
    [0xe26918f1d0509ebf, 0xa13f6bd945302244, 0xbe2daa8cdb41e24c, 0xa97f7cd4b3c993b4],
    [0xa575da57cc372a9e, 0x344a417b7fce19db, 0x040e008fdd5eb77a, 0xc749061668652e26],
    [0xcd27e384d9fcaf15, 0xa80198337744ee78, 0xfdbe86a75c139906, 0xddf092555409c19d],
    [0x173472a58cca247e, 0xfe8d59cb43619e4f, 0x0b4a2444a46a74c5, 0xa27233f3a5959508],
    [0x668c74d78ce20ace, 0x125dcdd589c2ff82, 0x7c1aab770f67f543, 0x04b3cb10c9c6d8e2],
    [0x2b834f1d509b9cd0, 0x7bea65c6421e189e, 0xfa804513275f58aa, 0x952072d6ff9c65bd],
    [0x461b1bbcb80f829c, 0x3b424f35f0ecce4c, 0x3291676c38d39324, 0xf73b839f13912c1a],
    [0x36969f8b77125e6a, 0xbf5113ab85b5ed44, 0x1c993f01115c57f7, 0xdd18aa4aec26eac4],
    [0x1323f252e493952a, 0xf7c96c55940a4726, 0xe2e0586bb5dc9419, 0xa68b2ec49d1921d0],
    [0xe1de5f100950c8ab, 0x5b551c86a8976933, 0x137cbf4e8aa50535, 0x6407be639bc5b738],
    [0x4dbb2fcd069d45db, 0xbb570a9f430ea7f6, 0x15c07a8c04226fe3, 0xac8df677299e8288],
    [0x0263b20d539e4139, 0x7e8581fbbcf5de01, 0xce1564c3df7d67ea, 0x178d1f6bd584afcc],
    [0xce37e84fc9541b4b, 0x02a85a7410754529, 0xd7a1f169475b4ddf, 0xec6f34ceacaa73a0],
    [0x9dd4ef421635b9dc, 0xc9816be068be66db, 0x625773cae69bbe05, 0x28221c36398c4c3a],
    [0xac995c5066bdaaa5, 0x27d053c0f150fe10, 0xd6b48259b69e8530, 0x08daae840b2a43eb],
    [0x6d69b1bd07837dc9, 0x451641e8455eedb6, 0x4624f85fe9b7cb83, 0xa1aa7f4a42808908],
    [0x549786448c4f3f4d, 0xbaf30f4638d2231b, 0x46dab2eba04afd78, 0x68126a90b051062b],
    [0x31f8514dc6115cb5, 0x8c641a6cb43ae7da, 0x8b8f45b58a12e6cc, 0x3242e1de1fa494c5],
    [0xcd1bb864637cf4f9, 0x10e34d63f48c5ed4, 0x5b075be3c412ad03, 0xe6857f7fc3345385],
    [0x47d58af32a91ddc2, 0x30abb6eab3f02921, 0x490df25e43f73f13, 0xf537773939d38a9b],
    [0x0180bb9d84d7141b, 0x134911d8e4bbaaec, 0x4b92b8f64e804905, 0x897da7bb358b6d21],
    [0x3d24524ac4d2c465, 0x0462308a30d9d3e5, 0x45254a01baae8a2e, 0xd2593661cf6daf12],
    [0xec0ddc2b82cb0747, 0xdaeda7da80dde8ce, 0x98e2f9df22a96604, 0x8ab85f67eec67f06],
    [0x2755c80bb1316dd9, 0x787ab24d5a604fb9, 0xdf25cd6e045b914d, 0x968513d803c0a611],
    [0x35eaa6e36461d0d3, 0x17905f2a781de540, 0x2d531dd8552f2765, 0x01eeb7b6a1494475],
    [0x828cc5c0f20462a9, 0x6d96e2a601b93c0e, 0x4cd09b8e39701ff1, 0xd909bb3be4c02cd8],
    [0xc86610f34f66b3df, 0x015c9bf09e75950a, 0xcbde1f5982ace379, 0x6a13800155ef04b7],
    [0x123308b4a9c5711a, 0x721dd5dacce5bc3d, 0x26804860af6a7e95, 0x7ccbc3bf87cc4d54],
    [0xcd43853968e0f8c3, 0x9cab4fb10369ef34, 0xf5aba10ba06befde, 0x99ff4d8ff311e9a0],
    [0x0c5516aa79811c1c, 0x8869b952943a29fc, 0xf382d60f67fcc2e2, 0xd3a606c601b5c66f],
    [0x29dc4c21401d787f, 0x5c4a52f82ad10df3, 0x7048dcd10cdece63, 0x5eee8921f4fcd342],
];

/// `y` of `(2i + 1) G`, entry `i`.
pub(crate) const G_ODD_MULTIPLES_Y: [[u64; 4]; 32] = [
    [0x02df32e52139f0a0, 0xd0a9877cc62a4740, 0x59bdcee36b692153, 0xbc3736a2f4f6779c],
    [0xaaacdd037458f6e6, 0x7c400ee5cd045292, 0xccc5cec08a72150f, 0x530b5dd88c688ef5],
    [0xa6976eff5fbe6480, 0x5006206eb579ff7d, 0x4504c622b51cf38f, 0xf2df5db2d144e945],
    [0x223b949657e52bc1, 0x037937707d6a49a2, 0x5cd6b6e9c12d2922, 0x847d18ffb38e8706],
    [0x85227940922c02e9, 0xc3a8433140d1ebca, 0x768f7689b210f45f, 0x379e72f63722c924],
    [0x739a8fd805174a4b, 0x0c94816e63c4bc72, 0x4918e5c02e2b0b93, 0x63516355287e39fe],
    [0x03891e105e009b00, 0x58d1434ae934ba75, 0x1a473f8d9748f238, 0xe6bb9804458bb70f],
    [0x4c3533771db0955e, 0xdc2e788fb170aa14, 0x5ee9fab985c12455, 0x32ec7722695dc7cf],
    [0xe0180d54d4ae2221, 0x6cce6001d7c0b853, 0x3361493f76fac50f, 0x161e5851969da822],
    [0xfd4520a63f5cc585, 0xb95f2de69200269e, 0x933ef442fca7a734, 0x96f361a23b3deb99],
    [0xf945321148e90344, 0x60fcfd988fff6dec, 0x12a9423fd80dea54, 0x141caee612e7ab07],
    [0x7bd8b7c847718ce5, 0x0e9b9643d766da33, 0x30c43be69b23cc14, 0xaef82cf361db1c71],
    [0x9b499a7da7820bf9, 0x7021aafc29ac8e86, 0x53da45cec1caada1, 0xf575f34e5f6c63c6],
    [0x73306a0ff0485872, 0xe607f33be20135ea, 0x6f251c63fbbd2927, 0x3c85cf62a744817e],
    [0x2995225e66b162ba, 0x64c77a81858d4ca1, 0xab2012c41627cd81, 0x3b4d172d6963510b],
    [0x2458b9e3c73bf657, 0xf7dc310560bbe83a, 0xc1b8e58150da662d, 0x80cc0a980495af87],
    [0xc3c8bd75b5fe25de, 0x6e67fd81941c6a60, 0xeb15fccc63694830, 0x3d420dee447499cf],
    [0x5a8ce092c6b7c016, 0xe7fec8984be51251, 0x35ecf208bdec5980, 0x7e72f70a2eaf1bf4],
    [0x7dab7b373c8f551b, 0x56ab9bcf11b6f25a, 0xaa27b4380a8333ad, 0xcbf18ef2f229c025],
    [0x1ca28a8ee15f1878, 0x5d72264551d68eae, 0x581dfa7d2b4c09e3, 0x6b61903f2ba03769],
    [0xf9099fa3212d8fc1, 0x63ae367eb959d9f8, 0x8e2e511cce74be18, 0xbeb6132d28ff4099],
    [0x38ecb2e51caf0aae, 0x6543e7e5a787f93d, 0xf571032510364cd2, 0x995b4a9a20d88c89],
    [0x5dca599abe435bf0, 0xa169da8afcb3a620, 0x6cf13824af9f6508, 0x416b602161b2bbf6],
    [0xe2874ab08c6c6e2b, 0x0445b6381fc45c42, 0x53e29b91b9afd253, 0x0d90c6f4584c9d15],
    [0x60f9fd6e5a72901a, 0x9a31b57f2e430478, 0x893c927b9668ddd5, 0xb0992fa258261de1],
    [0xb769488b3901a9f3, 0x7460ad9d8bcceeb9, 0x66a2abf1c7753bb8, 0xabd4a0f7fac6deb4],
    [0x5eefa9a3ec3f9511, 0x05977fb39adacec7, 0x5bb65608aa16f24f, 0x10d8c2a3b3396bd8],
    [0x1d092851b33025b7, 0x41d95d9e42639ac6, 0x84f5b14011d026db, 0x2de1cdf12e9cb8c0],
    [0x5995334c3e242616, 0x3acfb676b987c213, 0x145518b80573d4c0, 0xc6ebde08aded9af4],
    [0xd35aaa101d22c55a, 0xf2b3182557bf0529, 0xdd523fc5310a3ecf, 0x0b3cc5a35c82a6b7],
    [0x0d6b519f677f9e84, 0x3ef8e988f9e9e6c0, 0x8726d00ed296c2b3, 0x16429acf62bb2d8f],
    [0x9ffe119727f734ae, 0xf39e93dc1c8b27ad, 0x73516bbad0f603e4, 0xb6b3462b6a39a55b],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::Sm2FieldElement;
    use crate::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::sm2_point::Sm2JacobianPoint;

    #[test]
    fn table_matches_the_odd_multiples_of_g_computed_by_the_point_arithmetic() {
        let g = Sm2JacobianPoint::from_affine(
            Sm2FieldElement::from_limbs(G_X_LIMBS),
            Sm2FieldElement::from_limbs(G_Y_LIMBS),
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
