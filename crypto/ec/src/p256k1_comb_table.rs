//! The checked-in fixed-base comb table for `[k]G` (secp256k1's base point `G`), width 6, matching
//! this crate's other curves' choice for fields over 250 bits. See [`crate::p256k1_comb`] for the
//! multiplier that uses this table and the algorithm it implements.
//!
//! `COMB_TABLE_X[i]`/`COMB_TABLE_Y[i]` are the affine `(x, y)` coordinates of the `i`-th table
//! entry, as little-endian `u64` limbs; entry `0` is the point at infinity (`x = y = 0`, which is
//! not a valid affine coordinate pair for any point on the curve, so it's an unambiguous sentinel
//! here).
//!
//! Regenerated and compared against these checked-in values by this module's own `tests`
//! submodule below, using the same construction the (not checked in)
//! `generate_p256k1_comb_table.rs` scratch example used -- so a hand-edit or transcription error in
//! this file cannot survive `cargo test`. A unit test rather than an integration test because the
//! table is deliberately `pub(crate)`, not exposed outside the crate: see
//! [`crate::p256_comb_table`]'s docs for the same reasoning.

pub(crate) const COMB_TABLE_X: [[u64; 4]; 64] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac],
    [0x6048b06043ff8359, 0x46b4821dc65e7651, 0xb7d282b5c21da014, 0xa2b7b3629f7bd253],
    [0xbe27d057b10fd304, 0x86960638347f3a26, 0x8cd0b2d618e4a8ad, 0x6576d5548b4d88d4],
    [0x476706e4dfbfa4dc, 0xf5948a7804c85b17, 0x8392119d7adbb41f, 0xd6788590731fea19],
    [0x3e73fcc8f7866196, 0x25e21c3681b3f4aa, 0x52565e809339ae07, 0x29c47eab891e3cc0],
    [0xea375008edecc847, 0x309feffb5844a04c, 0x170a37e4cf58f7e0, 0xf73c12851ad31962],
    [0x8f6ff9c42b7fe6b1, 0xa647b5b065ded430, 0x5d53c32629aa5f4b, 0xcea2e17263d326c5],
    [0xe6847df84cf27076, 0xd89858ade7627eae, 0xfcafebe77fd9af59, 0x4d49aefd784e8158],
    [0x042f7989ce279a45, 0xea8b0fa8270f23bf, 0x505c7ce5bd2623d6, 0x2c0e4587cd0123c6],
    [0x0035af537f56f827, 0x8344fc81d253e9a6, 0xca8f1b6a99e92f76, 0xdcb97fc13cd4a952],
    [0x355569ba16f41f0a, 0x4d1ebb05a5850c70, 0x5a95769857e55d8a, 0x2543e5f81ce7d833],
    [0xe0b3a84374b45960, 0x76671c46723df5a8, 0xd2429517c61ca37f, 0xe5e08b13bb68be24],
    [0xf4ac2e2178e4e9da, 0x37b8d870d33dc867, 0xb70813e439ba6ea9, 0x3d56ce047d0c0bac],
    [0x8c30941ccc2a56d6, 0xa0ec8285004c17ba, 0xb54f07c0a704d6d1, 0x402d950e14fe9bf7],
    [0xbd776166facfba20, 0xbda9416232b1f491, 0x25d8a1a17909d66d, 0x8fd85dd82192f380],
    [0x8f763889be58ad71, 0xbb30d1f5cf9a3a20, 0x0a05fe9629de8c38, 0x7778a78c28dec3e3],
    [0x92b072dd48ed1367, 0x9c02cedd3d031297, 0xfdb0a5a0b38e947e, 0x0d207580a82f6607],
    [0xe1c74acab15cb0a8, 0x557e6c7059af20f2, 0x02cead8233dd830d, 0x42a4634af4baaf3f],
    [0xb30f195148e82495, 0x0f7f6787980ade7a, 0xed1ed0508f7226b5, 0xc1964e0efa8c13a7],
    [0xaaa028551d66e242, 0xd114895ee3e64e20, 0xa4e1409d981ff163, 0x7c636cdc59373163],
    [0xf96685261b2aea68, 0x6facbc2b3fada381, 0xce134bef23cd513e, 0xc7abfc5cfa35ca7b],
    [0x6eb52dd9eb777697, 0x8e30ca8755333c65, 0x2ec4adacbd496935, 0x0278107b5138c61f],
    [0x30663648957b0a0d, 0xf0d9b655f7643745, 0x2a0b0c4646614891, 0x40e94e242c4e3f25],
    [0x4005def415544867, 0x41133d514403863c, 0xc0e4fbdcb15f58e4, 0x5e67d6973d958a99],
    [0x87fa81c735d63671, 0x64885362f2eb49a9, 0xf5eb487f3d7eb3c1, 0xf1a5eae5457b84df],
    [0xda173e1ebb8c8298, 0xe4573e3aac647203, 0x2bd53450ac6e28c8, 0xfa7ea7717601ba84],
    [0x76205b8f0153a230, 0xe7b7f86f20dd1a21, 0xd3ae5d6d83c0c37e, 0x5c1048a532c2827d],
    [0xe19a13e934087a25, 0x6e48000d1ec217e7, 0x30646a487af20404, 0xd43e05cddbd1bc55],
    [0xddc3c419710f1026, 0x946f2362ca267c4a, 0x0604b808a753c190, 0x0a34bb13fecee2e7],
    [0x18dc08e5e954d499, 0x1ad0c60f3b5fc120, 0x387e34d2f97cf585, 0xddb618eba6e09ab5],
    [0x4b215fcf48506a70, 0x8758bf9ae7271fac, 0xad70fba2c0cabb2b, 0x0e7ac39f1d06f3fe],
    [0x5cf39944b26b64f1, 0xb7edcf28f5476d99, 0xd4cda4c62511e59d, 0x7175407f1b58f010],
    [0xaef3ddcc700952ef, 0x3297f9bd53ca9141, 0x2dd28fd1553aeada, 0x1cc817b6b0ccd48e],
    [0x5884159bd7721115, 0xb3664810b8e16dc1, 0xfa819d536135a62f, 0x60cac14d217ddb87],
    [0x53d48500959bacad, 0x339b127a602a2a3d, 0x1448bef4e641cb81, 0xefa53f427e0dae3e],
    [0x7ca3deea3dcbe5dd, 0xace67db5d03eb4fb, 0x1cc96933be39c4d5, 0xe10e89b87a56a16d],
    [0x4f085199122f0f71, 0x98bff21d564b3619, 0x3c554918ea1344f7, 0x80f118a6c729f953],
    [0xe43fd41476a4596c, 0xd07984ed74f4fbe9, 0xe10744cc1a03d271, 0x3fa3a9591fa88c85],
    [0x5408c2045ff781ed, 0x670205a77687900e, 0x44f2847c117953b2, 0x38c5897a9789510c],
    [0xcfb4a0870cc1b9ed, 0xa9dee8626b53beb2, 0x0bd8e3aed51620bc, 0x6e7f11c80980e5f2],
    [0xe6a6d143fbadaf91, 0xe45af20339e47148, 0x9bc61b74d04b9c13, 0x2f92485fd26eaef4],
    [0xb79b5ecfdfbb68a2, 0xf6de05e94f279bbd, 0xb906d78d7a39847d, 0x197ac92f79b928bf],
    [0x5c8e2b6c99b8a0ba, 0xd2cbaabb776eafc2, 0x1d2024c2bc6bc541, 0x75b0fd5a90d0dc18],
    [0x7fa42090eebf6bb7, 0xae0408813e8565b4, 0x09284cf6ae51bf84, 0x27b2b3a4e0a29511],
    [0x2cd59c9daeb002a6, 0x5c2c98db8e32d04a, 0xa7909e91edf6aa05, 0x802dddc6457716dc],
    [0xfbc5e2c63c1dbe36, 0x4e4390f2499a8c7d, 0x09b89e987ef771b4, 0x03179e314d2df8fa],
    [0x24cdcc14c9d36995, 0xc382a77a3b97b6e6, 0x85a6d079bccdefb3, 0x7aa61648693867e2],
    [0xbe35d0785ae60ba3, 0x2717bd735368c6d6, 0x20faebc11d660217, 0x91b44adb4ea4c464],
    [0x315b0d5d5d76033d, 0x1725522c39a2a2e7, 0x8e1396891270c1dd, 0x97cf990e77e65bb1],
    [0x2492273c8aa5cd34, 0x1c796c26aeb1ed2f, 0xe6e60b4949711f57, 0x10b2104665551826],
    [0x19756a7c1499350d, 0x0ce33ac1476127b0, 0xddbd90232bec1059, 0x6fca2fe6f5cce58d],
    [0x28c79f0aace757fe, 0x751914572dca79ef, 0xd1a6bbbe14761633, 0x17b832e44571386b],
    [0x40b90860607e5ba7, 0x1aa584bff5c5549b, 0x57f76e5ce962d92c, 0x60d45efb2b4e9144],
    [0x8ad7d399404f423d, 0x595585984ab8a5f7, 0xf714d3fa276ef53c, 0x71c441d7e3b32a5b],
    [0xa1a6b0ce40aeeec1, 0x861b55978252ed26, 0x6c5f6de278eff849, 0xb0fb446d18bdaea0],
    [0x0847b97e9d2b66f6, 0xfd9a06ecae0e537a, 0xfb8af82ae4121630, 0x2b5a3487e6d8f9a2],
    [0x792ea92c716e7b6c, 0x91a2d0aab2c822ff, 0x39af127145e2a74b, 0xadc613ff05c8f5f6],
    [0xbcee76e76f67a7fa, 0x9ed7eba393b18760, 0x2d464f09a69403a8, 0xe0f4e23fd03c30ce],
    [0x886e0c3293605259, 0x78df128a8d59b90b, 0x93eba20240223094, 0x37ac7f14067bef7f],
    [0x1a6d4cb959f54695, 0x2332bdb7a333feec, 0x7fc5f4d0872c146a, 0x2b3fefc1caf7a4cc],
    [0x8671b79095da59e5, 0x7aa04ff60a748575, 0xc9b59947d5d6a26e, 0x9e7dee383b895a3e],
    [0xf8d19d143cd79f44, 0x7bc9f6be59d0bd87, 0xfaad307731e36c60, 0x1c1e628390c75ab2],
    [0x93ccad491f530fee, 0x5ae91d7ffb3b1b98, 0x142893fdba91bf45, 0x25898ad2570fba39],
];

pub(crate) const COMB_TABLE_Y: [[u64; 4]; 64] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465],
    [0xa2397fecfe86fec2, 0x10d10835046f3835, 0x57a937a3f71e29c9, 0x693038941695122d],
    [0x3214fbf674b35a7e, 0xde91c8ff19dca53c, 0x4ba282bd7471a2cd, 0xb481e63e3a1e8c39],
    [0xca7bcd6bbd3b5406, 0x6206f1c4ddc9a07c, 0x940ef5c6d21c13aa, 0x28eaa8c89d5063c4],
    [0x3d9d8aa926ac3dcd, 0x3e49815b2ff10fdf, 0xd55a8dec6aca3ef4, 0x4e0d94b788b83df0],
    [0x2cf714db4b5d70e2, 0x99edbedf17b6864f, 0x8c3a8a7d3e0d2581, 0x506b9e2759c6b114],
    [0x7e5111e5b3cf7bd1, 0x2c157fa299c547a7, 0x884e42abc251b9e4, 0x31685db59b97d96f],
    [0x6b90b66203aa781e, 0x6e0f2d1a7df4d846, 0xe723f210359ca6f0, 0xcd32fc59a10dd135],
    [0xaa5491ed79858da8, 0xc881dbf3c5348ebe, 0xf45baa5c946801eb, 0xa02f612707d42762],
    [0x160a4b4e87b67c3d, 0x42443f4b408c6130, 0x0a19051212c01d14, 0x2efbd169ff5d737b],
    [0x50e913a00596238c, 0xef0e40312fbfc3dd, 0xc23eb566573634ad, 0x9af00533173c881f],
    [0x1caf639c6990cfc6, 0xf150b8e7aabacff0, 0xe2ec209e19a76c68, 0xeae00d38392329a9],
    [0x1a7205c76e005f31, 0x0b5b18920bbf0efa, 0x8ab4d9bb79d928ab, 0x425098972cb116d6],
    [0x78296ec7ffd37a94, 0xbe3298e1b7a03ac1, 0x72bbc0ef07122852, 0x92eae98fa04e067c],
    [0x0bf5973b1275d68d, 0xca56c7197b5b9ab6, 0x144cb34fcb3fb9e9, 0x90e00591afb2fff6],
    [0x3b513fc1fd9f43ac, 0x87b38411ff24ac56, 0xf7098e12f2ff5800, 0x34626d9ab5a5b22f],
    [0x97607326f693d28e, 0x4bf8e9d473d7045f, 0x249d105e7806a821, 0x7f6f578e9f2e5ae6],
    [0xb2f7ccf5e0da513c, 0xf4fa5d59638fc0a9, 0x8cdc23a3a39f43ce, 0xb239264b811e89b0],
    [0x248b057cddab5f2c, 0x74d4e3625ee35b01, 0x9b019bbf3b8e224c, 0x9bc3051601c21ffe],
    [0x22e7130ebda86be3, 0x772062dee9c411dc, 0x3be6c1effd6a1c16, 0x7274a8e2952cc272],
    [0xa1b5abd192658c1c, 0xbc85b730d19d0eb0, 0xcfc5fba029a3ccc5, 0x8758b7f138f755d9],
    [0x809bd73500fc31a9, 0xd450e064907f17ba, 0xb4e626800927f99f, 0xb5fe260e280282a7],
    [0x8d58f6f5a60e3e05, 0x6d731d6fe5a1d66c, 0xece08e1dbd3e84df, 0x169ee313ab745c23],
    [0x410a4e8ede26e2cf, 0x292dff5f82703792, 0xe043d144d4843ba9, 0x1d22c149a61301e9],
    [0x1f664b95af57dca7, 0xa394ce9c1b62afc2, 0x9a8940fea22c8191, 0x0aebc938cb8cb5b4],
    [0xfd9d7678d1f4270c, 0x432bed96063fa89b, 0xd71af888eb2b23ae, 0xdb11b810c620fd3e],
    [0x2cf3d4d1bc73a533, 0x91ffb64198a8b3ad, 0xbf2469c70f3e2ad0, 0x6859fc332680c891],
    [0x70fefab986e439bc, 0x67f66a711320dc1c, 0xd0b7b2422483c19f, 0x0aee002558089217],
    [0xbc660551837b4596, 0xd9411cfe0ee17558, 0x0c1eaf02c15f0f55, 0x1d69732ce08a903c],
    [0xeb60973f0acb5dd3, 0x54abb29ed770812b, 0x8c2095c67192db95, 0x7459f30c6d221978],
    [0x1455fa0e100ae7a9, 0x93464741763c7a81, 0x2d0ac5eaedcd7892, 0x2571789994c7a28d],
    [0x426e7efab24234d5, 0xb01fe8b774471d2a, 0xf36d3401134cc86e, 0x43b4554344e3d550],
    [0x26b1dd83127f538e, 0xcbe309dd783d6a22, 0xe444283c75033d5a, 0x1e3e58c7da85c29c],
    [0x4b5e3471fb69e482, 0x5d330d63d20bcad2, 0x455ee5d26976f1d0, 0xc2feb9354e25e444],
    [0xcfa2a15eca6afd2a, 0x25d7c847891f9e25, 0x07a27e70dd949df7, 0x6f5bbae1a2bb65c7],
    [0xb99d50433d1806cd, 0xe8319ac5e1466a33, 0xae56fa13651b1e7a, 0x8e4cd19d4498cb19],
    [0x26207c601f1a9ca2, 0x2b6624a104b6563d, 0x92af032f9dde7fed, 0x43c9408c7756af48],
    [0x0d42f7164a7b42a2, 0xeb89fca430883954, 0xb1eb18b23a788f67, 0x7d47da22bc60f121],
    [0x9fe387c9fd6f3968, 0xffeb48261caefd1b, 0x1b4d316423ca7311, 0x947858d56dfb3c09],
    [0x28c8a20507ee8b3e, 0xd05f9ae57c8e24b9, 0xded3a615b355f0d8, 0x1498b6f13b8aca26],
    [0x0b6a3795192d8926, 0x126b5cad4a7699fa, 0x1a1762337fc6f4ba, 0x20070b88f3824ca8],
    [0x6b38627a08912f0e, 0x66da353bf2096e06, 0xdf136ff180f7fb94, 0xac2b3ffebdfba5dc],
    [0xc09ef18e609ce2ec, 0xfbb2e1eb4031d2f6, 0xe59d734cfcf1f434, 0x3cf9a44b58bf2658],
    [0xc88b67e51397ec0a, 0x7abe3db71b219c9b, 0xae64b66de3bcdb3a, 0x800e23b46942800c],
    [0xc1bb3aeb20a34d02, 0x9920e08ac7fd6c58, 0xe4424fead91be4a0, 0xd46b7e27db848e62],
    [0x71871abe48b5ad2b, 0x2276676f01cbb15e, 0x0fbe633243935012, 0xfa461b20b73f95cb],
    [0x6fa33dc1ad4e9e90, 0x9715b2430c210b89, 0x6b1d7aee99991d1c, 0x215ea70656c3b7d6],
    [0xff0217dd5eb7d71b, 0x64864f81cbacdb25, 0xfa5643d779db1649, 0xf9a2a68cc58a4774],
    [0xab150e3c64d34089, 0xa427e24a0a79cd92, 0x66a8943c6eb4024e, 0x0c6f126af39bf3b1],
    [0xaf42a1540c680613, 0x6f5b700c0fc8d939, 0xb14f59a27f0a41dc, 0xf5498b37092d9be4],
    [0xe0f0f83a01e0f19f, 0x903cc85a3a3b24b1, 0xd1f61b64f79bb62b, 0x81bf22647b2dadf7],
    [0xf0a6cf26cb5b0597, 0x92cf246aac3971a5, 0x4e6675c1c73c3d28, 0x5a7ab53644c5fcc9],
    [0xac84af0e0417e3d3, 0x248e3dad0fae5b6c, 0x26ee0961e9a1346e, 0xcaad90be8ba9086c],
    [0x495bd4c107388eb8, 0x164eb4d7c62bcb6d, 0x5140b98166bb2cda, 0xf642d5afe309896c],
    [0xdd4c2e4ecc52cb4b, 0x614f658ca94f9a62, 0x4a02453e734823c2, 0x44573f4fcb570754],
    [0x8bb94c3a07fd388f, 0x55c3d037b8a94cb3, 0x53602650faaca627, 0x5bea4f2e8e0f3281],
    [0xe9d9793efb00cbf4, 0x31b7a7cc71b4d7a7, 0xb5254c04e38703c1, 0xc97f9a92f22280e9],
    [0x4393857792cd776f, 0xbaf513156d650a84, 0xf7aa6c27561b50eb, 0xf4281bf2368a21be],
    [0x83bbbb5dda29e74a, 0x5f455f8fa76e9b01, 0x58ba3533b5ecb4c4, 0x288e321f57c1c6bd],
    [0x15d04f75709faf11, 0xeaf837acf8978b40, 0x28b6429759909228, 0x92e6323d24602fd5],
    [0x3e0fba1a53ee485b, 0x354a1921026ca84f, 0xdd1ab3c30ac7cc2f, 0x49831bfa780722a4],
    [0xbba3ba1e3714ff9f, 0x1e7bb20b27969b07, 0x523b17914d391133, 0xa7f4d2429c57b316],
    [0x0baa59821b7180e3, 0x8a89e34cc7c54c52, 0xc9d4aad1f28203db, 0x2188b6d4b0267681],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256k1::P256K1FieldElement;
    use crate::p256k1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::p256k1_point::P256K1JacobianPoint;

    const WIDTH: usize = 6;
    const BITS: usize = 256;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic, per this module's construction: `pow2[i] = 2^(i*D) * G`, then
    /// `table[idx] = sum of pow2[b] for each bit b set in idx`.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = P256K1JacobianPoint::from_affine(
            P256K1FieldElement::from_limbs(G_X_LIMBS),
            P256K1FieldElement::from_limbs(G_Y_LIMBS),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [P256K1JacobianPoint::INFINITY; TABLE_SIZE];
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
