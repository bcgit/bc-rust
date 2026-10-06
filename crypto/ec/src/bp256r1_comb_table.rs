//! The checked-in fixed-base comb table for `[k]G` (brainpoolP256r1's base point `G`), width 6,
//! matching this crate's other curves' choice for fields over 250 bits. See
//! [`crate::bp256r1_comb`] for the multiplier that uses this table and the algorithm it
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

pub(crate) const COMB_TABLE_X: [[u64; 4]; 64] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x3a4453bd9ace3262, 0xb9de27e1e3bd23c2, 0x2c4b482ffc81b7af, 0x8bd2aeb9cb7e57cb],
    [0x3a86369d8f1b1b84, 0x7c3e4dfdeb152115, 0x8d730ac130ab006c, 0x81b13370b7253d72],
    [0xbab899b454bb984d, 0xdc8d910071de4892, 0xe8be5ed3ecef5281, 0x608a7298ec554706],
    [0xd0ea175c2d8e94ca, 0x8b9ce1b25f76cafc, 0xdbc6f24e88f420dc, 0x60e062486571c960],
    [0x256bb07a61a04906, 0x0b10c8d2b473cec9, 0xaa7d82b05a619978, 0x8d8c18d931e4fc4c],
    [0x44b4b45b206f1cd1, 0x29609dae4e7f44d1, 0x97ad2b9f2c9d25c6, 0x6e9849ea26cd5960],
    [0x0186795468b7a9c0, 0xb96e1f123b9fded3, 0x81348812232cc262, 0x54a434a208abe5db],
    [0x09ffb63b8d799c2d, 0x7b82757d8a693df5, 0x98a972ce4a159040, 0x245a28f898c1c6b3],
    [0xa781a50d3601041f, 0x81909e4978974543, 0xc45e4740c3f48169, 0x9abd6cf6f26a614e],
    [0x15137398384e94cd, 0x6d3ead2a1373f46d, 0xcabb6fac03e27523, 0xa28d53db717dceda],
    [0xfa8ed2b04767a9cf, 0xbac22791b46071ba, 0x66ec9a903ae584a8, 0x7b034967429639fd],
    [0x71ecf6da18d2dacb, 0x48d7a8f6dcbd1e08, 0xe7db3d2f6ae8c0f2, 0xa65d75823b3ac78d],
    [0x28c875ad7d8628ae, 0x542cc9afa8bbe243, 0x85fcc5e030d23569, 0x77ab196a7bc03943],
    [0xf9dc0d7f609de141, 0x9cdc2129f17dffc5, 0x883bc9b341b0dbee, 0x7786af963b57dce1],
    [0x631b0eb41859c9e2, 0xfbb0e053e1b0edf7, 0x942341993accd784, 0x6057115f58754b7b],
    [0x8fd1ea6f630273ba, 0x8a3e19cb24a2e4d6, 0x8fae09609f048ef4, 0x61d6ae0995b5c197],
    [0x397249cba5c38650, 0x473791c66f1b4a13, 0x34b474fbd85fee81, 0x89c7fc22e4c7ed19],
    [0x2cd0f810d2f310d7, 0x0486ce913cba2370, 0xcb341125f9139abd, 0x3283a923f091f51b],
    [0x7ae66a7c2a199c47, 0xc9fb9118661ded82, 0xf34852dac24ab2ea, 0x3da513e74bdb0e54],
    [0x73ffb26c65571474, 0xd22532949a4a7d1f, 0x57d23e6ca46a05a1, 0x5b2d3bff92596176],
    [0x93cc95ac9c4fb57b, 0x77a8a881f113f0bd, 0x93f78c54e27098c7, 0x04fb9b9ee7b27137],
    [0x06fc37839cce78b6, 0xb28c89a9f02dc78c, 0x9450293e5644f687, 0x7e3dbd1883f4b539],
    [0x405ca3269cda17ce, 0xf50d0c7847cee038, 0xc7e8fcce877fcc42, 0x18a399fe613fb9af],
    [0x8ac6f9144d751d98, 0x0991ee268f49c94b, 0x628d367acdfc2766, 0x02813b531e8fd074],
    [0xb84db09c21e5c3d1, 0x2c9fab3fa8b48655, 0x4912b7a7abcd16dc, 0x1ef5e3683ec22b30],
    [0x2a72a43dad054b76, 0x10ad777bdb0a0fa3, 0xb0b2ce5034e68c6d, 0xa5875a98ec9c01b9],
    [0x244505a65070c3dc, 0x874d78215e35b6de, 0xcda4cef6eb65102a, 0x1de85009364ff676],
    [0x3f37fa725eea9a4c, 0x437e49a7bd7b1984, 0x6f1e2b7fd4a7f9b9, 0x90a541430df07bc8],
    [0x77f19a7e8f4da3f2, 0x7e50d069ec0fa054, 0xd1164d859aa21bfc, 0x607e54772847dc2b],
    [0x20b810ff1120c32a, 0x04b5ce104f69e740, 0x5dcca19714425984, 0x21bfebe8143af397],
    [0x3e28307892931c6f, 0xdb25add13709c43d, 0xf7c8f86bd4ca45ea, 0x1db7a27f3959166b],
    [0x3cf3061cf546d47f, 0x419c3ab1675e9fba, 0xac0dc45a5a06bd4d, 0x27f61d28092ad0f8],
    [0x0314b65e32168000, 0xff6eaf97e9f12b39, 0x4dd6a6272ae496d4, 0x9667cb82bbad4801],
    [0x0b1f2cfbc7c00014, 0xe65663e58bc91a1e, 0x9e3419e6f87860d3, 0x7e3c2f8099d61671],
    [0x3f320346bc22ba02, 0x75ef2e5fb1f89925, 0xa7667e1719f4c2f7, 0x9b3b324d04da04d6],
    [0x4765f9656b47d3e0, 0x141982b066de5dec, 0xb4c9898cc3c44555, 0x394e482e9349cfc2],
    [0x988438cd2c795a63, 0x7a1de3356ab9f69a, 0x59e104a6cc3d998b, 0x34f1a6a9425a45b7],
    [0x9585a8a236d8b009, 0x67b89021355145c0, 0x7f55270684160d7e, 0x59ee07039e9976ff],
    [0xd43c32e6d218cec0, 0x9ad5de553f7d5297, 0x014fbb7c5a69fab2, 0x16cd5d0e1306a8dc],
    [0x01182a47397d7a73, 0xc54288cb6eae9823, 0x6a7e3da0fc895f80, 0x87a48e0b9ed54deb],
    [0x21d3250a95983d01, 0xb6884b1bcacd196d, 0x7eef247025e60047, 0x50e3ca28fe54ab48],
    [0xbfcaf66e763c36e7, 0xeed74f7137ae7404, 0xa41a5401405cf5ba, 0x686b6d968370337f],
    [0xcadd8354279c06f2, 0x0b7b288964d2ad61, 0xe5e8b5df5910a526, 0x795aae4fb23de090],
    [0x41220323cefefc57, 0x72be0fb5320b17c3, 0xadb5721a002cfeee, 0x51bdd252a0ea31d0],
    [0x8cfe76501c4bc37b, 0xc49907f914b8ce7c, 0xefd4dc98e4d791de, 0x8389a7b35caa5d30],
    [0x428825bbedeaab99, 0xc06900c69de3a905, 0xaae2bff25638d9a7, 0x18a718efe1fe47e6],
    [0x9c52caf7cf16cc6f, 0x4e4b80c3a51373a4, 0x3ff56250999d4acc, 0x2cd01182a150130f],
    [0x6e864816716d58a1, 0xa61f778991531812, 0x61bc8946e81c4b92, 0x66abcc2df313d586],
    [0xee7d33124c850ac6, 0xe6ebb052b723dc0d, 0x5f95c3ef9d327274, 0x6e8c9d9ed6aacf75],
    [0x0eee906899bb8cb2, 0x447a113f39f2db20, 0x873b76d2bfab1765, 0x38d114b7bfef5049],
    [0x6d5131a89583463b, 0x597b827a9093a08d, 0xaf5ebfda6d0d71b9, 0x278f80bef4ef1e8d],
    [0x3dd9198ae9180945, 0xbfc8669878d61cb6, 0x2683ac49f0d033d8, 0x57a9cf96dae5ea72],
    [0x9142e38dfd0b78eb, 0xaa06438939cfaa07, 0x900f9d3095b195ca, 0x4da55f13767c3765],
    [0x786a01e5cd51ae97, 0xb6ed8728b02200cc, 0x00c192eb9b0821cb, 0x35b15fa78dc28556],
    [0x025db8ddaa176ea5, 0x0b129cc4f5b1c3c0, 0xbfed1560dcd7c884, 0x8609981c4fabe8ea],
    [0xc8673a11bcd60f3d, 0xd024c638eb11bacf, 0x26259f06a793949a, 0x2c089ad1ba69c7fb],
    [0xd96dfa3814555890, 0xfe7e4355dcab45fa, 0x05cd4e5e6e072066, 0x8a7b2308e8b489b1],
    [0x3b2f94e5bb251d09, 0x2dc6de4f38131087, 0x12b9598588bb875e, 0x0ab5de80422f73fb],
    [0x18d6202481ae81a7, 0x2ed98b16b6c0805d, 0xab7473d27f6234b2, 0x09bde872dcb32862],
    [0x1a1fff1657279647, 0xa703e8a34828301a, 0x724ecc5ccedd74d8, 0x225faf4ebf100455],
    [0x571305aa4c32b3a5, 0x36daa0ddb0b5ddda, 0x3df3bae75ed4af51, 0x4b9418798c855a13],
    [0x0b0d2681405179e1, 0xa1ed1ca287b6d8ed, 0x713b664a188bcba3, 0x8cf3caaed23dd049],
    [0x3d0b47dc05c9909a, 0x28e9dd742064959c, 0xbdc25d60b82f36bd, 0x366fc0b7de9e294a],
];

pub(crate) const COMB_TABLE_Y: [[u64; 4]; 64] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x5c1d54c72f046997, 0xc27745132ded8e54, 0x97f8461a14611dc9, 0x547ef835c3dac4fd],
    [0x366f9b838d3aef4d, 0x24edeaf1fe6b7372, 0x0eea463b51d24d24, 0x76d5232aca72cb23],
    [0xb65ebecc16fcbe43, 0xfef8afa7e10db6c5, 0x845f244fb1f19bb4, 0xa8199d0eed359041],
    [0x169fee39e137a624, 0x629404f0e09d01b1, 0x7ca2a2c838165fc8, 0x28e5753e1e2040d3],
    [0xa04a69d87c4bfc2f, 0xc45de4b97538c9cf, 0xff3ad456ae72d32b, 0x0307b6da73eadbf8],
    [0x208fcf33dcd9c940, 0xf5d7a048f99f0739, 0xca50e85859d17a32, 0x42d2efb577a5e9b7],
    [0x10a4e04edd807162, 0xb623f408aab64acf, 0x3a119349c2d05360, 0x9fc297a8ad82fc63],
    [0xc34ec428fcd5ca97, 0x9fff81b0952c01e5, 0xfaf22b1c554b8ff0, 0x076de49a5b8a5ee1],
    [0x73a76e9c4bf4eed7, 0x09c30d43e312ef50, 0x45b4aec2b7cb08d3, 0x2a23224293d733d5],
    [0x970905ad31a91e85, 0x519711809aef9ee0, 0xca02cea8bb3703ca, 0x375339dda98108e1],
    [0xfec2e9b1a78becf6, 0xd165da61af3e8af8, 0x8a335393e2277f6f, 0x865bd62db4ecbb74],
    [0xd75fa01eded8e8b1, 0xb19b2eb7f2b59a3f, 0x0900405ad000b6ae, 0x20f4b2c891b966d0],
    [0xec91cb2f33ac98b0, 0xeef915be98242aff, 0xd86da94450ef40a6, 0x8e01d2cc4ffc7e95],
    [0xc2bb3ae413839bbf, 0x3dabcb6192c6416e, 0x40c7a2a7eb2fa88a, 0x74b5bd469bf7b0ba],
    [0xb695199d34d980bd, 0x8a10a77c659217b4, 0x3c409a84f13e115f, 0x5431cf1056392abd],
    [0x555ff88fe1852a4e, 0x7a6618c1e2453d51, 0xcacad1480cfd7c6c, 0x220d8c081f33e283],
    [0x3ef9e669efcd641c, 0xf23c4878ba9cddb8, 0x2e13e89907dcbb63, 0x8f0b31f1e98540b5],
    [0x4d0fe4442e6e8697, 0xa445918e85592017, 0xba64e0f014684614, 0x558094766f614dc8],
    [0x4ee21b912ea4e499, 0x01c37c9af83734f8, 0x3446cd3b6ef6a35f, 0x46df218fc1029c48],
    [0x0f8f1b5f1fb63931, 0x79bf34d5facece8a, 0x291805708ccb2f8a, 0x75a37300df3c5fb5],
    [0x436ba92465466c16, 0xa1b78a00a1c7657a, 0xced1cfe949f94a00, 0x5dcc826ca692ce5b],
    [0xefa592ca7f680a9e, 0x9f5a367b3da0b0f9, 0xf318c293586c7250, 0x89591b6b5a81248b],
    [0x45a42e03ffe9c13f, 0x81f29069dfae5975, 0x23c788598205570e, 0x6ededfe03b40b98b],
    [0xd67984c103d3c12c, 0x0de20ac1ab591f16, 0xc61ad065b4c888e9, 0x308f62c363d5f2de],
    [0x2e8ddfd8668a0ad4, 0x95a25f2f07bc4762, 0x39652a289054dea4, 0x657aa9ed934f4fbd],
    [0x79585526cf977286, 0xf5e69560bb343c58, 0xff24c0037d2abd09, 0x436a6ddc800a872b],
    [0x8ab135882befac01, 0xd1e0bf243c12ed67, 0xf0908ca3803f3f8e, 0x59f8079048a80e48],
    [0x7bda8340742981b1, 0xbdfadb5a6d9840f0, 0x43df96be862eded5, 0x6613f7e219c80927],
    [0xfc68e6cbf2cbae9a, 0xd8ed5d26264883ae, 0xd772d591b795a8e4, 0x2b1c569836c9eb8c],
    [0x263f9de2cc7d369c, 0x8b005a67925c2b73, 0x4e01f0b5556a7d39, 0x6a8e3daaf162e30e],
    [0xfe1d56c75812a539, 0x2e9917231212b54e, 0xcc4c46857c029ed8, 0x4370db0589b648e0],
    [0x58354c656a369ffa, 0x3d4eb3215d003734, 0xf9fdd6215146096e, 0x1bddfee2b170bd34],
    [0x3416c189d86a1854, 0x21a243013b08d0cc, 0xbca73955f4b00efe, 0x23aa6f70fae1fd1b],
    [0xb0b25e6296436ed5, 0xa4ba8ee234b5b009, 0xd132abb70142f77e, 0x87ea2c368b253538],
    [0x3b86cb1426052d9b, 0x73fbc4360265ce2d, 0x89e14bb4f4c2c600, 0x5c5583eb0db426f1],
    [0xd79204d6907a0d43, 0xa0d4d553a3ba5342, 0x1d9e9bf3009d3562, 0x3bd1fa37f0ac1897],
    [0xec95467fae693d45, 0xc676bd083602e4e9, 0x15994d48a7c2f57a, 0x47373e95c8224e11],
    [0x6de30d2613acc48a, 0xf451dbfea4570918, 0x4c7f7ec230444d53, 0x2a6be7261ffa2058],
    [0xbc16d33267c2f66c, 0x6af42a93a5c6ec91, 0xe658ee29fae87dc0, 0xa6c89865f7c477c9],
    [0xec2f00d1d9af1451, 0x0eaf1412de80df09, 0x7f4c984b26d0fcdb, 0x76f4f6496565ce1e],
    [0x82a49dd285d1284b, 0x202faad8e7fc4d81, 0xe707b91ac3c6361c, 0x3e054332ff577329],
    [0x91e6559bf409dad3, 0xa0bebebe6f4faa5b, 0xc1d3eb951486d7d0, 0x1a3100170a3e77c6],
    [0x6dc70f93d833765a, 0xeb35b5359c13db58, 0xa7a4338284252df1, 0x076ee237bff22244],
    [0xa4b029149128a831, 0xf4c3ff529be10db7, 0xb65f80d08837595b, 0x4363e27ff5fdc00e],
    [0x13c71b1006b82f29, 0xbfa786f918b91d4e, 0x76d43fb136bc322e, 0x390040c95c04f4aa],
    [0x60f8fd9e22a5c4ee, 0xb18a39c4555348c7, 0xcd81cff449d5650c, 0x9efc3ddb016fe144],
    [0x1450934d7b3024e7, 0x388829e8fb0033f0, 0x664e99d9cfb9e5d9, 0xa404f070d00a8a57],
    [0x9262df0e24b4a565, 0xd2b259b3cd6855f0, 0x411856005a628ac0, 0xa2899020f960e224],
    [0xdb0c6ad6a820e0c6, 0x5bc62a737ac36726, 0x11ecd269b43e8a03, 0x04c90f1259fb7546],
    [0x4726cb3fcab86834, 0x2913e851d6db02a1, 0x955308736c8fa143, 0x2207cacf7690deb2],
    [0x70922a1105f37dce, 0x112a1b8fa348eea0, 0x5f9f7007e99e16e2, 0x2dcb264b89655594],
    [0x36a947bec054ca7e, 0xff7c41507d8e9103, 0xe44e58803bab4301, 0x39c7f00b29ced75c],
    [0x5b256721d827f9e9, 0xdce677de013851ab, 0x6b08f88f04f051f0, 0x30e2f57a847d2c68],
    [0x4fada715afd4fb13, 0xd4c1919dd0742fb4, 0x6314d78d0996b536, 0x33f6c10847515c10],
    [0x3ff9826c9200ef55, 0xca469b59e283fc05, 0x7a914bf341595b03, 0x0cdbdef95612836e],
    [0x60ced74dd70d5d56, 0x87a24976da0c9708, 0x1184fadb7a1e029d, 0x33d0e6ef7f51a52e],
    [0x676e41b1152df8f1, 0x62b615e22f9ac122, 0x45f85ddebd4dd527, 0x1b15c58ac4e5cbb0],
    [0x1a8645f1b7e05541, 0x8bee43b0a0aecac0, 0x63ce88cd70ebfb43, 0x6c6ff37d938bfffe],
    [0xf60f2ff584a36f6b, 0xca5b56110f8e297f, 0xcd9f0edbc9ef7883, 0x376040fda21c8225],
    [0xa8bcbff94295a6f0, 0xa286037a0821c83e, 0x65d78840e2258ce9, 0x542376afe2ed2594],
    [0x7d93766939154944, 0xf59d6f8faba73b9a, 0xa6951bd8dbef9dbf, 0x72e8ee7c540e1d44],
    [0xc6c76a985dfe1675, 0x3e4be1378cbdec14, 0xdde69c31fa3c6cb1, 0x24d48a1e5ef7480d],
    [0x34c4152ac2a6f514, 0x55347c801ca03615, 0xc99a5d5f9f828edf, 0x8216fc4adb16a928],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp256r1::Bp256r1FieldElement;
    use crate::bp256r1_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::bp256r1_point::Bp256r1JacobianPoint;

    const WIDTH: usize = 6;
    const BITS: usize = 256;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic, per this module's construction: `pow2[i] = 2^(i*D) * G`, then
    /// `table[idx] = sum of pow2[b] for each bit b set in idx`.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = Bp256r1JacobianPoint::from_affine(
            Bp256r1FieldElement::from_limbs(G_X_LIMBS),
            Bp256r1FieldElement::from_limbs(G_Y_LIMBS),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [Bp256r1JacobianPoint::INFINITY; TABLE_SIZE];
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
