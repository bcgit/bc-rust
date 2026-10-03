//! The checked-in fixed-base comb table for `[k]G` (SM2's base point `G`), width 6, matching
//! this crate's other 250-bit-and-up curves' choice. See [`crate::sm2_comb`] for the multiplier
//! that uses this table and the algorithm it implements.
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
    [0x715a4589334c74c7, 0x8fe30bbff2660be1, 0x5f9904466a39c994, 0x32c4ae2c1f198119],
    [0x30297f640172d318, 0xef6784ec9a477091, 0x44ef2ee6203f324f, 0xbddbb72e16f0c0ad],
    [0xdc3f9e9b90b304b2, 0x30575d04556bd5d2, 0x82db8385293b4962, 0x5dec1d201cfa7326],
    [0xbadf32318c218204, 0xc915b83030bee951, 0x08172c75e8fcd723, 0xc3fd77aaa834c8d7],
    [0x6ee0babad9e3df53, 0x2dfb517e81c0e352, 0x3d885b4eb185a8ae, 0xd1869b3fff5b3e6d],
    [0x5d910dc1936657f3, 0x0d6fa7f347354660, 0x7a8f622d44777f3b, 0x741cd4ae0e5e38f8],
    [0xc2485e8957ae5ed2, 0x67c9ea4f8d42b904, 0x87fc85a61d8892b1, 0x6ed429a86861c277],
    [0x9bf3db7629176ddf, 0xd53e73af2990e129, 0x5caf459b22655702, 0x0b5aa6d9a4f3b961],
    [0x753675f22de491d6, 0xa55af38d801b8cce, 0xc08a004724056e61, 0x40ad97d9b2054e97],
    [0x1b30ee28a04adc5a, 0x4935f0e4dafc4cc7, 0x57abf49417a7dc5d, 0xb5b309c6a577c8ae],
    [0x2ecd57f2a8aebddb, 0xd0ada976e4160d1d, 0x983f8cb2fa643a27, 0x5366a15bb08ff503],
    [0x6fb3ceb12a2853fa, 0x63487ad721bb5995, 0xe85585dd7379c552, 0xbec9c6fd14f20cc8],
    [0x9444752a1198636c, 0x11724e36c14c1faa, 0x029570bce8237ddc, 0x29100fff4a0bd836],
    [0x90a5816e926fa17b, 0xd93cf4db513e48c4, 0x0d78ef3c7228cb7e, 0x03178e917583d056],
    [0xd6178587f20efb49, 0x9dba2f8c521fc1cb, 0x66bf7dd8265498bd, 0xd31be05182310ab3],
    [0xc897a6b93429783d, 0xb5d6b5765e42dc7a, 0xa5eee9d4a635ff82, 0x06687d1078ba0903],
    [0x0c022220a560e0ec, 0x40e69eb3fa9a8e9c, 0x21ef2cee9322ac95, 0x8ef2fea54288855b],
    [0x08b54030bdad5bb8, 0x7679994e7f010416, 0x39d782b377963b74, 0x72863b2848bb975c],
    [0x72174d6352073294, 0x353bec8490520ed0, 0xf2c6592776d36e67, 0x46f2d836da2a1cef],
    [0x34e2c829eaeb2769, 0xb2bb63ceabab6d62, 0x156ab43cfbf7e8b7, 0x6f88c5d3870fda46],
    [0x20139aef6baf953c, 0x75181c03ad9c7d4d, 0x929e86aed802aee5, 0x1bc853c658824ff4],
    [0xed7e355357b93b75, 0x3d87d0f5d9585b93, 0x3c516e063c8eb8c1, 0xc1801708a36ec12c],
    [0xcd5b2e5c784bd7be, 0x09a8bbbbf058d564, 0x6326c52bdc6bb6fc, 0xdf084bfa71ba22fc],
    [0x51c3de76d5113448, 0xb13a7919d9559ec7, 0xb465fb3576c7d63c, 0xa0a79bcb8e20b3fe],
    [0xa4c19824f806e454, 0x56cbda20382be57c, 0x961e17f2ee0db436, 0x3b21e2cbf460be30],
    [0xce511bf8e92252a7, 0x515db7d068550f8c, 0x93581561ea437b0f, 0x36dad43db0097efe],
    [0x263c68c8124af0d7, 0x3b02064371b60c09, 0xa97f1ac7e87eb620, 0xe04240dfde0bf19f],
    [0x126e9488176ac6a2, 0x014348a239083dd4, 0x51d230b8b0c290e4, 0x73007c218684ea44],
    [0xcc45d4b848946c45, 0xd5859cbd0b7a8a64, 0x0b0adf45a7434187, 0x6f620d4ec14c1857],
    [0x77e632ec0866c96a, 0xd5e344e5a52f1a43, 0x482f72079cdeab8f, 0x5d499c6d6ed92a4d],
    [0x2d6cdb59b7cf18dd, 0x45ab5696e3788f28, 0x78fe14a98fda73aa, 0x260c3de859294931],
    [0xf8e996c937040556, 0x965ab458322fdcb2, 0x4a21d0a2b9411d1d, 0x20dc3a017e6b3e61],
    [0x72a383a2c79a77d5, 0x05a6ad88a0e0605f, 0xd681b2e984c9c838, 0x20b96ae6a9fde8c6],
    [0x3e3f57f2232c6f08, 0x809b47f0bb093ebc, 0x0dafe0b2263f9631, 0x0d6d881baaa41540],
    [0x87d0a8abd7f4a968, 0xeed3035ea73ac891, 0xbd3ae0887bee9225, 0xfac16b813f440f26],
    [0xfcf868f82e2d7e27, 0x54d19b6afaaa750c, 0xec3403d09dec75ef, 0x928f0bb1e5018ccd],
    [0x9593e2fb1ada0120, 0x098b2676b5b292df, 0x63c10b1b02cfcd0f, 0xefffbb5f9ca7fdb3],
    [0x93d1a976962e79b4, 0xbd61c14f485b117f, 0xb3852db296ac32c3, 0x7bd08c5bbaecf1e2],
    [0xbdbd8499c54a069a, 0x9ab6f46c8d7d7332, 0xb08af5f213c6d9d0, 0xf651bb9a2fae8ceb],
    [0xe13ae537f0d74a60, 0xfc5c71c21419b747, 0x9dbf20e1aaa80c3b, 0x6b823ec2b8c0bef3],
    [0xc44582445e5f1c06, 0x8ded9fd756aa4d8b, 0xf19c393c666b59ed, 0xfc0da5d731fdc4d6],
    [0x3efc2b1519ab611f, 0x6bfec55600a04baa, 0x504896fe549b315d, 0xd745be971421d08b],
    [0x86da9e03d5d9ad8f, 0x562edd8f08957753, 0xe0bc92bee76e48cd, 0x362323599a5a81cf],
    [0x40ff530c79e067a3, 0xde0ec69b091056f0, 0x2c4f093879282347, 0x95b4758cc5803244],
    [0xc341ab9154c886ee, 0x54ae000c6cadd610, 0xe923576b2159a153, 0x18a50eb80d506782],
    [0x0c990bbb3237f366, 0x144647a2b61eb0b4, 0x9e17ab8826b55245, 0x7adf2798ac48e621],
    [0x337f8816ac9b1c43, 0xb71cd27f13454b35, 0xab83576f76147dd0, 0x20d371742deab886],
    [0xc2ef0dee3cd36c73, 0xe9fe773bacd0610e, 0x3d2c02501f0fdd2c, 0x96209cfa241789b9],
    [0x6f6c11c626e528be, 0xc78c24771d9bd9d1, 0xbe87718b1c154eeb, 0x95d9391f216b8021],
    [0x3d5bfe5802e930c3, 0x74a7234cd495ee2c, 0x3bb4c90912ac6b1c, 0x20041f7006d29f96],
    [0xbaf850bf0f429ebb, 0x60fec0f965a5e199, 0xb52a1c2d73c9808a, 0x9656e740e6b54848],
    [0x5cf53085cc4d2ede, 0xce4c2911fc77ee11, 0x828feae65f7134d2, 0x914a848e5673024a],
    [0xff925e20b53b4662, 0xa628335e0805770f, 0xae493b9409b175d8, 0x0191af58e356cf1c],
    [0xd1a82d4aeb85d4d9, 0xd9dbe53f79884646, 0x924c98d3a0b12bc0, 0xbcb12cee0d7da4fb],
    [0xd9cb4009613f1856, 0xdd61c6e146f7c005, 0x9acc40ec12d25a8c, 0x8e775e0175d964cc],
    [0x88625cad773d76e6, 0x91511a7494c425f3, 0x1aaf33c002dc65da, 0xb4db03cb61c6b4b4],
    [0xa8cfac075abe26a3, 0x107a785ab5b350c2, 0x9cd34055316aea68, 0x8fb56dd1691864b8],
    [0x51b5893000755844, 0x2627e603b5146640, 0xc40cd27135fd24ef, 0xc53979576e2f9996],
    [0x71633d18db7c39ef, 0x8f2ac0cb16cd69f8, 0x499f9fc01be7799d, 0xb810e071bb5cd0d7],
    [0x50b1a14d547f6ba1, 0xc50e86c62fb93522, 0x7e00b050a77cb534, 0xbf8cec2ce55aef6a],
    [0x64730071e3921016, 0x572b05bb9846b7c5, 0x609c96317455b218, 0x0d33be90d266965f],
    [0x3119de20ebc172ac, 0x078e7cc0d524894b, 0xbc8bd2119d638830, 0x48cb13104b525dda],
    [0xd1e7453e1e59bc8e, 0x7f0541628a9574c4, 0xfb5fac573ed25e17, 0x7c8c4433518025ef],
];

pub(crate) const COMB_TABLE_Y: [[u64; 4]; 64] = [
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x02df32e52139f0a0, 0xd0a9877cc62a4740, 0x59bdcee36b692153, 0xbc3736a2f4f6779c],
    [0x7d748dfb2957f9bb, 0x17a4fdca60443ba0, 0x67c440e8bc64c48c, 0x58bf85f5bbb9c432],
    [0x11e35829dd62dd65, 0x1b5f64616eb50a12, 0xacc4aba748697535, 0x3a3b657302465f1a],
    [0x4a3759686ddd1a8d, 0xd17459393ef8dfd0, 0x9eb6112e0f059ca5, 0x419a3cb9895b4a54],
    [0x2d76ffa5c396f9b0, 0xc1f7f09d121ae36b, 0x68fd44137ca2d1ca, 0x47aec31d3d5c2644],
    [0xa545b0fd992fae9e, 0x70e8ccd2752cb56d, 0x713be4a54a682331, 0x86ace92ce4656e50],
    [0xc698accb967977d0, 0x7cd12a528f10add1, 0x9cbb726b81b65ac1, 0x9f2e6edf8f19b983],
    [0xf08bf17067ab7ab4, 0xb47d3dfc9919b007, 0xc99b1c7de482791e, 0x01c94fe169f7cd30],
    [0xf392463627849851, 0x7b76cf052c8c2b87, 0x10727fae95e1ae8c, 0x98685c7df0c04a43],
    [0x18920974aa57143f, 0x38f4a412e5d0db43, 0x1cd16fd447c6a2e6, 0x2cf9038f8b921ee1],
    [0xcdf2b3461b728fd2, 0xa5216f7f58067224, 0x17b48358379a8651, 0xa54cad0b2f6a39e1],
    [0xc43a62c585503137, 0xd58c9c4a502c211e, 0x9162a6b8a162bdca, 0xc660365ca30d71b3],
    [0xc087a4767c73811a, 0xfd68b2636110d7c5, 0x81ee840404a88143, 0x7a84a51f8fc875dc],
    [0xb3f9a3a0d11c1f17, 0xf16584b911c6dc86, 0x3bcd5ef97419b437, 0xeb8c287fb1cd1b2f],
    [0x46b412844af6fa75, 0xb9eb5d28e023c3ae, 0x2c3c3a9524e64265, 0xb9090d54aace33a2],
    [0x036e4394ee352a7f, 0xa8133f73ada63db3, 0x1a7c23ce9652df72, 0x61a557d8490c51dd],
    [0xbe9d68a91498ea63, 0xb2b9c52c58d671a1, 0x17925255a842f06f, 0x404837ce7f6769c3],
    [0x8230861d98741357, 0xad6fbc514dd4e7bb, 0x733ab9a4322107c7, 0xa4fd30f1a4c97421],
    [0x0377fc6d3db7be51, 0x6b26f7746d733b22, 0x3d6f432bc01192f9, 0xc0aba70ce0b5ee0f],
    [0x41a6bbdbc91cab81, 0x01a1b8ea36117413, 0x888ae651663e9731, 0x7746173c72f5fb73],
    [0x4e4cfde197c46386, 0xc059f44c71177b9f, 0x23e2d11acec5c4ff, 0x4b80577fba0b8bd9],
    [0xf5bf536c2ba4fc63, 0x26c1c3e7a9646c92, 0xf403ffe5a4f1845e, 0x41bc7859837e6b16],
    [0x07a5b34046cd75cc, 0xd805bbf569579f5f, 0xfe5b0cec62085d99, 0xb56b7fd8539a97b9],
    [0xa3400ff74599561c, 0x46c7b206f0b0dea7, 0x2c2a2bcdf1d83d3e, 0x0b7de6648d942253],
    [0x14410812ef0180a4, 0xdbf936f5adf73405, 0xab7e1bf6f17f39a6, 0xdbbf77d39f5b7efb],
    [0x0ebb1fc4ab517dc7, 0x1440ab816918b140, 0x22e8115f4fa40e9c, 0x608ba5a6654dfa89],
    [0x857b3a697d8d6e9b, 0xa129e1729a4813bb, 0xa43e41765de86e0c, 0x8f6020ba36c190eb],
    [0x4ca594ca8433f3ef, 0x14a39d1075d22f55, 0xca4985075f659fde, 0x9789ae39187c3019],
    [0x79cf0ade6534e2e3, 0xd559c14b43929fad, 0x4a91bda3cb8e93b7, 0x86ca3d9a45ddabdd],
    [0x738e3e3dfb8deef5, 0x143f245fee4f04fd, 0x83997f458fb0ff3d, 0x04a28a30225ee6f9],
    [0x15a0ebdb9366890a, 0x7cd9bc2243fc7dad, 0x56dbe637a9cac5c8, 0xa07828d1a48e43b2],
    [0x143a57f20804d010, 0x0d18f09a537888a1, 0x085914296f7ceef0, 0x2bd03eec6509d5f1],
    [0x8ccec33be0a1dd96, 0x345f390bce4b2ddc, 0x742d263ee159f68c, 0x34d73d523a08adcf],
    [0x56eb4f425cf2b73d, 0xf4b163e56e50b55d, 0xe14a9150fa0305c0, 0x9785727f37c59c6c],
    [0x5a70cd7a972a5abe, 0x29f02f071d2701a6, 0x3ef174da781d95ad, 0xb95a5bd20276090b],
    [0x00cda4813063c68b, 0x6229d0786f28ae76, 0x0f927abfec0435b1, 0x9c37e1160ce7580b],
    [0xe694cd53342755b9, 0x43bb553e9fb29f7d, 0x792fb9debd7d70a6, 0xe160f12e1d05b504],
    [0x3000324bce86aedb, 0x9ba0c6d2e5f6eccf, 0x4a607fd220df4e55, 0x6c52198024e94c00],
    [0x54570c536795109c, 0xd484dba50c8558b8, 0xa21a49f531ff65d2, 0x58686a5f875ff04f],
    [0x6ee66dfcdcb90950, 0x7b820122a5c07d74, 0xe87135924528a3b1, 0xb09a50e1e2eb4f2f],
    [0x77d359ebc87fbf4f, 0x93964d1047168f26, 0xdac2730cd8755e03, 0x8dc3d0e4f160d179],
    [0x4837a1a14b89c855, 0xb2174cc98115f228, 0xb174667749595bb8, 0xb81aee315a0ed4db],
    [0xea0c48076598b02e, 0x7d0c5c8730b46a5b, 0xb962395e48492e0d, 0x79d728fbb76242b9],
    [0xa84bef0712d0cdf4, 0xa212c8c82d71c438, 0x5adb8aa4ceb59a4e, 0x1f8a3543416aa8d6],
    [0x78cb15480c85466b, 0x42acb71c101a17c8, 0x10da8babea9b27c7, 0x8bab6db5c4bded15],
    [0xa49ed2f7333a7fa0, 0xc4fbd4d8af8c2793, 0xb610d7a59a6a81d1, 0xefe279db2499b1a2],
    [0xe5e4cbd94d62f32a, 0x81feae7696260c18, 0x75eb41344b0d1973, 0xcbd8f6bdf79adb68],
    [0xd5dcb13ac47e261b, 0x0c2de49f70cabee5, 0xa52b44b933b8b580, 0x2436c98dd252516b],
    [0xe58d49b2b2896dfe, 0x5abe4bb1c7508945, 0x53b3ec3f8313782e, 0xf423f6e7dcacfead],
    [0x161e1ec2b2fc689a, 0x82f0a6ff6dcf3667, 0x0e724a76846ff153, 0xc53969eacbca9411],
    [0x214f504c1d7c8da2, 0x0777e406f44e9454, 0x96f834787b40f380, 0x9c065faf561c29c6],
    [0x3cc2e0a2d17ca7ab, 0xa81528877a79c99f, 0xc2cdcd3ff8b499ac, 0x5a333a3b39026531],
    [0xef0534400cc19085, 0x8ee09a42c64c2daa, 0x94e208975a8e84b0, 0xb808ee9f7800e89e],
    [0x484d72b85df5cb8c, 0x5a75ff19019bb2b0, 0x7fa879a8fbd82fab, 0xf5c56db20f37300a],
    [0x103880ae2cd7e0f8, 0xb1e55dc0de64187c, 0xfbd460818931057a, 0xd2d4a3a0134df8b5],
    [0x9dbd51ad0c9b9d07, 0xaeb88b187f2d27db, 0xd213ada3f6e2c7ac, 0x6b5b5a5815241dca],
    [0xaa41697e267da38d, 0x0dafdd8460455ec3, 0x82c56124fbfe5b9f, 0x8ee688f8ec2f6b2c],
    [0x50a6d2bada74067b, 0x177d55481c602d6e, 0xfaa2d230bf89412c, 0xb2e11b1af5c6073f],
    [0x52c7864a9c416c95, 0x2e12f61de2fa70fd, 0x627722935b7cabba, 0x00685ecdfad27705],
    [0xd794cd1077b9ca0b, 0x0c5fea2983fdc35c, 0x729492cdd2c5ad2e, 0x31feb3cf5dffbe9c],
    [0xa42b2668d30d1ae0, 0xec5daa69f8efecc0, 0x60c24211b430b4b6, 0xcd121826ac0b5871],
    [0x1e7019dfcdec72c1, 0xee69d284d5ba27e1, 0x4407da0bd774691d, 0xd3b1bf326c3abdd6],
    [0xead550d29cbe50a7, 0xa132a509dee07e44, 0xeb491785859f17cd, 0xc75df76213e683d5],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::Sm2FieldElement;
    use crate::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
    use crate::sm2_point::Sm2JacobianPoint;

    const WIDTH: usize = 6;
    const BITS: usize = 256;
    const D: usize = BITS.div_ceil(WIDTH);
    const TABLE_SIZE: usize = 1 << WIDTH;

    /// Regenerates the comb table from scratch via the crate's own (independently verified)
    /// point arithmetic, per this module's construction: `pow2[i] = 2^(i*D) * G`, then
    /// `table[idx] = sum of pow2[b] for each bit b set in idx`.
    #[test]
    fn regenerated_table_matches_checked_in_constants() {
        let g = Sm2JacobianPoint::from_affine(
            Sm2FieldElement::from_limbs(G_X_LIMBS),
            Sm2FieldElement::from_limbs(G_Y_LIMBS),
        );

        let mut pow2 = [g; WIDTH];
        for i in 1..WIDTH {
            let mut p = pow2[i - 1];
            for _ in 0..D {
                p = p.double();
            }
            pow2[i] = p;
        }

        let mut table = [Sm2JacobianPoint::INFINITY; TABLE_SIZE];
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
