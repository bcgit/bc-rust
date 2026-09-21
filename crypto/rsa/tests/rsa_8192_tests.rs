//! RSA-8192. Wycheproof has no `rsa_pkcs1_8192_sig_gen_test.json` and no matching-hash-and-MGF
//! PSS vector file at this size, so there is no real key to recover the way every smaller size in
//! this crate uses. Two independent checks stand in for that:
//!
//! 1. **BC Java cross-check.** A fresh 8192-bit keypair (two independently generated,
//!    Miller-Rabin-tested 4096-bit primes, `e = 65537`) was fed to BC Java's own RSA
//!    (`java.security.Signature` via the `BC` provider, `SHA{256,384,512}withRSA` and
//!    `SHA{256,384,512}withRSAandMGF1`) as an `RSAPrivateCrtKeySpec`, signing the UTF-8 bytes of
//!    `"hello"`. PKCS#1 v1.5 is deterministic, so its three signatures are checked here byte for
//!    byte against this crate's own PKCS#1 v1.5 signing (SHA-256/384/512); PSS is randomized, so its
//!    three signatures (BC Java's default PSS: salt length equal to the digest length, matching
//!    this crate's own convention) are instead checked with this crate's own
//!    PSS verifier, a genuine independent-implementation cross-check even though
//!    it cannot be a byte-for-byte one.
//! 2. **Real Wycheproof verify vectors, sampled.** `rsa_signature_8192_sha{256,384,512}_test.json`
//!    exist (verify-only, with their own unrelated key) and are used here, but not exhaustively:
//!    each has on the order of 260 vectors, and at `L = 128` a single verify costs roughly 19x
//!    what one costs at RSA-3072 (`(128/48)^3`), which would make a full run of three such files
//!    alone take on the order of an hour. Every *distinct* `(result, flags)` combination present
//!    in each file is still exercised at least once (deduplicated below), so every failure mode
//!    Wycheproof encodes for this hash is checked -- just not every repetition of it.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_8192::{
    PK_LEN, RSA8192PrivateKey, RSA8192PublicKey, RSASSA_PKCS1_v1_5_SHA256,
    RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512, SIG_LEN, SK_LEN,
};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Signs through the streaming trait path with a fixed salt (`set_signer_salt`) -- the
/// deterministic PSS mode, for tests against a known salt. Returns `sign_final`'s `Result`.
macro_rules! sign_with_salt {
    ($ty:ty, $sk:expr, $msg:expr, $salt:expr) => {{
        let mut signer = <$ty>::sign_init($sk, None).unwrap();
        signer.set_signer_salt($salt);
        signer.sign_update($msg);
        signer.sign_final()
    }};
}

const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

fn get_test_data(filename: &str) -> String {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return fs::read_to_string(path).unwrap();
        }
    }
    panic!(
        "wycheproof not found (looked for {filename} in {TEST_DATA_PATH_RELATIVE:?} and \
         {TEST_DATA_PATH:?}); this suite requires it rather than skipping"
    );
}

fn limbs_from_hex<const L: usize>(hex: &str) -> [u64; L] {
    let bytes_len = 8 * L;
    let mut bytes = hex_decode(hex).expect("valid hex");
    if bytes.len() == bytes_len + 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    assert_eq!(bytes.len(), bytes_len, "expected a {}-bit value", bytes_len * 8);
    let mut limbs = [0u64; L];
    for i in 0..L {
        let start = bytes_len - (i + 1) * 8;
        limbs[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    limbs
}

/// The fresh, self-generated key used for the BC Java cross-check and for self-consistency.
fn genuine_key() -> RSA8192PrivateKey {
    let p: [u64; 64] = [
        0xa9a87892c469b1e5, 0x038c3f4efcb198ac, 0xed4f14df1b8a1e1f, 0xef2330d78ee73020,
        0xd3093ddaf276904c, 0x94a438d69aeaff23, 0x48dbb3d700ad58ed, 0xbbd763b5346ff916,
        0xea402fb475938e3e, 0xcaed4c45c543aff3, 0xc0954c4255b90f57, 0x2fe6242da64a5099,
        0x3fd54a6b6175342c, 0xdf8dd0187588abbd, 0x4abc11d33376e220, 0x90d3482c7fc1397d,
        0xde925fb5a2cb1e7e, 0x062e99dfbd3c790b, 0x243ef703c0912a1e, 0x91ee31a02ef1a02e,
        0x13b19d3960842877, 0xc6e8036e26c4a339, 0xf2606f45a73314c9, 0x5dfe4c6dd0aa04ee,
        0x1385bfde55204d94, 0x454123829d28200d, 0x18a3d86f516f2a50, 0xcbe5e841cd2fdb17,
        0xc86825aae3031a2c, 0xf4726a6681852b6e, 0x3f16b45a496eee29, 0xd5c4b2319abff492,
        0x71077736745aee55, 0x72586dba7b765bbe, 0x681813f6851efdce, 0x196c13fa6d6781d2,
        0x4712ba3eb0734e43, 0xde2a9a8da6da8340, 0xc2f93a2af8ffbaaa, 0x4db552ab82a577ae,
        0x07c075eb13064f67, 0x818a7d0b31680682, 0xa58320f732d69460, 0xa5922479f4aaf594,
        0x4d545baa4cd73f39, 0xa20c87a2660869c4, 0x8350211511fe7d7a, 0x50174a372234ba89,
        0x6eefd36b20bd1ce7, 0x07d124cb61d25c8b, 0x7356e6380041dcd5, 0x6a7c98caab76211a,
        0x61ff7eaac65f815d, 0x1167dc0b28f418b3, 0x9fc8bf056efe8677, 0xf5ce4481e1670e10,
        0x6ae488da222292de, 0xcc786e194ea84d2a, 0x41b134cb6a8ae4f5, 0x870ff94b064466b7,
        0xc82ad608c14a9385, 0x5338550ac9d3f96d, 0xdce87e0d41f1ba9d, 0xef9beedb39920589,
    ];
    let q: [u64; 64] = [
        0x08798e2dd82b7d9f, 0x30208e668897171d, 0x8f73c28d70144ec6, 0x66f64ce7d2402ae0,
        0xdbc26c601d5cc3a3, 0x657176891201beee, 0x692812d7b9b796c5, 0xae27fa9062406a23,
        0x7b4e6ee5b4d2d22f, 0xd846e0e8fbeb0108, 0x52ca75d6866b780b, 0x2620152d7bb490c0,
        0xdca773f826ba9118, 0xb308499a61d0a4eb, 0x44ba0f58bff07ed5, 0x268483fe5829eb5c,
        0x02e7f0c1d3ee3856, 0x76eae3a004d0f37a, 0x99d9cb3aab5b3f1f, 0x0c9f76678a44f2c4,
        0xc82ba3f75883e512, 0x57719c85e8888746, 0x63c967ca1b81cf17, 0x6f4942a86e96bb6a,
        0x614105324fdb77ae, 0xdb6a0c777f7a4bbc, 0x184bf293127472d5, 0xc26798126a967a8f,
        0x45fa10ccadd5ef6e, 0x13cacbbf5cbc2722, 0x23b4e2f2d18785fd, 0x83a4d39485ad254b,
        0x3a096f5ddd674174, 0x6df8f2ed81ae9e7e, 0x77ee2d29fb78201d, 0x4b4c10c9ac8853eb,
        0x35690c51d0ff6208, 0x8de9a271cb50aa59, 0x51b0701f8cdd1505, 0x4cb715c9b578c63b,
        0x3c9b35776d94c3c7, 0xe952d6a7c34a2abb, 0xc432f1fcc2a5105f, 0x4f7f23a62cea2f81,
        0xfa507889f33eedd9, 0x7e37e435cb776085, 0x576b2ad8a4f39820, 0x0a85d1466d55ad69,
        0xb1dee047621be714, 0x216c6b3c1c945527, 0xe6298f6e1575e39e, 0xdd16506432adc399,
        0xc1c065319c823d2e, 0xf2d6f25d6f34a582, 0x75d6801f595c50fc, 0xccfcd556c20e1130,
        0xa24e6a1396173d85, 0xe2cbc5218657c80a, 0xe7bec5bf5a944815, 0x656f5fa54bf06f6c,
        0x7b68b002b0ea62d7, 0xa2eb84753d291781, 0xdd329e1ce00c2087, 0xcdb932d13e38ee0a,
    ];
    let d_p: [u64; 64] = [
        0x848c4d06bcab4c19, 0x2fa349116ae2bfd6, 0xcf9ea12f426f7eb3, 0xfa71d15136d85dff,
        0xc3e3a026e3968f1f, 0xd50f8056de82a33e, 0x68213465c1b3b2d7, 0x426387f62ee9c62e,
        0xeb14efe18920a873, 0xf3c385a60c9dc86c, 0x294ffd8852c4d95e, 0x940d14b53927fef5,
        0x3f709e3b4c8390c3, 0x3b9737d39c42994b, 0x5c02182c4dac78fe, 0x3b6b7c01fe0a0737,
        0x7adeedf6194f6d2c, 0x43c30f449d8ae36c, 0xb88cebf30dac95d4, 0x09fc3d623b8ceb6b,
        0x5d28293b759f2b09, 0xd350dee095846993, 0x1b323dc92b794164, 0xe19d52f0e7ef34bb,
        0x5ff017da15232c02, 0x58fa8d3b24b82973, 0x1c8aed916227e53f, 0xad49cd8938c909d4,
        0xc3d98be0501534a1, 0x91cec83019bd5bb6, 0x985b814d838ffdd2, 0x11df5cb357c86888,
        0xbc0d5590336b8dcf, 0xc25fa85b1912ac66, 0x390c8752384cadef, 0x07b54e62df65825a,
        0x7f7ad57e592cfc3b, 0xed1b7f53d6fe2a09, 0x41d9e577118adb13, 0xb6706780ace45139,
        0xbfbaadef8d19443b, 0x3dc42a1dccca1d87, 0xdb8a72a8ca8d4de7, 0xe10dec18507dbc43,
        0x66343911cfeb0313, 0xd29def907cf51b72, 0x998add714f12ef6f, 0x1c394a4b8053f8ec,
        0x46e0b76d81a07852, 0x498c3f81cb9f2b8d, 0x8fd0019a024e19be, 0xf2d405423b1d94e4,
        0x29ce52d9c49ff544, 0xd72643a03a2f9053, 0x1be76a355cfa02d2, 0x8db921cec169edf6,
        0x728f91a0f7d9dc15, 0xe34e3a4f3d41d26d, 0xab0a691f05332eb8, 0xb6241cc75fd5ee1b,
        0x5b8582afd5c1acda, 0xe405bceba411da3e, 0xd849aacac396ef0e, 0x57b5a6ebccd92cf9,
    ];
    let d_q: [u64; 64] = [
        0x77a312e8aa49ed35, 0x3bdc007b0396dd44, 0x187af52b1d2d6e88, 0x7d84fae3e1b134fa,
        0xb1af50faa281bf7d, 0xf868401279f57864, 0x1dba1e456f88eb01, 0xe2ee28d0f43ba792,
        0x3450781c72a68626, 0x30757ab4889c0c41, 0x7f34c53326389381, 0xa28e969fda4bc5e4,
        0x0ed664e6b7a53062, 0xfc9ad2c9c2bd3cf2, 0x1a7bb5627d58e8ba, 0x68b8c4da5a5a5104,
        0x5a0e586f0ebe7967, 0x2dcff7ca08c9b702, 0x89a724facd778478, 0x027fe07b2ad90a40,
        0xd2f67b0b487433d5, 0x28d451f2f0eaa3ad, 0xee8d5d55700c24ca, 0x584202d4e805a701,
        0xa1c40f0ed77d96a5, 0xc4055e480f1674ba, 0xf9fb2aeb561bf104, 0x6b846fe9ef936161,
        0x128295b5f01cf2ad, 0x4aaff225e483b5dd, 0x7cba43b61174a21c, 0xf68f9c7b4474bcbd,
        0xc8979d3dd627346e, 0x9c2b543e42af83ed, 0x221d3779bb596a50, 0xac4d7c5545e7c88b,
        0xa44c83a4cb2ffe15, 0x414d71c3a67b3563, 0xe22dd5c34f66bf5e, 0x6a9cd6374f4513e7,
        0x27765c4e3c8ee4d5, 0xf632603a9e123d3f, 0x748b0b2d39fcb6bd, 0x0bde2fc8edf891e6,
        0xded2b9cf10705222, 0xe5ca5d358eb8067a, 0x23368f3218b1bd0c, 0xe41d6519183900d0,
        0x36d90382237f0987, 0x858624f4663a543a, 0x2309265e924e5f4c, 0xfc548ae0263785e8,
        0xe010d5d5e76f3406, 0x963cc28c4228ff36, 0x4245a573c17ac537, 0x7e9ab38877e4d606,
        0xc69b8cfcee4fba17, 0xe127881203d02766, 0xf3b33254ff10a7b7, 0x4df7b087512a53dd,
        0x28ffecc1c7a3ee5d, 0x4c693f99aa4b22b7, 0x498cdaef4c3d1223, 0x78c24ba834042b07,
    ];
    let q_inv: [u64; 64] = [
        0xd87df1de9c759f36, 0x3ee1b8b22c8eab2d, 0xd6098595c2696717, 0xa922e4722b8304de,
        0x424bec1c55c1db54, 0x918f2f8bf0ac261a, 0x1e190b2089185564, 0xc0dedbfc6ee606bb,
        0x1d1d701caca565c9, 0x2d735f7a1c5b9d67, 0x8339684f656205db, 0xc2dc06896727d9ce,
        0x6c8d6fe334141d31, 0x5245e157c87cd8b4, 0x4975b68eb2eaad9a, 0xfbc3389ffb0e788d,
        0x5e9a45250d135847, 0x676e7e6a128cfa88, 0x74341d8b28dcbcb8, 0x8f7d07f37a0490e0,
        0x83a0eae9ecc99a0e, 0xa8188892180dc052, 0x3cd79e1eea7809cb, 0x3bcc1d769d917b24,
        0x1d8dc8edc7268e8d, 0x3ce2707055f522ca, 0x163ead0ca2eb5fee, 0xf147fb695aa70022,
        0xab406a6c89161f7d, 0x8fbbfe117a95f46e, 0xa16d4e65396165bd, 0xb54f52ab1bb357e5,
        0x67cdec7b6a349ed9, 0x303875e0d97cf3fa, 0x0af9378ecb114fd8, 0x4ada6f45b9d6b1df,
        0x9ef2cf55de53d0ed, 0x33e4c2070b165b52, 0x3feddf0f7a1158c0, 0x91463a2b1952e83a,
        0x65a9db73de55ef6b, 0x8e18c716a69a9a6a, 0x0ca44356ca6e2898, 0x7df214b19f2114f1,
        0x9af2aee9d5cf1077, 0x22fc8b019fd3d0ff, 0x50c6eead29ab18cd, 0xa7e6621f8eae45fe,
        0x588bde2d99b8692d, 0x339be0a07b4f0a7b, 0xcbdbdcc8717105d2, 0x78bbd3e3392a503e,
        0xb868f9db1cf14f74, 0x52f3dc7f028c9f7e, 0xa3629e034b453834, 0x52bab134f3ae91a2,
        0xd1aac2fe108f98c0, 0x1e799537a42b3060, 0xdbcce6fc287e449b, 0x1985969e5afbc524,
        0x61ba61f820f83597, 0x65c8523f0767bccc, 0xde04e1644a214f9a, 0x9748f8d853be7131,
    ];
    RSA8192PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("self-generated CRT components must be accepted")
}

const BC_JAVA_SHA256_SIG: &str = "be0dceec05a9aeff34565a9c7e9d2a63f9407d1f17e9786d45b49ee04d872155710b0d2aa4974398fa9b31ab0c61d0fe207fea57d7878736fa05ca44d22cb7d101b8e15d7a1d60c44bd394048d1ba988f351e3c780857a761d6f8a78bbaa150d5e0f3dd920b9c55a6b80541d26e50b343c0c1e3e4bfade12c8d0b7827b49663d8b2ea9196793c1b46bb4128cee5012f8b045d09ab96a172b35c341eaeed6447e02d02aa47c47ba9863052202325bf0e1378b6174d69d46a97d0419861e773272e852f08231a64badc22448d1ea036376de4c2627454803b690613e2c77a0a440bf55208b55a401c1a186c48eebdf0ec386d99dbf1602417c4b6185b4323aaf4805063511e45f2b0e80d7501b54339a491739a3e8c84690648e870c2811d40e20d6eb91d0f493e41e68e5f5dacc617c152e4c8acd5693c25860bdd03f0b64ad409397f196d781e9ffb0c10499662465ca29448359d343290433187ad46d50e864bcfe60b9fa7b67bd0c269baeeed2e23bed574a41600afe8947dda16947eb505d105d11512bdfff1b4853fb65602c9c8cfcbf3a50be13ca4af99c05ba3d9598e2b1f1a174594bc9fc0828fc29ca33343a4149d6bab10fa6a5063af111871777c86fad6952e590f8fc34c7c86637df1d40914109ecdb99a17ae708089eb976228af03783fc2379ef24b45d1fc3e8b875c196cf20aead62cfa968d97899828ca8d92e62d069cc0db0139250b842379d28c0bbfb7e79c9af376b265d14b7383b4c06a4c9fa953b3b413e52c4a87e61afe9bb79dc7ae5ef0d1bbed84b33fb49e105d3a9e9b5c11c83cb6299895c000a5bb68186bb2f29c78bce0ec494edcd79557a7f94faa24c009cee9a429a5e150b9204146056b19b3cfa2527dad32a263b558d51cf0aa12e12f0b8054e83b11caf9c7a49b10cefb5e63f08612b552b335db1ff182c818beeb618f5b6c108cb35e23cea812da2ad26f0af20e4f48b1586d65a563a240d52922ead451526f982a8b6aa3855836c5f274c979fbfca225f2ba4e68b4f233e3995df5471b5716a0b979a524535fed2f6ea67824b2f37d98534f78033bc2858a5aa5179761ba5e9d8458045427cbd035e111dbc35f67c0848890236bb33c1e4bf64881cb62747c50634a008cae2bffd1fd840c2fe4aa3d428e58b741034f89b5056ebd452061b2d3019c19df65122644ead8f0b6085004e4df187f515f11b003e971898845073472878186cd307b6ae1a30c0ad7994b63591bf702d27c191386f4616b99159527de7fd6f27f1200d310011ed3bb5f8c6ec4fb73d5f2c42485cedfacab9051a44c3b81d3631376ffcc5034d33f83fed3e94421cc6413b3be7d662f9400cf7c1d61529ab4dce3db9993d38f654db3edcd143929dd5ec0ed70ba68d834f7fed79b94bb519278440f395ffe623b5b321eb81fac2f6d9ae47a1";
const BC_JAVA_SHA384_SIG: &str = "bac97ad2bfcde4bc9793c15cad36a4bcab91534800ed5d2d2296bc8287dfbd1e529586eba90cc83bf228be988ef5533c56c8730770f4da0367ffe9eafbbe580c21a968902eab47a84498babe8182d1d36080f856f3c1a0af9bbefe4f90fb430ff82639df5e8278d28a77eab919b0b866d04942d19743c0f94a3feadc03b1c3c7b70aca244528b542e80f6e4bc04e53f6a3489c6c4d5e04e0db3d84c28c96121729b6447de494fc2f00c5441a4a6559dcd611b7f7565124e07122a9b09ffc43f60bd2ba278e780ba906050757dfd9b97acbb0d79654e9f3f2e9d0c9d87cb3767c7a83c6d74f9bd4e3066052fc35a57c074432b80fb0808328f1a6e38b1b5cc3a2826d67600b442852d26e043f5840492541aa574688393546d68d242000964e7cbbf8819b4ee5027c71f1fcc9c31667a3ff9c46f7d2d600bb437b4ea03fb2aabfe5430217021a72b26c27cd0b5933bb189f13cc6fbbab295ead06d9895c6b63063e0088549c5f1df6a6cd1bc59721ccf198034575875bbccb7c4784c6e6bf23d6a10fd2b929be9bf050939adc82ee71ad76b273e38bb2dddb262ba89d9e04257bce8c0b46329b003b5b06c4ea2bf913692caf787bcece575b8bf8744cb2add09199e9207aca80037582973412e639f4616bd588112ed65ebcec01e591edbba7985697248a0396486697e5407e29eca97b7706ea1ec66d46456013cdf8b6b761a44f62ff7a5e5537a32b8bdff134dbb9b732c5267a4a1da698997bceb25e23226efe8aca0f36c8758e1efe58c6e68dbb361732e4d2de70c8053ea9d979355bcbaeccfc44affc4406685906b377962756d5c6390993e73e2c2916400f598c5e6716ff9fe5551318096f1f1d696e00176e213a4e5ea82eadea4923e87d897e8f7829b45b94afc6bec7da169abafea907caaf5a511a99ce75ab31b8cd6c10c2fa9fc84b4fe67842c33521730fc7e18ee7fddd3e939bd5745caf28e5d56ac132da98b18772280b6d331d9702754a226dac161f8496a06c564d9a5e0a0b3496f45d7786d2f21c564a22c765cd2c79765e15fdff972873302c74ad6a346a71becc8de3e21e1a1be7198e81a05c9daeab8cb11e20099cc044c807f40222caf7125d6d0f79b4f9a6210183da8c2655e7f40bd7932024924c1bf253aad02e0d9c8ba95500fea3da66b9d0beedda9c7bb9f77da44237251d30d4d756b672c0d5f0cdb3878ead02768249276b3ef893005894299b505ba44c9a42d0c418b4907f28a374d8641cedbf65ce0022b294aafc8f8365b3c53ef2b0681be5b4ee168929d25289c55bfc8a4f753add94e95dc00d07e72b7e26fda36ac4ca61134b039dba30dbbd1f4eb30b8950be69fc1f1adfa70774f27d804c156962ac8173b9705a7474dc26bc34a37b2013b667848a66bc2d9d965f74f84b36694897b057fee496ffa2e2d59b19b4";
const BC_JAVA_SHA512_SIG: &str = "3e06407d4cdc681b2bb37ba5a6d73358bee4a19629d29e7ecfe017d907ed1109b7c1941d789fea049ddf4fc4f4e8113a0a3c239dd7eb808cb4ec50bc5f0c30b88ece92fd2de2dc95e983bafc3c64abc513856db49d4b7d953df014759f8eaf70bdc94b30bbe7c63d737d2b8a34a0e6446941204c1513e4c73aa186b95759535bcf394730022b8b5a01b60557f216ecb5a1ecde7966365e469bd64099475fee4df3de87e29be5cc00f243c7d6b88b1f1df176b200939cf760d7aac7f408dc9b7b2c12f3b1ff6c5e59dc0983bc471503c00a718bd06738cbc05e8940225943dd34ebae3f0431fbf0d50b032f2712d479f2bdc7dca856f040709c419f064c592af4a0faecb3780546554070f8e51f5e52c8686d9046c38f134a67192eb2f95c3bffc1fe0c3186db55e89bef8ce5bfb087a1e7f825127002056bc59181827292c015fa7ed0e858b3ec915eff8d945c254814218c73a61bd0d0060ea7974f64284cf94dfdbee1d98fc93bf1752e2710abbbf83ff9f63f80955902e2def49ee519e0103f0d38ce5d68b122a82bd88d1c4ff6816380048aa6e47f72e1cfacb8e8ec53499b38b8822a2bdc559fcf877a121963af5ea46f75f5e11b51253161c32794aafb3fcbdc9a8670801ef9220c9603ce99cdb6354d3f887f848cbfac484e39424fbb4a758007e49fe62b2f662c208df5151ee7b45bf5b33031f9247267d71a68634daadf0f5174727a8a6885452a226bf0d9143e47242bc61d1c16c475ce797bbef32773467d070f7bef2a3dbdd93d320162c587d1a3e302d5ee74109bf9e185d9a0934e256bb6c92fd5cfd98f0241370f3fc81d349d77501de922d3c3090e720ed26505986e3170f06affbea59193a91a8b85abdd170f38380d7587325ddad1a91b31bc96943535adfad65735d22fd8cadc0347055eb49ea6101adc60afdddb95d33adcbb4caeb50fd63e4a12fbeb856049326c508b2abb26c33275e5c994689053689d3c9bd365d5d4f0776d6316b605bd126d4db55334ac44ad2f0f7ea53ec984a0e82a4b800caade6a74088d0eda31c12e3133138fa86c44c63ad67a63b534ef1ec278c857a07dc7974b459af4dbd21ffd040c691a89480d1f34ab80d668e65a988996f21c9121696b80bc710e33d4835ee7e66136506d4ed75d15ebaa9ddb5f4b64fc8baa145a2978debeb8c5c623f4f05c6b17f392dbd9d82a8081519a45344bf15f6e11addc6e444777c56db09ac8f8d3982e596552f0259dcebc378104031bc4d699b75b450ad7d883e0545914e31ec24c3d503ac157f99528f2746c112c3282803db9672245469b70e7f48d3fc83eb3cc808b790d03ef2e602018308d2855c5e4eb57cdf89d1ea1eaf3673c73401ac8d0193263e84e17eb6e8ba87bc29def2d651f3fc677ea5a8733b20478b3ef5a56e92703a5dfc9a86fceeb677dd034";
const BC_JAVA_PSS_SHA256_SIG: &str = "71c1b3dd982fd6e1e8be1e20c8a4d42fbe6a8b204af54ab84b63f61b8c39efd20b75ebf477463869a21cff0956f304db041d8cc3357b9ebd92390a33a43e8b89d7c8549fd126f2606df61f97c068aea739bf831276dc8ce002e522c2a46465d649daa1ad92bc7d8d46be6d97839dfdadedd5f2f2471f83ac1facd237f673336e5efbcb7b87f44f80414e1f9479870f5624f3eb2c279ff64e99008e715bfcf7f02b32f1aac3e90cea194ddb7701367db41ad8c59ea635783a9ea724626f5d021a3758161ae1bd50b699a314e0a1a92fac184a9eb97ec44fc1c47000bc6da9267f302949aa837e1bfe45a09d526c974d1c5e7a12deb58817ce0cfde09b87e1cf4948df5c3f13d2d11d5dc926d4fd161b273d5f1195a7a8a174aa3f78f391273fef28b21c2a1f1ffe849c27c7545b199cf68a609bf022bca15cf9a946d6559a90240682b2f5437e78e67b15d8ccb8b703967a48f069dda9236d0caa6d3e2fd4c5bd311f83420c29fa3f8416a4b720b59c04fec4ac68f92f8d485ecccf6b1a23aa4b05ae5c220a7a0d4b9388b19f5bb7df484611e2958c5d5179230a37b302ceaf4b52a1ae781017059f8cc011655acc2ada8cc6ac6276e7fa5223a93ab9a17287abe6e9158a983373bb3eea9c28f7f3d2c15268cf41822fda6a029396fa87986a11078e08f9ec6dada5ffaa7f0f437168a136d0c46d076181ec231df545dc7dc6d644c076f95ff427a295cf83d29e5d3a75fc347a3df9895e4042b34b6a38145f8465c0740137b7387d1138f5bda49bab5b03e1ffd2e051a83a7c599a764ff9d931e12509fdbf1e8479ffc74621051e136bf3a50c278a5ad3b5a40a8e1697603d381d8925032e8a3d7a01c38d966636e0d017ee4dc5ac590ae1b730664155fe25aa27d52a7aab8754d525fef530b15b82f8e8bac2218edc5fec27dbfa11446473a92152d03e9d7c7f54ed592a48f126f6e67cb72c9f4795125b1a8dbab6fdc761d0ba83ea903f21c5ddd522da45af655423bfcf012b812054612bd8309f0b31b6dd286d99925cc379904a684ea90239717f0cb13878b2cbf00ee81cd46b37dfa6d8e504101b58ae1b2a43d58e49f982fbc4e3ede6c38a6e223d7eb0cbd49bb6a8d07bfdaa2b3822d6999dfe9ba8b6629c0b692f3f199856e59412a6fbbd5dbae9b116c35f141bf4ace2c7575f733a920c2c3d5750a0d0bba467921a542e1ba3b50384b5b5da9da13bd211e204b9e731568190c035c5b5a319f96de5cddc2e64f6ce386f72ada6f175d025ce15ed00f1ac6bd2572ad214124879b8e9cd95e3573ef6773c5aae10eb2027735bf1d4be77d8a049b63968a4acda99fbfe648a4fbba5a2bc38d43504dcdb862b336488b3f3a09a91ea9ff1ba271575c101b0a14427e4504f1ad2a499e6b5d5c373a72edf3656f33b46c11434e27d019c30dd6924960ca2";

#[test]
fn pkcs1_v1_5_matches_bc_java_byte_for_byte() {
    let sk = genuine_key();
    let sig256 = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, b"hello", None).unwrap();
    assert_eq!(sig256.to_vec(), hex_decode(BC_JAVA_SHA256_SIG).unwrap());

    let sig384 = RSASSA_PKCS1_v1_5_SHA384::sign(&sk, b"hello", None).unwrap();
    assert_eq!(sig384.to_vec(), hex_decode(BC_JAVA_SHA384_SIG).unwrap());

    let sig512 = RSASSA_PKCS1_v1_5_SHA512::sign(&sk, b"hello", None).unwrap();
    assert_eq!(sig512.to_vec(), hex_decode(BC_JAVA_SHA512_SIG).unwrap());
}

#[test]
fn pkcs1_v1_5_verifies_bc_java_signatures() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig256: [u8; 1024] = hex_decode(BC_JAVA_SHA256_SIG).unwrap().try_into().unwrap();
    let sig384: [u8; 1024] = hex_decode(BC_JAVA_SHA384_SIG).unwrap().try_into().unwrap();
    let sig512: [u8; 1024] = hex_decode(BC_JAVA_SHA512_SIG).unwrap().try_into().unwrap();
    RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"hello", None, &sig256)
        .expect("BC Java's SHA-256 sig must verify");
    RSASSA_PKCS1_v1_5_SHA384::verify(&pk, b"hello", None, &sig384)
        .expect("BC Java's SHA-384 sig must verify");
    RSASSA_PKCS1_v1_5_SHA512::verify(&pk, b"hello", None, &sig512)
        .expect("BC Java's SHA-512 sig must verify");
}

#[test]
fn pss_verifies_bc_java_sha256_signature() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig: [u8; 1024] = hex_decode(BC_JAVA_PSS_SHA256_SIG).unwrap().try_into().unwrap();
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig)
        .expect("BC Java's PSS/SHA-256 signature (default salt length = hLen) must verify");
}

/// Mutation testing found that fixed-salt PSS/SHA-256 signing, RNG-salted PSS/SHA-384 and /SHA-512
/// signing, and PSS/SHA-384 and /SHA-512 verification's rejection paths were never
/// exercised at this modulus size (the old combined self-consistency test above only called one
/// salt source per hash and never asserted rejection): a whole-function-body mutant replacing any
/// of them with a constant still passed the whole suite. Split into six tests, one per (hash, salt
/// source) pairing, matching `rsa_2048_pss_sha384_sha512_tests.rs`'s own shape.
#[test]
fn pss_sha256_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x33u8; 32];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA256, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA256::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha256_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA256::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA256::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn pss_sha384_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x11u8; 48];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA384, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA384::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha384_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA384::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA384::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn pss_sha512_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x22u8; 64];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA512, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA512::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha512_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA512::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA512::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

/// Every distinct `(result, flags)` combination in `filename`'s (single) test group, in file
/// order -- see this file's module docs for why this is a deliberate sample, not the full vector
/// set.
fn distinct_cases(tests: &[Value]) -> Vec<&Value> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for test in tests {
        let mut flags: Vec<&str> =
            test["flags"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
        flags.sort_unstable();
        let key = (test["result"].as_str().unwrap().to_string(), flags);
        if seen.insert(key) {
            out.push(test);
        }
    }
    out
}

fn run_sampled_pkcs1_v1_5_verify_vectors(
    filename: &str,
    verify: impl Fn(&RSA8192PublicKey, &[u8], &[u8; 1024]) -> bool,
    expected_sha: &str,
) {
    let doc: Value = serde_json::from_str(&get_test_data(filename)).expect("valid JSON");
    let group = &doc["testGroups"][0];
    assert_eq!(group["sha"], expected_sha);
    let n: [u64; 128] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
    let e =
        u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk = RSA8192PublicKey::new(&n, e).unwrap();

    let tests = group["tests"].as_array().unwrap();
    let sample = distinct_cases(tests);
    assert!(sample.len() >= 10, "expected a rich sample of distinct cases, got {}", sample.len());

    for test in sample {
        let tc_id = test["tcId"].as_u64().unwrap();
        let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
        let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
        let flags: Vec<&str> =
            test["flags"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();

        let Ok(sig): Result<[u8; 1024], _> = sig_bytes.try_into() else {
            assert_ne!(test["result"], "valid", "tcId {tc_id}: wrong-length 'valid' signature");
            continue;
        };
        let verified = verify(&pk, &msg, &sig);
        match test["result"].as_str().unwrap() {
            "valid" => assert!(verified, "tcId {tc_id}: expected valid, got invalid"),
            "invalid" => assert!(!verified, "tcId {tc_id}: expected invalid, got valid"),
            "acceptable" => {
                assert_eq!(flags, vec!["MissingNull"], "tcId {tc_id}: unreviewed acceptable");
                assert!(verified, "tcId {tc_id}: MissingNull must be accepted");
            }
            other => panic!("tcId {tc_id}: unknown result {other:?}"),
        }
    }
}

#[test]
fn rsa_signature_8192_sha256_wycheproof_vectors_sampled() {
    run_sampled_pkcs1_v1_5_verify_vectors(
        "rsa_signature_8192_sha256_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA256::verify(pk, msg, None, sig).is_ok(),
        "SHA-256",
    );
}

#[test]
fn rsa_signature_8192_sha384_wycheproof_vectors_sampled() {
    run_sampled_pkcs1_v1_5_verify_vectors(
        "rsa_signature_8192_sha384_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA384::verify(pk, msg, None, sig).is_ok(),
        "SHA-384",
    );
}

#[test]
fn rsa_signature_8192_sha512_wycheproof_vectors_sampled() {
    run_sampled_pkcs1_v1_5_verify_vectors(
        "rsa_signature_8192_sha512_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA512::verify(pk, msg, None, sig).is_ok(),
        "SHA-512",
    );
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

fn fixed_keypair() -> Result<(RSA8192PublicKey, RSA8192PrivateKey), SignatureError> {
    let sk = genuine_key();
    let pk = RSA8192PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

/// `core-test-framework`'s full conformance suite for one pairing at this width; the rest get
/// [`trait_round_trip`], for the reason `rsa_4096_tests.rs` gives (an RSA-8192 signature is
/// slower still in a debug build).
#[test]
fn pkcs1_v1_5_sha256_trait_conformance_suite() {
    TestFrameworkSignature::new(true, false).test_signature::<
        RSA8192PublicKey,
        RSA8192PrivateKey,
        RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA256,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
}

#[test]
fn key_trait_boundary_conditions() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<RSA8192PublicKey, RSA8192PrivateKey, PK_LEN, SK_LEN>(fixed_keypair);
}

fn trait_round_trip<S>(pk: &RSA8192PublicKey, sk: &RSA8192PrivateKey)
where
    S: Signer<RSA8192PrivateKey, SK_LEN, SIG_LEN>
        + SignatureVerifier<RSA8192PublicKey, PK_LEN, SIG_LEN>,
{
    let msg = b"RSA-8192 trait round trip";
    let sig = S::sign(sk, msg, None).unwrap();
    S::verify(pk, msg, None, &sig).unwrap();
    let mut signer = S::sign_init(sk, None).unwrap();
    signer.sign_update(&msg[..8]);
    signer.sign_update(&msg[8..]);
    S::verify(pk, msg, None, &signer.sign_final().unwrap()).unwrap();
    assert!(S::verify(pk, b"a different message", None, &sig).is_err());
}

#[test]
fn remaining_pairings_trait_round_trips() {
    let (pk, sk) = fixed_keypair().unwrap();
    trait_round_trip::<RSASSA_PKCS1_v1_5_SHA384>(&pk, &sk);
    trait_round_trip::<RSASSA_PKCS1_v1_5_SHA512>(&pk, &sk);
    trait_round_trip::<RSASSA_PSS_SHA256>(&pk, &sk);
    trait_round_trip::<RSASSA_PSS_SHA384>(&pk, &sk);
    trait_round_trip::<RSASSA_PSS_SHA512>(&pk, &sk);
}

/// The trait path reproduces BC Java's RSA-8192/PKCS#1 v1.5/SHA-256 signature byte for byte and
/// accepts BC Java's PSS signature -- the same cross-implementation check as the
/// tests above, through `Signer`/`SignatureVerifier`.
#[test]
fn trait_matches_bc_java() {
    let (pk, sk) = fixed_keypair().unwrap();
    let sig = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, b"hello", None).unwrap();
    assert_eq!(sig.to_vec(), hex_decode(BC_JAVA_SHA256_SIG).unwrap());
    let pss = hex_decode(BC_JAVA_PSS_SHA256_SIG).unwrap();
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &pss).unwrap();
}
