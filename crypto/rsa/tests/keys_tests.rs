//! Validation tests for [`bouncycastle_rsa::keys`]'s public API, including the
//! `PrivateKey`/`PublicKey` impls `rsa_2048` gives its aliases of these types
//! (`RsaPrivateComponents<32, 16>` *is* `RsaPrivateComponents<RSA2048>`, so the traits' methods resolve here once
//! imported). The generic boundary conditions every size shares are covered by
//! `core-test-framework`'s `test_keys` in each size's own test file; these pin the layout itself.

use bouncycastle_core::errors::{KEMError, KeyDecodingError, SignatureError};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::keys::{
    RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey,
};
use bouncycastle_rsa::rsa_2048::RSA2048KEMPrivateKey;
use bouncycastle_rsa::rsassa_pss::RSASSA_PSS;
use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_rsa::{RSA2048, RSA3072, RSA4096, RSA8192};
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// The scheme the encoding tests type their keys with; the bytes are the same under any.
type Pss256 = RSASSA_PSS<RSA2048, SHA256>;

// A genuine RSA-2048 key: the first SHA-256 group of Wycheproof's
// `rsa_pkcs1_2048_sig_gen_test.json` (`tests/rsa_2048_pkcs1_v1_5_tests.rs` has the provenance),
// with `N = P * Q` by Python's integers.
const P: [u64; 16] = [
    0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
    0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
    0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
    0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
];
const Q: [u64; 16] = [
    0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
    0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
    0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
    0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
];
const D_P: [u64; 16] = [
    0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
    0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
    0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
    0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
];
const D_Q: [u64; 16] = [
    0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
    0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
    0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
    0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
];
const Q_INV: [u64; 16] = [
    0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
    0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
    0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
    0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
];
const N: [u64; 32] = [
    0xf7820283f742b9d5, 0x6f453d1f5b4c2e9c, 0x9a02e5a530e77306, 0x5d12569a62807d3b,
    0xc22c4e5ac0f7c1a4, 0xf9f85e7975005d9b, 0x1b4d9cae79d460d8, 0x69816f48698bcbba,
    0x126422f590975a19, 0xfd7afc3e09ada0f1, 0xed5411eb878daf05, 0x4c03145b5d3495d4,
    0x12be82de4d1ece6b, 0x21d0fceca08d945a, 0x7d9658594266f5c0, 0x4c22da610428e09c,
    0x90ed81299615d981, 0x7a1fa26a8dce26f4, 0x3eff8f17e1a02939, 0x254a2fe9765313a0,
    0x3d3e42e46e48c98e, 0xcd20f79c15e8247f, 0x2ed8a7711a1253fa, 0xb5ab393189db9251,
    0x9e89d6eac8845097, 0x1700f65903b46942, 0x1878d80325b6ef5a, 0x37f9746d3f7cafd3,
    0x094fa1fee82224e6, 0x4a8a5b462ebef717, 0x6e45567151355051, 0xa2b451a07d0aa5f9,
];

// The same primes under other public exponents, with the `dP` and `dQ` that go with each
// (Python 3.12: `pow(e, -1, P - 1)`, `pow(e, -1, Q - 1)`): the smallest odd `e` with an inverse
// modulo both, the largest below 65537, the smallest above 2^32 and the largest of 64 bits.
const E_SMALL: u64 = 0x7;
const E_SMALL_D_P: [u64; 16] = [
    0xbf38d08f8f0f7bf7, 0x973accc1d377c0a9, 0x2e4f57f21e05c72f, 0x7a9c318e49c23885,
    0xcd7b78f0d59b3ea2, 0x17e83353023df656, 0x3b7f18f435a1844b, 0x491c70fb73aa444e,
    0x9fbfab8c49e42e3f, 0x3aa6058799b48d76, 0x6755601156e10b7a, 0xfd2606c5dd1ab10a,
    0x6eb9f5e35bbaae30, 0xa0699c8151d8c352, 0x6b0a725dfea07447, 0x7ddd2de51fb884e7,
];
const E_SMALL_D_Q: [u64; 16] = [
    0x494d0e526aaf2f63, 0xcda17dddc2ce108f, 0x4737bbd2ce2d494e, 0xeb2fb03b956220fb,
    0x41c7b5f71e241eaa, 0xa140768d073d2c56, 0xab845d87a3c1e854, 0x74e4485c167c7432,
    0xc4c3e4a93eae1572, 0xaa9e4e2d15963469, 0x348e83161e9b4567, 0xc82548f0df8a8601,
    0x22abfa23c8ffb97f, 0xcbfb35ba8139f428, 0x0cf4097c6cf43891, 0x8712ef132311ff48,
];
const E_BELOW: u64 = 0xfffd;
const E_BELOW_D_P: [u64; 16] = [
    0x77e6a34950d3cb45, 0x18e839c8bec68dce, 0x535f3bbc7add4f66, 0x158e1c8c426a3cb6,
    0xb733c15ba1860dff, 0xdc74a5a22f0078ac, 0xf218ab3dd9b0832a, 0xe6a06dd278d3d999,
    0xe1352bb095d9d052, 0x8863cc6003e9d305, 0xc215c51ea4476905, 0x7512ff4e89da1d31,
    0x835e8b2b98ab635b, 0x04d6d535dcfd533b, 0xfa8ff1b88cb32028, 0x005dc9a74f6f510a,
];
const E_BELOW_D_Q: [u64; 16] = [
    0x03826470445163b9, 0xf0d38e97e5146cf2, 0xb2d17021f389ad85, 0xf615156a2a2c9422,
    0x350f50b09febf84d, 0x5e4a38e29ea4071e, 0x9df43b6bec7674d4, 0x9eb0cfdf8a76ae95,
    0x575724326fb39135, 0x732640a7c5606412, 0x54d81126d12a574a, 0x33669f24940094f0,
    0xb2fb9cc530c6b5f4, 0x93e903f90fa61063, 0x8d9f09cd08d53532, 0x49e8d2d188652245,
];
const E_WIDE: u64 = 0x100000001;
const E_WIDE_D_P: [u64; 16] = [
    0x2a5aadf862509241, 0xf4e20920ff315f12, 0xaeee9ede3c51ac00, 0x8bfc23f3be90233a,
    0xe3ba1b4fc024a574, 0xbf1114de95cd0ccd, 0x99b53863ef13800b, 0x1ec975792f3daece,
    0xfcacb48978fdb324, 0x6e2fdd52d1aa2c70, 0x139b5a277eb919ec, 0x39fb7db865e8df3e,
    0x7c2390466bf502a2, 0x8b8cdb4674eeeb33, 0x98c61c689f2266a7, 0x8c145c9cf5717a8c,
];
const E_WIDE_D_Q: [u64; 16] = [
    0x01593384c82b3989, 0x8b72990d63f57e7a, 0xac6fd29d8dc6a8c7, 0x20878c7a0bf9b0c9,
    0x5061b5bc2701a64d, 0xe39713da5fc8694b, 0x79406f9357eeaaa4, 0x86c92fa01aae34db,
    0x6d6cc27867f92710, 0x18ee118e11964127, 0x7ffeeac8bbafb780, 0x3c209fc23c7a39e2,
    0x1683eebb30e62085, 0x6d6ed21bad159c65, 0xeae8d36fd3e99db9, 0x38c34f9e91cfd1d9,
];
const E_TOP: u64 = 0xfffffffffffffffd;
const E_TOP_D_P: [u64; 16] = [
    0x2d8f40f711030b55, 0x612763e1a7e4d026, 0x466b92677fcb720c, 0x710630dad58debc5,
    0x271660ecf1f4e376, 0xe8a2b8fc28878425, 0x920c2036ef255e14, 0x48e81c71ca282490,
    0x8674acbc5ad74738, 0x18583b1402b582b2, 0x0a09b5d952847ed0, 0x5ce58cfd03517976,
    0x4ed20001082a4aa6, 0x3517632c437b0b34, 0x1ceb827a39234d34, 0x6d0343843e622cb6,
];
const E_TOP_D_Q: [u64; 16] = [
    0x7466c40e5e4fdf4d, 0xd485574b3574477e, 0xa8c65f4c534ffb00, 0xc7f41139b8b0b17f,
    0xa6fd09e60c48b8b9, 0x7fecbee2c09736de, 0xf204586ce1479ae9, 0x0a2125f0ccdc0532,
    0x4672d26c4f4bff30, 0x12dcf4d1a17957c1, 0x832911cd468281f7, 0xcb91763e8bf7d54f,
    0x6e5e6376f37061b0, 0x490eb823fda561c3, 0x9f27c91a5600208d, 0x17f04b3290f24fc2,
];

// `D_P` and `Q_INV` times `2^64 + 1`, modulo `P - 1` and `P`: components whose congruence
// comes to `2^64 + 1` and not 1, a value that differs from 1 above its lowest word only.
const D_P_HIGH: [u64; 16] = [
    0x329bfae4efd19691, 0x20ac80997b1152e1, 0x3dc78d8e5b3fc2e0, 0xc196ac7710ac253f,
    0x69a71a0ece3e762e, 0x8da3f876623df6e4, 0x98b816f165a71c4c, 0xd855c2f8fea734b2,
    0x03f9a99108d99a49, 0x524e49160f8060db, 0x5e27b31a72033dab, 0x767b84b4093701f8,
    0xcf4687de505b2b4e, 0x8b822646a477e4be, 0x26f16a0e2866d812, 0x765394c55a623a1e,
];
const Q_INV_HIGH: [u64; 16] = [
    0xfa55eba0dee1766a, 0x6fbe7cd2bee98a08, 0x7a2fb9386f2dff81, 0x1c0e71343137908c,
    0xd2414046f66b13c7, 0xa5a5fb79d4b06a80, 0xdb850e432f80fa5c, 0xa439055284c1bb2e,
    0x3be23ace28716a26, 0xeae616db11f7cc78, 0x0c40539dfedf1ed6, 0x7da41e9398944b5b,
    0xd411f9513c198515, 0xb390f8a4faeafae9, 0x21dd8e936ffcc49a, 0x570c1d12866056bb,
];

// Key pairs that the constructor takes and SP 800-56B Rev. 2 §6.4.1.4.3 does not, one for each
// of its criteria, by Python 3.12 (primes by 40 rounds of Miller-Rabin; every `dP`, `dQ` and
// `qInv` the inverse it should be, with e = 65537 where none is named).
//
// LOW: `p` is about 1.3 * 2^1023, below sqrt(2) * 2^1023; `LOW_P_INV` is `p^-1 mod q`, for the
// same pair with its primes exchanged.
// CLOSE: `q - p` is just above 2^900.
// COMPOSITE_SMALL: `p` is three times a prime. COMPOSITE_MR: `p` is the product of two 512-bit
// primes. Both go with `COMPOSITE_Q`. COMPOSITE_SECOND: `P` above with `COMPOSITE_MR_P` as `q`.
// SHARED: `p = 6g + 1` and `q = 8g + 1`, so LCM(p - 1, q - 1) is 24g and the private exponent
// of e = 65537 has 1023 bits; that of e = 65539 has 1025.
const LOW_P: [u64; 16] = [
    0x2de7a655eb9290af, 0x6424696b02a0d676, 0xd9edc4c41ba8f717, 0xaea9413abfe74974,
    0xfe824590319e16d3, 0xfe9bc4d06047f54d, 0x65190b64a4c53325, 0xc371b3af45b32031,
    0x93d0438a38c8c25e, 0x999cc2e548f3fcc2, 0x696327472c84f674, 0xeb8748b4c0811bd9,
    0x0ea2fdcbb98eaac2, 0x2310b977c40191a3, 0x8a9a069bae2c6d07, 0xab43d7d93b360a0e,
];
const LOW_Q: [u64; 16] = [
    0x0d65180d51ca1125, 0xf8299b0f564b3ae7, 0xa07cde51c81bfa20, 0x6aa109b59dc4ba7c,
    0xd673e9aae15f5a37, 0x0562871e19c938c2, 0x4a6b368a555d7a9d, 0x71ffd529afe6d367,
    0x7be663d9a71e1120, 0xc3010a24a9af5e80, 0x7ebb7f93461e4430, 0x94896263f78e5d68,
    0x54e1fbe387424519, 0x1d30bc9ccbe3cba8, 0x84080730aa8f63d6, 0xfb81051c7ba4f1c0,
];
const LOW_D_P: [u64; 16] = [
    0x4f8abe02f3ea72bb, 0x615c24be44c0f34d, 0x5d3661d05041bfc1, 0x82cb140f65b79279,
    0x3aef4fe501e90bda, 0xeb2e22962cb7263a, 0x659532390d1d974a, 0xa11b5f0f149e87ae,
    0x3f858c502d185fc2, 0x1155104991eb671c, 0x4987cf6b755f1a68, 0xf8ce1b0a3ce80c37,
    0xf3f4ea85d8fd81aa, 0xa4aee9a4b1d6b07b, 0x7b279328cbf00492, 0x327443239900fb87,
];
const LOW_D_Q: [u64; 16] = [
    0xdbf01377225990a9, 0x61dd380ba9bbef8c, 0x37a046dd83b86bc8, 0x1cd37ed6b4726747,
    0x0594efe763efbe32, 0x42a4b6a5fe64f810, 0x4ac1f18610f1bd5d, 0x4d3fc44408da6145,
    0x1318088ee5ed0e9d, 0x2259fb16a9696d18, 0x3f0fed94c3aa99d6, 0x5531ab2d957d02da,
    0x98900ba6e57fe8b6, 0x60d724fa0bb2096c, 0xd2f00c4abc7a5916, 0x0e972b8ebd759238,
];
const LOW_Q_INV: [u64; 16] = [
    0xa02ab48c5187f38b, 0x4b53433cf8a912ae, 0x7addbde0d72a9449, 0xd1e8eee1bf5ac5e3,
    0x3ab68f0bfb75a0bf, 0xf6161746d69891c4, 0xf2a991a9bd83bfb1, 0x9a54a4c2acb63ec0,
    0x7b8419b805f3b684, 0x693a3f6bb58b6b13, 0x8a4a4557ad6df369, 0xae7c232b2eaa53b0,
    0xe6bcc18d0b3b63b2, 0xf36ec7b8ce6adc33, 0x16dd5765e8cb0077, 0x742945219cd0054f,
];
const CLOSE_P: [u64; 16] = [
    0x8a97813bb61ea68b, 0xf30375327149366e, 0xfbb68d825612bf7b, 0xfad0e2248020fa92,
    0x32b0fc3ce8c8ebe5, 0xa05de23aac5639cb, 0x40203b30aad0b96a, 0x4de40677b1a9d14b,
    0x9b2c85e8c6a2cb79, 0x7af44989469a0312, 0xfa5b08c7cffeca8b, 0x4a2c40e5a3c8663d,
    0x67dd2736d38987f4, 0xb12ed4fb1375c4cb, 0x1fd4ec92f6c63295, 0xec121853419bd041,
];
const CLOSE_Q: [u64; 16] = [
    0x8a97813bb61eace5, 0xf30375327149366e, 0xfbb68d825612bf7b, 0xfad0e2248020fa92,
    0x32b0fc3ce8c8ebe5, 0xa05de23aac5639cb, 0x40203b30aad0b96a, 0x4de40677b1a9d14b,
    0x9b2c85e8c6a2cb79, 0x7af44989469a0312, 0xfa5b08c7cffeca8b, 0x4a2c40e5a3c8663d,
    0x67dd2736d38987f4, 0xb12ed4fb1375c4cb, 0x1fd4ec92f6c632a5, 0xec121853419bd041,
];
const CLOSE_D_P: [u64; 16] = [
    0x888a413e05914903, 0x7a69ea399158d16c, 0xf22bff064094ab6a, 0x84a89f9715608981,
    0xf214df95b5037d71, 0x3cc6c9b57f695ffc, 0x5eb25731a1134f36, 0x8305bf443fa7b0bc,
    0xc84b672ee4fee8e6, 0xbaeb2c67bfe4cca3, 0x0aa509bace09b0b5, 0x2d34a8555deadd85,
    0xe2a4a034c45363ae, 0x26ce30984755ad60, 0xc4d9d1cfef819137, 0xd07325f196344c8e,
];
const CLOSE_D_Q: [u64; 16] = [
    0xb51dc53887b98e31, 0x6c6b13cadc3295bc, 0x991b6887dd640c12, 0x722b555021da7ece,
    0xac0241a29a577722, 0x5ef94d814625633e, 0x2c1b59b2de85233f, 0x9898627ff1220f08,
    0xac9e76bbcf0390e1, 0xa0b41e8d70a6b3bf, 0x3f5efec06ae329b0, 0x1c4e515ce7ba7afe,
    0x881b742131559f0a, 0x6b09534157ddb29b, 0xf01d8484aab3ecef, 0x211ff8e1d5d6f345,
];
const CLOSE_Q_INV: [u64; 16] = [
    0x51e5420152d64096, 0xfd4868cdfcce4ff7, 0x9fc33558191eb2e2, 0xfcdd44f3dc04e47d,
    0x98e906d1c575856e, 0x0c0ebfdc2dd9482c, 0x91a11624a391c69a, 0xcb2a5d7bf256f875,
    0x509afda3c58e4312, 0x24bdd0c90f69b548, 0x8e1d1279ca6f506f, 0xa7ddc0a8bb85b43f,
    0x637c9052c0c000ae, 0xe0139f9b12298311, 0xfa32c902b1adde0c, 0x2c3429dad65bb79a,
];
const COMPOSITE_SMALL_P: [u64; 16] = [
    0x99700d4db1e29b31, 0x0a0bf0bfc97f85c5, 0xaf0a6802589f67bf, 0x66d8dc7c6caeb939,
    0xd0c79d317b7d0bcd, 0xa1f380c565ef7cde, 0xd75a82c6ab92eba0, 0x006a20f983502b39,
    0xe68901c2783e5178, 0x6f440c83c818b332, 0xd73459d7d9019396, 0xf92edae27de6dec3,
    0x7a3c2ca631572eba, 0xa670352b85cb5acc, 0x7a647423c0876909, 0xc748520bbc92082e,
];
const COMPOSITE_SMALL_D_P: [u64; 16] = [
    0x240b73f899b01131, 0x64ab6a36dc2a9805, 0x96516c7e159e3063, 0x8e9004ddbfd7c4a3,
    0x9a17e364804aca55, 0x9ebbb8305ca31199, 0x076f9ed9c621a7ee, 0xfc35a0e357eb0746,
    0x86c213fa8141ac46, 0x15e62e69182cc2b5, 0xc5bb37e0a3456746, 0xfa692808ca925bc2,
    0x78fadeb206d91465, 0x84dfc1dff77c04a1, 0xc9814e6f33726f85, 0x08a9c32f516e43be,
];
const COMPOSITE_SMALL_Q_INV: [u64; 16] = [
    0x88b4bd98d7369220, 0x58eaae378022d46b, 0xf7172070956c9c15, 0x71ac0bb4dc8ef543,
    0x64872fa1c14baa4c, 0x2dd1c8253eeca512, 0xfc087cb3ad0b7f9e, 0xb91b897d9f5a5657,
    0x191953f77a7e3e17, 0x0c1468a477398f66, 0x5bf8dc5bc4250857, 0x4013fc236caffaec,
    0xce7199f1799b53c5, 0x655fe9a53b558c5e, 0x5506352d12dc99bb, 0xb9128974bb640972,
];
const COMPOSITE_Q: [u64; 16] = [
    0x61fc4b8f90b13e67, 0xab62f01d9209f77b, 0x5910844011bcd161, 0x883778b6aa03c85a,
    0x3c0977eb6cda92ab, 0x08c03adf8dc16f56, 0x28325cc990ad7879, 0x3b1d6d202ca0dfbc,
    0x6c8a2785da2b283b, 0x489b3a348da37d2a, 0xb75ea63bbed850c0, 0xf308674f78527135,
    0x27da49422c00e463, 0x6e7cd5032530cd80, 0x8e8cfde9778bc9d1, 0xfb9553049924adfe,
];
const COMPOSITE_D_Q: [u64; 16] = [
    0x46a11c1255dcc2ff, 0xabff482b9fbaa640, 0xcd17cb15ecb1d7d8, 0x08c18909ddc4fe5e,
    0x1dd467f400aa4984, 0x8ccf0756febcda6a, 0xe9e90d4d7fc30f4d, 0xa8303172068bc87e,
    0x4d4b8409d72e92e5, 0xce23beb0e287b102, 0x3171621b61c52ff7, 0x862febb4ed802d40,
    0xd5ce90e6ccaa2fea, 0x14d1dffd3bdff360, 0xaf55339f8b7b3886, 0x23e3905d368f81f6,
];
const COMPOSITE_MR_P: [u64; 16] = [
    0x3d816d53f5c204f9, 0x87cc04ff4b97b7de, 0xaf0f58ede9d5efd7, 0xd383d0b65bf8e3b0,
    0xef1cae6d06c25187, 0xd9651fc1f13dbf80, 0x032f21a717d174da, 0x46cfe8b2154ada9f,
    0x3662f71a81ba1834, 0x13c6d175301d5c53, 0x94afaed7f0a4ce91, 0x956518b151abea51,
    0x919ac818db2112da, 0x6860620f30d8676d, 0xc3050169dcd1cef8, 0xe7ba00ec1db593d7,
];
const COMPOSITE_MR_D_P: [u64; 16] = [
    0xe193d881e75faf91, 0x060fb8ee2ee78958, 0xb8faa9f5edd955a7, 0x5232821d5bb77bea,
    0x9ecb7ee6bff091cd, 0xc5dcc0b89eeba22f, 0x2ae4208e5dcf29e8, 0x3332e4479283d796,
    0xe0cc1f61113bda7c, 0x39d84e8177b01115, 0x3b2d3ce0e25dcc24, 0x0f3bbe2b37eab4dd,
    0x3ff74f69c889f92b, 0x426c8b38db03f417, 0x510a6f3812320a97, 0x26bed514a5cb0c93,
];
const COMPOSITE_MR_Q_INV: [u64; 16] = [
    0xe4b315cbe51c3bc7, 0x108d1a43a2fb29cd, 0xb40013de40010024, 0x7f4720ae73149400,
    0x08539072730686b9, 0xc06af9560f730262, 0xc5c4587962ea9cfb, 0x0dc6b586f0a02dc2,
    0x16269017260359c1, 0x2cb0157e5ec1f433, 0x625653e254127f39, 0xa6a751f17ca1bbbd,
    0x4eb998e18cc9f0a3, 0xed769524aeabd3c7, 0x1f17540877b860e9, 0x45d93af77ad1f349,
];
const COMPOSITE_SECOND_D_Q: [u64; 16] = [
    0xe193d881e75faf91, 0x060fb8ee2ee78958, 0xb8faa9f5edd955a7, 0x5232821d5bb77bea,
    0x9ecb7ee6bff091cd, 0xc5dcc0b89eeba22f, 0x2ae4208e5dcf29e8, 0x3332e4479283d796,
    0xe0cc1f61113bda7c, 0x39d84e8177b01115, 0x3b2d3ce0e25dcc24, 0x0f3bbe2b37eab4dd,
    0x3ff74f69c889f92b, 0x426c8b38db03f417, 0x510a6f3812320a97, 0x26bed514a5cb0c93,
];
const COMPOSITE_SECOND_Q_INV: [u64; 16] = [
    0x6b6ee542e598d393, 0x82fd60ee47af0965, 0xc3f0cd147ac0183f, 0x3f371ddc53b83a3a,
    0x6a2be84b4033aa0d, 0xcf31b64d97500836, 0x24f576bbb41d6362, 0x80ba6364b1db641a,
    0xdb81c9885dccede3, 0xc547c357c5777fca, 0x83ba215c3a6fc766, 0x53a16c6abb7a2948,
    0xc755d8449d799b96, 0x1a871a3d1e24ad4e, 0x536a78e3d125d2ef, 0x529bc0bdc269d5ec,
];
const SHARED_P: [u64; 16] = [
    0x3a41dafa7af63da7, 0x070cb59dccae7585, 0x66dfa71a24527bd3, 0x83fd40b7168acd75,
    0x5cc9c98715a18470, 0xc6dd5479b640d157, 0xce4f20447a085018, 0x0f4d08062af17f1a,
    0xc321b5483d617f19, 0xc6742291057e1d3e, 0x4d34ea0bc1e65c89, 0xcf77247ebeec6e6b,
    0x6ac694686b7ccb61, 0xd495a4e4a2c5538d, 0xba34deac71b65a74, 0xbeb66586afa59a9a,
];
const SHARED_Q: [u64; 16] = [
    0xf857cea34e9da789, 0x5ebb9cd2663df206, 0x892a3422db18a519, 0xaffc56497363bc9c,
    0xd10d0cb41cd75b40, 0xb3d1c5f79dabc1c9, 0x6869805b4d606acb, 0xbf1160083941fece,
    0x042cf1b5a72ca976, 0xb345836c0752d1a9, 0x119be2ba57ddd0b7, 0xbf4985fe53e5e88f,
    0xe3b3708b39fbb9d7, 0x1b723130d9071a11, 0x4d9bd390979dcdf1, 0xfe48875e3f8778ce,
];
const SHARED_Q_INV: [u64; 16] = [
    0x3a41dafa7af63da4, 0x070cb59dccae7585, 0x66dfa71a24527bd3, 0x83fd40b7168acd75,
    0x5cc9c98715a18470, 0xc6dd5479b640d157, 0xce4f20447a085018, 0x0f4d08062af17f1a,
    0xc321b5483d617f19, 0xc6742291057e1d3e, 0x4d34ea0bc1e65c89, 0xcf77247ebeec6e6b,
    0x6ac694686b7ccb61, 0xd495a4e4a2c5538d, 0xba34deac71b65a74, 0xbeb66586afa59a9a,
];
const SHARED_E_SMALL_D: u64 = 65537;
const SHARED_E_SMALL_D_D_P: [u64; 16] = [
    0x8d67d1085a791951, 0xf1523ce2c9e284ca, 0xa27e4a7d54e9f630, 0x5b8c6783c6264647,
    0x1c45c4d86df31a6d, 0xde391dd891f680da, 0xc3245bb6629aab98, 0x64779920a6956121,
    0xc10f0f1b4d830ab3, 0x57c905982bd9848f, 0x477380bf72b79a16, 0xec07214a18a041bc,
    0xd0ebd384dac79cbe, 0xbed7420f3fc322ae, 0x80b19ae5d2cc46a9, 0x4d4428ae00cbdf6f,
];
const SHARED_E_SMALL_D_D_Q: [u64; 16] = [
    0x8d67d1085a791951, 0xf1523ce2c9e284ca, 0xa27e4a7d54e9f630, 0x5b8c6783c6264647,
    0x1c45c4d86df31a6d, 0xde391dd891f680da, 0xc3245bb6629aab98, 0x64779920a6956121,
    0xc10f0f1b4d830ab3, 0x57c905982bd9848f, 0x477380bf72b79a16, 0xec07214a18a041bc,
    0xd0ebd384dac79cbe, 0xbed7420f3fc322ae, 0x80b19ae5d2cc46a9, 0x4d4428ae00cbdf6f,
];
const SHARED_E_LARGE_D: u64 = 65539;
const SHARED_E_LARGE_D_D_P: [u64; 16] = [
    0x2ebe9fe53cd80b2d, 0xdb3d9390ac1f4d02, 0xe68485decfb6630b, 0x0e67049811480eb0,
    0xc4b33aadb7fc1c50, 0x187221e36fb51fa4, 0xf7f18d74bfb4289c, 0xc4d0c07310dccafb,
    0x0fdf28009d64fad1, 0x6b1269efa73a02a4, 0xbb19d7db8bedacdb, 0xb4d23872b5bfef13,
    0xc324aa88da34728a, 0x2ac20da95bf46ae6, 0x7da302931771a92b, 0xb3053dd4aacad3f6,
];
const SHARED_E_LARGE_D_D_Q: [u64; 16] = [
    0x70a8ac3c6930a14b, 0x838eac5c128fd080, 0xc439f8d618f039c5, 0xe267ef05b46f1f89,
    0x506ff780b0c6457f, 0x2b7db065884a2f32, 0x5dd72d5dec5c0de9, 0x150c6871028c4b48,
    0xced3eb933399d074, 0x7e410914a5654e39, 0xf6b2df2cf5f638ad, 0xc4ffd6f320c674ef,
    0x4a37ce660bb58414, 0xe3e5815d25b2a462, 0xea3c0daef18a35ae, 0x73731bfd1ae8f5c2,
];
const LOW_P_INV: [u64; 16] = [
    0x534eca1d89d7145b, 0xccb16100a7bc160a, 0xb3a42e82520df80a, 0x969de6623e4088eb,
    0xce40f28f68823bfb, 0xc44479ddd30ef501, 0xff2095bc1e0668d0, 0x49f0ebbe010bdade,
    0xc8f33199463bff38, 0x64bbb79d7a8b4f15, 0xe86d85cfcd9331b9, 0x14e31ae0c5c1b577,
    0x2fbf36cdeeb81ada, 0x1e9b8b95c35be4a7, 0x9a210fe72baabd0b, 0x50eb9c5e894e9400,
];

#[test]
fn from_crt_components_accepts_a_genuine_key_and_derives_n() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .expect("genuine RSA-2048 CRT components must be accepted");
    assert_eq!(*sk.n(), N);
}

#[test]
fn from_crt_components_rejects_equal_primes() {
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &P, &D_P, &D_Q, &Q_INV, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_even_prime() {
    let mut even_p = P;
    even_p[0] &= !1;
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &even_p, &Q, &D_P, &D_Q, &Q_INV, 0x10001
        ),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_even_q() {
    let mut even_q = Q;
    even_q[0] &= !1;
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &P, &even_q, &D_P, &D_Q, &Q_INV, 0x10001
        ),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_dp_out_of_range() {
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &P, &D_Q, &Q_INV, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_qinv_out_of_range() {
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &P, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn public_key_accepts_e_65537() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x00010001).expect("e = 65537 is valid");
    assert_eq!(*pk.n(), N);
    assert_eq!(pk.e(), 0x00010001);
}

#[test]
fn public_key_rejects_even_exponent() {
    for e in [0, 2, 4, 65536, 1 << 32, u64::MAX - 1] {
        assert!(matches!(
            RsaPublicComponents::<RSA2048>::new(&N, e),
            Err(SignatureError::DecodingError(_))
        ));
    }
}

#[test]
fn public_key_rejects_exponent_below_three() {
    assert!(matches!(
        RsaPublicComponents::<RSA2048>::new(&N, 1),
        Err(SignatureError::DecodingError(_))
    ));
    assert!(RsaPublicComponents::<RSA2048>::new(&N, 3).is_ok());
}

#[test]
fn public_key_rejects_even_modulus() {
    let mut even_n = N;
    even_n[0] &= !1;
    assert!(matches!(
        RsaPublicComponents::<RSA2048>::new(&even_n, 3),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn public_key_encode_round_trips() {
    // 65537, a 33-bit and a 56-bit exponent, and the largest there is.
    for e in [0x10001, 0x1_0000_0001, 0x00c0_ffee_1234_5677, u64::MAX] {
        let pk = RsaPublicComponents::<RSA2048>::new(&N, e).unwrap().into_key::<Pss256>();
        let bytes: [u8; 264] = pk.encode();
        assert_eq!(bytes[256..], e.to_be_bytes());
        let decoded = RsaPublicKey::<Pss256>::from_bytes(&bytes).expect("must decode");
        assert_eq!(decoded, pk);
        assert_eq!(decoded.e(), e);
    }
}

/// `PublicKey`'s `n || e` layout, checked field by field rather than only by round
/// trip: `n` big-endian (its most significant limb's top byte first), then `e` big-endian in
/// eight bytes.
#[test]
fn public_key_encode_layout_is_n_then_e_big_endian() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let bytes = pk.encode();
    assert_eq!(bytes[..8], N[31].to_be_bytes());
    assert_eq!(bytes[248..256], N[0].to_be_bytes());
    assert_eq!(bytes[256..], [0, 0, 0, 0, 0x00, 0x01, 0x00, 0x01]);

    let mut out = [0xaau8; 264];
    assert_eq!(pk.encode_out(&mut out), 264);
    assert_eq!(out, bytes);
}

#[test]
fn public_key_from_bytes_rejects_even_modulus() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let mut bytes: [u8; 264] = pk.encode();
    bytes[255] &= !1; // clear n's low bit (last byte, big-endian)
    assert!(matches!(RsaPublicKey::<Pss256>::from_bytes(&bytes), Err(KeyDecodingError(_))));
}

#[test]
fn public_key_from_bytes_rejects_wrong_lengths() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let bytes = pk.encode();
    assert!(matches!(RsaPublicKey::<Pss256>::from_bytes(&bytes[..263]), Err(KeyDecodingError(_))));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(RsaPublicKey::<Pss256>::from_bytes(&too_long), Err(KeyDecodingError(_))));
}

/// `Display` (a `PublicKey` supertrait) prints `n` as one big-endian hex string and `e`
/// in hex, so a printed key can be matched by eye against a hex dump of its encoding.
#[test]
fn public_key_display_prints_big_endian_hex() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let shown = format!("{pk}");
    let n_hex: String = pk.encode()[..256].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        shown,
        format!("RsaPublicKey<RSASSA-PSS-SHA256, RSA-2048> {{ n: {n_hex}, e: 10001 }}")
    );
}

#[test]
fn private_key_encode_round_trips() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let bytes: [u8; 648] = sk.encode();
    let decoded = RsaPrivateKey::<Pss256>::from_bytes(&bytes).expect("must decode");
    assert_eq!(decoded, sk);
    assert_eq!(decoded.e(), 0x10001);
    assert_eq!(decoded.components().e(), 0x10001);

    // The exponent is part of the key and of its encoding, at any width: the same primes
    // under another `e` are another key, which round trips as itself.
    for (e, d_p, d_q) in [
        (E_SMALL, &E_SMALL_D_P, &E_SMALL_D_Q),
        (E_WIDE, &E_WIDE_D_P, &E_WIDE_D_Q),
        (E_TOP, &E_TOP_D_P, &E_TOP_D_Q),
    ] {
        let other =
            RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, d_p, d_q, &Q_INV, e)
                .unwrap()
                .into_key::<Pss256>();
        assert_ne!(other, sk);
        let bytes = other.encode();
        assert_eq!(bytes[640..], e.to_be_bytes());
        let decoded = RsaPrivateKey::<Pss256>::from_bytes(&bytes).expect("must decode");
        assert_eq!(decoded, other);
        assert_eq!(decoded.e(), e);
    }
}

/// The private key's copy of `e` is held to the public key's rule, odd and at least 3 (RFC
/// 8017 Section 3.1), by the constructors and on decoding.
#[test]
fn private_key_rejects_an_even_or_small_exponent() {
    let good =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    for e in [0, 1, 2, 4, 65536, 1 << 32, u64::MAX - 1] {
        let expected =
            SignatureError::DecodingError("RSA public exponent must be odd and at least 3");
        assert_eq!(
            RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, e)
                .unwrap_err(),
            expected
        );
        assert!(matches!(
            RsaPrivateKey::<Pss256>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, e),
            Err(SignatureError::DecodingError(_))
        ));
        let mut bytes = good.encode();
        bytes[640..].copy_from_slice(&e.to_be_bytes());
        assert_eq!(
            RsaPrivateKey::<Pss256>::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError("RSA public exponent must be odd and at least 3")
        );
    }
}

/// `PrivateKey`'s `p || q || dP || dQ || qInv || e` layout: five fields of 128 bytes
/// big-endian, then `e` big-endian in eight.
#[test]
fn private_key_encode_layout_is_five_big_endian_fields_and_e() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let bytes = sk.encode();
    for (i, field) in [P, Q, D_P, D_Q, Q_INV].iter().enumerate() {
        let start = 128 * i;
        assert_eq!(bytes[start..start + 8], field[15].to_be_bytes(), "field {i} MSB");
        assert_eq!(bytes[start + 120..start + 128], field[0].to_be_bytes(), "field {i} LSB");
    }
    assert_eq!(bytes[640..], [0, 0, 0, 0, 0x00, 0x01, 0x00, 0x01]);

    let mut out = [0xaau8; 648];
    assert_eq!(sk.encode_out(&mut out), 648);
    assert_eq!(out, bytes);
}

#[test]
fn private_key_from_bytes_rejects_equal_primes() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let mut bytes: [u8; 648] = sk.encode();
    // Overwrite q (the second 128-byte field) with p, making the two primes equal.
    let p_field = bytes[..128].to_vec();
    bytes[128..256].copy_from_slice(&p_field);
    assert!(matches!(RsaPrivateKey::<Pss256>::from_bytes(&bytes), Err(KeyDecodingError(_))));
}

#[test]
fn private_key_from_bytes_rejects_wrong_lengths() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let bytes = sk.encode();
    assert!(matches!(RsaPrivateKey::<Pss256>::from_bytes(&bytes[..647]), Err(KeyDecodingError(_))));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(RsaPrivateKey::<Pss256>::from_bytes(&too_long), Err(KeyDecodingError(_))));
}

/// The CRT checks run through the size's own forwarders: at every signing size a `dP` not
/// below `p`, a `dQ` not below `q` and a `qInv` not below `p` are refused, and so are
/// components in range that are not the inverses they should be (no primality check, so odd
/// values with their top two bits set, whose product is then full length, stand in for the
/// primes).
fn crt_components_out_of_range_rejected<K: RsaSigningSize>() {
    let mut p = <K as RsaSize>::HalfLimbs::ZEROED;
    p.as_mut()[0] = 7;
    let mut q = <K as RsaSize>::HalfLimbs::ZEROED;
    q.as_mut()[0] = 11;
    let top = p.as_ref().len() - 1;
    p.as_mut()[top] |= 0b11 << 62;
    q.as_mut()[top] |= 0b11 << 62;
    let mut small = <K as RsaSize>::HalfLimbs::ZEROED;
    small.as_mut()[0] = 3;
    let refused = |d_p, d_q, q_inv, why| {
        assert_eq!(
            RsaPrivateComponents::<K>::from_crt_components(&p, &q, d_p, d_q, q_inv, 0x10001)
                .unwrap_err(),
            SignatureError::DecodingError(why)
        );
    };
    refused(&small, &small, &small, "dP is not the inverse of e modulo p - 1");
    refused(&p, &small, &small, "dP must be less than p");
    refused(&small, &q, &small, "dQ must be less than q");
    refused(&small, &small, &p, "qInv must be less than p");
}

#[test]
fn crt_components_out_of_range_rejected_at_every_signing_size() {
    crt_components_out_of_range_rejected::<RSA2048>();
    crt_components_out_of_range_rejected::<RSA3072>();
    crt_components_out_of_range_rejected::<RSA4096>();
    crt_components_out_of_range_rejected::<RSA8192>();
}

// Key material whose modulus is not full length, for the tests below. Both are genuine keys
// (checked with Python 3.12: `p` and `q` pass 40 rounds of Miller-Rabin, and `dP`, `dQ`, `qInv`
// are `pow(e, -1, p - 1)`, `pow(e, -1, q - 1)`, `pow(q, -1, p)` for e = 65537), so every check
// but the modulus's length passes.
//
// SHORT_2047: two 1024-bit primes whose product has 2047 bits. This file's own test key until
// the length was checked.
const SHORT_2047_P: [u64; 16] = [
    0xfec673c1b07d4997, 0x98c9e3737faecc8b, 0x01369d6bebcfd19b, 0x8aadc1799d493a6e,
    0x958ca74fe2a455a1, 0x686e62c9e375661d, 0xbf73814b7bf6fe14, 0x791ffe2d364719e4,
    0xc82e25af581825a1, 0x716d239de20732c7, 0xdb517e266b0c15bc, 0xe92c721464fa1e50,
    0x683e7fcc3898a002, 0xc7f69cb8c57e630f, 0xc467ab3a006acdf7, 0xe189725eddf8ccb3,
];
const SHORT_2047_Q: [u64; 16] = [
    0x7b4cf8c928cc535f, 0x59f055409b91aa89, 0xcd0ba689661c56d5, 0xe4659bfb595039f4,
    0x751842ab04e21054, 0xe2c2655760ebb5fc, 0xb2f71094e48dc76b, 0x2efed995e680919d,
    0x83c35ffcfdb9ee9d, 0xfe4a5fdb9f28a01b, 0x0ebf4a61e23c7524, 0x8cc355a69e45d7e6,
    0x9589828fca436940, 0x4cd1bfe875cddd70, 0x203e0d5e8d4d3acb, 0x86278c27281306ec,
];
const SHORT_2047_D_P: [u64; 16] = [
    0xa7c48ae44e99dd99, 0xa6794425077c6c01, 0x0f7f8dfabf278380, 0xb481c3d6cf359f60,
    0xa5b5efbc5d9f744a, 0x91b95de874b741a1, 0xea3152a3da97ddf5, 0xe180bda330e9eba0,
    0xbcbfcc51e73a7a34, 0x019d0405e258c3c0, 0x0b08c52c187e3667, 0x84a723999981f7c1,
    0x5e50dc3287b126ff, 0xd0204fd4674f4ac6, 0x6e786ef11d0686f6, 0xa82c39200c1c4d67,
];
const SHORT_2047_D_Q: [u64; 16] = [
    0x0bc1fcecb5c853bf, 0x2000c1caf24e96d2, 0xb423419c07e0736a, 0x90bcb6fb03d68029,
    0xd811d2e24994ff2e, 0x5a89a6b7c7c83737, 0xbdea803dc4157f87, 0xffe93a09240b9b65,
    0xe6f584c8dc80c30a, 0x5e66076e22c91c3c, 0xb41221e6b67af91b, 0x2e3d8c36b1d9d161,
    0x7b1309bb3857cb1f, 0xee8de5186c920235, 0x5e4785a534bec7a3, 0x85883dd007ea907c,
];
const SHORT_2047_Q_INV: [u64; 16] = [
    0xf1be36246c217ae1, 0x079e038ceb7506d7, 0x2021f982bc5f6713, 0x55fa8fdd926a4d0f,
    0xb927b5edab1a24b8, 0xc2a1d37632cfb70e, 0x9ef39b4a3f144e8a, 0x70efa5974ed43d2f,
    0x6ea50741414ce321, 0x7df35889e34d4f38, 0x859106459f51850b, 0xd59e422a92f4a7a2,
    0x0c1e16e70fcbe362, 0xcf95cadb6a1f450d, 0x106a4e948e405012, 0x95a3415bfb9b5ff6,
];
const SHORT_2047_N: [u64; 32] = [
    0xbc9607fe59ae4409, 0x33fb0be666401931, 0x29fe66e068d6028b, 0xf4225b99e1483032,
    0x3e05752e447f3448, 0x3621f382f494e49c, 0xb12e1f7bd18e9f62, 0xba911df383b4764d,
    0x206002df096d6863, 0x07e881cdab73cfe3, 0x4e9ca660d04d6b6c, 0xfdd0169786ca06a2,
    0xffc09630c54f5731, 0x79ff3ac5ce73cc72, 0x72dd018024dd28a7, 0x4155291016140929,
    0x21a0943f3500f009, 0xd386df1b9afb0808, 0xd06dca00e14b1311, 0x31ed2137effa6d2a,
    0xb914de4e6361f98f, 0x181ad8797a7574fb, 0x98285be3abda6248, 0xcce5cb7a03c57a7d,
    0x3bdb7daa02c2b084, 0x8bb59db9b76bd95d, 0x95e3a77cea5ff912, 0x841d24a921abd3db,
    0x2895f5b063db401c, 0xe57dc21fc3866988, 0xb88f89afa429e300, 0x7630c947be6e9710,
];
// SHORT_1024: two 512-bit primes, a 1024-bit modulus held in RSA-2048's widths. Generated for
// this file with Python (`random.Random(20261122)`, candidates with their top two bits set).
const SHORT_1024_P: [u64; 16] = [
    0x6ef620d8244eb173, 0xc405f88ed21e8bab, 0x4078517af66e0441, 0x036fcb2eab272e2e,
    0x57f09c6542c341ad, 0x8655e0db4ac425db, 0xdc698685e27377e4, 0xcb9dc67a2e18f929,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_Q: [u64; 16] = [
    0xbcf68cf7e0d108c3, 0xb482cc7300abbbe5, 0xd118d4ab1ffa26fe, 0xeb6cc5ba79b7eeca,
    0xc65068d06f2c1194, 0x4b36e61a4ba7bc16, 0x050695b809674898, 0xd89d96cb1d2958b9,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_D_P: [u64; 16] = [
    0x507439de1e33939f, 0x0cd5993cb34799c4, 0xcf4386325df05157, 0xef856dc0b69eeb9a,
    0x39358ce56ac1db00, 0x4ac1f2816ff6d7ee, 0x0bec72dd511fa67a, 0xb45edc7e492d9833,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_D_Q: [u64; 16] = [
    0x04dbb2eefd45ce41, 0xcaa851093ed448e4, 0x476aff0896b72309, 0xcd8f1478d9bfb8ac,
    0x14ad71efe9532d06, 0x72b90e38ea541108, 0x09ff6630bfaedf41, 0x9e559283a52d33cd,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_Q_INV: [u64; 16] = [
    0x5d11de90a81493d9, 0x8a5a13bcd31c8f63, 0xb9713767ed1bec03, 0xfc6236e7ee0221a8,
    0xb718e73a2653ec00, 0x14428a8dc324d06f, 0x7b8178b611797b9e, 0x4c68e71595d411cf,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_N: [u64; 32] = [
    0x30365f3e9c5fc299, 0xea89d3517b5001ef, 0x0e1662fd6aff00e2, 0xfaa88695226220ad,
    0x61261165da096479, 0xff857d4c85008a3a, 0xed8cee4bc3cd0936, 0x93dcc09276ea8c4b,
    0xd846665bc425d759, 0x2187cf1d8b30d252, 0xe4c0359865f1981c, 0xcdf3a6d470131436,
    0xc583be54081dfae1, 0xd2439a393fe4795b, 0x56794795de362947, 0xac4a7729cf6d13c3,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];

/// A modulus with one limb set.
fn small_modulus(value: u64) -> [u64; 32] {
    let mut n = [0u64; 32];
    n[0] = value;
    n
}

const TOP_BIT_CLEAR: &str = "RSA modulus must have its top bit set";

/// A signature public key's modulus has exactly the size's bit length: RFC 8017 Section 8.1.1
/// step 1 encodes to `modBits - 1` bits, which EMSA-PSS here takes as `8 * K_LEN - 1`. `n = 1`,
/// `n = 105`, a 1024-bit modulus and a genuine 2047-bit one are each refused, by the
/// components, by the typed key and on decoding.
#[test]
fn public_key_rejects_a_modulus_that_is_not_full_length() {
    for n in [small_modulus(1), small_modulus(105), SHORT_1024_N, SHORT_2047_N] {
        assert_eq!(
            RsaPublicComponents::<RSA2048>::new(&n, 0x10001),
            Err(SignatureError::DecodingError(TOP_BIT_CLEAR))
        );
        assert!(matches!(
            RsaPublicKey::<Pss256>::new(&n, 0x10001),
            Err(SignatureError::DecodingError(TOP_BIT_CLEAR))
        ));
        // The encoding of what would be that key: n big-endian, then e.
        let mut bytes =
            RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().key::<Pss256>().encode();
        for (i, limb) in n.iter().enumerate() {
            bytes[256 - 8 * (i + 1)..256 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        assert_eq!(
            RsaPublicKey::<Pss256>::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError(TOP_BIT_CLEAR)
        );
    }
    // The 2047-bit modulus is the largest that is refused: with its top bit set it is taken.
    let mut full = SHORT_2047_N;
    full[31] |= 1 << 63;
    assert!(RsaPublicComponents::<RSA2048>::new(&full, 0x10001).is_ok());
}

/// The private key's check is on `p * q`. The genuine keys pass every other check, so the
/// error names this one; `n = 105` is `15 * 7` and `n = 1` is `1 * 1`, which the distinct-primes
/// check refuses first.
#[test]
fn private_key_rejects_a_modulus_that_is_not_full_length() {
    for (p, q, d_p, d_q, q_inv) in [
        (SHORT_2047_P, SHORT_2047_Q, SHORT_2047_D_P, SHORT_2047_D_Q, SHORT_2047_Q_INV),
        (SHORT_1024_P, SHORT_1024_Q, SHORT_1024_D_P, SHORT_1024_D_Q, SHORT_1024_Q_INV),
    ] {
        assert_eq!(
            RsaPrivateComponents::<RSA2048>::from_crt_components(
                &p, &q, &d_p, &d_q, &q_inv, 0x10001
            )
            .unwrap_err(),
            SignatureError::DecodingError(TOP_BIT_CLEAR)
        );
        assert!(matches!(
            RsaPrivateKey::<Pss256>::from_crt_components(&p, &q, &d_p, &d_q, &q_inv, 0x10001),
            Err(SignatureError::DecodingError(TOP_BIT_CLEAR))
        ));
        // The encoding of what would be that key: five big-endian fields, then e.
        let mut bytes = [0u8; 648];
        for (f, field) in [p, q, d_p, d_q, q_inv].iter().enumerate() {
            for (i, limb) in field.iter().enumerate() {
                let end = 128 * (f + 1) - 8 * i;
                bytes[end - 8..end].copy_from_slice(&limb.to_be_bytes());
            }
        }
        bytes[640..].copy_from_slice(&0x10001u64.to_be_bytes());
        assert_eq!(
            RsaPrivateKey::<Pss256>::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError(TOP_BIT_CLEAR)
        );
    }

    let limb = |value: u64| {
        let mut x = [0u64; 16];
        x[0] = value;
        x
    };
    // 15 * 7 = 105, with dP = dQ = qInv = 1 in range.
    assert_eq!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &limb(15),
            &limb(7),
            &limb(1),
            &limb(1),
            &limb(1),
            0x10001
        )
        .unwrap_err(),
        SignatureError::DecodingError(TOP_BIT_CLEAR)
    );
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &limb(1),
            &limb(1),
            &limb(0),
            &limb(0),
            &limb(0),
            0x10001
        ),
        Err(SignatureError::DecodingError(_))
    ));
}

/// A typed key exposes its exponent, names its algorithm in `Debug`, and compares by its
/// material.
#[test]
fn typed_keys_expose_e_debug_names_the_algorithm_and_eq_compares_material() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    assert_eq!(pk.e(), 0x10001);
    let shown = format!("{pk:?}");
    assert!(shown.starts_with("RsaPublicKey { algorithm: \"RSASSA-PSS-SHA256\", components: "));
    let pk_other_e = RsaPublicComponents::<RSA2048>::new(&N, 0x10003).unwrap().into_key::<Pss256>();
    assert_eq!(pk, pk.clone());
    assert_ne!(pk, pk_other_e);

    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let shown = format!("{sk:?}");
    assert!(shown.starts_with("RsaPrivateKey { algorithm: \"RSASSA-PSS-SHA256\", components: "));
    let sk_other = RsaPrivateComponents::<RSA2048>::from_crt_components(
        &P, &Q, &E_WIDE_D_P, &E_WIDE_D_Q, &Q_INV, E_WIDE,
    )
    .unwrap()
    .into_key::<Pss256>();
    assert_eq!(sk, sk.clone());
    assert_ne!(sk, sk_other);
}

/// RFC 8017 Section 3.2: `e * dP == 1 (mod (p - 1))`, `e * dQ == 1 (mod (q - 1))` and
/// `q * qInv == 1 (mod p)`. Components in range that fail one are refused, with the one named,
/// by the constructors and on decoding.
#[test]
fn private_key_rejects_components_that_do_not_belong_together() {
    const D_P_WRONG: &str = "dP is not the inverse of e modulo p - 1";
    const D_Q_WRONG: &str = "dQ is not the inverse of e modulo q - 1";
    const Q_INV_WRONG: &str = "qInv is not the inverse of q modulo p";
    let flipped = |x: &[u64; 16], limb: usize, bit: u32| {
        let mut x = *x;
        x[limb] ^= 1 << bit;
        x
    };
    let mut one = [0u64; 16];
    one[0] = 1;
    let mut p_minus_1 = P;
    p_minus_1[0] -= 1;
    let mut q_minus_1 = Q;
    q_minus_1[0] -= 1;

    let cases: [(&str, [u64; 16], [u64; 16], [u64; 16], u64, &str); 15] = [
        ("dP, a low bit", flipped(&D_P, 0, 1), D_Q, Q_INV, 0x10001, D_P_WRONG),
        ("dP, a high bit", flipped(&D_P, 15, 3), D_Q, Q_INV, 0x10001, D_P_WRONG),
        ("dP of 1", one, D_Q, Q_INV, 0x10001, D_P_WRONG),
        ("dP of p - 1", p_minus_1, D_Q, Q_INV, 0x10001, D_P_WRONG),
        ("dP off above its lowest word", D_P_HIGH, D_Q, Q_INV, 0x10001, D_P_WRONG),
        ("dP of another exponent", E_WIDE_D_P, D_Q, Q_INV, 0x10001, D_P_WRONG),
        ("dQ, a low bit", D_P, flipped(&D_Q, 0, 1), Q_INV, 0x10001, D_Q_WRONG),
        ("dQ, a high bit", D_P, flipped(&D_Q, 7, 40), Q_INV, 0x10001, D_Q_WRONG),
        ("dQ of 1", D_P, one, Q_INV, 0x10001, D_Q_WRONG),
        ("dQ of q - 1", D_P, q_minus_1, Q_INV, 0x10001, D_Q_WRONG),
        ("dQ of another exponent", D_P, E_WIDE_D_Q, Q_INV, 0x10001, D_Q_WRONG),
        ("qInv, a low bit", D_P, D_Q, flipped(&Q_INV, 0, 0), 0x10001, Q_INV_WRONG),
        ("qInv, a high bit", D_P, D_Q, flipped(&Q_INV, 15, 3), 0x10001, Q_INV_WRONG),
        ("qInv of 1", D_P, D_Q, one, 0x10001, Q_INV_WRONG),
        ("qInv off above its lowest word", D_P, D_Q, Q_INV_HIGH, 0x10001, Q_INV_WRONG),
    ];
    for (what, d_p, d_q, q_inv, e, why) in cases {
        assert_eq!(
            RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &d_p, &d_q, &q_inv, e)
                .unwrap_err(),
            SignatureError::DecodingError(why),
            "{what}"
        );
        assert_eq!(
            RsaPrivateKey::<Pss256>::from_crt_components(&P, &Q, &d_p, &d_q, &q_inv, e)
                .unwrap_err(),
            SignatureError::DecodingError(why),
            "{what}"
        );
    }
    // An exponent that is not the key's: neither dP nor dQ is its inverse, and dP is looked
    // at first. With the primes exchanged and nothing else, all three are wrong.
    let build = RsaPrivateComponents::<RSA2048>::from_crt_components;
    assert_eq!(
        build(&P, &Q, &D_P, &D_Q, &Q_INV, 65539).unwrap_err(),
        SignatureError::DecodingError(D_P_WRONG)
    );
    assert_eq!(
        build(&P, &Q, &D_P, &E_WIDE_D_Q, &Q_INV, E_WIDE).unwrap_err(),
        SignatureError::DecodingError(D_P_WRONG)
    );
    assert_eq!(
        build(&P, &Q, &E_WIDE_D_P, &D_Q, &Q_INV, E_WIDE).unwrap_err(),
        SignatureError::DecodingError(D_Q_WRONG)
    );

    // On decoding: one bit of the encoded dP, of the encoded qInv, and of the exponent.
    let good = build(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001).unwrap().into_key::<Pss256>();
    let bytes: [u8; 648] = good.encode();
    for (at, why) in [(383, D_P_WRONG), (511, D_Q_WRONG), (639, Q_INV_WRONG), (647, D_P_WRONG)] {
        let mut damaged = bytes;
        damaged[at] ^= 2;
        assert_eq!(
            RsaPrivateKey::<Pss256>::from_bytes(&damaged).unwrap_err(),
            KeyDecodingError(why),
            "byte {at}"
        );
    }
}

/// SP 800-56B Rev. 2 Section 6.2.1: a key-establishment key needs `e >= 65537`. Genuine keys
/// under a smaller exponent, which the signature key type takes, are refused for that and
/// nothing else, by the constructor and on decoding; one under a larger exponent is taken.
#[test]
fn a_key_establishment_key_refuses_a_genuine_key_with_a_small_exponent() {
    const TOO_SMALL: &str = "RSA key-establishment public exponent must be at least 65537";
    for (e, d_p, d_q) in
        [(E_SMALL, &E_SMALL_D_P, &E_SMALL_D_Q), (E_BELOW, &E_BELOW_D_P, &E_BELOW_D_Q)]
    {
        let as_signature_key =
            RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, d_p, d_q, &Q_INV, e)
                .unwrap()
                .into_key::<Pss256>();
        assert_eq!(
            RSA2048KEMPrivateKey::from_crt_components(&P, &Q, d_p, d_q, &Q_INV, e).unwrap_err(),
            KEMError::DecodingError(TOO_SMALL),
            "e = {e}"
        );
        let bytes: [u8; 648] = as_signature_key.encode();
        assert_eq!(
            RSA2048KEMPrivateKey::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError(TOO_SMALL),
            "e = {e}"
        );
    }
    let wide =
        RSA2048KEMPrivateKey::from_crt_components(&P, &Q, &E_WIDE_D_P, &E_WIDE_D_Q, &Q_INV, E_WIDE)
            .unwrap();
    assert_eq!(wide.e(), E_WIDE);
    let bytes: [u8; 648] = wide.encode();
    assert_eq!(RSA2048KEMPrivateKey::from_bytes(&bytes).unwrap().e(), E_WIDE);
    // The key-establishment key validates as its components do.
    assert_eq!(wide.validate(&mut DefaultRNG::default()), Ok(()));
    let composite = RSA2048KEMPrivateKey::from_crt_components(
        &COMPOSITE_MR_P, &COMPOSITE_Q, &COMPOSITE_MR_D_P, &COMPOSITE_D_Q, &COMPOSITE_MR_Q_INV,
        0x10001,
    )
    .unwrap();
    assert_eq!(
        composite.validate(&mut DefaultRNG::default()),
        Err(KEMError::DecodingError("a prime factor is composite"))
    );
}

/// The components of a key pair the constructor takes.
fn components(
    p: &[u64; 16],
    q: &[u64; 16],
    d_p: &[u64; 16],
    d_q: &[u64; 16],
    q_inv: &[u64; 16],
    e: u64,
) -> RsaPrivateComponents<RSA2048> {
    RsaPrivateComponents::<RSA2048>::from_crt_components(p, q, d_p, d_q, q_inv, e)
        .expect("every check of the constructor passes")
}

/// SP 800-56B Rev. 2 Section 6.4.1.4.3 on sound key pairs: at e = 65537, under the widest
/// exponent, and with a private exponent just above 2^(nBits/2).
#[test]
fn validate_accepts_a_sound_key_pair() {
    let mut rng = DefaultRNG::default();
    assert_eq!(components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001).validate(&mut rng), Ok(()));
    assert_eq!(
        components(&P, &Q, &E_TOP_D_P, &E_TOP_D_Q, &Q_INV, E_TOP).validate(&mut rng),
        Ok(())
    );
    let just_above = components(
        &SHARED_P, &SHARED_Q, &SHARED_E_LARGE_D_D_P, &SHARED_E_LARGE_D_D_Q, &SHARED_Q_INV,
        SHARED_E_LARGE_D,
    );
    assert_eq!(just_above.validate(&mut rng), Ok(()));
}

/// Each criterion of Section 6.4.1.4.3 that the constructor does not check, on a key pair that
/// fails it and no other.
#[test]
fn validate_refuses_a_key_pair_that_fails_a_criterion() {
    let mut rng = DefaultRNG::default();
    let mut refused = |sk: RsaPrivateComponents<RSA2048>, why: &'static str| {
        assert_eq!(sk.validate(&mut rng), Err(SignatureError::DecodingError(why)), "{why}");
    };
    // Step 1.c.
    let below = "the public exponent is below 65537";
    refused(components(&P, &Q, &E_SMALL_D_P, &E_SMALL_D_Q, &Q_INV, E_SMALL), below);
    refused(components(&P, &Q, &E_BELOW_D_P, &E_BELOW_D_Q, &Q_INV, E_BELOW), below);
    // Step 5.a and, with the primes exchanged, 5.b.
    let low = "a prime factor is below sqrt(2) * 2^(nBits/2 - 1)";
    refused(components(&LOW_P, &LOW_Q, &LOW_D_P, &LOW_D_Q, &LOW_Q_INV, 0x10001), low);
    refused(components(&LOW_Q, &LOW_P, &LOW_D_Q, &LOW_D_P, &LOW_P_INV, 0x10001), low);
    // Step 5.c.
    refused(
        components(&CLOSE_P, &CLOSE_Q, &CLOSE_D_P, &CLOSE_D_Q, &CLOSE_Q_INV, 0x10001),
        "the prime factors are too close together",
    );
    // Step 5.f, by trial division and by Miller-Rabin, and 5.g.
    let composite = "a prime factor is composite";
    refused(
        components(
            &COMPOSITE_SMALL_P, &COMPOSITE_Q, &COMPOSITE_SMALL_D_P, &COMPOSITE_D_Q,
            &COMPOSITE_SMALL_Q_INV, 0x10001,
        ),
        composite,
    );
    refused(
        components(
            &COMPOSITE_MR_P, &COMPOSITE_Q, &COMPOSITE_MR_D_P, &COMPOSITE_D_Q, &COMPOSITE_MR_Q_INV,
            0x10001,
        ),
        composite,
    );
    refused(
        components(
            &P, &COMPOSITE_MR_P, &D_P, &COMPOSITE_SECOND_D_Q, &COMPOSITE_SECOND_Q_INV, 0x10001,
        ),
        composite,
    );
    // Step 6.a.
    refused(
        components(
            &SHARED_P, &SHARED_Q, &SHARED_E_SMALL_D_D_P, &SHARED_E_SMALL_D_D_Q, &SHARED_Q_INV,
            SHARED_E_SMALL_D,
        ),
        "the private exponent is not above 2^(nBits/2)",
    );
}
