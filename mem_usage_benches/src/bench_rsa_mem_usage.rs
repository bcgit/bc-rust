//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_rsa_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_rsa_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Only one representative (scheme, hash) is benched per modulus size (PKCS#1 v1.5/SHA-256): peak
//! stack usage here is dominated by the const-generic-width RSASP1/RSAVP1 modular exponentiation
//! (`L`, this modulus size's own limb count), not by which hash fed into it -- the
//! `crypto/rsa/benches/rsa_*_benches.rs` criterion benches are where per-hash/per-scheme
//! *time* differences are measured instead.
//!
//! Main is at the bottom, controls which this was actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::rsa::{rsa_1024, rsa_1536, rsa_2048, rsa_3072, rsa_4096, rsa_8192};

const MSG: &[u8] = b"peak stack usage of RSA sign/verify, held constant across every modulus size";

/// This prints the on-disk encoded length of each modulus size's private/public keys and
/// signatures (`bouncycastle_rsa` has no in-memory key struct exposed here to `size_of` across
/// modules the way ECDSA's mem usage bench does, since each RSA key type is a distinct
/// `RsaPrivateKey<L, HALF>`/`RsaPublicKey<L>` monomorphization -- the byte lengths below are what
/// actually varies with modulus size).
fn print_key_sizes() {
    println!("\nRSA-1024 (verification only)");
    println!("public key on disk (n || e): {} bytes", 8 * 16 + 4);
    println!("signature: {} bytes", 8 * 16);

    println!("\nRSA-1536 (verification only)");
    println!("public key on disk (n || e): {} bytes", 8 * 24 + 4);
    println!("signature: {} bytes", 8 * 24);

    println!("\nRSA-2048");
    println!("private key on disk (p||q||dP||dQ||qInv): {} bytes", 5 * 8 * 16);
    println!("public key on disk (n || e): {} bytes", 8 * 32 + 4);
    println!("signature: {} bytes", 8 * 32);

    println!("\nRSA-3072");
    println!("private key on disk (p||q||dP||dQ||qInv): {} bytes", 5 * 8 * 24);
    println!("public key on disk (n || e): {} bytes", 8 * 48 + 4);
    println!("signature: {} bytes", 8 * 48);

    println!("\nRSA-4096");
    println!("private key on disk (p||q||dP||dQ||qInv): {} bytes", 5 * 8 * 32);
    println!("public key on disk (n || e): {} bytes", 8 * 64 + 4);
    println!("signature: {} bytes", 8 * 64);

    println!("\nRSA-8192");
    println!("private key on disk (p||q||dP||dQ||qInv): {} bytes", 5 * 8 * 64);
    println!("public key on disk (n || e): {} bytes", 8 * 128 + 4);
    println!("signature: {} bytes", 8 * 128);
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_1024_verify() {
    eprintln!("RSA-1024/Verify");

    let n: [u64; 16] = [
        0xd00343468eaacfbf, 0xb7c7044cc202dcca, 0x9686f30f478db649, 0x5179b54951fff6aa,
        0xbabb14f550d5d0dd, 0x5405db7c5c8f4cf6, 0x9816e2eda41fd7b9, 0xb31b6abd805bace9,
        0xb909dd0f4c6014f2, 0x9c8a5810b6d05990, 0x40760d1f23fe9250, 0x90adb011a919575a,
        0x45e48572113cab28, 0xcb9ca9ec12000fc8, 0x91b4fcaf62a14595, 0xac9048a7a4f560af,
    ];
    let pk = rsa_1024::Rsa1024PublicKey::new(&n, 0x10001).unwrap();
    let mut sig = [0u8; 128];
    sig.copy_from_slice(
        &bouncycastle::hex::decode(
            "41339884a9b3940e8488d666bb158063c6a2a2717cae7f564834a876fcbf7098ecf3acbfabf37d38a8e6127b1e313744f1f896e165efdaea0b2e7673867842b9e94db0868ed9a92bcdcb370a4e20ff275c82595e4400a8b9e9f12482f014846b48216f321266ae6ae6338dbcdc41b711e483e6e3e728772e7f9f5ef95c30196b",
        )
        .unwrap(),
    );
    let msg = bouncycastle::hex::decode("0000000000000000000000000000000000000000").unwrap();

    if rsa_1024::pkcs1_v1_5_verify_sha256(&pk, &msg, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn genuine_2048_key() -> rsa_2048::Rsa2048PrivateKey {
    let p: [u64; 16] = [
        0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
        0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
        0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
        0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
    ];
    let q: [u64; 16] = [
        0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
        0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
        0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
        0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
    ];
    let d_p: [u64; 16] = [
        0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
        0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
        0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
        0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
    ];
    let d_q: [u64; 16] = [
        0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
        0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
        0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
        0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
    ];
    let q_inv: [u64; 16] = [
        0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
        0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
        0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
        0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
    ];
    rsa_2048::Rsa2048PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv).unwrap()
}

fn bench_2048_sign() {
    eprintln!("RSA-2048/Sign");
    let sk = genuine_2048_key();
    let sig = rsa_2048::pkcs1_v1_5_sign_sha256(&sk, MSG).unwrap();
    println!("{:x?}", sig);
}

fn bench_2048_verify() {
    eprintln!("RSA-2048/Verify");
    let sk = genuine_2048_key();
    let pk = rsa_2048::Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig = rsa_2048::pkcs1_v1_5_sign_sha256(&sk, MSG).unwrap();

    if rsa_2048::pkcs1_v1_5_verify_sha256(&pk, MSG, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn genuine_8192_key() -> rsa_8192::Rsa8192PrivateKey {
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
    rsa_8192::Rsa8192PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv).unwrap()
}

fn bench_8192_sign() {
    eprintln!("RSA-8192/Sign");
    let sk = genuine_8192_key();
    let sig = rsa_8192::pkcs1_v1_5_sign_sha256(&sk, MSG).unwrap();
    println!("{:x?}", sig);
}

fn bench_8192_verify() {
    eprintln!("RSA-8192/Verify");
    let sk = genuine_8192_key();
    let pk = rsa_8192::Rsa8192PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig = rsa_8192::pkcs1_v1_5_sign_sha256(&sk, MSG).unwrap();

    if rsa_8192::pkcs1_v1_5_verify_sha256(&pk, MSG, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn main() {
    print_key_sizes()
    // bench_do_nothing()
    // bench_1024_verify()
    // bench_2048_sign()
    // bench_2048_verify()
    // bench_8192_sign()
    // bench_8192_verify()
}
