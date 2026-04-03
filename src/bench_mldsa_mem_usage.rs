//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_mldsa_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_mldsa_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//!
//! Make sure you build in release mode!
//!
//! Note: I'm using print!() to force the compiler not to optimize away the actual code.
//! I'm printing the important stuff for benchmarking to stderr so that I can pipe the junk to /dev/null
//! (I'm not doing it the other way because /usr/bin/time prints its useful stuff to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core_interface::traits::{Signature, SignaturePublicKey};
use bouncycastle_hex as hex;
use bouncycastle_mldsa::MLDSA44PublicKey;

/// This exists so I can use /usr/bin/time to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_mldsa44_keygen() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA44};

    eprintln!("MLDSA44/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let (pk, _sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_mldsa44_lowmem_keygen() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA44};

    eprintln!("MLDSA44_lowmemory/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let (pk, _sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_mldsa65_keygen() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA65};

    eprintln!("MLDSA65/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let (pk, _sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_mldsa65_lowmemory_keygen() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA65};

    eprintln!("MLDSA65_lowmemory/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let (pk, _sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_mldsa87_keygen() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA87};

    eprintln!("MLDSA87/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let (pk, _sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_mldsa87_lowmemory_keygen() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA87};

    eprintln!("MLDSA87_lowmemory/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let (pk, _sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_mldsa44_sign() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA44};

    eprintln!("MLDSA44/Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    /*** ML-DSA-44 ***/
    // since the goal here is to measure peak memory usage; we're here making an assumption that
    // mem usage of .sign will be higher than .keygen
    let (_mldsa44_pk, mldsa44_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

    let mu = MLDSA44::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
    let sig = MLDSA44::sign_mu_deterministic(&mldsa44_sk, &mu, [0u8; 32]).unwrap();
    print!("{:x?}", sig);
}

fn bench_mldsa44_lowmemory_sign() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA44};

    eprintln!("MLDSA44_lowmemory/Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    /*** ML-DSA-44 ***/
    let (_mldsa44_pk, mldsa44_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

    let mu = MLDSA44::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
    let sig = MLDSA44::sign_mu_deterministic(&mldsa44_sk, &mu, [0u8; 32]).unwrap();
    print!("{:x?}", sig);
}

fn bench_mldsa65_sign() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA65};

    eprintln!("MLDSA65/Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    let (_pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();

    let mu = MLDSA65::compute_mu_from_sk(&sk, msg, None).unwrap();
    let sig = MLDSA65::sign_mu_deterministic(&sk, &mu, [0u8; 32]).unwrap();
    print!("{:x?}", sig);
}

fn bench_mldsa65_lowmemory_sign() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA65};

    eprintln!("MLDSA65_lowmemory/Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    /*** ML-DSA-44 ***/
    let (_mldsa44_pk, mldsa44_sk) = MLDSA65::keygen_from_seed(&seed).unwrap();

    let mu = MLDSA65::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
    let sig = MLDSA65::sign_mu_deterministic(&mldsa44_sk, &mu, [0u8; 32]).unwrap();
    print!("{:x?}", sig);
}

fn bench_mldsa87_sign() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA87};

    eprintln!("MLDSA87/Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    let (_pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();

    let mu = MLDSA87::compute_mu_from_sk(&sk, msg, None).unwrap();
    let sig = MLDSA87::sign_mu_deterministic(&sk, &mu, [0u8; 32]).unwrap();
    print!("{:x?}", sig);
}

fn bench_mldsa87_lowmemory_sign() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA87};

    eprintln!("MLDSA87_lowmemory/Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    /*** ML-DSA-44 ***/
    let (_mldsa44_pk, mldsa44_sk) = MLDSA87::keygen_from_seed(&seed).unwrap();

    let mu = MLDSA87::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
    let sig = MLDSA87::sign_mu_deterministic(&mldsa44_sk, &mu, [0u8; 32]).unwrap();
    print!("{:x?}", sig);
}

fn bench_mldsa44_verify() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA44, MLDSA44_SIG_LEN, MLDSA44PublicKey};
    use bouncycastle_hex as hex;

    eprintln!("MLDSA44/Verify");

    let msg = b"The quick brown fox jumped over the lazy dog";

    /* One-time setup of the KAT -- commented out so that we're not capturing keygen in the bench */
    // let seed = KeyMaterial256::from_bytes_as_type(
    //     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
    //     KeyType::Seed,
    // ).unwrap();
    //
    // let (mldsa44_pk, _mldsa44_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

    // eprintln!("pk:\n{}", &*hex::encode(&mldsa44_pk.encode()));
    // let mu = MLDSA44::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
    // let sig = MLDSA44::sign_mu_deterministic(&mldsa44_sk, &mu, [0u8; 32]).unwrap();
    // eprintln!("sig:\n{}", &*hex::encode(sig));

    let mldsa44_pk = MLDSA44PublicKey::from_bytes(&*hex::decode("d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312").unwrap()).unwrap();
    let sig = &*hex::decode("5e93b785c5119c3983a291b18420fdbe4bca53d5a3732922faaacd5a5d32a745c78d105ba10bee1ed8069f19e6c537bda16e89d39004c359d1fd381a0291f1c51f1c38edcdb315c8c69570d8f25f1655ba8ea83aff24b8b6be8de762342e347eab2caa6803ed705952dd6450c5185e9d60ce96e8dca423a02f646cea690164a226e4c3d6a515ce16290f19b2c626da9b450ecf665013c5e226b6c0ac5c07ce90e278f1b0134e385d13e74208a0b3ff052a362579f9207ea01f18a039aa1b97ae3452675b620771f8012ee7a4e55c98bfd2019ed8a3b00acea8e8ab28172faa42ca1fda83c5ffe81a45be736bdedd5fb300ce17078b380f620bdeebad693601372c85eacf79bc98e1b48f2ad7e5dce4279a1295bb2ba60a0c5e3726642d2336c5eb1d37c8623c7558241318d89bc783c4f00098077484623c217560a0c7aaf75dcaccb78ee69c207c27c8bf3965ccf58a80c88efcc7e5deb3615d5045a741c4dac0a021dd060d315d4ec2857eb664d728d0af973bea07e1ca563faa0e19996cea3770316c11a5066665662005ace98f6110e883bae060daa7b6d83379e0878796691708a32b85730de8b92d89f90a3660c949165b14612567662e162232296cbd143517a282e22c46b63606d3c14ed4559a5a1c459bab7f355007ad6f7e3b1e07445dfc96bd9b75080b3d4f68998490a26b5e090be2674071ab925bb650590856c59f8ba7488d2b72f840ac3eafe4dd91f0f51c4364112c1a139e3e942a597b93a1e3f4faded129c14b5978b315e2246a93146a79365f0f597a18340cca86bb15ceed39f175eab1e546535afb966f0a65a8f66f737ab02897eddfe92cf7786894843c2691464776c94bd450a1069138b26df83b2d1dd801143a8fdfdc2514cc5b5831ab53a75c55ef29f40e7c63d2c72abe97e2af14853be49be16f4730a159974970951439e55c1589d0f4a162e3517df9d7abc98d8a307216e7f1cb4627c9175c0eef23337e56d5281b83726fff40a148b0c48e8df3496a2118d80219aef8f40b29fba1f2f78786b67ffb7b7d47d406b765bd136610bedeb95cd7321f58f3b836c9258be35d78b498f3efe1db2b243d734fab159baed8807c3cccf83eb2eaf8a9af01a518d48c60e91a96812ad689c2d83cc4e8e9b3650422bed6f13c24adaad91c95b3e3cf354f0f6bc9ee8941a6b15b6975131d95233d8935de367efc6d86a45dac7d0f1ddd9aebd2c59c027fcda448801e93e733aca51874be9ab927a904f96ddb7a46b2da13261d522b23c950c01d5f5e112b76f851ff234f06f8d5e65b1319abcd79a180ae063d65b28c745878c06dbb69ba73293eab34434bf1a92fba691993bd0ff3edac76a12f80c0ada4b1969c7665589d530a67016a625403c537032904f2e104547cd3ea406260dd357fa06ea012a785826c160e99ffd065b0e3f33c7689d3552ab9e2e09fa7e55bbcef042242bcacad8a3da47bcc54a121f1526c8cd4cc5a892a8131cf4eefaf4248ddd6a11ec427ba378aae89aaf582ce1f4e32690a555e740761d358ad4e92bc38418aa782da916524fb09ab2ca6b3d3113d6f2c2a6a9b9d29d4e7489255252af075cbf9feacedae6f3ec0b070824689dd3c78ac143ed6776d95dd8f13d435a290bdca4c11318e5acce04469644e1374a9451b6204f3b3961b7dd239e306fef5f4f4e51b78b0fb9dcee69c3e790b231f2e65fd1ab1c2a75b07067d5c16dde00983a58ffcdaaaee16d2742e133ed737b48064c8a38eca35ab3fa18f6d62f642b12cfdc7980f2ab7db321fec9dcfe499b4fc1ee7eb297954056617c60a6640b92835d165c3c00a951952614488d5657ba0b5e90ae9e0ef7b3b9ecaebd81b8551b6d70e835b2734761639d42e76ffc5b3272b61c896b45b4bd18f30e58c440643ba159221cc6739a19a65f2911fae47b0d4cac4200a6f043b17a03ad393ecb823ed03c8b6cd68167e6c8234f7432557db272079ee899aede73b6b98d6003f45789a141b60d6db40cd2a5974571a4ad3667b889318ba60285d903a2eac01c21608838c40907de6bbabe042cf2ecdd97f549f95ec698d79222c65ba27c30d332a68d057aecdc9388aa34320e0aa74fdbd4d1b643cace216b6d8ad8f07a99955bfdb743a86b40fc61527baca434ac2a7fbeaa77111dc8098b17e800f59dd77ccb0e67707e60123d334e073a2f5a16ffbcd701389add57c3ceccb88b286ac1e6e3e6485af1a12ea241d14a1b5003d7f3bc9e957d4483c0f9f703b3a187d55e505817615fbc4ae0837616184245cfba61ce3b929e33f52b71cdd7b6a0da55c1f997510b1a9002ca4e0678373a3b1ab2897e6b423f15a440a636cc861491ef41ad0aa627d8e198a5ee7bd7b6cb2c9ce2a8cc015f0d206de4c49e2f87f310954a10d86e294f742ee186f4ae9815f699622792206cafba8f5621738160e6c5d611a8252c6f35085b604ef895164d4ea6ddd310c7d8f0c879fb1f884c5741d096b3d2da0ce1151790dda881d18cb6b19a9fed6f5254b7d52d5d92bbbe24c9d6a65604a0b8ed24ad5c197d683f598743c96b5960e8723732b5bd647e9dbeaa851d0e1cf6d2c070d4442762c28098c5cf5a54b2b5e69a99b10815bf0f477bb71f0d5d3a62ba2b3e29bf84d4b4e574707f5f74af704d277bd6ca38da21e2cdac549e5eae1de7a18ee534c8c2291c908caabf159e90e6549db94ba7a3f3d97dd398a75df5b1a7cdfb25410b7efc4ed00d9995b37b58bf91ed7a3510cffea82f9e1c2a3290406004d09057d63b770fa0e53103199544eba662a2c302cf39008f142d2b16963e95ab10be7c2610168608f353a2f2c41c7056dec1a8c7a6bfa0027f9dedacb7786b67ea2c494d43ba851cf9415c1bcc52f027ec02c65534f608e9d166d51dd431cdf5871f5cdd1579cc06079df075a25062ba7e70d9666c4e7fed34cea0ea0f11ade1eb2a9b397bcaaad1061270ecf497803a5fce7f41e6504fbec71a7de7d066b8261868afc49b9e685f0dcce75e2fcb3ba8cf19057e3941576baf58fb821bd4268f7fae3028601da022e9b468646abdb4fa6098a449b4267d509d9a33f4c3ebcc32dac094d48ed600e765787fb92b1974f74f7bb4c66eb2bbd02895e6a381c1c452eaab1ae4731cf632f61ae2c905921174a3bc9bb4cdc89d630264b614988f3abbea1bd617ffa53d71b7d8a371462b773351a2dccaedd7f59cd728fadee059067bd80c94c8c9a1ffca2dc4f848b829c0561385aa82cc98503d0bb66a6aa4fae0703d12e60e1460efbbcdf2412c13e7c684d1b01102026343a414344585f6e7072748baeb5bbc6d1e2effbfe060e2e3e5160797c9ea6bac7f11024404a52575f6c898c97aab2c3cceaf22f3f535f7b818396a1b1bce6000000000000000000000000000018253642").unwrap();
    assert_eq!(sig.len(), MLDSA44_SIG_LEN);

    if MLDSA44::verify(&mldsa44_pk, msg, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_mldsa44_lowmemory_verify() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA44, MLDSA44_SIG_LEN, MLDSA44PublicKey};
    use bouncycastle_hex as hex;

    eprintln!("MLDSA44_lowmemory/Verify");

    let msg = b"The quick brown fox jumped over the lazy dog";

    /* One-time setup of the KAT -- commented out so that we're not capturing keygen in the bench */
    // let seed = KeyMaterial256::from_bytes_as_type(
    //     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
    //     KeyType::Seed,
    // ).unwrap();
    //
    // let (mldsa44_pk, _mldsa44_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

    // eprintln!("pk:\n{}", &*hex::encode(&mldsa44_pk.encode()));
    // let mu = MLDSA44::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
    // let sig = MLDSA44::sign_mu_deterministic(&mldsa44_sk, &mu, [0u8; 32]).unwrap();
    // eprintln!("sig:\n{}", &*hex::encode(sig));

    let mldsa44_pk = MLDSA44PublicKey::from_bytes(&*hex::decode("d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312").unwrap()).unwrap();
    let sig = &*hex::decode("5e93b785c5119c3983a291b18420fdbe4bca53d5a3732922faaacd5a5d32a745c78d105ba10bee1ed8069f19e6c537bda16e89d39004c359d1fd381a0291f1c51f1c38edcdb315c8c69570d8f25f1655ba8ea83aff24b8b6be8de762342e347eab2caa6803ed705952dd6450c5185e9d60ce96e8dca423a02f646cea690164a226e4c3d6a515ce16290f19b2c626da9b450ecf665013c5e226b6c0ac5c07ce90e278f1b0134e385d13e74208a0b3ff052a362579f9207ea01f18a039aa1b97ae3452675b620771f8012ee7a4e55c98bfd2019ed8a3b00acea8e8ab28172faa42ca1fda83c5ffe81a45be736bdedd5fb300ce17078b380f620bdeebad693601372c85eacf79bc98e1b48f2ad7e5dce4279a1295bb2ba60a0c5e3726642d2336c5eb1d37c8623c7558241318d89bc783c4f00098077484623c217560a0c7aaf75dcaccb78ee69c207c27c8bf3965ccf58a80c88efcc7e5deb3615d5045a741c4dac0a021dd060d315d4ec2857eb664d728d0af973bea07e1ca563faa0e19996cea3770316c11a5066665662005ace98f6110e883bae060daa7b6d83379e0878796691708a32b85730de8b92d89f90a3660c949165b14612567662e162232296cbd143517a282e22c46b63606d3c14ed4559a5a1c459bab7f355007ad6f7e3b1e07445dfc96bd9b75080b3d4f68998490a26b5e090be2674071ab925bb650590856c59f8ba7488d2b72f840ac3eafe4dd91f0f51c4364112c1a139e3e942a597b93a1e3f4faded129c14b5978b315e2246a93146a79365f0f597a18340cca86bb15ceed39f175eab1e546535afb966f0a65a8f66f737ab02897eddfe92cf7786894843c2691464776c94bd450a1069138b26df83b2d1dd801143a8fdfdc2514cc5b5831ab53a75c55ef29f40e7c63d2c72abe97e2af14853be49be16f4730a159974970951439e55c1589d0f4a162e3517df9d7abc98d8a307216e7f1cb4627c9175c0eef23337e56d5281b83726fff40a148b0c48e8df3496a2118d80219aef8f40b29fba1f2f78786b67ffb7b7d47d406b765bd136610bedeb95cd7321f58f3b836c9258be35d78b498f3efe1db2b243d734fab159baed8807c3cccf83eb2eaf8a9af01a518d48c60e91a96812ad689c2d83cc4e8e9b3650422bed6f13c24adaad91c95b3e3cf354f0f6bc9ee8941a6b15b6975131d95233d8935de367efc6d86a45dac7d0f1ddd9aebd2c59c027fcda448801e93e733aca51874be9ab927a904f96ddb7a46b2da13261d522b23c950c01d5f5e112b76f851ff234f06f8d5e65b1319abcd79a180ae063d65b28c745878c06dbb69ba73293eab34434bf1a92fba691993bd0ff3edac76a12f80c0ada4b1969c7665589d530a67016a625403c537032904f2e104547cd3ea406260dd357fa06ea012a785826c160e99ffd065b0e3f33c7689d3552ab9e2e09fa7e55bbcef042242bcacad8a3da47bcc54a121f1526c8cd4cc5a892a8131cf4eefaf4248ddd6a11ec427ba378aae89aaf582ce1f4e32690a555e740761d358ad4e92bc38418aa782da916524fb09ab2ca6b3d3113d6f2c2a6a9b9d29d4e7489255252af075cbf9feacedae6f3ec0b070824689dd3c78ac143ed6776d95dd8f13d435a290bdca4c11318e5acce04469644e1374a9451b6204f3b3961b7dd239e306fef5f4f4e51b78b0fb9dcee69c3e790b231f2e65fd1ab1c2a75b07067d5c16dde00983a58ffcdaaaee16d2742e133ed737b48064c8a38eca35ab3fa18f6d62f642b12cfdc7980f2ab7db321fec9dcfe499b4fc1ee7eb297954056617c60a6640b92835d165c3c00a951952614488d5657ba0b5e90ae9e0ef7b3b9ecaebd81b8551b6d70e835b2734761639d42e76ffc5b3272b61c896b45b4bd18f30e58c440643ba159221cc6739a19a65f2911fae47b0d4cac4200a6f043b17a03ad393ecb823ed03c8b6cd68167e6c8234f7432557db272079ee899aede73b6b98d6003f45789a141b60d6db40cd2a5974571a4ad3667b889318ba60285d903a2eac01c21608838c40907de6bbabe042cf2ecdd97f549f95ec698d79222c65ba27c30d332a68d057aecdc9388aa34320e0aa74fdbd4d1b643cace216b6d8ad8f07a99955bfdb743a86b40fc61527baca434ac2a7fbeaa77111dc8098b17e800f59dd77ccb0e67707e60123d334e073a2f5a16ffbcd701389add57c3ceccb88b286ac1e6e3e6485af1a12ea241d14a1b5003d7f3bc9e957d4483c0f9f703b3a187d55e505817615fbc4ae0837616184245cfba61ce3b929e33f52b71cdd7b6a0da55c1f997510b1a9002ca4e0678373a3b1ab2897e6b423f15a440a636cc861491ef41ad0aa627d8e198a5ee7bd7b6cb2c9ce2a8cc015f0d206de4c49e2f87f310954a10d86e294f742ee186f4ae9815f699622792206cafba8f5621738160e6c5d611a8252c6f35085b604ef895164d4ea6ddd310c7d8f0c879fb1f884c5741d096b3d2da0ce1151790dda881d18cb6b19a9fed6f5254b7d52d5d92bbbe24c9d6a65604a0b8ed24ad5c197d683f598743c96b5960e8723732b5bd647e9dbeaa851d0e1cf6d2c070d4442762c28098c5cf5a54b2b5e69a99b10815bf0f477bb71f0d5d3a62ba2b3e29bf84d4b4e574707f5f74af704d277bd6ca38da21e2cdac549e5eae1de7a18ee534c8c2291c908caabf159e90e6549db94ba7a3f3d97dd398a75df5b1a7cdfb25410b7efc4ed00d9995b37b58bf91ed7a3510cffea82f9e1c2a3290406004d09057d63b770fa0e53103199544eba662a2c302cf39008f142d2b16963e95ab10be7c2610168608f353a2f2c41c7056dec1a8c7a6bfa0027f9dedacb7786b67ea2c494d43ba851cf9415c1bcc52f027ec02c65534f608e9d166d51dd431cdf5871f5cdd1579cc06079df075a25062ba7e70d9666c4e7fed34cea0ea0f11ade1eb2a9b397bcaaad1061270ecf497803a5fce7f41e6504fbec71a7de7d066b8261868afc49b9e685f0dcce75e2fcb3ba8cf19057e3941576baf58fb821bd4268f7fae3028601da022e9b468646abdb4fa6098a449b4267d509d9a33f4c3ebcc32dac094d48ed600e765787fb92b1974f74f7bb4c66eb2bbd02895e6a381c1c452eaab1ae4731cf632f61ae2c905921174a3bc9bb4cdc89d630264b614988f3abbea1bd617ffa53d71b7d8a371462b773351a2dccaedd7f59cd728fadee059067bd80c94c8c9a1ffca2dc4f848b829c0561385aa82cc98503d0bb66a6aa4fae0703d12e60e1460efbbcdf2412c13e7c684d1b01102026343a414344585f6e7072748baeb5bbc6d1e2effbfe060e2e3e5160797c9ea6bac7f11024404a52575f6c898c97aab2c3cceaf22f3f535f7b818396a1b1bce6000000000000000000000000000018253642").unwrap();
    assert_eq!(sig.len(), MLDSA44_SIG_LEN);

    if MLDSA44::verify(&mldsa44_pk, msg, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_mldsa65_verify() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA65, MLDSA65_SIG_LEN, MLDSA65PublicKey};
    use bouncycastle_hex as hex;

    eprintln!("MLDSA65/Verify");

    let msg = b"The quick brown fox jumped over the lazy dog";

    /* One-time setup of the KAT -- commented out so that we're not capturing keygen in the bench */

    // let seed = KeyMaterial256::from_bytes_as_type(
    //     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
    //     KeyType::Seed,
    // ).unwrap();
    //
    // let (mldsa65_pk, mldsa65_sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
    //
    // eprintln!("pk:\n{}", &*hex::encode(&mldsa65_pk.encode()));
    // let mu = MLDSA65::compute_mu_from_sk(&mldsa65_sk, msg, None).unwrap();
    // let sig = MLDSA65::sign_mu_deterministic(&mldsa65_sk, &mu, [0u8; 32]).unwrap();
    // eprintln!("sig:\n{}", &*hex::encode(sig));

    let mldsa65_pk = MLDSA65PublicKey::from_bytes(&*hex::decode("48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300750df1d2c58753389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59c13d57374729fc4e295362e2a5191204530428bc1522afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cefe402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19294e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6dee639386c46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b51b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7b11a9098504fd5975bdf1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca3c215fd360026be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d627c086024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed40080d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f47703a5aef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0c1268b4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab620aa2396f56c0686b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d973738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35e15eb2fa04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923dadd6c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a3181954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be69a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b58536d109a7131c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589b80e566ad557ddef7367196b7227ea9870ef09ddfec79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d6be5a08e9b66da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f03a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a06b4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50ad18bd13fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f").unwrap()).unwrap();
    let sig = &*hex::decode("9061f15cbf2092f744fbcd799eb02414053c1b0f7412124bedc41cf9a3db0166469e874037d7f081e5f8d3d2033a0307d1c49ed01fe64578c4a6fabd80880cdf1911848f184d4bcf536ca795a0fb1aa19ab7ee3ba6b58bd64bbeac9f58650fff1ef5a97ab6916df962072e20e7c6be96090e3a781a504bc4442bd8889a0aa628907a74299f39fa836031f1bd68355bebe7ae93c1e361a9efbed1325d96227070461fcd6f151b8669d9229b977d9ee51fd2260c3e4a2e820416f9e074958dc3b3e2217e6312b7e0b582a048981cf6579f4bc7715b78c808e4c57e3b8aa38b05c04fcedf209f52c1e331ae83dbdff60ba450a17cc397568e54bc3f16ddf30b92747ce460d925b9be20a1d35e2aed97f124af2616a5361df28ba30e522dd08fa00fd28d1ac484d756a89e3a442fefe8332c56cd2a9fde691bdbda43f1cc54cef57bead96120b50c7d4695bdbb1303cc5ddda898e4eeb83083176e40e0232cdd1c3150371df05d6fdad7e1164d90393cf308e99edfeb31fed263e2866ee3b7f3937b399c974d87ba7b489efe3c9b80371d2928446adc31991ab0cefaaa080575b9ec81cfa133a9911c035a8058d0d3f2e34de4a9fb009bb4ccdb16de7b908574a7496725ff857556c1b33917e986c80f1014a9e3083add2fb35f345c5d06159e443329d0da099987b996c3731592b460c2ffd2955f7546f4216100ba43188803ff9b36969685f909fa2539323b8c8ec1c095a5085e554dd450e0e67ab670b6a11ebf6c25520fc13e364060f91f9b7f3d5cb48ff28b8fc83d4293f1f35ad6ff6ae4574ad7a1c6005fc0389a7b21386b0850a05d832fe6a14bb2b1db1f8e20bd09174946cd098b81c8f797e95f2143a949770cf1219bfef039db51a80fc247f65f41554c7173dd805ba82fdf47ab6d4bfd37dfe46fc47904421ae00dc005a22f9c4784b0ea9e665392a412245016d5c6d7673a6a180d228d4255a538e451ffd8b414d40304c0c888992e0ab6de1602109527417bc1c7eb782ae77a8c3cdfc1d13a1e874207898264e38080243109c5969649ac8383417e922ba115331142d0ed35440b15d40bee0cf58af37c0f0524ffac1c71ceed3bb82f76ab108a8ad1a0c8b78d9341148c642369be7bef59d46f49d70c83560607f140848ec9a7607d4a08f8b6e4447f5523f416981888a8de9647ffef79389e4983e5c9387698d0cc2d429322365ce7e7b5fd6d6eb921c813fcf06199fe1ca41e9cfe03b539f321671a2acad0963f876f9db7a1c4371b9f101005217995b5b6a40976246d245da603dba8dac812a5480c3476a99d0ffdf0ef943d72d912543148b2fe78e8b0159324fe9bcd4ced33cd212fe4f3dfd6d4c5e1958beb95ac6b533ace3e78015e3880b52bf45299263a4c0096f8ba5fe3a6298cab675cb7f382e7ef49720eb4cf47376e2d2574122ccf91129c858e948904fecefb91226ed42403ba12dd3258909a87dfcbf65cc3adc3d98d277fdcec7664e2292b7d27afbb5aafb405c20a34b2fe2c0849ee280bb891dfdf59f19b89b0246358db54cf3fdc66eaaaa750c8903f1d42678f3edf0b7530410aa881bc617f94346379854af4532e61f65aae7576c35faf55e155bd6787b4634d54191907e155c239e68480cdfa0c87054bfb62855f409a20d5335fb123e681e64ec847cd985b6062059f436aebac623c038b6c3405ac325191a8d1126a5ef8f38cccbf144a5c324c1e093cf99efbe10ca03d439bcfb8ba5e293b7d318837f7bc42a99964392369da76e79d71d1a2c248a11324a87ae1e3cbeab6fb0d0bcae1ef55e43dfb6f1b4cfb82c7a778fb828a3727ef07685fe38a74b3dd25d015322c2d9f245c08d8c2b43865694233782eb734436c4eddef5406208d6c4572c7371262fe02319cfbbcf2e23bed8aa969d1ae6f5f25ff6b8ebcf0925066f761a39bbff49f0c8dbc3be84f0c442b044ea01b669747e3c8293cfe9ccdf2ef063ae3d28d10720c279a2691616abd23b055cfc6c562125df4ad0fa6631304972ddc3674b1aaa7665bf621320d83eac8d5b371d7d719829f58b23458182558710de31d81ef9a47d8839c79640b2025d1965a418bc90e4115f1423311a8b64fcde0f2d2145ee535b0931b84bc8110445f2ff68d136ed709ddb7ea9ff75f3b4e8b4f836230ca9e81069477f634e07270af60ef96f72557a081d664abcf35548f699484653da645483ff2bf5998617ae8bfa62d56e714f3c0136e5035a3f78e06c2f470df7fd3380d14033f81e2aae6b4d90487dab76b9b3b8761fb56c36f5429da3d4346cb22e641ad8d7d2d80fa240d4e0154e6b3d2f1b3ef6cf174c08d062f575c83a4078174f874364df36a6328beeef69ba7f90e1df9fdcec9a2f15ebf04fa7d6756da2e5a59c9cbbcbc397d6fb28d0fc9a60534dff0752716ed079ad1ab19a224d1c8ae8a53242fd164989ff997489b6520eb3c0e97f4bcc1a9c3cbd44f008c03ef52cf7e626881d246925e0336c0ac668867f853da7820f914115a7c77ac31b66f46fbf97f66fa26416fc4581d459a4f2462d52cf0c79b278955aa73e8fa56e3c320f516bcc54c97e587199c15ab953cc37189b81c70cabb2559e445bcc9d8174ad7574e9acb02f43e0c34ff5e6746ee730ad41ff8eef93c2071c2649063dd92f343c06ef6abaf98f28d98d968071c12cc10a90c22d8b3b3480c76f7a51b7ec594b3435d2e3d779c1a15037697f3a058650472e47eecd5f32eb3243a516f0e703f9888c84690750648d6a9a876bf1f353db6891dc6d317d6e87ac088f42b5f6f20d799ece4fa7aaa928d2ac795e8de83d1e1c7fa2f9a4106693e981c21c63b3221c4fa2649f45f0c6e05dbf24011af16ab2e5fe94a640b485988037ebe1e8ad0b2623d95e9947f0726121d7828614e3b2d77a7a1f9a938bea9a1a7a2627b7d2e358c42ccc6c0b80a15a1c2f6e9aaf0495bdb7bb8d4b0e28a1ab5ab93ca0ff3e3f910c490c13486852534d5e12160835ec5916c5c68349c4e2d8fa956c643277edd3b6c81c88c010421705fd317ff9e3c94df0ed5305f530acbccf8dd0e87140cd38152664a572c168cd72595b7fac243c03f3fb33ef74a28c0e4469f94587c13704e9efe8010b2125aca78c22c33c82366e1a7c4028c2ae2e8d26e1a57e4297fac987f84a0a27f42b4c93a4f4d14569824b0880fb67407ed58f267ac403aa0b1f93784b4b4c67036037e60d58072611b0e90ca316976ef4e0b302cdad1b6dcca92efb8e1f6be2397967508be2c02a25ed0380ba1f7955f857c8fb043297780d136b2b064040c8e55143d715ea997e134ed973c98ef82786f0ccf66c17d863542180c66d54d08e116f2e35d995e214489ad0fad7a55fe9ebc1a777fe34141147c080b98d13463a3bbc6fc82f2fc95f4de7b3591d9c8cd4416917a4338095d5620104b7be13f5a131dd3f7aad5b559d11e8171dfb91e2bb1e47ac3810b1cdc1a1e370c867b7b7b50c4688dce545763157e02f47e1cc661d5bf2fbc336cfae080ab15728b1ab9dd199f2779d451e6178977fb658c17344cffb7aa3af5791a28fc8a089c85187753e5e313c8d1f0fe7755e28be444426a189e8bce2d2f79db31d4c3ca911a83455525355f95d159351cd731a88e55403851236ee2128f279d5be644c042453ae65d9e9f3b40d6c82bdeb002acdee061ecca3f2dceabef9a900e6e063d56ab39cb82dbc77a4677572d7616cd72c0f6d5b9b941dfda1fe7c896b8cc24d65a4322d712a84e94adfc8ed0cc56cc1ae97f775bd3cea5b20b524d9a7a916056e19af095d30171e5e14c7c998f78dc44845edf307363eab7913f680a5e5a1540a6f945507ffa67591f8d1a2920ab3b6e754e35379dd67870c242335e2717903ff3c687e5c33dc953416865d5f23bd752e55492b9d5d888d7b37ef33b0a6774d052b0987c066a2e01767207aa7fbfc393ca62874613dde3794f74fadb5d55b877b877a605918c812610fbcafad72ee245e6dd8721138d6bd3f4eedad853aed1ec437ad02ac937c80dae26fa5f70083bd346779b779387f7b3d2aae57770d8177928833281ccb7a38da24834fd9726fd17eb603cba9041e82bfeed0e33942dde1d48c271f5b39aa7230f41afb89d36f7976eee4f51a036743031c534f64685b94c990a93a5737fe628ee9cda8ed9c08b11d3836f833835c445b317a77ead7599d1a0c08873014510d36bb7ff5fb961277589ea48c32a60c87ec40681be067b17785ec44825bd89faa25249e735a628b6eebcc6cce4e0314c627588118c40b2e0d460d8d5ce358c56458f36914ca203f5a5381c6deb5a76bbc08c40a87437da0d0b571788a05e9f96d9bb770de8a0b1b960ff2a44a964c9b7939853742e83ce8deb79191b2d82454655f227079dd8c5b0216c8470b8e1ac70526301bbfa2bc4adca68a766ccb2a6e0ebf2e99905bf5242590b01703868b3faf841c11c383be145a40fea6375e18a01468e459603b5efdf8a4e9abd179280ae8b5947d78d2f0c4d37715eaa42bc37cf8730e41ffbf9826d46424f2922a96033cefaa8b4bbe4c8b89d43501fd5211d5392ca19a98ba127d9025b5c6e86ba024471940549a2b5d8e14961c9dc19696da1a5bffd01030d5e6100000000000000000000000000000000000000000000000005090f131a1f").unwrap();
    assert_eq!(sig.len(), MLDSA65_SIG_LEN);

    if MLDSA65::verify(&mldsa65_pk, msg, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_mldsa65_lowmemory_verify() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA65, MLDSA65_SIG_LEN, MLDSA65PublicKey};
    use bouncycastle_hex as hex;

    eprintln!("MLDSA65_lowmemory/Verify");

    let msg = b"The quick brown fox jumped over the lazy dog";

    /* One-time setup of the KAT -- commented out so that we're not capturing keygen in the bench */

    // let seed = KeyMaterial256::from_bytes_as_type(
    //     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
    //     KeyType::Seed,
    // ).unwrap();
    //
    // let (mldsa65_pk, mldsa65_sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
    //
    // eprintln!("pk:\n{}", &*hex::encode(&mldsa65_pk.encode()));
    // let mu = MLDSA65::compute_mu_from_sk(&mldsa65_sk, msg, None).unwrap();
    // let sig = MLDSA65::sign_mu_deterministic(&mldsa65_sk, &mu, [0u8; 32]).unwrap();
    // eprintln!("sig:\n{}", &*hex::encode(sig));

    let mldsa65_pk = MLDSA65PublicKey::from_bytes(&*hex::decode("48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300750df1d2c58753389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59c13d57374729fc4e295362e2a5191204530428bc1522afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cefe402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19294e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6dee639386c46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b51b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7b11a9098504fd5975bdf1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca3c215fd360026be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d627c086024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed40080d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f47703a5aef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0c1268b4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab620aa2396f56c0686b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d973738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35e15eb2fa04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923dadd6c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a3181954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be69a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b58536d109a7131c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589b80e566ad557ddef7367196b7227ea9870ef09ddfec79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d6be5a08e9b66da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f03a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a06b4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50ad18bd13fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f").unwrap()).unwrap();
    let sig = &*hex::decode("9061f15cbf2092f744fbcd799eb02414053c1b0f7412124bedc41cf9a3db0166469e874037d7f081e5f8d3d2033a0307d1c49ed01fe64578c4a6fabd80880cdf1911848f184d4bcf536ca795a0fb1aa19ab7ee3ba6b58bd64bbeac9f58650fff1ef5a97ab6916df962072e20e7c6be96090e3a781a504bc4442bd8889a0aa628907a74299f39fa836031f1bd68355bebe7ae93c1e361a9efbed1325d96227070461fcd6f151b8669d9229b977d9ee51fd2260c3e4a2e820416f9e074958dc3b3e2217e6312b7e0b582a048981cf6579f4bc7715b78c808e4c57e3b8aa38b05c04fcedf209f52c1e331ae83dbdff60ba450a17cc397568e54bc3f16ddf30b92747ce460d925b9be20a1d35e2aed97f124af2616a5361df28ba30e522dd08fa00fd28d1ac484d756a89e3a442fefe8332c56cd2a9fde691bdbda43f1cc54cef57bead96120b50c7d4695bdbb1303cc5ddda898e4eeb83083176e40e0232cdd1c3150371df05d6fdad7e1164d90393cf308e99edfeb31fed263e2866ee3b7f3937b399c974d87ba7b489efe3c9b80371d2928446adc31991ab0cefaaa080575b9ec81cfa133a9911c035a8058d0d3f2e34de4a9fb009bb4ccdb16de7b908574a7496725ff857556c1b33917e986c80f1014a9e3083add2fb35f345c5d06159e443329d0da099987b996c3731592b460c2ffd2955f7546f4216100ba43188803ff9b36969685f909fa2539323b8c8ec1c095a5085e554dd450e0e67ab670b6a11ebf6c25520fc13e364060f91f9b7f3d5cb48ff28b8fc83d4293f1f35ad6ff6ae4574ad7a1c6005fc0389a7b21386b0850a05d832fe6a14bb2b1db1f8e20bd09174946cd098b81c8f797e95f2143a949770cf1219bfef039db51a80fc247f65f41554c7173dd805ba82fdf47ab6d4bfd37dfe46fc47904421ae00dc005a22f9c4784b0ea9e665392a412245016d5c6d7673a6a180d228d4255a538e451ffd8b414d40304c0c888992e0ab6de1602109527417bc1c7eb782ae77a8c3cdfc1d13a1e874207898264e38080243109c5969649ac8383417e922ba115331142d0ed35440b15d40bee0cf58af37c0f0524ffac1c71ceed3bb82f76ab108a8ad1a0c8b78d9341148c642369be7bef59d46f49d70c83560607f140848ec9a7607d4a08f8b6e4447f5523f416981888a8de9647ffef79389e4983e5c9387698d0cc2d429322365ce7e7b5fd6d6eb921c813fcf06199fe1ca41e9cfe03b539f321671a2acad0963f876f9db7a1c4371b9f101005217995b5b6a40976246d245da603dba8dac812a5480c3476a99d0ffdf0ef943d72d912543148b2fe78e8b0159324fe9bcd4ced33cd212fe4f3dfd6d4c5e1958beb95ac6b533ace3e78015e3880b52bf45299263a4c0096f8ba5fe3a6298cab675cb7f382e7ef49720eb4cf47376e2d2574122ccf91129c858e948904fecefb91226ed42403ba12dd3258909a87dfcbf65cc3adc3d98d277fdcec7664e2292b7d27afbb5aafb405c20a34b2fe2c0849ee280bb891dfdf59f19b89b0246358db54cf3fdc66eaaaa750c8903f1d42678f3edf0b7530410aa881bc617f94346379854af4532e61f65aae7576c35faf55e155bd6787b4634d54191907e155c239e68480cdfa0c87054bfb62855f409a20d5335fb123e681e64ec847cd985b6062059f436aebac623c038b6c3405ac325191a8d1126a5ef8f38cccbf144a5c324c1e093cf99efbe10ca03d439bcfb8ba5e293b7d318837f7bc42a99964392369da76e79d71d1a2c248a11324a87ae1e3cbeab6fb0d0bcae1ef55e43dfb6f1b4cfb82c7a778fb828a3727ef07685fe38a74b3dd25d015322c2d9f245c08d8c2b43865694233782eb734436c4eddef5406208d6c4572c7371262fe02319cfbbcf2e23bed8aa969d1ae6f5f25ff6b8ebcf0925066f761a39bbff49f0c8dbc3be84f0c442b044ea01b669747e3c8293cfe9ccdf2ef063ae3d28d10720c279a2691616abd23b055cfc6c562125df4ad0fa6631304972ddc3674b1aaa7665bf621320d83eac8d5b371d7d719829f58b23458182558710de31d81ef9a47d8839c79640b2025d1965a418bc90e4115f1423311a8b64fcde0f2d2145ee535b0931b84bc8110445f2ff68d136ed709ddb7ea9ff75f3b4e8b4f836230ca9e81069477f634e07270af60ef96f72557a081d664abcf35548f699484653da645483ff2bf5998617ae8bfa62d56e714f3c0136e5035a3f78e06c2f470df7fd3380d14033f81e2aae6b4d90487dab76b9b3b8761fb56c36f5429da3d4346cb22e641ad8d7d2d80fa240d4e0154e6b3d2f1b3ef6cf174c08d062f575c83a4078174f874364df36a6328beeef69ba7f90e1df9fdcec9a2f15ebf04fa7d6756da2e5a59c9cbbcbc397d6fb28d0fc9a60534dff0752716ed079ad1ab19a224d1c8ae8a53242fd164989ff997489b6520eb3c0e97f4bcc1a9c3cbd44f008c03ef52cf7e626881d246925e0336c0ac668867f853da7820f914115a7c77ac31b66f46fbf97f66fa26416fc4581d459a4f2462d52cf0c79b278955aa73e8fa56e3c320f516bcc54c97e587199c15ab953cc37189b81c70cabb2559e445bcc9d8174ad7574e9acb02f43e0c34ff5e6746ee730ad41ff8eef93c2071c2649063dd92f343c06ef6abaf98f28d98d968071c12cc10a90c22d8b3b3480c76f7a51b7ec594b3435d2e3d779c1a15037697f3a058650472e47eecd5f32eb3243a516f0e703f9888c84690750648d6a9a876bf1f353db6891dc6d317d6e87ac088f42b5f6f20d799ece4fa7aaa928d2ac795e8de83d1e1c7fa2f9a4106693e981c21c63b3221c4fa2649f45f0c6e05dbf24011af16ab2e5fe94a640b485988037ebe1e8ad0b2623d95e9947f0726121d7828614e3b2d77a7a1f9a938bea9a1a7a2627b7d2e358c42ccc6c0b80a15a1c2f6e9aaf0495bdb7bb8d4b0e28a1ab5ab93ca0ff3e3f910c490c13486852534d5e12160835ec5916c5c68349c4e2d8fa956c643277edd3b6c81c88c010421705fd317ff9e3c94df0ed5305f530acbccf8dd0e87140cd38152664a572c168cd72595b7fac243c03f3fb33ef74a28c0e4469f94587c13704e9efe8010b2125aca78c22c33c82366e1a7c4028c2ae2e8d26e1a57e4297fac987f84a0a27f42b4c93a4f4d14569824b0880fb67407ed58f267ac403aa0b1f93784b4b4c67036037e60d58072611b0e90ca316976ef4e0b302cdad1b6dcca92efb8e1f6be2397967508be2c02a25ed0380ba1f7955f857c8fb043297780d136b2b064040c8e55143d715ea997e134ed973c98ef82786f0ccf66c17d863542180c66d54d08e116f2e35d995e214489ad0fad7a55fe9ebc1a777fe34141147c080b98d13463a3bbc6fc82f2fc95f4de7b3591d9c8cd4416917a4338095d5620104b7be13f5a131dd3f7aad5b559d11e8171dfb91e2bb1e47ac3810b1cdc1a1e370c867b7b7b50c4688dce545763157e02f47e1cc661d5bf2fbc336cfae080ab15728b1ab9dd199f2779d451e6178977fb658c17344cffb7aa3af5791a28fc8a089c85187753e5e313c8d1f0fe7755e28be444426a189e8bce2d2f79db31d4c3ca911a83455525355f95d159351cd731a88e55403851236ee2128f279d5be644c042453ae65d9e9f3b40d6c82bdeb002acdee061ecca3f2dceabef9a900e6e063d56ab39cb82dbc77a4677572d7616cd72c0f6d5b9b941dfda1fe7c896b8cc24d65a4322d712a84e94adfc8ed0cc56cc1ae97f775bd3cea5b20b524d9a7a916056e19af095d30171e5e14c7c998f78dc44845edf307363eab7913f680a5e5a1540a6f945507ffa67591f8d1a2920ab3b6e754e35379dd67870c242335e2717903ff3c687e5c33dc953416865d5f23bd752e55492b9d5d888d7b37ef33b0a6774d052b0987c066a2e01767207aa7fbfc393ca62874613dde3794f74fadb5d55b877b877a605918c812610fbcafad72ee245e6dd8721138d6bd3f4eedad853aed1ec437ad02ac937c80dae26fa5f70083bd346779b779387f7b3d2aae57770d8177928833281ccb7a38da24834fd9726fd17eb603cba9041e82bfeed0e33942dde1d48c271f5b39aa7230f41afb89d36f7976eee4f51a036743031c534f64685b94c990a93a5737fe628ee9cda8ed9c08b11d3836f833835c445b317a77ead7599d1a0c08873014510d36bb7ff5fb961277589ea48c32a60c87ec40681be067b17785ec44825bd89faa25249e735a628b6eebcc6cce4e0314c627588118c40b2e0d460d8d5ce358c56458f36914ca203f5a5381c6deb5a76bbc08c40a87437da0d0b571788a05e9f96d9bb770de8a0b1b960ff2a44a964c9b7939853742e83ce8deb79191b2d82454655f227079dd8c5b0216c8470b8e1ac70526301bbfa2bc4adca68a766ccb2a6e0ebf2e99905bf5242590b01703868b3faf841c11c383be145a40fea6375e18a01468e459603b5efdf8a4e9abd179280ae8b5947d78d2f0c4d37715eaa42bc37cf8730e41ffbf9826d46424f2922a96033cefaa8b4bbe4c8b89d43501fd5211d5392ca19a98ba127d9025b5c6e86ba024471940549a2b5d8e14961c9dc19696da1a5bffd01030d5e6100000000000000000000000000000000000000000000000005090f131a1f").unwrap();
    assert_eq!(sig.len(), MLDSA65_SIG_LEN);

    if MLDSA65::verify(&mldsa65_pk, msg, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_mldsa87_verify() {
    use bouncycastle_mldsa::{MLDSATrait, MLDSA87, MLDSA87_SIG_LEN, MLDSA87PublicKey};
    use bouncycastle_hex as hex;

    eprintln!("MLDSA87/Verify");

    let msg = b"The quick brown fox jumped over the lazy dog";

    /* One-time setup of the KAT -- commented out so that we're not capturing keygen in the bench */

    // let seed = KeyMaterial256::from_bytes_as_type(
    //     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
    //     KeyType::Seed,
    // ).unwrap();
    //
    // let (mldsa65_pk, mldsa65_sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
    //
    // eprintln!("pk:\n{}", &*hex::encode(&mldsa65_pk.encode()));
    // let mu = MLDSA87::compute_mu_from_sk(&mldsa65_sk, msg, None).unwrap();
    // let sig = MLDSA87::sign_mu_deterministic(&mldsa65_sk, &mu, [0u8; 32]).unwrap();
    // eprintln!("sig:\n{}", &*hex::encode(sig));

    let mldsa87_pk = MLDSA87PublicKey::from_bytes(&*hex::decode("9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e9147054ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60").unwrap()).unwrap();
    let sig = &*hex::decode("781368e64dba542a7eacbd2257335cc943a03241009b797093c615f76a671a7591430441d80bb582304b33b9fce295e0dd57fe169355ddf4453a2aca62d8eb8109ef0d9cf3f5b0a94e04ad81b3e786014243ecde816551aa7fe01c639054256a491756bef59f5034f717ff4f85e70ba7731a49971415b6a7e7d816ab434b9f17a3095ede6fd432be2bfa82724045dda0dfff7a0281e9000939ccba3d8ab3245139c441648c76a6536127e4d1ef0df1531883ab78c8b41323617ad8db03d9908c9e08a9f7321c45051b3c94213347b11c4a84491de7a7be68701e47d7f0e0b33e767bef17694e4d33244ed92ebd74c85ab6c84441cddc14331e6ae8bd23674bda27f09c050d88f7d430feee7f15a72a24d653bb6bec54491b98362ce131d37c7d78a3f9a893db5abdccd6663593b88bc6c97f07f8eafccfd25e8180d918efbcd95bbf3da29f081e3e1932095939198e2a155b2d803a3e84ca4f34569df695c259faf3c0d8f0cd217ebd2dbad542b32fbb54e44aaf0b5dc739fafef2e46db8d68bfc35f44f038cb1f5231a1b5b134ae683e7f3297cc7a95bd191b310f68201450797fe3293cde1672dfeca4b493f53c768ea048a972a4cd84d39ef682957b8f28ba29487b4689b43fec2655823d9bb99ffcf31490366a9860a5d5b8e32a3b8bfeb6f55f88fb80c8c0142086f220e1f6f2862dabda58c3b6f5faa805b39cfac4b6d7ea7acdf1b0690063b0c1ea38c7c4755189966dc631055f153f71b77b114fa5c309316ba512330ea5cdb0bb176001e57461563d17259f35d0c30ef5ac838c0325402bab52c531469526ae3ee6293f7b5769d27e69fa81cd25a31cd095b126e70c57ac3169a5f585a11f1748d9d22f2564911c26a24b2153a78f3a06822f5f1963f237abeb48efd9a9cd478de579c5a0ba84d00e96fbde36d8ce20e7e948547fb6850834ff79d211830f6ee973359781d9d5008fb43a89354782fde4158177f5206ce1d38c889e99e4bb5b4ab34d6a05c42f5d719ea03dbc54adba75a3bb44a3c08c7556462f8c5b7c568a69242cf5be6098eba0a2249c1ca5b2109b6404a962abc1c159c6b48a79fb97e4a3337d99323746221297423f9bd1b12e78489e01e6a10f0fd6bba1cfd6ae1b75dbe69f8b8ee51a4e7f68ba2c407c9c0bad3892b29b0170ab75836fdd49a7ee3c2bb30f2c3d226bcec49140952170b0d160f97b30b7b7b096719538677ebb06922f26925227c8852acc107a8f173b38d96697584bd3dfe169b4073aa58a7bf371d5c4bb0eed30f08212defb3aec902d4546084176bf0f86d93cf36a4689a5e874b32d6b7d3c1e3fbcfd988c35dbc9a8d0a019ad6d7e15ec3ac97125db6abfe00beffe35a81666699a91e15945c62d646690b5b52de8b835ee9be53588fde5d63023b52b2b1f4610c237a829f5901a46042963cce7b85aa040adde02985e14e23c4eadb75221c607d24672e244c66c9c24c3cb7fd90bb23295c9d3d9da516bce3dd462d6660f9f91ef0618a4d4d3d6668c5d1e2e8ed433ebfe0762beb743324e11608f8b14b69ce4c221c1654ba4992a5af2d949c2939f95d1c8fb767af2a843cc7c78f57259d5c0c6ca83fca41ef5ecc4eeeea93e4518c24d3040f2cd90df3e535e989e606fa109e2c453ed7353db1cdb27137f005f9dd8d2aebfb7255a6098b690215e100cfe44ca0f2745fced48322bc9667ab16d2e1c0ff491b96a17b833d4fd44d31c2230ac835796e063ab03000f04f15c70560033763a48552cceaacade9ca5c8055f3745e179068a287183f2bc3ef6327dec5ac7cf7b052ef5a8873e697efde089688f43be464827c2fa83eb531b3674145e95c699c82990e684967dad319d9f64ab16cd9fe9b6c41232ac4ae3795fd8a76aa9b02e970242061c6da45a2af74ad9cb2a79935c92625e242f4bc7fce54d5c10a9e61f875162fa651b66057ba036f062d6d39d0502b93a5640b78c6c2fd20b02ff83676a87a94945d476c349803ea4fe60cdcea65bb2629e2bc09d4472ec63422dee2052f098deaf5531e6c9bed6672a8b699802efe0cded80c8455f585d1ba633d281f1a21adab48e63b44e0c2a4d7608cf98aabf8adc86bcb8f61e8b06cd2385f82e0a3cdd03cab152d5951859c4532f9168e78f17ba2a5772780327dcf4e62b4d26e443762fc488ae4cd4d1156dbd5782595cfd7697a514abc9b160c9ccf08edc86134a755b90e9bb543511e888e3157721a52d1bc5db33029fb335ea2114e21c03368c8d7f4d827960641772a4a32a738df60d19ec77ab09d22f57cc2523b9503b3f5b1cebc5ae15f885f159842db7359a1c89d3d82d3407068f15b6739626eb8c521fc8c5c7491f945d49f14e6989da340bdf49e7f8a792747aa658bc114143ba93f26022d001735b744639bbf22aab2a1851cfc934f9c69d3764fdea3d23db17998e6138cfd7cd9e9a47cb74193bd71aaf28cdd9d1eb595125546a4f4357ebbd1f410e3bf8557892de68509b5b98c5c229e942c910fdd3e54cb6ad54d8dd886cb97ecc06d1e401b8395d0bcb0db9a031dc66c9294f9053c68fc42042b1fa1671fc7d510b70916c0139cfebe3a91244527ce9439860cedb30908197be851cbd1d3b18ca541358449fb34fb5cd569630ed5f67b8795e87828f2ce3becfe457579d82333b0bbab094de391e1f8157bd431e365ca864630932bbebb48f45f8134424e18ab455029b54b19e2f3bfec5e44ad0ea5c03f53d8f925b635838aa7015a7c9e325bdfaff966ea9512dd50f87c8995cea7561c23f4fb06d964ab8f1913a6ca17e4ca60d6bc078e1784f89c673c91d955bcf45f58ca9709579d5e3831df12cfdb7516fd21878cb54243579b9346d2de4be25f508e84b1adc78cb91c03da3c4fd59e4529189838f74f6312820620a5996b791ffcb332f847094613f2148b862034fa89d0d0ff1808d902c5d1af64d5522492d61ecde4c73be89a33782cef1acc1dc327fb2eb9d17642209b85aa8b1dc57cbf067c7aa29da6b7e157d23e171d3ae6f3855834071791402c851ff2dd67109979f7ee5e09e64b4eefdee7112b55ce200bb8c8051e3428c305fa1d576bffbb25a70eb571168fc60dadd928b10cfd07de80a85b8df3edc372d488c21f0d5787611cc6fb73aeeb6f920a109294b49d3870f90de3b360d14df77ef95640bcac7a4dbca901a31db83e83f5c59ce327207ea9b27c3b978d30d53865c1b84764f025e8732d5007554ce5c9cc410b2eefd7e4d990c538557606a6bc47577a43768d30aa3e8598fd6f4fe7ac439f3931c58fd69d90765ac9f456ac7de085e14a0898c4557f5d3baaae07edc607de6900146b97b35aae570153dc107815ef9febdd4fd567d637fee8f8bfb4b3413ea6aead4846ab733a04f1e4bc32a3bbb1c16baf8d0bdb9ccb82fe46479ccfd040b5e64064e539b39c66e4501dc822873ac6119a4a112a1f7cd6df0e5f84356ce853ced34ce69a9e7383534983c51c50269bf8b9586a0e5ba905fd3bce080b00e7f7d48e55f489479b5771e995fb020e58feb74af65c3ee76aa4e69b5ba8bda249a1b2d62c08d418c3635d061846040843991ab475473da85d94981fb84425e7ad951ce0a42be642fe658b7aaae72b147cdc086c24b1571eb2272e2a72b15660d854ebe19ec7d9ab7ea17800d0b6ae727b39217467c662ba08e6f19193951eeff02806a7843eb5c71b2f04dcb605ecedc5128cd67703038c44bf20fe06f3ed8c1368fe38e72944d5c52fca46a45fd48d8fe5da64183d4d62ec01aa3d9d672ec67a01c17f21e02525f0513cce030c664fc8784763086608bc8099c204c255ffed1daf432ceb45fbd135e21e8190c5bfee192171faa77520481e69e87b7f76790bef76cb8d3c88f5c6e32fc59e7bd45351d66696b61d9f40726fb9a98000b68738cf7e34b98b6a4aaa2ac1d7b1407db89783f8077103ea9c9e89247eae078adfb36e21474c3bb1fe0c87687c6233a533a01e1081b93a3521d339f39c075609bace531994988ae314f77fc6034113a138c67eb7e03750cbec8d28bd21afedfefa8f091619ae500b4ca4599d019dc8ca4bf118d70b8676dfc796a4f6d986adba4c8574ed4abaea5465466220e5e53dc8fcb395d1e59d278673cbc4e3f40658df98ac2fd126a94922879e1a3be91c1acc20803c35fa764abbadab07bde85ff4bd9e0fb6f06baf5bf42b8a2cbf6c2f62606becc361552921a12d6c8236fde84db4bddac77e8872478cffc4e148c1c7acfedf6b17d98731c2de36f3cbef1f6f781a940e0874d5b74535bbe066b53064d43b13926570a9e1c4e6da206c8bd252caf2b62e7d223f7ac12939137f330be59374d7295a6c2dff92e07c727510e48d970593e47229fc8bc3bd5b8ea780dacff4d23063df65feda5f8f65b17a333e532acad7916780c74d6a70d38b367f3f6f4e947b85fc15235bbe46b26495d2780098db853a931377cfbedea620f2355ca21e81ce9e0078b0dd6cb70f23ed558682be3b3d594eefe85344e1f275428b316cc088995939298f2a2d15ac9b676ac3e9cb92f2a64dec7732a91fc761aa1b126ea575e3953177da6e1cd78faea824665330a81d9e24572b9860bf0aba4df8bd5d4e3e2c72bbfbb2a985c7ae2f077951fe8401e1d156ecada1e353817b20f41e0b2460a0caaf2b36d6a7f1b35125d797dcc714421027d14171765a646071ed952b6a5294eecf6a3a71c104c843a4a8b3efcc27467b20cb0a94abf5802229ea4d8312783e78791a50b3c0a88fe6497198cd4bf470dac46f34e50019fdee2040cfe99124b312b1122b83e51d878877cec0855f1158c445cfdc2253f4389d5e3a8ba1669abb5976a4617e85f543da9f5e30b10ca7481c8185392782b46fb0a0e5ab408b2945e3c79a1cc49fb7c27254a9b540e7397a5b655bf7e4f83184db32a128aa2e00a624d7dcd6b77efd151f1e5cba8890af9170fa06c555715dc1787e995ad19270973ae95b88dcafdaf62c28843d3f8b9c78dc8e37d911dab3f7ee9d4c7389c654bdcfc05056b360020140e57e31473258a4081e2a708f7caba90c356d0847098fc0762484086aba898a60b023d6a3060402406240748785d51caff52a0ef3dc2a45dadf80ac18502d24422a8cbb10192b88f4e9160206b2ed3e04114f2a339df269e2c36b8613ce37087471701755330cb559575366ee0fa2d3afcda32eede6dd906345daaa04812198e96c42239c242edb90059709f497da5b87705384aef2af22dc2edfef3c00d8c9156d8b3163fe7a7779e04f04911a8b934fb3072eee844484fede5e2ee96d338eefe2da986067ffe0218ada7de1d0e42d823d6b033918278888ba0608ab8f7be997bdf263689a36f5204c802ad836363779b4b0d6ce5083df0b98a2e2c700062a4fa5e57bc73bd45357e01d90c7954bc6904d1ce8166a9168da39a60c5cae8119bb6b9ab074fb2d0aee384fc2c0e4806811d6002b4e2401e7430b50cb0e8075f33d5386aecde256e169d95e2f9c6556c08ba042e68a53ce8aca9cc02818f7382f150dc04de0019b19c7a3ab0d72d6ed013d7a115d74b279f71fd6effef34049877e0b11e0659be938a5de684eaf23513095eb4a1bdf536c3c01a4655c4b4a0673214cef29a481d06a02cc9a5bfc7b8d846c33484cd67b1de98f60b69918f177b64558ca567a6237d35ff01771a42320ce02bb98f3e4ad4ac7db75611bd9961eac662a38b1f785970c99f3dd105ff586f61301c48d66708cbf7d53a733e357b6c256e8b73f0e1305a0bc137989e521100c2ee6259e607fe12198e8bcb988b0854668e40d7cae6adc3ba40ba121b7319d06d988a073d03097b9f5c1c07284b6473ae57bf154811b77baceb0412b8a6983bdd0ccd9e3bf014e520009cb26d5780eabef1bbafa5e25d41098a54c47fce8b68d395291d54284d33aa50b9664d1510b467c8a539361ca9a4448bc01fcb4c4e3ef475e8afb46a494ae13ee9ea8a1266825fba7f32b9712fde252698a68359b50141d90f5c4a06283ddb54ad7e1412ac5ebb12501f7a82b2a7f27b2dbab626c3db4074523b3211d3182ea261397a6f7b187cf2b8a356ded10812f1d305169aedf79b5ff1cf7c2d6e86ee11f28e96aa63b5a03f59fc960ac7d0572e91dda61905c0711a9b26344a2a10aa2041f2b13cb1a9a9a27774b6d0deddc9d81ea1b142ad7b72be47991f2c9261d6708156e38d00b074020766eb0c494392d65b82ca65f7c3352f9bb78325ecb6df596c8ae57826b08ccd6f1d529d2e25925c1ac972425bedeb88a5d0e3138ddc434da3462ebdf6b1239a21f141ec62cbe4bb993ba253b55a76d30fac19c2c1384ef6b9746c07787aa1fe913a1348390bd8c1f386a08c77cf7106c927ce24dffc9d6ee1b32354d95ed2923482531de6b390bf0f5eb80276e90e7ed11131c848bbabec4d317236269a0a3a7cbe0f1272f93949ca6d23ea2a7ee3f697791aab71533423066d400000000000000000000000000000000000000000000000000000000050e181f23292c2f").unwrap();
    assert_eq!(sig.len(), MLDSA87_SIG_LEN);

    if MLDSA87::verify(&mldsa87_pk, msg, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_mldsa87_lowmemory_verify() {
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA87, MLDSA87_SIG_LEN, MLDSA87PublicKey};
    use bouncycastle_hex as hex;

    eprintln!("MLDSA87/Verify");

    let msg = b"The quick brown fox jumped over the lazy dog";

    /* One-time setup of the KAT -- commented out so that we're not capturing keygen in the bench */

    // let seed = KeyMaterial256::from_bytes_as_type(
    //     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
    //     KeyType::Seed,
    // ).unwrap();
    //
    // let (mldsa65_pk, mldsa65_sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
    //
    // eprintln!("pk:\n{}", &*hex::encode(&mldsa65_pk.encode()));
    // let mu = MLDSA87::compute_mu_from_sk(&mldsa65_sk, msg, None).unwrap();
    // let sig = MLDSA87::sign_mu_deterministic(&mldsa65_sk, &mu, [0u8; 32]).unwrap();
    // eprintln!("sig:\n{}", &*hex::encode(sig));

    let mldsa87_pk = MLDSA87PublicKey::from_bytes(&*hex::decode("9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e9147054ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60").unwrap()).unwrap();
    let sig = &*hex::decode("781368e64dba542a7eacbd2257335cc943a03241009b797093c615f76a671a7591430441d80bb582304b33b9fce295e0dd57fe169355ddf4453a2aca62d8eb8109ef0d9cf3f5b0a94e04ad81b3e786014243ecde816551aa7fe01c639054256a491756bef59f5034f717ff4f85e70ba7731a49971415b6a7e7d816ab434b9f17a3095ede6fd432be2bfa82724045dda0dfff7a0281e9000939ccba3d8ab3245139c441648c76a6536127e4d1ef0df1531883ab78c8b41323617ad8db03d9908c9e08a9f7321c45051b3c94213347b11c4a84491de7a7be68701e47d7f0e0b33e767bef17694e4d33244ed92ebd74c85ab6c84441cddc14331e6ae8bd23674bda27f09c050d88f7d430feee7f15a72a24d653bb6bec54491b98362ce131d37c7d78a3f9a893db5abdccd6663593b88bc6c97f07f8eafccfd25e8180d918efbcd95bbf3da29f081e3e1932095939198e2a155b2d803a3e84ca4f34569df695c259faf3c0d8f0cd217ebd2dbad542b32fbb54e44aaf0b5dc739fafef2e46db8d68bfc35f44f038cb1f5231a1b5b134ae683e7f3297cc7a95bd191b310f68201450797fe3293cde1672dfeca4b493f53c768ea048a972a4cd84d39ef682957b8f28ba29487b4689b43fec2655823d9bb99ffcf31490366a9860a5d5b8e32a3b8bfeb6f55f88fb80c8c0142086f220e1f6f2862dabda58c3b6f5faa805b39cfac4b6d7ea7acdf1b0690063b0c1ea38c7c4755189966dc631055f153f71b77b114fa5c309316ba512330ea5cdb0bb176001e57461563d17259f35d0c30ef5ac838c0325402bab52c531469526ae3ee6293f7b5769d27e69fa81cd25a31cd095b126e70c57ac3169a5f585a11f1748d9d22f2564911c26a24b2153a78f3a06822f5f1963f237abeb48efd9a9cd478de579c5a0ba84d00e96fbde36d8ce20e7e948547fb6850834ff79d211830f6ee973359781d9d5008fb43a89354782fde4158177f5206ce1d38c889e99e4bb5b4ab34d6a05c42f5d719ea03dbc54adba75a3bb44a3c08c7556462f8c5b7c568a69242cf5be6098eba0a2249c1ca5b2109b6404a962abc1c159c6b48a79fb97e4a3337d99323746221297423f9bd1b12e78489e01e6a10f0fd6bba1cfd6ae1b75dbe69f8b8ee51a4e7f68ba2c407c9c0bad3892b29b0170ab75836fdd49a7ee3c2bb30f2c3d226bcec49140952170b0d160f97b30b7b7b096719538677ebb06922f26925227c8852acc107a8f173b38d96697584bd3dfe169b4073aa58a7bf371d5c4bb0eed30f08212defb3aec902d4546084176bf0f86d93cf36a4689a5e874b32d6b7d3c1e3fbcfd988c35dbc9a8d0a019ad6d7e15ec3ac97125db6abfe00beffe35a81666699a91e15945c62d646690b5b52de8b835ee9be53588fde5d63023b52b2b1f4610c237a829f5901a46042963cce7b85aa040adde02985e14e23c4eadb75221c607d24672e244c66c9c24c3cb7fd90bb23295c9d3d9da516bce3dd462d6660f9f91ef0618a4d4d3d6668c5d1e2e8ed433ebfe0762beb743324e11608f8b14b69ce4c221c1654ba4992a5af2d949c2939f95d1c8fb767af2a843cc7c78f57259d5c0c6ca83fca41ef5ecc4eeeea93e4518c24d3040f2cd90df3e535e989e606fa109e2c453ed7353db1cdb27137f005f9dd8d2aebfb7255a6098b690215e100cfe44ca0f2745fced48322bc9667ab16d2e1c0ff491b96a17b833d4fd44d31c2230ac835796e063ab03000f04f15c70560033763a48552cceaacade9ca5c8055f3745e179068a287183f2bc3ef6327dec5ac7cf7b052ef5a8873e697efde089688f43be464827c2fa83eb531b3674145e95c699c82990e684967dad319d9f64ab16cd9fe9b6c41232ac4ae3795fd8a76aa9b02e970242061c6da45a2af74ad9cb2a79935c92625e242f4bc7fce54d5c10a9e61f875162fa651b66057ba036f062d6d39d0502b93a5640b78c6c2fd20b02ff83676a87a94945d476c349803ea4fe60cdcea65bb2629e2bc09d4472ec63422dee2052f098deaf5531e6c9bed6672a8b699802efe0cded80c8455f585d1ba633d281f1a21adab48e63b44e0c2a4d7608cf98aabf8adc86bcb8f61e8b06cd2385f82e0a3cdd03cab152d5951859c4532f9168e78f17ba2a5772780327dcf4e62b4d26e443762fc488ae4cd4d1156dbd5782595cfd7697a514abc9b160c9ccf08edc86134a755b90e9bb543511e888e3157721a52d1bc5db33029fb335ea2114e21c03368c8d7f4d827960641772a4a32a738df60d19ec77ab09d22f57cc2523b9503b3f5b1cebc5ae15f885f159842db7359a1c89d3d82d3407068f15b6739626eb8c521fc8c5c7491f945d49f14e6989da340bdf49e7f8a792747aa658bc114143ba93f26022d001735b744639bbf22aab2a1851cfc934f9c69d3764fdea3d23db17998e6138cfd7cd9e9a47cb74193bd71aaf28cdd9d1eb595125546a4f4357ebbd1f410e3bf8557892de68509b5b98c5c229e942c910fdd3e54cb6ad54d8dd886cb97ecc06d1e401b8395d0bcb0db9a031dc66c9294f9053c68fc42042b1fa1671fc7d510b70916c0139cfebe3a91244527ce9439860cedb30908197be851cbd1d3b18ca541358449fb34fb5cd569630ed5f67b8795e87828f2ce3becfe457579d82333b0bbab094de391e1f8157bd431e365ca864630932bbebb48f45f8134424e18ab455029b54b19e2f3bfec5e44ad0ea5c03f53d8f925b635838aa7015a7c9e325bdfaff966ea9512dd50f87c8995cea7561c23f4fb06d964ab8f1913a6ca17e4ca60d6bc078e1784f89c673c91d955bcf45f58ca9709579d5e3831df12cfdb7516fd21878cb54243579b9346d2de4be25f508e84b1adc78cb91c03da3c4fd59e4529189838f74f6312820620a5996b791ffcb332f847094613f2148b862034fa89d0d0ff1808d902c5d1af64d5522492d61ecde4c73be89a33782cef1acc1dc327fb2eb9d17642209b85aa8b1dc57cbf067c7aa29da6b7e157d23e171d3ae6f3855834071791402c851ff2dd67109979f7ee5e09e64b4eefdee7112b55ce200bb8c8051e3428c305fa1d576bffbb25a70eb571168fc60dadd928b10cfd07de80a85b8df3edc372d488c21f0d5787611cc6fb73aeeb6f920a109294b49d3870f90de3b360d14df77ef95640bcac7a4dbca901a31db83e83f5c59ce327207ea9b27c3b978d30d53865c1b84764f025e8732d5007554ce5c9cc410b2eefd7e4d990c538557606a6bc47577a43768d30aa3e8598fd6f4fe7ac439f3931c58fd69d90765ac9f456ac7de085e14a0898c4557f5d3baaae07edc607de6900146b97b35aae570153dc107815ef9febdd4fd567d637fee8f8bfb4b3413ea6aead4846ab733a04f1e4bc32a3bbb1c16baf8d0bdb9ccb82fe46479ccfd040b5e64064e539b39c66e4501dc822873ac6119a4a112a1f7cd6df0e5f84356ce853ced34ce69a9e7383534983c51c50269bf8b9586a0e5ba905fd3bce080b00e7f7d48e55f489479b5771e995fb020e58feb74af65c3ee76aa4e69b5ba8bda249a1b2d62c08d418c3635d061846040843991ab475473da85d94981fb84425e7ad951ce0a42be642fe658b7aaae72b147cdc086c24b1571eb2272e2a72b15660d854ebe19ec7d9ab7ea17800d0b6ae727b39217467c662ba08e6f19193951eeff02806a7843eb5c71b2f04dcb605ecedc5128cd67703038c44bf20fe06f3ed8c1368fe38e72944d5c52fca46a45fd48d8fe5da64183d4d62ec01aa3d9d672ec67a01c17f21e02525f0513cce030c664fc8784763086608bc8099c204c255ffed1daf432ceb45fbd135e21e8190c5bfee192171faa77520481e69e87b7f76790bef76cb8d3c88f5c6e32fc59e7bd45351d66696b61d9f40726fb9a98000b68738cf7e34b98b6a4aaa2ac1d7b1407db89783f8077103ea9c9e89247eae078adfb36e21474c3bb1fe0c87687c6233a533a01e1081b93a3521d339f39c075609bace531994988ae314f77fc6034113a138c67eb7e03750cbec8d28bd21afedfefa8f091619ae500b4ca4599d019dc8ca4bf118d70b8676dfc796a4f6d986adba4c8574ed4abaea5465466220e5e53dc8fcb395d1e59d278673cbc4e3f40658df98ac2fd126a94922879e1a3be91c1acc20803c35fa764abbadab07bde85ff4bd9e0fb6f06baf5bf42b8a2cbf6c2f62606becc361552921a12d6c8236fde84db4bddac77e8872478cffc4e148c1c7acfedf6b17d98731c2de36f3cbef1f6f781a940e0874d5b74535bbe066b53064d43b13926570a9e1c4e6da206c8bd252caf2b62e7d223f7ac12939137f330be59374d7295a6c2dff92e07c727510e48d970593e47229fc8bc3bd5b8ea780dacff4d23063df65feda5f8f65b17a333e532acad7916780c74d6a70d38b367f3f6f4e947b85fc15235bbe46b26495d2780098db853a931377cfbedea620f2355ca21e81ce9e0078b0dd6cb70f23ed558682be3b3d594eefe85344e1f275428b316cc088995939298f2a2d15ac9b676ac3e9cb92f2a64dec7732a91fc761aa1b126ea575e3953177da6e1cd78faea824665330a81d9e24572b9860bf0aba4df8bd5d4e3e2c72bbfbb2a985c7ae2f077951fe8401e1d156ecada1e353817b20f41e0b2460a0caaf2b36d6a7f1b35125d797dcc714421027d14171765a646071ed952b6a5294eecf6a3a71c104c843a4a8b3efcc27467b20cb0a94abf5802229ea4d8312783e78791a50b3c0a88fe6497198cd4bf470dac46f34e50019fdee2040cfe99124b312b1122b83e51d878877cec0855f1158c445cfdc2253f4389d5e3a8ba1669abb5976a4617e85f543da9f5e30b10ca7481c8185392782b46fb0a0e5ab408b2945e3c79a1cc49fb7c27254a9b540e7397a5b655bf7e4f83184db32a128aa2e00a624d7dcd6b77efd151f1e5cba8890af9170fa06c555715dc1787e995ad19270973ae95b88dcafdaf62c28843d3f8b9c78dc8e37d911dab3f7ee9d4c7389c654bdcfc05056b360020140e57e31473258a4081e2a708f7caba90c356d0847098fc0762484086aba898a60b023d6a3060402406240748785d51caff52a0ef3dc2a45dadf80ac18502d24422a8cbb10192b88f4e9160206b2ed3e04114f2a339df269e2c36b8613ce37087471701755330cb559575366ee0fa2d3afcda32eede6dd906345daaa04812198e96c42239c242edb90059709f497da5b87705384aef2af22dc2edfef3c00d8c9156d8b3163fe7a7779e04f04911a8b934fb3072eee844484fede5e2ee96d338eefe2da986067ffe0218ada7de1d0e42d823d6b033918278888ba0608ab8f7be997bdf263689a36f5204c802ad836363779b4b0d6ce5083df0b98a2e2c700062a4fa5e57bc73bd45357e01d90c7954bc6904d1ce8166a9168da39a60c5cae8119bb6b9ab074fb2d0aee384fc2c0e4806811d6002b4e2401e7430b50cb0e8075f33d5386aecde256e169d95e2f9c6556c08ba042e68a53ce8aca9cc02818f7382f150dc04de0019b19c7a3ab0d72d6ed013d7a115d74b279f71fd6effef34049877e0b11e0659be938a5de684eaf23513095eb4a1bdf536c3c01a4655c4b4a0673214cef29a481d06a02cc9a5bfc7b8d846c33484cd67b1de98f60b69918f177b64558ca567a6237d35ff01771a42320ce02bb98f3e4ad4ac7db75611bd9961eac662a38b1f785970c99f3dd105ff586f61301c48d66708cbf7d53a733e357b6c256e8b73f0e1305a0bc137989e521100c2ee6259e607fe12198e8bcb988b0854668e40d7cae6adc3ba40ba121b7319d06d988a073d03097b9f5c1c07284b6473ae57bf154811b77baceb0412b8a6983bdd0ccd9e3bf014e520009cb26d5780eabef1bbafa5e25d41098a54c47fce8b68d395291d54284d33aa50b9664d1510b467c8a539361ca9a4448bc01fcb4c4e3ef475e8afb46a494ae13ee9ea8a1266825fba7f32b9712fde252698a68359b50141d90f5c4a06283ddb54ad7e1412ac5ebb12501f7a82b2a7f27b2dbab626c3db4074523b3211d3182ea261397a6f7b187cf2b8a356ded10812f1d305169aedf79b5ff1cf7c2d6e86ee11f28e96aa63b5a03f59fc960ac7d0572e91dda61905c0711a9b26344a2a10aa2041f2b13cb1a9a9a27774b6d0deddc9d81ea1b142ad7b72be47991f2c9261d6708156e38d00b074020766eb0c494392d65b82ca65f7c3352f9bb78325ecb6df596c8ae57826b08ccd6f1d529d2e25925c1ac972425bedeb88a5d0e3138ddc434da3462ebdf6b1239a21f141ec62cbe4bb993ba253b55a76d30fac19c2c1384ef6b9746c07787aa1fe913a1348390bd8c1f386a08c77cf7106c927ce24dffc9d6ee1b32354d95ed2923482531de6b390bf0f5eb80276e90e7ed11131c848bbabec4d317236269a0a3a7cbe0f1272f93949ca6d23ea2a7ee3f697791aab71533423066d400000000000000000000000000000000000000000000000000000000050e181f23292c2f").unwrap();
    assert_eq!(sig.len(), MLDSA87_SIG_LEN);

    if MLDSA87::verify(&mldsa87_pk, msg, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}



fn main() {
    // bench_do_nothing();
    // bench_mldsa44_keygen();
    // bench_mldsa44_lowmem_keygen();
    // bench_mldsa65_keygen();
    // bench_mldsa65_lowmemory_keygen()
    // bench_mldsa87_keygen();
    // bench_mldsa87_lowmemory_keygen()
    // bench_mldsa44_sign();
    // bench_mldsa44_lowmemory_sign();
    // bench_mldsa65_sign();
    // bench_mldsa65_lowmemory_sign();
    // bench_mldsa87_sign();
    // bench_mldsa87_lowmemory_sign();
    // bench_mldsa44_verify();
    // bench_mldsa44_lowmemory_verify();
    // bench_mldsa65_verify();
    // bench_mldsa65_lowmemory_verify();
    // bench_mldsa87_verify();
    bench_mldsa87_lowmemory_verify();
}