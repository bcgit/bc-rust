//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_eccdh_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_eccdh_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The crate docs' stack table is not massif's peak, which for these curves sits at the
//! process's start-up baseline: it is the deepest frame chain below each [`measure`] instance,
//! from a release build with `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"`
//! (the "N stack bytes in function" lines) and the binary's call graph (`objdump -d`, with the
//! GOT-indirect calls resolved through `readelf -rW` and `nm`), summed with a return address
//! per hop over the `bouncycastle_*` symbols; `main` calls every bench for that build so none
//! is dead-stripped.
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::agreement_key::AgreementKey;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle::eccdh::keys_common::DerivePublicKey;
use bouncycastle::eccdh::{
    keys_bp256r1, keys_bp384r1, keys_bp512r1, keys_p256, keys_p256k1, keys_p384, keys_p521,
};
use bouncycastle::rng::DefaultRNG;

/// Runs the operation under measurement out of line, so that its frames sit below one symbol
/// the stack-table method (see the crate docs) can root a call chain at.
#[inline(never)]
fn measure<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// This prints the in-memory size of all the public and private key structs, plus their on-disk
/// encoded length, for every curve.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nECC CDH P-256");
    println!("size_of<ECCDHP256PublicKey>: {}", size_of::<keys_p256::ECCDHP256PublicKey>());
    println!("PK_LEN (on disk): {}", keys_p256::PK_LEN);
    println!("size_of<ECCDHP256PrivateKey>: {}", size_of::<keys_p256::ECCDHP256PrivateKey>());
    println!("SK_LEN (on disk): {}", keys_p256::SK_LEN);

    println!("\nECC CDH P-384");
    println!("size_of<ECCDHP384PublicKey>: {}", size_of::<keys_p384::ECCDHP384PublicKey>());
    println!("PK_LEN (on disk): {}", keys_p384::PK_LEN);
    println!("size_of<ECCDHP384PrivateKey>: {}", size_of::<keys_p384::ECCDHP384PrivateKey>());
    println!("SK_LEN (on disk): {}", keys_p384::SK_LEN);

    println!("\nECC CDH P-521");
    println!("size_of<ECCDHP521PublicKey>: {}", size_of::<keys_p521::ECCDHP521PublicKey>());
    println!("PK_LEN (on disk): {}", keys_p521::PK_LEN);
    println!("size_of<ECCDHP521PrivateKey>: {}", size_of::<keys_p521::ECCDHP521PrivateKey>());
    println!("SK_LEN (on disk): {}", keys_p521::SK_LEN);

    println!("\nECC CDH secp256k1");
    println!(
        "size_of<ECCDHSecp256K1PublicKey>: {}",
        size_of::<keys_p256k1::ECCDHSecp256K1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_p256k1::PK_LEN);
    println!(
        "size_of<ECCDHSecp256K1PrivateKey>: {}",
        size_of::<keys_p256k1::ECCDHSecp256K1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_p256k1::SK_LEN);

    println!("\nECC CDH brainpoolP256r1");
    println!(
        "size_of<ECCDHBp256r1PublicKey>: {}",
        size_of::<keys_bp256r1::ECCDHBp256r1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_bp256r1::PK_LEN);
    println!(
        "size_of<ECCDHBp256r1PrivateKey>: {}",
        size_of::<keys_bp256r1::ECCDHBp256r1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_bp256r1::SK_LEN);

    println!("\nECC CDH brainpoolP384r1");
    println!(
        "size_of<ECCDHBp384r1PublicKey>: {}",
        size_of::<keys_bp384r1::ECCDHBp384r1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_bp384r1::PK_LEN);
    println!(
        "size_of<ECCDHBp384r1PrivateKey>: {}",
        size_of::<keys_bp384r1::ECCDHBp384r1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_bp384r1::SK_LEN);

    println!("\nECC CDH brainpoolP512r1");
    println!(
        "size_of<ECCDHBp512r1PublicKey>: {}",
        size_of::<keys_bp512r1::ECCDHBp512r1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_bp512r1::PK_LEN);
    println!(
        "size_of<ECCDHBp512r1PrivateKey>: {}",
        size_of::<keys_bp512r1::ECCDHBp512r1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_bp512r1::SK_LEN);
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_p256_keygen() {
    eprintln!("ECC CDH P-256/KeyGen");

    let (pk, _sk) = measure(|| keys_p256::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_p256_agree() {
    eprintln!("ECC CDH P-256/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_p256::SK_LEN];
    bytes[keys_p256::SK_LEN - 1] = 0x2A;
    let sk = keys_p256::ECCDHP256PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_p256::SK_LEN - 1] = 0x07;
    let peer_pk = keys_p256::ECCDHP256PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_p384_keygen() {
    eprintln!("ECC CDH P-384/KeyGen");

    let (pk, _sk) = measure(|| keys_p384::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_p384_agree() {
    eprintln!("ECC CDH P-384/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_p384::SK_LEN];
    bytes[keys_p384::SK_LEN - 1] = 0x2A;
    let sk = keys_p384::ECCDHP384PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_p384::SK_LEN - 1] = 0x07;
    let peer_pk = keys_p384::ECCDHP384PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_p521_keygen() {
    eprintln!("ECC CDH P-521/KeyGen");

    let (pk, _sk) = measure(|| keys_p521::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_p521_agree() {
    eprintln!("ECC CDH P-521/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_p521::SK_LEN];
    bytes[keys_p521::SK_LEN - 1] = 0x2A;
    let sk = keys_p521::ECCDHP521PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_p521::SK_LEN - 1] = 0x07;
    let peer_pk = keys_p521::ECCDHP521PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_secp256k1_keygen() {
    eprintln!("ECC CDH secp256k1/KeyGen");

    let (pk, _sk) = measure(|| keys_p256k1::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_secp256k1_agree() {
    eprintln!("ECC CDH secp256k1/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_p256k1::SK_LEN];
    bytes[keys_p256k1::SK_LEN - 1] = 0x2A;
    let sk = keys_p256k1::ECCDHSecp256K1PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_p256k1::SK_LEN - 1] = 0x07;
    let peer_pk = keys_p256k1::ECCDHSecp256K1PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_bp256r1_keygen() {
    eprintln!("ECC CDH brainpoolP256r1/KeyGen");

    let (pk, _sk) = measure(|| keys_bp256r1::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_bp256r1_agree() {
    eprintln!("ECC CDH brainpoolP256r1/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_bp256r1::SK_LEN];
    bytes[keys_bp256r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp256r1::ECCDHBp256r1PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_bp256r1::SK_LEN - 1] = 0x07;
    let peer_pk = keys_bp256r1::ECCDHBp256r1PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_bp384r1_keygen() {
    eprintln!("ECC CDH brainpoolP384r1/KeyGen");

    let (pk, _sk) = measure(|| keys_bp384r1::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_bp384r1_agree() {
    eprintln!("ECC CDH brainpoolP384r1/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_bp384r1::SK_LEN];
    bytes[keys_bp384r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp384r1::ECCDHBp384r1PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_bp384r1::SK_LEN - 1] = 0x07;
    let peer_pk = keys_bp384r1::ECCDHBp384r1PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_bp512r1_keygen() {
    eprintln!("ECC CDH brainpoolP512r1/KeyGen");

    let (pk, _sk) = measure(|| keys_bp512r1::keygen(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

fn bench_bp512r1_agree() {
    eprintln!("ECC CDH brainpoolP512r1/Agree");

    // Fixed keys, d = 42 and the peer's d = 7, so keygen's own stack cost is not folded in.
    let mut bytes = [0u8; keys_bp512r1::SK_LEN];
    bytes[keys_bp512r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp512r1::ECCDHBp512r1PrivateKey::from_bytes(&bytes).unwrap();
    bytes[keys_bp512r1::SK_LEN - 1] = 0x07;
    let peer_pk = keys_bp512r1::ECCDHBp512r1PrivateKey::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_p256_keygen()
    // bench_p256_agree()
    // bench_p384_keygen()
    // bench_p384_agree()
    // bench_p521_keygen()
    // bench_p521_agree()
    // bench_secp256k1_keygen()
    // bench_secp256k1_agree()
    // bench_bp256r1_keygen()
    // bench_bp256r1_agree()
    // bench_bp384r1_keygen()
    // bench_bp384r1_agree()
    // bench_bp512r1_keygen()
    // bench_bp512r1_agree()
}
