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
use bouncycastle::ec::curve::Curve;
use bouncycastle::ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle::eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey, keygen};
use bouncycastle::eccdh::keys_common::DerivePublicKey;
use bouncycastle::rng::DefaultRNG;

/// Runs the operation under measurement out of line, so that its frames sit below one symbol
/// the stack-table method (see the crate docs) can root a call chain at.
#[inline(never)]
fn measure<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// The in-memory size of a curve's key structs, plus their on-disk encoded length.
fn print_sizes<C: Curve>(name: &str) {
    use core::mem::size_of;

    println!("\nECC CDH {name}");
    println!("size_of<ECCDHPublicKey<{}>>: {}", C::NAME, size_of::<ECCDHPublicKey<C>>());
    println!("PK_LEN (on disk): {}", C::PK_UNCOMPRESSED_LEN);
    println!("size_of<ECCDHPrivateKey<{}>>: {}", C::NAME, size_of::<ECCDHPrivateKey<C>>());
    println!("SK_LEN (on disk): {}", C::SCALAR_LEN);
}

/// This prints the in-memory size of all the public and private key structs, plus their on-disk
/// encoded length, for every curve.
fn print_struct_sizes() {
    print_sizes::<P256>("P-256");
    print_sizes::<P384>("P-384");
    print_sizes::<P521>("P-521");
    print_sizes::<Secp256K1>("secp256k1");
    print_sizes::<Bp256r1>("brainpoolP256r1");
    print_sizes::<Bp384r1>("brainpoolP384r1");
    print_sizes::<Bp512r1>("brainpoolP512r1");
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Key generation on one curve; the figure excludes the caller's RNG, reached through `dyn RNG`.
fn keygen_bench<C, const PK_LEN: usize>(name: &str)
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
{
    eprintln!("ECC CDH {name}/KeyGen");

    let (pk, _sk) = measure(|| keygen::<C>(&mut DefaultRNG::default()).unwrap());
    println!("{:x?}", pk.encode());
}

/// Agreement on one curve, with fixed keys, d = 42 and the peer's d = 7, so keygen's own stack
/// cost is not folded in.
fn agree_bench<C, const PK_LEN: usize, const SK_LEN: usize, const SS_LEN: usize>(name: &str)
where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN], FeBytes = [u8; SS_LEN]>,
{
    eprintln!("ECC CDH {name}/Agree");

    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    let sk = ECCDHPrivateKey::<C>::from_bytes(&bytes).unwrap();
    bytes[SK_LEN - 1] = 0x07;
    let peer_pk = ECCDHPrivateKey::<C>::from_bytes(&bytes).unwrap().derive_pk();

    let z = measure(|| sk.agree(&peer_pk, ()).unwrap());
    println!("{:x?}", z.ref_to_bytes());
}

fn bench_p256_keygen() {
    keygen_bench::<P256, 65>("P-256");
}

fn bench_p256_agree() {
    agree_bench::<P256, 65, 32, 32>("P-256");
}

fn bench_p384_keygen() {
    keygen_bench::<P384, 97>("P-384");
}

fn bench_p384_agree() {
    agree_bench::<P384, 97, 48, 48>("P-384");
}

fn bench_p521_keygen() {
    keygen_bench::<P521, 133>("P-521");
}

fn bench_p521_agree() {
    agree_bench::<P521, 133, 66, 66>("P-521");
}

fn bench_secp256k1_keygen() {
    keygen_bench::<Secp256K1, 65>("secp256k1");
}

fn bench_secp256k1_agree() {
    agree_bench::<Secp256K1, 65, 32, 32>("secp256k1");
}

fn bench_bp256r1_keygen() {
    keygen_bench::<Bp256r1, 65>("brainpoolP256r1");
}

fn bench_bp256r1_agree() {
    agree_bench::<Bp256r1, 65, 32, 32>("brainpoolP256r1");
}

fn bench_bp384r1_keygen() {
    keygen_bench::<Bp384r1, 97>("brainpoolP384r1");
}

fn bench_bp384r1_agree() {
    agree_bench::<Bp384r1, 97, 48, 48>("brainpoolP384r1");
}

fn bench_bp512r1_keygen() {
    keygen_bench::<Bp512r1, 129>("brainpoolP512r1");
}

fn bench_bp512r1_agree() {
    agree_bench::<Bp512r1, 129, 64, 64>("brainpoolP512r1");
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
