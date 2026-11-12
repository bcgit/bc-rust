//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ecdsa_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ecdsa_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
use bouncycastle::core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle::ec::curve::Curve;
use bouncycastle::ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle::ecdsa::ecdsa::EcdsaHash;
use bouncycastle::ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey, keygen};
use bouncycastle::ecdsa::keys_common::DerivePublicKey;
use bouncycastle::rng::DefaultRNG;
use bouncycastle::sha2::{SHA256, SHA384, SHA512};

/// A fixed message, reused across every curve's sign/verify bench so peak stack usage reflects
/// only the signature algorithm, not message size.
const MSG: &[u8] = b"peak stack usage of ECDSA sign/verify, held constant across every curve";

/// The in-memory size of a curve's key structs, plus their on-disk encoded length.
fn print_sizes<C: Curve, H: EcdsaHash>(name: &str) {
    use core::mem::size_of;

    println!("\nECDSA {name}");
    println!("size_of<ECDSAPublicKey<{}>>: {}", C::NAME, size_of::<ECDSAPublicKey<C, H>>());
    println!("PK_LEN (on disk): {}", C::PK_UNCOMPRESSED_LEN);
    println!("size_of<ECDSAPrivateKey<{}>>: {}", C::NAME, size_of::<ECDSAPrivateKey<C, H>>());
    println!("SK_LEN (on disk): {}", C::SCALAR_LEN);
}

/// This prints the in-memory size of all the public and private key structs, plus their on-disk
/// encoded length, for every curve.
fn print_struct_sizes() {
    print_sizes::<P256, SHA256>("P-256");
    print_sizes::<P384, SHA384>("P-384");
    print_sizes::<P521, SHA512>("P-521");
    print_sizes::<Secp256K1, SHA256>("secp256k1");
    print_sizes::<Bp256r1, SHA256>("brainpoolP256r1");
    print_sizes::<Bp384r1, SHA384>("brainpoolP384r1");
    print_sizes::<Bp512r1, SHA512>("brainpoolP512r1");
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// d = 42, well within [1, n-1]: the same fixed-key trick the crate's own tests use, so keygen's
/// own stack cost is not folded into a sign or verify measurement.
fn fixed_key<C, H, const SK_LEN: usize>() -> ECDSAPrivateKey<C, H>
where
    C: Curve<ScalarBytes = [u8; SK_LEN]>,
    H: EcdsaHash,
{
    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    ECDSAPrivateKey::<C, H>::from_bytes(&bytes).unwrap()
}

fn keygen_bench<C, H, const PK_LEN: usize>(name: &str)
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
    H: EcdsaHash,
{
    eprintln!("ECDSA {name}/KeyGen");

    let (pk, _sk) = keygen::<C, H>(&mut DefaultRNG::default()).unwrap();
    println!("{:x?}", pk.encode());
}

fn sign_bench<C, H, const SK_LEN: usize, const SIG_LEN: usize>(name: &str)
where
    C: Curve<ScalarBytes = [u8; SK_LEN], Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    eprintln!("ECDSA {name}/Sign");

    let sk = fixed_key::<C, H, SK_LEN>();
    let sig = sk.sign(&mut DefaultRNG::default(), MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn sign_deterministic_bench<C, H, const SK_LEN: usize, const SIG_LEN: usize>(name: &str)
where
    C: Curve<ScalarBytes = [u8; SK_LEN], Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    eprintln!("ECDetDSA {name}/Sign");

    let sk = fixed_key::<C, H, SK_LEN>();
    let sig = sk.sign_deterministic(MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn verify_bench<C, H, const PK_LEN: usize, const SK_LEN: usize, const SIG_LEN: usize>(name: &str)
where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN], Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    eprintln!("ECDSA {name}/Verify");

    let sk = fixed_key::<C, H, SK_LEN>();
    let pk = sk.derive_pk();
    let sig = sk.sign(&mut DefaultRNG::default(), MSG, None).unwrap();

    if pk.verify(MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_p256_keygen() {
    keygen_bench::<P256, SHA256, 65>("P-256");
}

fn bench_p256_sign() {
    sign_bench::<P256, SHA256, 32, 64>("P-256");
}

fn bench_p256_sign_deterministic() {
    sign_deterministic_bench::<P256, SHA256, 32, 64>("P-256");
}

fn bench_p256_verify() {
    verify_bench::<P256, SHA256, 65, 32, 64>("P-256");
}

fn bench_p384_keygen() {
    keygen_bench::<P384, SHA384, 97>("P-384");
}

fn bench_p384_sign() {
    sign_bench::<P384, SHA384, 48, 96>("P-384");
}

fn bench_p384_sign_deterministic() {
    sign_deterministic_bench::<P384, SHA384, 48, 96>("P-384");
}

fn bench_p384_verify() {
    verify_bench::<P384, SHA384, 97, 48, 96>("P-384");
}

fn bench_p521_keygen() {
    keygen_bench::<P521, SHA512, 133>("P-521");
}

fn bench_p521_sign() {
    sign_bench::<P521, SHA512, 66, 132>("P-521");
}

fn bench_p521_sign_deterministic() {
    sign_deterministic_bench::<P521, SHA512, 66, 132>("P-521");
}

fn bench_p521_verify() {
    verify_bench::<P521, SHA512, 133, 66, 132>("P-521");
}

fn bench_secp256k1_keygen() {
    keygen_bench::<Secp256K1, SHA256, 65>("secp256k1");
}

fn bench_secp256k1_sign() {
    sign_bench::<Secp256K1, SHA256, 32, 64>("secp256k1");
}

fn bench_secp256k1_sign_deterministic() {
    sign_deterministic_bench::<Secp256K1, SHA256, 32, 64>("secp256k1");
}

fn bench_secp256k1_verify() {
    verify_bench::<Secp256K1, SHA256, 65, 32, 64>("secp256k1");
}

fn bench_bp256r1_keygen() {
    keygen_bench::<Bp256r1, SHA256, 65>("brainpoolP256r1");
}

fn bench_bp256r1_sign() {
    sign_bench::<Bp256r1, SHA256, 32, 64>("brainpoolP256r1");
}

fn bench_bp256r1_sign_deterministic() {
    sign_deterministic_bench::<Bp256r1, SHA256, 32, 64>("brainpoolP256r1");
}

fn bench_bp256r1_verify() {
    verify_bench::<Bp256r1, SHA256, 65, 32, 64>("brainpoolP256r1");
}

fn bench_bp384r1_keygen() {
    keygen_bench::<Bp384r1, SHA384, 97>("brainpoolP384r1");
}

fn bench_bp384r1_sign() {
    sign_bench::<Bp384r1, SHA384, 48, 96>("brainpoolP384r1");
}

fn bench_bp384r1_sign_deterministic() {
    sign_deterministic_bench::<Bp384r1, SHA384, 48, 96>("brainpoolP384r1");
}

fn bench_bp384r1_verify() {
    verify_bench::<Bp384r1, SHA384, 97, 48, 96>("brainpoolP384r1");
}

fn bench_bp512r1_keygen() {
    keygen_bench::<Bp512r1, SHA512, 129>("brainpoolP512r1");
}

fn bench_bp512r1_sign() {
    sign_bench::<Bp512r1, SHA512, 64, 128>("brainpoolP512r1");
}

fn bench_bp512r1_sign_deterministic() {
    sign_deterministic_bench::<Bp512r1, SHA512, 64, 128>("brainpoolP512r1");
}

fn bench_bp512r1_verify() {
    verify_bench::<Bp512r1, SHA512, 129, 64, 128>("brainpoolP512r1");
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_p256_keygen()
    // bench_p256_sign()
    // bench_p256_sign_deterministic()
    // bench_p256_verify()
    // bench_p384_keygen()
    // bench_p384_sign()
    // bench_p384_sign_deterministic()
    // bench_p384_verify()
    // bench_p521_keygen()
    // bench_p521_sign()
    // bench_p521_sign_deterministic()
    // bench_p521_verify()
    // bench_secp256k1_keygen()
    // bench_secp256k1_sign()
    // bench_secp256k1_sign_deterministic()
    // bench_secp256k1_verify()
    // bench_bp256r1_keygen()
    // bench_bp256r1_sign()
    // bench_bp256r1_sign_deterministic()
    // bench_bp256r1_verify()
    // bench_bp384r1_keygen()
    // bench_bp384r1_sign()
    // bench_bp384r1_sign_deterministic()
    // bench_bp384r1_verify()
    // bench_bp512r1_keygen()
    // bench_bp512r1_sign()
    // bench_bp512r1_sign_deterministic()
    // bench_bp512r1_verify()
}
