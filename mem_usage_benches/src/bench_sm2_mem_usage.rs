//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sm2_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sm2_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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

use bouncycastle::core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle::sm2::keys::{PK_LEN, SK_LEN, SM2PrivateKey, SM2PublicKey, keygen};
use bouncycastle::sm2::sm2::SM2;

/// A fixed message, reused across the sign/verify benches.
const MSG: &[u8] = b"peak stack usage of SM2 sign/verify, held constant across runs";

/// SM2 requires `ctx` to carry the signer's identity `IDA`; this is a fixed placeholder, not a
/// crate-provided default (the crate has none -- see `bouncycastle_sm2::sm2`'s docs).
const ID: &[u8] = b"1234567812345678";

/// This prints the in-memory size of the public and private key structs, plus their on-disk
/// encoded length.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nSM2");
    println!("size_of<SM2PublicKey>: {}", size_of::<SM2PublicKey>());
    println!("PK_LEN (on disk): {}", PK_LEN);
    println!("size_of<SM2PrivateKey>: {}", size_of::<SM2PrivateKey>());
    println!("SK_LEN (on disk): {}", SK_LEN);
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_sm2_keygen() {
    eprintln!("SM2/KeyGen");

    let (pk, _sk) = keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_sm2_sign() {
    eprintln!("SM2/Sign");

    // dA = 42, well within [1, n-1] -- same fixed-key trick the crate's own tests use, so
    // keygen's own stack cost is not folded into this measurement.
    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    let sk = SM2PrivateKey::from_bytes(&bytes).unwrap();

    let sig = SM2::sign(&sk, MSG, Some(ID)).unwrap();
    println!("{:x?}", sig);
}

fn bench_sm2_verify() {
    eprintln!("SM2/Verify");

    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    let sk = SM2PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = SM2::sign(&sk, MSG, Some(ID)).unwrap();

    if SM2::verify(&pk, MSG, Some(ID), &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sm2_keygen()
    // bench_sm2_sign()
    // bench_sm2_verify()
}
