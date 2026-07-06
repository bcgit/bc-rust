//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_hashdrbg_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_hashdrbg_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//!
//! Make sure you build in release mode!
//!
//! Note: I'm using print!() to force the compiler not to optimize away the actual code.
//! I'm printing the important stuff for benchmarking to stderr so that I can pipe the junk to /dev/null
//! (I'm not doing it the other way because /usr/bin/time prints its useful stuff to stderr as well)
//!
//! This exercises the HashDRBG (SP 800-90A) implementation from the `rng` crate. We seed from
//! fixed dummy entropy (NOT from the OS) so the run is deterministic and reproducible under massif.
//!
//! Main is at the bottom, controls which this was actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::key_material::{KeyMaterial0, KeyMaterial256, KeyMaterial512, KeyType};
use bouncycastle::core::traits::{RNG, SecurityStrength};
use bouncycastle::rng::{HashDRBG_SHA256, HashDRBG_SHA512, Sp80090ADrbg};

/// Fixed dummy entropy for seeding. HashDRBG-SHA256 needs 32 bytes (128-bit strength);
/// HashDRBG-SHA512 needs 64 bytes (256-bit strength). We take the prefix we need.
const DUMMY_SEED: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

/// This exists so I can use /usr/bin/time to measure the base memory footprint of the harness.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// This prints the in-memory size of the DRBG state structs.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("size_of<HashDRBG_SHA256>: {}", size_of::<HashDRBG_SHA256>());
    println!("size_of<HashDRBG_SHA512>: {}", size_of::<HashDRBG_SHA512>());
}

fn bench_hashdrbg_sha256_generate() {
    eprintln!("HashDRBG-SHA256/Generate");

    let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
    let mut rng = HashDRBG_SHA256::new_unititialized();
    rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();

    let mut out = [0u8; 32];
    rng.generate_out(&[], &mut out).unwrap();
    print!("{:x?}", out);
}

fn bench_hashdrbg_sha512_generate() {
    eprintln!("HashDRBG-SHA512/Generate");

    let seed = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED, KeyType::Seed).unwrap();
    let mut rng = HashDRBG_SHA512::new_unititialized();
    rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_256bit).unwrap();

    let mut out = [0u8; 32];
    rng.generate_out(&[], &mut out).unwrap();
    print!("{:x?}", out);
}

fn main() {
    // bench_do_nothing()
    print_struct_sizes()
    // bench_hashdrbg_sha256_generate()
    // bench_hashdrbg_sha512_generate()
}
