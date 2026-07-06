//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sha2_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sha2_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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

use bouncycastle::core::traits::Hash;
use bouncycastle::sha2::{SHA224, SHA256, SHA384, SHA512};

/// A fixed input larger than one block for every SHA-2 variant, so a single hash call
/// exercises multiple compression rounds.
const INPUT: [u8; 1024] = [0xAB; 1024];

/// Number of `do_update` calls in the streaming benches (total absorbed = 16 KiB).
const STREAMING_ITERS: usize = 16;

/// This exists so I can use /usr/bin/time to measure the base memory footprint of the harness.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// This prints the in-memory size of all the SHA-2 state structs.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("size_of<SHA224>: {}", size_of::<SHA224>());
    println!("size_of<SHA256>: {}", size_of::<SHA256>());
    println!("size_of<SHA384>: {}", size_of::<SHA384>());
    println!("size_of<SHA512>: {}", size_of::<SHA512>());
}

fn bench_sha224_oneshot() {
    eprintln!("SHA224/OneShot");

    let mut digest = [0u8; 28];
    SHA224::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha224_streaming() {
    eprintln!("SHA224/Streaming");

    let mut digest = [0u8; 28];
    let mut md = SHA224::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_sha256_oneshot() {
    eprintln!("SHA256/OneShot");

    let mut digest = [0u8; 32];
    SHA256::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha256_streaming() {
    eprintln!("SHA256/Streaming");

    let mut digest = [0u8; 32];
    let mut md = SHA256::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_sha384_oneshot() {
    eprintln!("SHA384/OneShot");

    let mut digest = [0u8; 48];
    SHA384::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha384_streaming() {
    eprintln!("SHA384/Streaming");

    let mut digest = [0u8; 48];
    let mut md = SHA384::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_sha512_oneshot() {
    eprintln!("SHA512/OneShot");

    let mut digest = [0u8; 64];
    SHA512::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha512_streaming() {
    eprintln!("SHA512/Streaming");

    let mut digest = [0u8; 64];
    let mut md = SHA512::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn main() {
    // print_struct_sizes()
    // bench_do_nothing()
    // bench_sha224_oneshot()
    // bench_sha224_streaming()
    // bench_sha256_oneshot()
    // bench_sha256_streaming()
    // bench_sha384_oneshot()
    // bench_sha384_streaming()
    bench_sha512_oneshot()
    // bench_sha512_streaming()
}
