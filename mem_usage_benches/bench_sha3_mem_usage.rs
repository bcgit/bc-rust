//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sha3_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sha3_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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

use bouncycastle::core::traits::{Hash, XOF};
use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

/// A fixed input larger than one block for every SHA-3 variant, so a single hash call
/// exercises multiple Keccak permutations.
const INPUT: [u8; 1024] = [0xAB; 1024];

/// Number of `do_update`/`absorb` calls in the streaming benches (total absorbed = 16 KiB).
const STREAMING_ITERS: usize = 16;

/// Large XOF output size (16 KiB) — for SHAKE the interesting axis is the squeeze length.
const XOF_OUT_LEN: usize = 16 * 1024;

/// This exists so I can use /usr/bin/time to measure the base memory footprint of the harness.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// This prints the in-memory size of all the SHA-3 / SHAKE state structs.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("size_of<SHA3_224>: {}", size_of::<SHA3_224>());
    println!("size_of<SHA3_256>: {}", size_of::<SHA3_256>());
    println!("size_of<SHA3_384>: {}", size_of::<SHA3_384>());
    println!("size_of<SHA3_512>: {}", size_of::<SHA3_512>());
    println!("size_of<SHAKE128>: {}", size_of::<SHAKE128>());
    println!("size_of<SHAKE256>: {}", size_of::<SHAKE256>());
}

fn bench_sha3_224_oneshot() {
    eprintln!("SHA3-224/OneShot");

    let mut digest = [0u8; 28];
    SHA3_224::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_224_streaming() {
    eprintln!("SHA3-224/Streaming");

    let mut digest = [0u8; 28];
    let mut md = SHA3_224::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_256_oneshot() {
    eprintln!("SHA3-256/OneShot");

    let mut digest = [0u8; 32];
    SHA3_256::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_256_streaming() {
    eprintln!("SHA3-256/Streaming");

    let mut digest = [0u8; 32];
    let mut md = SHA3_256::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_384_oneshot() {
    eprintln!("SHA3-384/OneShot");

    let mut digest = [0u8; 48];
    SHA3_384::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_384_streaming() {
    eprintln!("SHA3-384/Streaming");

    let mut digest = [0u8; 48];
    let mut md = SHA3_384::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_512_oneshot() {
    eprintln!("SHA3-512/OneShot");

    let mut digest = [0u8; 64];
    SHA3_512::new().hash_out(&INPUT, &mut digest);
    print!("{:x?}", digest);
}

fn bench_sha3_512_streaming() {
    eprintln!("SHA3-512/Streaming");

    let mut digest = [0u8; 64];
    let mut md = SHA3_512::new();
    for _ in 0..STREAMING_ITERS {
        md.do_update(&INPUT);
    }
    md.do_final_out(&mut digest);
    print!("{:x?}", digest);
}

fn bench_shake128_oneshot() {
    eprintln!("SHAKE128/OneShot");

    let mut out = vec![0u8; XOF_OUT_LEN];
    SHAKE128::new().hash_xof_out(&INPUT, &mut out);
    print!("{:x?}", &out[..32]);
}

fn bench_shake128_streaming() {
    eprintln!("SHAKE128/Streaming");

    let mut out = vec![0u8; XOF_OUT_LEN];
    let mut xof = SHAKE128::new();
    for _ in 0..STREAMING_ITERS {
        xof.absorb(&INPUT);
    }
    xof.squeeze_out(&mut out);
    print!("{:x?}", &out[..32]);
}

fn bench_shake256_oneshot() {
    eprintln!("SHAKE256/OneShot");

    let mut out = vec![0u8; XOF_OUT_LEN];
    SHAKE256::new().hash_xof_out(&INPUT, &mut out);
    print!("{:x?}", &out[..32]);
}

fn bench_shake256_streaming() {
    eprintln!("SHAKE256/Streaming");

    let mut out = vec![0u8; XOF_OUT_LEN];
    let mut xof = SHAKE256::new();
    for _ in 0..STREAMING_ITERS {
        xof.absorb(&INPUT);
    }
    xof.squeeze_out(&mut out);
    print!("{:x?}", &out[..32]);
}

fn main() {
    // print_struct_sizes()
    bench_do_nothing()
    // bench_sha3_224_oneshot()
    // bench_sha3_224_streaming()
    // bench_sha3_256_oneshot()
    // bench_sha3_256_streaming()
    // bench_sha3_384_oneshot()
    // bench_sha3_384_streaming()
    // bench_sha3_512_oneshot()
    // bench_sha3_512_streaming()
    // bench_shake128_oneshot()
    // bench_shake128_streaming()
    // bench_shake256_oneshot()
    // bench_shake256_streaming()
}
