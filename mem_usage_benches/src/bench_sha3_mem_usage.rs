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
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run. `print_struct_sizes()` is the source of
//! the numbers in the "Memory Usage" table in the bouncycastle-sha3 crate docs.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::traits::{Hash, Suspendable, XOF};
use bouncycastle::sha3::{
    SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, SUSPENDED_SHA3_STATE_LEN,
};

/// A 1 KiB message so that the sponge is permuted several times.
const MSG: [u8; 1024] = [0xA5; 1024];

/// This prints the in-memory size of all the hash / XOF objects and the suspended state.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nSHA3 / SHAKE");
    println!("size_of<SHA3_224>: {}", size_of::<SHA3_224>());
    println!("size_of<SHA3_256>: {}", size_of::<SHA3_256>());
    println!("size_of<SHA3_384>: {}", size_of::<SHA3_384>());
    println!("size_of<SHA3_512>: {}", size_of::<SHA3_512>());
    println!("size_of<SHAKE128>: {}", size_of::<SHAKE128>());
    println!("size_of<SHAKE256>: {}", size_of::<SHAKE256>());
    println!("SUSPENDED_SHA3_STATE_LEN: {}", SUSPENDED_SHA3_STATE_LEN);
}

fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_sha3_256_hash() {
    eprintln!("SHA3-256/hash");

    let mut out = [0u8; 32];
    SHA3_256::new().hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_sha3_512_hash() {
    eprintln!("SHA3-512/hash");

    let mut out = [0u8; 64];
    SHA3_512::new().hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_sha3_256_streaming() {
    eprintln!("SHA3-256/do_update+do_final_out");

    let mut h = SHA3_256::new();
    for chunk in MSG.chunks(100) {
        h.do_update(chunk);
    }
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_shake128_xof() {
    eprintln!("SHAKE128/absorb+squeeze_out");

    let mut x = SHAKE128::new();
    x.absorb(&MSG).expect("absorb before squeeze is infallible");
    let mut out = [0u8; 512];
    x.squeeze_out(&mut out);
    println!("{:x?}", out);
}

fn bench_shake256_xof() {
    eprintln!("SHAKE256/absorb+squeeze_out");

    let mut x = SHAKE256::new();
    x.absorb(&MSG).expect("absorb before squeeze is infallible");
    let mut out = [0u8; 512];
    x.squeeze_out(&mut out);
    println!("{:x?}", out);
}

fn bench_sha3_256_suspend_resume() {
    eprintln!("SHA3-256/suspend+from_suspended");

    let mut h = SHA3_256::new();
    h.do_update(&MSG[..500]);
    let state = h.suspend();
    let mut h = SHA3_256::from_suspended(state).expect("round-trip of a freshly suspended state");
    h.do_update(&MSG[500..]);
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sha3_256_hash()
    // bench_sha3_512_hash()
    // bench_sha3_256_streaming()
    // bench_shake128_xof()
    // bench_shake256_xof()
    // bench_sha3_256_suspend_resume()
}
