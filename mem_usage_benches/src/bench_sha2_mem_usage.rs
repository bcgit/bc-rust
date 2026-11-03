//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sha2_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sha2_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run. `print_struct_sizes()` is the source of
//! the numbers in the "Memory Usage" tables in the bouncycastle-sha2 crate docs.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::key_material::{KeyMaterial256, KeyType};
use bouncycastle::core::traits::{Hash, HashOneShot, MAC, Suspendable};
use bouncycastle::hmac::HmacKey;
use bouncycastle::sha2::hmac::{HMAC_SHA256, HMAC_SHA512};
use bouncycastle::sha2::{
    SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256, SUSPENDED_SHA256_STATE_LEN,
    SUSPENDED_SHA512_STATE_LEN,
};

/// A 1 KiB message so that the compression function runs several times.
const MSG: [u8; 1024] = [0xA5; 1024];

/// This prints the in-memory size of the hash and HMAC objects and the suspended states.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nSHA-2");
    println!("size_of<SHA224>: {}", size_of::<SHA224>());
    println!("size_of<SHA256>: {}", size_of::<SHA256>());
    println!("size_of<SHA384>: {}", size_of::<SHA384>());
    println!("size_of<SHA512>: {}", size_of::<SHA512>());
    println!("size_of<SHA512_224>: {}", size_of::<SHA512_224>());
    println!("size_of<SHA512_256>: {}", size_of::<SHA512_256>());
    println!("SUSPENDED_SHA256_STATE_LEN: {}", SUSPENDED_SHA256_STATE_LEN);
    println!("SUSPENDED_SHA512_STATE_LEN: {}", SUSPENDED_SHA512_STATE_LEN);

    println!("\nHMAC-SHA-2");
    println!("size_of<HMAC_SHA256>: {}", size_of::<HMAC_SHA256>());
    println!("size_of<HmacKey<SHA256>>: {}", size_of::<HmacKey<SHA256>>());
    println!("size_of<HMAC_SHA512>: {}", size_of::<HMAC_SHA512>());
    println!("size_of<HmacKey<SHA512>>: {}", size_of::<HmacKey<SHA512>>());
}

fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_sha256_hash() {
    eprintln!("SHA-256/hash");

    let mut out = [0u8; 32];
    SHA256::hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_sha512_hash() {
    eprintln!("SHA-512/hash");

    let mut out = [0u8; 64];
    SHA512::hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_sha256_streaming() {
    eprintln!("SHA-256/do_update+do_final_out");

    let mut h = SHA256::new();
    for chunk in MSG.chunks(100) {
        h.do_update(chunk);
    }
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_sha256_suspend_resume() {
    eprintln!("SHA-256/suspend+from_suspended");

    let mut h = SHA256::new();
    h.do_update(&MSG[..500]);
    let state = h.suspend();
    let mut h = SHA256::from_suspended(state).expect("round-trip of a freshly suspended state");
    h.do_update(&MSG[500..]);
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_hmac_sha256() {
    eprintln!("HMAC-SHA-256/mac_out");

    let key = KeyMaterial256::from_bytes_as_type(&MSG[..32], KeyType::MACKey).unwrap();
    let mut out = [0u8; 32];
    HMAC_SHA256::new(&key).unwrap().mac_out(&MSG, &mut out).unwrap();
    println!("{:x?}", out);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sha256_hash()
    // bench_sha512_hash()
    // bench_sha256_streaming()
    // bench_sha256_suspend_resume()
    // bench_hmac_sha256()
}
