//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_blake2_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_blake2_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run. `print_struct_sizes()` is the source of
//! the numbers in the "Memory Usage" table in the bouncycastle-blake2 crate docs.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::blake2::{
    BLAKE2b_512, BLAKE2b_512_MAC, BLAKE2b_512_MACKey, BLAKE2s_256, BLAKE2s_256_MAC,
    BLAKE2s_256_MACKey, SUSPENDED_BLAKE2B_512_MAC_STATE_LEN, SUSPENDED_BLAKE2B_512_STATE_LEN,
    SUSPENDED_BLAKE2S_256_MAC_STATE_LEN, SUSPENDED_BLAKE2S_256_STATE_LEN,
};
use bouncycastle::core::key_material::{KeyMaterial256, KeyMaterial512, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::{Hash, MAC, Suspendable, SuspendableKeyed};

/// A 1 KiB message: 8 BLAKE2b blocks, 16 BLAKE2s blocks.
const MSG: [u8; 1024] = [0xA5; 1024];

/// This prints the in-memory size of all the hash / MAC objects and the suspended states.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nBLAKE2");
    println!("size_of<BLAKE2b_512>: {}", size_of::<BLAKE2b_512>());
    println!("size_of<BLAKE2b_512_MAC>: {}", size_of::<BLAKE2b_512_MAC>());
    println!("size_of<BLAKE2b_512_MACKey>: {}", size_of::<BLAKE2b_512_MACKey>());
    println!("size_of<BLAKE2s_256>: {}", size_of::<BLAKE2s_256>());
    println!("size_of<BLAKE2s_256_MAC>: {}", size_of::<BLAKE2s_256_MAC>());
    println!("size_of<BLAKE2s_256_MACKey>: {}", size_of::<BLAKE2s_256_MACKey>());
    println!("SUSPENDED_BLAKE2B_512_STATE_LEN: {}", SUSPENDED_BLAKE2B_512_STATE_LEN);
    println!("SUSPENDED_BLAKE2B_512_MAC_STATE_LEN: {}", SUSPENDED_BLAKE2B_512_MAC_STATE_LEN);
    println!("SUSPENDED_BLAKE2S_256_STATE_LEN: {}", SUSPENDED_BLAKE2S_256_STATE_LEN);
    println!("SUSPENDED_BLAKE2S_256_MAC_STATE_LEN: {}", SUSPENDED_BLAKE2S_256_MAC_STATE_LEN);
}

fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_blake2b_512_hash() {
    eprintln!("BLAKE2b-512/hash");

    let mut out = [0u8; 64];
    BLAKE2b_512::new().hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_blake2s_256_hash() {
    eprintln!("BLAKE2s-256/hash");

    let mut out = [0u8; 32];
    BLAKE2s_256::new().hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_blake2b_512_streaming() {
    eprintln!("BLAKE2b-512/do_update+do_final_out");

    let mut h = BLAKE2b_512::new();
    for chunk in MSG.chunks(100) {
        h.do_update(chunk);
    }
    let mut out = [0u8; 64];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake2s_256_streaming() {
    eprintln!("BLAKE2s-256/do_update+do_final_out");

    let mut h = BLAKE2s_256::new();
    for chunk in MSG.chunks(100) {
        h.do_update(chunk);
    }
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake2b_512_mac() {
    eprintln!("BLAKE2b-512-MAC/mac_out");

    let key = KeyMaterial512::from_bytes_as_type(&[0x0Bu8; 64], KeyType::MACKey)
        .expect("a 64-byte MAC key");
    let mac_key =
        BLAKE2b_512_MACKey::from_key_material_allow_weak(&key).expect("a 64-byte MAC key");
    let mut out = [0u8; 64];
    mac_key.create_generator().mac_out(&MSG, &mut out).expect("a 64-byte output buffer");
    println!("{:x?}", out);
}

fn bench_blake2s_256_mac() {
    eprintln!("BLAKE2s-256-MAC/mac_out");

    let key = KeyMaterial256::from_bytes_as_type(&[0x0Bu8; 32], KeyType::MACKey)
        .expect("a 32-byte MAC key");
    let mac_key =
        BLAKE2s_256_MACKey::from_key_material_allow_weak(&key).expect("a 32-byte MAC key");
    let mut out = [0u8; 32];
    mac_key.create_generator().mac_out(&MSG, &mut out).expect("a 32-byte output buffer");
    println!("{:x?}", out);
}

fn bench_blake2b_512_suspend_resume() {
    eprintln!("BLAKE2b-512/suspend+from_suspended");

    let mut h = BLAKE2b_512::new();
    h.do_update(&MSG[..500]);
    let state = h.suspend();
    let mut h =
        BLAKE2b_512::from_suspended(state).expect("round-trip of a freshly suspended state");
    h.do_update(&MSG[500..]);
    let mut out = [0u8; 64];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake2s_256_mac_suspend_resume() {
    eprintln!("BLAKE2s-256-MAC/suspend+from_suspended");

    let key = KeyMaterial256::from_bytes_as_type(&[0x0Bu8; 32], KeyType::MACKey)
        .expect("a 32-byte MAC key");
    let mac_key =
        BLAKE2s_256_MACKey::from_key_material_allow_weak(&key).expect("a 32-byte MAC key");
    let mut mac = mac_key.create_generator();
    mac.do_update(&MSG[..500]);
    let state = mac.suspend();
    let mut mac = BLAKE2s_256_MAC::from_suspended(state, &mac_key)
        .expect("round-trip of a freshly suspended state");
    mac.do_update(&MSG[500..]);
    let mut out = [0u8; 32];
    mac.do_final_out(&mut out).expect("a 32-byte output buffer");
    println!("{:x?}", out);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_blake2b_512_hash()
    // bench_blake2s_256_hash()
    // bench_blake2b_512_streaming()
    // bench_blake2s_256_streaming()
    // bench_blake2b_512_mac()
    // bench_blake2s_256_mac()
    // bench_blake2b_512_suspend_resume()
    // bench_blake2s_256_mac_suspend_resume()
}
