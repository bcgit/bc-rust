//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_blake3_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_blake3_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run. `print_struct_sizes()` is the source of
//! the numbers in the "Memory Usage" table in the bouncycastle-blake3 crate docs.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::blake3::{
    BLAKE3, BLAKE3KeyedHash, BLAKE3KeyedHashKey, BLAKE3KeyedSqueezer, BLAKE3Squeezer,
    SUSPENDED_BLAKE3_KEYED_HASH_STATE_LEN, SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN,
    SUSPENDED_BLAKE3_STATE_LEN,
};
use bouncycastle::core::key_material::{KeyMaterial256, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::{Hash, MAC, Suspendable, XOF, XOFSqueezer};

/// A 4 KiB message: four 1 KiB chunks, so the CV stack is pushed and merged (BLAKE3 spec s. 5.1.2).
const MSG: [u8; 4096] = [0xA5; 4096];

/// This prints the in-memory size of all the hasher / squeezer objects and the suspended states.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nBLAKE3");
    println!("size_of<BLAKE3>: {}", size_of::<BLAKE3>());
    println!("size_of<BLAKE3KeyedHash>: {}", size_of::<BLAKE3KeyedHash>());
    println!("size_of<BLAKE3KeyedHashKey>: {}", size_of::<BLAKE3KeyedHashKey>());
    println!("size_of<BLAKE3Squeezer>: {}", size_of::<BLAKE3Squeezer>());
    println!("size_of<BLAKE3KeyedSqueezer>: {}", size_of::<BLAKE3KeyedSqueezer>());
    println!("SUSPENDED_BLAKE3_STATE_LEN: {}", SUSPENDED_BLAKE3_STATE_LEN);
    println!("SUSPENDED_BLAKE3_KEYED_HASH_STATE_LEN: {}", SUSPENDED_BLAKE3_KEYED_HASH_STATE_LEN);
    println!("SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN: {}", SUSPENDED_BLAKE3_SQUEEZER_STATE_LEN);
}

fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_blake3_hash() {
    eprintln!("BLAKE3/hash");

    let mut out = [0u8; 32];
    BLAKE3::new().hash_out(&MSG, &mut out);
    println!("{:x?}", out);
}

fn bench_blake3_streaming() {
    eprintln!("BLAKE3/do_update+do_final_out");

    let mut h = BLAKE3::new();
    for chunk in MSG.chunks(100) {
        h.do_update(chunk);
    }
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake3_xof() {
    eprintln!("BLAKE3/absorb+squeeze_out");

    let mut x = BLAKE3::new();
    x.do_update(&MSG);
    let mut out = [0u8; 512];
    let mut x = x.into_squeezer();
    x.do_output_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake3_keyed_hash() {
    eprintln!("BLAKE3-KeyedHash/mac_out");

    let key = KeyMaterial256::from_bytes_as_type(&[0x0Bu8; 32], KeyType::MACKey)
        .expect("a 32-byte MAC key");
    let mac_key =
        BLAKE3KeyedHashKey::from_key_material_allow_weak(&key).expect("a 32-byte MAC key");
    let mut out = [0u8; 32];
    mac_key.create_generator().mac_out(&MSG, &mut out).expect("a 32-byte output buffer");
    println!("{:x?}", out);
}

fn bench_blake3_keyed_hash_xof() {
    eprintln!("BLAKE3-KeyedHash/absorb+into_squeezer+squeeze_out");

    let key = KeyMaterial256::from_bytes_as_type(&[0x0Bu8; 32], KeyType::MACKey)
        .expect("a 32-byte MAC key");
    let mac_key =
        BLAKE3KeyedHashKey::from_key_material_allow_weak(&key).expect("a 32-byte MAC key");
    let mut mac = mac_key.create_generator();
    mac.do_update(&MSG);
    let mut out = [0u8; 512];
    mac.into_squeezer().do_output_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake3_derive_key() {
    eprintln!("BLAKE3/new_derive_key+hash");

    let mut out = [0u8; 32];
    BLAKE3::new_derive_key(b"bc-rust 2026-10-22 mem_usage_benches example context")
        .hash_out(&MSG[..32], &mut out);
    println!("{:x?}", out);
}

fn bench_blake3_suspend_resume() {
    eprintln!("BLAKE3/suspend+from_suspended");

    let mut h = BLAKE3::new();
    h.do_update(&MSG[..2500]);
    let state = h.suspend();
    let mut h = BLAKE3::from_suspended(state).expect("round-trip of a freshly suspended state");
    h.do_update(&MSG[2500..]);
    let mut out = [0u8; 32];
    h.do_final_out(&mut out);
    println!("{:x?}", out);
}

fn bench_blake3_squeezer_suspend_resume() {
    eprintln!("BLAKE3Squeezer/suspend+from_suspended");

    let mut h = BLAKE3::new();
    h.do_update(&MSG);
    let mut s = h.into_squeezer();
    let mut out = [0u8; 100];
    s.do_output_out(&mut out);
    let state = s.suspend();
    let mut s =
        BLAKE3Squeezer::from_suspended(state).expect("round-trip of a freshly suspended state");
    s.do_output_out(&mut out);
    println!("{:x?}", out);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_blake3_hash()
    // bench_blake3_streaming()
    // bench_blake3_xof()
    // bench_blake3_keyed_hash()
    // bench_blake3_keyed_hash_xof()
    // bench_blake3_derive_key()
    // bench_blake3_suspend_resume()
    // bench_blake3_squeezer_suspend_resume()
}
