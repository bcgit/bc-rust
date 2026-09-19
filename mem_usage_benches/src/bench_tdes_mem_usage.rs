//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_tdes_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_tdes_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! Note: print!() is used to force the compiler not to optimize away the actual code.
//! The important stuff for benchmarking goes to stderr so the junk can be piped to /dev/null.
//!
//! Main is at the bottom, and controls which of these actually runs -- measure one at a time,
//! because massif reports the peak across the whole process.
//!
//! # What to expect
//!
//! Like AES, TDES has no interesting stack profile: peak usage is a small constant plus the key
//! schedule. The numbers worth recording in the crate docs are the persistent size of the engine
//! (three packed DEA schedules, 384 bytes) and the confirmation that per-block work is a fixed,
//! small amount of stack -- the six input planes and the 128-byte working array of the S-box
//! layer's ANF evaluation.
//!
//! The point of comparison is that a table-driven Triple DES carries 2 KiB of combined S/P tables
//! on top of its schedules; this implementation carries none.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, TDES, TDES2Key};

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of the engine, i.e. the persistent cost of holding a key schedule.
fn print_struct_sizes() {
    use core::mem::size_of;

    // Three DEA keys, sixteen round keys each, two words per round key: 3 * 16 * 2 * 4 = 384.
    println!("size_of<TDES>: {}", size_of::<TDES>());
    // Two DEA keys: 2 * 16 * 2 * 4 = 256.
    println!("size_of<TDES2Key>: {}", size_of::<TDES2Key>());
}

fn key() -> KeyMaterial<KEY_LEN> {
    // A fixed pattern whose three 8-byte components are distinct and not weak; an all-zero buffer
    // would be tagged KeyType::Zeroized and rejected.
    let mut bytes = [0u8; KEY_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_tdes_key_expansion() {
    eprintln!("TDES::new (key expansion)");

    let tdes = TDES::new(&key()).unwrap();
    print!("{tdes:?}");
}

fn bench_tdes_encrypt_block() {
    eprintln!("TDES::encrypt_block");

    let tdes = TDES::new(&key()).unwrap();
    let mut block = [0x11u8; BLOCK_LEN];
    tdes.encrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_tdes_decrypt_block() {
    eprintln!("TDES::decrypt_block");

    let tdes = TDES::new(&key()).unwrap();
    let mut block = [0x11u8; BLOCK_LEN];
    tdes.decrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_tdes_encrypt_4blocks() {
    eprintln!("TDES::encrypt_4blocks");

    let tdes = TDES::new(&key()).unwrap();
    let mut blocks = [[0x11u8; BLOCK_LEN]; 4];
    tdes.encrypt_4blocks(&mut blocks);
    print!("{blocks:x?}");
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_tdes_key_expansion()
    // bench_tdes_encrypt_block()
    // bench_tdes_decrypt_block()
    // bench_tdes_encrypt_4blocks()
}
