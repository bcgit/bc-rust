//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aria_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aria_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! Like AES, SM4 and Camellia, ARIA has no interesting stack profile: peak usage is a small constant
//! plus the round keys. The numbers worth recording in the crate docs are what `print_struct_sizes`
//! prints -- the persistent 208, 240 or 272 bytes of round keys -- and the confirmation that per-call
//! work is the four-block working state (four 32-bit words per block, 64 bytes), the four class
//! words being substituted (16 bytes), the eight 16-bit S-box planes (16 bytes), one round key and
//! circuit temporaries. There are no lookup tables; a straightforward implementation adds 1 KiB of
//! S-box tables and 256 bytes of diffusion masks on top of these numbers.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::aria::{ARIA_128, ARIA_192, ARIA_256, LANES};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::traits::ElectronicCodeBook;

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each engine, i.e. the persistent cost of holding the subkeys.
fn print_struct_sizes() {
    use core::mem::size_of;

    // RFC 5794 Sec 2.2: ek1 .. ek{n+1} for n = 12, 14, 16 rounds -- 13, 15 or 17 keys of 16 bytes.
    println!("size_of<ARIA_128>: {}", size_of::<ARIA_128>());
    println!("size_of<ARIA_192>: {}", size_of::<ARIA_192>());
    println!("size_of<ARIA_256>: {}", size_of::<ARIA_256>());
}

fn key<const KEY_LEN: usize>() -> KeyMaterial<KEY_LEN> {
    // A fixed non-zero key: an all-zero buffer would be tagged KeyType::Zeroized and rejected.
    let mut bytes = [0u8; KEY_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_aria128_key_expansion() {
    eprintln!("ARIA_128::new (key expansion)");

    let aria = ARIA_128::new(&key()).unwrap();
    print!("{aria:?}");
}

fn bench_aria256_key_expansion() {
    eprintln!("ARIA_256::new (key expansion)");

    let aria = ARIA_256::new(&key()).unwrap();
    print!("{aria:?}");
}

fn bench_aria128_encrypt_block() {
    eprintln!("ARIA_128::encrypt_block");

    let aria = ARIA_128::new(&key()).unwrap();
    let mut block = [0x11u8; 16];
    aria.encrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_aria256_decrypt_block() {
    eprintln!("ARIA_256::decrypt_block");

    let aria = ARIA_256::new(&key()).unwrap();
    let mut block = [0x11u8; 16];
    aria.decrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_aria256_encrypt_4blocks() {
    eprintln!("ARIA_256::encrypt_4blocks");

    let aria = ARIA_256::new(&key()).unwrap();
    let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [0x11 * (i as u8 + 1); 16]);
    aria.encrypt_4blocks(&mut blocks);
    print!("{blocks:x?}");
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_aria128_key_expansion()
    // bench_aria256_key_expansion()
    // bench_aria128_encrypt_block()
    // bench_aria256_decrypt_block()
    // bench_aria256_encrypt_4blocks()
}
