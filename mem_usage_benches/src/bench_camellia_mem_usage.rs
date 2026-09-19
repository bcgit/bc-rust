//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_camellia_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_camellia_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! Like AES and SM4, Camellia has no interesting stack profile: peak usage is a small constant plus
//! the subkeys. The numbers worth recording in the crate docs are what `print_struct_sizes` prints
//! -- the persistent 208 bytes (Camellia-128) or 272 bytes (Camellia-192/256) of subkeys -- and the
//! confirmation that per-call work is the four-block working state (two 64-bit halves per block,
//! 64 bytes), the eight 32-bit S-box planes (32 bytes) plus their copy during the byte rotations,
//! and circuit temporaries. There are no lookup tables; a table-driven engine adds anywhere from
//! 256 bytes to 4 KiB of tables on top of these numbers.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::camellia::{Camellia_128, Camellia_192, Camellia_256, LANES};
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

    // RFC 3713 Sec 2.2: kw1..kw4, k1..k18 and ke1..ke4 for 128-bit keys (26 x 8 bytes);
    // kw1..kw4, k1..k24 and ke1..ke6 otherwise (34 x 8 bytes).
    println!("size_of<Camellia_128>: {}", size_of::<Camellia_128>());
    println!("size_of<Camellia_192>: {}", size_of::<Camellia_192>());
    println!("size_of<Camellia_256>: {}", size_of::<Camellia_256>());
}

fn key<const KEY_LEN: usize>() -> KeyMaterial<KEY_LEN> {
    // A fixed non-zero key: an all-zero buffer would be tagged KeyType::Zeroized and rejected.
    let mut bytes = [0u8; KEY_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_camellia128_key_expansion() {
    eprintln!("Camellia_128::new (key expansion)");

    let camellia = Camellia_128::new(&key()).unwrap();
    print!("{camellia:?}");
}

fn bench_camellia256_key_expansion() {
    eprintln!("Camellia_256::new (key expansion)");

    let camellia = Camellia_256::new(&key()).unwrap();
    print!("{camellia:?}");
}

fn bench_camellia128_encrypt_block() {
    eprintln!("Camellia_128::encrypt_block");

    let camellia = Camellia_128::new(&key()).unwrap();
    let mut block = [0x11u8; 16];
    camellia.encrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_camellia256_decrypt_block() {
    eprintln!("Camellia_256::decrypt_block");

    let camellia = Camellia_256::new(&key()).unwrap();
    let mut block = [0x11u8; 16];
    camellia.decrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_camellia256_encrypt_4blocks() {
    eprintln!("Camellia_256::encrypt_4blocks");

    let camellia = Camellia_256::new(&key()).unwrap();
    let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [0x11 * (i as u8 + 1); 16]);
    camellia.encrypt_4blocks(&mut blocks);
    print!("{blocks:x?}");
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_camellia128_key_expansion()
    // bench_camellia256_key_expansion()
    // bench_camellia128_encrypt_block()
    // bench_camellia256_decrypt_block()
    // bench_camellia256_encrypt_4blocks()
}
