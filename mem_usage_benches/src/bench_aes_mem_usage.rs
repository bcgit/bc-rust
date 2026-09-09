//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aes_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aes_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! Unlike ML-KEM and ML-DSA, AES has no interesting stack profile: there is no polynomial
//! arithmetic and no sampling, so peak usage is a small constant plus the key schedule. The
//! numbers worth recording in the crate docs are the ones `print_struct_sizes` prints -- the
//! persistent size of each engine -- and the confirmation that per-block work is a fixed, small
//! amount of stack independent of key length.
//!
//! The point of comparison is that a table-driven AES adds 256 B (`AESLightEngine`) to 8 KiB
//! (T-tables) of static data on top of these numbers; this implementation adds zero.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each engine, i.e. the persistent cost of holding a key schedule.
fn print_struct_sizes() {
    use core::mem::size_of;

    // FIPS 197 Sec 5.2: the schedule is 4 * (Nr + 1) words, so 176 / 208 / 240 bytes. The
    // bit-sliced form is stored compressed, so bit-slicing adds nothing to these.
    println!("size_of<Aes128>: {}", size_of::<Aes128>());
    println!("size_of<Aes192>: {}", size_of::<Aes192>());
    println!("size_of<Aes256>: {}", size_of::<Aes256>());
}

fn key<const N: usize>() -> KeyMaterial<N> {
    // A fixed non-zero key: an all-zero buffer would be tagged KeyType::Zeroized and rejected.
    let mut bytes = [0u8; N];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_aes128_key_expansion() {
    eprintln!("Aes128::new (key expansion)");

    let aes = Aes128::new(&key::<16>()).unwrap();
    print!("{aes:?}");
}

fn bench_aes192_key_expansion() {
    eprintln!("Aes192::new (key expansion)");

    let aes = Aes192::new(&key::<24>()).unwrap();
    print!("{aes:?}");
}

fn bench_aes256_key_expansion() {
    eprintln!("Aes256::new (key expansion)");

    let aes = Aes256::new(&key::<32>()).unwrap();
    print!("{aes:?}");
}

fn bench_aes128_encrypt_block() {
    eprintln!("Aes128::encrypt_block");

    let aes = Aes128::new(&key::<16>()).unwrap();
    let mut block = [0x11u8; 16];
    aes.encrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_aes256_encrypt_block() {
    eprintln!("Aes256::encrypt_block");

    let aes = Aes256::new(&key::<32>()).unwrap();
    let mut block = [0x11u8; 16];
    aes.encrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_aes256_decrypt_block() {
    eprintln!("Aes256::decrypt_block");

    let aes = Aes256::new(&key::<32>()).unwrap();
    let mut block = [0x11u8; 16];
    aes.decrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_aes256_encrypt_blocks2() {
    eprintln!("Aes256::encrypt_blocks2");

    let aes = Aes256::new(&key::<32>()).unwrap();
    let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
    aes.encrypt_blocks2(&mut blocks);
    print!("{blocks:x?}");
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_aes128_key_expansion()
    // bench_aes192_key_expansion()
    // bench_aes256_key_expansion()
    // bench_aes128_encrypt_block()
    // bench_aes256_encrypt_block()
    // bench_aes256_decrypt_block()
    // bench_aes256_encrypt_blocks2()
}
