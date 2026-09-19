//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sm4_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sm4_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! Like AES, SM4 has no interesting stack profile: peak usage is a small constant plus the round
//! keys. The number worth recording in the crate docs is what `print_struct_sizes` prints -- the
//! persistent 128 bytes of round keys -- and the confirmation that per-call work is the four-block
//! working state (64 bytes), the eight `u16` S-box planes (16 bytes) and circuit temporaries. There
//! are no lookup tables; a table-driven engine adds a 256-byte table on top of these numbers.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::sm4::{LANES, SM4};

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of the engine, i.e. the persistent cost of holding the round keys.
fn print_struct_sizes() {
    use core::mem::size_of;

    // draft-ribose-cfrg-sm4-10 Sec 7.3: 32 round keys of 32 bits, so 128 bytes.
    println!("size_of<SM4>: {}", size_of::<SM4>());
}

fn key() -> KeyMaterial<16> {
    // A fixed non-zero key: an all-zero buffer would be tagged KeyType::Zeroized and rejected.
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_sm4_key_expansion() {
    eprintln!("SM4::new (key expansion)");

    let sm4 = SM4::new(&key()).unwrap();
    print!("{sm4:?}");
}

fn bench_sm4_encrypt_block() {
    eprintln!("SM4::encrypt_block");

    let sm4 = SM4::new(&key()).unwrap();
    let mut block = [0x11u8; 16];
    sm4.encrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_sm4_decrypt_block() {
    eprintln!("SM4::decrypt_block");

    let sm4 = SM4::new(&key()).unwrap();
    let mut block = [0x11u8; 16];
    sm4.decrypt_block(&mut block);
    print!("{block:x?}");
}

fn bench_sm4_encrypt_4blocks() {
    eprintln!("SM4::encrypt_4blocks");

    let sm4 = SM4::new(&key()).unwrap();
    let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [0x11 * (i as u8 + 1); 16]);
    sm4.encrypt_4blocks(&mut blocks);
    print!("{blocks:x?}");
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sm4_key_expansion()
    // bench_sm4_encrypt_block()
    // bench_sm4_decrypt_block()
    // bench_sm4_encrypt_4blocks()
}
