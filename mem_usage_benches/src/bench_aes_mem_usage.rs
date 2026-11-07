//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aes_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aes_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! Note: print!() is used to force the compiler not to optimize away the actual code.
//! The important stuff for benchmarking goes to stderr so the junk can be piped to /dev/null.
//!
//! Main is at the bottom, and controls which of these actually runs -- measure one at a time,
//! because massif reports the peak across the whole process. The operations themselves are the
//! shared `block_cipher_mem_usage` harness over this cipher's permutations; this file holds the
//! keys and the choice.
//!
//! # What to expect, and why massif cannot see it
//!
//! Unlike ML-KEM and ML-DSA, AES has no interesting stack profile: there is no polynomial
//! arithmetic and no sampling, so a call needs a few hundred bytes -- the bit-sliced state
//! (16, 32 or 64 bytes for the one-, two- and four-block entry points), the widened round key
//! (the same again) and the S-box circuit's spills. That is below what this harness resolves:
//! the process's own start-up reaches about 7.7 kB of stack before `main` runs, every bench
//! here reports exactly that peak, and none of massif's later snapshots lands inside the cipher.
//! So the massif number is the floor, not a measurement.
//!
//! The numbers that do mean something come from the compiler's frame-layout remarks
//! (`.claude/skills/memory-hygiene-in-rust`, section 5): build this binary with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"` and read the frame of each
//! `measure` closure, which is the operation's frame with nothing else in it. The shape below
//! is what makes that reading clean: the key or engine is built in an `#[inline(never)]` helper
//! so its frame is a sibling of the operation's, and the operation runs in a non-inlined,
//! non-returning closure so nothing crosses back across the boundary. The persistent cost, the
//! engine itself, is what `print_struct_sizes` prints.
//!
//! The point of comparison is that a table-driven AES adds 256 B (`AESLightEngine`) to 8 KiB
//! (T-tables) of static data on top of these numbers; this implementation adds zero.

#![allow(dead_code)]

use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};

use mem_usage_benches::block_cipher_mem_usage as bench;

const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const KEY_192: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
];
const KEY_256: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

fn print_struct_sizes() {
    bench::print_struct_size::<AES128Internal>("AES128Internal");
    bench::print_struct_size::<AES192Internal>("AES192Internal");
    bench::print_struct_size::<AES256Internal>("AES256Internal");
}

fn main() {
    print_struct_sizes()
    // bench::do_nothing()
    // bench::all::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::key_expansion::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::encrypt_block::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::decrypt_block::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::encrypt_2blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::decrypt_2blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::encrypt_4blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::decrypt_4blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::all::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::key_expansion::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::encrypt_block::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::decrypt_block::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::encrypt_2blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::decrypt_2blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::encrypt_4blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::decrypt_4blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::all::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::key_expansion::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::encrypt_block::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::decrypt_block::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::encrypt_2blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::decrypt_2blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::encrypt_4blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::decrypt_4blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
}
