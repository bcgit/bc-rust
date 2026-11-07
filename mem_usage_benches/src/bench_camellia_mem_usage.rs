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
//! because massif reports the peak across the whole process. The operations themselves are the
//! shared `block_cipher_mem_usage` harness over this cipher's permutations; this file holds the
//! keys and the choice.
//!
//! # What to expect, and why massif cannot see it
//!
//! Like AES, Camellia has no interesting stack profile: a call needs a few hundred bytes -- the
//! four-block working state (64 bytes), the eight `u32` S-box planes (32 bytes) plus their copy
//! during the byte rotations, and the circuit's spills -- which is below what massif resolves,
//! since the process's own start-up reaches about 7.7 kB of stack before `main` runs. So the
//! massif number is the floor, not a measurement.
//!
//! The numbers that do mean something come from the compiler's frame-layout remarks, as for
//! `bench_aes_mem_usage`: build this binary with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"`, with `main` calling every
//! bench so none is dead-stripped, and sum the deepest chain of frames below each `measure`
//! closure. The closure is not the whole cost: `encrypt_4blocks` (or the schedule's `expand`),
//! `f` and `ortho` keep their own frames under it (`objdump -d` shows the calls), each with its
//! 8-byte return address. The engine is built in an `#[inline(never)]` helper so its frame is a
//! sibling of the operation's, and the operation runs in a non-inlined, non-returning closure so
//! nothing crosses back across the boundary. The persistent cost, the subkeys, is what
//! `print_struct_sizes` prints. There are no lookup tables; a table-driven engine adds anywhere
//! from 256 bytes to 4 KiB of them on top.
//!
//! With rustc 1.97 nightly on x86-64 the frames are: closures 456 B for Camellia-128's `new`,
//! 584 B for the other two, 88 B for the one- and four-block entry points and 104 B for the
//! two-block ones; `expand` 248 B for Camellia-128 and 328 B for the other two; `encrypt_4blocks`
//! and `decrypt_4blocks` 200 B, or 232 B and 216 B for the copies the four-block closures call;
//! `f` 152 B; `ortho` 24 B. The crate docs tabulate the chains: `new` 720 B for Camellia-128 and
//! 1120 B for the other two, 496 B for the one-block calls, 512 B for the two-block calls and
//! `decrypt_4blocks`, 528 B for `encrypt_4blocks`.

#![allow(dead_code)]

use bouncycastle::camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};

use mem_usage_benches::block_cipher_mem_usage as bench;

const KEY_128: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const KEY_192: [u8; 24] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
];
const KEY_256: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn print_struct_sizes() {
    bench::print_struct_size::<Camellia128Internal>("Camellia128Internal");
    bench::print_struct_size::<Camellia192Internal>("Camellia192Internal");
    bench::print_struct_size::<Camellia256Internal>("Camellia256Internal");
}

fn main() {
    print_struct_sizes()
    // bench::do_nothing()
    // bench::all::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::key_expansion::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::encrypt_block::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::decrypt_block::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::encrypt_2blocks::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::decrypt_2blocks::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::encrypt_4blocks::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::decrypt_4blocks::<Camellia128Internal, 16>("Camellia128Internal", &KEY_128)
    // bench::all::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::key_expansion::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::encrypt_block::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::decrypt_block::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::encrypt_2blocks::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::decrypt_2blocks::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::encrypt_4blocks::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::decrypt_4blocks::<Camellia192Internal, 24>("Camellia192Internal", &KEY_192)
    // bench::all::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::key_expansion::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::encrypt_block::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::decrypt_block::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::encrypt_2blocks::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::decrypt_2blocks::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::encrypt_4blocks::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
    // bench::decrypt_4blocks::<Camellia256Internal, 32>("Camellia256Internal", &KEY_256)
}
