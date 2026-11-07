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
//! because massif reports the peak across the whole process. The operations themselves are the
//! shared `block_cipher_mem_usage` harness over this cipher's permutations; this file holds the
//! keys and the choice.
//!
//! # What to expect, and why massif cannot see it
//!
//! Like AES, SM4 has no interesting stack profile: a call needs a few hundred bytes -- the
//! four-block working state (64 bytes), the eight `u16` S-box planes (16 bytes) and the circuit's
//! spills -- which is below what massif resolves, since the process's own start-up reaches about
//! 7.7 kB of stack before `main` runs. So the massif number is the floor, not a measurement.
//!
//! The numbers that do mean something come from the compiler's frame-layout remarks, as for
//! `bench_aes_mem_usage`: build this binary with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"`, with `main` calling every
//! bench so none is dead-stripped, and sum the deepest chain of frames below each `measure`
//! closure. The closure is not the whole cost: `encrypt_4blocks`, `tau` and `ortho` keep their
//! own frames under it (`objdump -d` shows the calls), so the chain is closure, `encrypt_4blocks`
//! or `new`, `tau`, `ortho`, each with its 8-byte return address. The engine is built in an
//! `#[inline(never)]` helper so its frame is a sibling of the operation's, and the operation
//! runs in a non-inlined, non-returning closure so nothing crosses back across the boundary.
//! The persistent cost, the 128 bytes of round keys, is what `print_struct_sizes` prints. There
//! are no lookup tables; a table-driven engine adds a 256-byte table on top.
//!
//! With rustc 1.97 nightly on x86-64 the frames are: closures 264 B for `new`, 88 B for the one-
//! and four-block entry points and 104 B for the two-block ones; `new` 232 B; `encrypt_4blocks`
//! and `decrypt_4blocks` 120 B; `tau` 152 B; `ortho` 24 B. The crate docs tabulate the chains,
//! 704 B for `new`, 416 B for the one- and four-block calls and 432 B for the two-block ones.

#![allow(dead_code)]

use bouncycastle::sm4::hazmat::SM4Internal;

use mem_usage_benches::block_cipher_mem_usage as bench;

const KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
];

fn print_struct_sizes() {
    bench::print_struct_size::<SM4Internal>("SM4Internal");
}

fn main() {
    print_struct_sizes()
    // bench::do_nothing()
    // bench::all::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::key_expansion::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::encrypt_block::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::decrypt_block::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::encrypt_2blocks::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::decrypt_2blocks::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::encrypt_4blocks::<SM4Internal, 16>("SM4Internal", &KEY)
    // bench::decrypt_4blocks::<SM4Internal, 16>("SM4Internal", &KEY)
}
