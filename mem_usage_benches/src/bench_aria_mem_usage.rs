//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aria_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_aria_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! Like AES, ARIA has no interesting stack profile: a call needs a few hundred bytes -- the
//! four-block working state (64 bytes), the four class words being substituted (16 bytes), the
//! eight `u16` S-box planes (16 bytes), one round key (16 bytes) and the circuits' spills -- which
//! is below what massif resolves, since the process's own start-up reaches about 7.7 kB of stack
//! before `main` runs. So the massif number is the floor, not a measurement.
//!
//! The numbers that do mean something come from the compiler's frame-layout remarks, as for
//! `bench_aes_mem_usage`: build this binary with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"`, with `main` calling every
//! bench so none is dead-stripped, and sum the deepest chain of frames below each `measure`
//! closure (`objdump -d` shows which of the crate's functions keep a frame of their own under it,
//! each with its 8-byte return address). The engine is built in an `#[inline(never)]` helper so
//! its frame is a sibling of the operation's, and the operation runs in a non-inlined,
//! non-returning closure so nothing crosses back across the boundary. The persistent cost, the
//! round keys, is what `print_struct_sizes` prints. There are no lookup tables; a table-driven
//! engine adds 1 KiB of S-box tables and 256 bytes of diffusion masks on top.
//!
//! The crate docs' Memory Usage table is the result; its caption says the toolchain.

#![allow(dead_code)]

use bouncycastle::aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};

use mem_usage_benches::block_cipher_mem_usage as bench;

const KEY_128: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const KEY_192: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];
const KEY_256: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn print_struct_sizes() {
    bench::print_struct_size::<ARIA128Internal>("ARIA128Internal");
    bench::print_struct_size::<ARIA192Internal>("ARIA192Internal");
    bench::print_struct_size::<ARIA256Internal>("ARIA256Internal");
}

fn main() {
    print_struct_sizes()
    // bench::do_nothing()
    // bench::all::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::key_expansion::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::encrypt_block::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::decrypt_block::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::encrypt_2blocks::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::decrypt_2blocks::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::encrypt_4blocks::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::decrypt_4blocks::<ARIA128Internal, 16>("ARIA128Internal", &KEY_128)
    // bench::all::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::key_expansion::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::encrypt_block::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::decrypt_block::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::encrypt_2blocks::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::decrypt_2blocks::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::encrypt_4blocks::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::decrypt_4blocks::<ARIA192Internal, 24>("ARIA192Internal", &KEY_192)
    // bench::all::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::key_expansion::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::encrypt_block::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::decrypt_block::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::encrypt_2blocks::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::decrypt_2blocks::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::encrypt_4blocks::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
    // bench::decrypt_4blocks::<ARIA256Internal, 32>("ARIA256Internal", &KEY_256)
}
