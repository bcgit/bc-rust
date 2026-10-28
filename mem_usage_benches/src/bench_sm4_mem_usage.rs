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
//! # What to expect, and why massif cannot see it
//!
//! Like AES, SM4 has no interesting stack profile: a call needs a few hundred bytes -- the
//! four-block working state (64 bytes), the eight `u16` S-box planes (16 bytes) and the circuit's
//! spills -- which is below what massif resolves, since the process's own start-up reaches about
//! 7.7 kB of stack before `main` runs. So the massif number is the floor, not a measurement.
//!
//! The numbers that do mean something come from the compiler's frame-layout remarks, as for
//! `bench_aes_mem_usage`: build this binary with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"` and read the frame of each
//! `measure` closure, which is the operation's frame with nothing else in it. The engine is built
//! in an `#[inline(never)]` helper so its frame is a sibling of the operation's, and the
//! operation runs in a non-inlined, non-returning closure so nothing crosses back across the
//! boundary. The persistent cost, the 128 bytes of round keys, is what `print_struct_sizes`
//! prints. There are no lookup tables; a table-driven engine adds a 256-byte table on top.
//!
//! With rustc 1.97 nightly on x86-64 the closure frames are 264 B for `new`, 88 B for the
//! one- and four-block entry points and 104 B for the two-block ones; the crate docs tabulate
//! them with the 8-byte return address added.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::sm4::LANES;
use bouncycastle::sm4::hazmat::SM4Internal;

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of the engine, i.e. the persistent cost of holding the round keys.
fn print_struct_sizes() {
    use core::mem::size_of;

    // draft-ribose-cfrg-sm4-10 Sec 7.3: 32 round keys of 32 bits, so 128 bytes.
    println!("size_of<SM4Internal>: {}", size_of::<SM4Internal>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary and
/// the closure's frame is exactly the operation's.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// The draft-ribose-cfrg-sm4-10 Appendix A.1.1 key, so the engine under measurement is a known
/// one.
const KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// Wraps the hard-coded key. `#[inline(never)]` so the wrapping is a sibling frame of whatever
/// uses the key, not part of it.
#[inline(never)]
fn key() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&KEY, KeyType::SymmetricCipherKey).unwrap()
}

/// Expands the key into an engine, in its own frame, so the expansion's temporaries are popped
/// before an operation on the engine runs.
#[inline(never)]
fn load_sm4() -> SM4Internal {
    SM4Internal::new(&key()).unwrap()
}

// ---- key expansion: the expansion is the operation, so it runs inside `measure` ------------

fn bench_sm4_key_expansion() {
    eprintln!("SM4Internal::new (key expansion)");
    let key = key();
    measure(|| {
        let sm4 = SM4Internal::new(&key).unwrap();
        print!("{sm4:?}");
    });
}

// ---- the six entry points ---------------------------------------------------------------------
//
// Every entry point runs the same four-lane circuit: a single block fills all four lanes with
// copies, two blocks fill two, so the working state is the same size throughout. The blocks are
// stack arrays in the closure, never a heap buffer, so massif's --heap=no does not hide them.

fn bench_sm4_encrypt_block() {
    eprintln!("SM4Internal::encrypt_block");
    let sm4 = load_sm4();
    measure(|| {
        let mut block = [0x11u8; 16];
        sm4.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_sm4_decrypt_block() {
    eprintln!("SM4Internal::decrypt_block");
    let sm4 = load_sm4();
    measure(|| {
        let mut block = [0x11u8; 16];
        sm4.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_sm4_encrypt_2blocks() {
    eprintln!("SM4Internal::encrypt_2blocks");
    let sm4 = load_sm4();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        sm4.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_sm4_decrypt_2blocks() {
    eprintln!("SM4Internal::decrypt_2blocks");
    let sm4 = load_sm4();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        sm4.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_sm4_encrypt_4blocks() {
    eprintln!("SM4Internal::encrypt_4blocks");
    let sm4 = load_sm4();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        sm4.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_sm4_decrypt_4blocks() {
    eprintln!("SM4Internal::decrypt_4blocks");
    let sm4 = load_sm4();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        sm4.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sm4_key_expansion()
    // bench_sm4_encrypt_block()
    // bench_sm4_decrypt_block()
    // bench_sm4_encrypt_2blocks()
    // bench_sm4_decrypt_2blocks()
    // bench_sm4_encrypt_4blocks()
    // bench_sm4_decrypt_4blocks()
}
