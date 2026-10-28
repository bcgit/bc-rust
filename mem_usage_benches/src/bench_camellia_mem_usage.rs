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
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"` and read the frame of each
//! `measure` closure, which is the operation's frame with nothing else in it. The engine is built
//! in an `#[inline(never)]` helper so its frame is a sibling of the operation's, and the
//! operation runs in a non-inlined, non-returning closure so nothing crosses back across the
//! boundary. The persistent cost, the subkeys, is what `print_struct_sizes` prints. There are no
//! lookup tables; a table-driven engine adds anywhere from 256 bytes to 4 KiB of them on top.
//!
//! With rustc 1.97 nightly on x86-64 the closure frames are 456 B for Camellia-128's `new` and
//! 584 B for the other two, 88 B for the one- and four-block entry points and 104 B for the
//! two-block ones; the crate docs tabulate them with the 8-byte return address added.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::camellia::LANES;
use bouncycastle::camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};

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
    println!("size_of<Camellia128Internal>: {}", size_of::<Camellia128Internal>());
    println!("size_of<Camellia192Internal>: {}", size_of::<Camellia192Internal>());
    println!("size_of<Camellia256Internal>: {}", size_of::<Camellia256Internal>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary and
/// the closure's frame is exactly the operation's.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// The RFC 3713 Appendix A keys, so the engines under measurement are known ones.
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

/// Wraps a hard-coded key. `#[inline(never)]` so the wrapping is a sibling frame of whatever
/// uses the key, not part of it.
#[inline(never)]
fn key<const N: usize>(bytes: &[u8; N]) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// Expands the key into an engine, in its own frame, so the expansion's temporaries are popped
/// before an operation on the engine runs.
#[inline(never)]
fn load_camellia128() -> Camellia128Internal {
    Camellia128Internal::new(&key(&KEY_128)).unwrap()
}
#[inline(never)]
fn load_camellia192() -> Camellia192Internal {
    Camellia192Internal::new(&key(&KEY_192)).unwrap()
}
#[inline(never)]
fn load_camellia256() -> Camellia256Internal {
    Camellia256Internal::new(&key(&KEY_256)).unwrap()
}

// ---- key expansion: the expansion is the operation, so it runs inside `measure` ------------

fn bench_camellia128_key_expansion() {
    eprintln!("Camellia128Internal::new (key expansion)");
    let key = key(&KEY_128);
    measure(|| {
        let camellia = Camellia128Internal::new(&key).unwrap();
        print!("{camellia:?}");
    });
}

fn bench_camellia192_key_expansion() {
    eprintln!("Camellia192Internal::new (key expansion)");
    let key = key(&KEY_192);
    measure(|| {
        let camellia = Camellia192Internal::new(&key).unwrap();
        print!("{camellia:?}");
    });
}

fn bench_camellia256_key_expansion() {
    eprintln!("Camellia256Internal::new (key expansion)");
    let key = key(&KEY_256);
    measure(|| {
        let camellia = Camellia256Internal::new(&key).unwrap();
        print!("{camellia:?}");
    });
}

// ---- the six entry points, per key length -------------------------------------------------
//
// Every entry point runs the same four-lane circuit: a single block fills all four lanes with
// copies, two blocks fill two, so the working state is the same size throughout. The blocks are
// stack arrays in the closure, never a heap buffer, so massif's --heap=no does not hide them.

fn bench_camellia128_encrypt_block() {
    eprintln!("Camellia128Internal::encrypt_block");
    let camellia = load_camellia128();
    measure(|| {
        let mut block = [0x11u8; 16];
        camellia.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_camellia128_decrypt_block() {
    eprintln!("Camellia128Internal::decrypt_block");
    let camellia = load_camellia128();
    measure(|| {
        let mut block = [0x11u8; 16];
        camellia.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_camellia128_encrypt_2blocks() {
    eprintln!("Camellia128Internal::encrypt_2blocks");
    let camellia = load_camellia128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        camellia.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia128_decrypt_2blocks() {
    eprintln!("Camellia128Internal::decrypt_2blocks");
    let camellia = load_camellia128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        camellia.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia128_encrypt_4blocks() {
    eprintln!("Camellia128Internal::encrypt_4blocks");
    let camellia = load_camellia128();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        camellia.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia128_decrypt_4blocks() {
    eprintln!("Camellia128Internal::decrypt_4blocks");
    let camellia = load_camellia128();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        camellia.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia192_encrypt_block() {
    eprintln!("Camellia192Internal::encrypt_block");
    let camellia = load_camellia192();
    measure(|| {
        let mut block = [0x11u8; 16];
        camellia.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_camellia192_decrypt_block() {
    eprintln!("Camellia192Internal::decrypt_block");
    let camellia = load_camellia192();
    measure(|| {
        let mut block = [0x11u8; 16];
        camellia.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_camellia192_encrypt_2blocks() {
    eprintln!("Camellia192Internal::encrypt_2blocks");
    let camellia = load_camellia192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        camellia.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia192_decrypt_2blocks() {
    eprintln!("Camellia192Internal::decrypt_2blocks");
    let camellia = load_camellia192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        camellia.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia192_encrypt_4blocks() {
    eprintln!("Camellia192Internal::encrypt_4blocks");
    let camellia = load_camellia192();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        camellia.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia192_decrypt_4blocks() {
    eprintln!("Camellia192Internal::decrypt_4blocks");
    let camellia = load_camellia192();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        camellia.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia256_encrypt_block() {
    eprintln!("Camellia256Internal::encrypt_block");
    let camellia = load_camellia256();
    measure(|| {
        let mut block = [0x11u8; 16];
        camellia.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_camellia256_decrypt_block() {
    eprintln!("Camellia256Internal::decrypt_block");
    let camellia = load_camellia256();
    measure(|| {
        let mut block = [0x11u8; 16];
        camellia.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_camellia256_encrypt_2blocks() {
    eprintln!("Camellia256Internal::encrypt_2blocks");
    let camellia = load_camellia256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        camellia.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia256_decrypt_2blocks() {
    eprintln!("Camellia256Internal::decrypt_2blocks");
    let camellia = load_camellia256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        camellia.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia256_encrypt_4blocks() {
    eprintln!("Camellia256Internal::encrypt_4blocks");
    let camellia = load_camellia256();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        camellia.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_camellia256_decrypt_4blocks() {
    eprintln!("Camellia256Internal::decrypt_4blocks");
    let camellia = load_camellia256();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        camellia.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_camellia128_key_expansion()
    // bench_camellia192_key_expansion()
    // bench_camellia256_key_expansion()
    // bench_camellia128_encrypt_block()
    // bench_camellia128_decrypt_block()
    // bench_camellia128_encrypt_2blocks()
    // bench_camellia128_decrypt_2blocks()
    // bench_camellia128_encrypt_4blocks()
    // bench_camellia128_decrypt_4blocks()
    // bench_camellia192_encrypt_block()
    // bench_camellia192_decrypt_block()
    // bench_camellia192_encrypt_2blocks()
    // bench_camellia192_decrypt_2blocks()
    // bench_camellia192_encrypt_4blocks()
    // bench_camellia192_decrypt_4blocks()
    // bench_camellia256_encrypt_block()
    // bench_camellia256_decrypt_block()
    // bench_camellia256_encrypt_2blocks()
    // bench_camellia256_decrypt_2blocks()
    // bench_camellia256_encrypt_4blocks()
    // bench_camellia256_decrypt_4blocks()
}
