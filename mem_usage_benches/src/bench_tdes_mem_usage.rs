//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_tdes_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_tdes_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! Like AES, TDEA has no interesting stack profile: a call needs a few hundred bytes -- the six
//! input planes, the 128-byte working array of the S-box layer's ANF evaluation and a few words
//! of block state -- which is below what massif resolves, since the process's own start-up
//! reaches about 7.7 kB of stack before `main` runs. So the massif number is the floor, not a
//! measurement.
//!
//! The numbers that do mean something come from the compiler's frame-layout remarks, as for
//! `bench_aes_mem_usage`: build this binary with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"`, with `main` calling every
//! bench so none is dead-stripped, and sum the deepest chain of frames below each `measure`
//! closure, each with its 8-byte return address. The closure is not always the whole cost:
//! `objdump -d` shows the key-expansion closures calling the engine's `new` out of line, which
//! calls the schedule's `expand`, and the one-block closures calling `encrypt_block` /
//! `decrypt_block`; the two- and four-block entry points are inlined into their closures. The
//! engine is built in an `#[inline(never)]` helper so its frame is a sibling of the operation's,
//! and the operation runs in a non-inlined, non-returning closure so nothing crosses back across
//! the boundary. The persistent cost, the packed schedules, is what `print_struct_sizes` prints.
//! A table-driven Triple DES carries 2 KiB of combined S/P tables on top; this one carries none.
//! The two-key engine is decryption-only, so only its decrypting entry points are measured.
//!
//! With rustc 1.97 nightly on x86-64 the frames are: closures 792 B for `TDESInternal::new` and
//! 536 B for `TDES2Internal::new`, and 40, 72 and 104 B for the one-, two- and four-block entry
//! points of either engine; the engines' `new` 440 B and 312 B; `expand` 48 B; the one-block
//! permutation methods 48 B. The crate docs tabulate the chains: `new` 1304 B and 920 B, the
//! one-block calls 104 B, the two- and four-block calls 80 B and 112 B.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::tdes::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, KEY_LEN_2KEY};

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each engine, i.e. the persistent cost of holding the schedules.
fn print_struct_sizes() {
    use core::mem::size_of;

    // Three DEA keys, sixteen round keys each, two words per round key: 3 * 16 * 2 * 4 = 384.
    println!("size_of<TDESInternal>: {}", size_of::<TDESInternal>());
    // Two DEA keys: 2 * 16 * 2 * 4 = 256.
    println!("size_of<TDES2Internal>: {}", size_of::<TDES2Internal>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary and
/// the closure's frame is exactly the operation's.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// The NIST CAVP TECBMMT3.rsp `[ENCRYPT]` COUNT = 0 bundle, so the engine under measurement is a
/// known one; the two-key bundle is its first two components.
const KEY_3: [u8; KEY_LEN] = [
    0xe9, 0x7c, 0x83, 0x13, 0xba, 0x26, 0x5d, 0x43, 0x25, 0x4c, 0xbf, 0x9e, 0x8f, 0x7c, 0x2a, 0xa8,
    0xa7, 0x54, 0xd6, 0x5e, 0x8a, 0xe9, 0x97, 0xe3,
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
fn load_tdes() -> TDESInternal {
    TDESInternal::new(&key(&KEY_3)).unwrap()
}
#[inline(never)]
fn load_tdes2() -> TDES2Internal {
    let two: [u8; KEY_LEN_2KEY] = KEY_3[..KEY_LEN_2KEY].try_into().unwrap();
    TDES2Internal::new(&key(&two)).unwrap()
}

// ---- key expansion: the expansion is the operation, so it runs inside `measure` ------------

fn bench_tdes_key_expansion() {
    eprintln!("TDESInternal::new (key expansion)");
    let key = key(&KEY_3);
    measure(|| {
        let tdes = TDESInternal::new(&key).unwrap();
        print!("{tdes:?}");
    });
}

fn bench_tdes2_key_expansion() {
    eprintln!("TDES2Internal::new (key expansion)");
    let two: [u8; KEY_LEN_2KEY] = KEY_3[..KEY_LEN_2KEY].try_into().unwrap();
    let key = key(&two);
    measure(|| {
        let tdes = TDES2Internal::new(&key).unwrap();
        print!("{tdes:?}");
    });
}

// ---- the block entry points -----------------------------------------------------------------
//
// The engine has no natural unit larger than one block, so the pair and four-block methods are
// single-block loops over the same state. The blocks are stack arrays in the closure, never a
// heap buffer, so massif's --heap=no does not hide them.

fn bench_tdes_encrypt_block() {
    eprintln!("TDESInternal::encrypt_block");
    let tdes = load_tdes();
    measure(|| {
        let mut block = [0x11u8; BLOCK_LEN];
        tdes.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_tdes_decrypt_block() {
    eprintln!("TDESInternal::decrypt_block");
    let tdes = load_tdes();
    measure(|| {
        let mut block = [0x11u8; BLOCK_LEN];
        tdes.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_tdes_encrypt_2blocks() {
    eprintln!("TDESInternal::encrypt_2blocks");
    let tdes = load_tdes();
    measure(|| {
        let mut blocks = [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN]];
        tdes.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_tdes_decrypt_2blocks() {
    eprintln!("TDESInternal::decrypt_2blocks");
    let tdes = load_tdes();
    measure(|| {
        let mut blocks = [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN]];
        tdes.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_tdes_encrypt_4blocks() {
    eprintln!("TDESInternal::encrypt_4blocks");
    let tdes = load_tdes();
    measure(|| {
        let mut blocks =
            [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN], [0x33u8; BLOCK_LEN], [0x44u8; BLOCK_LEN]];
        tdes.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_tdes_decrypt_4blocks() {
    eprintln!("TDESInternal::decrypt_4blocks");
    let tdes = load_tdes();
    measure(|| {
        let mut blocks =
            [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN], [0x33u8; BLOCK_LEN], [0x44u8; BLOCK_LEN]];
        tdes.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_tdes2_decrypt_block() {
    eprintln!("TDES2Internal::decrypt_block");
    let tdes = load_tdes2();
    measure(|| {
        let mut block = [0x11u8; BLOCK_LEN];
        tdes.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_tdes2_decrypt_2blocks() {
    eprintln!("TDES2Internal::decrypt_2blocks");
    let tdes = load_tdes2();
    measure(|| {
        let mut blocks = [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN]];
        tdes.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_tdes2_decrypt_4blocks() {
    eprintln!("TDES2Internal::decrypt_4blocks");
    let tdes = load_tdes2();
    measure(|| {
        let mut blocks =
            [[0x11u8; BLOCK_LEN], [0x22u8; BLOCK_LEN], [0x33u8; BLOCK_LEN], [0x44u8; BLOCK_LEN]];
        tdes.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_tdes_key_expansion()
    // bench_tdes2_key_expansion()
    // bench_tdes_encrypt_block()
    // bench_tdes_decrypt_block()
    // bench_tdes_encrypt_2blocks()
    // bench_tdes_decrypt_2blocks()
    // bench_tdes_encrypt_4blocks()
    // bench_tdes_decrypt_4blocks()
    // bench_tdes2_decrypt_block()
    // bench_tdes2_decrypt_2blocks()
    // bench_tdes2_decrypt_4blocks()
}
