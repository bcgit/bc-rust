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
//! because massif reports the peak across the whole process.
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
#![allow(unused_imports)]

use bouncycastle::aria::LANES;
use bouncycastle::aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each engine, i.e. the persistent cost of holding the round keys.
fn print_struct_sizes() {
    use core::mem::size_of;

    // RFC 5794 Sec 2.2: ek1 .. ek{n+1} for n = 12, 14, 16 rounds -- 13, 15 or 17 keys of 16 bytes.
    println!("size_of<ARIA128Internal>: {}", size_of::<ARIA128Internal>());
    println!("size_of<ARIA192Internal>: {}", size_of::<ARIA192Internal>());
    println!("size_of<ARIA256Internal>: {}", size_of::<ARIA256Internal>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary and
/// the closure's frame is exactly the operation's.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// The RFC 5794 Appendix A keys (`00 01 02 .. 1f`, truncated to the key length), so the engines
/// under measurement are known ones.
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

/// Wraps a hard-coded key. `#[inline(never)]` so the wrapping is a sibling frame of whatever
/// uses the key, not part of it.
#[inline(never)]
fn key<const N: usize>(bytes: &[u8; N]) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// Expands the key into an engine, in its own frame, so the expansion's temporaries are popped
/// before an operation on the engine runs.
#[inline(never)]
fn load_aria128() -> ARIA128Internal {
    ARIA128Internal::new(&key(&KEY_128)).unwrap()
}
#[inline(never)]
fn load_aria192() -> ARIA192Internal {
    ARIA192Internal::new(&key(&KEY_192)).unwrap()
}
#[inline(never)]
fn load_aria256() -> ARIA256Internal {
    ARIA256Internal::new(&key(&KEY_256)).unwrap()
}

// ---- key expansion: the expansion is the operation, so it runs inside `measure` ------------

fn bench_aria128_key_expansion() {
    eprintln!("ARIA128Internal::new (key expansion)");
    let key = key(&KEY_128);
    measure(|| {
        let aria = ARIA128Internal::new(&key).unwrap();
        print!("{aria:?}");
    });
}

fn bench_aria192_key_expansion() {
    eprintln!("ARIA192Internal::new (key expansion)");
    let key = key(&KEY_192);
    measure(|| {
        let aria = ARIA192Internal::new(&key).unwrap();
        print!("{aria:?}");
    });
}

fn bench_aria256_key_expansion() {
    eprintln!("ARIA256Internal::new (key expansion)");
    let key = key(&KEY_256);
    measure(|| {
        let aria = ARIA256Internal::new(&key).unwrap();
        print!("{aria:?}");
    });
}

// ---- the six entry points, per key length -------------------------------------------------
//
// Every entry point runs the same four-lane circuit: a single block fills all four lanes with
// copies, two blocks fill two, so the working state is the same size throughout. The blocks are
// stack arrays in the closure, never a heap buffer, so massif's --heap=no does not hide them.

fn bench_aria128_encrypt_block() {
    eprintln!("ARIA128Internal::encrypt_block");
    let aria = load_aria128();
    measure(|| {
        let mut block = [0x11u8; 16];
        aria.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aria128_decrypt_block() {
    eprintln!("ARIA128Internal::decrypt_block");
    let aria = load_aria128();
    measure(|| {
        let mut block = [0x11u8; 16];
        aria.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aria128_encrypt_2blocks() {
    eprintln!("ARIA128Internal::encrypt_2blocks");
    let aria = load_aria128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aria.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria128_decrypt_2blocks() {
    eprintln!("ARIA128Internal::decrypt_2blocks");
    let aria = load_aria128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aria.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria128_encrypt_4blocks() {
    eprintln!("ARIA128Internal::encrypt_4blocks");
    let aria = load_aria128();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aria.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria128_decrypt_4blocks() {
    eprintln!("ARIA128Internal::decrypt_4blocks");
    let aria = load_aria128();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aria.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria192_encrypt_block() {
    eprintln!("ARIA192Internal::encrypt_block");
    let aria = load_aria192();
    measure(|| {
        let mut block = [0x11u8; 16];
        aria.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aria192_decrypt_block() {
    eprintln!("ARIA192Internal::decrypt_block");
    let aria = load_aria192();
    measure(|| {
        let mut block = [0x11u8; 16];
        aria.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aria192_encrypt_2blocks() {
    eprintln!("ARIA192Internal::encrypt_2blocks");
    let aria = load_aria192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aria.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria192_decrypt_2blocks() {
    eprintln!("ARIA192Internal::decrypt_2blocks");
    let aria = load_aria192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aria.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria192_encrypt_4blocks() {
    eprintln!("ARIA192Internal::encrypt_4blocks");
    let aria = load_aria192();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aria.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria192_decrypt_4blocks() {
    eprintln!("ARIA192Internal::decrypt_4blocks");
    let aria = load_aria192();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aria.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria256_encrypt_block() {
    eprintln!("ARIA256Internal::encrypt_block");
    let aria = load_aria256();
    measure(|| {
        let mut block = [0x11u8; 16];
        aria.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aria256_decrypt_block() {
    eprintln!("ARIA256Internal::decrypt_block");
    let aria = load_aria256();
    measure(|| {
        let mut block = [0x11u8; 16];
        aria.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aria256_encrypt_2blocks() {
    eprintln!("ARIA256Internal::encrypt_2blocks");
    let aria = load_aria256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aria.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria256_decrypt_2blocks() {
    eprintln!("ARIA256Internal::decrypt_2blocks");
    let aria = load_aria256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aria.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria256_encrypt_4blocks() {
    eprintln!("ARIA256Internal::encrypt_4blocks");
    let aria = load_aria256();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aria.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aria256_decrypt_4blocks() {
    eprintln!("ARIA256Internal::decrypt_4blocks");
    let aria = load_aria256();
    measure(|| {
        let mut blocks: [[u8; 16]; LANES] =
            [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aria.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_aria128_key_expansion()
    // bench_aria192_key_expansion()
    // bench_aria256_key_expansion()
    // bench_aria128_encrypt_block()
    // bench_aria128_decrypt_block()
    // bench_aria128_encrypt_2blocks()
    // bench_aria128_decrypt_2blocks()
    // bench_aria128_encrypt_4blocks()
    // bench_aria128_decrypt_4blocks()
    // bench_aria192_encrypt_block()
    // bench_aria192_decrypt_block()
    // bench_aria192_encrypt_2blocks()
    // bench_aria192_decrypt_2blocks()
    // bench_aria192_encrypt_4blocks()
    // bench_aria192_decrypt_4blocks()
    // bench_aria256_encrypt_block()
    // bench_aria256_decrypt_block()
    // bench_aria256_encrypt_2blocks()
    // bench_aria256_decrypt_2blocks()
    // bench_aria256_encrypt_4blocks()
    // bench_aria256_decrypt_4blocks()
}
