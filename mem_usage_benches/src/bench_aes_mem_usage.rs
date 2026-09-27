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
//! because massif reports the peak across the whole process.
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
#![allow(unused_imports)]

use bouncycastle::aes::aes_internal::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::traits::ElectronicCodeBook;

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each engine, i.e. the persistent cost of holding a key schedule.
fn print_struct_sizes() {
    use core::mem::size_of;

    // FIPS 197 Sec 5.2: the schedule is 4 * (Nr + 1) words, so 176 / 208 / 240 bytes. The
    // bit-sliced form is stored at the one-block width, so bit-slicing adds nothing to these.
    println!("size_of<AES128Internal>: {}", size_of::<AES128Internal>());
    println!("size_of<AES192Internal>: {}", size_of::<AES192Internal>());
    println!("size_of<AES256Internal>: {}", size_of::<AES256Internal>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary and
/// the closure's frame is exactly the operation's.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// The FIPS 197 Appendix A.1 key, so the engine under measurement is a known one.
const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
/// FIPS 197 Appendix A.2.
const KEY_192: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
];
/// FIPS 197 Appendix A.3.
const KEY_256: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
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
fn load_aes128() -> AES128Internal {
    AES128Internal::new(&key(&KEY_128)).unwrap()
}
#[inline(never)]
fn load_aes192() -> AES192Internal {
    AES192Internal::new(&key(&KEY_192)).unwrap()
}
#[inline(never)]
fn load_aes256() -> AES256Internal {
    AES256Internal::new(&key(&KEY_256)).unwrap()
}

// ---- key expansion: the expansion is the operation, so it runs inside `measure` ------------

fn bench_aes128_key_expansion() {
    eprintln!("AES128Internal::new (key expansion)");
    let key = key(&KEY_128);
    measure(|| {
        let aes = AES128Internal::new(&key).unwrap();
        print!("{aes:?}");
    });
}

fn bench_aes192_key_expansion() {
    eprintln!("AES192Internal::new (key expansion)");
    let key = key(&KEY_192);
    measure(|| {
        let aes = AES192Internal::new(&key).unwrap();
        print!("{aes:?}");
    });
}

fn bench_aes256_key_expansion() {
    eprintln!("AES256Internal::new (key expansion)");
    let key = key(&KEY_256);
    measure(|| {
        let aes = AES256Internal::new(&key).unwrap();
        print!("{aes:?}");
    });
}

// ---- the six entry points, per key length -------------------------------------------------
//
// One block runs on u16 planes, two on u32, four on u64; the working state and the widened
// round key scale with that, so the three widths are measured separately. The blocks are
// stack arrays in the closure, never a heap buffer, so massif's --heap=no does not hide them.

fn bench_aes128_encrypt_block() {
    eprintln!("AES128Internal::encrypt_block");
    let aes = load_aes128();
    measure(|| {
        let mut block = [0x11u8; 16];
        aes.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aes128_decrypt_block() {
    eprintln!("AES128Internal::decrypt_block");
    let aes = load_aes128();
    measure(|| {
        let mut block = [0x11u8; 16];
        aes.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aes128_encrypt_2blocks() {
    eprintln!("AES128Internal::encrypt_2blocks");
    let aes = load_aes128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aes.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes128_decrypt_2blocks() {
    eprintln!("AES128Internal::decrypt_2blocks");
    let aes = load_aes128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aes.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes128_encrypt_4blocks() {
    eprintln!("AES128Internal::encrypt_4blocks");
    let aes = load_aes128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aes.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes128_decrypt_4blocks() {
    eprintln!("AES128Internal::decrypt_4blocks");
    let aes = load_aes128();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aes.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes192_encrypt_block() {
    eprintln!("AES192Internal::encrypt_block");
    let aes = load_aes192();
    measure(|| {
        let mut block = [0x11u8; 16];
        aes.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aes192_decrypt_block() {
    eprintln!("AES192Internal::decrypt_block");
    let aes = load_aes192();
    measure(|| {
        let mut block = [0x11u8; 16];
        aes.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aes192_encrypt_2blocks() {
    eprintln!("AES192Internal::encrypt_2blocks");
    let aes = load_aes192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aes.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes192_decrypt_2blocks() {
    eprintln!("AES192Internal::decrypt_2blocks");
    let aes = load_aes192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aes.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes192_encrypt_4blocks() {
    eprintln!("AES192Internal::encrypt_4blocks");
    let aes = load_aes192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aes.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes192_decrypt_4blocks() {
    eprintln!("AES192Internal::decrypt_4blocks");
    let aes = load_aes192();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aes.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes256_encrypt_block() {
    eprintln!("AES256Internal::encrypt_block");
    let aes = load_aes256();
    measure(|| {
        let mut block = [0x11u8; 16];
        aes.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aes256_decrypt_block() {
    eprintln!("AES256Internal::decrypt_block");
    let aes = load_aes256();
    measure(|| {
        let mut block = [0x11u8; 16];
        aes.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

fn bench_aes256_encrypt_2blocks() {
    eprintln!("AES256Internal::encrypt_2blocks");
    let aes = load_aes256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aes.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes256_decrypt_2blocks() {
    eprintln!("AES256Internal::decrypt_2blocks");
    let aes = load_aes256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        aes.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes256_encrypt_4blocks() {
    eprintln!("AES256Internal::encrypt_4blocks");
    let aes = load_aes256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aes.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn bench_aes256_decrypt_4blocks() {
    eprintln!("AES256Internal::decrypt_4blocks");
    let aes = load_aes256();
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        aes.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_aes128_key_expansion()
    // bench_aes192_key_expansion()
    // bench_aes256_key_expansion()
    // bench_aes128_encrypt_block()
    // bench_aes128_decrypt_block()
    // bench_aes128_encrypt_2blocks()
    // bench_aes128_decrypt_2blocks()
    // bench_aes128_encrypt_4blocks()
    // bench_aes128_decrypt_4blocks()
    // bench_aes192_encrypt_block()
    // bench_aes192_decrypt_block()
    // bench_aes192_encrypt_2blocks()
    // bench_aes192_decrypt_2blocks()
    // bench_aes192_encrypt_4blocks()
    // bench_aes192_decrypt_4blocks()
    // bench_aes256_encrypt_block()
    // bench_aes256_decrypt_block()
    // bench_aes256_encrypt_2blocks()
    // bench_aes256_decrypt_2blocks()
    // bench_aes256_encrypt_4blocks()
    // bench_aes256_decrypt_4blocks()
}
