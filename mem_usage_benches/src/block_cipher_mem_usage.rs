//! The stack-usage harness every block cipher bench shares: one function per entry point of a
//! permutation, generic over it, each printing what it measures to stderr and running the
//! operation inside a non-inlined closure so that its frame is the operation's and nothing else.
//! The per-cipher binaries (`bench_aes_mem_usage` and the rest) hold their keys and their
//! `main`, which picks the function to measure; their docs give the valgrind recipe and say what
//! the frame-layout remarks showed.
//!
//! `print!()` keeps the compiler from optimizing the operation away; the junk it writes goes to
//! stdout so it can be piped to `/dev/null`, and the names go to stderr.

use bouncycastle::core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use core::fmt::Debug;

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
pub fn do_nothing() {
    eprintln!("DoNothing");
    print!("{}", 1 + 1);
}

/// The persistent cost: the size of the engine, which is its schedule.
pub fn print_struct_size<P>(name: &str) {
    println!("size_of<{name}>: {}", core::mem::size_of::<P>());
}

/// The operation under measurement runs in here, so that its frame is a leaf under `main`'s.
#[inline(never)]
pub fn measure(f: impl FnOnce()) {
    f()
}

/// Key material from raw bytes, out of line so its frame is a sibling of the operation's.
#[inline(never)]
pub fn key<const N: usize>(bytes: &[u8; N]) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// The engine, built out of line so that its frame is a sibling of the operation's.
#[inline(never)]
pub fn load<P: KeyExpansion<N>, const N: usize>(bytes: &[u8; N]) -> P {
    P::new(&key(bytes)).unwrap()
}

/// Key expansion: `P::new`.
pub fn key_expansion<P: KeyExpansion<N> + Debug, const N: usize>(name: &str, bytes: &[u8; N]) {
    eprintln!("{name}::new (key expansion)");
    let key = key(bytes);
    measure(|| {
        let engine = P::new(&key).unwrap();
        print!("{engine:?}");
    });
}

/// `encrypt_block`.
pub fn encrypt_block<P: KeyExpansion<N> + BlockPermutation<16>, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    eprintln!("{name}::encrypt_block");
    let engine: P = load(bytes);
    measure(|| {
        let mut block = [0x11u8; 16];
        engine.encrypt_block(&mut block);
        print!("{block:x?}");
    });
}

/// `decrypt_block`.
pub fn decrypt_block<P: KeyExpansion<N> + BlockPermutation<16>, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    eprintln!("{name}::decrypt_block");
    let engine: P = load(bytes);
    measure(|| {
        let mut block = [0x11u8; 16];
        engine.decrypt_block(&mut block);
        print!("{block:x?}");
    });
}

/// `encrypt_2blocks`.
pub fn encrypt_2blocks<P: KeyExpansion<N> + BlockPermutation<16>, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    eprintln!("{name}::encrypt_2blocks");
    let engine: P = load(bytes);
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        engine.encrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

/// `decrypt_2blocks`.
pub fn decrypt_2blocks<P: KeyExpansion<N> + BlockPermutation<16>, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    eprintln!("{name}::decrypt_2blocks");
    let engine: P = load(bytes);
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16]];
        engine.decrypt_2blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

/// `encrypt_4blocks`.
pub fn encrypt_4blocks<P: KeyExpansion<N> + BlockPermutation<16>, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    eprintln!("{name}::encrypt_4blocks");
    let engine: P = load(bytes);
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        engine.encrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

/// `decrypt_4blocks`.
pub fn decrypt_4blocks<P: KeyExpansion<N> + BlockPermutation<16>, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    eprintln!("{name}::decrypt_4blocks");
    let engine: P = load(bytes);
    measure(|| {
        let mut blocks = [[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]];
        engine.decrypt_4blocks(&mut blocks);
        print!("{blocks:x?}");
    });
}

/// Every entry point of one engine at one key length, so that a build with `main` calling this
/// keeps all of them for the frame-layout remarks.
pub fn all<P: KeyExpansion<N> + BlockPermutation<16> + Debug, const N: usize>(
    name: &str,
    bytes: &[u8; N],
) {
    key_expansion::<P, N>(name, bytes);
    encrypt_block::<P, N>(name, bytes);
    decrypt_block::<P, N>(name, bytes);
    encrypt_2blocks::<P, N>(name, bytes);
    decrypt_2blocks::<P, N>(name, bytes);
    encrypt_4blocks::<P, N>(name, bytes);
    decrypt_4blocks::<P, N>(name, bytes);
}
