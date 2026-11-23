//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_scrypt_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The crate docs' stack figure is the deepest frame chain from [`measure`] down, as for the
//! ECC CDH harness. It is the stack only: scrypt's working memory, `ScryptParams::work_len`
//! bytes, is the caller's buffer, a heap allocation here, made outside the measured region.
//!
//! Note: print!() forces the compiler not to optimize away the actual code. The name of the bench
//! goes to stderr so that the junk on stdout can be piped to /dev/null.
//!
//! Main is at the bottom, controls which bench is actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;

use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::digest::scrypt::{SCrypt, ScryptParams};

/// Runs the operation under measurement out of line, so that its frames sit below one symbol
/// the stack-table method can root a call chain at.
#[inline(never)]
fn measure<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// This exists so that /usr/bin/time can measure the base memory footprint of the harness.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// The password, built out of line so its temporaries are popped before the operation.
#[inline(never)]
fn password() -> KeyMaterial<64> {
    KeyMaterial::<64>::from_bytes_as_type(
        &black_box(*b"correct horse battery staple"),
        KeyType::Unknown,
    )
    .unwrap()
}

/// scrypt with N = 2^14, r = 8, p = 1 (RFC 7914 Section 12's third parameter set), 64 bytes
/// of key; the stack does not depend on N.
fn bench_scrypt() {
    eprintln!("SCrypt::derive_with_memory_out");
    let password = password();
    let salt = black_box([0x5Au8; 16]);
    let params = ScryptParams::new(black_box(14), 8, 1).unwrap();
    let mut work = vec![0u8; params.work_len()];
    let mut out = KeyMaterial::<64>::new();
    measure(|| {
        SCrypt::new(&salt, params)
            .derive_with_memory_out(&password, 64, &mut work, &mut out)
            .unwrap();
    });
    print!("{:x?}", out.ref_to_bytes());
}

fn main() {
    bench_scrypt()
    // bench_do_nothing()
}
