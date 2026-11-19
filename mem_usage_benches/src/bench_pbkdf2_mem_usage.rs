//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_pbkdf2_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The crate docs' stack table is the deepest frame chain from each [`measure`] instance down,
//! as for the ECC CDH harness; `main` calls every bench for that build so none is dead-stripped.
//!
//! Note: print!() forces the compiler not to optimize away the actual code. The name of the bench
//! goes to stderr so that the junk on stdout can be piped to /dev/null.
//!
//! Main is at the bottom, controls which bench is actually run.
//!
//! Each bench derives 64 bytes from a password with 1,000 iterations; the stack does not depend
//! on the count.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;
use core::num::NonZeroU32;

use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::hmac::HMACParams;
use bouncycastle::pbkdf2::PBKDF2;
use bouncycastle::sha2::{SHA256, SHA512};
use bouncycastle::sha3::SHA3_256;

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

/// Derives 64 bytes over `H` under [`measure`] and prints them.
fn run<H: HMACParams>(name: &str) {
    eprintln!("{name}");
    let password = password();
    let salt = black_box([0x5Au8; 16]);
    let iterations = NonZeroU32::new(black_box(1_000)).unwrap();
    let mut out = KeyMaterial::<64>::new();
    measure(|| {
        PBKDF2::<H>::derive_out(&password, &salt, iterations, 64, &mut out).unwrap();
    });
    print!("{:x?}", out.ref_to_bytes());
}

fn bench_pbkdf2_hmac_sha256() {
    run::<SHA256>("PBKDF2_HMAC_SHA256")
}

fn bench_pbkdf2_hmac_sha512() {
    run::<SHA512>("PBKDF2_HMAC_SHA512")
}

fn bench_pbkdf2_hmac_sha3_256() {
    run::<SHA3_256>("PBKDF2_HMAC_SHA3_256")
}

fn main() {
    bench_pbkdf2_hmac_sha256()
    // bench_do_nothing()
    // bench_pbkdf2_hmac_sha512()
    // bench_pbkdf2_hmac_sha3_256()
}
