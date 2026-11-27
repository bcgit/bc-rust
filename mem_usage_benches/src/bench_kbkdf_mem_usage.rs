//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_kbkdf_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The `kbkdf` module docs' stack table is the deepest frame chain from each [`measure`] instance
//! down, as for the ECC CDH harness, with `main` calling that bench alone: one build per bench.
//! With every bench called from `main` the HMAC-SHA2 figures come out up to 720 bytes larger.
//!
//! Note: print!() forces the compiler not to optimize away the actual code. The name of the bench
//! goes to stderr so that the junk on stdout can be piped to /dev/null.
//!
//! Main is at the bottom, controls which bench is actually run.
//!
//! Each bench derives 64 bytes from a 32-byte key-derivation key through the concrete type, so
//! that the call is not through a vtable the stack-table method cannot follow.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;

use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::traits::KDF;
use bouncycastle::symmetric::kbkdf::{
    CounterSize, IterationCounterPosition, KDF_Counter_CMAC_AES256, KDF_Counter_HMAC_SHA3_256,
    KDF_Counter_HMAC_SHA256, KDF_Counter_HMAC_SHA512, KDF_DoublePipeline_HMAC_SHA256,
    KDF_DoublePipeline_HMAC_SHA512, KDF_Feedback_HMAC_SHA256, KDF_Feedback_HMAC_SHA512,
    KDF_KMAC128, KDF_KMAC256,
};

const FIXED: &[u8] = b"label\0context: sixteen bytes+";
const COUNTER: (CounterSize, IterationCounterPosition) =
    (CounterSize::_32bit, IterationCounterPosition::AfterIterationVariable);

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

/// The key-derivation key, built out of line so its temporaries are popped before the operation.
#[inline(never)]
fn k_in() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&black_box([0x5A; 32]), KeyType::CryptographicRandom)
        .unwrap()
}

/// Derives 64 bytes with `kdf` under [`measure`] and prints them.
fn run(name: &str, kdf: &impl KDF) {
    eprintln!("{name}");
    let key = k_in();
    let mut out = KeyMaterial::<64>::new();
    measure(|| {
        kdf.derive_key_out(&key, black_box(FIXED), 64, &mut out).unwrap();
    });
    print!("{:x?}", out.ref_to_bytes());
}

fn bench_counter_hmac_sha256() {
    run("KDF_Counter_HMAC_SHA256", &KDF_Counter_HMAC_SHA256::new())
}

fn bench_counter_hmac_sha512() {
    run("KDF_Counter_HMAC_SHA512", &KDF_Counter_HMAC_SHA512::new())
}

fn bench_counter_hmac_sha3_256() {
    run("KDF_Counter_HMAC_SHA3_256", &KDF_Counter_HMAC_SHA3_256::new())
}

fn bench_counter_cmac_aes256() {
    run("KDF_Counter_CMAC_AES256", &KDF_Counter_CMAC_AES256::new())
}

fn bench_feedback_hmac_sha256() {
    run(
        "KDF_Feedback_HMAC_SHA256",
        &KDF_Feedback_HMAC_SHA256::with_counter(b"", COUNTER.0, COUNTER.1),
    )
}

fn bench_feedback_hmac_sha512() {
    run(
        "KDF_Feedback_HMAC_SHA512",
        &KDF_Feedback_HMAC_SHA512::with_counter(b"", COUNTER.0, COUNTER.1),
    )
}

fn bench_double_pipeline_hmac_sha256() {
    run(
        "KDF_DoublePipeline_HMAC_SHA256",
        &KDF_DoublePipeline_HMAC_SHA256::with_counter(COUNTER.0, COUNTER.1),
    )
}

fn bench_double_pipeline_hmac_sha512() {
    run(
        "KDF_DoublePipeline_HMAC_SHA512",
        &KDF_DoublePipeline_HMAC_SHA512::with_counter(COUNTER.0, COUNTER.1),
    )
}

fn bench_kmac128() {
    run("KDF_KMAC128", &KDF_KMAC128::new(b"KDF"))
}

fn bench_kmac256() {
    run("KDF_KMAC256", &KDF_KMAC256::new(b"KDF"))
}

fn main() {
    bench_counter_hmac_sha256()
    // bench_do_nothing()
    // bench_counter_hmac_sha512()
    // bench_counter_hmac_sha3_256()
    // bench_counter_cmac_aes256()
    // bench_feedback_hmac_sha256()
    // bench_feedback_hmac_sha512()
    // bench_double_pipeline_hmac_sha256()
    // bench_double_pipeline_hmac_sha512()
    // bench_kmac128()
    // bench_kmac256()
}
