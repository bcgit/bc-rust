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
//! because massif reports the peak across the whole process. The operations themselves are the
//! shared `block_cipher_mem_usage` harness over this cipher's permutations; this file holds the
//! keys and the choice.
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
//!
//! # XTS
//!
//! The `xts_*` benches measure `XTS_AES_128` and `XTS_AES_256`, whose figures are in their docs.
//! Those are the deepest frame chain below each `measure` instance, counted as for
//! `bench_gcm_siv_mem_usage`: a return address per hop over the `bouncycastle_*` symbols, the
//! root's own not, and no leaf's red zone. They were read from the release build's assembly for
//! `x86_64-unknown-linux-gnu`, with `main` calling `xts_all` so that none is dead-stripped:
//!
//! ```text
//! RUSTFLAGS="-C symbol-mangling-version=v0" cargo rustc --release -p mem_usage_benches \
//!     --bin bench_aes_mem_usage --target x86_64-unknown-linux-gnu -- --emit asm
//! ```
//!
//! A function's frame is its largest `.cfi_def_cfa_offset`, and the v0 names tell the generic
//! instances apart. Off Linux the link step fails for want of a Linux linker, after the `.s` files
//! are written to `target/x86_64-unknown-linux-gnu/release/deps/`.

#![allow(dead_code)]

use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::aes::{XTS_AES_128, XTS_AES_256};
use bouncycastle::cipher::modes::XTSKey;
use bouncycastle::core::hazmat::BlockPermutation;
use bouncycastle::core::symmetric_key::FromKeyMaterial;

use mem_usage_benches::block_cipher_mem_usage as bench;

const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const KEY_192: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
];
const KEY_256: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

/// `Key_1 | Key_2` for XTS-AES-128: the key of NIST's ACVP-AES-XTS-2.0 tcId 125.
const XTS_KEY_128: [u8; 32] = [
    0xc3, 0xd3, 0xdc, 0x0b, 0x7a, 0x34, 0x5c, 0xcf, 0xe4, 0x8b, 0x23, 0x20, 0x75, 0xe4, 0x72, 0x99,
    0xeb, 0xf1, 0x1e, 0x5c, 0x40, 0xe1, 0xbf, 0xe4, 0x2a, 0xcf, 0x96, 0xe1, 0x84, 0x0b, 0x73, 0x53,
];
/// `Key_1 | Key_2` for XTS-AES-256: counting bytes, whose halves differ.
const XTS_KEY_256: [u8; 64] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];
const XTS_TWEAK: [u8; 16] = [0x5a; 16];

/// The data unit the XTS benches process: seven whole blocks and seven bytes. Encryption takes the
/// four-, two- and one-block paths and then steals; decryption takes the four- and two-block paths
/// and then undoes the stealing a block at a time. The data unit is the caller's buffer, so
/// beyond which of those paths run, the call's stack does not depend on its length.
const XTS_DATA_UNIT_LEN: usize = 119;

fn print_struct_sizes() {
    bench::print_struct_size::<AES128Internal>("AES128Internal");
    bench::print_struct_size::<AES192Internal>("AES192Internal");
    bench::print_struct_size::<AES256Internal>("AES256Internal");
    bench::print_struct_size::<XTS_AES_128>("XTS_AES_128");
    bench::print_struct_size::<XTS_AES_256>("XTS_AES_256");
}

/// The XTS key, built out of line so that its frame is a sibling of the operation's.
#[inline(never)]
fn xts_load<K: FromKeyMaterial<N>, const N: usize>(bytes: &[u8; N]) -> K {
    K::from_key_material(&bench::key(bytes)).unwrap()
}

// The XTS benches keep their output out of `measure`: `black_box` holds the result inside, and the
// data unit, which is the caller's buffer, is printed after, so that the closure's frame is the
// call's and nothing else. Key construction keeps its `Result` whole, the one slot a caller of
// `from_key_material` needs, rather than unwrapping it into a second copy of the key.

/// XTS key construction: the checks on `Key_1 | Key_2`, the split, and the two key expansions.
fn xts_key_construction<K: FromKeyMaterial<N>, const N: usize>(name: &str, bytes: &[u8; N]) {
    eprintln!("{name}::from_key_material");
    let material = bench::key(bytes);
    bench::measure(|| {
        let key = K::from_key_material(&material);
        assert!(core::hint::black_box(&key).is_ok());
    });
    print!("{}", core::mem::size_of::<K>());
}

/// XTS `encrypt_inplace` of one [`XTS_DATA_UNIT_LEN`]-byte data unit.
fn xts_encrypt<P: BlockPermutation<16>, const N: usize>(name: &str, bytes: &[u8; N])
where
    XTSKey<P>: FromKeyMaterial<N>,
{
    eprintln!("{name}::encrypt_inplace, {XTS_DATA_UNIT_LEN} B");
    let key: XTSKey<P> = xts_load(bytes);
    let mut data_unit = [0x11u8; XTS_DATA_UNIT_LEN];
    bench::measure(|| {
        core::hint::black_box(key.encrypt_inplace(&XTS_TWEAK, &mut data_unit).unwrap());
    });
    print!("{data_unit:x?}");
}

/// XTS `decrypt_inplace` of one [`XTS_DATA_UNIT_LEN`]-byte data unit.
fn xts_decrypt<P: BlockPermutation<16>, const N: usize>(name: &str, bytes: &[u8; N])
where
    XTSKey<P>: FromKeyMaterial<N>,
{
    eprintln!("{name}::decrypt_inplace, {XTS_DATA_UNIT_LEN} B");
    let key: XTSKey<P> = xts_load(bytes);
    let mut data_unit = [0x11u8; XTS_DATA_UNIT_LEN];
    bench::measure(|| {
        core::hint::black_box(key.decrypt_inplace(&XTS_TWEAK, &mut data_unit).unwrap());
    });
    print!("{data_unit:x?}");
}

/// Every XTS bench, so that a build with `main` calling this keeps all of them for the
/// frame-layout remarks.
fn xts_all() {
    xts_key_construction::<XTS_AES_128, 32>("XTS_AES_128", &XTS_KEY_128);
    xts_encrypt::<AES128Internal, 32>("XTS_AES_128", &XTS_KEY_128);
    xts_decrypt::<AES128Internal, 32>("XTS_AES_128", &XTS_KEY_128);
    xts_key_construction::<XTS_AES_256, 64>("XTS_AES_256", &XTS_KEY_256);
    xts_encrypt::<AES256Internal, 64>("XTS_AES_256", &XTS_KEY_256);
    xts_decrypt::<AES256Internal, 64>("XTS_AES_256", &XTS_KEY_256);
}

fn main() {
    print_struct_sizes()
    // bench::do_nothing()
    // bench::all::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::key_expansion::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::encrypt_block::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::decrypt_block::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::encrypt_2blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::decrypt_2blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::encrypt_4blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::decrypt_4blocks::<AES128Internal, 16>("AES128Internal", &KEY_128)
    // bench::all::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::key_expansion::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::encrypt_block::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::decrypt_block::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::encrypt_2blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::decrypt_2blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::encrypt_4blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::decrypt_4blocks::<AES192Internal, 24>("AES192Internal", &KEY_192)
    // bench::all::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::key_expansion::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::encrypt_block::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::decrypt_block::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::encrypt_2blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::decrypt_2blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::encrypt_4blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // bench::decrypt_4blocks::<AES256Internal, 32>("AES256Internal", &KEY_256)
    // xts_all()
    // xts_key_construction::<XTS_AES_128, 32>("XTS_AES_128", &XTS_KEY_128)
    // xts_encrypt::<AES128Internal, 32>("XTS_AES_128", &XTS_KEY_128)
    // xts_decrypt::<AES128Internal, 32>("XTS_AES_128", &XTS_KEY_128)
    // xts_key_construction::<XTS_AES_256, 64>("XTS_AES_256", &XTS_KEY_256)
    // xts_encrypt::<AES256Internal, 64>("XTS_AES_256", &XTS_KEY_256)
    // xts_decrypt::<AES256Internal, 64>("XTS_AES_256", &XTS_KEY_256)
}
