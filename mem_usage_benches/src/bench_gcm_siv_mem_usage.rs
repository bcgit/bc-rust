//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_gcm_siv_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! As for `bench_aes_mem_usage`, massif cannot see these: a call needs well under the 7.7 kB the
//! process's own start-up reaches. The figures in `bouncycastle-aes`'s `AES_GCM_SIV_128` docs are
//! the deepest frame chain below each [`measure`] instance, from a release build with
//! `RUSTFLAGS="-C remark=prologepilog -C remark=stack-frame-layout"` (the "N stack bytes in
//! function" lines) and the binary's call graph (`objdump -d`), summed with a return address per
//! hop over the `bouncycastle_*` symbols; `main` calls `bench_all` for that build so none is
//! dead-stripped. The message buffer is the caller's and is not in the figure.
//!
//! Note: print!() is used to force the compiler not to optimize away the actual code.
//! The important stuff for benchmarking goes to stderr so the junk can be piped to /dev/null.
//!
//! Main is at the bottom, and controls which of these actually runs.

#![allow(dead_code)]

use bouncycastle::aes::{AES_GCM_SIV_128, AES_GCM_SIV_256, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::symmetric_key::{
    AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey, FromKeyMaterial,
};

/// The message length. The mode works in the caller's buffer, so its own stack does not depend
/// on this; four blocks, a pair and a partial block reach every path of the counter mode (its
/// four-block and two-block loops) and of POLYVAL.
const MESSAGE_LEN: usize = 120;

const NONCE: [u8; GCM_SIV_NONCE_LEN] = [0x24; GCM_SIV_NONCE_LEN];

/// Runs the operation under measurement out of line, so that its frames sit below one symbol
/// the stack-table method (see the module docs) can root a call chain at.
#[inline(never)]
fn measure<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// Key material, out of line so its frame is a sibling of the operation's.
#[inline(never)]
fn material<const N: usize>() -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[0x42u8; N], KeyType::SymmetricCipherKey).unwrap()
}

/// The key object, built out of line so that its frame is a sibling of the operation's.
#[inline(never)]
fn key<K: FromKeyMaterial<N>, const N: usize>() -> K {
    K::from_key_material(&material::<N>()).unwrap()
}

/// The message, filled at run time so that it is a stack array in every bench alike.
#[inline(never)]
fn message() -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m.fill(core::hint::black_box(0xA5));
    m
}

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
#[inline(never)]
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// The persistent cost: a key is its expanded schedule.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("size_of<AES_GCM_SIV_128>: {}", size_of::<AES_GCM_SIV_128>());
    println!("size_of<AES_GCM_SIV_256>: {}", size_of::<AES_GCM_SIV_256>());
}

/// Key construction: validation and the one key expansion a key object does.
fn key_construction<K: FromKeyMaterial<N>, const N: usize>(name: &str) {
    eprintln!("{name}::from_key_material");
    let material = material::<N>();
    let key = measure(|| K::from_key_material(&material).unwrap());
    print!("{}", core::mem::size_of_val(core::hint::black_box(&key)));
}

/// Encryption in place under a supplied nonce: the key derivation, the second key expansion,
/// POLYVAL and the counter mode.
fn encrypt<K, const N: usize>(name: &str)
where
    K: FromKeyMaterial<N> + AeadInPlaceEncryptionKey<N, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>,
{
    eprintln!("{name}::encrypt_detached_inplace_nonce, {MESSAGE_LEN} B");
    let key: K = key();
    let mut buf = message();
    let tag = measure(|| key.encrypt_detached_inplace_nonce(&NONCE, &[], &mut buf).unwrap());
    print!("{buf:x?}{tag:x?}");
}

/// Decryption in place; the sealed message is made out of line, so only the decryption is under
/// [`measure`].
fn decrypt<K, const N: usize>(name: &str)
where
    K: FromKeyMaterial<N>
        + AeadInPlaceEncryptionKey<N, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>
        + AeadInPlaceDecryptionKey<N, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>,
{
    eprintln!("{name}::decrypt_detached_inplace, {MESSAGE_LEN} B");
    let key: K = key();
    let mut buf = message();
    let tag = key.encrypt_detached_inplace_nonce(&NONCE, &[], &mut buf).unwrap();
    measure(|| key.decrypt_detached_inplace(&NONCE, &[], &mut buf, &tag).unwrap());
    print!("{buf:x?}");
}

#[inline(never)]
fn bench_aes128_key_construction() {
    key_construction::<AES_GCM_SIV_128, 16>("AES_GCM_SIV_128");
}

#[inline(never)]
fn bench_aes128_encrypt() {
    encrypt::<AES_GCM_SIV_128, 16>("AES_GCM_SIV_128");
}

#[inline(never)]
fn bench_aes128_decrypt() {
    decrypt::<AES_GCM_SIV_128, 16>("AES_GCM_SIV_128");
}

#[inline(never)]
fn bench_aes256_key_construction() {
    key_construction::<AES_GCM_SIV_256, 32>("AES_GCM_SIV_256");
}

#[inline(never)]
fn bench_aes256_encrypt() {
    encrypt::<AES_GCM_SIV_256, 32>("AES_GCM_SIV_256");
}

#[inline(never)]
fn bench_aes256_decrypt() {
    decrypt::<AES_GCM_SIV_256, 32>("AES_GCM_SIV_256");
}

/// Every bench, so that a build with `main` calling this keeps all of them for the frame-layout
/// remarks.
fn bench_all() {
    bench_aes128_key_construction();
    bench_aes128_encrypt();
    bench_aes128_decrypt();
    bench_aes256_key_construction();
    bench_aes256_encrypt();
    bench_aes256_decrypt();
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_all()
    // bench_aes128_key_construction()
    // bench_aes128_encrypt()
    // bench_aes128_decrypt()
    // bench_aes256_key_construction()
    // bench_aes256_encrypt()
    // bench_aes256_decrypt()
}
