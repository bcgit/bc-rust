//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ccm_mem_usage > /dev/null
//!
//! ms_print massif.out.835000
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ccm_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! Note: print!() is used to force the compiler not to optimize away the actual code.
//! The important stuff for benchmarking goes to stderr so the junk can be piped to /dev/null.
//!
//! # What it measures
//!
//! Peak stack from `ms_print`, `--heap=no --stacks=yes`, release, on x86-64, at
//! `DATA_LEN = 16384` and `AAD_LEN = 64`; every bench processes the same `DATA_LEN` bytes.
//! `bench_do_nothing`'s figure is the process's own start-up, below which nothing is visible; the
//! frame is sized to clear it by a wide margin so the comparisons are legible:

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::aes::AES128Key;
use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::cipher::modes::{CCM, CCMFrame, CcmDecryptor, CcmEncryptor};
use bouncycastle::core::hazmat::{
    AeadPacketDecryptMode, AeadPacketEncryptMode, ElectronicCodeBook,
};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle::core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle::rng::HashDRBG_SHA512;

/// The parameters the ACVP vectors and most protocols use: 12-byte nonce, 16-byte tag.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The adapters' frame: 16 KiB. Larger than any packet CCM was designed for, on purpose:
/// massif reports a peak of about 7.7 KB for `bench_do_nothing` -- the process's own start-up --
/// and anything that peaks below that is invisible, so at 4 KiB the direct and trait paths all
/// read as "7.7 KB" and nothing can be compared. At 16 KiB every path clears that floor by a
/// wide margin. The AAD capacity is a protocol-header-sized 64 bytes; no bench sends AAD.
const DATA_LEN: usize = 16384;
const AAD_LEN: usize = 64;
const MESSAGE_LEN: usize = DATA_LEN;

/// The mode's in-place one-shots over the keyed permutation: the direct path.
type Aes128CcmMode = CCM<NONCE_LEN, TAG_LEN>;
/// The key bound to the fixed frame, whose streams are the pair below.
type Aes128CcmFrameKey = AES128Key<CCMFrame<NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>>;
type Aes128CcmEncryptor =
    CcmEncryptor<AES128Internal, 16, 16, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>;
type Aes128CcmDecryptor =
    CcmDecryptor<AES128Internal, 16, 16, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>;

fn key<const N: usize>() -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[0x42u8; N], KeyType::SymmetricCipherKey).unwrap()
}

fn perm() -> AES128Internal {
    AES128Internal::new(&key::<16>()).unwrap()
}

fn frame_key() -> Aes128CcmFrameKey {
    Aes128CcmFrameKey::from_key_material(&key::<16>()).unwrap()
}

/// The message every bench processes, filled at run time and then only ever reached through a
/// `black_box`ed reference, so that it is a whole stack array in every bench alike. Without that,
/// a `[0xA5; N]` literal is a constant the compiler may keep in read-only data in one bench, or
/// fuse straight into the copy `encrypt_detached_out` makes in another, and the two paths that do
/// identical work measured a whole `MESSAGE_LEN` apart.
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

/// Prints the in-memory size of each CCM value: the persistent cost of holding one open.
///
/// A mode-bound key is the keyed permutation alone; the trait pair is the mode's packet state
/// (the permutation, three blocks and five counters, independent of `NONCE_LEN` and `TAG_LEN`)
/// plus the `AAD_LEN` buffer and a few words, at any `DATA_LEN`.
#[inline(never)]
fn print_struct_sizes() {
    use core::mem::size_of;

    eprintln!("--- the key state: the keyed permutation alone ---");
    eprintln!("AES128Internal  {:>7} B", size_of::<AES128Internal>());
    eprintln!("AES192Internal  {:>7} B", size_of::<AES192Internal>());
    eprintln!("AES256Internal  {:>7} B", size_of::<AES256Internal>());

    eprintln!(
        "--- the trait pair: packet state + AAD_LEN + bookkeeping, independent of DATA_LEN ---"
    );
    eprintln!("CcmEncryptor<.., {AAD_LEN}, {DATA_LEN}> {:>7} B", size_of::<Aes128CcmEncryptor>());
    eprintln!("CcmDecryptor<.., {AAD_LEN}, {DATA_LEN}> {:>7} B", size_of::<Aes128CcmDecryptor>());
    eprintln!(
        "CcmEncryptor<.., 64, 240>      {:>7} B",
        size_of::<CcmEncryptor<AES128Internal, 16, 16, NONCE_LEN, TAG_LEN, 64, 240>>()
    );
    eprintln!(
        "CcmEncryptor<.., 7, 4, ..>     {:>7} B",
        size_of::<CcmEncryptor<AES128Internal, 16, 16, 7, 4, AAD_LEN, DATA_LEN>>()
    );
    eprintln!(
        "CcmEncryptor<AES256Internal>   {:>7} B",
        size_of::<CcmEncryptor<AES256Internal, 32, 16, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>>()
    );

    print!("{}", size_of::<Aes128CcmEncryptor>());
}

/// The in-place path over the message: the packet state plus the caller's one buffer, and
/// nothing else. This is the baseline for `bench_streaming_encrypt`, `bench_streaming_decrypt`
/// and `bench_oneshot_encrypt_out_detached`.
#[inline(never)]
fn bench_in_place_encrypt() {
    eprintln!("CCM::encrypt_detached_in_place_nonce, {MESSAGE_LEN} B");

    let perm = perm();
    let nonce = [0x24u8; NONCE_LEN];
    let mut data = message();
    let data = core::hint::black_box(&mut data);
    let tag = Aes128CcmMode::encrypt_detached_in_place_nonce(&perm, &nonce, &[], data).unwrap();
    print!("{:x?}", &tag);
}

/// The same message through the frame key's **streaming** encryptor: `create_encryptor` builds
/// the value under a drawn nonce, `do_encrypt_out` writes each chunk's ciphertext straight out,
/// and the final returns the tag. The caller's two arrays are the whole of the stack that scales.
#[inline(never)]
fn bench_streaming_encrypt() {
    eprintln!(
        "CcmEncryptor create_encryptor/do_encrypt_out/do_encrypt_final_detached_out, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = frame_key();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (mut enc, _nonce) = k.create_encryptor(&mut rng).unwrap();
    let mut written = 0;
    for chunk in plaintext.chunks(1024) {
        written += enc.do_encrypt_out(chunk, &mut ciphertext[written..]).unwrap();
    }
    let mut last = [0u8; TAG_LEN];
    let (_, tag) = enc.do_encrypt_final_detached_out(&mut last).unwrap();
    print!("{:x?}", &tag);
}

/// The decrypting side of the same comparison, with the tag inline: the decryptor releases each
/// chunk's plaintext as it arrives into the caller's `opened` array and holds back only the tag.
///
/// The sealed message is produced in place with the mode's one-shot, so that the bench holds
/// two arrays -- `sealed` and `opened` -- and only the streaming decrypt is under measurement.
#[inline(never)]
fn bench_streaming_decrypt() {
    eprintln!(
        "CcmDecryptor create_decryptor/do_decrypt_out/do_decrypt_final, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = frame_key();
    let nonce = [0x24u8; NONCE_LEN];
    let mut sealed = [0u8; MESSAGE_LEN + TAG_LEN];
    sealed[..MESSAGE_LEN].fill(core::hint::black_box(0xA5));
    let tag = Aes128CcmMode::encrypt_detached_in_place_nonce(
        &perm(),
        &nonce,
        &[],
        &mut sealed[..MESSAGE_LEN],
    )
    .unwrap();
    sealed[MESSAGE_LEN..].copy_from_slice(&tag);
    let sealed = core::hint::black_box(&sealed);

    let mut opened = [0u8; MESSAGE_LEN];
    let mut dec = k.create_decryptor(&nonce);
    let mut written = 0;
    for chunk in sealed.chunks(1024) {
        written += dec.do_decrypt_out(chunk, &mut opened[written..]).unwrap();
    }
    let (_, m) = dec.do_decrypt_final().unwrap();
    print!("{}", written + m);
}

/// The frame key's **one-shot**, written over its stream, into the caller's output buffer under
/// a nonce drawn from the caller's DRBG, so it should measure what `bench_streaming_encrypt`
/// measures plus that DRBG.
#[inline(never)]
fn bench_oneshot_encrypt_out_detached() {
    eprintln!("AES128Key<CCMFrame>::encrypt_detached_out, {MESSAGE_LEN} B");

    let k = frame_key();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (_, _, tag) = k.encrypt_detached_out(&mut rng, &[], plaintext, &mut ciphertext).unwrap();
    print!("{:x?}", &tag);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_in_place_encrypt()
    // bench_streaming_encrypt()
    // bench_streaming_decrypt()
    // bench_oneshot_encrypt_out_detached()
}
