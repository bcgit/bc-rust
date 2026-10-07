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

use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::aes::{AES_CCM_128_Key, AES_CCM_192_Key, AES_CCM_256_Key};
use bouncycastle::cipher::modes::{Ccm, CcmDecryptor, CcmEncryptor};
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::traits::SymmetricCipherKey;
use bouncycastle::core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

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

type Aes128Ccm<Dir> = Ccm<AES128Internal, Dir, AES_CCM_128_Key, 16, 16, NONCE_LEN, TAG_LEN>;
type Aes128CcmEncryptor =
    CcmEncryptor<AES128Internal, AES_CCM_128_Key, 16, 16, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>;
type Aes128CcmDecryptor =
    CcmDecryptor<AES128Internal, AES_CCM_128_Key, 16, 16, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>;

fn key() -> AES_CCM_128_Key {
    AES_CCM_128_Key::from_bytes(&[0x42u8; 16]).unwrap()
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
/// The two things to notice are that `Ccm` does not depend on `NONCE_LEN` or `TAG_LEN` -- the nonce
/// lives inside the counter template and the tag is assembled at finalization -- and that the
/// trait adapters are `Ccm` plus the `AAD_LEN` buffer and a few words, at any `DATA_LEN`.
#[inline(never)]
fn print_struct_sizes() {
    use core::mem::size_of;

    eprintln!("--- Ccm: permutation + 3 blocks + 5 counters, independent of nonce/tag length ---");
    eprintln!("Ccm<AES128Internal, .., 12, 16>  {:>7} B", size_of::<Aes128Ccm<Encrypting>>());
    eprintln!(
        "Ccm<AES128Internal, .., 7, 4>    {:>7} B",
        size_of::<Ccm<AES128Internal, Encrypting, AES_CCM_128_Key, 16, 16, 7, 4>>()
    );
    eprintln!(
        "Ccm<AES128Internal, .., 13, 16>  {:>7} B",
        size_of::<Ccm<AES128Internal, Encrypting, AES_CCM_128_Key, 16, 16, 13, 16>>()
    );
    eprintln!(
        "Ccm<AES192Internal, .., 12, 16>  {:>7} B",
        size_of::<Ccm<AES192Internal, Encrypting, AES_CCM_192_Key, 24, 16, 12, 16>>()
    );
    eprintln!(
        "Ccm<AES256Internal, .., 12, 16>  {:>7} B",
        size_of::<Ccm<AES256Internal, Encrypting, AES_CCM_256_Key, 32, 16, 12, 16>>()
    );
    eprintln!("Decrypting is the same size:");
    eprintln!("Ccm<AES128Internal, Decrypting>  {:>7} B", size_of::<Aes128Ccm<Decrypting>>());

    eprintln!("--- the trait adapters: Ccm + AAD_LEN + bookkeeping, independent of DATA_LEN ---");
    eprintln!("CcmEncryptor<.., {AAD_LEN}, {DATA_LEN}> {:>7} B", size_of::<Aes128CcmEncryptor>());
    eprintln!("CcmDecryptor<.., {AAD_LEN}, {DATA_LEN}> {:>7} B", size_of::<Aes128CcmDecryptor>());
    eprintln!(
        "CcmEncryptor<.., 64, 240>      {:>7} B",
        size_of::<CcmEncryptor<AES128Internal, AES_CCM_128_Key, 16, 16, NONCE_LEN, TAG_LEN, 64, 240>>(
        )
    );

    print!("{}", size_of::<Aes128Ccm<Encrypting>>());
}

/// The direct path over the message: `Ccm` plus the caller's own buffers, and nothing else.
/// This is the baseline for `bench_streaming_encrypt`, `bench_streaming_decrypt` and
/// `bench_oneshot_encrypt_out_detached`.
#[inline(never)]
fn bench_direct_encrypt_detached() {
    eprintln!("Ccm::encrypt_detached_out, {MESSAGE_LEN} B");

    let k = key();
    let nonce = [0x24u8; NONCE_LEN];
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (_, tag) =
        Aes128Ccm::<Encrypting>::encrypt_detached_out(&k, &nonce, &[], plaintext, &mut ciphertext)
            .unwrap();
    print!("{:x?}", &tag);
}

/// The same message through the trait encryptor's **streaming** methods: `do_encrypt_init`
/// builds the value, `do_update_out` writes each chunk's ciphertext straight out, and the final
/// returns the tag. The caller's two arrays are the whole of the stack that scales.
#[inline(never)]
fn bench_streaming_encrypt() {
    eprintln!(
        "CcmEncryptor do_encrypt_init/do_update_out/do_encrypt_final_detachedtag_out, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = key();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (mut enc, _nonce) = Aes128CcmEncryptor::do_encrypt_init(&k).unwrap();
    let mut written = 0;
    for chunk in plaintext.chunks(1024) {
        written += enc.do_encrypt_out(chunk, &mut ciphertext[written..]).unwrap();
    }
    let mut last = [0u8; TAG_LEN];
    let (_, tag) = enc.do_encrypt_final_detachedtag_out(&mut last).unwrap();
    print!("{:x?}", &tag);
}

/// The decrypting side of the same comparison, with the tag inline: the decryptor releases each
/// chunk's plaintext as it arrives into the caller's `opened` array and holds back only the tag.
///
/// The sealed message is produced in place with the direct streaming API, so that the bench
/// holds two arrays -- `sealed` and `opened` -- like `bench_direct_encrypt_detached` does, and
/// only the streaming decrypt is under measurement.
#[inline(never)]
fn bench_streaming_decrypt() {
    eprintln!(
        "CcmDecryptor do_decrypt_init/do_update_out/do_decrypt_final, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = key();
    let nonce = [0x24u8; NONCE_LEN];
    let mut sealed = [0u8; MESSAGE_LEN + TAG_LEN];
    sealed[..MESSAGE_LEN].fill(core::hint::black_box(0xA5));
    let mut ccm = Aes128Ccm::<Encrypting>::new(&k, &nonce, &[], MESSAGE_LEN).unwrap();
    ccm.do_encrypt(&mut sealed[..MESSAGE_LEN]).unwrap();
    let tag = ccm.do_encrypt_final().unwrap();
    sealed[MESSAGE_LEN..].copy_from_slice(&tag);
    let sealed = core::hint::black_box(&sealed);

    let mut opened = [0u8; MESSAGE_LEN];
    let mut dec = Aes128CcmDecryptor::do_decrypt_init(&k, &nonce).unwrap();
    let mut written = 0;
    for chunk in sealed.chunks(1024) {
        written += dec.do_decrypt_out(chunk, &mut opened[written..]).unwrap();
    }
    let (_, m) = dec.do_decrypt_final().unwrap();
    print!("{}", written + m);
}

/// The trait encryptor's **one-shot**, which is the trait's own, provided over the streaming
/// adapter, so it should measure what `bench_streaming_encrypt` measures: the adapter value and
/// the DRBG the nonce is drawn from above `bench_direct_encrypt_detached`.
#[inline(never)]
fn bench_oneshot_encrypt_out_detached() {
    eprintln!("CcmEncryptor::encrypt_detached_out, {MESSAGE_LEN} B");

    let k = key();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (_, _, tag) =
        Aes128CcmEncryptor::encrypt_detached_out(&k, &[], plaintext, &mut ciphertext).unwrap();
    print!("{:x?}", &tag);
}

/// The streaming direct path, which is what a caller in SP 800-38C Sec 3's packet environment
/// with a run-time length should use: the payload length is declared up front and encrypted in
/// place, so peak stack is the `Ccm` value plus one array.
#[inline(never)]
fn bench_direct_streaming() {
    eprintln!("Ccm::do_encrypt_update, {MESSAGE_LEN} B in 1 KiB chunks");

    let k = key();
    let nonce = [0x24u8; NONCE_LEN];
    let mut data = message();
    let data = core::hint::black_box(&mut data);
    let mut ccm = Aes128Ccm::<Encrypting>::new(&k, &nonce, &[], data.len()).unwrap();
    for chunk in data.chunks_mut(1024) {
        ccm.do_encrypt(chunk).unwrap();
    }
    let tag = ccm.do_encrypt_final().unwrap();
    print!("{:x?}", &tag);
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    match which.as_str() {
        "nothing" => bench_do_nothing(),
        "direct" => bench_direct_encrypt_detached(),
        "stream_enc" => bench_streaming_encrypt(),
        "stream_dec" => bench_streaming_decrypt(),
        "oneshot" => bench_oneshot_encrypt_out_detached(),
        "direct_stream" => bench_direct_streaming(),
        _ => print_struct_sizes(),
    }
}
