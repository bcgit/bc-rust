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
//! Main is at the bottom, and controls which of these actually runs -- measure one at a time,
//! because massif reports the peak across the whole process.
//!
//! # Why CCM gets a harness when the other modes do not
//!
//! CCM (NIST SP 800-38C) is the only mode in `bouncycastle-modes` with a non-trivial stack
//! profile, and it has it for a specific, avoidable reason.
//!
//! `Ccm` itself is boring: 256 B for AES-128, independent of message length, nonce length and tag
//! length, and per-byte work that touches a constant amount of stack. `print_struct_sizes` records
//! those, and they are the numbers to use.
//!
//! **`CcmEncryptor` / `CcmDecryptor` are the interesting case.** They exist to satisfy
//! `AEADCipherEncryptor` / `AEADCipherDecryptor`, whose `do_encrypt_init` is handed a key and no
//! length; CCM cannot form `B0` -- and so cannot authenticate anything -- until it knows the total
//! payload length (SP 800-38C Appendix A.2.1), so their **streaming** methods buffer the whole
//! message. That is `2 * FINAL_LEN` in the value (the crate docs' "4304 B at `FINAL_LEN = 2048`",
//! which `print_struct_sizes` confirms), and on top of it `do_final` returns a third
//! `[u8; FINAL_LEN]` by value. `bench_streaming_encrypt` / `bench_streaming_encrypt_detached` /
//! `bench_streaming_decrypt` drive that path -- `do_*_init`, `do_update_out`, then a final -- and
//! are what measure it, since it is the one memory claim in that crate large enough to matter.
//!
//! The adapters' **one-shots are not the streaming path**: `encrypt_out_detached` and its
//! siblings override the trait defaults and run `Ccm` directly, so the crate docs claim they cost
//! the same as `Ccm` regardless of `FINAL_LEN`. `bench_oneshot_encrypt_out_detached` checks that
//! claim, and must *not* be mistaken for a measurement of the buffers -- it never touches them.
//!
//! # What it measures
//!
//! Peak stack from `ms_print`, `--heap=no --stacks=yes`, release, on x86-64 with the pinned
//! nightly, at `FINAL_LEN = 16384`; every bench processes the same `FINAL_LEN - TAG_LEN` bytes.
//! `bench_do_nothing`'s 7.7 KB is the process's own start-up and is the floor below which nothing
//! is visible (see `FINAL_LEN` for why the harness is sized to clear it):
//!
//! ```text
//! bench_do_nothing                       7 680 B
//! bench_direct_encrypt_detached         34 864 B   two 16 KiB arrays (message, ciphertext) + frames
//! bench_direct_streaming                18 512 B   one 16 KiB array, encrypted in place
//! bench_oneshot_encrypt_out_detached    36 184 B   = direct + 1.3 KB: the DRBG the nonce is drawn from
//! bench_streaming_encrypt              134 968 B   ~ 7 * FINAL_LEN above the message array
//! bench_streaming_encrypt_detached     135 000 B   the same
//! bench_streaming_decrypt              149 976 B   ~ 7 * FINAL_LEN above the message and sealed arrays
//! ```
//!
//! Two things to take from that. The one-shot really does bypass the buffers: it is within the
//! cost of a DRBG of the direct path, at any `FINAL_LEN`. And the streaming path costs about
//! **`7 * FINAL_LEN`**, not the `3 * FINAL_LEN` a count of the arrays -- two in the value, one
//! returned -- would suggest: every method that finishes the flow takes the `2 * FINAL_LEN` value
//! by value, and each such move that the optimizer does not elide is another `2 * FINAL_LEN` on
//! the stack. That the detached final, which has one array fewer to return, measures the same is
//! consistent with the moves rather than the arrays being what dominates. It is a property of
//! passing a large value by value through the trait's consuming finals, not of CCM, and a caller
//! who cares should use the inherent `Ccm` API, which is the `bench_direct_streaming` line.
//!
//! The comparisons to draw, all on the *same* message:
//!
//! * `bench_streaming_encrypt` against `bench_direct_encrypt_detached`: the direct path does
//!   identical cipher work with none of the buffers, so the difference is the whole cost of
//!   streaming through the generic trait;
//! * `bench_oneshot_encrypt_out_detached` against `bench_direct_encrypt_detached`: these should
//!   be within a couple of KB of each other, which is what "the one-shots bypass the buffer" means
//!   in numbers.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::aes::aes_internal::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle::modes::{Ccm, CcmDecryptor, CcmEncryptor, Decrypting, Encrypting};

/// The parameters the ACVP vectors and most protocols use: 12-byte nonce, 16-byte tag.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The adapters' `FINAL_LEN`: 16 KiB. Larger than any packet CCM was designed for, on purpose:
/// massif reports a peak of about 7.7 KB for `bench_do_nothing` -- the process's own start-up --
/// and anything that peaks below that is invisible, so at 4 KiB the direct and one-shot paths all
/// read as "7.7 KB" and nothing can be compared. At 16 KiB every path clears that floor by a
/// wide margin and the multiples of `FINAL_LEN` are legible. The streaming capacity is
/// `FINAL_LEN - TAG_LEN`, so the message every bench sends is that.
const FINAL_LEN: usize = 16384;
const MESSAGE_LEN: usize = FINAL_LEN - TAG_LEN;

type Aes128Ccm<Dir> = Ccm<AES128Internal, Dir, 16, 16, NONCE_LEN, TAG_LEN>;
type Aes128CcmEncryptor = CcmEncryptor<AES128Internal, 16, 16, NONCE_LEN, TAG_LEN, FINAL_LEN>;
type Aes128CcmDecryptor = CcmDecryptor<AES128Internal, 16, 16, NONCE_LEN, TAG_LEN, FINAL_LEN>;

fn key<const N: usize>() -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[0x42u8; N], KeyType::SymmetricCipherKey).unwrap()
}

/// The message every bench processes, filled at run time and then only ever reached through a
/// `black_box`ed reference, so that it is a whole stack array in every bench alike. Without that,
/// a `[0xA5; N]` literal is a constant the compiler may keep in read-only data in one bench, or
/// fuse straight into the copy `encrypt_out_detached` makes in another, and the two paths that do
/// identical work measured a whole `MESSAGE_LEN` apart.
fn message() -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m.fill(core::hint::black_box(0xA5));
    m
}

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each CCM value: the persistent cost of holding one open.
///
/// The two things to notice are that `Ccm` does not depend on `NONCE_LEN` or `TAG_LEN` -- the nonce
/// lives inside the counter template and the tag is assembled at finalization -- and that the
/// buffering pair is more than an order of magnitude larger at any useful `FINAL_LEN`.
fn print_struct_sizes() {
    use core::mem::size_of;

    eprintln!("--- Ccm: permutation + 3 blocks + 4 counters, independent of nonce/tag length ---");
    eprintln!("Ccm<AES128Internal, .., 12, 16>  {:>7} B", size_of::<Aes128Ccm<Encrypting>>());
    eprintln!(
        "Ccm<AES128Internal, .., 7, 4>    {:>7} B",
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 7, 4>>()
    );
    eprintln!(
        "Ccm<AES128Internal, .., 13, 16>  {:>7} B",
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 13, 16>>()
    );
    eprintln!(
        "Ccm<AES192Internal, .., 12, 16>  {:>7} B",
        size_of::<Ccm<AES192Internal, Encrypting, 24, 16, 12, 16>>()
    );
    eprintln!(
        "Ccm<AES256Internal, .., 12, 16>  {:>7} B",
        size_of::<Ccm<AES256Internal, Encrypting, 32, 16, 12, 16>>()
    );
    eprintln!("Decrypting is the same size:");
    eprintln!("Ccm<AES128Internal, Decrypting>  {:>7} B", size_of::<Aes128Ccm<Decrypting>>());

    eprintln!("--- the buffering trait adapters: 2 * FINAL_LEN each ---");
    eprintln!("CcmEncryptor<.., {FINAL_LEN}>   {:>7} B", size_of::<Aes128CcmEncryptor>());
    eprintln!("CcmDecryptor<.., {FINAL_LEN}>   {:>7} B", size_of::<Aes128CcmDecryptor>());
    eprintln!(
        "CcmEncryptor<.., 256>     {:>7} B",
        size_of::<CcmEncryptor<AES128Internal, 16, 16, NONCE_LEN, TAG_LEN, 256>>()
    );

    print!("{}", size_of::<Aes128Ccm<Encrypting>>());
}

/// The direct, non-buffering path over the message: `Ccm` plus the caller's own buffers, and
/// nothing else. This is the baseline for both `bench_streaming_encrypt` and
/// `bench_oneshot_encrypt_out_detached`.
fn bench_direct_encrypt_detached() {
    eprintln!("Ccm::encrypt_out_detached, {MESSAGE_LEN} B");

    let k = key::<16>();
    let nonce = [0x24u8; NONCE_LEN];
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (_, tag) =
        Aes128Ccm::<Encrypting>::encrypt_out_detached(&k, &nonce, &[], plaintext, &mut ciphertext)
            .unwrap();
    print!("{:x?}", &tag);
}

/// The same message through the buffering encryptor's **streaming** methods, which is the only
/// path that touches its buffers: `do_encrypt_init` builds the `2 * FINAL_LEN` value,
/// `do_update_out` fills it and writes nothing, and `do_final` returns a third `[u8; FINAL_LEN]`
/// by value. Measures about `7 * FINAL_LEN` above the message array -- about `6 * FINAL_LEN` above
/// `bench_direct_encrypt_detached`, which also holds a ciphertext array -- see the module docs for
/// why that is more than the three arrays.
fn bench_streaming_encrypt() {
    eprintln!(
        "CcmEncryptor do_encrypt_init/do_update_out/do_final, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = key::<16>();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let (mut enc, _nonce) = Aes128CcmEncryptor::do_encrypt_init(&k).unwrap();
    for chunk in plaintext.chunks(1024) {
        enc.do_encrypt_out(chunk, &mut []).unwrap();
    }
    let (sealed, n) = enc.do_final().unwrap();
    print!("{:x?}", &sealed[n - TAG_LEN..n]);
}

/// The same flow finished with `do_final_out_detached` into the caller's `[u8; FINAL_LEN]`, the
/// shape the shared test framework drives: one fewer `FINAL_LEN` array than `do_final`, which
/// builds that buffer itself and then returns it by value.
fn bench_streaming_encrypt_detached() {
    eprintln!(
        "CcmEncryptor do_encrypt_init/do_update_out/do_final_out_detached, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = key::<16>();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let (mut enc, _nonce) = Aes128CcmEncryptor::do_encrypt_init(&k).unwrap();
    for chunk in plaintext.chunks(1024) {
        enc.do_encrypt_out(chunk, &mut []).unwrap();
    }
    let mut ciphertext = [0u8; FINAL_LEN];
    let (_, tag) = enc.do_final_out_detached(&mut ciphertext).unwrap();
    print!("{:x?}", &tag);
}

/// The decrypting side of the same comparison, with the tag inline: the decryptor buffers the
/// whole `ciphertext || tag` and `do_final` returns the `[u8; FINAL_LEN]` plaintext by value, so
/// the expectation is the same `7 * FINAL_LEN` or so, above the message and sealed arrays.
///
/// The sealed message is produced with the direct one-shot so that only the streaming decrypt
/// is under measurement; massif reports the peak across the whole process, and the direct path
/// peaks well below the streaming one.
fn bench_streaming_decrypt() {
    eprintln!(
        "CcmDecryptor do_decrypt_init/do_update_out/do_final, {MESSAGE_LEN} B in 1 KiB chunks"
    );

    let k = key::<16>();
    let nonce = [0x24u8; NONCE_LEN];
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut sealed = [0u8; FINAL_LEN];
    let n = Aes128Ccm::<Encrypting>::encrypt_out(&k, &nonce, &[], plaintext, &mut sealed).unwrap();

    let mut dec = Aes128CcmDecryptor::do_decrypt_init(&k, &nonce).unwrap();
    for chunk in sealed[..n].chunks(1024) {
        dec.do_decrypt_out(chunk, &mut []).unwrap();
    }
    let (opened, m) = dec.do_final().unwrap();
    print!("{}", opened[..m].len());
}

/// The buffering encryptor's **one-shot**, which the crate docs claim bypasses the buffers and
/// costs the same as `Ccm` regardless of `FINAL_LEN`. Measures about 1.3 KB above
/// `bench_direct_encrypt_detached` -- the DRBG it draws the nonce from -- and nowhere near
/// `bench_streaming_encrypt`.
fn bench_oneshot_encrypt_out_detached() {
    eprintln!("CcmEncryptor::encrypt_out_detached, {MESSAGE_LEN} B");

    let k = key::<16>();
    let plaintext = message();
    let plaintext = core::hint::black_box(&plaintext);
    let mut ciphertext = [0u8; MESSAGE_LEN];
    let (_, _, tag) =
        Aes128CcmEncryptor::encrypt_out_detached(&k, &[], plaintext, &mut ciphertext).unwrap();
    print!("{:x?}", &tag);
}

/// The streaming direct path, which is what a caller in SP 800-38C Sec 3's packet environment
/// should use: the payload length is declared up front and nothing is buffered, so peak stack is
/// the `Ccm` value plus one chunk.
fn bench_direct_streaming() {
    eprintln!("Ccm::do_encrypt_update, {MESSAGE_LEN} B in 1 KiB chunks");

    let k = key::<16>();
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
    print_struct_sizes()
    // bench_do_nothing()
    // bench_direct_encrypt_detached()
    // bench_streaming_encrypt()
    // bench_streaming_encrypt_detached()
    // bench_streaming_decrypt()
    // bench_oneshot_encrypt_out_detached()
    // bench_direct_streaming()
}
