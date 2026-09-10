//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//!     valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ccm_mem_usage > /dev/null
//!
//!     ms_print massif.out.835000
//!
//! or, shoved all into one line:
//!
//!     clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ccm_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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
//! payload length (SP 800-38C Appendix A.2.1), so they buffer the whole message. That costs
//! `2 * BUFFER_LEN` in the value, and the trait's provided one-shots put a third `FINAL_LEN`-byte
//! buffer on the stack, so a call to `encrypt_out` is expected to peak at roughly
//! **`3 * BUFFER_LEN`**. That figure is quoted in the crate docs; `bench_buffering_encrypt_out` is
//! what checks it, since it is the one memory claim in that crate large enough to matter.
//!
//! The comparison to draw is `bench_buffering_encrypt_out` against
//! `bench_direct_encrypt_detached` on the *same* message: the direct path does identical cipher
//! work with none of the buffers, so the difference is the whole cost of using the generic trait.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::aes::{AES_128, AES_192, AES_256};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
use bouncycastle::modes::{Ccm, CcmDecryptor, CcmEncryptor, Decrypting, Encrypting};

/// The parameters the ACVP vectors and most protocols use: 12-byte nonce, 16-byte tag.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// 4 KiB: comfortably above an 802.11 frame, the packet size CCM was designed for, and small
/// enough that `3 * BUFFER_LEN` is a sane amount of stack.
const BUFFER_LEN: usize = 4096;

type Aes128Ccm<Dir> = Ccm<AES_128, Dir, 16, 16, NONCE_LEN, TAG_LEN>;
type Aes128CcmEncryptor = CcmEncryptor<AES_128, 16, 16, NONCE_LEN, TAG_LEN, BUFFER_LEN>;
type Aes128CcmDecryptor = CcmDecryptor<AES_128, 16, 16, NONCE_LEN, TAG_LEN, BUFFER_LEN>;

fn key<const N: usize>() -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[0x42u8; N], KeyType::SymmetricCipherKey).unwrap()
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
/// buffering pair is more than an order of magnitude larger at any useful `BUFFER_LEN`.
fn print_struct_sizes() {
    use core::mem::size_of;

    eprintln!("--- Ccm: permutation + 3 blocks + 4 counters, independent of nonce/tag length ---");
    eprintln!("Ccm<AES_128, .., 12, 16>  {:>7} B", size_of::<Aes128Ccm<Encrypting>>());
    eprintln!(
        "Ccm<AES_128, .., 7, 4>    {:>7} B",
        size_of::<Ccm<AES_128, Encrypting, 16, 16, 7, 4>>()
    );
    eprintln!(
        "Ccm<AES_128, .., 13, 16>  {:>7} B",
        size_of::<Ccm<AES_128, Encrypting, 16, 16, 13, 16>>()
    );
    eprintln!(
        "Ccm<AES_192, .., 12, 16>  {:>7} B",
        size_of::<Ccm<AES_192, Encrypting, 24, 16, 12, 16>>()
    );
    eprintln!(
        "Ccm<AES_256, .., 12, 16>  {:>7} B",
        size_of::<Ccm<AES_256, Encrypting, 32, 16, 12, 16>>()
    );
    eprintln!("Decrypting is the same size:");
    eprintln!("Ccm<AES_128, Decrypting>  {:>7} B", size_of::<Aes128Ccm<Decrypting>>());

    eprintln!("--- the buffering trait adapters: 2 * BUFFER_LEN each ---");
    eprintln!("CcmEncryptor<.., 4096>    {:>7} B", size_of::<Aes128CcmEncryptor>());
    eprintln!("CcmDecryptor<.., 4096>    {:>7} B", size_of::<Aes128CcmDecryptor>());
    eprintln!(
        "CcmEncryptor<.., 256>     {:>7} B",
        size_of::<CcmEncryptor<AES_128, 16, 16, NONCE_LEN, TAG_LEN, 256>>()
    );

    print!("{}", size_of::<Aes128Ccm<Encrypting>>());
}

/// The direct, non-buffering path over a 4 KiB message: `Ccm` plus the caller's own buffers, and
/// nothing else. This is the baseline for `bench_buffering_encrypt_out`.
fn bench_direct_encrypt_detached() {
    eprintln!("Ccm::encrypt_detached, 4 KiB");

    let k = key::<16>();
    let nonce = [0x24u8; NONCE_LEN];
    let plaintext = [0xA5u8; BUFFER_LEN];
    let mut ciphertext = [0u8; BUFFER_LEN];
    let (_, tag) =
        Aes128Ccm::<Encrypting>::encrypt_detached(&k, &nonce, &[], &plaintext, &mut ciphertext)
            .unwrap();
    print!("{:x?}", &tag);
}

/// The same 4 KiB message through the buffering `AEADCipherEncryptor` one-shot.
///
/// Expected to peak at roughly `3 * BUFFER_LEN` above `bench_direct_encrypt_detached`: the
/// encryptor's own two buffers plus the `FINAL_LEN`-byte flush buffer that the trait's provided
/// `encrypt_out` puts on the stack.
fn bench_buffering_encrypt_out() {
    eprintln!("CcmEncryptor::encrypt_out, 4 KiB");

    let k = key::<16>();
    let plaintext = [0xA5u8; BUFFER_LEN];
    let mut ciphertext = [0u8; BUFFER_LEN];
    let (_, _, tag) =
        Aes128CcmEncryptor::encrypt_out(&k, &[], &plaintext, &mut ciphertext).unwrap();
    print!("{:x?}", &tag);
}

/// The decrypting side of the same comparison; `do_decrypt_final` also decrypts into the caller's
/// `FINAL_LEN` buffer before checking the tag.
fn bench_buffering_decrypt_out() {
    eprintln!("CcmDecryptor::decrypt_out, 4 KiB");

    let k = key::<16>();
    let plaintext = [0xA5u8; BUFFER_LEN];
    let mut ciphertext = [0u8; BUFFER_LEN];
    let (nonce, _, tag) =
        Aes128CcmEncryptor::encrypt_out(&k, &[], &plaintext, &mut ciphertext).unwrap();

    let mut recovered = [0u8; BUFFER_LEN];
    let n = Aes128CcmDecryptor::decrypt_out(&k, &nonce, &[], &ciphertext, &tag, &mut recovered)
        .unwrap();
    print!("{n}");
}

/// The streaming direct path, which is what a caller in SP 800-38C Sec 3's packet environment
/// should use: the payload length is declared up front and nothing is buffered, so peak stack is
/// the `Ccm` value plus one chunk.
fn bench_direct_streaming() {
    eprintln!("Ccm::do_encrypt_update, 4 KiB in 1 KiB chunks");

    let k = key::<16>();
    let nonce = [0x24u8; NONCE_LEN];
    let mut data = [0xA5u8; BUFFER_LEN];
    let mut ccm = Aes128Ccm::<Encrypting>::new(&k, &nonce, &[], data.len()).unwrap();
    for chunk in data.chunks_mut(1024) {
        ccm.do_encrypt_update(chunk).unwrap();
    }
    let tag = ccm.do_encrypt_final().unwrap();
    print!("{:x?}", &tag);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_direct_encrypt_detached()
    // bench_buffering_encrypt_out()
    // bench_buffering_decrypt_out()
    // bench_direct_streaming()
}
