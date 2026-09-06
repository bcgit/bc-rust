//! Shared plumbing for the stream-cipher-mode subcommands: `aes{128,192,256}-{cfb,cfb8}`.
//!
//! The stream-cipher counterpart of [`crate::block_mode_cmd`], and deliberately parallel to it:
//! same key loading (reused directly from there), same IV convention, same `-x` hex output, same
//! 1 KiB streaming chunk. Everything here is mode-independent and generic over
//! [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`], so `aes_cfb_cmd` and `aes_cfb8_cmd` are
//! thin dispatchers over it and cannot drift apart on the parts that matter for correctness.
//!
//! # The IV travels in the ciphertext
//!
//! Exactly as for the block modes: there is no `--iv` flag, because `bouncycastle-modes` has no API
//! for a caller-supplied IV -- NIST SP 800-38A Sec 5.3 requires the CFB IV to be *unpredictable*
//! rather than merely unique. `encrypt` generates one from the OS-backed DRBG and writes it as the
//! **first block of the output**; `decrypt` reads it back from the **first block of the input**, so
//! the two compose directly in a pipeline.
//!
//! # No alignment requirement, and no padding
//!
//! This is the one place the stream commands differ from the block ones. A stream cipher is defined
//! on any length -- CFB8's segment is a byte, and `Cfb` extends the `s = b` equations to a short
//! final segment (see its module docs) -- so input of *any* size is accepted, nothing is padded,
//! and the ciphertext is exactly as long as the plaintext. A partial read from stdin therefore
//! needs no buffering to a block boundary: whatever arrives is processed immediately.
//!
//! # Binary in, binary out
//!
//! stdin is read as binary so the commands compose in a pipeline. `-x` renders the *output* as hex.
//! For hex input, pipe through `hex-decode` first.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, CHUNK_LEN};
use crate::helpers::write_bytes_or_hex;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use std::io;
use std::io::{Read, Write};
use std::process::exit;

/// Encrypts stdin to stdout under the stream mode `E`, writing the generated IV first.
///
/// `INIT_DATA_LEN` is the mode's: one block for CFB and CFB8.
pub(crate) fn encrypt_stream<E, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    E: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
{
    let (mut enc, iv) = E::do_encrypt_init(key).unwrap_or_else(|e| {
        eprintln!("Error: couldn't start encryption: {e:?}");
        exit(-1);
    });

    // The IV goes out ahead of the ciphertext, so `decrypt` can pick it up.
    write_bytes_or_hex(&iv, output_hex);

    // The cipher works in place: `data` holds plaintext on the way in and ciphertext on the way out.
    stream(|data| {
        // Cannot fail: neither CFB nor CFB8 has a per-IV data limit.
        enc.do_encrypt(data).unwrap();
        write_bytes_or_hex(data, output_hex);
    });

    finish(output_hex);
}

/// Decrypts stdin to stdout under the stream mode `D`, taking the IV from the first
/// `INIT_DATA_LEN` bytes of input.
pub(crate) fn decrypt_stream<D, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    D: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
{
    // The leading bytes are the IV, not ciphertext.
    let mut iv = [0u8; INIT_DATA_LEN];
    if let Err(e) = io::stdin().read_exact(&mut iv) {
        eprintln!(
            "Error: input too short to contain the {INIT_DATA_LEN}-byte IV that `encrypt` writes \
             as its first block ({e})."
        );
        exit(-1);
    }

    let mut dec = D::do_decrypt_init(key, &iv).unwrap_or_else(|e| {
        eprintln!("Error: couldn't start decryption: {e:?}");
        exit(-1);
    });

    stream(|data| {
        dec.do_decrypt(data).unwrap();
        write_bytes_or_hex(data, output_hex);
    });

    finish(output_hex);
}

/// Reads stdin and hands it to `process` in pieces of at most `CHUNK_LEN` bytes, mutably so it can
/// be transformed in place.
///
/// Unlike the block modes' `stream_aligned`, nothing is buffered to a boundary and no length is
/// rejected: a stream cipher takes any number of bytes, and a sequence of calls is equivalent to
/// one call over the concatenation, so whatever a read returns can go straight through. That also
/// means the mode's own byte path is exercised at whatever alignment the pipe happens to deliver,
/// which is precisely what the trait guarantees is safe.
fn stream(mut process: impl FnMut(&mut [u8])) {
    let mut buf = [0u8; CHUNK_LEN];

    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            break;
        }
        process(&mut buf[..n]);
    }
}

/// Flushes stdout, and adds the trailing newline the hex-output commands all emit.
fn finish(output_hex: bool) {
    if output_hex {
        println!();
    }
    io::stdout().flush().unwrap_or_else(|e| {
        eprintln!("Error: failed to flush stdout: {e}");
        exit(-1);
    });
}

/// Runs one direction of a stream mode. The two `run` dispatchers in `aes_cfb_cmd` and
/// `aes_cfb8_cmd` differ only in which mode they name, so the match lives here.
pub(crate) fn run_stream_mode<E, D, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    E: StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>,
    D: StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>,
{
    match action {
        BlockModeAction::Encrypt => encrypt_stream::<E, KEY_LEN, BLOCK_LEN>(key, output_hex),
        BlockModeAction::Decrypt => decrypt_stream::<D, KEY_LEN, BLOCK_LEN>(key, output_hex),
    }
}
