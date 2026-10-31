//! Shared plumbing for the stream-cipher-mode subcommands: `aes{128,192,256}-{cfb,cfb8,ctr}`.
//!
//! The stream-cipher counterpart of [`crate::helpers::block_mode_helpers`], and deliberately parallel to it:
//! same key loading (reused directly from there), same IV convention, same `-x` hex output, same
//! 1 KiB streaming chunk. Everything here is mode-independent and generic over
//! [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`], so `aes_cfb_cmd`, `aes_cfb8_cmd` and
//! `aes_ctr_cmd` are thin dispatchers over it and cannot drift apart on the parts that matter for
//! correctness. The init data length is a parameter, so it need not be a whole block: it is the
//! block for the CFB modes and a 12-byte nonce for CTR.
//!
//! # The IV travels in the ciphertext, unless `--iv` is given
//!
//! Exactly as for the block modes, see [`crate::helpers::block_mode_helpers`]: by default
//! `encrypt` generates the IV (CFB, CFB8) or nonce (CTR) and writes it first, `decrypt` reads it
//! back, and with `--iv` / `--iv-file` the caller supplies it and only ciphertext is written or
//! read. The length is the mode's `INIT_DATA_LEN`: 16 bytes for CFB and CFB8, 12 for CTR.
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

use crate::helpers::block_mode_helpers::{CHUNK_LEN, CipherDirection, start_encryptor};
use crate::helpers::{flush_stdout, write_bytes_or_hex, write_stdout};
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use std::io;
use std::io::Read;
use std::process::exit;

/// Encrypts stdin to stdout under the key's stream mode. With no `iv`, the IV is generated and
/// written first; with one, it is used and the output is ciphertext only.
///
/// `INIT_DATA_LEN` is the mode's: one block for CFB and CFB8, 12 bytes for CTR.
pub(crate) fn encrypt_stream<'k, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    key: &'k K,
    iv: Option<[u8; INIT_DATA_LEN]>,
    output_hex: bool,
) where
    K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
    K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
{
    let (mut enc, generated_iv) = start_encryptor(iv, |rng| key.create_encryptor(rng));

    // A generated IV goes out ahead of the ciphertext, so `decrypt` can pick it up. A supplied
    // one is the caller's to carry.
    if let Some(iv) = generated_iv {
        write_bytes_or_hex(&iv, output_hex);
    }

    // The cipher works in place: `data` holds plaintext on the way in and ciphertext on the way out.
    stream(|data| {
        // Cannot fail: neither CFB nor CFB8 has a per-IV data limit.
        // CFB and CFB8 cannot fail here; CTR can, once its counter is exhausted, which is a real
        // limit a long enough stream reaches rather than a bug.
        enc.do_encrypt_inplace(data).unwrap_or_else(|e| {
            eprintln!("Error: encryption failed: {e:?}");
            exit(-1);
        });
        write_bytes_or_hex(data, output_hex);
    });

    finish(output_hex);
}

/// Decrypts stdin to stdout under the key's stream mode, taking the IV from `iv` if given and
/// otherwise from the first `INIT_DATA_LEN` bytes of input.
pub(crate) fn decrypt_stream<'k, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    key: &'k K,
    iv: Option<[u8; INIT_DATA_LEN]>,
    output_hex: bool,
) where
    K: SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
    K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
{
    let iv = iv.unwrap_or_else(|| {
        // The leading bytes are the IV, not ciphertext.
        let mut iv = [0u8; INIT_DATA_LEN];
        if let Err(e) = io::stdin().read_exact(&mut iv) {
            eprintln!(
                "Error: input too short to contain the {INIT_DATA_LEN}-byte IV that `encrypt` \
                 writes as its first block ({e}). If the IV is held separately, pass it with --iv."
            );
            exit(-1);
        }
        iv
    });

    let mut dec = key.create_decryptor(&iv);

    stream(|data| {
        dec.do_decrypt_inplace(data).unwrap_or_else(|e| {
            eprintln!("Error: decryption failed: {e:?}");
            exit(-1);
        });
        write_bytes_or_hex(data, output_hex);
    });

    finish(output_hex);
}

/// Reads stdin and hands it to `process` in pieces of at most `CHUNK_LEN` bytes, mutably so it can
/// be transformed in place.
///
/// Unlike the block modes (`block_mode_helpers`), nothing is buffered to a boundary and no length is
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
        write_stdout(b"\n");
    }
    flush_stdout();
}

/// Runs one direction of a stream mode under its key. The `run` dispatchers in `aes_cfb_cmd`,
/// `aes_cfb8_cmd` and `aes_ctr_cmd` differ only in which key type they load, so the match lives
/// here.
pub(crate) fn run_stream_mode<'k, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    action: &CipherDirection,
    key: &'k K,
    iv: Option<[u8; INIT_DATA_LEN]>,
    output_hex: bool,
) where
    K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
    K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
    K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            encrypt_stream::<K, KEY_LEN, INIT_DATA_LEN>(key, iv, output_hex)
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<K, KEY_LEN, INIT_DATA_LEN>(key, iv, output_hex)
        }
    }
}
