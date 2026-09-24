//! Shared plumbing for the AEAD subcommands: `aes{128,192,256}-gcm`.
//!
//! Parallel to [`crate::stream_mode_cmd`], but for [`bouncycastle::modes::Gcm`] rather than a
//! [`StreamCipherEncryptor`](bouncycastle::core::traits::StreamCipherEncryptor) mode: GCM carries
//! additional authenticated data and a tag, neither of which that trait has room for, so this
//! module drives `Gcm`'s inherent `do_update_aad` / `do_encrypt` / `do_decrypt` / `finish` API
//! directly instead of going through a shared trait.
//!
//! # On-the-wire format: `nonce || ciphertext || tag`
//!
//! `encrypt` writes the generated 12-byte nonce first, then the ciphertext as it streams, then the
//! 16-byte tag once stdin is exhausted. `decrypt` reads the 12-byte nonce first, then streams the
//! rest of stdin through the inline decryptor -- which, per [`SymmetricCipherDecryptor`]'s contract,
//! holds back the last 16 bytes it has seen because they might be the tag -- and checks the tag on
//! `do_final`.
//!
//! # The exit code is the signal, not the output
//!
//! On a tag failure, `decrypt` has **already written plaintext to stdout**: the inline decryptor
//! releases bytes as they clear the tail hold-back, well before the tag at the very end of the
//! stream can be checked. This is the same trade-off `Gcm`'s streaming API documents; a script that
//! needs to know before acting on the output must use the one-shot instead (not exposed by this
//! CLI) or check the exit code before trusting anything already written. On failure this command
//! prints `Error: authentication failed` to stderr and exits non-zero.
//!
//! # AAD
//!
//! `--aad <hex>` or `--aad-file <path>` (binary or hex); if neither is given, AAD is empty. Fed to
//! the engine in one call before any ciphertext, matching SP 800-38D Algorithm 4's requirement that
//! AAD precede data.

use crate::helpers::{read_from_file, write_bytes_or_hex};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::{
    ElectronicCodeBook, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle::hex;
use bouncycastle::modes::{Decrypting, Encrypting, Gcm};
use std::io;
use std::io::{Read, Write};
use std::process::exit;

/// Bytes read from stdin per call. GCM has no batching advantage from a larger chunk the way CTR's
/// four-block path does, so this matches the other streaming commands' 1 KiB rather than needing
/// its own tuning.
const CHUNK_LEN: usize = 1024;

/// Loads the additional authenticated data from `--aad` (hex) or `--aad-file` (binary or hex).
/// Empty if neither is given: AAD is optional, unlike the key.
pub(crate) fn load_aad(aad: &Option<String>, aad_file: &Option<String>) -> Vec<u8> {
    if let Some(path) = aad_file {
        read_from_file(path)
    } else if let Some(hex_str) = aad {
        hex::decode(hex_str).unwrap_or_else(|_| {
            eprintln!("Error: `--aad` must be hex. Use `--aad-file` for raw bytes.");
            exit(-1);
        })
    } else {
        Vec::new()
    }
}

/// Encrypts stdin to stdout under GCM: writes the generated nonce, then the ciphertext as it
/// streams, then the tag.
pub(crate) fn encrypt_gcm<P, const KEY_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    aad: &[u8],
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let (mut enc, nonce) = Gcm::<P, Encrypting, KEY_LEN, TAG_LEN>::do_encrypt_init(key)
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't start encryption: {e:?}");
            exit(-1);
        });
    write_bytes_or_hex(&nonce, output_hex);

    enc.do_update_aad(aad).unwrap_or_else(|e| {
        eprintln!("Error: couldn't absorb the additional authenticated data: {e:?}");
        exit(-1);
    });

    let mut buf = [0u8; CHUNK_LEN];
    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            break;
        }
        enc.do_encrypt(&mut buf[..n]).unwrap_or_else(|e| {
            eprintln!("Error: encryption failed: {e:?}");
            exit(-1);
        });
        write_bytes_or_hex(&buf[..n], output_hex);
    }

    let tag = enc.finish();
    write_bytes_or_hex(&tag, output_hex);
    finish(output_hex);
}

/// Decrypts stdin to stdout under GCM: reads the 12-byte nonce, streams the rest through the
/// inline decryptor, and checks the tag on `do_final`. See the module docs for why plaintext may
/// already be written to stdout by the time a tag failure is reported.
pub(crate) fn decrypt_gcm<P, const KEY_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    aad: &[u8],
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let mut nonce = [0u8; 12];
    if let Err(e) = io::stdin().read_exact(&mut nonce) {
        eprintln!(
            "Error: input too short to contain the 12-byte nonce that `encrypt` writes first ({e})."
        );
        exit(-1);
    }

    let mut dec = Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::do_decrypt_init(key, &nonce)
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't start decryption: {e:?}");
            exit(-1);
        });
    dec.do_update_aad(aad).unwrap_or_else(|e| {
        eprintln!("Error: couldn't absorb the additional authenticated data: {e:?}");
        exit(-1);
    });

    let mut buf = [0u8; CHUNK_LEN];
    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            break;
        }
        let out_len = dec.update_out_len(n);
        let mut out = vec![0u8; out_len];
        dec.do_update_out(&buf[..n], &mut out).unwrap_or_else(|e| {
            eprintln!("Error: decryption failed: {e:?}");
            exit(-1);
        });
        write_bytes_or_hex(&out, output_hex);
    }

    if let Err(e) = dec.do_final() {
        // Whatever plaintext was already written above stands; the exit code is the signal a
        // script must check (see the module docs).
        io::stdout().flush().ok();
        eprintln!("Error: authentication failed: {e:?}");
        exit(-1);
    }

    finish(output_hex);
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
