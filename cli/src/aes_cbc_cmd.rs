//! AES-CBC encryption and decryption, streaming stdin to stdout.
//!
//! # The IV travels in the ciphertext
//!
//! There is no `--iv` flag, and that is deliberate: `bouncycastle-modes` has no API for a
//! caller-supplied IV, because NIST SP 800-38A Sec 5.3 requires the CBC IV to be *unpredictable*
//! rather than merely unique. `encrypt` therefore generates one from the OS-backed DRBG and writes
//! it as the **first block of the output**; `decrypt` reads it back from the **first block of the
//! input**. So the two compose directly:
//!
//! ```text
//! bc-rust aes128-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes128-cbc decrypt --key-file k.bin < cipher.bin > plain.bin
//! ```
//!
//! The IV is not secret (Sec 5.3), so shipping it in the clear is correct. Its *integrity* is not
//! protected, and neither is the ciphertext's -- see the warning below.
//!
//! # Input must be block-aligned
//!
//! CBC is defined only on whole blocks (SP 800-38A Sec 5.2), and this workspace has no padding
//! layer yet, so input that is not a multiple of 16 bytes is rejected rather than silently padded.
//! Padding is the caller's business until `PaddedEncryptor`/`PaddedDecryptor` land.
//!
//! # Binary in, binary out
//!
//! stdin is read as binary so the commands compose in a pipeline. `-x` renders the *output* as hex.
//! For hex input, pipe through `hex-decode` first:
//!
//! ```text
//! cat cipher.hex | bc-rust hex-decode | bc-rust aes256-cbc decrypt --key-file k.bin
//! ```

use crate::helpers::write_bytes_or_hex;
use bouncycastle::aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle::core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle::core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation, SecurityStrength,
};
use bouncycastle::hex;
use bouncycastle::modes::{Cbc, Decrypting, Encrypting};
use clap::ValueEnum;
use std::io::{Read, Write};
use std::process::exit;
use std::{fs, io};

/// The AES block length in bytes.
const BLOCK_LEN: usize = 16;

/// Bytes processed per call: 1 KiB = 64 blocks, matching the other streaming commands.
///
/// A full chunk goes through `do_*::<CHUNK_LEN>` in one call, in place, which for decryption means
/// 32 pairs down the `decrypt_blocks2` path. The at-most-63-block tail at end of input goes one
/// block at a time; it is bounded, so its cost does not scale with the input.
const CHUNK_LEN: usize = 64 * BLOCK_LEN;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum AESCBCAction {
    /// Encrypt stdin to stdout under CBC mode.
    /// A freshly generated IV is written as the first 16 bytes of the output, so that `decrypt`
    /// can read it back. Input length must be a multiple of 16 bytes.
    Encrypt,
    /// Decrypt stdin to stdout under CBC mode.
    /// The first 16 bytes of input are taken as the IV, as written by `encrypt`. The remaining
    /// length must be a multiple of 16 bytes.
    Decrypt,
}

pub(crate) fn aes128_cbc_cmd(
    action: &AESCBCAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "AES-128");
    match action {
        AESCBCAction::Encrypt => encrypt_stream::<Aes128, 16>(&key, output_hex),
        AESCBCAction::Decrypt => decrypt_stream::<Aes128, 16>(&key, output_hex),
    }
}

pub(crate) fn aes192_cbc_cmd(
    action: &AESCBCAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<24>(key, key_file, "AES-192");
    match action {
        AESCBCAction::Encrypt => encrypt_stream::<Aes192, 24>(&key, output_hex),
        AESCBCAction::Decrypt => decrypt_stream::<Aes192, 24>(&key, output_hex),
    }
}

pub(crate) fn aes256_cbc_cmd(
    action: &AESCBCAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<32>(key, key_file, "AES-256");
    match action {
        AESCBCAction::Encrypt => encrypt_stream::<Aes256, 32>(&key, output_hex),
        AESCBCAction::Decrypt => decrypt_stream::<Aes256, 32>(&key, output_hex),
    }
}

/// Loads the key from `--key` (hex) or `--key-file` (binary or hex), and checks its length.
///
/// `KEY_LEN` is exact: AES has three key lengths and the command selects one, so a key of the
/// wrong length is a mistake rather than something to truncate or pad.
fn load_key<const KEY_LEN: usize>(
    key: &Option<String>,
    key_file: &Option<String>,
    alg: &str,
) -> KeyMaterial<KEY_LEN> {
    let key_bytes: Vec<u8> = if let Some(key_file) = key_file {
        // A file may hold raw bytes or hex; try hex first, as the other commands do.
        let raw = fs::read(key_file).unwrap_or_else(|e| {
            eprintln!("Error: couldn't read key file '{key_file}': {e}");
            exit(-1);
        });
        match hex::decode(&raw) {
            Ok(decoded) => decoded,
            Err(_) => raw,
        }
    } else if let Some(key) = key {
        hex::decode(key).unwrap_or_else(|_| {
            eprintln!("Error: `--key` must be hex. Use `--key-file` for raw bytes.");
            exit(-1);
        })
    } else {
        eprintln!("Error: either `--key` or `--key-file` must be supplied.");
        exit(-1);
    };

    if key_bytes.len() != KEY_LEN {
        eprintln!("Error: {alg} needs a {KEY_LEN}-byte key, got {} bytes.", key_bytes.len());
        exit(-1);
    }

    // `from_bytes_as_type` tags the key at the strength its length implies, which is exactly what
    // the engine requires -- except for an all-zero key, which it marks Zeroized instead.
    let mut key =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .unwrap_or_else(|e| {
                eprintln!("Error: couldn't load the key: {e:?}");
                exit(-1);
            });

    if key.key_type() != KeyType::SymmetricCipherKey {
        // Same stance as `helpers::parse_seed`: warn, then do what was asked. A CLI is used for
        // test vectors and scripting, where an all-zero key is a legitimate thing to want.
        eprintln!(
            "Warning: all-zero (or otherwise zeroized) key provided. Proceeding, but this is not secure."
        );
        do_hazardous_operations(&mut key, |key| {
            key.set_key_type(KeyType::SymmetricCipherKey)?;
            key.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
        })
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't tag the key: {e:?}");
            exit(-1);
        });
    }

    key
}

/// Encrypts stdin to stdout, writing the generated IV first.
fn encrypt_stream<P, const KEY_LEN: usize>(key: &KeyMaterial<KEY_LEN>, output_hex: bool)
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let (mut enc, iv) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init(key)
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't start encryption: {e:?}");
            exit(-1);
        });

    // The IV goes out ahead of the ciphertext, so `decrypt` can pick it up.
    write_bytes_or_hex(&iv, output_hex);

    // The cipher works in place: `data` holds plaintext on the way in and ciphertext on the way out.
    stream_aligned(|data| {
        if let Ok(chunk) = <&mut [u8; CHUNK_LEN]>::try_from(&mut *data) {
            // Cannot fail: CBC has no per-IV data limit.
            enc.do_encrypt(chunk).unwrap();
        } else {
            // The bounded tail at end of input: whole blocks, fewer than a chunk.
            for block in data.as_chunks_mut::<BLOCK_LEN>().0 {
                enc.do_encrypt(block).unwrap();
            }
        }
        write_bytes_or_hex(data, output_hex);
    });

    finish(output_hex);
}

/// Decrypts stdin to stdout, taking the IV from the first block of input.
fn decrypt_stream<P, const KEY_LEN: usize>(key: &KeyMaterial<KEY_LEN>, output_hex: bool)
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    // The leading block is the IV, not ciphertext.
    let mut iv = [0u8; BLOCK_LEN];
    if let Err(e) = io::stdin().read_exact(&mut iv) {
        eprintln!(
            "Error: input too short to contain the {BLOCK_LEN}-byte IV that `encrypt` writes \
             as its first block ({e})."
        );
        exit(-1);
    }

    let mut dec = Cbc::<P, Decrypting, KEY_LEN, BLOCK_LEN>::do_decrypt_init(key, &iv)
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't start decryption: {e:?}");
            exit(-1);
        });

    stream_aligned(|data| {
        if let Ok(chunk) = <&mut [u8; CHUNK_LEN]>::try_from(&mut *data) {
            // A full chunk is 32 pairs, so this is the `decrypt_blocks2` path.
            dec.do_decrypt(chunk).unwrap();
        } else {
            for block in data.as_chunks_mut::<BLOCK_LEN>().0 {
                dec.do_decrypt(block).unwrap();
            }
        }
        write_bytes_or_hex(data, output_hex);
    });

    finish(output_hex);
}

/// Reads stdin and hands it to `process` in block-aligned pieces, mutably so it can be transformed
/// in place: a full `CHUNK_LEN` bytes each time one has accumulated, then once more at end of input
/// with whatever whole blocks remain (fewer than a chunk). Reads need not respect block or chunk boundaries -- bytes simply accumulate in the
/// buffer until it is full -- so a block split across two reads needs no special handling.
///
/// Input whose total length is not a multiple of `BLOCK_LEN` is an error, because CBC is not
/// defined on a partial block and there is no padding layer to appeal to.
fn stream_aligned(mut process: impl FnMut(&mut [u8])) {
    let mut buf = [0u8; CHUNK_LEN];
    let mut filled = 0usize;

    loop {
        let n = io::stdin().read(&mut buf[filled..]).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            break;
        }
        filled += n;
        if filled == CHUNK_LEN {
            process(&mut buf);
            filled = 0;
        }
    }

    if !filled.is_multiple_of(BLOCK_LEN) {
        eprintln!(
            "Error: input is not a whole number of {BLOCK_LEN}-byte blocks ({} trailing byte(s)). \
             CBC is defined only on whole blocks (SP 800-38A Sec 5.2), and this build has no \
             padding layer, so the input must be padded by the caller.",
            filled % BLOCK_LEN
        );
        exit(-1);
    }
    if filled != 0 {
        process(&mut buf[..filled]);
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
