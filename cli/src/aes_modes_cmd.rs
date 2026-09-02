//! AES encryption and decryption in CBC and CFB mode, streaming stdin to stdout.
//!
//! Six subcommands -- `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `aes128-cfb`, `aes192-cfb`,
//! `aes256-cfb` -- share every line of this module below the entry points, because the two modes
//! present an identical API. The streaming helpers are generic over the encryptor / decryptor type
//! rather than over the cipher, which is what lets them.
//!
//! The CFB subcommands are the full-block segment variant, `s = b`, i.e. **CFB128** (NIST SP
//! 800-38A Sec 6.3). There is no CFB1 or CFB8 here; `bouncycastle-modes` does not implement them.
//!
//! # The IV travels in the ciphertext
//!
//! There is no `--iv` flag, and that is deliberate: `bouncycastle-modes` has no API for a
//! caller-supplied IV, because NIST SP 800-38A Sec 5.3 requires the CBC *and CFB* IV to be
//! *unpredictable* rather than merely unique. `encrypt` therefore generates one from the OS-backed
//! DRBG and writes it as the **first block of the output**; `decrypt` reads it back from the
//! **first block of the input**. So the two compose directly:
//!
//! ```text
//! bc-rust aes128-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes128-cbc decrypt --key-file k.bin < cipher.bin > plain.bin
//!
//! bc-rust aes256-cfb encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cfb decrypt --key-file k.bin < cipher.bin > plain.bin
//! ```
//!
//! The IV is not secret (Sec 5.3), so shipping it in the clear is correct. Its *integrity* is not
//! protected, and neither is the ciphertext's -- see the warnings below.
//!
//! # Input must be block-aligned
//!
//! CBC is defined only on whole blocks (SP 800-38A Sec 5.2), and CFB on whole segments -- which at
//! `s = b` is the same thing. This workspace has no padding layer yet, so input that is not a
//! multiple of 16 bytes is rejected rather than silently padded. Padding is the caller's business
//! until `PaddedEncryptor` / `PaddedDecryptor` land.
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
use bouncycastle::core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, SecurityStrength};
use bouncycastle::hex;
use bouncycastle::modes::{Cbc, Cfb, Decrypting, Encrypting};
use clap::ValueEnum;
use std::io::{Read, Write};
use std::process::exit;
use std::{fs, io};

/// The AES block length in bytes.
const BLOCK_LEN: usize = 16;

/// Blocks processed per call: 64 blocks = 1 KiB, matching the other streaming commands.
///
/// A whole chunk goes through `do_*_blocks[_out]::<CHUNK_BLOCKS>` in one call, which for decryption
/// means 32 pairs down the permutation's two-block path. The at-most-63-block tail at end of input
/// is flushed one block at a time; it is bounded, so its cost does not scale with the input.
const CHUNK_BLOCKS: usize = 64;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum AESModeAction {
    /// Encrypt stdin to stdout.
    /// A freshly generated IV is written as the first 16 bytes of the output, so that `decrypt`
    /// can read it back. Input length must be a multiple of 16 bytes.
    Encrypt,
    /// Decrypt stdin to stdout.
    /// The first 16 bytes of input are taken as the IV, as written by `encrypt`. The remaining
    /// length must be a multiple of 16 bytes.
    Decrypt,
}

// ---- entry points ------------------------------------------------------------------------

pub(crate) fn aes128_cbc_cmd(
    action: &AESModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "AES-128");
    match action {
        AESModeAction::Encrypt => {
            encrypt_stream::<Cbc<Aes128, Encrypting, 16, BLOCK_LEN>, 16>(&key, output_hex)
        }
        AESModeAction::Decrypt => {
            decrypt_stream::<Cbc<Aes128, Decrypting, 16, BLOCK_LEN>, 16>(&key, output_hex)
        }
    }
}

pub(crate) fn aes192_cbc_cmd(
    action: &AESModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<24>(key, key_file, "AES-192");
    match action {
        AESModeAction::Encrypt => {
            encrypt_stream::<Cbc<Aes192, Encrypting, 24, BLOCK_LEN>, 24>(&key, output_hex)
        }
        AESModeAction::Decrypt => {
            decrypt_stream::<Cbc<Aes192, Decrypting, 24, BLOCK_LEN>, 24>(&key, output_hex)
        }
    }
}

pub(crate) fn aes256_cbc_cmd(
    action: &AESModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<32>(key, key_file, "AES-256");
    match action {
        AESModeAction::Encrypt => {
            encrypt_stream::<Cbc<Aes256, Encrypting, 32, BLOCK_LEN>, 32>(&key, output_hex)
        }
        AESModeAction::Decrypt => {
            decrypt_stream::<Cbc<Aes256, Decrypting, 32, BLOCK_LEN>, 32>(&key, output_hex)
        }
    }
}

pub(crate) fn aes128_cfb_cmd(
    action: &AESModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "AES-128");
    match action {
        AESModeAction::Encrypt => {
            encrypt_stream::<Cfb<Aes128, Encrypting, 16, BLOCK_LEN>, 16>(&key, output_hex)
        }
        AESModeAction::Decrypt => {
            decrypt_stream::<Cfb<Aes128, Decrypting, 16, BLOCK_LEN>, 16>(&key, output_hex)
        }
    }
}

pub(crate) fn aes192_cfb_cmd(
    action: &AESModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<24>(key, key_file, "AES-192");
    match action {
        AESModeAction::Encrypt => {
            encrypt_stream::<Cfb<Aes192, Encrypting, 24, BLOCK_LEN>, 24>(&key, output_hex)
        }
        AESModeAction::Decrypt => {
            decrypt_stream::<Cfb<Aes192, Decrypting, 24, BLOCK_LEN>, 24>(&key, output_hex)
        }
    }
}

pub(crate) fn aes256_cfb_cmd(
    action: &AESModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<32>(key, key_file, "AES-256");
    match action {
        AESModeAction::Encrypt => {
            encrypt_stream::<Cfb<Aes256, Encrypting, 32, BLOCK_LEN>, 32>(&key, output_hex)
        }
        AESModeAction::Decrypt => {
            decrypt_stream::<Cfb<Aes256, Decrypting, 32, BLOCK_LEN>, 32>(&key, output_hex)
        }
    }
}

// ---- key loading -------------------------------------------------------------------------

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

// ---- streaming ---------------------------------------------------------------------------

/// Encrypts stdin to stdout, writing the generated IV first.
///
/// Generic over the encryptor, so one body serves CBC and CFB.
fn encrypt_stream<E, const KEY_LEN: usize>(key: &KeyMaterial<KEY_LEN>, output_hex: bool)
where
    E: BlockCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let (mut enc, iv) = E::do_encrypt_init(key).unwrap_or_else(|e| {
        eprintln!("Error: couldn't start encryption: {e:?}");
        exit(-1);
    });

    // The IV goes out ahead of the ciphertext, so `decrypt` can pick it up.
    write_bytes_or_hex(&iv, output_hex);

    let mut out = [[0u8; BLOCK_LEN]; CHUNK_BLOCKS];

    stream_blocks(|blocks| match <&[[u8; BLOCK_LEN]; CHUNK_BLOCKS]>::try_from(blocks) {
        Ok(full_chunk) => {
            // Cannot fail: the mode's block methods are infallible for a constructed value.
            enc.do_encrypt_blocks_out(full_chunk, &mut out).unwrap();
            write_blocks(&out, output_hex);
        }
        Err(_) => {
            // The bounded tail at end of input.
            for block in blocks.iter() {
                let [c] = enc.do_encrypt_blocks(&[*block]).unwrap();
                write_bytes_or_hex(&c, output_hex);
            }
        }
    });

    finish(output_hex);
}

/// Decrypts stdin to stdout, taking the IV from the first block of input.
///
/// Generic over the decryptor, so one body serves CBC and CFB.
fn decrypt_stream<D, const KEY_LEN: usize>(key: &KeyMaterial<KEY_LEN>, output_hex: bool)
where
    D: BlockCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
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

    let mut dec = D::do_decrypt_init(key, &iv).unwrap_or_else(|e| {
        eprintln!("Error: couldn't start decryption: {e:?}");
        exit(-1);
    });

    let mut out = [[0u8; BLOCK_LEN]; CHUNK_BLOCKS];

    stream_blocks(|blocks| match <&[[u8; BLOCK_LEN]; CHUNK_BLOCKS]>::try_from(blocks) {
        Ok(full_chunk) => {
            // A full chunk is 32 pairs, so this takes the permutation's two-block path.
            dec.do_decrypt_blocks_out(full_chunk, &mut out).unwrap();
            write_blocks(&out, output_hex);
        }
        Err(_) => {
            for block in blocks.iter() {
                let [p] = dec.do_decrypt_blocks(&[*block]).unwrap();
                write_bytes_or_hex(&p, output_hex);
            }
        }
    });

    finish(output_hex);
}

/// Reads stdin a block at a time, calling `process` with a full `CHUNK_BLOCKS` slice whenever one
/// is available and once more at end of input with whatever whole blocks remain.
///
/// `process` therefore sees a slice of exactly `CHUNK_BLOCKS` for every call but the last, which is
/// how the callers can hand a fixed-size array to `do_*_blocks_out::<CHUNK_BLOCKS>` and fall back
/// to single blocks only for the bounded tail.
///
/// Reads do not respect block boundaries, so a block can arrive split across two reads; the
/// partial block is carried over rather than assumed complete. Input whose total length is not a
/// multiple of `BLOCK_LEN` is an error, because these modes are not defined on a partial block and
/// there is no padding layer to appeal to.
fn stream_blocks(mut process: impl FnMut(&[[u8; BLOCK_LEN]])) {
    let mut staged = [[0u8; BLOCK_LEN]; CHUNK_BLOCKS];
    let mut read_buf = [0u8; BLOCK_LEN * CHUNK_BLOCKS];
    let mut partial = [0u8; BLOCK_LEN];
    let mut partial_len = 0usize;
    let mut blocks = 0usize;

    loop {
        let n = io::stdin().read(&mut read_buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            break;
        }

        let mut src = &read_buf[..n];
        while !src.is_empty() {
            let take = core::cmp::min(BLOCK_LEN - partial_len, src.len());
            partial[partial_len..partial_len + take].copy_from_slice(&src[..take]);
            partial_len += take;
            src = &src[take..];

            if partial_len == BLOCK_LEN {
                staged[blocks] = partial;
                blocks += 1;
                partial_len = 0;

                if blocks == CHUNK_BLOCKS {
                    process(&staged);
                    blocks = 0;
                }
            }
        }
    }

    if partial_len != 0 {
        eprintln!(
            "Error: input is not a whole number of {BLOCK_LEN}-byte blocks ({partial_len} \
             trailing byte(s)). CBC and CFB are defined only on whole blocks (SP 800-38A Sec \
             5.2), and this build has no padding layer, so the input must be padded by the caller."
        );
        exit(-1);
    }

    if blocks != 0 {
        process(&staged[..blocks]);
    }
}

/// Writes a run of whole blocks.
fn write_blocks(blocks: &[[u8; BLOCK_LEN]], output_hex: bool) {
    for block in blocks.iter() {
        write_bytes_or_hex(block, output_hex);
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
