//! Shared plumbing for the block-cipher-mode subcommands: `aes{128,192,256}-{cbc,ecb}`.
//!
//! Everything here is mode-independent -- key loading, stdin framing, block-alignment enforcement,
//! output formatting -- and is generic over the mode via [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`]. `aes_cbc_cmd` and `aes_ecb_cmd` are thin dispatchers over it,
//! instantiating it with the `AES_CBC_*` types under `PKCS7` and the `AES_ECB_*` types under
//! `NoPadding`, so the commands cannot drift apart on the parts that matter for correctness.
//!
//! The CFB and CTR commands are stream ciphers and live in [`crate::helpers::stream_mode_helpers`] instead;
//! they share
//! [`load_key`] and [`CipherDirection`] with this module, so the key handling and the `encrypt` /
//! `decrypt` spelling stay identical across all of them.
//!
//! # The IV travels in the ciphertext, unless `--iv` is given
//!
//! By default `encrypt` generates the IV from the OS-backed DRBG and writes it as the **first
//! block of the output**, and `decrypt` reads it back from the **first block of the input**, so
//! the two compose directly. NIST SP 800-38A Sec 5.3 requires the CBC and CFB IV to be
//! *unpredictable*, and a DRBG draw is the way to get one. The framing is generic over the mode's
//! `INIT_DATA_LEN`: for ECB it is 0, so those commands write and read no IV and the ciphertext
//! is exactly as long as the plaintext.
//!
//! ```text
//! bc-rust aes128-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes128-cbc decrypt --key-file k.bin < cipher.bin > plain.bin
//! ```
//!
//! Every mode with an IV or nonce (CBC, CFB, CFB8, CTR, GCM) also takes `--iv` / `--iv-file`,
//! loaded by [`load_iv`], for a format that carries the IV itself and for reproducing published
//! vectors. With it, `encrypt` uses the supplied value and writes **only the ciphertext**, and
//! `decrypt` takes it from the flag and reads **only ciphertext** from stdin. The modes have no
//! IV-taking constructor, so it reaches them through `do_encrypt_init_rng` and a [`FixedIv`]
//! that hands out exactly those bytes (GCM has `do_encrypt_init_nonce` and uses that).
//! Unpredictability, and for CTR and GCM uniqueness, is then the caller's responsibility. CCM
//! keeps its own `--nonce`, which is variable-length and was never generated.
//!
//! The IV is not secret (Sec 5.3), so shipping it in the clear is correct. Its *integrity* is not
//! protected, and neither is the ciphertext's -- see the warnings on each subcommand.
//!
//! # Padding and block alignment
//!
//! The modes in this module are defined only on whole blocks (SP 800-38A Sec 5.2). The CBC
//! commands pad with PKCS7, so they encrypt input of any length, and the ciphertext body is always
//! one to sixteen bytes longer than the plaintext. The ECB commands apply no padding, so input that
//! is not a multiple of 16 bytes is rejected rather than silently padded. (The CFB commands have
//! no such requirement; see [`crate::helpers::stream_mode_helpers`].)
//!
//! # Binary in, binary out
//!
//! stdin is read as binary so the commands compose in a pipeline. `-x` renders the *output* as hex.
//! For hex input, pipe through `hex-decode` first:
//!
//! ```text
//! cat cipher.hex | bc-rust hex-decode | bc-rust aes256-cbc decrypt --key-file k.bin
//! ```

use crate::helpers;
use crate::helpers::{
    flush_stdout, read_from_file, strip_trailing_newline, write_bytes_or_hex, write_stdout,
};
use bouncycastle::core::errors::RNGError;
use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::traits::{RNG, SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle::hex;
use clap::ValueEnum;
use std::io;
use std::io::{Read, Write};
use std::process::exit;

/// The AES block length in bytes.
pub(crate) const BLOCK_LEN: usize = 16;

/// Bytes read from stdin per call: 1 KiB = 64 blocks, shared with the stream-mode commands.
pub(crate) const CHUNK_LEN: usize = 64 * BLOCK_LEN;

/// Which direction to run. Shared by cipher subcommands, -- see the specific subcommand's
/// own `--help` (`bc-rust aes128-ccm --help` and friends) for what `encrypt`/`decrypt` actually do
/// for the mode you are running.
#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum CipherDirection {
    /// Encrypt stdin to stdout.
    Encrypt,
    /// Decrypt stdin to stdout.
    Decrypt,
}

/// Loads the key from `--key` (hex) or `--key-file` (binary or hex), and checks its length.
///
/// `KEY_LEN` is exact: AES has three key lengths and the command selects one, so a key of the
/// wrong length is a mistake rather than something to truncate or pad.
pub(crate) fn load_key<const KEY_LEN: usize>(
    key: &Option<String>,
    key_file: &Option<String>,
    alg: &str,
) -> KeyMaterial<KEY_LEN> {
    let key_bytes: Vec<u8> = if let Some(key_file) = key_file {
        // A file may hold raw bytes or hex; `read_from_file` tries hex first, as the other
        // commands do.
        let bytes = read_from_file(key_file);
        // `read_from_file` already ignores a trailing newline on a hex file. A *raw* key file may
        // end in one too, which lengthens the key by a byte; strip it only when that leaves
        // exactly the key, so a binary key whose last byte really is `0x0a` is not shortened.
        let trimmed = strip_trailing_newline(&bytes);
        if trimmed.len() == KEY_LEN { trimmed.to_vec() } else { bytes }
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

/// An [`RNG`] that yields the caller's IV once, so `--iv` can reach a mode whose only
/// constructors are `do_encrypt_init` and `do_encrypt_init_rng`. A second draw, or one of the
/// wrong length, is an error rather than a repeat: the IV must be consumed exactly as given.
pub(crate) struct FixedIv<const N: usize> {
    iv: [u8; N],
    used: bool,
}

impl<const N: usize> FixedIv<N> {
    pub(crate) fn new(iv: [u8; N]) -> Self {
        Self { iv, used: false }
    }
}

impl<const N: usize> RNG for FixedIv<N> {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("a fixed IV cannot be reseeded"))
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("a fixed IV only supplies the IV"))
    }

    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        let mut out = vec![0u8; len];
        self.next_bytes_out(&mut out)?;
        Ok(out)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        if self.used || out.len() != N {
            return Err(RNGError::GenericError("the cipher asked for more than the one IV"));
        }
        self.used = true;
        out.copy_from_slice(&self.iv);
        Ok(N)
    }

    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("a fixed IV only supplies the IV"))
    }

    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::None
    }
}

/// Loads `--iv-file` (raw bytes, never hex-decoded) or `--iv` (hex); the file wins if both are
/// given, as for `--key-file`. `None` when neither is given, which selects the generated,
/// in-band IV. The IV must be exactly `INIT_DATA_LEN` bytes.
///
/// As for CCM's `--nonce-file`, a trailing newline in the file is part of the IV, and is warned
/// about, because a file written with `echo` rather than `echo -n` is the usual way to get one.
pub(crate) fn load_iv<const INIT_DATA_LEN: usize>(
    iv: &Option<String>,
    iv_file: &Option<String>,
) -> Option<[u8; INIT_DATA_LEN]> {
    let bytes = if let Some(file) = iv_file {
        let bytes = helpers::read_from_file_raw(file);
        if bytes.last() == Some(&b'\n') {
            eprintln!(
                "Warning: IV file '{file}' ends with a newline byte (0x0a), which is used as part \
                 of the IV. If that is not intended, write it with `printf` or `echo -n`."
            );
        }
        bytes
    } else if let Some(v) = iv {
        hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: IV is not valid hex.");
            exit(-1)
        })
    } else {
        return None;
    };
    Some(bytes.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!(
            "Error: IV is {} bytes; this mode requires exactly {INIT_DATA_LEN}.",
            bytes.len()
        );
        exit(-1)
    }))
}

/// Encrypts stdin to stdout under the mode `E`. With no `iv`, the init data (the IV) is generated
/// and written first; with one, it is used and the output is ciphertext only.
///
/// `INIT_DATA_LEN` is the mode's: one block for CBC, 0 for ECB, in which case nothing is written
/// ahead of the ciphertext. `aligned_mode` is `Some(mode name)` for a mode that pads nothing, whose
/// input must therefore be a whole number of blocks; the name appears in the error message.
pub(crate) fn encrypt_stream<E, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    iv: Option<[u8; INIT_DATA_LEN]>,
    output_hex: bool,
    aligned_mode: Option<&str>,
) where
    E: SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    let init = match iv {
        Some(iv) => E::do_encrypt_init_rng(key, &mut FixedIv::new(iv)),
        None => E::do_encrypt_init(key),
    };
    let (mut enc, generated_iv) = init.unwrap_or_else(|e| {
        eprintln!("Error: couldn't start encryption: {e:?}");
        exit(-1);
    });

    // A generated IV goes out ahead of the ciphertext, so `decrypt` can pick it up. (Empty for
    // ECB.) A supplied one is the caller's to carry.
    if INIT_DATA_LEN > 0 && iv.is_none() {
        write_bytes_or_hex(&generated_iv, output_hex);
    }

    let mut out = [0u8; CHUNK_LEN];
    let total = stream_chunks(|data| {
        // Cannot fail: `out` has room for every whole block of `data` plus the fewer than
        // `BLOCK_LEN` bytes held over from the last call, and none of these modes has a per-IV
        // data limit.
        let written = enc.do_encrypt_out(data, &mut out).unwrap();
        write_bytes_or_hex(&out[..written], output_hex);
    });

    if let Some(mode) = aligned_mode {
        check_aligned(mode, total);
    }
    // The padded final block; under `NoPadding` an aligned message has none, and this reports 0.
    let (last, last_len) = enc.do_encrypt_final().unwrap_or_else(|e| {
        eprintln!("Error: encryption failed: {e:?}");
        exit(-1);
    });
    write_bytes_or_hex(&last[..last_len], output_hex);

    finish(output_hex);
}

/// Decrypts stdin to stdout under the mode `D`, taking the init data (the IV) from `iv` if given
/// and otherwise from the first `INIT_DATA_LEN` bytes of input -- one block for CBC, nothing for
/// ECB. `aligned_mode` is as for [`encrypt_stream`].
pub(crate) fn decrypt_stream<D, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    iv: Option<[u8; INIT_DATA_LEN]>,
    output_hex: bool,
    aligned_mode: Option<&str>,
) where
    D: SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    let iv = iv.unwrap_or_else(|| {
        // The leading bytes are the IV, not ciphertext. (None for ECB: the read is skipped.)
        let mut iv = [0u8; INIT_DATA_LEN];
        if INIT_DATA_LEN > 0
            && let Err(e) = io::stdin().read_exact(&mut iv)
        {
            eprintln!(
                "Error: input too short to contain the {INIT_DATA_LEN}-byte IV that `encrypt` \
                 writes as its first block ({e}). If the IV is held separately, pass it with --iv."
            );
            exit(-1);
        }
        iv
    });

    let mut dec = D::do_decrypt_init(key, &iv).unwrap_or_else(|e| {
        eprintln!("Error: couldn't start decryption: {e:?}");
        exit(-1);
    });

    let mut out = [0u8; CHUNK_LEN];
    let total = stream_chunks(|data| {
        // Cannot fail: the decryptor releases no more than it is given plus what it holds over
        // (under one block buffered, and one whole block held back in case it is the last), and
        // that never exceeds `out`.
        let written = dec.do_decrypt_out(data, &mut out).unwrap();
        write_bytes_or_hex(&out[..written], output_hex);
    });

    if let Some(mode) = aligned_mode {
        check_aligned(mode, total);
    }
    // Releases the block held back above, unpadded; under `NoPadding` all of it is data. A
    // padded ciphertext that is unaligned or has malformed padding fails here.
    let (last, last_len) = dec.do_decrypt_final().unwrap_or_else(|e| {
        // Flush what was already written first, as `check_aligned` does, so the error follows it.
        let _ = io::stdout().flush();
        eprintln!("\nError: decryption failed: {e:?}");
        exit(-1);
    });
    write_bytes_or_hex(&last[..last_len], output_hex);

    finish(output_hex);
}

/// Reads stdin to the end, handing it to `process` in pieces of at most `CHUNK_LEN` bytes, and
/// returns the total number of bytes read. Pieces need not be block-aligned: the cipher buffers a
/// partial block across calls.
fn stream_chunks(mut process: impl FnMut(&[u8])) -> usize {
    let mut buf = [0u8; CHUNK_LEN];
    let mut total = 0usize;
    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            return total;
        }
        total += n;
        process(&buf[..n]);
    }
}

/// Exits with an error if `total` is not a whole number of blocks, for a mode that is defined only
/// on whole blocks and pads nothing. `NoPadding` would also refuse it at `do_*_final`, but without
/// saying how many bytes were left over.
fn check_aligned(mode: &str, total: usize) {
    if !total.is_multiple_of(BLOCK_LEN) {
        // Everything before the misaligned tail has already been written (bar the one block a
        // decryptor holds back until `do_decrypt_final`), and in hex mode is
        // still sitting in stdout's line buffer with no newline to release it. Flush first so the
        // output and the error come out in order rather than the error landing inside it.
        let _ = io::stdout().flush();
        eprintln!(
            "\nError: input to {mode} must be a whole number of {BLOCK_LEN}-byte blocks (data contained {} trailing byte(s)).",
            total % BLOCK_LEN
        );
        exit(-1);
    }
}

/// Flushes stdout, and adds the trailing newline the hex-output commands all emit.
fn finish(output_hex: bool) {
    if output_hex {
        write_stdout(b"\n");
    }
    flush_stdout();
}
