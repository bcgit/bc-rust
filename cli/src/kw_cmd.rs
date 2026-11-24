//! Key wrap (KW, NIST SP 800-38F Sec 6.2 / RFC 3394) and key wrap with padding (KWP, Sec 6.3 /
//! RFC 5649) over any 128-bit block permutation: the `aes*-kw`, `aria*-kw`, `camellia*-kw`,
//! `sm4-kw` and `*-kwp` commands, `-d encrypt|decrypt`, stdin to stdout, as two generic
//! functions that `main` instantiates per cipher and key length. `encrypt` wraps
//! and `decrypt` unwraps: the spelling is shared with every other cipher command, and SP 800-38F
//! itself calls the two halves authenticated encryption and decryption (KW-AE, KW-AD).
//!
//! Key loading is shared with the other cipher commands ([`crate::helpers::block_mode_helpers::load_key_object`]),
//! so `--key` / `--key-file` behave identically. Everything else differs from the streaming
//! commands, because key wrap is a one-shot algorithm:
//!
//! # Not streaming
//!
//! The wrapping function makes six passes over the whole input (SP 800-38F Algorithm 1), so there
//! is no way to emit output before all of stdin has been read. These commands read stdin to the
//! end and then write the result in one go. That is fine for what key wrap is for -- a key, or a
//! small encoded private key -- and the algorithm's own limits (below) keep it bounded.
//!
//! # No IV
//!
//! Key wrap is deterministic: the same input under the same KEK gives the same output, and there
//! is nothing to prepend or strip. The output is one 8-byte semiblock longer than the input for
//! KW, and the input rounded up to a multiple of 8 plus 8 for KWP.
//!
//! # Input lengths
//!
//! `aes*-kw` wraps 2 or more whole 8-byte semiblocks (16, 24, 32, ... bytes: the lengths of
//! AES, HMAC and other symmetric keys) and unwraps ciphertexts of 3 or more. `aes*-kwp` wraps
//! anything from 1 byte to 2^32 - 1 bytes and unwraps ciphertexts of 2 or more whole semiblocks.
//! Other lengths are rejected with an explanation rather than padded or truncated.
//!
//! # Unwrap fails closed
//!
//! Both algorithms are authenticated. A ciphertext that was tampered with, was wrapped under a
//! different KEK, or was produced by the other algorithm (KW vs KWP) makes `decrypt` exit
//! non-zero with nothing written to stdout. It does not say which of those it was; that is
//! deliberate.
//!
//! # Binary in, binary out
//!
//! stdin is read as binary. `-x` renders the output as hex. For hex input, pipe through
//! `hex-decode` first:
//!
//! ```text
//! echo -n 00112233445566778899aabbccddeeff | bc-rust hex-decode \
//!     | bc-rust aes128-kw -d encrypt --key 000102030405060708090a0b0c0d0e0f -x
//! ```

use crate::helpers::block_mode_helpers::{CipherDirection, InputLimit, load_key_object};
use crate::helpers::{finish_stdout, read_secret_stdin_all, wipe, write_secret_bytes_or_hex};
use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::symmetric_key::{KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle::symmetric::BlockCipherKey;
use bouncycastle::symmetric::modes::ModeNames;
use bouncycastle::symmetric::modes::{KW, KWP};
use std::process::exit;

/// KW under a `KEY_LEN`-byte key-encryption key for the permutation `P`; `alg` names the cipher
/// and key length, "AES-128" and the like, and the messages add the algorithm.
pub(crate) fn kw_cmd<P, const KEY_LEN: usize>(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
{
    let alg = format!("{alg}-KW");
    run::<_, KEY_LEN>(
        direction,
        load_key_object::<BlockCipherKey<P, KW>, KEY_LEN>(key, key_file, &alg),
        None,
        output_hex,
        &alg,
    );
}

/// KWP, as [`kw_cmd`].
pub(crate) fn kwp_cmd<P, const KEY_LEN: usize>(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
{
    let alg = format!("{alg}-KWP");
    run::<_, KEY_LEN>(
        direction,
        load_key_object::<BlockCipherKey<P, KWP>, KEY_LEN>(key, key_file, &alg),
        None,
        output_hex,
        &alg,
    );
}

/// Reads all of stdin, wraps or unwraps it under `kek`, and writes the result. `alg` names the
/// algorithm in error messages. Shared with the other block ciphers' key-wrap commands.
pub(crate) fn run<K, const KEK_LEN: usize>(
    direction: &CipherDirection,
    kek: K,
    limit: Option<&InputLimit>,
    output_hex: bool,
    alg: &str,
) where
    K: KeyWrappingKey<KEK_LEN> + KeyUnwrappingKey<KEK_LEN>,
{
    match direction {
        CipherDirection::Encrypt => run_with(
            kek,
            |kek, len| kek.wrap_out_len(len),
            |kek, input, out| kek.wrap_out(input, out),
            limit,
            output_hex,
            alg,
        ),
        CipherDirection::Decrypt => run_with(
            kek,
            |kek, len| kek.unwrap_out_max_len(len),
            |kek, input, out| kek.unwrap_out(input, out),
            None,
            output_hex,
            alg,
        ),
    }
}

/// Reads all of stdin, applies `op` to it and writes the result; the unwrap-only commands pass
/// their key's `unwrap_out` alone, so that no wrapper is ever instantiated for their key type.
/// `out_len` is the output buffer `op` needs for an input of the given length. `limit`, for a
/// wrapping command whose standard bounds what one key may protect, is checked against the whole
/// input before `op` runs.
///
/// One side of either direction is a key in the clear, so the input and the output are both
/// wiped before the function returns or exits, and `kek` is dropped once `op` has run, before
/// anything is written or reported. A failed read of stdin still exits with `kek` alive.
pub(crate) fn run_with<K>(
    kek: K,
    out_len: impl FnOnce(&K, usize) -> usize,
    op: impl FnOnce(&K, &[u8], &mut [u8]) -> Result<usize, SymmetricCipherError>,
    limit: Option<&InputLimit>,
    output_hex: bool,
    alg: &str,
) {
    let mut input = read_secret_stdin_all();
    let input_len = input.len();
    if let Some(limit) = limit
        && input_len as u64 > limit.max_bytes
    {
        wipe(&mut input);
        drop(kek);
        eprintln!("Error: {}", limit.message);
        exit(-1);
    }

    let mut output = vec![0u8; out_len(&kek, input_len)];
    let result = op(&kek, &input, &mut output);
    // `exit` runs no destructors.
    drop(kek);
    wipe(&mut input);
    let written = match result {
        Ok(written) => write_secret_bytes_or_hex(&output[..written], output_hex),
        Err(_) => Ok(()),
    };
    wipe(&mut output);
    finish_stdout(written);

    match result {
        Ok(_) => {}
        Err(SymmetricCipherError::DecryptionFailed) => {
            eprintln!(
                "Error: {alg} unwrap failed: the input is not an authentic {alg} ciphertext under \
                 this key (it was tampered with, wrapped under a different key, or produced by a \
                 different algorithm)."
            );
            exit(-1);
        }
        Err(SymmetricCipherError::InvalidInputLength(why)) => {
            eprintln!("Error: {alg}: input of {input_len} bytes rejected: {why}.");
            exit(-1);
        }
        Err(e) => {
            eprintln!("Error: {alg} failed: {e:?}");
            exit(-1);
        }
    }
}
