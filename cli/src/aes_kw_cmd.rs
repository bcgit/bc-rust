//! AES key wrap (KW, NIST SP 800-38F Sec 6.2 / RFC 3394) and key wrap with padding (KWP, Sec 6.3
//! / RFC 5649): `aes{128,192,256}-{kw,kwp} -d encrypt|decrypt`, stdin to stdout. `encrypt` wraps
//! and `decrypt` unwraps: the spelling is shared with every other cipher command, and SP 800-38F
//! itself calls the two halves authenticated encryption and decryption (KW-AE, KW-AD).
//!
//! Key loading is shared with the other AES commands ([`crate::helpers::block_mode_helpers::load_key_object`]),
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
//! is nothing to prepend or strip. The output is exactly `wrap_out_len` of the input: one 8-byte
//! semiblock longer for KW, the input rounded up to a multiple of 8 plus 8 for KWP.
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

use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use crate::helpers::write_bytes_or_hex;
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::{KW, KWP};
use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::symmetric_key::{KeyUnwrappingKey, KeyWrappingKey};
use std::io::Read;
use std::process::exit;

pub(crate) fn aes128_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        direction,
        &load_key_object::<AES128Key<KW>, 16>(key, key_file, "AES-128-KW"),
        output_hex,
        "AES-128-KW",
    );
}

pub(crate) fn aes192_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        direction,
        &load_key_object::<AES192Key<KW>, 24>(key, key_file, "AES-192-KW"),
        output_hex,
        "AES-192-KW",
    );
}

pub(crate) fn aes256_kw_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        direction,
        &load_key_object::<AES256Key<KW>, 32>(key, key_file, "AES-256-KW"),
        output_hex,
        "AES-256-KW",
    );
}

pub(crate) fn aes128_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        direction,
        &load_key_object::<AES128Key<KWP>, 16>(key, key_file, "AES-128-KWP"),
        output_hex,
        "AES-128-KWP",
    );
}

pub(crate) fn aes192_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        direction,
        &load_key_object::<AES192Key<KWP>, 24>(key, key_file, "AES-192-KWP"),
        output_hex,
        "AES-192-KWP",
    );
}

pub(crate) fn aes256_kwp_cmd(
    direction: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        direction,
        &load_key_object::<AES256Key<KWP>, 32>(key, key_file, "AES-256-KWP"),
        output_hex,
        "AES-256-KWP",
    );
}

/// Reads all of stdin, wraps or unwraps it under `kek`, and writes the result. `alg` names the
/// algorithm in error messages.
fn run<K, const KEK_LEN: usize>(direction: &CipherDirection, kek: &K, output_hex: bool, alg: &str)
where
    K: KeyWrappingKey<KEK_LEN> + KeyUnwrappingKey<KEK_LEN>,
{
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("Error: couldn't read stdin: {e}");
        exit(-1);
    }

    let (result, mut output) = match direction {
        CipherDirection::Encrypt => {
            let mut output = vec![0u8; kek.wrap_out_len(input.len())];
            (kek.wrap_out(&input, &mut output), output)
        }
        CipherDirection::Decrypt => {
            let mut output = vec![0u8; kek.unwrap_out_max_len(input.len())];
            (kek.unwrap_out(&input, &mut output), output)
        }
    };

    match result {
        Ok(n) => {
            output.truncate(n);
            write_bytes_or_hex(&output, output_hex);
        }
        Err(SymmetricCipherError::DecryptionFailed) => {
            eprintln!(
                "Error: {alg} unwrap failed: the input is not an authentic {alg} ciphertext under \
                 this key (it was tampered with, wrapped under a different key, or produced by a \
                 different algorithm)."
            );
            exit(-1);
        }
        Err(SymmetricCipherError::InvalidInputLength(why)) => {
            eprintln!("Error: {alg}: input of {} bytes rejected: {why}.", input.len());
            exit(-1);
        }
        Err(e) => {
            eprintln!("Error: {alg} failed: {e:?}");
            exit(-1);
        }
    }
}
