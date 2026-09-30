//! AES key wrap (KW, NIST SP 800-38F Sec 6.2 / RFC 3394) and key wrap with padding (KWP, Sec 6.3
//! / RFC 5649): `aes{128,192,256}-{kw,kwp} wrap|unwrap`, stdin to stdout.
//!
//! Key loading is shared with the other AES commands ([`crate::helpers::block_mode_helpers::load_key`]),
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
//! different KEK, or was produced by the other algorithm (KW vs KWP) makes `unwrap` exit non-zero
//! with nothing written to stdout. It does not say which of those it was; that is deliberate.
//!
//! # Binary in, binary out
//!
//! stdin is read as binary. `-x` renders the output as hex. For hex input, pipe through
//! `hex-decode` first:
//!
//! ```text
//! echo -n 00112233445566778899aabbccddeeff | bc-rust hex-decode \
//!     | bc-rust aes128-kw wrap --key 000102030405060708090a0b0c0d0e0f -x
//! ```

use crate::helpers::block_mode_helpers::load_key;
use crate::helpers::write_bytes_or_hex;
use bouncycastle::aes::{
    AES_KW_128, AES_KW_192, AES_KW_256, AES_KWP_128, AES_KWP_192, AES_KWP_256,
};
use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::{KeyUnwrapper, KeyWrapper};
use clap::ValueEnum;
use std::io::Read;
use std::process::exit;

/// Which direction to run.
#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum KeyWrapAction {
    /// Wrap stdin under the KEK and write the ciphertext to stdout.
    Wrap,
    /// Unwrap stdin under the KEK and write the recovered data to stdout, or exit non-zero if
    /// the ciphertext is not authentic.
    Unwrap,
}

pub(crate) fn aes128_kw_cmd(
    action: &KeyWrapAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_KW_128, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128-KW"),
        output_hex,
        "AES-128-KW",
    );
}

pub(crate) fn aes192_kw_cmd(
    action: &KeyWrapAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_KW_192, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192-KW"),
        output_hex,
        "AES-192-KW",
    );
}

pub(crate) fn aes256_kw_cmd(
    action: &KeyWrapAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_KW_256, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256-KW"),
        output_hex,
        "AES-256-KW",
    );
}

pub(crate) fn aes128_kwp_cmd(
    action: &KeyWrapAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_KWP_128, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128-KWP"),
        output_hex,
        "AES-128-KWP",
    );
}

pub(crate) fn aes192_kwp_cmd(
    action: &KeyWrapAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_KWP_192, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192-KWP"),
        output_hex,
        "AES-192-KWP",
    );
}

pub(crate) fn aes256_kwp_cmd(
    action: &KeyWrapAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_KWP_256, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256-KWP"),
        output_hex,
        "AES-256-KWP",
    );
}

/// Reads all of stdin, wraps or unwraps it under `kek` with the algorithm `W`, and writes the
/// result. `alg` names the algorithm in error messages.
fn run<W, const KEK_LEN: usize>(
    action: &KeyWrapAction,
    kek: &KeyMaterial<KEK_LEN>,
    output_hex: bool,
    alg: &str,
) where
    W: KeyWrapper<KEK_LEN> + KeyUnwrapper<KEK_LEN>,
{
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("Error: couldn't read stdin: {e}");
        exit(-1);
    }

    let (result, mut output) = match action {
        KeyWrapAction::Wrap => {
            let mut output = vec![0u8; W::wrap_out_len(input.len())];
            (W::wrap_out(kek, &input, &mut output), output)
        }
        KeyWrapAction::Unwrap => {
            let mut output = vec![0u8; W::unwrap_out_max_len(input.len())];
            (W::unwrap_out(kek, &input, &mut output), output)
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
