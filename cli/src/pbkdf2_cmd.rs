//! The `pbkdf2` subcommand: PBKDF2 (RFC 8018 Section 5.2) over HMAC, a derived key of `--len`
//! bytes from a password, a salt and an iteration count. The password comes from a file or from
//! stdin, never from the command line, which other users can read and the shell records.

use crate::helpers::{
    decode_hex_arg, read_input_file, read_secret_file_or_stdin, write_secret_bytes_or_hex,
};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::digest::hmac::HMACParams;
use bouncycastle::digest::pbkdf2::PBKDF2;
use bouncycastle::digest::sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle::digest::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use clap::ValueEnum;
use std::num::NonZeroU32;
use std::process::exit;

/// The most key one invocation produces: the other KDF commands' bound.
const MAX_OUT_LEN: usize = 255 * 64;

/// The HMAC PBKDF2 runs over.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum Pbkdf2Prf {
    #[value(name = "hmac-sha224")]
    HmacSha224,
    #[value(name = "hmac-sha256")]
    HmacSha256,
    #[value(name = "hmac-sha384")]
    HmacSha384,
    #[value(name = "hmac-sha512")]
    HmacSha512,
    #[value(name = "hmac-sha3-224")]
    HmacSha3_224,
    #[value(name = "hmac-sha3-256")]
    HmacSha3_256,
    #[value(name = "hmac-sha3-384")]
    HmacSha3_384,
    #[value(name = "hmac-sha3-512")]
    HmacSha3_512,
}

fn run<H: HMACParams>(
    password: &impl KeyMaterialTrait,
    salt: &[u8],
    iterations: NonZeroU32,
    len: usize,
    output_hex: bool,
) {
    let mut out_key = KeyMaterial::<MAX_OUT_LEN>::new();
    if let Err(e) = PBKDF2::<H>::derive_out(password, salt, iterations, len, &mut out_key) {
        eprintln!("Error: key derivation failed: {e:?}");
        exit(-1);
    }
    write_secret_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
}

pub(crate) fn pbkdf2_cmd(
    prf: Pbkdf2Prf,
    password_file: &Option<String>,
    salt: &Option<String>,
    salt_file: &Option<String>,
    iterations: NonZeroU32,
    len: usize,
    output_hex: bool,
) {
    // The salt is public; from a file or hex on the command line, the file winning.
    let salt = match (salt_file, salt) {
        (Some(file), _) => read_input_file(file),
        (None, Some(hex_str)) => decode_hex_arg(hex_str, "salt"),
        (None, None) => {
            eprintln!("Error: either `--salt` or `--salt-file` must be supplied.");
            exit(-1);
        }
    };
    if len > MAX_OUT_LEN {
        eprintln!("Error: --len must be at most {MAX_OUT_LEN}.");
        exit(-1);
    }
    // The password's bytes as they are, a trailing newline included: the function takes octets.
    let password = read_secret_file_or_stdin(password_file);
    if password.key_len() == 0 {
        eprintln!("Error: the password is empty.");
        exit(-1);
    }

    match prf {
        Pbkdf2Prf::HmacSha224 => run::<SHA224>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha256 => run::<SHA256>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha384 => run::<SHA384>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha512 => run::<SHA512>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha3_224 => run::<SHA3_224>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha3_256 => run::<SHA3_256>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha3_384 => run::<SHA3_384>(&password, &salt, iterations, len, output_hex),
        Pbkdf2Prf::HmacSha3_512 => run::<SHA3_512>(&password, &salt, iterations, len, output_hex),
    }
}
