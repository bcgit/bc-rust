//! The `scrypt` subcommand: scrypt (RFC 7914), a derived key of `--len` bytes from a password,
//! a salt and the cost parameters N, r and p. The password comes from a file or from stdin,
//! never from the command line, as for `pbkdf2`.

use crate::helpers::{
    decode_hex_arg, finish_stdout, read_input_file, read_secret_file_or_stdin,
    write_secret_bytes_or_hex,
};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::core::traits::KDF;
use bouncycastle::digest::scrypt::{SCrypt, ScryptParams};
use std::process::exit;

/// The most key one invocation produces: the other KDF commands' bound.
const MAX_OUT_LEN: usize = 255 * 64;

#[allow(clippy::too_many_arguments)]
pub(crate) fn scrypt_cmd(
    log2_n: u8,
    r: u32,
    p: u32,
    max_memory_mib: usize,
    password_file: &Option<String>,
    salt: &Option<String>,
    salt_file: &Option<String>,
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
    let params = match ScryptParams::new(log2_n, r, p) {
        Ok(params) => params,
        Err(e) => {
            eprintln!("Error: the scrypt parameters are not valid: {e:?}");
            exit(-1);
        }
    };
    let max_work_len = max_memory_mib.saturating_mul(1024 * 1024);
    if params.work_len() > max_work_len {
        eprintln!(
            "Error: these parameters need {} bytes of working memory, more than --max-memory allows ({max_memory_mib} MiB).",
            params.work_len()
        );
        exit(-1);
    }
    // The password's bytes as they are, a trailing newline included: the function takes octets.
    let password = read_secret_file_or_stdin(password_file);
    if password.key_len() == 0 {
        eprintln!("Error: the password is empty.");
        exit(-1);
    }

    let kdf = SCrypt::new(&salt, params).with_max_work_len(max_work_len);
    let mut out_key = KeyMaterial::<MAX_OUT_LEN>::new();
    if let Err(e) = kdf.derive_key_out(&password, &[], len, &mut out_key) {
        eprintln!("Error: key derivation failed: {e:?}");
        exit(-1);
    }
    let written = write_secret_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
    // `exit` runs no destructors, so the secrets are dropped before a failed write exits.
    drop(out_key);
    drop(password);
    finish_stdout(written);
}
