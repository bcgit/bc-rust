//! The `x963kdf-*` and `concatkdf-*` subcommands: one command over the [`KDF`] trait, keying
//! data of `--len` bytes from a shared secret (`--ikm`) and the optional SharedInfo or
//! FixedInfo (`--additional-input`), as the `hkdf-*` subcommands take their inputs minus the
//! salt. The X9.63 KDF is SEC 1 v2 Section 3.6.1 and the concatenation KDF is SP 800-56C Rev. 2
//! Section 4.1 (Option 1, `H(x) = hash(x)`); which one runs is the instance `main` passes.

use crate::helpers::{decode_hex_arg, load_secret, read_input_file, write_bytes_or_hex};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::core::traits::KDF;
use std::process::exit;

/// The most keying data one invocation produces: the `hkdf-*` commands' bound, well inside
/// either KDF's own.
const MAX_OUT_LEN: usize = 255 * 64;

pub(crate) fn kdf_cmd(
    kdf: &dyn KDF,
    ikm: &Option<String>,
    ikm_file: &Option<String>,
    additional_input: &Option<String>,
    additional_input_file: &Option<String>,
    len: usize,
    output_hex: bool,
) {
    // The shared secret Z, from hex on the command line or from a file; the file wins.
    let z = load_secret(ikm, ikm_file, "ikm");
    refuse_empty_ikm(&z);
    // SharedInfo (Section 3.6.1 input 3) and FixedInfo are both optional.
    let info = match (additional_input_file, additional_input) {
        (Some(file), _) => read_input_file(file),
        (None, Some(hex_str)) => decode_hex_arg(hex_str, "additional-input"),
        (None, None) => Vec::new(),
    };
    if len > MAX_OUT_LEN {
        eprintln!("Error: --len must be at most {MAX_OUT_LEN}.");
        exit(-1);
    }

    let mut out_key = KeyMaterial::<MAX_OUT_LEN>::new();
    if let Err(e) = kdf.derive_key_out(&z, &info, len, &mut out_key) {
        eprintln!("Error: key derivation failed: {e:?}");
        exit(-1);
    }
    write_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
}

/// The `KDF` trait derives from an empty key (the framework's suites hold that), which no user
/// of a command line means: an empty `--ikm` or `--ikm-file` is refused by the three KDF
/// commands, before any derivation.
pub(crate) fn refuse_empty_ikm(ikm: &impl KeyMaterialTrait) {
    if ikm.key_len() == 0 {
        eprintln!("Error: `--ikm` is empty; the input keying material must not be empty.");
        exit(-1);
    }
}
