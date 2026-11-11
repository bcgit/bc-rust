//! The `x963kdf-*` subcommands: the ANSI X9.63 KDF of SEC 1 v2 Section 3.6.1, keying data of
//! `--len` bytes from a shared secret (`--ikm`) and the optional `SharedInfo`
//! (`--additional-input`), as the `hkdf-*` subcommands take their inputs minus the salt.

use crate::helpers::{decode_hex_arg, load_secret, read_input_file, write_bytes_or_hex};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::x963kdf::{X963KDF_SHA256, X963KDF_SHA384, X963KDF_SHA512};
use std::process::exit;

/// The most keying data one invocation produces: the `hkdf-*` commands' bound, well inside
/// Section 3.6.1 step 2's.
const MAX_OUT_LEN: usize = 255 * 64;

#[allow(non_camel_case_types)]
pub(crate) enum X963KDFVariant {
    SHA256,
    SHA384,
    SHA512,
}

pub(crate) fn x963kdf_cmd(
    variant: X963KDFVariant,
    ikm: &Option<String>,
    ikm_file: &Option<String>,
    additional_input: &Option<String>,
    additional_input_file: &Option<String>,
    len: usize,
    output_hex: bool,
) {
    // The shared secret Z, from hex on the command line or from a file; the file wins.
    let z = load_secret(ikm, ikm_file, "ikm");
    // SharedInfo is optional (Section 3.6.1 input 3).
    let shared_info = match (additional_input_file, additional_input) {
        (Some(file), _) => read_input_file(file),
        (None, Some(hex_str)) => decode_hex_arg(hex_str, "additional-input"),
        (None, None) => Vec::new(),
    };
    if len > MAX_OUT_LEN {
        eprintln!("Error: --len must be at most {MAX_OUT_LEN}.");
        exit(-1);
    }

    let mut out_key = KeyMaterial::<MAX_OUT_LEN>::new();
    let result = match variant {
        X963KDFVariant::SHA256 => X963KDF_SHA256::derive_out(&z, &shared_info, len, &mut out_key),
        X963KDFVariant::SHA384 => X963KDF_SHA384::derive_out(&z, &shared_info, len, &mut out_key),
        X963KDFVariant::SHA512 => X963KDF_SHA512::derive_out(&z, &shared_info, len, &mut out_key),
    };
    if let Err(e) = result {
        eprintln!("Error: key derivation failed: {e:?}");
        exit(-1);
    }
    write_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
}
