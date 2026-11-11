//! The `concatkdf-*` subcommands: the NIST concatenation KDF of SP 800-56C Rev. 2 Section 4.1
//! (Option 1, `H(x) = hash(x)`), keying material of `--len` bytes from a shared secret (`--ikm`)
//! and the optional `FixedInfo` (`--additional-input`), as the `x963kdf-*` subcommands take
//! theirs.

use crate::helpers::{decode_hex_arg, load_secret, read_input_file, write_bytes_or_hex};
use bouncycastle::concatkdf::{
    ConcatKDF_SHA3_256, ConcatKDF_SHA3_384, ConcatKDF_SHA3_512, ConcatKDF_SHA256, ConcatKDF_SHA384,
    ConcatKDF_SHA512,
};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use std::process::exit;

/// The most keying material one invocation produces: the `hkdf-*` and `x963kdf-*` commands'
/// bound, well inside Section 4.1 step 2's.
const MAX_OUT_LEN: usize = 255 * 64;

#[allow(non_camel_case_types)]
pub(crate) enum ConcatKDFVariant {
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

pub(crate) fn concatkdf_cmd(
    variant: ConcatKDFVariant,
    ikm: &Option<String>,
    ikm_file: &Option<String>,
    additional_input: &Option<String>,
    additional_input_file: &Option<String>,
    len: usize,
    output_hex: bool,
) {
    // The shared secret Z, from hex on the command line or from a file; the file wins.
    let z = load_secret(ikm, ikm_file, "ikm");
    // FixedInfo may be empty.
    let fixed_info = match (additional_input_file, additional_input) {
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
        ConcatKDFVariant::SHA256 => {
            ConcatKDF_SHA256::derive_out(&z, &fixed_info, len, &mut out_key)
        }
        ConcatKDFVariant::SHA384 => {
            ConcatKDF_SHA384::derive_out(&z, &fixed_info, len, &mut out_key)
        }
        ConcatKDFVariant::SHA512 => {
            ConcatKDF_SHA512::derive_out(&z, &fixed_info, len, &mut out_key)
        }
        ConcatKDFVariant::SHA3_256 => {
            ConcatKDF_SHA3_256::derive_out(&z, &fixed_info, len, &mut out_key)
        }
        ConcatKDFVariant::SHA3_384 => {
            ConcatKDF_SHA3_384::derive_out(&z, &fixed_info, len, &mut out_key)
        }
        ConcatKDFVariant::SHA3_512 => {
            ConcatKDF_SHA3_512::derive_out(&z, &fixed_info, len, &mut out_key)
        }
    };
    if let Err(e) = result {
        eprintln!("Error: key derivation failed: {e:?}");
        exit(-1);
    }
    write_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
}
