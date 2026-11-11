//! The `hkdf-*` subcommands: RFC 5869 extract-then-expand.

use std::process::exit;

use crate::helpers::{
    SecretBytes, decode_hex_arg, load_secret, read_input_file, write_bytes_or_hex, write_stdout,
};
use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::hkdf;
use bouncycastle::hkdf::HKDF;
use bouncycastle::hmac::HMACParams;
use bouncycastle::sha2::hkdf::{HKDF_SHA256, HKDF_SHA384, HKDF_SHA512};
use bouncycastle::sm3::hkdf::HKDF_SM3;

#[allow(non_camel_case_types)]
pub(crate) enum HKDFVariant {
    SHA256,
    SHA384,
    SHA512,
    SM3,
}

#[allow(clippy::too_many_arguments)] // one flag per RFC 5869 input, each inline or from a file
pub(crate) fn hkdf_cmd(
    variant: HKDFVariant,
    salt: &Option<String>,
    salt_file: &Option<String>,
    ikm: &Option<String>,
    ikm_file: &Option<String>,
    additional_input: &Option<String>,
    additional_input_file: &Option<String>,
    secret_salt: bool,
    len: usize,
    output_hex: bool,
) {
    // Each value may come from hex on the command line or from a file; the file wins if both
    // are given, as the subcommands' help says. RFC 5869 Section 2.2's salt is optional: absent
    // (neither flag, or an empty value), HKDF uses a string of HashLen zeros.
    let mut salt = match (salt_file, salt) {
        (None, None) => SecretBytes::new(),
        _ => load_secret(salt, salt_file, "salt"),
    };
    // RFC 5869 Section 2.2's salt is "a non-secret random value", typed as such, which credits
    // no entropy; `--secret-salt` marks it as SP 800-56C Rev. 2 Section 5.1's secret salt, the
    // MACKey HKDF credits. The output bytes are the same either way, as the mlkem*-hkdf-*
    // commands' salt is typed. The absent salt is typed the same way so that it is not refused
    // as Unknown.
    let key_type = if secret_salt { KeyType::MACKey } else { KeyType::CryptographicRandom };
    do_hazardous_operations(&mut salt, |salt| salt.set_key_type(key_type)).unwrap_or_else(|e| {
        eprintln!("Error: couldn't load the salt: {e:?}");
        exit(-1);
    });
    let ikm = load_secret(ikm, ikm_file, "ikm");
    crate::kdf_cmd::refuse_empty_ikm(&ikm);

    // RFC 5869 Section 2.3: info is "optional context and application specific information (can
    // be a zero-length string)", so neither flag is required.
    let info = match (additional_input_file, additional_input) {
        (Some(file), _) => read_input_file(file),
        (None, Some(hex_str)) => decode_hex_arg(hex_str, "additional-input"),
        (None, None) => Vec::new(),
    };

    // RFC 5869: PRK = HKDF-Extract(salt, IKM), then OKM = HKDF-Expand(PRK, info, L). The IKM is
    // streamed into the extract phase and the additional input is the expand phase's `info`. The
    // library refuses an L above 255 * HashLen.
    let mut out_key = KeyMaterial::<{ 255 * hkdf::MAX_HMAC_OUTPUT_LEN }>::new();
    let result = match variant {
        HKDFVariant::SHA256 => run(HKDF_SHA256::new(), &salt, &ikm, &info, len, &mut out_key),
        HKDFVariant::SHA384 => run(HKDF_SHA384::new(), &salt, &ikm, &info, len, &mut out_key),
        HKDFVariant::SHA512 => run(HKDF_SHA512::new(), &salt, &ikm, &info, len, &mut out_key),
        HKDFVariant::SM3 => run(HKDF_SM3::new(), &salt, &ikm, &info, len, &mut out_key),
    };
    if let Err(e) = result {
        eprintln!("Error: HKDF failed: {e}");
        exit(-1);
    }

    write_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
    if output_hex {
        write_stdout(b"\n");
    }
}

/// Extract then expand through `h`, into `out_key`.
fn run<H: HMACParams>(
    mut h: HKDF<H>,
    salt: &impl KeyMaterialTrait,
    ikm: &impl KeyMaterialTrait,
    info: &[u8],
    len: usize,
    out_key: &mut impl KeyMaterialTrait,
) -> Result<usize, String> {
    h.do_extract_init(salt).map_err(|e| format!("{e:?}"))?;
    h.do_extract_update_bytes(ikm.ref_to_bytes()).map_err(|e| format!("{e:?}"))?;
    let prk = h.do_extract_final().map_err(|e| format!("{e:?}"))?;
    HKDF::<H>::expand_out(&prk, info, len, out_key).map_err(|e| format!("{e:?}"))
}
