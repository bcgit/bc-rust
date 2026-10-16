use std::fs;
use std::process::exit;

use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::hex;
use bouncycastle::hkdf;
use bouncycastle::sha2::hkdf::{HKDF_SHA256, HKDF_SHA384, HKDF_SHA512};

pub(crate) fn hkdf_cmd(
    hkdfname: &str,
    salt: &Option<String>,
    salt_file: &Option<String>,
    ikm: &Option<String>,
    ikm_file: &Option<String>,
    additional_input: &Option<String>,
    additional_input_file: &Option<String>,
    len: usize,
    output_hex: bool,
) {
    // Each value may come from hex on the command line or from a binary file; the file wins if
    // both are given, as the subcommands' help says.
    let salt_bytes = if let Some(file) = salt_file {
        fs::read(file).unwrap()
    } else if let Some(hex_str) = salt {
        hex::decode(hex_str).unwrap()
    } else {
        eprintln!("Error: either `salt` or `salt-file` must be supplied.");
        exit(-1)
    };
    if salt_bytes.len() > 128 {
        eprintln!("Error: The CLI only supports HKDF salts up to 128 bytes (1024 bits).");
        exit(-1);
    }
    let mut salt_key = KeyMaterial::<1024>::from_bytes(&salt_bytes).unwrap();
    // force it just so the CLI behaves properly even with all-zero or zero-length keys
    do_hazardous_operations(&mut salt_key, |salt_key| salt_key.set_key_type(KeyType::MACKey))
        .unwrap();

    let ikm_bytes = if let Some(file) = ikm_file {
        fs::read(file).unwrap()
    } else if let Some(hex_str) = ikm {
        hex::decode(hex_str).unwrap()
    } else {
        eprintln!("Error: either `ikm` or `ikm_file` must be supplied.");
        exit(-1)
    };

    let info = if let Some(file) = additional_input_file {
        fs::read(file).unwrap()
    } else if let Some(hex_str) = additional_input {
        hex::decode(hex_str).unwrap()
    } else {
        eprintln!("Error: either `additional_input` or `additional_input_file` must be supplied.");
        exit(-1)
    };

    // RFC 5869: PRK = HKDF-Extract(salt, IKM), then OKM = HKDF-Expand(PRK, info, L). The IKM is
    // streamed into the extract phase, so its length is not bounded by a KeyMaterial buffer, and the
    // additional input is the expand phase's `info`. The library refuses an L above 255 * HashLen.
    let mut out_key = KeyMaterial::<{ 255 * hkdf::MAX_HMAC_OUTPUT_LEN }>::new();
    let result = match hkdfname {
        "HKDF-SHA256" => {
            let mut h = HKDF_SHA256::new();
            h.do_extract_init(&salt_key).unwrap();
            h.do_extract_update_bytes(&ikm_bytes).unwrap();
            let prk = h.do_extract_final().unwrap();
            HKDF_SHA256::expand_out(&prk, &info, len, &mut out_key)
        }
        "HKDF-SHA384" => {
            let mut h = HKDF_SHA384::new();
            h.do_extract_init(&salt_key).unwrap();
            h.do_extract_update_bytes(&ikm_bytes).unwrap();
            let prk = h.do_extract_final().unwrap();
            HKDF_SHA384::expand_out(&prk, &info, len, &mut out_key)
        }
        "HKDF-SHA512" => {
            let mut h = HKDF_SHA512::new();
            h.do_extract_init(&salt_key).unwrap();
            h.do_extract_update_bytes(&ikm_bytes).unwrap();
            let prk = h.do_extract_final().unwrap();
            HKDF_SHA512::expand_out(&prk, &info, len, &mut out_key)
        }
        _ => {
            panic!("{} is not a supported HKDF variant.", hkdfname);
        }
    };
    if let Err(e) = result {
        eprintln!("Error: {e:?}");
        exit(-1);
    }

    crate::helpers::write_bytes_or_hex(out_key.ref_to_bytes(), output_hex);
}
