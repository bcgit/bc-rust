use std::{fs, io};
use std::io::Write;
use std::process::exit;

use bouncycastle::core_interface::key_material::{KeyMaterialSized, KeyType};
use bouncycastle::core_interface::traits::KeyMaterial;
use bouncycastle::hex;
use bouncycastle::hkdf;

pub(crate) fn hkdf_cmd(hkdfname: &str,
                       salt: &Option<String>,
                       salt_file: &Option<String>,
                       ikm: &Option<String>,
                       ikm_file: &Option<String>,
                       additional_input: &Option<String>,
                       additional_input_file: &Option<String>,
                       len: usize,
                       output_hex: bool ) {
    let salt_bytes: Vec<u8>;
    let ikm_bytes: Vec<u8>;
    let additional_input_bytes: Vec<u8>;
    let mut out_key = KeyMaterialSized::<1024>::new();

    if len > 1024 {
        eprintln!("Error: The CLI only supports output lengths up to 128 bytes (1024 bits).");
        exit(-1);
    }

    // load the values

    salt_bytes = if salt.is_some() {
        hex::decode(salt.as_ref().unwrap()).unwrap()
    } else if salt_file.is_some() {
        fs::read(salt_file.as_ref().unwrap()).unwrap()
    } else {
        eprintln!("Error: either `salt` or `salt-file` must be supplied.");
        exit(-1)
    };
    if salt_bytes.len() > 128 {
        eprintln!("Error: The CLI only supports HKDF salts up to 128 bytes (1024 bytes).");
        exit(-1);
    }
    let mut salt_key = KeyMaterialSized::<1024>::from_bytes(&salt_bytes).unwrap();
    // force it just so the CLI behaves properly even with all-zero or zero-length keys
    salt_key.allow_hazardous_operations();
    salt_key.convert_key_type(KeyType::MACKey).unwrap();

    ikm_bytes = if ikm.is_some() {
        hex::decode(ikm.as_ref().unwrap()).unwrap()
    } else if ikm_file.is_some() {
        fs::read(ikm_file.as_ref().unwrap()).unwrap()
    } else {
        eprintln!("Error: either `ikm` or `ikm_file` must be supplied.");
        exit(-1)
    };


    additional_input_bytes = if additional_input.is_some() {
        hex::decode(additional_input.as_ref().unwrap()).unwrap()
    } else if additional_input.is_some() {
        fs::read(additional_input_file.as_ref().unwrap()).unwrap()
    } else {
        eprintln!("Error: either `additional_input` or `additional_input_file` must be supplied.");
        exit(-1)
    };

    // Do the HKDF

    match hkdfname {
        "HKDF-SHA256" => {
            let mut h = hkdf::HKDF_SHA256::new();
            h.do_extract_init(&salt_key).unwrap();
            h.do_extract_update_bytes(ikm_bytes.as_slice()).unwrap();
            h.do_extract_update_bytes(additional_input_bytes.as_slice()).unwrap();
            h.do_extract_final_out(&mut out_key).unwrap();
        },
        "HKDF-SHA512" => {
            let mut h = hkdf::HKDF_SHA512::new();
            h.do_extract_init(&salt_key).unwrap();
            h.do_extract_update_bytes(ikm_bytes.as_slice()).unwrap();
            h.do_extract_update_bytes(additional_input_bytes.as_slice()).unwrap();
            h.do_extract_final_out(&mut out_key).unwrap();
        },
        _ => { panic!("{} is not a supported HKDF variant.", hkdfname); }
    }


    if output_hex {
        for b in out_key.ref_to_bytes().iter() {
            print!("{b:02x}");
        }
    } else { io::stdout().write(&out_key.ref_to_bytes()).unwrap(); }
}