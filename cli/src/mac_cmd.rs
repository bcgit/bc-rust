use std::io::{Read, Write};
use std::process::exit;
use std::{fs, io};

use bouncycastle::core::key_material::{
    KeyMaterial512, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle::core::traits::MAC;
use bouncycastle::hex;
use bouncycastle::hmac::{HMAC_SHA256, HMAC_SHA512, HMAC_SHA512_224, HMAC_SHA512_256, HMAC_SM3};
use bouncycastle::sha3::{KMAC128, KMAC256};

#[allow(non_camel_case_types)]
pub(crate) enum HMACVariant {
    SHA256,
    SHA512,
    SHA512_224,
    SHA512_256,
    SM3,
}

/// Loads a MAC key from `--key` (hex) or `--key-file` (raw), tagged as a MAC key.
fn load_mac_key(key: &Option<String>, key_file: &Option<String>) -> KeyMaterial512 {
    let key_bytes: Vec<u8> = if key.is_some() {
        hex::decode(key.as_ref().unwrap()).unwrap()
    } else if key_file.is_some() {
        fs::read(key_file.as_ref().unwrap()).unwrap()
    } else {
        eprintln!("Error: either `key` or `key-file` must be supplied.");
        exit(-1)
    };

    if key_bytes.len() > 64 {
        eprintln!("Error: CLI only supports MAC keys 64 bytes.");
        exit(-1);
    }
    let mut key = KeyMaterial512::from_bytes(&key_bytes).unwrap();
    do_hazardous_operations(&mut key, |key| key.set_key_type(KeyType::MACKey)).unwrap();
    key
}

pub(crate) fn mac_cmd(
    hmac_variant: HMACVariant,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file);

    // instantiate the MAC object and call do_mac()
    match hmac_variant {
        HMACVariant::SHA256 => {
            let mac = HMAC_SHA256::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        }
        HMACVariant::SHA512 => {
            let mac = HMAC_SHA512::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        }
        HMACVariant::SHA512_224 => {
            let mac = HMAC_SHA512_224::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        }
        HMACVariant::SHA512_256 => {
            let mac = HMAC_SHA512_256::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        }
        HMACVariant::SM3 => {
            let mac = HMAC_SM3::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        }
    }
}

/// KMAC (NIST SP 800-185 Sec 4), which unlike HMAC takes a customization string and a caller-
/// chosen tag length -- both are bound into the computation, so the verifier must use the same.
pub(crate) fn kmac_cmd(
    bit_len: usize,
    length: usize,
    customization: &Option<String>,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file);
    let s = customization.as_deref().unwrap_or("").as_bytes();
    // new_allow_weak_key, as the HMAC commands do: a CLI is used for test vectors and scripting,
    // where a short or all-zero key is a legitimate thing to want.
    match bit_len {
        128 => do_mac(
            KMAC128::new_with_params(&key, s, length, true).expect("a valid MAC key"),
            verify_val,
            output_hex,
        ),
        256 => do_mac(
            KMAC256::new_with_params(&key, s, length, true).expect("a valid MAC key"),
            verify_val,
            output_hex,
        ),
        _ => panic!("Unsupported algorithm: KMAC-{bit_len}"),
    }
}

fn do_mac(mut mac: impl MAC, verify_val: &Option<String>, output_hex: bool) {
    // read the content to be MAC'd from stdin
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        mac.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    if verify_val.is_none() {
        // compute a MAC value
        let out = mac.do_final();

        if output_hex {
            for b in out.iter() {
                print!("{b:02x}");
            }
        } else {
            io::stdout().write(&out).unwrap();
        }
        println!();
    } else {
        // verify a MAC
        if mac.do_verify_final(&hex::decode(verify_val.as_ref().unwrap()).unwrap()) {
            exit(0)
        } else {
            exit(-1)
        }
    }
}
