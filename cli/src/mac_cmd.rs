use std::io::{Read, Write};
use std::process::exit;
use std::{fs, io};

use bouncycastle::core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle::core::traits::MAC;
use bouncycastle::hex;
use bouncycastle::hmac::{HMAC_SHA256, HMAC_SHA512};

pub(crate) enum HMACVariant {
    SHA256,
    SHA512,
}

pub(crate) fn mac_cmd(
    hmac_variant: HMACVariant,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    // load the key
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
    key.allow_hazardous_operations();
    key.convert_key_type(KeyType::MACKey).unwrap();


    // instantiate the MAC object and call do_mac()
    match hmac_variant {
        HMACVariant::SHA256 => {
            let mac = HMAC_SHA256::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        },
        HMACVariant::SHA512 => {
            let mac = HMAC_SHA512::new_allow_weak_key(&key).unwrap();
            do_mac(mac, verify_val, output_hex);
        }
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
        let mut out = [0u8; 64];
        let bytes_written =
            mac.do_final_out(&mut out).expect("Failed to compute the MAC value");
        let out = &out[..bytes_written];

        if output_hex {
            for b in out.iter() {
                print!("{b:02x}");
            }
        } else {
            io::stdout().write(out).unwrap();
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
