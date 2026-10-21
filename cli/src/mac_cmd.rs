use std::io::Read;
use std::process::exit;
use std::{fs, io};

use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::MAC;
use bouncycastle::hex;
use bouncycastle::hmac::HmacKey;
use bouncycastle::poly1305;
use bouncycastle::poly1305::hazmat::key_from_bytes;
use bouncycastle::sha2::{SHA256, SHA512, SHA512_224, SHA512_256};
use bouncycastle::sha3::kmac::{KMAC128Key, KMAC256Key};
use bouncycastle::sm3::SM3;

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
            let hmac_key = HmacKey::<SHA256>::from_key_material_allow_weak(&key).unwrap();
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SHA512 => {
            let hmac_key = HmacKey::<SHA512>::from_key_material_allow_weak(&key).unwrap();
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SHA512_224 => {
            let hmac_key = HmacKey::<SHA512_224>::from_key_material_allow_weak(&key).unwrap();
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SHA512_256 => {
            let hmac_key = HmacKey::<SHA512_256>::from_key_material_allow_weak(&key).unwrap();
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SM3 => {
            let hmac_key = HmacKey::<SM3>::from_key_material_allow_weak(&key).unwrap();
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
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
    // The allow-weak form, as the HMAC commands use: a CLI is used for test vectors and
    // scripting, where a short or all-zero key is a legitimate thing to want.
    match bit_len {
        128 => do_mac(
            KMAC128Key::with_params_allow_weak(&key, s, length)
                .expect("a valid MAC key")
                .create_generator(),
            verify_val,
            output_hex,
        ),
        256 => do_mac(
            KMAC256Key::with_params_allow_weak(&key, s, length)
                .expect("a valid MAC key")
                .create_generator(),
            verify_val,
            output_hex,
        ),
        _ => panic!("Unsupported algorithm: KMAC-{bit_len}"),
    }
}

/// Poly1305 (RFC 8439 Sec 2.5) under a 32-byte one-time key, which must never MAC a second
/// message. The tag is always the full 16 bytes.
pub(crate) fn poly1305_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file);
    // No key policy, as the other MAC commands take their allow-weak forms: a CLI is used for test
    // vectors and scripting, where a weak or all-zero key is a legitimate thing to want.
    let Ok(bytes) = <&[u8; poly1305::KEY_LEN]>::try_from(key.ref_to_bytes()) else {
        eprintln!("Error: Poly1305 needs a 32-byte one-time key, got {} bytes.", key.key_len());
        exit(-1)
    };
    do_mac(key_from_bytes(bytes).into_generator(), verify_val, output_hex);
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

        crate::helpers::write_bytes_or_hex(&out, output_hex);
        crate::helpers::write_stdout(b"\n");
    } else {
        // verify a MAC
        if mac.do_verify_final(&hex::decode(verify_val.as_ref().unwrap()).unwrap()) {
            exit(0)
        } else {
            exit(-1)
        }
    }
}
