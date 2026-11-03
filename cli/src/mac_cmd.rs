//! The `hmac-*` and `kmac*` subcommands: a MAC over stdin, computed or verified.

use crate::helpers::{
    SecretBytes, decode_hex_arg, load_secret, stream_stdin, write_bytes_or_hex, write_stdout,
};
use crate::sha3_cmd::{MAX_FIXED_OUTPUT_LEN, Strength};
use bouncycastle::core::errors::MACError;
use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::MAC;
use bouncycastle::hmac::HmacKey;
use bouncycastle::sha2::{SHA256, SHA512, SHA512_224, SHA512_256};
use bouncycastle::sha3::kmac::{KMAC128Key, KMAC256Key};
use bouncycastle::sm3::SM3;
use std::process::exit;

#[allow(non_camel_case_types)]
pub(crate) enum HMACVariant {
    SHA256,
    SHA512,
    SHA512_224,
    SHA512_256,
    SM3,
}

/// The MAC key from `--key-file` or `--key`, tagged as a MAC key. Any length the secret buffer
/// holds is accepted: HMAC hashes a key longer than its block (RFC 2104 Section 2), and KMAC
/// encodes the key's length (SP 800-185 Section 4.2).
fn load_mac_key(key: &Option<String>, key_file: &Option<String>) -> SecretBytes {
    let mut key = load_secret(key, key_file, "key");
    if key.key_type() == KeyType::Zeroized {
        // Same stance as the cipher loaders: warn, then do what was asked. A CLI is used for
        // test vectors and scripting, where an all-zero key is a legitimate thing to want.
        eprintln!(
            "Warning: all-zero (or otherwise zeroized) key provided. Proceeding, but this is not secure."
        );
    }
    do_hazardous_operations(&mut key, |key| key.set_key_type(KeyType::MACKey)).unwrap_or_else(
        |e| {
            eprintln!("Error: couldn't load the key: {e:?}");
            exit(-1);
        },
    );
    key
}

fn mac_key_error(e: MACError) -> ! {
    eprintln!("Error: couldn't build the MAC key: {e:?}");
    exit(-1)
}

pub(crate) fn mac_cmd(
    hmac_variant: HMACVariant,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    let key = load_mac_key(key, key_file);

    // The allow-weak form: a CLI is used for test vectors and scripting, where a short or
    // all-zero key is a legitimate thing to want.
    match hmac_variant {
        HMACVariant::SHA256 => {
            let hmac_key = HmacKey::<SHA256>::from_key_material_allow_weak(&key)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SHA512 => {
            let hmac_key = HmacKey::<SHA512>::from_key_material_allow_weak(&key)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SHA512_224 => {
            let hmac_key = HmacKey::<SHA512_224>::from_key_material_allow_weak(&key)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SHA512_256 => {
            let hmac_key = HmacKey::<SHA512_256>::from_key_material_allow_weak(&key)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
        HMACVariant::SM3 => {
            let hmac_key = HmacKey::<SM3>::from_key_material_allow_weak(&key)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(hmac_key.create_generator(), verify_val, output_hex);
        }
    }
}

/// KMAC (NIST SP 800-185 Sec 4), which unlike HMAC takes a customization string and a caller-
/// chosen tag length -- both are bound into the computation, so the verifier must use the same.
pub(crate) fn kmac_cmd(
    strength: Strength,
    length: usize,
    customization: &[u8],
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    if length > MAX_FIXED_OUTPUT_LEN {
        eprintln!(
            "Error: a KMAC tag is computed whole; this command takes at most {MAX_FIXED_OUTPUT_LEN} bytes. Use kmacxof* for a long, streamed output."
        );
        exit(-1);
    }
    let key = load_mac_key(key, key_file);
    match strength {
        Strength::Bits128 => {
            let kmac_key = KMAC128Key::with_params_allow_weak(&key, customization, length)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(kmac_key.create_generator(), verify_val, output_hex)
        }
        Strength::Bits256 => {
            let kmac_key = KMAC256Key::with_params_allow_weak(&key, customization, length)
                .unwrap_or_else(|e| mac_key_error(e));
            do_mac(kmac_key.create_generator(), verify_val, output_hex)
        }
    }
}

/// Streams stdin into `mac`, then writes the tag, or verifies `--verify` against it and reports
/// the outcome through the exit status (0 verified, 255 not) and an `Error:` line.
pub(crate) fn do_mac(mut mac: impl MAC, verify_val: &Option<String>, output_hex: bool) {
    stream_stdin(|chunk| mac.do_update(chunk));

    match verify_val {
        None => {
            let out = mac.do_final();
            write_bytes_or_hex(&out, output_hex);
            write_stdout(b"\n");
        }
        Some(verify_val) => {
            let expected = decode_hex_arg(verify_val, "verify");
            if mac.do_verify_final(&expected) {
                exit(0)
            }
            eprintln!("Error: MAC verification failed.");
            exit(-1)
        }
    }
}
