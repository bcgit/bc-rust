//! BLAKE2b-512 and BLAKE2s-256 (RFC 7693): the unkeyed hashes and their built-in keyed (MAC) mode.

use bouncycastle::blake2::{BLAKE2b_512, BLAKE2b_512_MACKey, BLAKE2s_256, BLAKE2s_256_MACKey};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};

use crate::helpers::{load_blake_mac_key, stream_hash};
use crate::mac_cmd::do_mac;

#[allow(non_camel_case_types)]
pub(crate) enum BLAKE2Variant {
    BLAKE2b_512,
    BLAKE2s_256,
}

/// BLAKE2b-512 / BLAKE2s-256 of stdin, streamed in 1 KiB pieces.
pub(crate) fn blake2_cmd(variant: BLAKE2Variant, output_hex: bool) {
    match variant {
        BLAKE2Variant::BLAKE2b_512 => stream_hash(BLAKE2b_512::new(), output_hex),
        BLAKE2Variant::BLAKE2s_256 => stream_hash(BLAKE2s_256::new(), output_hex),
    }
}

/// Keyed BLAKE2b-512 / BLAKE2s-256 (RFC 7693 s. 3.3) of stdin: compute a tag, or with `--verify`
/// check one and report the result in the exit status.
pub(crate) fn blake2_mac_cmd(
    variant: BLAKE2Variant,
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_hex: bool,
) {
    // RFC 7693 s. 2.1 table, "Key bytes": "0 <= kk <= 64" (BLAKE2b) / "0 <= kk <= 32" (BLAKE2s).
    // kk = 0 is the unkeyed hash, which is the other command, so a MAC key is at least 1 byte.
    //
    // The allow-weak form, as the HMAC and KMAC commands use: a CLI is used for test vectors and
    // scripting, where a short or all-zero key is a legitimate thing to want.
    match variant {
        BLAKE2Variant::BLAKE2b_512 => {
            let key = load_blake_mac_key(key, key_file, "BLAKE2b-512-MAC", 1, 64);
            // infallible: a 1..=64-byte MACKey (or Zeroized) key is exactly what the key object
            // accepts once the strength check is skipped.
            let mac_key = BLAKE2b_512_MACKey::from_key_material_allow_weak(&key).unwrap();
            do_mac(mac_key.create_generator(), verify_val, output_hex);
        }
        BLAKE2Variant::BLAKE2s_256 => {
            let key = load_blake_mac_key(key, key_file, "BLAKE2s-256-MAC", 1, 32);
            // infallible: as above, with the 1..=32-byte range of BLAKE2s.
            let mac_key = BLAKE2s_256_MACKey::from_key_material_allow_weak(&key).unwrap();
            do_mac(mac_key.create_generator(), verify_val, output_hex);
        }
    }
}
