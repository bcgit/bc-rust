//! BLAKE3 (BLAKE3 specification, version 20211102173700): the `hash`, `keyed_hash` and
//! `derive_key` modes, each with output of any length.

use std::io::{self, Read};
use std::process::exit;

use bouncycastle::blake3::{BLAKE3, BLAKE3KeyedHashKey};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::{MAC, XOFSqueezer};

use crate::helpers::{load_blake_mac_key, stream_xof, write_bytes_or_hex, write_stdout};
use crate::mac_cmd::do_mac;

/// BLAKE3 spec s. 2.3: `keyed_hash` "takes an input of any length together with a 256-bit key".
/// The crate has no public constant for it.
const BLAKE3_KEY_LEN: usize = 32;

/// The default-length BLAKE3 output: BLAKE3 spec s. 2.1, "The chaining value of the root node,
/// encoded as 32 bytes in little-endian order, is the default-length BLAKE3 hash of the input."
pub(crate) const BLAKE3_DEFAULT_OUT_LEN: usize = 32;

/// BLAKE3 `hash` mode of stdin, streamed in 1 KiB pieces, squeezing `output_len` bytes.
pub(crate) fn blake3_cmd(output_len: usize, output_hex: bool) {
    stream_xof(BLAKE3::new(), output_len, output_hex);
}

/// BLAKE3 `derive_key` mode: the key material is streamed from stdin, the context string is the
/// argument, and `output_len` bytes of derived key are written out.
///
/// BLAKE3 spec s. 6.2: the context string "should be hardcoded, globally unique, and
/// application-specific"; this command takes it as an argument only so that scripts can name the
/// application's fixed string.
pub(crate) fn blake3_derive_key_cmd(context: &str, output_len: usize, output_hex: bool) {
    stream_xof(BLAKE3::new_derive_key(context.as_bytes()), output_len, output_hex);
}

/// BLAKE3 `keyed_hash` mode of stdin: write `output_len` bytes of keyed output, or with `--verify`
/// check a 32-byte tag and report the result in the exit status.
pub(crate) fn blake3_keyed_hash_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    verify_val: &Option<String>,
    output_len: usize,
    output_hex: bool,
) {
    // Verification goes through MAC::do_verify_final, which compares the default 32-byte tag in
    // constant time and requires an exact length match; an extended output length has no
    // meaning there, so refuse the combination rather than silently ignore --length.
    if verify_val.is_some() && output_len != BLAKE3_DEFAULT_OUT_LEN {
        eprintln!(
            "Error: --verify checks the {BLAKE3_DEFAULT_OUT_LEN}-byte tag and cannot be combined \
             with --length."
        );
        exit(-1);
    }

    let key = load_blake_mac_key(key, key_file, "BLAKE3-KeyedHash", BLAKE3_KEY_LEN, BLAKE3_KEY_LEN);
    // The allow-weak form, as the HMAC and KMAC commands use: a CLI is used for test vectors and
    // scripting, where a low-entropy or all-zero key is a legitimate thing to want.
    // infallible: a 32-byte MACKey (or Zeroized) key is exactly what the key object accepts once
    // the strength check is skipped.
    let mac_key = BLAKE3KeyedHashKey::from_key_material_allow_weak(&key).unwrap();
    let mut mac = mac_key.create_generator();

    if verify_val.is_some() {
        // do_mac streams stdin and, given a value to verify, exits with the result.
        do_mac(mac, verify_val, output_hex);
        return;
    }

    // Hand-rolled rather than a helper: stream_xof needs an XOF and do_mac finishes with
    // MAC::do_final, but extended keyed output needs the inherent into_squeezer afterwards.
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        mac.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    // BLAKE3 spec s. 2.6: the keyed output stream, of which the MAC tag is the first 32 bytes.
    let out = mac.into_squeezer().do_output_final(output_len);
    write_bytes_or_hex(&out, output_hex);
    write_stdout(b"\n");
}
