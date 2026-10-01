//! ARIA-CFB8 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
//! `aes*-cfb8` commands. See those modules for the command-line contract.
//!
//! `aria128-cfb8` / `aria192-cfb8` / `aria256-cfb8` are the same command as `aes*-cfb8`
//! over the ARIA permutation (RFC 5794; 16-, 24- or 32-byte key, 16-byte block), so every
//! remark there applies unchanged. The segment size is one byte (NIST SP 800-38A Sec 6.3 with
//! `s = 8`): a DIFFERENT, NON-INTEROPERABLE mode from the CFB128 of `aria*-cfb`, costing a full
//! ARIA call per byte, sixteen times the work. Prefer `aria*-cfb` unless a byte-granular
//! self-synchronising stream is required or the format demands CFB8.
//!
//! # Warning
//!
//! CFB8 provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Do not decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{BLOCK_LEN, CipherDirection, load_key};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::aria::hazmat::{ARIA_128, ARIA_192, ARIA_256};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::modes::{Cfb8, Decrypting, Encrypting};

pub(crate) fn aria128_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_128, 16>(action, &load_key::<16>(key, key_file, "ARIA-128"), output_hex);
}

pub(crate) fn aria192_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_192, 24>(action, &load_key::<24>(key, key_file, "ARIA-192"), output_hex);
}

pub(crate) fn aria256_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_256, 32>(action, &load_key::<32>(key, key_file, "ARIA-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cfb8` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    run_stream_mode::<
        Cfb8<P, Encrypting, KEY_LEN, BLOCK_LEN>,
        Cfb8<P, Decrypting, KEY_LEN, BLOCK_LEN>,
        KEY_LEN,
        BLOCK_LEN,
    >(action, key, output_hex)
}
