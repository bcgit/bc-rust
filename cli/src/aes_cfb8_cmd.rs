//! AES-CFB8 encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-cfb` commands. See those modules for the command-line contract.
//!
//! # Which CFB
//!
//! These commands are **CFB8**: the segment size is one byte (`s = 8` in NIST SP 800-38A Sec 6.3).
//! That is a different, non-interoperable mode from the CFB128 of `aes*-cfb`, not a variant of it:
//! the two ciphertexts agree on their first byte and differ everywhere after it. It also costs a
//! full AES call per byte of data, sixteen times the work of `aes*-cfb`, so prefer `aes*-cfb`
//! unless a byte-granular self-synchronising stream is required or the format demands CFB8.
//!
//! # Any length
//!
//! CFB8's segment is a single byte, so these commands accept input of any length, pad nothing, and
//! emit a ciphertext exactly as long as the plaintext.
//!
//! # Warning
//!
//! CFB8 provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Appendix D, Table D.2 gives "SBE in the decryption of Cj" plus random
//! errors in the next `b/s` segments: flipping a ciphertext bit flips the *same* bit of the *same*
//! plaintext byte, corrupts the following 16 bytes, and then decryption resynchronises. Do not
//! decrypt data you have not authenticated separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Cfb8, Decrypting, Encrypting};

pub(crate) fn aes128_cfb8_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes128, 16>(action, &load_key::<16>(key, key_file, "AES-128"), output_hex);
}

pub(crate) fn aes192_cfb8_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes192, 24>(action, &load_key::<24>(key, key_file, "AES-192"), output_hex);
}

pub(crate) fn aes256_cfb8_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes256, 32>(action, &load_key::<32>(key, key_file, "AES-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cfb8` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    run_stream_mode::<
        Cfb8<P, Encrypting, KEY_LEN, BLOCK_LEN>,
        Cfb8<P, Decrypting, KEY_LEN, BLOCK_LEN>,
        KEY_LEN,
    >(action, key, output_hex)
}
