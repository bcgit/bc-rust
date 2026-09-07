//! AES-ECB encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: key loading, stdin framing and block-alignment enforcement are
//! all in [`crate::block_mode_cmd`], shared with the `aes*-cbc` and `aes*-cfb` commands. See that
//! module for the command-line contract. ECB has no IV (`INIT_DATA_LEN = 0`), so unlike those
//! commands nothing is prepended to the output or consumed from the input: the ciphertext is exactly
//! as long as the plaintext.
//!
//! # Warning
//!
//! ECB (NIST SP 800-38A Sec 6.1) is **not a confidentiality mode for data**. Under a given key every
//! plaintext block maps to the same ciphertext block, so equal blocks stay visibly equal, the
//! structure of the plaintext shows through, and blocks can be reordered, repeated or removed with
//! nothing to detect it. The same plaintext encrypts to the same ciphertext every time. These commands
//! exist for interoperability with systems that use ECB and for driving test vectors; for data, use
//! `aes*-cbc` or `aes*-cfb` under separate authentication, or better an AEAD.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::aes::{Aes128, Aes192, Aes256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Decrypting, Ecb, Encrypting};

/// Names the mode in error messages.
const MODE: &str = "ECB";

pub(crate) fn aes128_ecb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes128, 16>(action, &load_key::<16>(key, key_file, "AES-128"), output_hex);
}

pub(crate) fn aes192_ecb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes192, 24>(action, &load_key::<24>(key, key_file, "AES-192"), output_hex);
}

pub(crate) fn aes256_ecb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes256, 32>(action, &load_key::<32>(key, key_file, "AES-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Ecb` filled in as the mode. `INIT_DATA_LEN` is 0,
/// so the loops write and read no IV.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Ecb<P, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, 0>(
                key, output_hex, MODE,
            )
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Ecb<P, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, 0>(
                key, output_hex, MODE,
            )
        }
    }
}
