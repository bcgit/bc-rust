//! Camellia-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::block_mode_cmd`], shared with the `aes*-cbc`,
//! `aes*-cfb` and `aes*-ecb` commands. See that module for the command-line contract.
//!
//! `camellia128-cbc` / `camellia192-cbc` / `camellia256-cbc` are the same command as `aes*-cbc` over
//! the Camellia permutation (RFC 3713; 16-, 24- or 32-byte key, 16-byte block -- the
//! `id-camellia*-cbc` algorithms of RFC 3713 Sec 3), so every remark there applies unchanged. CBC
//! (NIST SP 800-38A Sec 6.2) provides confidentiality only: neither the ciphertext nor the IV is
//! authenticated. Do not decrypt data you have not authenticated separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::camellia::{Camellia_128, Camellia_192, Camellia_256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Cbc, Decrypting, Encrypting};

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn camellia128_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia_128, 16>(action, &load_key::<16>(key, key_file, "Camellia-128"), output_hex);
}

pub(crate) fn camellia192_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia_192, 24>(action, &load_key::<24>(key, key_file, "Camellia-192"), output_hex);
}

pub(crate) fn camellia256_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia_256, 32>(action, &load_key::<32>(key, key_file, "Camellia-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cbc` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Cbc<P, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, BLOCK_LEN>(
                key, output_hex, MODE,
            )
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Cbc<P, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, BLOCK_LEN>(
                key, output_hex, MODE,
            )
        }
    }
}
