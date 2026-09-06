//! AES-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::block_mode_cmd`], shared with the `aes*-cfb`
//! commands. See that module for the command-line contract.
//!
//! CBC (NIST SP 800-38A Sec 6.2) provides confidentiality only. It does not detect tampering, and
//! neither the ciphertext nor the IV is authenticated -- a flipped ciphertext bit flips the same bit
//! of the *next* block's plaintext (Appendix D). Do not decrypt data you have not authenticated
//! separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::BlockPermutation;
use bouncycastle::modes::{Cbc, Decrypting, Encrypting};

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn aes128_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes128, 16>(action, &load_key::<16>(key, key_file, "AES-128"), output_hex);
}

pub(crate) fn aes192_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes192, 24>(action, &load_key::<24>(key, key_file, "AES-192"), output_hex);
}

pub(crate) fn aes256_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes256, 32>(action, &load_key::<32>(key, key_file, "AES-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cbc` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Cbc<P, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN>(key, output_hex, MODE)
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Cbc<P, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN>(key, output_hex, MODE)
        }
    }
}
