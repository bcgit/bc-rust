//! AES-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cfb` and
//! `aes*-ecb` commands. See that module for the command-line contract.
//!
//! CBC (NIST SP 800-38A Sec 6.2) provides confidentiality only. It does not detect tampering, and
//! neither the ciphertext nor the IV is authenticated -- a flipped ciphertext bit flips the same bit
//! of the *next* block's plaintext (Appendix D). Do not decrypt data you have not authenticated
//! separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_key,
};
use bouncycastle::aes::AES_BLOCK_LEN;
use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::cipher::modes::Cbc;
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::key_material::KeyMaterial;

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn aes128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES128Internal, 16>(action, &load_key::<16>(key, key_file, "AES-128"), output_hex);
}

pub(crate) fn aes192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES192Internal, 24>(action, &load_key::<24>(key, key_file, "AES-192"), output_hex);
}

pub(crate) fn aes256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES256Internal, 32>(action, &load_key::<32>(key, key_file, "AES-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cbc` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, AES_BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => encrypt_stream::<
            Cbc<P, Encrypting, KEY_LEN, AES_BLOCK_LEN>,
            KEY_LEN,
            AES_BLOCK_LEN,
            AES_BLOCK_LEN,
        >(key, output_hex, MODE),
        CipherDirection::Decrypt => decrypt_stream::<
            Cbc<P, Decrypting, KEY_LEN, AES_BLOCK_LEN>,
            KEY_LEN,
            AES_BLOCK_LEN,
            AES_BLOCK_LEN,
        >(key, output_hex, MODE),
    }
}
