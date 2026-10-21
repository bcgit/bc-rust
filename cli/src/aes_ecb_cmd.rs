//! AES-ECB encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: key loading, stdin framing and block-alignment enforcement are
//! all in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc` and `aes*-cfb` commands. See that
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

use crate::helpers::block_mode_helpers::{
    BLOCK_LEN, CipherDirection, decrypt_stream, encrypt_stream, load_key,
};
use bouncycastle::aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};

/// Names the mode in error messages.
const MODE: &str = "ECB";

pub(crate) fn aes128_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_ECB_128<Encrypting, NoPadding>, AES_ECB_128<Decrypting, NoPadding>, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        output_hex,
    );
}

pub(crate) fn aes192_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_ECB_192<Encrypting, NoPadding>, AES_ECB_192<Decrypting, NoPadding>, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        output_hex,
    );
}

pub(crate) fn aes256_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_ECB_256<Encrypting, NoPadding>, AES_ECB_256<Decrypting, NoPadding>, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops. `INIT_DATA_LEN` is 0, so the loops write and read no
/// IV.
fn run<E, D, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    E: SymmetricCipherEncryptor<KEY_LEN, 0, BLOCK_LEN>,
    D: SymmetricCipherDecryptor<KEY_LEN, 0, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => encrypt_stream::<E, KEY_LEN, 0>(key, output_hex, Some(MODE)),
        CipherDirection::Decrypt => decrypt_stream::<D, KEY_LEN, 0>(key, output_hex, Some(MODE)),
    }
}
