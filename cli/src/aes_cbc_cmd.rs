//! AES-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are all in
//! [`crate::helpers::block_mode_helpers`], shared with the `aes*-ecb` commands. See that module
//! for the command-line contract. Input is padded with PKCS7, so it may be any length.
//!
//! CBC (NIST SP 800-38A Sec 6.2) provides confidentiality only. It does not detect tampering, and
//! neither the ciphertext nor the IV is authenticated -- a flipped ciphertext bit flips the same bit
//! of the *next* block's plaintext (Appendix D). Do not decrypt data you have not authenticated
//! separately.

use crate::helpers::block_mode_helpers::{
    BLOCK_LEN, CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key,
};
use bouncycastle::aes::{AES_CBC_128, AES_CBC_192, AES_CBC_256};
use bouncycastle::cipher::padding::PKCS7;
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};

pub(crate) fn aes128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_CBC_128<Encrypting, PKCS7>, AES_CBC_128<Decrypting, PKCS7>, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_CBC_192<Encrypting, PKCS7>, AES_CBC_192<Decrypting, PKCS7>, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_CBC_256<Encrypting, PKCS7>, AES_CBC_256<Decrypting, PKCS7>, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops.
fn run<E, D, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    iv: Option<[u8; BLOCK_LEN]>,
    output_hex: bool,
) where
    E: SymmetricCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
    D: SymmetricCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            encrypt_stream::<E, KEY_LEN, BLOCK_LEN>(key, iv, output_hex, None)
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<D, KEY_LEN, BLOCK_LEN>(key, iv, output_hex, None)
        }
    }
}
