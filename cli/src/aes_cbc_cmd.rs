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
    BLOCK_LEN, CipherDirection, decrypt_stream, encrypt_stream, load_key,
};
use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::aes::{AES_CBC_128_Key, AES_CBC_192_Key, AES_CBC_256_Key};
use bouncycastle::cipher::modes::Cbc;
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::traits::SymmetricCipherKey;

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn aes128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES128Internal, AES_CBC_128_Key, 16>(
        action,
        &load_key::<AES_CBC_128_Key, 16>(key, key_file, "AES-128"),
        output_hex,
    );
}

pub(crate) fn aes192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES192Internal, AES_CBC_192_Key, 24>(
        action,
        &load_key::<AES_CBC_192_Key, 24>(key, key_file, "AES-192"),
        output_hex,
    );
}

pub(crate) fn aes256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES256Internal, AES_CBC_256_Key, 32>(
        action,
        &load_key::<AES_CBC_256_Key, 32>(key, key_file, "AES-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Cbc` filled in as the mode.
fn run<P, K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: SymmetricCipherKey<KEY_LEN>,
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            encrypt_stream::<Cbc<P, Encrypting, K, KEY_LEN, BLOCK_LEN>, K, KEY_LEN, BLOCK_LEN>(
                key, output_hex, MODE,
            )
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<Cbc<P, Decrypting, K, KEY_LEN, BLOCK_LEN>, K, KEY_LEN, BLOCK_LEN>(
                key, output_hex, MODE,
            )
        }
    }
}
