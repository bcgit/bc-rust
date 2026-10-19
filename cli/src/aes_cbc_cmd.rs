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
    BLOCK_LEN, CipherDirection, decrypt_stream, encrypt_stream, load_key_object,
};
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::{Blocks, CBC};
use bouncycastle::core::symmetric_key::{BlockDecryptionKey, BlockEncryptionKey};
use bouncycastle::rng::HashDRBG_SHA512;
use std::process::exit;

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn aes128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<AES128Key<CBC<Blocks>>, 16>(key, key_file, "AES-128"),
        output_hex,
    );
}

pub(crate) fn aes192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<AES192Key<CBC<Blocks>>, 24>(key, key_file, "AES-192"),
        output_hex,
    );
}

pub(crate) fn aes256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<AES256Key<CBC<Blocks>>, 32>(key, key_file, "AES-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Cbc` filled in as the mode.
fn run<K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: BlockEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>
        + BlockDecryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            // The IV is drawn from the OS-backed DRBG; there is no way to supply one.
            let (enc, iv) =
                key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap_or_else(|e| {
                    eprintln!("Error: couldn't start encryption: {e:?}");
                    exit(-1);
                });
            encrypt_stream::<_, BLOCK_LEN>(enc, &iv, output_hex, MODE)
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<_, BLOCK_LEN>(|iv| key.create_decryptor(iv), output_hex, MODE)
        }
    }
}
