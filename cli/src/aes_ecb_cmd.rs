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
    BLOCK_LEN, CipherDirection, decrypt_stream, encrypt_stream, load_key_object,
};
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::Blocks;
use bouncycastle::cipher::modes::hazmat::ECB;
use bouncycastle::core::hazmat::{EcbDecryptionKey, EcbEncryptionKey};

/// Names the mode in error messages.
const MODE: &str = "ECB";

pub(crate) fn aes128_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<AES128Key<ECB<Blocks>>, 16>(key, key_file, "AES-128"),
        output_hex,
    );
}

pub(crate) fn aes192_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<AES192Key<ECB<Blocks>>, 24>(key, key_file, "AES-192"),
        output_hex,
    );
}

pub(crate) fn aes256_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<AES256Key<ECB<Blocks>>, 32>(key, key_file, "AES-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Ecb` filled in as the mode. `INIT_DATA_LEN` is 0,
/// so the loops write and read no IV.
fn run<K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: EcbEncryptionKey<KEY_LEN, BLOCK_LEN> + EcbDecryptionKey<KEY_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            encrypt_stream::<_, KEY_LEN, 0>(key.create_encryptor(), &[], output_hex, MODE)
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<_, KEY_LEN, 0>(|_| key.create_decryptor(), output_hex, MODE)
        }
    }
}
