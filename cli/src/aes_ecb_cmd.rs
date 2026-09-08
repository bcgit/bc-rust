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
    CipherDirection, decrypt_stream, encrypt_stream, load_key_object, start_encryptor,
};
use bouncycastle::aes::{AES_BLOCK_LEN, AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::hazmat::ecb::ECB;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

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
        &load_key_object::<AES128Key<ECB<NoPadding>>, 16>(key, key_file, "AES-128"),
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
        &load_key_object::<AES192Key<ECB<NoPadding>>, 24>(key, key_file, "AES-192"),
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
        &load_key_object::<AES256Key<ECB<NoPadding>>, 32>(key, key_file, "AES-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops under the key's ECB mode. `INIT_DATA_LEN` is 0, so
/// the loops write and read no IV, and `NoPadding` makes them refuse a partial final block.
fn run<K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: SymmetricEncryptionKey<KEY_LEN, 0, AES_BLOCK_LEN>
        + SymmetricDecryptionKey<KEY_LEN, 0, AES_BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            // ECB has no IV: the constructor's RNG draws nothing, and nothing is written.
            let (enc, _) = start_encryptor(None, |rng| key.create_encryptor(rng));
            encrypt_stream::<_, 0, AES_BLOCK_LEN>(enc, None, output_hex, Some(MODE))
        }
        CipherDirection::Decrypt => decrypt_stream::<_, 0, AES_BLOCK_LEN>(
            None,
            |no_iv| key.create_decryptor(no_iv),
            output_hex,
            Some(MODE),
        ),
    }
}
