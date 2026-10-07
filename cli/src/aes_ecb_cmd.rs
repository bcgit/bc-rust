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
use bouncycastle::aes::hazmat::{AES_ECB_128_Key, AES_ECB_192_Key, AES_ECB_256_Key};
use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::cipher::modes::hazmat::Ecb;
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::traits::SymmetricCipherKey;

/// Names the mode in error messages.
const MODE: &str = "ECB";

pub(crate) fn aes128_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES128Internal, AES_ECB_128_Key, 16>(
        action,
        &load_key::<AES_ECB_128_Key, 16>(key, key_file, "AES-128"),
        output_hex,
    );
}

pub(crate) fn aes192_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES192Internal, AES_ECB_192_Key, 24>(
        action,
        &load_key::<AES_ECB_192_Key, 24>(key, key_file, "AES-192"),
        output_hex,
    );
}

pub(crate) fn aes256_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES256Internal, AES_ECB_256_Key, 32>(
        action,
        &load_key::<AES_ECB_256_Key, 32>(key, key_file, "AES-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Ecb` filled in as the mode. `INIT_DATA_LEN` is 0,
/// so the loops write and read no IV.
fn run<P, K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: SymmetricCipherKey<KEY_LEN>,
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            encrypt_stream::<Ecb<P, Encrypting, K, KEY_LEN, BLOCK_LEN>, K, KEY_LEN, 0>(
                key, output_hex, MODE,
            )
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<Ecb<P, Decrypting, K, KEY_LEN, BLOCK_LEN>, K, KEY_LEN, 0>(
                key, output_hex, MODE,
            )
        }
    }
}
