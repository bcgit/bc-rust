//! ChaCha20-Poly1305 (RFC 8439 Sec 2.8) authenticated encryption and decryption, streaming stdin
//! to stdout.
//!
//! The framing, AAD flags and exit-code contract are those of [`crate::helpers::aead_cipher_helpers`],
//! shared with the `aes*-gcm` commands: `nonce || ciphertext || tag`, with a 12-byte generated
//! nonce and a 16-byte tag. As there, a tag failure on `decrypt` is reported after the plaintext
//! has already reached stdout; check the exit code before using it.

use crate::helpers::aead_cipher_helpers::{decrypt_aead, encrypt_aead, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use bouncycastle::chacha20_poly1305_aead::{ChaCha20Poly1305Key, KEY_LEN, NONCE_LEN, TAG_LEN};

pub(crate) fn chacha20_poly1305_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<ChaCha20Poly1305Key, KEY_LEN>(key, key_file, "ChaCha20-Poly1305");
    let aad = load_aad(aad, aad_file);
    match action {
        CipherDirection::Encrypt => {
            encrypt_aead::<_, KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>(&key, &aad, output_hex)
        }
        CipherDirection::Decrypt => {
            decrypt_aead::<_, KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>(&key, &aad, output_hex)
        }
    }
}
