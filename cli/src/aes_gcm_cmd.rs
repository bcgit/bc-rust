//! AES-GCM authenticated encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the nonce/tag framing, AAD loading and stdin streaming are in
//! [`helpers::aead_cipher_helpers`], shared across all three key lengths. See that module for the
//! command-line contract (`nonce || ciphertext || tag`, the AAD flags, and why a tag failure may be
//! reported after plaintext has already reached stdout).
//!
//! GCM (NIST SP 800-38D) is authenticated: unlike `aes*-cbc`, `aes*-cfb`, `aes*-cfb8` and
//! `aes*-ctr`, tampering with the ciphertext, the AAD or the nonce is detected rather than merely
//! producing wrong plaintext. The nonce is 12 bytes and the tag 16 (128-bit, the maximum SP
//! 800-38D Sec 5.2.1.2 allows); a fresh nonce is generated per `encrypt` and there is no `--iv`
//! flag, for the same reason as the other modes -- and doubly so here, since a repeated GCM nonce
//! also lets an attacker recover the hash subkey (SP 800-38D Appendix A).

use crate::helpers::aead_cipher_helpers::{decrypt_gcm, encrypt_gcm, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::GCM;
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};

pub(crate) fn aes128_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES128Key<GCM>, 16>(
        action,
        &load_key_object::<_, 16>(key, key_file, "AES-128"),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

pub(crate) fn aes192_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES192Key<GCM>, 24>(
        action,
        &load_key_object::<_, 24>(key, key_file, "AES-192"),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

pub(crate) fn aes256_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES256Key<GCM>, 32>(
        action,
        &load_key_object::<_, 32>(key, key_file, "AES-256"),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

/// Dispatches to the shared AEAD streaming loops with `Gcm`'s 128-bit tag.
fn run<K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, aad: &[u8], output_hex: bool)
where
    K: AeadEncryptionKey<KEY_LEN, 12, 16, 16> + AeadDecryptionKey<KEY_LEN, 12, 16, 16>,
{
    match action {
        CipherDirection::Encrypt => encrypt_gcm::<K, KEY_LEN, 16>(key, aad, output_hex),
        CipherDirection::Decrypt => decrypt_gcm::<K, KEY_LEN, 16>(key, aad, output_hex),
    }
}
