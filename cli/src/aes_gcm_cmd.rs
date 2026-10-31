//! AES-GCM authenticated encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV/tag framing, AAD loading and stdin streaming are in
//! [`crate::helpers::aead_cipher_helpers`], shared across all three key lengths. See that module for the
//! command-line contract (`IV || ciphertext || tag`, the AAD flags, and why a tag failure may be
//! reported after plaintext has already reached stdout).
//!
//! GCM (NIST SP 800-38D) is authenticated: unlike `aes*-cbc`, `aes*-cfb`, `aes*-cfb8` and
//! `aes*-ctr`, tampering with the ciphertext, the AAD or the IV is detected rather than merely
//! producing wrong plaintext. The IV (SP 800-38D's term; it defines it as a nonce) is 12 bytes and
//! the tag 16 (128-bit, the maximum Sec 5.2.1.2 allows); a fresh IV is generated per `encrypt`
//! unless `--iv` supplies one, in which case uniqueness is the caller's to guarantee -- and it
//! matters more here than in the other modes, since a repeated GCM IV also lets an attacker
//! recover the hash subkey (Appendix A).

use crate::helpers::aead_cipher_helpers::{decrypt_aead, encrypt_aead, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::GCM;
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};

pub(crate) fn aes128_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES128Key<GCM>, 16>(
        action,
        &load_key_object::<_, 16>(key, key_file, "AES-128"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

pub(crate) fn aes192_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES192Key<GCM>, 24>(
        action,
        &load_key_object::<_, 24>(key, key_file, "AES-192"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

pub(crate) fn aes256_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES256Key<GCM>, 32>(
        action,
        &load_key_object::<_, 32>(key, key_file, "AES-256"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

/// Dispatches to the shared AEAD streaming loops with `Gcm`'s 128-bit tag.
fn run<K, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &K,
    nonce: Option<[u8; 12]>,
    aad: &[u8],
    output_hex: bool,
) where
    K: AeadEncryptionKey<KEY_LEN, 12, 16, 16> + AeadDecryptionKey<KEY_LEN, 12, 16, 16>,
{
    match action {
        CipherDirection::Encrypt => {
            encrypt_aead::<K, KEY_LEN, 12, 16, 16>(key, nonce, aad, output_hex)
        }
        CipherDirection::Decrypt => {
            decrypt_aead::<K, KEY_LEN, 12, 16, 16>(key, nonce, aad, output_hex)
        }
    }
}
