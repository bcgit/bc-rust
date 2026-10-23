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

use crate::helpers::aead_cipher_helpers::{decrypt_gcm, encrypt_gcm, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key};
use bouncycastle::aes::{AES_GCM_128, AES_GCM_192, AES_GCM_256};
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};

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
    run::<AES_GCM_128<Encrypting>, AES_GCM_128<Decrypting>, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
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
    run::<AES_GCM_192<Encrypting>, AES_GCM_192<Decrypting>, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
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
    run::<AES_GCM_256<Encrypting>, AES_GCM_256<Decrypting>, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

/// Dispatches to the shared AEAD streaming loops with GCM's 128-bit tag.
fn run<E, D, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    nonce: Option<[u8; 12]>,
    aad: &[u8],
    output_hex: bool,
) where
    E: AEADCipherEncryptor<KEY_LEN, 12, 16, 16>,
    D: AEADCipherDecryptor<KEY_LEN, 12, 16, 16>,
{
    match action {
        CipherDirection::Encrypt => encrypt_gcm::<E, KEY_LEN, 16>(key, nonce, aad, output_hex),
        CipherDirection::Decrypt => decrypt_gcm::<D, KEY_LEN, 16>(key, nonce, aad, output_hex),
    }
}
