//! SM4-GCM authenticated encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV/tag framing, AAD loading and stdin streaming are in
//! [`crate::helpers::aead_cipher_helpers`], shared with the `aes*-gcm` commands. See that module
//! for the command-line contract (`IV || ciphertext || tag`, the AAD flags, and why a tag failure
//! may be reported after plaintext has already reached stdout).
//!
//! `sm4-gcm` is the same command as `aes128-gcm` over the SM4 permutation (GB/T 32907-2016;
//! 16-byte key, 16-byte block), which is RFC 8998 Sec 3.5.1's `AEAD_SM4_GCM`: a 12-byte nonce and
//! a 16-byte tag. Every remark there applies unchanged, above all that a repeated IV under one
//! key lets an attacker recover the hash subkey (SP 800-38D Appendix A).

use crate::helpers::aead_cipher_helpers::{decrypt_gcm, encrypt_gcm, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use bouncycastle::cipher::modes::{GCM, GCM_NONCE_LEN};
use bouncycastle::sm4::{KEY_LEN, SM4Key};

/// Dispatches to the shared AEAD streaming loops with `Gcm`'s 128-bit tag.
pub(crate) fn sm4_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<SM4Key<GCM>, KEY_LEN>(key, key_file, "SM4");
    let nonce = load_iv::<GCM_NONCE_LEN>(iv, iv_file);
    let aad = load_aad(aad, aad_file);
    match action {
        CipherDirection::Encrypt => encrypt_gcm::<_, KEY_LEN, 16>(&key, nonce, &aad, output_hex),
        CipherDirection::Decrypt => decrypt_gcm::<_, KEY_LEN, 16>(&key, nonce, &aad, output_hex),
    }
}
