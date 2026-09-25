//! AES-GCM authenticated encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the nonce/tag framing, AAD loading and stdin streaming are in
//! [`crate::aead_mode_cmd`], shared across all three key lengths. See that module for the
//! command-line contract (`nonce || ciphertext || tag`, the AAD flags, and why a tag failure may be
//! reported after plaintext has already reached stdout).
//!
//! GCM (NIST SP 800-38D) is authenticated: unlike `aes*-cbc`, `aes*-cfb`, `aes*-cfb8` and
//! `aes*-ctr`, tampering with the ciphertext, the AAD or the nonce is detected rather than merely
//! producing wrong plaintext. The nonce is 12 bytes and the tag 16 (128-bit, the maximum SP
//! 800-38D Sec 5.2.1.2 allows); a fresh nonce is generated per `encrypt` and there is no `--iv`
//! flag, for the same reason as the other modes -- and doubly so here, since a repeated GCM nonce
//! also lets an attacker recover the hash subkey (SP 800-38D Appendix A).

use crate::aead_mode_cmd::{decrypt_gcm, encrypt_gcm, load_aad};
use crate::block_mode_cmd::{BlockModeAction, load_key};
use bouncycastle::aes::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;

pub(crate) fn aes128_gcm_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES128Internal, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

pub(crate) fn aes192_gcm_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES192Internal, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

pub(crate) fn aes256_gcm_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES256Internal, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

/// Dispatches to the shared AEAD streaming loops with `Gcm`'s 128-bit tag.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    aad: &[u8],
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    match action {
        BlockModeAction::Encrypt => encrypt_gcm::<P, KEY_LEN, 16>(key, aad, output_hex),
        BlockModeAction::Decrypt => decrypt_gcm::<P, KEY_LEN, 16>(key, aad, output_hex),
    }
}
