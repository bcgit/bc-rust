//! ARIA-GCM authenticated encryption and decryption, streaming stdin to stdout: the `aes*-gcm`
//! commands over the ARIA permutation (RFC 5794; Appendix B's `id-aria*-gcm`), with the same
//! `IV || ciphertext || tag` contract, AAD flags and warnings. See `aes_gcm_cmd` and
//! [`crate::helpers::aead_cipher_helpers`] for the command-line contract.

use crate::helpers::aead_cipher_helpers::{decrypt_gcm, encrypt_gcm, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use bouncycastle::aria::{ARIA128Key, ARIA192Key, ARIA256Key};
use bouncycastle::cipher::modes::GCM;
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};

#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn aria128_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA128Key<GCM>, 16>(
        action,
        &load_key_object::<_, 16>(key, key_file, "ARIA-128"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn aria192_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA192Key<GCM>, 24>(
        action,
        &load_key_object::<_, 24>(key, key_file, "ARIA-192"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn aria256_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA256Key<GCM>, 32>(
        action,
        &load_key_object::<_, 32>(key, key_file, "ARIA-256"),
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
        CipherDirection::Encrypt => encrypt_gcm::<K, KEY_LEN, 16>(key, nonce, aad, output_hex),
        CipherDirection::Decrypt => decrypt_gcm::<K, KEY_LEN, 16>(key, nonce, aad, output_hex),
    }
}
