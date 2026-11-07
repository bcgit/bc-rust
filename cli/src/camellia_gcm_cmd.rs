//! Camellia-GCM authenticated encryption and decryption, streaming stdin to stdout: the `aes*-gcm`
//! commands over the Camellia permutation (RFC 3713; the Camellia-GCM of RFC 6367), with the same
//! `IV || ciphertext || tag` contract, AAD flags and warnings. See `aes_gcm_cmd` and
//! [`crate::helpers::aead_cipher_helpers`] for the command-line contract.

use crate::helpers::aead_cipher_helpers::{decrypt_aead, encrypt_aead, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use bouncycastle::camellia::{Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::GCM;
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};

#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn camellia128_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia128Key<GCM>, 16>(
        action,
        &load_key_object::<_, 16>(key, key_file, "Camellia-128"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn camellia192_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia192Key<GCM>, 24>(
        action,
        &load_key_object::<_, 24>(key, key_file, "Camellia-192"),
        load_iv::<12>(iv, iv_file),
        &load_aad(aad, aad_file),
        output_hex,
    );
}

#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn camellia256_gcm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia256Key<GCM>, 32>(
        action,
        &load_key_object::<_, 32>(key, key_file, "Camellia-256"),
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
