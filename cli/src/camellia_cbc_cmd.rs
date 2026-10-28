//! Camellia-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are all
//! in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc` and `aes*-ecb`
//! commands. See that module for the command-line contract. Input is padded with PKCS7, so it
//! may be any length.
//!
//! `camellia128-cbc` / `camellia192-cbc` / `camellia256-cbc` are the same command as `aes*-cbc`
//! over the Camellia permutation (RFC 3713; 16-, 24- or 32-byte key, 16-byte block -- the
//! `id-camellia*-cbc` algorithms of RFC 3713 Sec 3), so every remark there applies unchanged. CBC
//! (NIST SP 800-38A Sec 6.2) provides confidentiality only: neither the ciphertext nor the IV is
//! authenticated. Do not decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key_object, start_encryptor,
};
use bouncycastle::camellia::{BLOCK_LEN, Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::PKCS7;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

pub(crate) fn camellia128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<Camellia128Key<CBC<PKCS7>>, 16>(key, key_file, "Camellia-128"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn camellia192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<Camellia192Key<CBC<PKCS7>>, 24>(key, key_file, "Camellia-192"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn camellia256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<Camellia256Key<CBC<PKCS7>>, 32>(key, key_file, "Camellia-256"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops under the key's padded CBC mode.
fn run<K, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &K,
    iv: Option<[u8; BLOCK_LEN]>,
    output_hex: bool,
) where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            let (enc, generated_iv) = start_encryptor(iv, |rng| key.create_encryptor(rng));
            encrypt_stream::<_, BLOCK_LEN>(enc, generated_iv.as_ref(), output_hex, None)
        }
        CipherDirection::Decrypt => {
            decrypt_stream::<_, BLOCK_LEN>(iv, |iv| key.create_decryptor(iv), output_hex, None)
        }
    }
}
