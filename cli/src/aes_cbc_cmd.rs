//! AES-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are all in
//! [`crate::helpers::block_mode_helpers`], shared with the `aes*-ecb` commands. See that module
//! for the command-line contract. Input is padded with PKCS7, so it may be any length.
//!
//! CBC (NIST SP 800-38A Sec 6.2) provides confidentiality only. It does not detect tampering, and
//! neither the ciphertext nor the IV is authenticated -- a flipped ciphertext bit flips the same bit
//! of the *next* block's plaintext (Appendix D). Do not decrypt data you have not authenticated
//! separately.

use crate::helpers::block_mode_helpers::{
    BLOCK_LEN, CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key_object,
    start_encryptor,
};
use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::PKCS7;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

pub(crate) fn aes128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<AES128Key<CBC<PKCS7>>, 16>(key, key_file, "AES-128"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<AES192Key<CBC<PKCS7>>, 24>(key, key_file, "AES-192"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<AES256Key<CBC<PKCS7>>, 32>(key, key_file, "AES-256"),
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
