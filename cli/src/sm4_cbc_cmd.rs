//! SM4-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are all
//! in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc` and `aes*-ecb`
//! commands. See that module for the command-line contract. Input is padded with PKCS7, so it
//! may be any length.
//!
//! `sm4-cbc` is the same command as `aes128-cbc` over the SM4 permutation (GB/T 32907-2016;
//! 16-byte key, 16-byte block), so every remark there applies unchanged. CBC (NIST SP 800-38A
//! Sec 6.2) provides confidentiality only: neither the ciphertext nor the IV is authenticated,
//! and a flipped ciphertext bit flips the same bit of the *next* block's plaintext (Appendix D).
//! Do not decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key_object, start_encryptor,
};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::PKCS7;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::sm4::{BLOCK_LEN, KEY_LEN, SM4Key};

/// Dispatches to the shared streaming loops under the key's padded CBC mode.
pub(crate) fn sm4_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<SM4Key<CBC<PKCS7>>, KEY_LEN>(key, key_file, "SM4");
    let iv = load_iv::<BLOCK_LEN>(iv, iv_file);
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
