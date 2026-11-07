//! ARIA-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are all
//! in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc` and `aes*-ecb`
//! commands. See that module for the command-line contract. Input is padded with PKCS7, so it
//! may be any length.
//!
//! `aria128-cbc` / `aria192-cbc` / `aria256-cbc` are the same command as `aes*-cbc` over the ARIA
//! permutation (RFC 5794; 16-, 24- or 32-byte key, 16-byte block), so every remark there applies
//! unchanged. They are not the `id-aria*-cbc` objects of RFC 5794 Appendix B: those default to
//! padding method 2 of ISO/IEC 9797-1 (`AriaCbcParameters`' `padAlgo DEFAULT id-pad-1`), and
//! PKCS#7 is not among the padding algorithms the RFC specifies. CBC (NIST SP 800-38A Sec 6.2)
//! provides confidentiality only: neither the ciphertext nor the IV is authenticated. Do not
//! decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key_object, start_encryptor,
};
use bouncycastle::aria::{ARIA128Key, ARIA192Key, ARIA256Key, BLOCK_LEN};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::PKCS7;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

pub(crate) fn aria128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<ARIA128Key<CBC<PKCS7>>, 16>(key, key_file, "ARIA-128"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aria192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<ARIA192Key<CBC<PKCS7>>, 24>(key, key_file, "ARIA-192"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aria256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<ARIA256Key<CBC<PKCS7>>, 32>(key, key_file, "ARIA-256"),
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
            encrypt_stream::<_, BLOCK_LEN, BLOCK_LEN>(enc, generated_iv.as_ref(), output_hex, None)
        }
        CipherDirection::Decrypt => decrypt_stream::<_, BLOCK_LEN, BLOCK_LEN>(
            iv,
            |iv| key.create_decryptor(iv),
            output_hex,
            None,
        ),
    }
}
