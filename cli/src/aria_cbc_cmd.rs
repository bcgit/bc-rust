//! ARIA-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc`,
//! `aes*-cfb` and `aes*-ecb` commands. See that module for the
//! command-line contract.
//!
//! `aria128-cbc` / `aria192-cbc` / `aria256-cbc` are the same command as `aes*-cbc` over the ARIA
//! permutation (RFC 5794; 16-, 24- or 32-byte key, 16-byte block -- the `id-aria*-cbc` algorithms of
//! RFC 5794 Appendix B), so every remark there applies unchanged. CBC (NIST SP 800-38A Sec 6.2)
//! provides confidentiality only: neither the ciphertext nor the IV is authenticated. Do not decrypt
//! data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_key_object, start_encryptor,
};
use bouncycastle::aria::{ARIA128Key, ARIA192Key, ARIA256Key, BLOCK_LEN};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn aria128_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<ARIA128Key<CBC<NoPadding>>, 16>(key, key_file, "ARIA-128"),
        output_hex,
    );
}

pub(crate) fn aria192_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<ARIA192Key<CBC<NoPadding>>, 24>(key, key_file, "ARIA-192"),
        output_hex,
    );
}

pub(crate) fn aria256_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<ARIA256Key<CBC<NoPadding>>, 32>(key, key_file, "ARIA-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops under the key's CBC mode. `NoPadding` keeps the
/// command's contract: whole blocks only, with the IV in band.
fn run<K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            let (enc, generated_iv) = start_encryptor(None, |rng| key.create_encryptor(rng));
            encrypt_stream::<_, BLOCK_LEN>(enc, generated_iv.as_ref(), output_hex, Some(MODE))
        }
        CipherDirection::Decrypt => decrypt_stream::<_, BLOCK_LEN>(
            None,
            |iv| key.create_decryptor(iv),
            output_hex,
            Some(MODE),
        ),
    }
}
