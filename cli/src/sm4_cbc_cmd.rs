//! SM4-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc`,
//! `aes*-cfb` and `aes*-ecb` commands. See that module for the command-line contract.
//!
//! `sm4-cbc` is the same command as `aes128-cbc` over the SM4 permutation (GB/T 32907-2016; 16-byte
//! key, 16-byte block), so every remark there applies unchanged. CBC (NIST SP 800-38A Sec 6.2)
//! provides confidentiality only: neither the ciphertext nor the IV is authenticated, and a flipped
//! ciphertext bit flips the same bit of the *next* block's plaintext (Appendix D). Do not decrypt data
//! you have not authenticated separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_key_object, start_encryptor,
};
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::sm4::{BLOCK_LEN, KEY_LEN, SM4Key};

/// Names the mode in error messages.
const MODE: &str = "CBC";

/// Dispatches to the shared streaming loops under the key's CBC mode. `NoPadding` keeps the
/// command's contract: whole blocks only, with the IV in band.
pub(crate) fn sm4_cbc_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<SM4Key<CBC<NoPadding>>, KEY_LEN>(key, key_file, "SM4");
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
