//! CBC encryption and decryption over any 128-bit block permutation, streaming stdin to stdout:
//! the `aes*-cbc`, `aria*-cbc`, `camellia*-cbc` and `sm4-cbc` commands, one generic function
//! that `main` instantiates per cipher and key length.
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
    CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key_object, start_encryptor,
};
use bouncycastle::cipher::BlockCipherKey;
use bouncycastle::cipher::modes::CBC;
use bouncycastle::cipher::modes::ModeNames;
use bouncycastle::cipher::padding::PKCS7;
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

/// The 128-bit block of the ciphers these commands serve; TDES has its own commands.
const BLOCK_LEN: usize = 16;

/// CBC with PKCS7 padding under a `KEY_LEN`-byte key for the permutation `P`; `alg` names the
/// cipher and key length in messages, "AES-128" and the like.
pub(crate) fn cbc_cmd<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    run::<_, KEY_LEN>(
        action,
        &load_key_object::<BlockCipherKey<P, CBC<PKCS7>>, KEY_LEN>(key, key_file, alg),
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
