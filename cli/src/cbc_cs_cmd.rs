//! CBC with ciphertext stealing over any 128-bit block permutation, streaming stdin to stdout: the
//! `aes*-cbc-cs1`, `aes*-cbc-cs2` and `aes*-cbc-cs3` commands (the last also `aes*-cts`), one
//! generic function that `main` instantiates per variant and key length.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are
//! [`crate::helpers::block_mode_helpers`]'s, as for the `aes*-cbc` commands. There is no padding,
//! so the ciphertext after the IV is exactly as long as the plaintext, and input shorter than one
//! block, 16 bytes, is refused at the end, in both directions (Addendum to NIST SP 800-38A Sec 1).
//! A worker holds back at most the last 32 bytes of the message, so one call releases at most the
//! 1 KiB the shared loops hand it, which is what their output buffer holds.
//!
//! CBC-CS provides confidentiality only, as CBC does: it does not detect tampering, and neither the
//! ciphertext nor the IV is authenticated. Do not decrypt data you have not authenticated
//! separately.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_iv, load_key_object, start_encryptor,
};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::symmetric::BlockCipherKey;
use bouncycastle::symmetric::modes::{CBC_CS, CBC_CS_FINAL_LEN, CsVariant, ModeNames};

/// The 128-bit block the variants are implemented over.
const BLOCK_LEN: usize = 16;

/// CBC under the ciphertext-stealing variant `V` with a `KEY_LEN`-byte key for the permutation
/// `P`; `alg` names the cipher and key length in messages, "AES-128" and the like.
pub(crate) fn cbc_cs_cmd<P, V, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    V: CsVariant<P>,
{
    run::<_, KEY_LEN>(
        action,
        &load_key_object::<BlockCipherKey<P, CBC_CS<V>>, KEY_LEN>(key, key_file, alg),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops, whose final buffer is the mode's two blocks.
fn run<K, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &K,
    iv: Option<[u8; BLOCK_LEN]>,
    output_hex: bool,
) where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, CBC_CS_FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, CBC_CS_FINAL_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            let (enc, generated_iv) = start_encryptor(
                iv,
                |rng| key.create_encryptor(rng),
                |iv| key.create_encryptor_nonce(iv),
            );
            encrypt_stream::<_, BLOCK_LEN, CBC_CS_FINAL_LEN>(
                enc,
                generated_iv.as_ref(),
                output_hex,
                None,
            )
        }
        CipherDirection::Decrypt => decrypt_stream::<_, BLOCK_LEN, CBC_CS_FINAL_LEN>(
            iv,
            |iv| key.create_decryptor(iv),
            output_hex,
            None,
        ),
    }
}
