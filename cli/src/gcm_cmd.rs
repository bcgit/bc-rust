//! GCM authenticated encryption and decryption over any 128-bit block permutation, streaming
//! stdin to stdout: the `aes*-gcm`, `aria*-gcm`, `camellia*-gcm` and `sm4-gcm` commands, one
//! generic function that `main` instantiates per cipher and key length.
//!
//! Only the mode wiring lives here: the IV/tag framing, AAD loading and stdin streaming are in
//! [`crate::helpers::aead_cipher_helpers`], shared across every cipher and key length. See that module for the
//! command-line contract (`IV || ciphertext || tag`, the AAD flags, and why a tag failure may be
//! reported after plaintext has already reached stdout).
//!
//! GCM (NIST SP 800-38D) is authenticated: unlike `aes*-cbc`, `aes*-cfb`, `aes*-cfb8` and
//! `aes*-ctr`, tampering with the ciphertext, the AAD or the IV is detected rather than merely
//! producing wrong plaintext. The IV (SP 800-38D's term; it defines it as a nonce) is 12 bytes and
//! the tag 16 (128-bit, the maximum Sec 5.2.1.2 allows); a fresh IV is generated per `encrypt`
//! unless `--iv` supplies one, in which case uniqueness is the caller's to guarantee -- and it
//! matters more here than in the other modes, since a repeated GCM IV also lets an attacker
//! recover the hash subkey (Appendix A).

use crate::helpers::aead_cipher_helpers::{decrypt_aead, encrypt_aead, load_aad};
use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use bouncycastle::cipher::BlockCipherKey;
use bouncycastle::cipher::modes::ModeNames;
use bouncycastle::cipher::modes::{GCM, GCM_NONCE_LEN};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};

/// GCM with a 128-bit tag under a `KEY_LEN`-byte key for the permutation `P`; `alg` names the
/// cipher and key length in messages.
#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn gcm_cmd<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
{
    run::<BlockCipherKey<P, GCM>, KEY_LEN>(
        action,
        &load_key_object::<_, KEY_LEN>(key, key_file, alg),
        load_iv::<GCM_NONCE_LEN>(iv, iv_file),
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
