//! ECB encryption and decryption over any 128-bit block permutation, streaming stdin to stdout:
//! the `aes*-ecb` commands, one generic function that `main` instantiates per key length.
//!
//! Only the mode wiring lives here: key loading, stdin framing and block-alignment enforcement are
//! all in [`crate::helpers::block_mode_helpers`], shared with the `aes*-cbc` and `aes*-cfb` commands. See that
//! module for the command-line contract. ECB has no IV (`INIT_DATA_LEN = 0`), so unlike those
//! commands nothing is prepended to the output or consumed from the input: the ciphertext is exactly
//! as long as the plaintext.
//!
//! # Warning
//!
//! ECB (NIST SP 800-38A Sec 6.1) is **not a confidentiality mode for data**. Under a given key every
//! plaintext block maps to the same ciphertext block, so equal blocks stay visibly equal, the
//! structure of the plaintext shows through, and blocks can be reordered, repeated or removed with
//! nothing to detect it. The same plaintext encrypts to the same ciphertext every time. These commands
//! exist for interoperability with systems that use ECB and for driving test vectors; for data, use
//! `aes*-cbc` or `aes*-cfb` under separate authentication, or better an AEAD.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_key_object, start_encryptor,
};
use bouncycastle::cipher::BlockCipherKey;
use bouncycastle::cipher::modes::ModeNames;
use bouncycastle::cipher::modes::hazmat::ecb::ECB;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};

/// The 128-bit block of the ciphers these commands serve; TDES has its own commands.
const BLOCK_LEN: usize = 16;

const MODE: &str = "ECB";

/// ECB without padding under a `KEY_LEN`-byte key for the permutation `P`; `alg` names the
/// cipher and key length in messages.
pub(crate) fn ecb_cmd<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    run::<_, KEY_LEN>(
        action,
        &load_key_object::<BlockCipherKey<P, ECB<NoPadding>>, KEY_LEN>(key, key_file, alg),
        output_hex,
    );
}

fn run<K, const KEY_LEN: usize>(action: &CipherDirection, key: &K, output_hex: bool)
where
    K: SymmetricEncryptionKey<KEY_LEN, 0, BLOCK_LEN>
        + SymmetricDecryptionKey<KEY_LEN, 0, BLOCK_LEN>,
{
    match action {
        CipherDirection::Encrypt => {
            // ECB has no IV: the constructor's RNG draws nothing, and nothing is written.
            let (enc, _) = start_encryptor(
                None,
                |rng| key.create_encryptor(rng),
                |no_iv| key.create_encryptor_nonce(no_iv),
            );
            encrypt_stream::<_, 0, BLOCK_LEN>(enc, None, output_hex, Some(MODE))
        }
        CipherDirection::Decrypt => decrypt_stream::<_, 0, BLOCK_LEN>(
            None,
            |no_iv| key.create_decryptor(no_iv),
            output_hex,
            Some(MODE),
        ),
    }
}
