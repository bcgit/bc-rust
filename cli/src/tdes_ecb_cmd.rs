//! TDES-ECB encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: key loading, stdin framing and block-alignment enforcement are
//! all in [`crate::helpers::block_mode_helpers`], shared with the AES commands and `tdes-cbc`. See
//! that module for the command-line contract. ECB has no IV (`INIT_DATA_LEN = 0`), so nothing is
//! prepended to
//! the output or consumed from the input: the ciphertext is exactly as long as the plaintext. The
//! block is 8 bytes.
//!
//! # Warning
//!
//! ECB (NIST SP 800-38A Sec 6.1; TECB in its Appendix E) is **not a confidentiality mode for
//! data**. Under a given key every plaintext block maps to the same ciphertext block, so equal
//! blocks stay visibly equal, the structure of the plaintext shows through, and blocks can be
//! reordered, repeated or removed with nothing to detect it. The same plaintext encrypts to the
//! same ciphertext every time. This command exists for interoperability with systems that use ECB
//! and for driving test vectors.
//!
//! TDEA is a legacy algorithm, disallowed for encryption by NIST SP 800-131A Rev 2 after 2023; see
//! the `bouncycastle-tdes` crate docs.

use crate::helpers::block_mode_helpers::{
    CipherDirection, decrypt_stream, encrypt_stream, load_key_object, start_encryptor,
};
use bouncycastle::cipher::modes::hazmat::ecb::ECB;
use bouncycastle::cipher::padding::NoPadding;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, TDES3Key};

/// Names the mode in error messages.
const MODE: &str = "ECB";

pub(crate) fn tdes_ecb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<TDES3Key<ECB<NoPadding>>, KEY_LEN>(key, key_file, "TDES");
    match action {
        CipherDirection::Encrypt => {
            // ECB has no IV: the constructor's RNG draws nothing, and nothing is written.
            let (enc, _) = start_encryptor(None, |rng| key.create_encryptor(rng));
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
