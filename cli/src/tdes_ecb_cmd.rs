//! TDES-ECB encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: key loading, stdin framing and block-alignment enforcement are
//! all in [`crate::block_mode_cmd`], shared with the AES commands and `tdes-cbc`. See that module
//! for the command-line contract. ECB has no IV (`INIT_DATA_LEN = 0`), so nothing is prepended to
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

use crate::block_mode_cmd::{BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::modes::{Decrypting, Ecb, Encrypting};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, TDES};

/// Names the mode in error messages.
const MODE: &str = "ECB";

pub(crate) fn tdes_ecb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<KEY_LEN>(key, key_file, "TDES");
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Ecb<TDES, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, 0, BLOCK_LEN>(
                &key, output_hex, MODE,
            )
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Ecb<TDES, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, 0, BLOCK_LEN>(
                &key, output_hex, MODE,
            )
        }
    }
}
