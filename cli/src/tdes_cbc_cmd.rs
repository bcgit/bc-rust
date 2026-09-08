//! TDES-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::block_mode_cmd`], shared with the AES commands
//! and `tdes-ecb`. See that module for the command-line contract. The block, and so the IV, is
//! 8 bytes.
//!
//! CBC (NIST SP 800-38A Sec 6.2; TCBC in its Appendix E) provides confidentiality only. It does not
//! detect tampering, and neither the ciphertext nor the IV is authenticated -- a flipped ciphertext
//! bit flips the same bit of the *next* block's plaintext (Appendix D). Do not decrypt data you have
//! not authenticated separately.
//!
//! TDEA is a legacy algorithm, disallowed for encryption by NIST SP 800-131A Rev 2 after 2023; see
//! the `bouncycastle-tdes` crate docs. One key bundle must not protect more than 2^20 blocks (8 MiB)
//! in total (SP 800-67 Rev 2 Sec 3.4); the command does not count across invocations.

use crate::block_mode_cmd::{BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::modes::{Cbc, Decrypting, Encrypting};
use bouncycastle::tdes::{BLOCK_LEN, KEY_LEN, TDES};

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn tdes_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<KEY_LEN>(key, key_file, "TDES");
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Cbc<TDES, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, BLOCK_LEN, BLOCK_LEN>(
                &key, output_hex, MODE,
            )
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Cbc<TDES, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, BLOCK_LEN, BLOCK_LEN>(
                &key, output_hex, MODE,
            )
        }
    }
}
