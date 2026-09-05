//! SM4-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::block_mode_cmd`], shared with the `aes*-cbc`,
//! `aes*-cfb` and `aes*-ecb` commands. See that module for the command-line contract.
//!
//! `sm4-cbc` is the same command as `aes128-cbc` over the SM4 permutation (GB/T 32907-2016; 16-byte
//! key, 16-byte block), so every remark there applies unchanged. CBC (NIST SP 800-38A Sec 6.2)
//! provides confidentiality only: neither the ciphertext nor the IV is authenticated, and a flipped
//! ciphertext bit flips the same bit of the *next* block's plaintext (Appendix D). Do not decrypt data
//! you have not authenticated separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::modes::{Cbc, Decrypting, Encrypting};
use bouncycastle::sm4::SM4;

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn sm4_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "SM4");
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Cbc<SM4, Encrypting, 16, BLOCK_LEN>, 16, BLOCK_LEN>(
                &key, output_hex, MODE,
            )
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Cbc<SM4, Decrypting, 16, BLOCK_LEN>, 16, BLOCK_LEN>(
                &key, output_hex, MODE,
            )
        }
    }
}
