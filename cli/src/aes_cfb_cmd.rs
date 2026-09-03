//! AES-CFB128 encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::block_mode_cmd`], shared with the `aes*-cbc`
//! commands. See that module for the command-line contract.
//!
//! # Which CFB
//!
//! These commands are **CFB128**: the segment size is the full 16-byte block (`s = b` in NIST
//! SP 800-38A Sec 6.3). That is the only segment size `bouncycastle-modes` provides, because it is
//! the only block-aligned one. SP 800-38A also defines `s = 8` and `s = 1`, which are *not*
//! interoperable with these commands -- if you need `CFB8` or `CFB1`, this is not it.
//!
//! # Warning
//!
//! CFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. CFB's malleability is more directly exploitable than CBC's: Appendix D,
//! Table D.2 gives "SBE in the decryption of Cj" -- flipping a ciphertext bit flips the *same* bit
//! of the plaintext in the *same* block, so an attacker edits the block they aimed at, at the cost
//! of randomising the next one. Do not decrypt data you have not authenticated separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::BlockPermutation;
use bouncycastle::modes::{Cfb, Decrypting, Encrypting};

/// Names the mode in error messages. Spelled with the segment size, because `CFB8` and `CFB1` are
/// different modes and a bare "CFB" in a diagnostic would be ambiguous.
const MODE: &str = "CFB128";

pub(crate) fn aes128_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes128, 16>(action, &load_key::<16>(key, key_file, "AES-128"), output_hex);
}

pub(crate) fn aes192_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes192, 24>(action, &load_key::<24>(key, key_file, "AES-192"), output_hex);
}

pub(crate) fn aes256_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Aes256, 32>(action, &load_key::<32>(key, key_file, "AES-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cfb` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Cfb<P, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN>(key, output_hex, MODE)
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Cfb<P, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN>(key, output_hex, MODE)
        }
    }
}
