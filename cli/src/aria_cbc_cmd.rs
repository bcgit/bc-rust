//! ARIA-CBC encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading, stdin framing and
//! block-alignment enforcement are all in [`crate::block_mode_cmd`], shared with the `aes*-cbc`,
//! `aes*-cfb` and `aes*-ecb` commands. See that module for the
//! command-line contract.
//!
//! `aria128-cbc` / `aria192-cbc` / `aria256-cbc` are the same command as `aes*-cbc` over the ARIA
//! permutation (RFC 5794; 16-, 24- or 32-byte key, 16-byte block -- the `id-aria*-cbc` algorithms of
//! RFC 5794 Appendix B), so every remark there applies unchanged. CBC (NIST SP 800-38A Sec 6.2)
//! provides confidentiality only: neither the ciphertext nor the IV is authenticated. Do not decrypt
//! data you have not authenticated separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, decrypt_stream, encrypt_stream, load_key};
use bouncycastle::aria::{ARIA_128, ARIA_192, ARIA_256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Cbc, Decrypting, Encrypting};

/// Names the mode in error messages.
const MODE: &str = "CBC";

pub(crate) fn aria128_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_128, 16>(action, &load_key::<16>(key, key_file, "ARIA-128"), output_hex);
}

pub(crate) fn aria192_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_192, 24>(action, &load_key::<24>(key, key_file, "ARIA-192"), output_hex);
}

pub(crate) fn aria256_cbc_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_256, 32>(action, &load_key::<32>(key, key_file, "ARIA-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cbc` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    match action {
        BlockModeAction::Encrypt => {
            encrypt_stream::<Cbc<P, Encrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, BLOCK_LEN>(
                key, output_hex, MODE,
            )
        }
        BlockModeAction::Decrypt => {
            decrypt_stream::<Cbc<P, Decrypting, KEY_LEN, BLOCK_LEN>, KEY_LEN, BLOCK_LEN>(
                key, output_hex, MODE,
            )
        }
    }
}
