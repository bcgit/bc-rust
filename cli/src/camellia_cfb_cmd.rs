//! Camellia-CFB128 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-cfb` commands. See those modules for the command-line contract.
//!
//! `camellia128-cfb` / `camellia192-cfb` / `camellia256-cfb` are the same command as `aes*-cfb`
//! over the Camellia permutation (RFC 3713; 16-, 24- or 32-byte key, 16-byte block), so every
//! remark there applies unchanged. The segment size is the full block, i.e. **CFB128**
//! (NIST SP 800-38A Sec 6.3 with `s = b`); the `s = 8` variant is a different, non-interoperable
//! mode and has its own commands, `camellia*-cfb8`.
//!
//! CFB is a stream cipher, so unlike `camellia*-cbc` these commands accept input of any length and
//! pad nothing; the ciphertext is exactly as long as the plaintext.
//!
//! # Warning
//!
//! CFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Flipping a ciphertext bit flips the *same* bit of the plaintext in the
//! *same* block (SP 800-38A Appendix D, Table D.2), at the cost of randomising the next one, so an
//! attacker edits the block they aimed at. Do not decrypt data you have not authenticated
//! separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::camellia::{Camellia_128, Camellia_192, Camellia_256};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Cfb, Decrypting, Encrypting};

pub(crate) fn camellia128_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia_128, 16>(action, &load_key::<16>(key, key_file, "Camellia-128"), output_hex);
}

pub(crate) fn camellia192_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia_192, 24>(action, &load_key::<24>(key, key_file, "Camellia-192"), output_hex);
}

pub(crate) fn camellia256_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<Camellia_256, 32>(action, &load_key::<32>(key, key_file, "Camellia-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cfb` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    run_stream_mode::<
        Cfb<P, Encrypting, KEY_LEN, BLOCK_LEN>,
        Cfb<P, Decrypting, KEY_LEN, BLOCK_LEN>,
        KEY_LEN,
        BLOCK_LEN,
    >(action, key, output_hex)
}
