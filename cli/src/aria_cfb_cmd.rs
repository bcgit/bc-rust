//! ARIA-CFB128 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
//! `aes*-cfb` commands. See those modules for the command-line contract.
//!
//! `aria128-cfb` / `aria192-cfb` / `aria256-cfb` are the same command as `aes*-cfb`
//! over the ARIA permutation (RFC 5794; 16-, 24- or 32-byte key, 16-byte block), so every
//! remark there applies unchanged. The segment size is the full block, i.e. **CFB128**
//! (NIST SP 800-38A Sec 6.3 with `s = b`); the `s = 8` variant is a different, non-interoperable
//! mode and has its own commands, `aria*-cfb8`.
//!
//! CFB is a stream cipher, so unlike `aria*-cbc` these commands accept input of any length and
//! pad nothing; the ciphertext is exactly as long as the plaintext.
//!
//! # Warning
//!
//! CFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Flipping a ciphertext bit flips the *same* bit of the plaintext in the
//! *same* block (SP 800-38A Appendix D, Table D.2), at the cost of randomising the next one, so an
//! attacker edits the block they aimed at. Do not decrypt data you have not authenticated
//! separately.

use crate::helpers::block_mode_helpers::{BLOCK_LEN, CipherDirection, load_key};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::aria::hazmat::{ARIA_128, ARIA_192, ARIA_256};
use bouncycastle::cipher::modes::Cfb;
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::key_material::KeyMaterial;

pub(crate) fn aria128_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_128, 16>(action, &load_key::<16>(key, key_file, "ARIA-128"), output_hex);
}

pub(crate) fn aria192_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_192, 24>(action, &load_key::<24>(key, key_file, "ARIA-192"), output_hex);
}

pub(crate) fn aria256_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_256, 32>(action, &load_key::<32>(key, key_file, "ARIA-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Cfb` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &CipherDirection,
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
