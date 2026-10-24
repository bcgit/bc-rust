//! Camellia-CFB128 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
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

use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::camellia::{BLOCK_LEN, Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::CFB;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};

pub(crate) fn camellia128_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<Camellia128Key<CFB>, 16>(key, key_file, "Camellia-128"),
        output_hex,
    );
}

pub(crate) fn camellia192_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<Camellia192Key<CFB>, 24>(key, key_file, "Camellia-192"),
        output_hex,
    );
}

pub(crate) fn camellia256_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<Camellia256Key<CFB>, 32>(key, key_file, "Camellia-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Cfb` filled in as the mode; the init data
/// travels in band, as the command's contract says.
fn run<'k, K, const KEY_LEN: usize>(action: &CipherDirection, key: &'k K, output_hex: bool)
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, 0>,
    K::Encryptor<'k>: StreamCipherEncryptor<BLOCK_LEN>,
    K::Decryptor<'k>: StreamCipherDecryptor<BLOCK_LEN>,
{
    run_stream_mode::<K, KEY_LEN, BLOCK_LEN>(action, key, None, output_hex)
}
