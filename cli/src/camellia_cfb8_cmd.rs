//! Camellia-CFB8 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
//! `aes*-cfb8` commands. See those modules for the command-line contract.
//!
//! `camellia128-cfb8` / `camellia192-cfb8` / `camellia256-cfb8` are the same command as `aes*-cfb8`
//! over the Camellia permutation (RFC 3713; 16-, 24- or 32-byte key, 16-byte block), so every
//! remark there applies unchanged. The segment size is one byte (NIST SP 800-38A Sec 6.3 with
//! `s = 8`): a DIFFERENT, NON-INTEROPERABLE mode from the CFB128 of `camellia*-cfb`, costing a full
//! Camellia call per byte, sixteen times the work. Prefer `camellia*-cfb` unless a byte-granular
//! self-synchronising stream is required or the format demands CFB8.
//!
//! # Warning
//!
//! CFB8 provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Do not decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::camellia::{BLOCK_LEN, Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::CFB8;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};

pub(crate) fn camellia128_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<Camellia128Key<CFB8>, 16>(key, key_file, "Camellia-128"),
        output_hex,
    );
}

pub(crate) fn camellia192_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<Camellia192Key<CFB8>, 24>(key, key_file, "Camellia-192"),
        output_hex,
    );
}

pub(crate) fn camellia256_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<Camellia256Key<CFB8>, 32>(key, key_file, "Camellia-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Cfb8` filled in as the mode; the init data
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
