//! AES-CFB8 encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
//! `aes*-cfb` commands. See those modules for the command-line contract.
//!
//! # Which CFB
//!
//! These commands are **CFB8**: the segment size is one byte (`s = 8` in NIST SP 800-38A Sec 6.3).
//! That is a different, non-interoperable mode from the CFB128 of `aes*-cfb`, not a variant of it:
//! the two ciphertexts agree on their first byte and differ everywhere after it. It also costs a
//! full AES call per byte of data, sixteen times the work of `aes*-cfb`, so prefer `aes*-cfb`
//! unless a byte-granular self-synchronising stream is required or the format demands CFB8.
//!
//! # Any length
//!
//! CFB8's segment is a single byte, so these commands accept input of any length, pad nothing, and
//! emit a ciphertext exactly as long as the plaintext.
//!
//! # Warning
//!
//! CFB8 provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Appendix D, Table D.2 gives "SBE in the decryption of Cj" plus random
//! errors in the next `b/s` segments: flipping a ciphertext bit flips the *same* bit of the *same*
//! plaintext byte, corrupts the following 16 bytes, and then decryption resynchronises. Do not
//! decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::aes::{AES_BLOCK_LEN, AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::CFB8;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};

pub(crate) fn aes128_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<AES128Key<CFB8>, 16>(key, key_file, "AES-128"),
        load_iv::<AES_BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes192_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<AES192Key<CFB8>, 24>(key, key_file, "AES-192"),
        load_iv::<AES_BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes256_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<AES256Key<CFB8>, 32>(key, key_file, "AES-256"),
        load_iv::<AES_BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Cfb8` filled in as the mode.
fn run<'k, K, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &'k K,
    iv: Option<[u8; AES_BLOCK_LEN]>,
    output_hex: bool,
) where
    K: SymmetricEncryptionKey<KEY_LEN, AES_BLOCK_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, AES_BLOCK_LEN, 0>,
    K::Encryptor<'k>: StreamCipherEncryptor<AES_BLOCK_LEN>,
    K::Decryptor<'k>: StreamCipherDecryptor<AES_BLOCK_LEN>,
{
    run_stream_mode::<K, KEY_LEN, AES_BLOCK_LEN>(action, key, iv, output_hex)
}
