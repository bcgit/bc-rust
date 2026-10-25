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

use crate::helpers::block_mode_helpers::{BLOCK_LEN, CipherDirection, load_iv, load_key};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::aes::{AES_CFB8_128, AES_CFB8_192, AES_CFB8_256};
use bouncycastle::aes::{AES_CFB8_128_Key, AES_CFB8_192_Key, AES_CFB8_256_Key};
use bouncycastle::cipher::{Decrypting, Encrypting};

pub(crate) fn aes128_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<
        AES_CFB8_128<Encrypting>,
        AES_CFB8_128<Decrypting>,
        AES_CFB8_128_Key,
        16,
        BLOCK_LEN,
    >(
        action,
        &load_key::<AES_CFB8_128_Key, 16>(key, key_file, "AES-128"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
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
    run_stream_mode::<
        AES_CFB8_192<Encrypting>,
        AES_CFB8_192<Decrypting>,
        AES_CFB8_192_Key,
        24,
        BLOCK_LEN,
    >(
        action,
        &load_key::<AES_CFB8_192_Key, 24>(key, key_file, "AES-192"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
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
    run_stream_mode::<
        AES_CFB8_256<Encrypting>,
        AES_CFB8_256<Decrypting>,
        AES_CFB8_256_Key,
        32,
        BLOCK_LEN,
    >(
        action,
        &load_key::<AES_CFB8_256_Key, 32>(key, key_file, "AES-256"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}
