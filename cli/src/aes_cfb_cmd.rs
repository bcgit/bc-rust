//! AES-CFB128 encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
//! `aes*-cfb8` commands. See those modules for the command-line contract.
//!
//! # Which CFB
//!
//! These commands are **CFB128**: the segment size is the full 16-byte block (`s = b` in NIST
//! SP 800-38A Sec 6.3). SP 800-38A also defines `s = 8`, which is a different, non-interoperable
//! mode -- if you need CFB8, the `aes*-cfb8` commands are it -- and `s = 1`, which this library does
//! not provide.
//!
//! # Any length
//!
//! CFB is a stream cipher, so unlike `aes*-cbc` and `aes*-ecb` these commands accept input of any
//! length and pad nothing; the ciphertext is exactly as long as the plaintext. For a message that
//! is not a whole number of blocks the last partial block is a short final segment, which is what
//! every streaming CFB128 implementation does; see the `bouncycastle_cipher::modes::Cfb` docs.
//!
//! # Warning
//!
//! CFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. CFB's malleability is more directly exploitable than CBC's: Appendix D,
//! Table D.2 gives "SBE in the decryption of Cj" -- flipping a ciphertext bit flips the *same* bit
//! of the plaintext in the *same* block, so an attacker edits the block they aimed at, at the cost
//! of randomising the next one. Do not decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{BLOCK_LEN, CipherDirection, load_iv, load_key};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::aes::{AES_CFB_128, AES_CFB_192, AES_CFB_256};
use bouncycastle::cipher::{Decrypting, Encrypting};

pub(crate) fn aes128_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<AES_CFB_128<Encrypting>, AES_CFB_128<Decrypting>, 16, BLOCK_LEN>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes192_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<AES_CFB_192<Encrypting>, AES_CFB_192<Decrypting>, 24, BLOCK_LEN>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

pub(crate) fn aes256_cfb_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<AES_CFB_256<Encrypting>, AES_CFB_256<Decrypting>, 32, BLOCK_LEN>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}
