//! ChaCha20 (RFC 8439 Sec 2.4) encryption and decryption, streaming stdin to stdout.
//!
//! The command-line contract is the one [`crate::helpers::stream_mode_helpers`] describes for
//! `aes*-ctr`: `encrypt` writes the generated 12-byte nonce ahead of the ciphertext and `decrypt`
//! reads it back, unless `--iv` / `--iv-file` supplies the nonce, in which case only ciphertext is
//! written or read. Any input length is accepted, and the output is exactly as long as the input.
//! A message may be at most 2^32 64-byte blocks (256 GiB).
//!
//! # Warning
//!
//! ChaCha20 alone provides confidentiality only, and is as malleable as CTR: see
//! [`crate::aes_ctr_cmd`]. Use `chacha20-poly1305` unless the ciphertext is authenticated by
//! some other means. A supplied nonce must never repeat under one key: the keystream would repeat
//! with it.

use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::chacha20::{ChaCha20Key, KEY_LEN, NONCE_LEN};

pub(crate) fn chacha20_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<_, KEY_LEN, NONCE_LEN>(
        action,
        &load_key_object::<ChaCha20Key, KEY_LEN>(key, key_file, "ChaCha20"),
        load_iv::<NONCE_LEN>(iv, iv_file),
        output_hex,
    );
}
