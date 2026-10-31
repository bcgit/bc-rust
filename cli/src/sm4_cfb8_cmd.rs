//! SM4-CFB8 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the
//! key and IV loaders), shared with the `aes*-cfb8` commands. See those modules for the
//! command-line contract.
//!
//! `sm4-cfb8` is the same command as `aes128-cfb8` over the SM4 permutation (GB/T 32907-2016;
//! 16-byte key, 16-byte block), so every remark there applies unchanged. The segment size is one
//! byte: this is draft-ribose-cfrg-sm4-10's **SM4-CFB-8** (Sec 8.5.1), a different and
//! non-interoperable mode from the SM4-CFB-128 of `sm4-cfb`, and it costs a full SM4 call per byte,
//! sixteen times the work. Prefer `sm4-cfb` unless a byte-granular self-synchronising stream is
//! required or the format demands CFB8.
//!
//! # Warning
//!
//! CFB8 provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Do not decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::cipher::modes::CFB8;
use bouncycastle::sm4::{BLOCK_LEN, KEY_LEN, SM4Key};

/// Dispatches to the shared streaming loops under the key's `CFB8` mode.
pub(crate) fn sm4_cfb8_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key_object::<SM4Key<CFB8>, KEY_LEN>(key, key_file, "SM4");
    run_stream_mode::<_, KEY_LEN, BLOCK_LEN>(action, &key, load_iv(iv, iv_file), output_hex)
}
