//! SM4-CFB8 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-cfb8` commands. See those modules for the command-line contract.
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

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::modes::{Cfb8, Decrypting, Encrypting};
use bouncycastle::sm4::SM4;

pub(crate) fn sm4_cfb8_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "SM4");
    run_stream_mode::<
        Cfb8<SM4, Encrypting, 16, BLOCK_LEN>,
        Cfb8<SM4, Decrypting, 16, BLOCK_LEN>,
        16,
        BLOCK_LEN,
    >(action, &key, output_hex)
}
