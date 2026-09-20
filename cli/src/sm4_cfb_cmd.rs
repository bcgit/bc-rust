//! SM4-CFB128 encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-cfb` commands. See those modules for the command-line contract.
//!
//! `sm4-cfb` is the same command as `aes128-cfb` over the SM4 permutation (GB/T 32907-2016; 16-byte
//! key, 16-byte block), so every remark there applies unchanged. The segment size is the full
//! block, i.e. draft-ribose-cfrg-sm4-10's **SM4-CFB-128** (Sec 8.5.1); the draft's 8-bit variant is
//! a different, non-interoperable mode and has its own command, `sm4-cfb8`.
//!
//! CFB is a stream cipher, so unlike `sm4-cbc` this command accepts input of any length and pads
//! nothing; the ciphertext is exactly as long as the plaintext.
//!
//! # Warning
//!
//! CFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Flipping a ciphertext bit flips the *same* bit of the plaintext in the
//! *same* block (NIST SP 800-38A Appendix D, Table D.2), at the cost of randomising the next one,
//! so an attacker edits the block they aimed at. Do not decrypt data you have not authenticated
//! separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::modes::{Cfb, Decrypting, Encrypting};
use bouncycastle::sm4::SM4;

pub(crate) fn sm4_cfb_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    let key = load_key::<16>(key, key_file, "SM4");
    run_stream_mode::<
        Cfb<SM4, Encrypting, 16, BLOCK_LEN>,
        Cfb<SM4, Decrypting, 16, BLOCK_LEN>,
        16,
        BLOCK_LEN,
    >(action, &key, output_hex)
}
