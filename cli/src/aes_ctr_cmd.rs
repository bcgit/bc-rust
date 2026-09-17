//! AES-CTR encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the nonce convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-cfb` and `aes*-cfb8` commands. See those modules for the command-line contract.
//!
//! # The nonce is 12 bytes and the counter is 4
//!
//! NIST SP 800-38A Sec 6.5 builds CTR on a sequence of counter blocks, and Appendix B.2's second
//! approach makes each one a message nonce followed by a counter. These commands use the
//! `AES_CTR_*` aliases, so the nonce is **12 bytes** and the counter is the remaining 4, giving
//! 2^32 blocks -- 64 GiB -- in a single message.
//!
//! `encrypt` writes that 12-byte nonce as the first bytes of its output and `decrypt` reads it back,
//! exactly as the other modes do with their IVs; note that it is 12 bytes here, not 16.
//!
//! # Any length
//!
//! CTR is a stream cipher: input of any length is accepted, nothing is padded, and the output is
//! exactly as long as the input.
//!
//! # Warning
//!
//! CTR provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the nonce is authenticated. It is the most malleable of the modes here: flipping any ciphertext
//! bit flips exactly the corresponding plaintext bit and affects nothing else (SP 800-38A
//! Appendix D, Table D.2, "SBE in the decryption of Cj"), so an attacker can edit the plaintext at
//! will, wherever they like, without any garbling to give it away. Do not decrypt data you have not
//! authenticated separately.
//!
//! A repeated nonce is fatal here rather than merely unwise: the same nonce under the same key
//! gives the same keystream, and two messages XORed with the same keystream leak their XOR. The
//! nonce is drawn from the OS-backed DRBG for exactly that reason, and there is no way to supply
//! one.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::aes::{AES_128, AES_192, AES_256, CTR_NONCE_LEN};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Ctr, Decrypting, Encrypting};

pub(crate) fn aes128_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_128, 16>(action, &load_key::<16>(key, key_file, "AES-128"), output_hex);
}

pub(crate) fn aes192_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_192, 24>(action, &load_key::<24>(key, key_file, "AES-192"), output_hex);
}

pub(crate) fn aes256_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<AES_256, 32>(action, &load_key::<32>(key, key_file, "AES-256"), output_hex);
}

/// Dispatches to the shared streaming loops with `Ctr` filled in as the mode.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    run_stream_mode::<
        Ctr<P, Encrypting, KEY_LEN, BLOCK_LEN, CTR_NONCE_LEN>,
        Ctr<P, Decrypting, KEY_LEN, BLOCK_LEN, CTR_NONCE_LEN>,
        KEY_LEN,
        CTR_NONCE_LEN,
    >(action, key, output_hex)
}
