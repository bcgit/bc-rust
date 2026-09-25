//! ARIA-CTR encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the nonce convention, key loading and stdin framing are in
//! [`crate::stream_mode_cmd`] (and [`crate::block_mode_cmd`] for the key loader), shared with the
//! `aes*-ctr` commands. See those modules for the command-line contract.
//!
//! `aria128-ctr` / `aria192-ctr` / `aria256-ctr` are the same command as `aes*-ctr` over
//! the ARIA permutation (RFC 5794; 16-, 24- or 32-byte key, 16-byte block), so every remark
//! there applies unchanged, including the split of the counter block: the nonce is **12 bytes** and
//! the counter the remaining 4, giving 2^32 blocks -- 64 GiB -- in a single message. That is
//! NIST SP 800-38A Appendix B.2's construction, and it is the one KISA's published ARIA-CTR
//! vectors use: their counter block is all zeros and increments from there, which is what a
//! twelve-byte zero nonce and a counter starting at zero produce.
//!
//! `encrypt` writes that 12-byte nonce as the first bytes of its output and `decrypt` reads it back,
//! exactly as the other modes do with their IVs; note that it is 12 bytes here, not 16.
//!
//! # Warning
//!
//! CTR provides confidentiality only and is the most malleable mode here: flipping any ciphertext
//! bit flips exactly the corresponding plaintext bit and affects nothing else (SP 800-38A
//! Appendix D, Table D.2), so an attacker can edit the plaintext at will with no garbling to give
//! it away. A repeated nonce under one key is fatal rather than merely unwise -- the same keystream
//! twice leaks the XOR of the two messages -- which is why the nonce is drawn from the OS-backed
//! DRBG and there is no way to supply one. Do not decrypt data you have not authenticated
//! separately.

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::stream_mode_cmd::run_stream_mode;
use bouncycastle::aria::{ARIA_128, ARIA_192, ARIA_256, CTR_NONCE_LEN};
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::modes::{Ctr, Decrypting, Encrypting};

pub(crate) fn aria128_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_128, 16>(action, &load_key::<16>(key, key_file, "ARIA-128"), output_hex);
}

pub(crate) fn aria192_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_192, 24>(action, &load_key::<24>(key, key_file, "ARIA-192"), output_hex);
}

pub(crate) fn aria256_ctr_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<ARIA_256, 32>(action, &load_key::<32>(key, key_file, "ARIA-256"), output_hex);
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
