//! AES-CTR encryption and decryption, streaming stdin to stdout.
//!
//! Only the mode wiring lives here: the nonce convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
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

use crate::helpers::block_mode_helpers::{CipherDirection, load_key};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::aes::{AES_CTR_128, AES_CTR_192, AES_CTR_256, CTR_NONCE_LEN};
use bouncycastle::cipher::{Decrypting, Encrypting};

pub(crate) fn aes128_ctr_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<AES_CTR_128<Encrypting>, AES_CTR_128<Decrypting>, 16, CTR_NONCE_LEN>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        output_hex,
    );
}

pub(crate) fn aes192_ctr_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<AES_CTR_192<Encrypting>, AES_CTR_192<Decrypting>, 24, CTR_NONCE_LEN>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        output_hex,
    );
}

pub(crate) fn aes256_ctr_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run_stream_mode::<AES_CTR_256<Encrypting>, AES_CTR_256<Decrypting>, 32, CTR_NONCE_LEN>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        output_hex,
    );
}
