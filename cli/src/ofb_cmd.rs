//! OFB encryption and decryption over any 128-bit block permutation, streaming stdin to stdout:
//! the `aes*-ofb`, `aria*-ofb`, `camellia*-ofb` and `sm4-ofb` commands, one generic function that
//! `main` instantiates per cipher and key length.
//!
//! Only the mode wiring lives here: the IV convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key
//! loader), shared with the other stream-mode commands. See those modules for the command-line
//! contract.
//!
//! # Any length
//!
//! OFB is a stream cipher (NIST SP 800-38A Sec 6.4), so these commands accept input of any length
//! and pad nothing; the ciphertext is exactly as long as the plaintext.
//!
//! # Warning
//!
//! OFB provides confidentiality only. It does not detect tampering, and neither the ciphertext nor
//! the IV is authenticated. Appendix D, Table D.2 gives "SBE in the decryption of Cj": flipping a
//! ciphertext bit flips the *same* bit of the plaintext, and no other block notices. A supplied IV
//! must never be repeated under one key, since a repeated IV repeats the whole keystream. Do not
//! decrypt data you have not authenticated separately.

use crate::helpers::block_mode_helpers::{CipherDirection, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::symmetric::BlockCipherKey;
use bouncycastle::symmetric::modes::ModeNames;
use bouncycastle::symmetric::modes::OFB;

/// The 128-bit block of the ciphers these commands serve; TDES has its own commands.
const BLOCK_LEN: usize = 16;

/// OFB under a `KEY_LEN`-byte key for the permutation `P`; `alg` names the cipher and key
/// length in messages.
pub(crate) fn ofb_cmd<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    iv: &Option<String>,
    iv_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    run_stream_mode::<_, KEY_LEN, BLOCK_LEN>(
        action,
        &load_key_object::<BlockCipherKey<P, OFB>, KEY_LEN>(key, key_file, alg),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}
