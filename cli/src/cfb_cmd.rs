//! CFB128 encryption and decryption over any 128-bit block permutation, streaming stdin to
//! stdout: the `aes*-cfb`, `aria*-cfb`, `camellia*-cfb` and `sm4-cfb` commands, one generic
//! function that `main` instantiates per cipher and key length.
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

use crate::helpers::block_mode_helpers::{BLOCK_LEN, CipherDirection, load_iv, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::cipher::BlockCipherKey;
use bouncycastle::cipher::modes::CFB;
use bouncycastle::cipher::modes::ModeNames;
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};

/// CFB under a `KEY_LEN`-byte key for the permutation `P`; `alg` names the cipher and key
/// length in messages.
pub(crate) fn cfb_cmd<P, const KEY_LEN: usize>(
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
    run::<_, KEY_LEN>(
        action,
        &load_key_object::<BlockCipherKey<P, CFB>, KEY_LEN>(key, key_file, alg),
        load_iv::<BLOCK_LEN>(iv, iv_file),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Cfb` filled in as the mode.
fn run<'k, K, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &'k K,
    iv: Option<[u8; BLOCK_LEN]>,
    output_hex: bool,
) where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, 0>,
    K::Encryptor<'k>: StreamCipherEncryptor<BLOCK_LEN>,
    K::Decryptor<'k>: StreamCipherDecryptor<BLOCK_LEN>,
{
    run_stream_mode::<K, KEY_LEN, BLOCK_LEN>(action, key, iv, output_hex)
}
