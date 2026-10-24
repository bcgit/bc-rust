//! Camellia-CTR encryption and decryption, streaming stdin to stdout.
//!
//! Only the cipher wiring lives here: the nonce convention, key loading and stdin framing are in
//! [`crate::helpers::stream_mode_helpers`] (and [`crate::helpers::block_mode_helpers`] for the key loader), shared with the
//! `aes*-ctr` commands. See those modules for the command-line contract.
//!
//! `camellia128-ctr` / `camellia192-ctr` / `camellia256-ctr` are the same command as `aes*-ctr` over
//! the Camellia permutation (RFC 3713; 16-, 24- or 32-byte key, 16-byte block), so every remark
//! there applies unchanged, including the split of the counter block: the nonce is **12 bytes** and
//! the counter the remaining 4, giving 2^32 blocks -- 64 GiB -- in a single message. That is
//! NIST SP 800-38A Appendix B.2's construction, not RFC 5528's, which divides the same block into a
//! 4-octet nonce, an 8-octet IV and a counter starting at one; ciphertexts are not interchangeable
//! with an RFC 5528 implementation.
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

use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use crate::helpers::stream_mode_helpers::run_stream_mode;
use bouncycastle::camellia::{CTR_NONCE_LEN, Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle::cipher::modes::CTR;
use bouncycastle::core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle::core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};

pub(crate) fn camellia128_ctr_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 16>(
        action,
        &load_key_object::<Camellia128Key<CTR>, 16>(key, key_file, "Camellia-128"),
        output_hex,
    );
}

pub(crate) fn camellia192_ctr_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 24>(
        action,
        &load_key_object::<Camellia192Key<CTR>, 24>(key, key_file, "Camellia-192"),
        output_hex,
    );
}

pub(crate) fn camellia256_ctr_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    output_hex: bool,
) {
    run::<_, 32>(
        action,
        &load_key_object::<Camellia256Key<CTR>, 32>(key, key_file, "Camellia-256"),
        output_hex,
    );
}

/// Dispatches to the shared streaming loops with `Ctr` filled in as the mode; the init data
/// travels in band, as the command's contract says.
fn run<'k, K, const KEY_LEN: usize>(action: &CipherDirection, key: &'k K, output_hex: bool)
where
    K: SymmetricEncryptionKey<KEY_LEN, CTR_NONCE_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, CTR_NONCE_LEN, 0>,
    K::Encryptor<'k>: StreamCipherEncryptor<CTR_NONCE_LEN>,
    K::Decryptor<'k>: StreamCipherDecryptor<CTR_NONCE_LEN>,
{
    run_stream_mode::<K, KEY_LEN, CTR_NONCE_LEN>(action, key, None, output_hex)
}
