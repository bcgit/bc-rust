//! AES-GCM-SIV authenticated encryption and decryption (RFC 8452): the `aes128-gcm-siv` and
//! `aes256-gcm-siv` commands. AES-128 and AES-256 are the two AEADs RFC 8452 Section 6 defines,
//! so there is no command for AES-192 or for another cipher.
//!
//! # This command does not stream, and cannot
//!
//! Like `aes*-ccm` it reads stdin to the end first. The tag is computed over the whole plaintext
//! and is also the initial counter block (RFC 8452 Section 4), so encryption has no ciphertext
//! byte to write until it has read the last plaintext byte; and decryption has the whole
//! plaintext before it can check the tag, which Section 9 forbids it to release unchecked. The
//! input is processed in place, so memory use is the input and no second copy of it, and
//! `decrypt` writes nothing unless the tag verified.
//!
//! # Framing
//!
//! The framing is `aes*-gcm`'s: `nonce || ciphertext || tag` with a 12-byte nonce drawn per
//! `encrypt`, or `ciphertext || tag` in both directions when `--nonce` supplies it. The tag is
//! 16 bytes. The AAD flags are [`crate::helpers::aead_cipher_helpers::load_aad`]'s.

use std::process::exit;

use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::symmetric_key::{
    AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey, FromKeyMaterial,
};
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::symmetric::aes::{GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN};

use crate::helpers;
use crate::helpers::aead_cipher_helpers::load_aad;
use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object, load_nonce};

/// AES-GCM-SIV under the key type `K`, `AES_GCM_SIV_128` or `AES_GCM_SIV_256`; `alg` names the
/// cipher and key length in messages. See the module docs and the subcommand help.
#[allow(clippy::too_many_arguments)] // one flag per input, each inline or from a file
pub(crate) fn gcm_siv_cmd<K, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    output_hex: bool,
    alg: &str,
) where
    K: FromKeyMaterial<KEY_LEN>
        + AeadInPlaceEncryptionKey<KEY_LEN, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>
        + AeadInPlaceDecryptionKey<KEY_LEN, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>,
{
    // Everything but the key is read first, and each operation runs in a block that drops the
    // key before its result is looked at: `exit` runs no destructors, so a failure that ends
    // the process must not find the key schedule still in memory.
    let nonce = load_nonce::<GCM_SIV_NONCE_LEN>(nonce, nonce_file);
    let aad = load_aad(aad, aad_file);
    // See the module docs on why this is not a streaming command.
    let mut input = helpers::read_stdin_all();

    match action {
        CipherDirection::Encrypt => {
            let result = {
                let key: K = load_key_object::<_, KEY_LEN>(key, key_file, alg);
                match nonce {
                    Some(nonce) => key
                        .encrypt_detached_inplace_nonce(&nonce, &aad, &mut input)
                        .map(|tag| (None, tag)),
                    None => key
                        .encrypt_detached_inplace(
                            &mut HashDRBG_SHA512::new_from_os(),
                            &aad,
                            &mut input,
                        )
                        .map(|(nonce, tag)| (Some(nonce), tag)),
                }
            };
            let (drawn_nonce, tag) = result.unwrap_or_else(|e| {
                eprintln!("Error: {alg}-GCM-SIV encryption failed: {e:?}");
                exit(-1)
            });
            // A drawn nonce goes out ahead of the ciphertext, so `decrypt` can pick it up.
            if let Some(nonce) = drawn_nonce {
                helpers::write_bytes_or_hex(&nonce, output_hex);
            }
            helpers::write_bytes_or_hex(&input, output_hex);
            helpers::write_bytes_or_hex(&tag, output_hex);
        }
        CipherDirection::Decrypt => {
            // Without `--nonce` the leading bytes are the nonce `encrypt` wrote.
            let (nonce, rest) = match nonce {
                Some(nonce) => (nonce, &mut input[..]),
                None => match input.split_first_chunk_mut::<GCM_SIV_NONCE_LEN>() {
                    Some((nonce, rest)) => (*nonce, rest),
                    None => {
                        eprintln!(
                            "Error: input too short to contain the {GCM_SIV_NONCE_LEN}-byte nonce \
                             that `encrypt` writes first. If the nonce is held separately, pass \
                             it with --nonce."
                        );
                        exit(-1)
                    }
                },
            };
            let Some((data, tag)) = rest.split_last_chunk_mut::<GCM_SIV_TAG_LEN>() else {
                eprintln!(
                    "Error: ciphertext is {} bytes, shorter than the {GCM_SIV_TAG_LEN}-byte tag \
                     it must end with.",
                    rest.len()
                );
                exit(-1)
            };
            let result = {
                let key: K = load_key_object::<_, KEY_LEN>(key, key_file, alg);
                key.decrypt_detached_inplace(&nonce, &aad, data, tag)
            };
            match result {
                Ok(()) => helpers::write_bytes_or_hex(data, output_hex),
                Err(SymmetricCipherError::AEADTagCheckFailed) => {
                    eprintln!(
                        "Error: {alg}-GCM-SIV authentication failed; the input is not authentic."
                    );
                    exit(-1)
                }
                Err(e) => {
                    eprintln!("Error: {alg}-GCM-SIV decryption failed: {e:?}");
                    exit(-1)
                }
            }
        }
    }
    if output_hex {
        helpers::write_stdout(b"\n");
    }
    helpers::flush_stdout();
}
