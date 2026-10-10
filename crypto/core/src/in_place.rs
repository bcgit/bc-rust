//! The provided bodies of the in-place one-shots: a message encrypted or decrypted in its own
//! buffer through a streaming worker whose update methods take separate input and output slices.
//!
//! Each chunk is copied out to a small stack buffer and processed back into the bytes it came
//! from. The output never overtakes the input: a streaming cipher emits at most what it has been
//! given, so after `consumed` bytes have been read, at most `consumed` have been written, and the
//! slice `[written, consumed)` is both already read and long enough for what this call can emit.
//! That holds for a cipher that holds bytes back as well as for one that releases them at once.
//! The price over a true in-place update is one memcpy of the data through `CHUNK` bytes of
//! stack, and no second buffer the size of the message.

use crate::errors::SymmetricCipherError;
use crate::traits::{AEADCipherDecryptor, AEADCipherEncryptor};

/// Bytes copied out per step. Four 16-byte blocks keeps a block-cipher mode on its wide path.
const CHUNK: usize = 64;

/// Encrypts `buf` in place through `enc` after absorbing `aad`, returning the detached tag.
///
/// # Errors
/// Any error of the worker's streaming methods.
pub(crate) fn encrypt_detached<
    E,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut enc: E,
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], SymmetricCipherError>
where
    E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    enc.do_update_aad(aad)?;
    let mut tmp = [0u8; CHUNK];
    let mut consumed = 0;
    let mut written = 0;
    while consumed < buf.len() {
        let n = CHUNK.min(buf.len() - consumed);
        tmp[..n].copy_from_slice(&buf[consumed..consumed + n]);
        consumed += n;
        written += enc.do_encrypt_out(&tmp[..n], &mut buf[written..consumed])?;
    }
    let mut last = [0u8; FINAL_LEN];
    let (last_len, tag) = enc.do_encrypt_final_detached_out(&mut last)?;
    buf[written..written + last_len].copy_from_slice(&last[..last_len]);
    Ok(tag)
}

/// Decrypts `buf` in place through `dec` after absorbing `aad`, and checks `tag`. On any error
/// `buf` is zeroized: the plaintext was written into it before the tag could be checked.
///
/// # Errors
/// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, or any error of the
/// worker's streaming methods.
pub(crate) fn decrypt_detached<
    D,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut dec: D,
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), SymmetricCipherError>
where
    D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    let result = (|| {
        dec.do_update_aad(aad)?;
        let mut tmp = [0u8; CHUNK];
        let mut consumed = 0;
        let mut written = 0;
        while consumed < buf.len() {
            let n = CHUNK.min(buf.len() - consumed);
            tmp[..n].copy_from_slice(&buf[consumed..consumed + n]);
            consumed += n;
            written += dec.do_decrypt_out(&tmp[..n], &mut buf[written..consumed])?;
        }
        let mut last = [0u8; FINAL_LEN];
        let last_len = dec.do_decrypt_final_detached_out(tag, &mut last)?;
        buf[written..written + last_len].copy_from_slice(&last[..last_len]);
        Ok(())
    })();
    if result.is_err() {
        buf.fill(0);
    }
    result
}
