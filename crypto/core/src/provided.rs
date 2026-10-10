//! The provided bodies of the role keys' and mode traits' one-shots, over a worker that has
//! already been constructed, so that the drawing and the supplied-nonce forms share them.
//!
//! The `_out` bodies stream the message from one slice to another. The in-place bodies run a
//! message in its own buffer through the same split-slice update methods: each chunk is copied out to a small stack buffer and processed back into the bytes it came
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

/// Encrypts `plaintext` through `enc` after absorbing `aad` into `ciphertext`, tag inline, and
/// returns the number of bytes written. `ciphertext` is zeroized first and must hold
/// `encrypt_out_len(plaintext.len())` bytes.
///
/// # Errors
/// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, or any error of
/// the worker's streaming methods.
pub(crate) fn encrypt_inline<
    E,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut enc: E,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize, SymmetricCipherError>
where
    E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    ciphertext.fill(0);
    let needed = E::encrypt_out_len(plaintext.len());
    if ciphertext.len() < needed {
        return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
    }
    enc.do_update_aad(aad)?;
    let written = enc.do_encrypt_out(plaintext, ciphertext)?;
    let (last, last_len) = enc.do_encrypt_final()?;
    // `encrypt_out_len` is exactly `written + last_len`, so this fits in `ciphertext[..needed]`.
    ciphertext[written..written + last_len].copy_from_slice(&last[..last_len]);
    Ok(written + last_len)
}

/// As [`encrypt_inline`] with the tag detached: `ciphertext` needs only
/// `encrypt_detached_out_len(plaintext.len())` bytes, and the tag is returned.
///
/// # Errors
/// As [`encrypt_inline`].
pub(crate) fn encrypt_detached<
    E,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut enc: E,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError>
where
    E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    ciphertext.fill(0);
    let needed = E::encrypt_detached_out_len(plaintext.len());
    if ciphertext.len() < needed {
        return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
    }
    enc.do_update_aad(aad)?;
    let written = enc.do_encrypt_out(plaintext, ciphertext)?;
    let mut final_buf = [0u8; FINAL_LEN];
    let (final_len, tag) = enc.do_encrypt_final_detached_out(&mut final_buf)?;
    // `encrypt_detached_out_len` bounds `written + final_len`, so this fits in
    // `ciphertext[..needed]`.
    ciphertext[written..written + final_len].copy_from_slice(&final_buf[..final_len]);
    Ok((written + final_len, tag))
}

/// Encrypts `buf` in place through `enc` after absorbing `aad`, returning the detached tag.
///
/// # Errors
/// Any error of the worker's streaming methods.
pub(crate) fn encrypt_detached_in_place<
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
pub(crate) fn decrypt_detached_in_place<
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
