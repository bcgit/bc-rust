//! The provided bodies of the role keys' and mode traits' one-shots, over a worker that has
//! already been constructed, so that the drawing, supplied-nonce and packet forms share them.
//!
//! The `_out` bodies stream the message from one slice to another. The in-place bodies run a
//! message in its own buffer through the same split-slice update methods: each chunk is copied out
//! to a small stack buffer and processed back into the bytes it came from. The output never
//! overtakes the input: a streaming cipher emits at most what it has been given, so after
//! `consumed` bytes have been read, at most `consumed` have been written, and the slice
//! `[written, consumed)` is both already read and long enough for what this call can emit. That
//! holds for a cipher that holds bytes back as well as for one that releases them at once. The
//! price over a true in-place update is one memcpy of the data through `CHUNK` bytes of stack,
//! and no second buffer the size of the message.

use crate::errors::SymmetricCipherError;
use crate::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

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
    E: AEADCipherEncryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>,
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
    E: AEADCipherEncryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>,
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
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut enc: E,
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], SymmetricCipherError>
where
    E: AEADCipherEncryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

/// Decrypts `ciphertext`, tag inline, through `dec` after absorbing `aad` into `plaintext`, and
/// returns the number of bytes written. `plaintext` is zeroized first, must hold
/// `decrypt_out_len(ciphertext.len())` bytes, and is zeroized again before an error is returned.
///
/// # Errors
/// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short,
/// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, or any error of the
/// worker's streaming methods.
pub(crate) fn decrypt_inline<
    D,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut dec: D,
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<usize, SymmetricCipherError>
where
    D: AEADCipherDecryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    plaintext.fill(0);
    let needed = D::decrypt_out_len(ciphertext.len());
    if plaintext.len() < needed {
        return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
    }
    dec.do_update_aad(aad)?;
    let written = dec.do_decrypt_out(ciphertext, plaintext)?;
    match dec.do_decrypt_final() {
        Ok((last, data_len)) => {
            // `decrypt_out_len` bounds `written + data_len`, so this fits in `plaintext[..needed]`.
            plaintext[written..written + data_len].copy_from_slice(&last[..data_len]);
            Ok(written + data_len)
        }
        Err(e) => {
            // What `do_decrypt_out` released is unauthenticated, and this one-shot owns the
            // whole message, so it does not leave that in the caller's hands.
            plaintext[..written].fill(0);
            Err(e)
        }
    }
}

/// As [`decrypt_inline`] with the tag supplied separately; `plaintext` needs
/// `decrypt_detached_out_len(ciphertext.len())` bytes.
///
/// # Errors
/// As [`decrypt_inline`].
pub(crate) fn decrypt_detached<
    D,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>(
    mut dec: D,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    plaintext: &mut [u8],
) -> Result<usize, SymmetricCipherError>
where
    D: AEADCipherDecryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    plaintext.fill(0);
    let needed = D::decrypt_detached_out_len(ciphertext.len());
    if plaintext.len() < needed {
        return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
    }
    dec.do_update_aad(aad)?;
    let written = dec.do_decrypt_out(ciphertext, plaintext)?;
    let mut final_buf = [0u8; FINAL_LEN];
    match dec.do_decrypt_final_detached_out(tag, &mut final_buf) {
        Ok(final_len) => {
            plaintext[written..written + final_len].copy_from_slice(&final_buf[..final_len]);
            Ok(written + final_len)
        }
        Err(e) => {
            plaintext[..written].fill(0);
            Err(e)
        }
    }
}

/// Decrypts `buf` in place through `dec` after absorbing `aad`, and checks `tag`. On any error
/// `buf` is zeroized: the plaintext was written into it before the tag could be checked.
///
/// # Errors
/// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, or any error of the
/// worker's streaming methods.
pub(crate) fn decrypt_detached_in_place<
    D,
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
    D: AEADCipherDecryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

/// The payload length inside an inline `ciphertext || tag`, or the malformed-input error if
/// there is not room for a tag.
///
/// # Errors
/// [`SymmetricCipherError::DecryptionFailed`] if `ciphertext_len < TAG_LEN`.
pub(crate) fn inline_payload_len<const TAG_LEN: usize>(
    ciphertext_len: usize,
) -> Result<usize, SymmetricCipherError> {
    ciphertext_len.checked_sub(TAG_LEN).ok_or(SymmetricCipherError::DecryptionFailed)
}

/// Encrypts `plaintext` through `enc` into `ciphertext`, and returns the number of bytes written.
/// `ciphertext` is zeroized first and must hold `encrypt_out_len(plaintext.len())` bytes. The
/// unauthenticated counterpart of [`encrypt_inline`], for the symmetric role keys.
///
/// # Errors
/// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, or any error of
/// the worker's streaming methods.
pub(crate) fn symmetric_encrypt_out<E, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>(
    mut enc: E,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize, SymmetricCipherError>
where
    E: SymmetricCipherEncryptor<INIT_DATA_LEN, FINAL_LEN>,
{
    ciphertext.fill(0);
    let needed = E::encrypt_out_len(plaintext.len());
    if ciphertext.len() < needed {
        return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
    }
    let written = enc.do_encrypt_out(plaintext, ciphertext)?;
    let (last, last_len) = enc.do_encrypt_final()?;
    // `encrypt_out_len` is exactly `written + last_len`, so this fits in `ciphertext[..needed]`.
    ciphertext[written..written + last_len].copy_from_slice(&last[..last_len]);
    Ok(written + last_len)
}

/// Decrypts `ciphertext` through `dec` into `plaintext`, and returns the number of bytes
/// written. `plaintext` is zeroized first, must hold `decrypt_out_len(ciphertext.len())` bytes,
/// and is zeroized again before an error is returned. The unauthenticated counterpart of
/// [`decrypt_inline`].
///
/// # Errors
/// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short, or any error of
/// the worker's streaming methods.
pub(crate) fn symmetric_decrypt_out<D, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>(
    mut dec: D,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<usize, SymmetricCipherError>
where
    D: SymmetricCipherDecryptor<INIT_DATA_LEN, FINAL_LEN>,
{
    plaintext.fill(0);
    let needed = D::decrypt_out_len(ciphertext.len());
    if plaintext.len() < needed {
        return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
    }
    let written = dec.do_decrypt_out(ciphertext, plaintext)?;
    match dec.do_decrypt_final() {
        Ok((last, data_len)) => {
            // `decrypt_out_len` bounds `written + data_len`, so this fits in `plaintext[..needed]`.
            plaintext[written..written + data_len].copy_from_slice(&last[..data_len]);
            Ok(written + data_len)
        }
        Err(e) => {
            // A padding failure says the stream was not what it claimed to be; this one-shot owns
            // the whole message, so it does not leave the decrypted prefix in the caller's hands.
            plaintext[..written].fill(0);
            Err(e)
        }
    }
}
