//! Provides simplified abstracted APIs over classes of cryptographic primitives, such as Hash, KDF, etc.

use crate::errors::*;
use crate::key_material::KeyMaterialTrait;
use core::fmt::{Debug, Display};
use core::marker::Sized;

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyMaterial;
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

/// The basic functions of an Authenticated Encryption with Addititional Data cipher.
pub trait AEADCipher<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>:
    Algorithm + Sized
{
    #[cfg(feature = "std")]
    /// A one-shot API to encrypt some plaintext with the given key, with no additional
    /// authenticated data.
    ///
    /// This and the three that follow were the whole of the former `SymmetricCipher` trait, which
    /// every symmetric cipher was once expected to implement. They now live here, because an AEAD
    /// is the only kind of cipher left that needs them: a block mode reaches the same shape through
    /// [`SimpleCipherEncryptor`] / [`SimpleCipherDecryptor`] and the padding adapters, and a
    /// stream mode gets those traits directly.
    ///
    /// These are meant to be simple, easy to use, secure and fool-proof, at the cost of producing a
    /// ciphertext whose layout is this implementation's business: an AEAD has a tag to put
    /// somewhere, and where it goes is not fixed here. See the documentation of the underlying
    /// implementation before assuming another one will read it.
    ///
    /// Returns the generated nonce and the ciphertext as a `Vec<u8>`, so it needs the `std`
    /// feature. For AAD, use [`aead_encrypt`](Self::aead_encrypt).
    fn encrypt(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), SymmetricCipherError>;

    /// As [`encrypt`](Self::encrypt), writing into a caller-supplied buffer so it is available
    /// without `std`.
    ///
    /// See the documentation for the underlying implementation for how big the ciphertext buffer
    /// must be; an AEAD needs room for the tag as well as the data. Returns the generated nonce and
    /// the number of bytes written.
    fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize), SymmetricCipherError>;

    #[cfg(feature = "std")]
    /// A one-shot API to decrypt what [`encrypt`](Self::encrypt) produced, with no additional
    /// authenticated data. Returns the plaintext as a `Vec<u8>`, so it needs the `std` feature.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if the ciphertext does not authenticate. This
    /// view has no AAD and no separate tag to name, so it reports every authentication failure
    /// this way rather than as [`SymmetricCipherError::AEADTagCheckFailed`], which is reserved for
    /// [`aead_decrypt`](Self::aead_decrypt) / [`aead_decrypt_out`](Self::aead_decrypt_out); either
    /// way, the caller learns only that decryption failed, not why.
    fn decrypt(
        key: &KeyMaterial<KEY_LEN>,
        init_data: [u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError>;

    /// As [`decrypt`](Self::decrypt), writing into a caller-supplied buffer so it is available
    /// without `std`. Returns the number of bytes written.
    ///
    /// # Errors
    /// As [`decrypt`](Self::decrypt).
    fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        init_data: [u8; NONCE_LEN],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    #[cfg(feature = "std")]
    /// A one-shot API to encrypt some plaintext with the given key.
    /// A distinguishing feature of AEAD ciphers is the ability to provide additional authenticated data (AAD)
    /// that is not encrypted but is protected by the authentication tag; ie it can be sent along with the ciphertext
    /// and any tampering with it will result in the decryption operation failing the tag check.
    /// This function returns the ciphertext as a `Vec<u8>`, and therefore is only available when compiling with std.
    /// Returns a tuple containing a generated nonce, the ciphertext and the tag.
    fn aead_encrypt(
        key: &KeyMaterial<KEY_LEN>,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>, [u8; TAG_LEN]), SymmetricCipherError>;
    /// A one-shot API to encrypt some plaintext with the given key.
    /// A distinguishing feature of AEAD ciphers is the ability to provide additional authenticated data (AAD)
    /// that is not encrypted but is protected by the authentication tag; ie it can be sent along with the ciphertext
    /// and any tampering with it will result in the decryption operation failing the tag check.
    /// Returns a tuple containing the randomly-generated nonce, number of bytes written to the ciphertext buffer, and the tag.
    /// If you need a deterministic mode where you feed in the nonce, use the streaming API of [`BlockCipherEncryptor`]
    /// or [`StreamCipherEncryptor`] as appropriate and feed the nonce into the IV field.
    fn aead_encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError>;
    /// Finishes a streaming encryption flow with an AEAD-specific `do_final()` that computes and
    /// returns the authentication tag.
    ///
    /// An AEAD's own streaming API is [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], which has
    /// this step (as [`AEADCipherEncryptor::do_encrypt_final`]) and an AAD phase of its own; this
    /// method is for an implementor that streams through one of the unauthenticated cipher traits
    /// -- [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] or [`StreamCipherEncryptor`] /
    /// [`StreamCipherDecryptor`] -- and needs somewhere to put the tag.
    fn do_aead_encrypt_final(self) -> Result<[u8; TAG_LEN], SymmetricCipherError>;
    #[cfg(feature = "std")]
    /// A one-shot API to decrypt some ciphertext with the given key.
    /// This function returns the ciphertext as a `Vec<u8>`, and therefore is only available when compiling with std.
    fn aead_decrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>, SymmetricCipherError>;
    /// A one-shot API to decrypt some ciphertext with the given key.
    /// This function takes a reference to the output buffer for the plaintext, and is therefore available in no_std.
    /// See the documentation for the underlying implementation for details on providing a plaintext buffer of sufficient size;
    /// typically the ciphertext is the same length as the plaintext, but some ciphers may have an expansion factor or require
    /// extra space for a nonce or tag.
    /// Returns the number of bytes written to the plaintext buffer.
    fn aead_decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;
    /// Finishes a streaming decryption flow by checking `tag`; the mirror of
    /// [`do_aead_encrypt_final`](Self::do_aead_encrypt_final), and see it for when this is the
    /// right finalizer rather than [`AEADCipherDecryptor::do_decrypt_final`].
    fn do_aead_decrypt_final(self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError>;
}

/// The decryption half of an AEAD cipher's streaming API; see [`AEADCipherEncryptor`], whose notes
/// on the AAD phase, buffering, and the `Result` all apply here too.
///
/// # The plaintext is not authenticated until `do_decrypt_final` returns `Ok`
///
/// This is the one thing a streaming AEAD API cannot hide from its caller.
/// [`do_update_out`](Self::do_update_out) releases plaintext as soon as it can, long before there
/// is a tag to check it against, so a caller that *uses* those bytes before
/// [`do_decrypt_final`](Self::do_decrypt_final) has returned `Ok` is acting on unauthenticated
/// plaintext -- bytes an attacker may have chosen. Preventing exactly that is what the tag is for.
/// A streaming caller must therefore treat everything `do_update_out` produces as untrusted until
/// the final call succeeds, and scrub it if it does not.
///
/// The one-shot [`decrypt`](Self::decrypt) has no such caveat: it owns the whole message, so it
/// zeroizes the buffer itself before returning the error.
pub trait AEADCipherDecryptor<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>: Algorithm + Sized
{
    /// Begins a streaming decryption flow from the nonce returned by
    /// [`AEADCipherEncryptor::do_encrypt_init`].
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError>;

    /// Absorbs additional authenticated data; see [`AEADCipherEncryptor::do_update_aad`] for the
    /// rules, which are the same on both sides. The concatenation of what a decryptor absorbs must
    /// be byte-for-byte the concatenation the encryptor absorbed, or the tag check fails.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if called with a non-empty `aad` after
    /// [`do_update_out`](Self::do_update_out).
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError>;

    /// The exact number of bytes the next [`do_update_out`](Self::do_update_out) will write if
    /// given `input_len` more bytes of ciphertext. Depends on what is already buffered; identically
    /// `0` for a cipher that never holds anything back, such as Ascon-AEAD128.
    fn update_out_len(&self, input_len: usize) -> usize;

    /// Streaming: consumes `ciphertext`, writing every plaintext byte that can be released so far
    /// into `plaintext` and buffering the rest. Returns the number of bytes written, which is
    /// exactly [`update_out_len`](Self::update_out_len) of `ciphertext.len()`.
    ///
    /// The bytes this writes are *not* yet authenticated; see the trait docs. A decryptor may have
    /// to hold back the tail of what it has seen -- a block-oriented cipher's partial final block,
    /// or the bytes that might turn out to be an inline tag -- so a sequence of calls releases data
    /// later than the corresponding encryptor produced it, but the concatenation of everything
    /// released, in any chunking, plus the data part of
    /// [`do_decrypt_final`](Self::do_decrypt_final), is the plaintext.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `plaintext` is shorter than
    /// [`update_out_len`](Self::update_out_len), carrying the required length. Nothing is
    /// consumed in that case.
    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Finishes the decryption, consuming the decryptor: flushes whatever ciphertext was held back
    /// into `output`, computes the tag over the AAD and ciphertext it has seen, and compares it
    /// against `tag`. Returns how many leading bytes of `output` are plaintext; the remainder is
    /// not data and must not be used. `Ok` is the only thing that makes those bytes -- or anything
    /// already released by [`do_update_out`](Self::do_update_out) -- trustworthy.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify. Implementors must
    /// compare in constant time, and the caller learns only that the check failed.
    fn do_decrypt_final(
        self,
        tag: &[u8; TAG_LEN],
        output: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>;

    /// An upper bound on the plaintext recovered from `ciphertext_len` bytes of ciphertext, i.e.
    /// the buffer [`decrypt_out`](Self::decrypt_out) requires. The default returns `ciphertext_len`
    /// itself, which is exact for every conformant AEAD: unlike a padding scheme, an AEAD never
    /// expands or shrinks the data it is given, only adds the separate `tag`.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }

    /// One-shot: decrypts `ciphertext` into `plaintext`, which needs
    /// [`decrypt_out_max_len`](Self::decrypt_out_max_len) bytes, under `nonce` and `aad`, and
    /// checks `tag`. Returns the number of plaintext bytes written.
    ///
    /// Unlike the streaming methods this releases nothing unauthenticated: on failure `plaintext`
    /// is zeroized before the error is returned, so a caller who ignores the `Result` is left with
    /// zeros rather than attacker-chosen plaintext.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `plaintext` is too short, checked
    /// before any work is done; otherwise whatever the streaming methods return, including
    /// [`do_decrypt_final`](Self::do_decrypt_final)'s.
    fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = Self::decrypt_out_max_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("plaintext", needed));
        }
        let mut dec = Self::do_decrypt_init(key, nonce)?;
        dec.do_update_aad(aad)?;
        let written = dec.do_update_out(ciphertext, plaintext)?;
        let mut final_buf = [0u8; FINAL_LEN];
        match dec.do_decrypt_final(tag, &mut final_buf) {
            Ok(final_len) => {
                plaintext[written..written + final_len].copy_from_slice(&final_buf[..final_len]);
                Ok(written + final_len)
            }
            Err(e) => {
                // As in the trait docs: what `do_update_out` already released is unauthenticated,
                // and this one-shot owns the whole message, so it does not leave that in the
                // caller's hands. A plain `fill` rather than a volatile write because `core` is
                // `#![forbid(unsafe_code)]`; the store is to the caller's own buffer, which the
                // caller may read after this returns, so it is not a dead store the optimizer is
                // entitled to drop.
                plaintext[..written].fill(0);
                Err(e)
            }
        }
    }

    #[cfg(feature = "std")]
    /// One-shot, allocating: as [`decrypt_out`](Self::decrypt_out), returning the plaintext as a
    /// `Vec<u8>` of exactly the recovered length. Only available with the `std` feature.
    fn decrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::decrypt_out_max_len(ciphertext.len())];
        let written = Self::decrypt_out(key, nonce, aad, ciphertext, tag, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }
}

/// The encryption half of an AEAD cipher's streaming API. This is the AEAD counterpart of
/// [`SimpleCipherEncryptor`] -- the same separate-output, init-data-generating, possibly-buffering
/// shape -- with the two differences that authentication forces.
///
/// The first is an extra phase. An AEAD authenticates data it does not encrypt -- additional
/// authenticated data (AAD), typically a header that has to travel in the clear but must still be
/// protected against tampering -- and every AEAD construction absorbs that AAD *before* the
/// plaintext. So [`do_update_aad`](Self::do_update_aad) may be called any number of times after
/// the constructor and before the first [`do_update_out`](Self::do_update_out), and returns
/// [`SymmetricCipherError::StateError`] thereafter. (An empty `aad` slice is a no-op and is
/// accepted at any point, so a generic caller may pass one unconditionally.) That is a runtime
/// error for the same reason [`XOF`] rejects absorb-after-squeeze at runtime: the phase order is a
/// property of a value's history, and encoding it in the type would cost every implementor an
/// extra type and an explicit transition.
///
/// The second is a finalization step that also produces a tag: [`do_encrypt_final`](Self::do_encrypt_final)
/// consumes the encryptor, flushes whatever ciphertext it was holding back into `output`, and
/// returns the tag, which the recipient needs for [`AEADCipherDecryptor::do_decrypt_final`]. Where
/// the tag travels -- appended to the ciphertext, carried in a separate field -- is the caller's
/// choice, not this trait's; contrast [`AEADCipher`], whose one-shots pick a layout for you, and
/// see `bouncycastle_core::tagged_aead` for an adapter that appends it.
///
/// Encryption and decryption are separate traits, as with [`BlockCipherEncryptor`] /
/// [`BlockCipherDecryptor`], so that the direction is encoded in the type. For an AEAD that also
/// buys away a class of runtime check: a single type serving both directions has to remember which
/// one it is and refuse the other's methods, whereas a paired-type implementation cannot be asked
/// the question.
///
/// # The nonce is generated, not supplied
///
/// The constructor draws the nonce itself and returns it for transmission alongside the ciphertext;
/// there is no API here for the caller to choose one, for the same reason as in
/// [`BlockCipherEncryptor`], but with sharper consequences. Reusing a nonce under one key does not
/// merely leak equality of plaintexts as it does for an unauthenticated mode -- for most AEAD
/// constructions it forfeits confidentiality of the affected messages and can expose the material
/// the tag is computed from, costing authenticity for every other message under that key. A caller
/// who genuinely needs a deterministic, caller-chosen nonce (to follow a protocol's construction,
/// or to run a spec's test vectors) should see the documentation of the underlying implementation,
/// which is where that hazard belongs.
///
/// # A cipher may buffer
///
/// [`do_update_out`](Self::do_update_out) takes separate input and output buffers, because an AEAD
/// is not guaranteed to release a ciphertext byte the moment it sees the matching plaintext byte.
/// Ascon-AEAD128 does -- each rate-block byte is transformed independently of the others in that
/// block -- but a block-oriented AEAD holds back a partial final block, and any AEAD adapted to an
/// inline `ciphertext || tag` layout must hold back at least `TAG_LEN` bytes until it knows they
/// are not the tag (see `bouncycastle_core::tagged_aead`). [`update_out_len`](Self::update_out_len)
/// answers exactly how many bytes the next call releases, so a caller never has to guess a buffer
/// size or find plaintext left over at the end of one it guessed too large; the concatenation of
/// everything released, in any chunking, plus the data part of
/// [`do_encrypt_final`](Self::do_encrypt_final), is the ciphertext.
///
/// # Any length, as a slice
///
/// [`do_update_out`](Self::do_update_out)'s input is a `&[u8]` rather than a `&[u8; LEN]` because
/// every length is valid, including zero, so there is no invariant for a const parameter to carry
/// and nothing for a compile-time check to check -- the same reasoning as
/// [`StreamCipherEncryptor`], and the reason there is no `BLOCK_LEN` here.
///
/// # Why the data methods still return `Result`
///
/// Nothing about the buffer can go wrong, and a constructed value is always ready to use, so
/// [`do_update_out`](Self::do_update_out) has nothing to report for most ciphers. The `Result` is
/// for the per-(key, nonce) data limit an AEAD generally has -- past it the construction's security
/// argument no longer holds -- which a streaming API cannot check any earlier than the call that
/// would cross it, and for [`IncorrectOutputBufferLength`](SymmetricCipherError::IncorrectOutputBufferLength)
/// if the caller under-sized `ciphertext`.
pub trait AEADCipherEncryptor<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>: Algorithm + Sized
{
    /// Begins a streaming encryption flow, returning the encryptor and the generated nonce, which
    /// the recipient needs for [`AEADCipherDecryptor::do_decrypt_init`]. Sources randomness from
    /// the library's default OS-backed RNG.
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`]; a failure to draw the nonce comes back as a
    /// [`SymmetricCipherError::RNGError`].
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError>;

    /// As [`do_encrypt_init`](Self::do_encrypt_init), but sources randomness from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError>;

    /// Absorbs `aad`: data that is authenticated by the tag but not encrypted. May be called
    /// repeatedly before the first [`do_update_out`](Self::do_update_out); a sequence of calls is
    /// equivalent to one call over the concatenation. An empty `aad` is a no-op.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if called with a non-empty `aad` after
    /// [`do_update_out`](Self::do_update_out) -- see the trait docs for why the AAD comes first.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError>;

    /// The exact number of bytes the next [`do_update_out`](Self::do_update_out) will write if
    /// given `input_len` more bytes of plaintext. Depends on what is already buffered; identically
    /// `0` for a cipher that never holds anything back, such as Ascon-AEAD128.
    fn update_out_len(&self, input_len: usize) -> usize;

    /// Streaming: consumes `plaintext`, writing every ciphertext byte that can be produced so far
    /// into `ciphertext` and buffering the rest. Returns the number of bytes written, which is
    /// exactly [`update_out_len`](Self::update_out_len) of `plaintext.len()`. A sequence of calls
    /// is equivalent to one call over the concatenation, whatever the chunking.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `ciphertext` is shorter than
    /// [`update_out_len`](Self::update_out_len), carrying the required length. Nothing is
    /// consumed in that case.
    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Finishes the encryption, consuming the encryptor: flushes whatever plaintext was held back,
    /// encrypted, into `output`, and returns how many leading bytes of it are ciphertext together
    /// with the tag over the AAD and plaintext it has seen. The tag must be transmitted with the
    /// ciphertext; the recipient passes it to [`AEADCipherDecryptor::do_decrypt_final`].
    fn do_encrypt_final(
        self,
        output: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError>;

    /// The exact ciphertext length for a `plaintext_len`-byte plaintext, i.e. the buffer
    /// [`encrypt_out`](Self::encrypt_out) requires and the number of bytes it writes (the tag is
    /// returned separately, not counted here). The default returns `plaintext_len` itself, which
    /// holds for every conformant AEAD: unlike a padding scheme, an AEAD never expands or shrinks
    /// the data it is given.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }

    /// One-shot: encrypts `plaintext` into `ciphertext`, which needs
    /// [`encrypt_out_len`](Self::encrypt_out_len) bytes, authenticating `aad` along with it under a
    /// fresh nonce. Returns the generated nonce, the number of bytes written, and the tag.
    ///
    /// Provided as `do_encrypt_init`, one `do_update_aad`, one `do_update_out` and
    /// `do_encrypt_final`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `ciphertext` is too short, checked
    /// before any work is done; otherwise whatever the streaming methods return.
    fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let needed = Self::encrypt_out_len(plaintext.len());
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", needed));
        }
        let (mut enc, nonce) = Self::do_encrypt_init(key)?;
        enc.do_update_aad(aad)?;
        let written = enc.do_update_out(plaintext, ciphertext)?;
        let mut final_buf = [0u8; FINAL_LEN];
        let (final_len, tag) = enc.do_encrypt_final(&mut final_buf)?;
        // `encrypt_out_len` bounds `written + final_len`, so this fits in `ciphertext[..needed]`.
        ciphertext[written..written + final_len].copy_from_slice(&final_buf[..final_len]);
        Ok((nonce, written + final_len, tag))
    }

    /// As [`encrypt_out`](Self::encrypt_out), but sources randomness from the provided RNG.
    fn encrypt_out_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let needed = Self::encrypt_out_len(plaintext.len());
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", needed));
        }
        let (mut enc, nonce) = Self::do_encrypt_init_rng(key, rng)?;
        enc.do_update_aad(aad)?;
        let written = enc.do_update_out(plaintext, ciphertext)?;
        let mut final_buf = [0u8; FINAL_LEN];
        let (final_len, tag) = enc.do_encrypt_final(&mut final_buf)?;
        ciphertext[written..written + final_len].copy_from_slice(&final_buf[..final_len]);
        Ok((nonce, written + final_len, tag))
    }

    #[cfg(feature = "std")]
    /// One-shot, allocating: as [`encrypt_out`](Self::encrypt_out), returning the ciphertext as a
    /// `Vec<u8>`. Only available with the `std` feature.
    fn encrypt(
        key: &KeyMaterial<KEY_LEN>,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>, [u8; TAG_LEN]), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::encrypt_out_len(plaintext.len())];
        let (nonce, written, tag) = Self::encrypt_out(key, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext, tag))
    }
}

/// Metadata about a cryptographic algorithm.
pub trait Algorithm {
    /// String name for the algorithm, used consistently across the library.
    const ALG_NAME: &'static str;
    /// Maximum security strength supported by the algorithm.
    /// In other words, this algorithm can produce outputs up to this security strength,
    /// but may produce outputs with lower security strength, for example, if asked to truncate.
    const MAX_SECURITY_STRENGTH: SecurityStrength;
}

/// Some algorithms have an assigned OID.
pub trait AlgorithmOID {
    /// The OID in component form -- each u32 is one OID component.
    const OID: &'static [u32];
    /// The OID in its DER-encoded form.
    const OID_DER: &'static [u8];
}

/// The decryption half of a block cipher's streaming API; see [`BlockCipherEncryptor`], whose
/// notes on in-place operation, compile-time lengths and the `Result` all apply here too.
pub trait BlockCipherDecryptor<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
>: Algorithm + Sized
{
    /// Begins a streaming decryption flow from the init data returned by [`BlockCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError>;
    /// The implementor hook: decrypts consecutive whole blocks in place. See
    /// [`BlockCipherEncryptor::do_encrypt_blocks`]; callers should normally use the flat
    /// [`BlockCipherDecryptor::do_decrypt`] instead.
    fn do_decrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<(), SymmetricCipherError>;

    /// Streaming: decrypts `LEN` bytes, a whole number of blocks, in place. `LEN % BLOCK_LEN == 0`
    /// is checked at compile time, exactly as for [`BlockCipherEncryptor::do_encrypt`].
    fn do_decrypt<const LEN: usize>(
        &mut self,
        data: &mut [u8; LEN],
    ) -> Result<(), SymmetricCipherError> {
        const {
            assert!(
                LEN.is_multiple_of(BLOCK_LEN),
                "length must be a whole number of BLOCK_LEN-byte blocks"
            )
        };
        // The remainder is provably empty (asserted above) and ignored.
        let (blocks, _) = data.as_chunks_mut::<BLOCK_LEN>();
        self.do_decrypt_blocks(blocks)
    }

    /// One-shot: decrypts `LEN` bytes in place from the given init data. `LEN % BLOCK_LEN == 0` is
    /// checked at compile time exactly as for [`BlockCipherEncryptor::encrypt`].
    fn decrypt<const LEN: usize>(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
        data: &mut [u8; LEN],
    ) -> Result<(), SymmetricCipherError> {
        Self::do_decrypt_init(key, init_data)?.do_decrypt(data)
    }
}

/// The encryption half of a block cipher's streaming API. Strictly block-aligned: whole blocks in, whole
/// blocks out, no finalization step. Padding of non-block-aligned data is handled by a separate layer
/// (`PaddedEncryptor` / `PaddedDecryptor`) built on top of this trait.
///
/// Encryption and decryption are separate traits (as with [`KEMEncapsulator`] / [`KEMDecapsulator`]) so
/// that the direction can be encoded in the type, and so that a policy can permit decryption of an
/// algorithm while forbidding new encryptions.
///
/// This trait allows for a block cipher to generate initialization data, such as an Initialization Vector (IV) or Counter (CTR)
/// which is not technically part of the ciphertext, but must be transmitted along with the ciphertext in order for the
/// recipient to perform successful decryption. The length of the initialization data is specified by the implementing struct
/// via the `INIT_DATA_LEN` constant.
/// In order for these APIs to be usable securely in all contexts, the init data will be generated
/// securely by the block cipher implementation and returned along with the ciphertext, and there is no API for the
/// user to provide the init data. If you require this functionality, see the documentation for the underlying implementation.
///
/// # Everything is in place
///
/// Every data method here transforms its buffer in place: the plaintext goes in, the ciphertext
/// comes out in the same bytes. A block cipher mode never changes the length of its data, so a
/// separate output buffer would only ever be a copy, and a copy of plaintext is one more thing to
/// scrub. Callers that need to keep the plaintext copy it first.
///
/// # Lengths are checked at compile time
///
/// Every buffer is a `[u8; LEN]`, and `LEN % BLOCK_LEN == 0` is checked by an inline `const`
/// assertion when the method is instantiated: a misaligned length is a compile error at the call
/// site, not a runtime `Err`, which is why there is no length variant of [`SymmetricCipherError`]
/// here. Data whose length is only known at run time is fed in block by block, or through the
/// padding layer.
///
/// # Why the data methods still return `Result`
///
/// Nothing about the buffer can go wrong, and a constructed value is always ready to use, so a
/// mode like CBC never returns `Err` from them. The `Result` is for modes with a per-initialization
/// data limit -- a counter-based mode must refuse to encrypt past the point where its counter would
/// repeat -- which a streaming API cannot check any earlier than the call that would cross it.
pub trait BlockCipherEncryptor<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
>: Algorithm + Sized
{
    /// Begins a streaming encryption flow, returning the generated init data (e.g. IV).
    /// Sources randomness from the library's default OS-backed RNG.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError>;
    /// As [`BlockCipherEncryptor::do_encrypt_init`], but sources randomness from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError>;
    /// The implementor hook: encrypts consecutive whole blocks in place. A sequence of calls is
    /// equivalent to one call over the concatenation.
    ///
    /// This is the only method an implementor writes besides the two `_init` constructors; the
    /// block shape is what guarantees it never sees a partial block. It takes a slice rather than
    /// a `[[u8; BLOCK_LEN]; N]` array because every whole number of blocks is valid, so there is
    /// no length invariant for a const parameter to carry, and because how to batch the blocks --
    /// singly, in pairs, in fours -- is the mode's decision, not the caller's: a mode whose
    /// permutation processes several blocks at once (CBC decryption, CTR) chunks the slice itself.
    /// Callers should normally use the flat [`BlockCipherEncryptor::do_encrypt`] instead.
    fn do_encrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<(), SymmetricCipherError>;

    /// Streaming: encrypts `LEN` bytes, a whole number of blocks, in place. A sequence of calls
    /// is equivalent to one call over the concatenation.
    ///
    /// `LEN % BLOCK_LEN == 0` is checked **at compile time**; see the trait docs. The whole buffer
    /// then goes to [`BlockCipherEncryptor::do_encrypt_blocks`] in one call.
    fn do_encrypt<const LEN: usize>(
        &mut self,
        data: &mut [u8; LEN],
    ) -> Result<(), SymmetricCipherError> {
        const {
            assert!(
                LEN.is_multiple_of(BLOCK_LEN),
                "length must be a whole number of BLOCK_LEN-byte blocks"
            )
        };
        // The remainder is provably empty (asserted above) and ignored.
        let (blocks, _) = data.as_chunks_mut::<BLOCK_LEN>();
        self.do_encrypt_blocks(blocks)
    }

    /// One-shot: encrypts `LEN` bytes in place under a fresh init, and returns the generated init
    /// data. `LEN % BLOCK_LEN == 0` is checked **at compile time**; see the trait docs.
    fn encrypt<const LEN: usize>(
        key: &KeyMaterial<KEY_LEN>,
        data: &mut [u8; LEN],
    ) -> Result<[u8; INIT_DATA_LEN], SymmetricCipherError> {
        let (mut enc, init_data) = Self::do_encrypt_init(key)?;
        enc.do_encrypt(data)?;
        Ok(init_data)
    }
    /// As [`BlockCipherEncryptor::encrypt`], but sources randomness from the provided RNG.
    fn encrypt_rng<const LEN: usize>(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        data: &mut [u8; LEN],
    ) -> Result<[u8; INIT_DATA_LEN], SymmetricCipherError> {
        let (mut enc, init_data) = Self::do_encrypt_init_rng(key, rng)?;
        enc.do_encrypt(data)?;
        Ok(init_data)
    }
}

/// A keyed block permutation: the `CIPH_K` / `CIPH^-1_K` of NIST SP 800-38A Sec 5.1.
///
/// This is the raw primitive a mode of operation is built on, not something to encrypt data with.
/// It transforms exactly one block, so applying it directly to data is ECB (Sec 6.1), which is not
/// confidential -- the trait is named for the mode it *is* when used that way, as a reminder. [`BlockCipherEncryptor`] and [`BlockCipherDecryptor`] are the *mode* traits --
/// they carry initialization data and chaining state; this one carries only a key schedule.
///
/// Implementors are expected to hold that key schedule in a zeroize-on-drop wrapper
/// (`bouncycastle_utils::secret::Secret`), so it is scrubbed when the value is dropped.
///
/// # Why the block methods are infallible
///
/// Every length here is fixed by a type, and a constructed value is always ready to use, so there
/// is nothing a caller can get wrong once [`ElectronicCodeBook::new`] has returned. Only `new` can
/// fail, and only because of the key.
pub trait ElectronicCodeBook<const KEY_LEN: usize, const BLOCK_LEN: usize>:
    Algorithm + Sized
{
    /// Expands the key.
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError>;

    /// The forward cipher function, in place.
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// The inverse cipher function, in place.
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// The forward cipher function on two *independent* blocks, in place.
    ///
    /// Provided as two [`ElectronicCodeBook::encrypt_block`] calls. Bit-sliced implementations
    /// override it, because a pair of blocks is their natural unit of work and costs barely more
    /// than one; see `bouncycastle-aes`.
    ///
    /// Overrides must be indistinguishable from the default, including the order of the two
    /// results. `TestFrameworkElectronicCodeBook` pins that.
    ///
    /// Modes whose structure is parallel -- CBC decryption, CFB decryption, CTR -- should prefer
    /// this. CBC and CFB *encryption* cannot use it: each input block depends on the previous
    /// output.
    fn encrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        let [a, b] = blocks;
        self.encrypt_block(a);
        self.encrypt_block(b);
    }

    /// The inverse cipher function on two *independent* blocks, in place.
    /// See [`ElectronicCodeBook::encrypt_2blocks`].
    fn decrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        let [a, b] = blocks;
        self.decrypt_block(a);
        self.decrypt_block(b);
    }

    /// The forward cipher function on four *independent* blocks, in place.
    ///
    /// Provided as two [`ElectronicCodeBook::encrypt_2blocks`] calls, so an implementation that
    /// overrides only the pair form gets its benefit here too. An engine whose natural unit is
    /// larger than a pair overrides this directly: a bit-sliced engine whose S-box circuit
    /// substitutes four blocks per pass runs the four as one full pass rather than two half-empty
    /// pair calls. Four is the unit because it is the widest any engine in this library fills:
    /// AES fills a pair, and the `u16`- and `u32`-plane engines (SM4, Camellia, ARIA) fill four.
    ///
    /// Overrides must be indistinguishable from the default, including the order of the four
    /// results. `TestFrameworkElectronicCodeBook` pins that.
    ///
    /// Modes with parallel structure chunk their data into fours first, then pairs, then single
    /// blocks; see CBC decryption in `bouncycastle-modes`.
    fn encrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]) {
        // Four is a multiple of two, so the remainder is empty.
        let (pairs, _) = blocks.as_mut_slice().as_chunks_mut::<2>();
        for pair in pairs {
            self.encrypt_2blocks(pair);
        }
    }

    /// The inverse cipher function on four *independent* blocks, in place.
    /// See [`ElectronicCodeBook::encrypt_4blocks`].
    fn decrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]) {
        // Four is a multiple of two, so the remainder is empty.
        let (pairs, _) = blocks.as_mut_slice().as_chunks_mut::<2>();
        for pair in pairs {
            self.decrypt_2blocks(pair);
        }
    }
}

/// A hash function is a cryptographic primitive that takes an input of any length and produces a fixed-size output.
/// Formally: `H: {0,1}^* -> {0,1}^n`.
/// A cryptographic hash function will typically satisfy several security properties, including:
/// * Collision resistance: finding two inputs that yield the same output is computationally difficult.
/// * Preimage resistance: from a given output, finding an input that generates it is computationally difficult.
/// * Second preimage resistance: given an input, finding another input that yields the same output is computationally difficult.
pub trait Hash: Algorithm + Default {
    /// The size of the internal block in bits -- needed by functions such as HMAC to compute security parameters.
    fn block_bitlen(&self) -> usize;

    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// A static one-shot API that hashes the provided data.
    /// `data` can be of any length, including zero bytes.
    fn hash(self, data: &[u8]) -> Vec<u8>;

    /// A static one-shot API that hashes the provided data into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    /// The entire output buffer is zeroized before the hash output is written.
    /// The return value is the number of bytes written.
    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize;

    /// Provide a chunk of data to be absorbed into the hashes.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    fn do_update(&mut self, data: &[u8]);

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    fn do_final(self) -> Vec<u8>;

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    ///
    /// If the provided buffer is smaller than the hash's output length, the output will be truncated.
    /// If the provided buffer is larger than the hash's output length, the output  will be placed in
    /// the first [`Hash::output_len`] bytes.
    /// The entire output buffer is zeroized before the hash output is written, so any bytes past
    /// [`Hash::output_len`] will be 0.
    ///
    /// The output byte is zeroized before the result is written.
    /// The return value is the number of bytes written.
    fn do_final_out(self, output: &mut [u8]) -> usize;

    /// The same as [`Hash::do_final`], but allows for supplying a partial byte as the last input.
    ///
    /// The partial byte is taken as it arrives in the final octet of an ASN.1 BIT STRING
    /// (X.690 s. 8.6.2.1: the bits are placed "commencing with the leading bit ... in bits 8 to 1"):
    /// the `num_bits` message bits are the most significant bits of `partial_byte`, leading bit first,
    /// and the low `8 - num_bits` bits (the BIT STRING's "unused bits", X.690 s. 8.6.2.2) are ignored.
    /// So for a BIT STRING whose initial octet is `unused` (1..=7), pass its final content octet with
    /// `num_bits = 8 - unused`. The convention is the same for every hash family in this library;
    /// implementations whose native bit order differs (SHA-3, which absorbs a byte LSB-first per
    /// FIPS 202 Appendix B.1) convert internally.
    ///
    /// Note on test vectors: the NIST CAVP SHAVS (SHA-2) bit-oriented files pack trailing bits
    /// left-justified and can be passed here directly; the SHA3VS files use the FIPS 202 B.1 packing
    /// (first bit in the LSB) and must be bit-reversed (`u8::reverse_bits`) first.
    ///
    /// 0 is a valid value and means the message ends on a byte boundary (equivalent to [`Hash::do_final`]).
    /// `num_bits` must be in `0..=7`; larger values return [`HashError::InvalidLength`].
    fn do_final_partial_bits(self, partial_byte: u8, num_bits: usize)
    -> Result<Vec<u8>, HashError>;

    /// The same as [`Hash::do_final_partial_bits`], but takes the output buffer as an argument.
    /// The output byte is zeroized before the result is written.
    /// The return value is the number of bytes written.
    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// Standard parameters for a hash function.
pub trait HashAlgParams: Algorithm {
    /// The fixed output length of the hash function.
    const OUTPUT_LEN: usize;
    /// The internal block length of the hash function, which is often used as a meta-parameter for
    /// determining the security strength of the hash function since this limits the internal
    /// collision resistance of the hash function.
    const BLOCK_LEN: usize;
}

/// A Key Derivation Function (KDF) is a function that takes in one or more input key and some unstructured
/// additional input, and uses them to produces a derived key.
pub trait KDF: Default {
    /// Implementations of this function are capable of deriving an output key from an input key,
    /// assuming that they have been properly initialized.
    ///
    /// # Entropy Conversion rules
    /// Implementations SHOULD act on a KeyMaterial of any [`KeyType`] and will generally
    /// return a KeyMaterial of the same type
    ///
    /// ex.:
    ///
    ///   * [`KeyType::Unknown`] -> [`KeyType::Unknown`])
    ///   * [`KeyType::CryptographicRandom`] -> [`KeyType::CryptographicRandom`])
    ///   * [`KeyType::SymmetricCipherKey`] -> [`KeyType::SymmetricCipherKey`])
    ///
    /// If provided with an input key, even if it is [`KeyType::CryptographicRandom`], but that
    /// contains less key material than the internal block size of the KDF, then the KDF
    /// will not be considered properly seeded, and the output [`KeyMaterial`] will be set to
    /// [`KeyType::Unknown`] -- for example, seeding SHA3-256 with a [`KeyMaterial`] containing
    /// only 128 bits of key material.
    ///
    /// An implementation can, and in most cases SHOULD, return a [`HashError`] if provided
    /// with a [`KeyMaterial`] of type [`KeyType::Zeroized`].
    ///
    /// # Additional Input
    /// The `additional_input` parameter is used in deriving the key, but is not credited with any entropy,
    /// and therefore does not affect the type of the output [`KeyMaterial`].
    /// This corresponds directly to `FixedInfo` as defined in NIST SP 800-56C.
    /// The `additional_input` parameter can be empty by passing in `&[0u8; 0]`.
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError>;

    /// Same as [`KDF::derive_key`], but fills the provided output [`KeyMaterial`].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterward
    /// using [`KeyMaterialTrait::set_key_len`].
    fn derive_key_out(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError>;

    /// Meant to be used for hybrid key establishment schemes or other spit-key scenarios where multiple
    /// keys need to be combined into a single key of the same length.
    ///
    /// This function can also be used to mix a KeyMaterial of low entropy with one of full entropy to
    /// produce a new full entropy key. For the purposes of determining whether enough input key material
    /// was provided, the lengths of all full-entropy input keys are added together.
    ///
    /// Implementations that are not safe to be used as a split-key PRF MAY still implement this function
    /// and return a result, but SHOULD set the entropy level of the returned key appropriately; for example
    /// a KDF that is only full-entropy when keyed in the first input SHOULD return a full entropy key
    /// only if the first input is full entropy.
    ///
    /// Implementations can, and in most cases SHOULD, return a [`KeyMaterial`] of the same type as the
    /// strongest key, and SHOULD throw a [`HashError`] if all input keys are zeroized.
    /// For example output a [`KeyType::CryptographicRandom`] key whenever any one of
    /// the input keys is a [`KeyType::CryptographicRandom`] key.
    /// As another example, combining a [`KeyType::Unknown`] key with a [`KeyType::MACKey`] key
    /// should return a [`KeyType::MACKey`].
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError>;

    /// Same as [`KDF::derive_key`], but fills the provided output [`KeyMaterial`].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterward
    /// by using [`KeyMaterialTrait::set_key_len`].
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// A Key Encapsulation Mechanism (KEM) is defined as a set of three operations:
/// key generation, encapsulation, and decapsulation.
///
/// This trait represents the decapsulation operation performed by the holder of the private key.
/// Encapsulation operations are performed by the corresponding [`KEMEncapsulator`] trait, and key
/// generation is provided as an inherent associated function directly on the algorithm struct.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the encapsulation and decapsulation implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new ciphertexts
/// can no longer be created, but existing ciphertexts can still be decapsulated. Splitting the traits
/// makes this policy easier to enforce.
///
/// The arrays used to encode private keys, ciphertexts, and shared secrets are statically-sized
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a KEM algorithm that does not have fixed sizes for the encodings of these objects.
pub trait KEMDecapsulator<
    SK: KEMPrivateKey<SK_LEN>,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>: Sized
{
    /// Performs a decapsulation of the given ciphertext.
    /// Returns the derived shared secret.
    fn decaps(sk: &SK, ct: &[u8]) -> Result<KeyMaterial<SS_LEN>, KEMError>;
}

/// A Key Encapsulation Mechanism (KEM) is defined as a set of three operations:
/// key generation, encapsulation, and decapsulation.
///
/// This trait represents the encapsulation operation performed by the holder of the public key.
/// Decapsulation operations are performed by the corresponding [`KEMDecapsulator`] trait, and key
/// generation is provided as an inherent associated function directly on the algorithm struct.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the encapsulation and decapsulation implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new ciphertexts
/// can no longer be created, but existing ciphertexts can still be decapsulated. Splitting the traits
/// makes this policy easier to enforce.
///
/// The arrays used to encode public keys, ciphertexts, and shared secrets are statically-sized
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a KEM algorithm that does not have fixed sizes for the encodings of these objects.
pub trait KEMEncapsulator<
    PK: KEMPublicKey<PK_LEN>,
    const PK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>: Sized
{
    /// Performs an encapsulation against the given public key.
    /// Sources randomness from the library's default OS-backed RNG.
    /// Returns the ciphertext and derived shared secret.
    fn encaps(pk: &PK) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError>;
    /// Performs an encapsulation against the given public key.
    /// Sources randomness from the provided RNG.
    /// Returns the ciphertext and derived shared secret.
    fn encaps_rng(
        pk: &PK,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError>;
}

// todo: could the public and private key types impl Into<T: AsRef<[u8]>> and From<T: AsRef<[u8]>>
//       that automatically call the encode and from_bytes() ?

/// A private key for a KEM algorithm, often denoted "sk" (for "secret key").
pub trait KEMPrivateKey<const SK_LEN: usize>: PartialEq + Eq + Clone + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; SK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError>;
}

/// A public key for a KEM algorithm, often denoted "pk".
pub trait KEMPublicKey<const PK_LEN: usize>:
    PartialEq + Eq + Clone + Debug + Display + Sized
{
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; PK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError>;
}

/// A Message Authentication Code algorithm is a keyed hash function that behaves somewhat like a symmetric signature function.
/// A MAC algorithm takes in a key and some data, and produces a MAC (message authentication code) that
/// can be used to verify the integrity of data.
///
/// This trait provides one-shot functions [`MAC::mac`], [`MAC::mac_out`], and [`MAC::verify`].
/// It also provides streaming functions [`MAC::do_update`], [`MAC::do_final`], [`MAC::do_final_out`],
/// and [`MAC::do_verify_final`].
/// The workflow is that a MAC object is initialized with a key with [`MAC::new`] -- or [`MAC::new_allow_weak_key`] if you
/// need to disable the library's safety mechanism to prevent the use of weak keys -- then data is
/// processed into one or more calls to [`MAC::do_update`],
/// after that the object can either create a MAC with [`MAC::do_final`] or [`MAC::do_final_out`] (which are final functions, and so consume the object),
/// or the object can be used to verify a MAC.
///
/// For varifying an existing MAC, it is functionally equivalent to use the provided [`MAC::verify`] and [`MAC::do_verify_final`]
/// function or to compute a new MAC and compare it to the existing MAC, however the provided verification functions
/// use constant-time comparison to avoid cryptographic timing attacks whereby an attacker could learn
/// the bytes of the MAC value under some conditions. Therefore, it is highly recommended to use the provided verification functions.
///
/// Note that the MAC key is not represented in this trait because it is provided to the MAC algorithm
/// as part of its new functions.
///
/// MACs do not implement Default because they do not have a sensible no-args constructor.
pub trait MAC: Sized {
    /// Create a new MAC instance with the given key.
    ///
    /// This is a common constructor whether creating or verifying a MAC value.
    ///
    /// Key / Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
    ///
    /// # Note about the security strength of the provided key:
    /// If you initialize the MAC with a key that is tagged at a lower [`SecurityStrength`] than the
    /// underlying hash function then [`MAC::new`] will fail with the following error:
    /// ```text
    /// MACError::KeyMaterialError(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC")
    /// ```
    /// There are situations in which it is completely reasonable and secure to provide low-entropy
    /// (and sometimes all-zero) keys / salts; for these cases we have provided [`MAC::new_allow_weak_key`].
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError>;

    /// Create a new HMAC instance with the given key.
    ///
    /// This constructor completely ignores the [`SecurityStrength`] tag on the input key and will "just work".
    /// This should be used if you really do need to use a weak key, such as an all-zero salt,
    /// but use of this constructor is discouraged and you should really be asking yourself why you need it;
    /// in most cases it indicates that your key is not long enough to support the security level of this
    /// HMAC instance, or the key was derived using algorithms at a lower security level, etc.
    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError>;

    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// One-shot API that computes a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Note about the security strength of the provided key:
    /// If the provided key is tagged at a lower [`SecurityStrength`] than the instantiated MAC algorithm,
    /// this will fail with an error:
    /// ```text
    /// MACError::KeyMaterialError(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC")
    /// ```
    fn mac(self, data: &[u8]) -> Vec<u8>;

    /// One-shot API that computes a MAC for the provided data and writes it into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [`MACError::InvalidLength`].
    ///
    /// The entire output buffer is zeroized before the MAC value is written.
    fn mac_out(self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError>;

    /// One-shot API that verifies a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Internally, this will re-compute the MAC value and then compare it to the provided mac value
    /// using constant-time comparison. It is highly encouraged to use this utility function instead of
    /// comparing mac values for equality yourself.
    ///
    /// Returns a bool to indicate successful verification of the provided mac value.
    /// The provided mac value must be an exact match, including length; for example a mac value
    /// which has been truncated, or which contains extra bytes at the end is considered to not be a match
    /// and will return false.
    fn verify(self, data: &[u8], mac: &[u8]) -> bool;

    /// Provide a chunk of data to be absorbed into the MAC.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    fn do_update(&mut self, data: &[u8]);

    /// Finish absorbing input and produce the MAC value.
    fn do_final(self) -> Vec<u8>;

    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [`MACError::InvalidLength`].
    ///
    /// The entire output buffer is zeroized before the MAC value is written.
    fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError>;

    /// Internally, this will re-compute the MAC value and then compare it to the provided mac value
    /// using constant-time comparison. It is highly encouraged to use this utility function instead of
    /// comparing mac values for equality yourself.
    ///
    /// Returns a bool to indicate successful verification of the provided mac value.
    /// The provided mac value must be an exact match, including length; for example a mac value
    /// which has been truncated, or which contains extra bytes at the end is considered to not be a match
    /// and will return false.
    fn do_verify_final(self, mac: &[u8]) -> bool;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// A block padding scheme, used to extend arbitrary-length data to a whole number of blocks so that it
/// can be processed by a [`BlockCipherEncryptor`]. Implementations are pure functions of the block
/// contents: no key, no state.
///
/// Only the final, partial block of a message is ever padded; the padding layer sitting between the
/// caller and the block cipher is responsible for routing whole blocks straight through.
pub trait Padding<const BLOCK_LEN: usize> {
    /// Whether the scheme appends a whole block of padding to data that is already a whole number
    /// of blocks. `true` for a scheme like PKCS7, which must always add at least one byte so that
    /// unpadding is unambiguous; a caller then finishes an aligned message with `pad(block, 0)`.
    /// `false` for a scheme that never adds bytes (`NoPadding`): an aligned message is finished with
    /// no final block, and `pad` is called only for a partial one -- where such a scheme errors.
    const ALWAYS_PADS: bool;
    /// Pads `block` in place: bytes `0..data_len` are data and are left untouched, bytes
    /// `data_len..BLOCK_LEN` are overwritten with padding. `data_len` must be less than `BLOCK_LEN`
    /// (a full block of data requires a whole additional block of padding, which the caller supplies
    /// as `data_len = 0` -- only when [`ALWAYS_PADS`](Self::ALWAYS_PADS) is `true`).
    ///
    /// # Errors
    /// [`PaddingError::DataLengthTooLong`] if `data_len >= BLOCK_LEN`;
    /// [`PaddingError::PaddingNotPermitted`] from a scheme that adds no bytes and was asked to.
    fn pad(block: &mut [u8; BLOCK_LEN], data_len: usize) -> Result<(), PaddingError>;
    /// Returns the number of data bytes in a padded `block`, or [`PaddingError::InvalidPadding`].
    /// Implementations must run in constant time with respect to the block contents, so that a
    /// decryptor built on them does not leak a padding oracle.
    fn unpad(block: &[u8; BLOCK_LEN]) -> Result<usize, PaddingError>;
}

/// Pre-Hashed Signature Verifier is an extension to [`SignatureVerifier`] that adds functionality specific to signature
/// primatives that can operate on a pre-hashed message instead of the full message.
pub trait PHSignatureVerifier<
    PK: SignaturePublicKey<PK_LEN>,
    const PK_LEN: usize,
    const SIG_LEN: usize,
    const PH_LEN: usize,
>: SignatureVerifier<PK, PK_LEN, SIG_LEN>
{
    /// On success, returns Ok(())
    /// On failure, returns Err([`SignatureError::SignatureVerificationFailed`]); may also return other types of [`SignatureError`] as appropriate (such as for invalid-length inputs).
    fn verify_ph(
        pk: &PK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError>;
}

/// Pre-Hashed Signer is an extension to [`Signer`] that adds functionality specific to signature
/// primatives that can operate on a pre-hashed message instead of the full message.
pub trait PHSigner<
    PK: SignaturePublicKey<PK_LEN>,
    SK: SignaturePrivateKey<SK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    const PH_LEN: usize,
>: Signer<SK, SK_LEN, SIG_LEN>
{
    /// Produce a signature for the provided pre-hashed message and context.
    ///
    /// `ctx` accepts a zero-length byte array.
    ///
    /// A note about the `ctx` context parameter:
    /// This is a newer addition to cryptographic signature primitives. It allows for binding the
    /// signature to some external property of the application so that a signature will fail to validate
    /// if removed from its intended context.
    /// This is particularly useful at preventing content confusion attacks between data formats that
    /// have very similar data structures, for example S/MIME emails, signed PDFs, and signed executables
    /// that all use the Cryptographic Message Syntax (CMS) data format, or multiple data objects that
    /// all use the JWS data format.
    /// To be properly effective, the ctx value must not be under the control of the attacker, which generally
    /// means that it needs to be a value that is never transmitted over the wire, but rather is something
    /// known to the application by context.
    /// For example, "email" vs "pdf" would be a good choice since the application should know what it is
    /// attempting to sign or verify.
    /// The `ctx` param can also be used to bind the signed content to a transaction ID or a username,
    /// but care should be taken to ensure that an attacker attempting a
    /// content confusion attack not also cause the signed / verifier to use an incorrect transaction ID or username.
    ///
    /// Not all signature primitives will support a context value, so you may need to consult the
    /// documentation for the underlying primitive for how it handles a ctx in that case, for example, it
    /// might throw an error, ignore the provided ctx value, or append the ctx to the msg in a non-standard way.
    fn sign_ph(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    /// The entire output buffer is zeroized before the signature is written.
    fn sign_ph_out(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
}

/// An interface for random number generation.
/// This interface is meant to be simpler and more ergonomic than the interfaces provided by the
/// `rng` crate, but that one should
/// be used by applications that intend to submit to FIPS certification as it more closely aligns with the
/// requirements of SP 800-90A.
/// Note: this interface produces bytes. If you want a [`KeyMaterialTrait`], then use [`KeyMaterial::from_rng`].
///
/// Implementors are expected to also implement [`Default`] (default-construction should produce a
/// securely OS-seeded instance), but this is intentionally *not* a supertrait bound: requiring
/// `Default` would make `RNG` not dyn-compatible, and `&mut dyn RNG` is needed so RNG instances
/// can be handed around as trait objects.
pub trait RNG {
    // TODO: add back once we figure out streaming interaction with entropy sources.
    // fn add_seed_bytes(&mut self, additional_seed: &[u8]) -> Result<(), RNGError>;

    /// Provide additional key material to be mixed in to the existing RNG instance.
    /// The exact behaviour will be implementation-specific, but this is intended for injecting
    /// additional entropy, not as the primary method of seeding the RNG.
    fn add_seed_keymaterial(
        &mut self,
        additional_seed: &dyn KeyMaterialTrait,
    ) -> Result<(), RNGError>;
    /// Returns the next random 32-bit integer.
    fn next_int(&mut self) -> Result<u32, RNGError>;

    /// Returns the number of requested bytes.
    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError>;

    /// Returns the number of bytes written.
    /// The entire output buffer is zeroized before the random bytes are written.
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError>;

    /// Fill the provided [`KeyMaterial`] with random bytes.
    fn fill_keymaterial_out(&mut self, out: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError>;

    /// Returns the Security Strength of this RNG.
    // todo: we should do a refactor to make [Algorithm] be a `security_strength()` function instead of constant,
    //      then have `RNG: Algorithm`, then delete this function.
    fn security_strength(&self) -> SecurityStrength;
}

/// A general indicator used across the library for marking the security level of a cryptographic primitive,
/// and for tracking the security level of the algorithms that interacted with a given piece of data.
/// For example, if a KDF at the 128-bit security strength is used to produce a 512-bit key, that key
/// will also be tagged as having a 128-bit security strength.
///
/// Some functions across the library may reject or behave differently based on the security strength
/// of the inputs they are given. For example a `keygen_from_seed()` may reject a seed taged at a lower
/// security strength than the one required by the algorithm, or it may proceed, but lower its own
/// advertised security strength accordingly -- each cryptographic primitive may have additional detail.
// Dev note: The explicit `#[repr(u8)]` discriminants are the stable on-the-wire encoding used by
// `SerializableState` implementations (see the corresponding `TryFrom<u8>` impl below).
// If additional strength levels are added in the future, they can be placed into the enum in
// any order, but should use currently unassigned values (unless you're doing this on a MAJOR or MINOR
// release as a breaking change).
#[derive(Eq, PartialEq, PartialOrd, Clone, Copy, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum SecurityStrength {
    ///
    None = 0,
    ///
    _112bit = 1,
    ///
    _128bit = 2,
    ///
    _192bit = 3,
    ///
    _256bit = 4,
}

impl TryFrom<u8> for SecurityStrength {
    type Error = SuspendableError;

    /// Inverse of `self as u8`; rejects unrecognized discriminants with [`SuspendableError::InvalidData`].
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::None,
            1 => Self::_112bit,
            2 => Self::_128bit,
            3 => Self::_192bit,
            4 => Self::_256bit,
            _ => return Err(SuspendableError::InvalidData),
        })
    }
}

impl SecurityStrength {
    /// Rounds down to the closest supported security strength.
    /// For example, 120-bits is rounded down to 112-bit.
    pub fn from_bits(bits: usize) -> Self {
        if bits < 112 {
            Self::None
        } else if bits < 128 {
            Self::_112bit
        } else if bits < 192 {
            Self::_128bit
        } else if bits < 256 {
            Self::_192bit
        } else {
            Self::_256bit
        }
    }

    /// Rounds down to the closest supported security strength.
    /// For example, 15 bytes (120-bits) is rounded down to 112-bit.
    pub fn from_bytes(bytes: usize) -> Self {
        Self::from_bits(bytes * 8)
    }

    /// Outputs the security strength in bits for easier computation.
    pub fn as_int(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::_112bit => 112,
            Self::_128bit => 128,
            Self::_192bit => 192,
            Self::_256bit => 256,
        }
    }
}

// todo: could the public and private key types impl Into<T: AsRef<[u8]>> and From<T: AsRef<[u8]>>
// todo: that automatically call the encode and from_bytes() ?

/// A private key for a signature algorithm, often denoted "sk" (for "secret key").
pub trait SignaturePrivateKey<const SK_LEN: usize>: PartialEq + Eq + Clone + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; SK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;
}

/// A public key for a signature algorithm, often denoted "pk".
pub trait SignaturePublicKey<const PK_LEN: usize>:
    PartialEq + Eq + Clone + Debug + Display + Sized
{
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; PK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;
}

/// A digital signature algorithm is defined as a set of three operations:
/// key generation, signing, and verification.
///
/// This trait represents the verification operations performed by the holder of the verification public key.
/// Keygen and signing operations are performed by the corresponding [`Signer`] trait.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the signature generation and verification implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new signatures
/// can no longer be created, but existing signatures can still be verified. Splitting the traits
/// makes this policy easier to enforce.
///
/// Here we statically-size the arrays used to encode public keys, private keys, and signature values
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a signature algorithm that do not have fixed sizes for the encodings of these objects.
pub trait SignatureVerifier<
    PK: SignaturePublicKey<PK_LEN>,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>: Sized
{
    /// On success, returns Ok(())
    /// On failure, returns Err([`SignatureError::SignatureVerificationFailed`]); may also return other types of [`SignatureError`] as appropriate (such as for invalid-length inputs).
    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError>;

    /// streaming verification API
    fn verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError>;

    // todo: make this a AsRef<[u8]> ?
    /// Update the verifier with the next chunk of data.
    /// This can be called multiple times.
    fn verify_update(&mut self, msg_chunk: &[u8]);

    /// On success, returns Ok(())
    /// On failure, returns Err([`SignatureError::SignatureVerificationFailed`]); may also return other types of [`SignatureError`] as appropriate (such as for invalid-length inputs).
    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError>;
}

/// A digital signature algorithm is defined as a set of three operations:
/// key generation, signing, and verification.
///
/// This trait represents the operations performed by the holder of the signing private key:
/// which include signing and key generation. Verification operations are performed by the corresponding
/// [`SignatureVerifier`] trait.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the signature generation and verification implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new signatures
/// can no longer be created, but existing signatures can still be verified. Splitting the traits
/// makes this policy easier to enforce.
///
/// This high-level trait defines the operations over a generic signature algorithm that is assumed
/// to source all its randomness from bouncycastle's default os-backed RNG.
/// The underlying signature primitives will expose APIs that allow for specifying a specific RNG
/// or deterministic seed values.
///
/// The arrays used to encode public keys, private keys, and signature values are statically-sized
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a signature algorithm that do not have fixed sizes for the encodings of these objects.
pub trait Signer<SK: SignaturePrivateKey<SK_LEN>, const SK_LEN: usize, const SIG_LEN: usize>:
    Sized
{
    /// Produce a signature for the provided message and context.
    /// Both the `msg` and `ctx` accept zero-length byte arrays.
    ///
    /// A note about the `ctx` context parameter:
    /// This is a newer addition to cryptographic signature primitives. It allows for binding the
    /// signature to some external property of the application so that a signature will fail to validate
    /// if removed from its intended context.
    /// This is particularly useful at preventing content confusion attacks between data formats that
    /// have very similar data structures, for example S/MIME emails, signed PDFs, and signed executables
    /// that all use the Cryptographic Message Syntax (CMS) data format, or multiple data objects that
    /// all use the JWS data format.
    /// To be properly effective, the ctx value must not be under the control of the attacker, which generally
    /// means that it needs to be a value that is never transmitted over the wire, but rather is something
    /// known to the application by context.
    /// For example, "email" vs "pdf" would be a good choice since the application should know what it is
    /// attempting to sign or verify.
    /// The `ctx` param can also be used to bind the signed content to a transaction ID or a username,
    /// but care should be taken to ensure that an attacker attempting a
    /// content confusion attack not also cause the signed / verifier to use an incorrect transaction ID or username.
    ///
    /// Not all signature primitives will support a context value, so you may need to consult the
    /// documentation for the underlying primitive for how it handles a ctx in that case, for example, it
    /// might throw an error, ignore the provided ctx value, or append the ctx to the msg in a non-standard way.
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<[u8; SIG_LEN], SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    /// The entire output buffer is zeroized before the signature is written.
    fn sign_out(
        sk: &SK,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;

    /* streaming signing API */
    /// Initialize a signer for streaming mode with the provided private key.
    fn sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError>;

    // todo: make this a AsRef<[u8]> ?
    /// Update the signer with the next chunk of data.
    /// This can be called multiple times.
    fn sign_update(&mut self, msg_chunk: &[u8]);

    /// Complete the signing operation. Consumes self.
    fn sign_final(self) -> Result<[u8; SIG_LEN], SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    /// The entire output buffer is zeroized before the signature is written.
    fn sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError>;
}

/// The decryption half of a stream cipher's streaming API; see [`StreamCipherEncryptor`], whose
/// notes on in-place operation, arbitrary lengths, the `Result` and the free
/// [`SimpleCipherDecryptor`] impl all apply here too.
pub trait StreamCipherDecryptor<const KEY_LEN: usize, const INIT_DATA_LEN: usize>:
    Algorithm + Sized
{
    /// Begins a streaming decryption flow from the init data returned by
    /// [`StreamCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError>;

    /// Streaming: decrypts `data`, of any length, in place. A sequence of calls is equivalent to
    /// one call over the concatenation, whatever the chunking, exactly as for
    /// [`StreamCipherEncryptor::do_encrypt`].
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError>;

    /// One-shot: decrypts `data` in place from the given init data.
    fn decrypt(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
        data: &mut [u8],
    ) -> Result<(), SymmetricCipherError> {
        Self::do_decrypt_init(key, init_data)?.do_decrypt(data)
    }
}

/// The encryption half of a stream cipher's streaming API. This is the stream-cipher counterpart
/// of [`BlockCipherEncryptor`]: the same in-place, init-data-generating shape, but with no block
/// length. A stream cipher applies its keystream byte by byte, so the data methods take a
/// `&mut [u8]` of any length, and there is no alignment to check, no padding layer to reach for,
/// and no finalization step.
///
/// Encryption and decryption are separate traits for the same reasons as
/// [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`]: the direction is encoded in the type, and a
/// policy can permit decryption of an algorithm while forbidding new encryptions.
///
/// # You also get the arbitrary-length API for free
///
/// Every implementor is automatically a [`SimpleCipherEncryptor`] with `FINAL_LEN = 0`, by a
/// blanket impl written in terms of [`do_encrypt`](Self::do_encrypt). So an implementor writes the
/// three methods below and a caller may still use `encrypt_out`, `do_update_out` and the rest --
/// the separate-output view that the padding adapters present -- and hold a stream mode through the
/// same trait as a padded block mode.
///
/// Init data (a nonce or IV) is generated securely by the implementation in the constructor and
/// returned for transmission alongside the ciphertext; there is no API for the user to supply it,
/// for the same reason as in [`BlockCipherEncryptor`]. A stream cipher is only as safe as its
/// nonce is unique, so if you require a caller-chosen nonce, see the documentation for the
/// underlying implementation.
///
/// # Everything is in place
///
/// Every data method here transforms its buffer in place: the plaintext goes in, the ciphertext
/// comes out in the same bytes. A stream cipher never changes the length of its data, so a
/// separate output buffer would only ever be a copy, and a copy of plaintext is one more thing to
/// scrub. Callers that need to keep the plaintext copy it first.
///
/// # Any length, as a slice
///
/// The data is a `&mut [u8]` rather than a `&[u8; LEN]` because every length is valid, including
/// zero, so there is no invariant for a const parameter to carry and nothing for a compile-time
/// check to check. How the keystream is produced internally -- in 64-byte blocks, in words, a bit
/// at a time -- is the cipher's business; it buffers any unused keystream between calls so that
/// the caller's chunking is never visible in the output.
///
/// # Why the data methods still return `Result`
///
/// Nothing about the buffer can go wrong, and a constructed value is always ready to use. The
/// `Result` is for the per-initialization data limit most stream ciphers have: a counter-driven
/// keystream must refuse to run past the point where its counter would wrap and the keystream
/// repeat, and a streaming API cannot check that any earlier than the call that would cross it.
pub trait StreamCipherEncryptor<const KEY_LEN: usize, const INIT_DATA_LEN: usize>:
    Algorithm + Sized
{
    /// Begins a streaming encryption flow, returning the generated init data (e.g. nonce).
    /// Sources randomness from the library's default OS-backed RNG.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError>;
    /// As [`StreamCipherEncryptor::do_encrypt_init`], but sources randomness from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError>;

    /// Streaming: encrypts `data`, of any length, in place. A sequence of calls is equivalent to
    /// one call over the concatenation, whatever the chunking.
    ///
    /// This is the only method an implementor writes besides the two `_init` constructors.
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError>;

    /// One-shot: encrypts `data` in place under a fresh init, and returns the generated init data.
    fn encrypt(
        key: &KeyMaterial<KEY_LEN>,
        data: &mut [u8],
    ) -> Result<[u8; INIT_DATA_LEN], SymmetricCipherError> {
        let (mut enc, init_data) = Self::do_encrypt_init(key)?;
        enc.do_encrypt(data)?;
        Ok(init_data)
    }
    /// As [`StreamCipherEncryptor::encrypt`], but sources randomness from the provided RNG.
    fn encrypt_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        data: &mut [u8],
    ) -> Result<[u8; INIT_DATA_LEN], SymmetricCipherError> {
        let (mut enc, init_data) = Self::do_encrypt_init_rng(key, rng)?;
        enc.do_encrypt(data)?;
        Ok(init_data)
    }
}

/// Allows a stateful object to suspend its operation by serializing its state into a byte array
///so that it can be resumed later, potentially from a different host.
///
/// This is intended for situations where an object is being used through its streaming API
/// (do_update, do_final) and the operation wants to be paused to a cache, for example while waiting
/// for network IO.
///
/// This is not intended as a mechanism to clone the state of an object since in most cases `.clone()`
/// will be more straightforward.
///
/// The serialized state MAY contain short-term sensitive values such as nonces or IVs,
/// but it MUST NOT include a serialized private key.
/// Keyed algorithms MUST instead impl
/// [`SuspendableKeyed`] which requires the key to be supplied independently at the time of deserialization.
pub trait Suspendable<const SERIALIZED_STATE_LEN: usize>: Sized {
    /// Suspend operation by serializing out the state of the object.
    ///
    /// Note that this consumes `self` to prevent accidentally continuing to use the object after serialization.
    /// If you want to do this intentionally, then you will need to clone the object before serializing it.
    ///
    /// The serialized state MUST include a prefix indicating the version of the library that serialized it.
    fn suspend(self) -> [u8; SERIALIZED_STATE_LEN];

    /// Resume operation from a serialized state.
    ///
    /// Deserializers SHOULD check the version and reject serialized states from incompatible versions
    /// (including rejecting serializations from a future version of the library).
    /// For example, if a given object made a breaking change to its serialization in version 1.2.3, then its
    /// deserializer should reject serialized states from that version or older.
    fn from_suspended(state: [u8; SERIALIZED_STATE_LEN]) -> Result<Self, SuspendableError>;
}

/// Similar to [`Suspendable`] in that it allows a stateful object to suspend its operation by
/// serializing its state into a byte array so that it can be resumed later, potentially from a different host.
///
/// The difference is that this trait is for keyed algorithms -- MACs, symmetric ciphers, signatures, etc --
/// which require a private key in order to resume successfully.
/// For security reasons, the private key is not included in the serialized state
/// and must be provided separately as part of the deserialization process.
pub trait SuspendableKeyed<const SERIALIZED_STATE_LEN: usize>: Sized {
    /// The type of key that must be re-supplied to resume this object.
    type Key: ?Sized;

    /// Suspend operation by serializing out the state of the object.
    ///
    /// Note that this consumes `self` to prevent accidentally continuing to use the object after serialization.
    /// If you want to do this intentionally, then you will need to clone the object before serializing it.
    ///
    /// The serialized state MUST include a prefix indicating the version of the library that serialized it.
    fn suspend(self) -> [u8; SERIALIZED_STATE_LEN];

    /// Resume operation from a serialized state and the key.
    ///
    /// Deserializers SHOULD check the version and reject serialized states from incompatible versions
    /// (including rejecting serializations from a future version of the library).
    /// For example, if a given object made a breaking change to its serialization in version 1.2.3, then its
    /// deserializer should reject serialized states from that version or older.
    fn from_suspended(
        state: [u8; SERIALIZED_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError>;
}

/// The decryption half of a symmetric cipher's arbitrary-length API. See
/// [`SimpleCipherEncryptor`] for the shape of the API and the meaning of `FINAL_LEN`; this is
/// its mirror image, and the two are implemented by paired types.
///
/// Decryption is not the exact mirror of encryption in one respect: the last `FINAL_LEN` bytes a
/// decryptor releases may be only partly data. A padding scheme's final block carries
/// `data_len < BLOCK_LEN` bytes of plaintext and the rest padding, and an authenticated cipher may
/// release nothing at all once it has checked the tag. So [`do_final`](Self::do_final) returns the
/// buffer *and* how much of it is data, and the one-shot length helper is an upper bound rather
/// than an exact count.
///
/// The one-shot [`decrypt_out`](Self::decrypt_out) is provided over the streaming methods, as is
/// the allocating [`decrypt`](Self::decrypt) behind the `std` feature. An implementor writes only
/// [`do_decrypt_init`](Self::do_decrypt_init), [`update_out_len`](Self::update_out_len),
/// [`do_update_out`](Self::do_update_out), [`do_final`](Self::do_final) and
/// [`decrypt_out_max_len`](Self::decrypt_out_max_len).
pub trait SimpleCipherDecryptor<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const FINAL_LEN: usize,
>: Algorithm + Sized
{
    /// Begins a streaming decryption from the init data returned by
    /// [`SimpleCipherEncryptor::do_encrypt_init`].
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError>;

    /// The exact number of bytes the next [`do_update_out`](Self::do_update_out) will write if
    /// given `input_len` more bytes of ciphertext. Depends on what is already buffered.
    fn update_out_len(&self, input_len: usize) -> usize;

    /// Streaming: consumes `ciphertext`, writing every plaintext byte that can be released so far
    /// into `plaintext` and buffering the rest. Returns the number of bytes written, which is
    /// exactly [`update_out_len`](Self::update_out_len) of `ciphertext.len()`.
    ///
    /// A decryptor may have to hold back the tail of what it has seen -- the last block, which
    /// might carry the padding, or the bytes that might be the tag -- so a sequence of calls
    /// releases data later than the corresponding encryptor produced it, but the concatenation of
    /// everything released plus the data part of [`do_final`](Self::do_final) is the plaintext.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `plaintext` is shorter than
    /// [`update_out_len`](Self::update_out_len), carrying the required length. Nothing is
    /// consumed in that case.
    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Finishes the decryption, consuming the decryptor: processes whatever was held back, checks
    /// it -- padding, tag -- and returns the final buffer together with the number of leading
    /// bytes of it that are plaintext. The remainder of the buffer is not data and must not be
    /// used.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if the ciphertext was malformed (empty, or not a
    /// whole number of blocks); [`SymmetricCipherError::PaddingError`] or
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the check fails. In every error case the
    /// caller learns only that decryption failed, not where.
    fn do_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// As [`do_final`](Self::do_final), writing the final buffer into `plaintext`. Returns the
    /// number of leading bytes of it that are data.
    fn do_final_out(self, plaintext: &mut [u8; FINAL_LEN]) -> Result<usize, SymmetricCipherError> {
        let (buffer, data_len) = self.do_final()?;
        *plaintext = buffer;
        Ok(data_len)
    }

    /// An upper bound on the plaintext recovered from `ciphertext_len` bytes of ciphertext, i.e.
    /// the buffer [`decrypt_out`](Self::decrypt_out) requires. Exact for ciphers with no padding;
    /// for a padding scheme the exact length is only known after decryption.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize;

    /// One-shot: decrypts `ciphertext` into `plaintext`, which needs
    /// [`decrypt_out_max_len`](Self::decrypt_out_max_len) bytes. Returns the number of plaintext
    /// bytes written.
    ///
    /// Provided as `do_decrypt_init`, one `do_update_out` and `do_final`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `plaintext` is too short, checked
    /// before any work is done; otherwise whatever the streaming methods return.
    fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = Self::decrypt_out_max_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("plaintext", needed));
        }
        let mut dec = Self::do_decrypt_init(key, init_data)?;
        let written = dec.do_update_out(ciphertext, plaintext)?;
        let (last, data_len) = dec.do_final()?;
        // `decrypt_out_max_len` bounds `written + data_len`, so this fits in `plaintext[..needed]`.
        plaintext[written..written + data_len].copy_from_slice(&last[..data_len]);
        Ok(written + data_len)
    }

    #[cfg(feature = "std")]
    /// One-shot, allocating: as [`decrypt_out`](Self::decrypt_out), returning the plaintext as a
    /// `Vec<u8>` of exactly the recovered length. Only available with the `std` feature.
    fn decrypt(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::decrypt_out_max_len(ciphertext.len())];
        let written = Self::decrypt_out(key, init_data, ciphertext, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }
}

/// The encryption half of a symmetric cipher's arbitrary-length API: streaming `do_update_out` /
/// `do_final`, plus one-shots provided over them.
///
/// This is the layer a caller with *data* uses, as opposed to the block-aligned
/// [`BlockCipherEncryptor`] a mode implements. Its shape is that of the padding adapters in
/// `bouncycastle-padding`, which are its first implementors: an authenticated cipher or a stream
/// cipher fits the same shape, with the tag or nothing in place of the final padded block.
///
/// `FINAL_LEN` is the fixed length of what [`do_final`](Self::do_final) produces after the last
/// byte of plaintext has been consumed: one block for a padding scheme, the tag length for an
/// authenticated cipher, zero for a stream cipher. Everything else about the output length is
/// answered exactly, before the fact, by [`update_out_len`](Self::update_out_len) and
/// [`encrypt_out_len`](Self::encrypt_out_len), so a caller can size buffers without guessing.
///
/// Init data (an IV or nonce) is generated by the constructor and returned, never supplied, for
/// the same reason as in [`BlockCipherEncryptor`]. Everything is `no_std`-friendly except the
/// allocating [`encrypt`](Self::encrypt), which sits behind the `std` feature.
///
/// The one-shots [`encrypt_out`](Self::encrypt_out) and [`encrypt_out_rng`](Self::encrypt_out_rng)
/// are provided over the streaming methods. An implementor writes only the two `_init`
/// constructors, [`update_out_len`](Self::update_out_len), [`do_update_out`](Self::do_update_out),
/// [`do_final`](Self::do_final) and [`encrypt_out_len`](Self::encrypt_out_len).
pub trait SimpleCipherEncryptor<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const FINAL_LEN: usize,
>: Algorithm + Sized
{
    /// Begins a streaming encryption, returning the encryptor and the generated init data (IV or
    /// nonce), which the recipient needs for [`SimpleCipherDecryptor::do_decrypt_init`]. Sources
    /// randomness from the library's default OS-backed RNG.
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError>;

    /// As [`do_encrypt_init`](Self::do_encrypt_init), but sources randomness from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError>;

    /// The exact number of bytes the next [`do_update_out`](Self::do_update_out) will write if
    /// given `input_len` more bytes of plaintext. Depends on what is already buffered.
    fn update_out_len(&self, input_len: usize) -> usize;

    /// Streaming: consumes `plaintext`, writing every ciphertext byte that can be produced so far
    /// into `ciphertext` and buffering the rest. Returns the number of bytes written, which is
    /// exactly [`update_out_len`](Self::update_out_len) of `plaintext.len()`. A sequence of calls
    /// is equivalent to one call over the concatenation.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `ciphertext` is shorter than
    /// [`update_out_len`](Self::update_out_len), carrying the required length. Nothing is
    /// consumed in that case.
    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Finishes the encryption, consuming the encryptor: pads and encrypts whatever was buffered,
    /// or computes the tag, and returns the final buffer together with the number of leading bytes
    /// of it that are ciphertext -- the last bytes of the message. For most ciphers that is always
    /// `FINAL_LEN` (the padded block, the tag); a padding scheme that adds nothing to aligned data
    /// returns 0 for an aligned message. The remainder of the buffer is not output.
    ///
    /// # Errors
    /// [`SymmetricCipherError::PaddingError`] if the buffered data cannot be finished -- with a
    /// scheme that adds no padding, a message that is not a whole number of blocks.
    fn do_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// As [`do_final`](Self::do_final), writing the final buffer into `ciphertext`. Returns the
    /// number of leading bytes of it that are output.
    fn do_final_out(self, ciphertext: &mut [u8; FINAL_LEN]) -> Result<usize, SymmetricCipherError> {
        let (buffer, out_len) = self.do_final()?;
        *ciphertext = buffer;
        Ok(out_len)
    }

    /// The exact ciphertext length for a `plaintext_len`-byte plaintext that the cipher accepts,
    /// i.e. the buffer [`encrypt_out`](Self::encrypt_out) requires and the number of bytes it
    /// writes. (A length the cipher rejects -- unaligned data under a scheme that adds no padding --
    /// fails in [`do_final`](Self::do_final) instead.)
    fn encrypt_out_len(plaintext_len: usize) -> usize;

    /// One-shot: encrypts `plaintext` into `ciphertext`, which needs
    /// [`encrypt_out_len`](Self::encrypt_out_len) bytes. Returns the generated init data and the
    /// number of bytes written.
    ///
    /// Provided as `do_encrypt_init`, one `do_update_out` and `do_final`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `ciphertext` is too short, checked
    /// before any work is done; otherwise whatever the streaming methods return.
    fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; INIT_DATA_LEN], usize), SymmetricCipherError> {
        let needed = Self::encrypt_out_len(plaintext.len());
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", needed));
        }
        let (mut enc, init_data) = Self::do_encrypt_init(key)?;
        let written = enc.do_update_out(plaintext, ciphertext)?;
        let (last, last_len) = enc.do_final()?;
        // `encrypt_out_len` is exactly `written + last_len`, so this fits in `ciphertext[..needed]`.
        ciphertext[written..written + last_len].copy_from_slice(&last[..last_len]);
        Ok((init_data, written + last_len))
    }

    /// As [`encrypt_out`](Self::encrypt_out), but sources randomness from the provided RNG.
    fn encrypt_out_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; INIT_DATA_LEN], usize), SymmetricCipherError> {
        let needed = Self::encrypt_out_len(plaintext.len());
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", needed));
        }
        let (mut enc, init_data) = Self::do_encrypt_init_rng(key, rng)?;
        let written = enc.do_update_out(plaintext, ciphertext)?;
        let (last, last_len) = enc.do_final()?;
        ciphertext[written..written + last_len].copy_from_slice(&last[..last_len]);
        Ok((init_data, written + last_len))
    }

    #[cfg(feature = "std")]
    /// One-shot, allocating: as [`encrypt_out`](Self::encrypt_out), returning the ciphertext as a
    /// `Vec<u8>`. Only available with the `std` feature.
    fn encrypt(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8],
    ) -> Result<([u8; INIT_DATA_LEN], Vec<u8>), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::encrypt_out_len(plaintext.len())];
        let (init_data, written) = Self::encrypt_out(key, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((init_data, ciphertext))
    }
}

/// Every stream cipher is also a [`SimpleCipherEncryptor`] with `FINAL_LEN = 0`.
///
/// The two traits describe the same operation at different granularities. [`StreamCipherEncryptor`]
/// is the in-place view -- one buffer, transformed where it lies -- and
/// [`SimpleCipherEncryptor`] is the separate-output view that the padding adapters and the AEAD
/// ciphers share. A stream cipher can offer the second in terms of the first, because it changes
/// neither the length of its data nor anything at the end of the message: `update_out_len` is the
/// identity, `encrypt_out_len` is the identity, and `do_final` has nothing to produce, which is
/// exactly what `FINAL_LEN = 0` says.
///
/// The point of the blanket impl is that a caller can hold a CFB, CFB8 or CTR value through the
/// same trait as a padded CBC one, and write code that does not care which mode it was handed. It
/// applies to every present and future implementor, so a new stream mode gets the arbitrary-length
/// API by writing one method.
///
/// Note that both traits then offer `do_encrypt_init` and `do_encrypt_init_rng` with identical
/// signatures. Where both are in scope, a call needs qualifying --
/// `<Cfb<..> as StreamCipherEncryptor<..>>::do_encrypt_init(&key)` -- though either resolves to the
/// same function.
impl<T, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
    SimpleCipherEncryptor<KEY_LEN, INIT_DATA_LEN, 0> for T
where
    T: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
{
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        <T as StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>>::do_encrypt_init(key)
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        <T as StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>>::do_encrypt_init_rng(key, rng)
    }

    /// A stream cipher buffers nothing, so every input byte produces exactly one output byte.
    fn update_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Copies the plaintext into the output buffer and encrypts it there, so the caller's input is
    /// left untouched -- the one thing the in-place [`StreamCipherEncryptor::do_encrypt`] cannot
    /// offer.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `ciphertext` is shorter than
    /// `plaintext`, checked before anything is consumed; otherwise whatever `do_encrypt` returns.
    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "ciphertext",
                plaintext.len(),
            ));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.do_encrypt(out)?;
        Ok(plaintext.len())
    }

    /// Nothing is held back, so there is nothing to finish: an empty buffer, none of it output.
    ///
    /// `cargo mutants` reports the `[]` here as a surviving mutant against `[0; 0]` and `[1; 0]`.
    /// Those are the same value: a zero-length array has no element to differ in, so the three
    /// spellings are indistinguishable and no test can separate them. The mutants that *do* change
    /// behaviour -- returning 1 rather than 0 for the data length -- are caught.
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        Ok(([], 0))
    }

    /// A stream cipher never changes the length of its data.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

/// Every stream cipher is also a [`SimpleCipherDecryptor`] with `FINAL_LEN = 0`. The mirror of
/// the [`StreamCipherEncryptor`] blanket impl above; see it for why this exists.
impl<T, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
    SimpleCipherDecryptor<KEY_LEN, INIT_DATA_LEN, 0> for T
where
    T: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
{
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        <T as StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>>::do_decrypt_init(key, init_data)
    }

    /// A stream cipher holds nothing back, so every input byte can be released immediately.
    fn update_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Copies the ciphertext into the output buffer and decrypts it there, leaving the caller's
    /// input untouched.
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `plaintext` is shorter than
    /// `ciphertext`, checked before anything is consumed; otherwise whatever `do_decrypt` returns.
    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if plaintext.len() < ciphertext.len() {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "plaintext",
                ciphertext.len(),
            ));
        }
        let out = &mut plaintext[..ciphertext.len()];
        out.copy_from_slice(ciphertext);
        self.do_decrypt(out)?;
        Ok(ciphertext.len())
    }

    /// Nothing is held back, and there is no padding or tag to check.
    ///
    /// `cargo mutants` reports the `[]` here as a surviving mutant against `[0; 0]` and `[1; 0]`.
    /// Those are the same value: a zero-length array has no element to differ in, so the three
    /// spellings are indistinguishable and no test can separate them. The mutants that *do* change
    /// behaviour -- returning 1 rather than 0 for the data length -- are caught.
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        Ok(([], 0))
    }

    /// Exact rather than an upper bound: a stream cipher never changes the length of its data.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

/// Extensible Output Functions (XOFs) are similar to hash functions, except that they can produce output of arbitrary length.
/// The naming used for the functions of this trait are borrowed from the SHA3-style sponge constructions that split XOF operation
/// into two phases: an absorb phase in which an arbitrary amount of input is provided to the XOF,
/// and then a squeeze phase in which an arbitrary amount of output is extracted.
/// Once squeezing begins, no more input can be absorbed.
///
/// XOFs are _similar to_ hash functions, but are not hash functions for one technical but important reason:
/// since the amount of output to produce is not provided to the XOF in advance, it cannot be used to
/// diversify the XOF output streams.
/// In other words, the overlapping parts of their outputs will be the same!
/// For example, consider two XOFs that absorb the same input data, one that is squeezed to produce 32 bytes,
/// and the other to produce 1 kb; both outputs will be identical in their first 32 bytes.
/// This could lead to loss of security in a number of ways, for example distinguishing attacks where
/// it is sufficient for the attacker to know that two values came from the same input, even if the
/// attacker cannot learn what that input was. This is attack is often sufficient, for example,
/// to break anonymity-preserving technology.
/// Applications that require the arbitrary-length output of an XOF, but also care about these
/// distinguishing attacks should consider adding a cryptographic salt to diversify the inputs.
///
/// # State and Absorb-after-Squeeze
/// This trait makes the design choice that an XOF consists of an absorb phase followed by a squeeze phase.
/// This means that once the XOF has begun squeezing, attempting to absorb more will return
/// [`HashError::InvalidState`] and leave the object usable for further squeezing.
///
/// Without this restriction, the [`XOF::absorb_last_partial_byte`] API cannot function correctly.
///
/// If Absorb-after-Squeeze becomes necessary to support in the future, then these design choices can be revisited.
pub trait XOF: Default {
    /// A static one-shot API that digests the input data and produces `result_len` bytes of output.
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8>;

    /// A static one-shot API that digests the input data and produces `result_len` bytes of output.
    /// Fills the provided output slice.
    /// The entire output buffer is zeroized before the output is written.
    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize;

    /// Absorb some amount of input.
    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError>;

    /// The same as [`XOF::absorb`], but allows for supplying a partial byte as the last input.
    /// The partial byte is taken as it arrives in the final octet of an ASN.1 BIT STRING
    /// (X.690 s. 8.6.2.1): the `num_bits` message bits are the most significant bits of
    /// `partial_byte`, leading bit first, and the low `8 - num_bits` bits (the BIT STRING's "unused
    /// bits") are ignored. This is the same convention as [`Hash::do_final_partial_bits`]; see there
    /// for the relationship to the FIPS 202 Appendix B.1 bit order and to the NIST test vector files.
    /// 0 is a valid value and means the message ends on a byte boundary (equivalent to [`XOF::absorb`]).
    /// `num_bits` must be in `0..=7`; larger values return [`HashError::InvalidLength`].
    ///
    /// Unlike [`XOF::absorb`], this switches the XOF from Absorbing mode into Squeezing mode because
    /// absorbing more input after absorbing a partial byte is undefined behaviour.
    fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<(), HashError>;

    /// Can be called multiple times.
    fn squeeze(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Can be called multiple times.
    /// Fills the provided output slice.
    /// The entire output buffer is zeroized before the output is written.
    fn squeeze_out(&mut self, output: &mut [u8]) -> usize;

    /// Squeezes a partial byte (`num_bits` in `0..=7`) from the XOF.
    /// The bits are returned as they would be placed in the final octet of an ASN.1 BIT STRING
    /// (X.690 s. 8.6.2.1): in the most significant `num_bits` bits of the returned u8, first output
    /// bit first, with the low `8 - num_bits` "unused" bits zero. This matches the input convention of
    /// [`XOF::absorb_last_partial_byte`]. (FIPS 202 Appendix B.1 orders the bits of an output byte
    /// LSB-first; the implementation converts.)
    /// 0 is a valid value and requests no bits, so the result is `0x00`.
    /// `num_bits` must be in `0..=7`; larger values return [`HashError::InvalidLength`].
    /// This is a final call and consumes self.
    fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError>;

    /// The same as [`XOF::squeeze_partial_byte_final`], but writes into the provided output byte.
    /// The output byte is zeroized before the result is written.
    fn squeeze_partial_byte_final_out(
        self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    // todo: we should do a refactor to make [Algorithm] be a `security_strength()` function instead of constant,
    //      then have `RNG: Algorithm`, then delete this function.
    fn max_security_strength(&self) -> SecurityStrength;
}
