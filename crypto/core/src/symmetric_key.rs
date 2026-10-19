//! Key objects for symmetric ciphers and MACs: how a key is made, and what it can produce.
//!
//! A key object is bound to one algorithm and, for a cipher, one mode -- `AES128Key<GCM>`,
//! `HmacKey<SHA256>` -- and is validated once, when it is made. It holds whatever the construction
//! keeps per key (an expanded schedule, HMAC's two pad states) and hands out one worker per
//! message: an encryptor, a decryptor, a MAC generator or a MAC verifier. The worker traits in
//! [`crate::traits`] then describe only an object that already exists.
//!
//! Two kinds of trait live here:
//!
//! * **Construction**, for keys the process holds: [`FromKeyMaterial`] for a key of exactly
//!   `KEY_LEN` bytes, [`FromAnyKeyMaterial`] for a construction that accepts any byte string.
//!   A key that lives in a hardware token implements neither; it has its own way in.
//! * **Roles**, one trait per direction: [`AeadEncryptionKey`] / [`AeadDecryptionKey`], their
//!   packet forms [`AeadPacketEncryptionKey`] / [`AeadPacketDecryptionKey`] for a mode that must
//!   know the lengths up front, [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] for the
//!   unauthenticated modes that take data of any length (padded CBC, CFB, CFB8, CTR),
//!   [`BlockEncryptionKey`] / [`BlockDecryptionKey`] for the whole-block modes, the ECB pair in
//!   [`crate::hazmat`], and [`MacGenerationKey`] / [`MacVerificationKey`]. A key type
//!   implements the sides it is allowed to use, so a decrypt-only or verify-only key refuses the
//!   other side at compile time. The one-shots are provided methods over `create_*` and the
//!   worker's streaming methods, which [`AeadEncryptWorker`] / [`AeadDecryptWorker`] describe
//!   for the AEAD pair and the cipher traits in [`crate::traits`] for the rest.
//!
//! Which role a cipher key carries is decided by its mode type through the mode traits in
//! [`crate::hazmat`] ([`Mode`], [`AeadEncryptMode`], [`AeadDecryptMode`] and their packet,
//! symmetric, block and ECB forms); the permutation crate connects the two with a forwarding
//! impl per role. A mode implements exactly one pair, so `key.create_encryptor(..)` on a key
//! bound to it is never ambiguous.
//!
//! ```text
//! let key = AES128Key::<GCM>::generate(&mut rng)?;
//! let (mut enc, nonce) = key.create_encryptor(&mut rng)?;    // Result for the nonce draw only
//! let mut dec = key.create_decryptor(&nonce);                // infallible
//!
//! let key = HmacKey::<SHA256>::generate(&mut rng)?;
//! let mut gen = key.create_generator();                      // infallible, any number of times
//! ```
//!
//! Nothing here instantiates a DRBG for the caller: a method that draws randomness takes
//! `&mut dyn RNG`. The caller holds one RNG across operations.
//!
//! [`Mode`]: crate::hazmat::Mode
//! [`AeadEncryptMode`]: crate::hazmat::AeadEncryptMode
//! [`AeadDecryptMode`]: crate::hazmat::AeadDecryptMode

use crate::errors::{MACError, SymmetricCipherError};
use crate::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
#[cfg(feature = "std")]
use crate::traits::AEADEncryptedTuple;
use crate::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, MAC, RNG, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

/// Construction of a key object from exactly `KEY_LEN` bytes of key material.
///
/// Implemented per concrete key length (`AES128Key<M>` implements `FromKeyMaterial<16>`), because
/// a `KeyMaterial<N>` argument cannot be sized from an associated constant on stable Rust; the
/// fixed-capacity argument is what makes a wrong-length key a compile error.
pub trait FromKeyMaterial<const KEY_LEN: usize>: Sized {
    /// The [`KeyType`] the material must carry: [`KeyType::SymmetricCipherKey`] for a cipher key,
    /// [`KeyType::MACKey`] for a MAC built on a cipher. A mode-bound key takes it from its mode.
    const KEY_TYPE: KeyType;

    /// Validates `key` and does the construction's per-key work (schedule expansion and whatever
    /// the mode derives from it) once.
    ///
    /// # Errors
    /// [`SymmetricCipherError::KeyMaterialError`] if the key is not of type
    /// [`Self::KEY_TYPE`], carries a security strength below the key length, or fails the
    /// algorithm's own key checks.
    fn from_key_material(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError>;

    /// Draws `KEY_LEN` bytes from `rng`, tags them [`Self::KEY_TYPE`] and constructs the key. The
    /// material carries the RNG's security strength, so an RNG instantiated below the key's
    /// strength is refused by [`from_key_material`](Self::from_key_material).
    ///
    /// # Errors
    /// [`SymmetricCipherError::KeyMaterialError`] if the RNG fails or its strength is too low.
    fn generate(rng: &mut dyn RNG) -> Result<Self, SymmetricCipherError> {
        let mut key = KeyMaterial::<KEY_LEN>::from_rng(rng)?;
        key.set_key_type(Self::KEY_TYPE)?;
        Self::from_key_material(&key)
    }
}

/// Construction of a key object from key material of any length: HMAC and KMAC accept any byte
/// string as a key, so [`FromKeyMaterial`] does not fit them.
///
/// This is the only constructor with a weak-key form. A key built on a cipher takes a full-length
/// cipher key through [`FromKeyMaterial`] and the cipher's own policy, with no exemption.
pub trait FromAnyKeyMaterial: Sized {
    /// Checks the key type and that the key's security strength meets the construction's, then
    /// does the construction's per-key work once.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the key type is wrong or the strength is too low.
    fn from_key_material(key: &dyn KeyMaterialTrait) -> Result<Self, MACError>;

    /// As [`from_key_material`](Self::from_key_material) without the strength check, for a
    /// protocol that calls for a weak or all-zero key such as an absent HKDF salt.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the key type is wrong.
    fn from_key_material_allow_weak(key: &dyn KeyMaterialTrait) -> Result<Self, MACError>;

    /// Draws a key of the length the construction recommends from `rng`, tagged
    /// [`KeyType::MACKey`], and constructs the key object from it.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the RNG fails or its strength is below the
    /// construction's.
    fn generate(rng: &mut dyn RNG) -> Result<Self, MACError>;
}

// The lengths the cipher traits carry are const generics on the role traits rather than associated
// constants, because stable Rust can neither pass an associated constant as a const-generic
// argument (the worker bound) nor size an array from one (the returned nonce). `KEY_LEN` is on
// the role traits only while the cipher traits still carry it; it goes when their constructors do.

/// An AEAD encryptor that already exists: the streaming methods of the cipher traits without
/// their constructors, which is all a key's worker needs. A worker produced by a key implements
/// this; the cipher traits' own types implement it by forwarding.
pub trait AeadEncryptWorker<const NONCE_LEN: usize, const TAG_LEN: usize, const FINAL_LEN: usize>:
    Sized
{
    /// Absorbs associated data, which is authenticated but not encrypted, before any payload.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if non-empty after the payload has begun, or the
    /// worker's own refusal of more than it declared.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError>;

    /// The most ciphertext bytes the next `do_encrypt_out` of `input_len` bytes can release.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize;

    /// Encrypts `plaintext` into `ciphertext`, returning the bytes written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is shorter than
    /// [`do_encrypt_out_len`](Self::do_encrypt_out_len) says, or the worker's own refusals.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Finishes with the tag inline: whatever was held back, then the tag, and how many bytes
    /// of the array are valid.
    ///
    /// # Errors
    /// The worker's own refusal of a message it was not given all of.
    fn do_encrypt_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// Finishes with the tag detached: whatever was held back goes into `ciphertext`, and the
    /// bytes written come back with the tag.
    ///
    /// # Errors
    /// As [`do_encrypt_final`](Self::do_encrypt_final).
    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError>;

    /// The ciphertext length, tag inline, for `plaintext_len` bytes.
    fn encrypt_out_len(plaintext_len: usize) -> usize;

    /// The ciphertext length, tag detached, for `plaintext_len` bytes.
    fn encrypt_detached_out_len(plaintext_len: usize) -> usize;
}

/// An AEAD decryptor that already exists; see [`AeadEncryptWorker`].
pub trait AeadDecryptWorker<const NONCE_LEN: usize, const TAG_LEN: usize, const FINAL_LEN: usize>:
    Sized
{
    /// Absorbs associated data before any ciphertext.
    ///
    /// # Errors
    /// As [`AeadEncryptWorker::do_update_aad`].
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError>;

    /// The most plaintext bytes the next `do_decrypt_out` of `input_len` bytes can release.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize;

    /// Decrypts `ciphertext` into `plaintext`, returning the bytes written. What is written is
    /// not yet authenticated: only the final says whether it may be trusted.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is shorter than
    /// [`do_decrypt_out_len`](Self::do_decrypt_out_len) says, or the worker's own refusals.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Finishes with the tag taken from the end of the ciphertext: whatever was held back, and
    /// how many bytes of the array are valid.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, and
    /// [`SymmetricCipherError::DecryptionFailed`] for a malformed ciphertext.
    fn do_decrypt_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// Finishes against a detached `tag`: whatever was held back goes into `plaintext`, and the
    /// bytes written come back.
    ///
    /// # Errors
    /// As [`do_decrypt_final`](Self::do_decrypt_final).
    fn do_decrypt_final_detached_out(
        self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>;

    /// The plaintext length for `ciphertext_len` bytes with the tag inline.
    fn decrypt_out_len(ciphertext_len: usize) -> usize;

    /// The plaintext length for `ciphertext_len` bytes with the tag detached.
    fn decrypt_detached_out_len(ciphertext_len: usize) -> usize;
}

/// A key that can begin an authenticated encryption: the encryption half of an AEAD key.
///
/// The encryptor is the mode's ordinary worker; this trait adds where it comes from. The
/// one-shots are provided over [`create_encryptor`](Self::create_encryptor) and the worker's
/// streaming methods, and return the same bytes as streaming the message by hand.
///
/// # The nonce is drawn by default
///
/// Every form without `_nonce` in its name draws the nonce from the RNG it is given and returns
/// it. The `_nonce` forms take the nonce instead, for a protocol whose nonce is a counter or
/// another value it manages itself; the caller then takes on the obligation the drawing forms
/// discharge for it, that the nonce never repeats under this key.
pub trait AeadEncryptionKey<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming encryptor this key produces.
    type Encryptor: AeadEncryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins an encryption under a nonce drawn from `rng`. The nonce is returned alongside the
    /// encryptor and must reach the recipient, who passes it to
    /// [`AeadDecryptionKey::create_decryptor`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    fn create_encryptor(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError>;

    /// Begins an encryption under a nonce the caller supplies. Infallible, as
    /// [`AeadDecryptionKey::create_decryptor`] is.
    fn create_encryptor_nonce(&self, nonce: &[u8; NONCE_LEN]) -> Self::Encryptor;

    /// One-shot with the tag inline: encrypts `plaintext` under `aad` into `ciphertext`, which
    /// needs `encrypt_out_len(plaintext.len())` bytes of the encryptor type, and returns the number
    /// of bytes written with the generated nonce. The entire output buffer is zeroized before the
    /// ciphertext is written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, or any error
    /// of [`create_encryptor`](Self::create_encryptor) and the encryptor's streaming methods.
    fn encrypt_with_aad_out(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; NONCE_LEN]), SymmetricCipherError> {
        let (enc, nonce) = self.create_encryptor(rng)?;
        let written = crate::provided::encrypt_inline(enc, aad, plaintext, ciphertext)?;
        Ok((written, nonce))
    }

    /// As [`encrypt_with_aad_out`](Self::encrypt_with_aad_out), allocating the ciphertext.
    ///
    /// # Errors
    /// As [`encrypt_with_aad_out`](Self::encrypt_with_aad_out).
    #[cfg(feature = "std")]
    fn encrypt_with_aad(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_out_len(plaintext.len())];
        let (written, nonce) = self.encrypt_with_aad_out(rng, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext))
    }

    /// One-shot with the tag detached: as [`encrypt_with_aad_out`](Self::encrypt_with_aad_out),
    /// with `ciphertext` needing only `encrypt_detached_out_len(plaintext.len())` bytes and the tag
    /// returned separately.
    ///
    /// # Errors
    /// As [`encrypt_with_aad_out`](Self::encrypt_with_aad_out).
    fn encrypt_detached_out(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        let (enc, nonce) = self.create_encryptor(rng)?;
        let (written, tag) = crate::provided::encrypt_detached(enc, aad, plaintext, ciphertext)?;
        Ok((written, nonce, tag))
    }

    /// As [`encrypt_detached_out`](Self::encrypt_detached_out), allocating the ciphertext.
    ///
    /// # Errors
    /// As [`encrypt_detached_out`](Self::encrypt_detached_out).
    #[cfg(feature = "std")]
    fn encrypt_detached(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<AEADEncryptedTuple<NONCE_LEN, TAG_LEN>, SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_detached_out_len(plaintext.len())];
        let (written, nonce, tag) =
            self.encrypt_detached_out(rng, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext, tag))
    }

    /// One-shot in place, tag detached: encrypts `buf` under `aad` and a nonce drawn from `rng`,
    /// in its own buffer, and returns the nonce and tag. For a message that is already in a
    /// buffer the caller owns, this needs no second buffer the size of the message.
    ///
    /// # Errors
    /// As [`encrypt_detached_out`](Self::encrypt_detached_out).
    fn encrypt_detached_in_place(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        let (enc, nonce) = self.create_encryptor(rng)?;
        let tag = crate::provided::encrypt_detached_in_place(enc, aad, buf)?;
        Ok((nonce, tag))
    }

    /// [`encrypt_with_aad_out`](Self::encrypt_with_aad_out) under a nonce the caller supplies;
    /// returns the number of bytes written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, or any error
    /// of the encryptor's streaming methods.
    fn encrypt_with_aad_nonce_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        crate::provided::encrypt_inline(
            self.create_encryptor_nonce(nonce),
            aad,
            plaintext,
            ciphertext,
        )
    }

    /// As [`encrypt_with_aad_nonce_out`](Self::encrypt_with_aad_nonce_out), allocating the
    /// ciphertext.
    ///
    /// # Errors
    /// As [`encrypt_with_aad_nonce_out`](Self::encrypt_with_aad_nonce_out).
    #[cfg(feature = "std")]
    fn encrypt_with_aad_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_out_len(plaintext.len())];
        let written = self.encrypt_with_aad_nonce_out(nonce, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok(ciphertext)
    }

    /// [`encrypt_detached_out`](Self::encrypt_detached_out) under a nonce the caller supplies;
    /// returns the number of bytes written and the tag.
    ///
    /// # Errors
    /// As [`encrypt_with_aad_nonce_out`](Self::encrypt_with_aad_nonce_out).
    fn encrypt_detached_nonce_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        crate::provided::encrypt_detached(
            self.create_encryptor_nonce(nonce),
            aad,
            plaintext,
            ciphertext,
        )
    }

    /// As [`encrypt_detached_nonce_out`](Self::encrypt_detached_nonce_out), allocating the
    /// ciphertext.
    ///
    /// # Errors
    /// As [`encrypt_detached_nonce_out`](Self::encrypt_detached_nonce_out).
    #[cfg(feature = "std")]
    fn encrypt_detached_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_LEN]), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_detached_out_len(plaintext.len())];
        let (written, tag) =
            self.encrypt_detached_nonce_out(nonce, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((ciphertext, tag))
    }

    /// [`encrypt_detached_in_place`](Self::encrypt_detached_in_place) under a nonce the caller
    /// supplies; returns the tag.
    ///
    /// # Errors
    /// Any error of the encryptor's streaming methods.
    fn encrypt_detached_in_place_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        crate::provided::encrypt_detached_in_place(self.create_encryptor_nonce(nonce), aad, buf)
    }
}

/// A key that can begin an authenticated decryption: the decryption half of an AEAD key.
///
/// Separate from [`AeadEncryptionKey`] so that a key type can carry one side and not the other.
/// Construction is infallible: the key is already validated and the nonce length is in the type.
pub trait AeadDecryptionKey<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming decryptor this key produces.
    type Decryptor: AeadDecryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins the decryption of a message whose encryptor returned `nonce`.
    fn create_decryptor(&self, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor;

    /// One-shot with the tag inline: decrypts `ciphertext` under `nonce` and `aad` into
    /// `plaintext`, which needs `decrypt_out_len(ciphertext.len())` bytes of the decryptor type,
    /// and returns the number of plaintext bytes written. The entire output buffer is zeroized
    /// before the plaintext is written, and again before an error is returned, so a caller who
    /// ignores the `Result` is left with zeros rather than unauthenticated plaintext.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short,
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, or any error of
    /// the decryptor's streaming methods.
    fn decrypt_with_aad_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        crate::provided::decrypt_inline(self.create_decryptor(nonce), aad, ciphertext, plaintext)
    }

    /// As [`decrypt_with_aad_out`](Self::decrypt_with_aad_out), allocating the plaintext.
    ///
    /// # Errors
    /// As [`decrypt_with_aad_out`](Self::decrypt_with_aad_out).
    #[cfg(feature = "std")]
    fn decrypt_with_aad(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::Decryptor::decrypt_out_len(ciphertext.len())];
        let written = self.decrypt_with_aad_out(nonce, aad, ciphertext, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// One-shot with the tag detached: as [`decrypt_with_aad_out`](Self::decrypt_with_aad_out),
    /// with `plaintext` needing `decrypt_detached_out_len(ciphertext.len())` bytes and the tag
    /// supplied separately.
    ///
    /// # Errors
    /// As [`decrypt_with_aad_out`](Self::decrypt_with_aad_out).
    fn decrypt_detached_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        crate::provided::decrypt_detached(
            self.create_decryptor(nonce),
            aad,
            ciphertext,
            tag,
            plaintext,
        )
    }

    /// As [`decrypt_detached_out`](Self::decrypt_detached_out), allocating the plaintext.
    ///
    /// # Errors
    /// As [`decrypt_detached_out`](Self::decrypt_detached_out).
    #[cfg(feature = "std")]
    fn decrypt_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::Decryptor::decrypt_detached_out_len(ciphertext.len())];
        let written = self.decrypt_detached_out(nonce, aad, ciphertext, tag, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// One-shot in place, tag detached: decrypts `buf` under `nonce` and `aad` in its own buffer
    /// and checks `tag`. On any error `buf` is left zeroized, as the `_out` forms leave their
    /// output: the plaintext was written into it before the tag could be checked.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, or any error of
    /// the decryptor's streaming methods.
    fn decrypt_detached_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        crate::provided::decrypt_detached_in_place(self.create_decryptor(nonce), aad, buf, tag)
    }
}

/// The encryption half of an AEAD key whose mode must know the AAD and payload lengths before
/// its first byte: CCM. The constructors take both, and the worker then needs no buffer for
/// either and holds nothing back. The one-shots have the lengths in hand, so they are provided
/// exactly as [`AeadEncryptionKey`]'s are and behave the same.
pub trait AeadPacketEncryptionKey<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming encryptor this key produces.
    type Encryptor: AeadEncryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins an encryption of `payload_len` bytes under `aad_len` bytes of AAD and a nonce
    /// drawn from `rng`, which is returned. The worker then takes exactly those amounts.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails, or the mode's refusal of a
    /// length it cannot encode.
    fn create_encryptor(
        &self,
        rng: &mut dyn RNG,
        aad_len: usize,
        payload_len: usize,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError>;

    /// As [`create_encryptor`](Self::create_encryptor) under a nonce the caller supplies, who
    /// takes on the obligation that it never repeat under this key.
    ///
    /// # Errors
    /// The mode's refusal of a length it cannot encode.
    fn create_encryptor_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Encryptor, SymmetricCipherError>;

    /// As [`AeadEncryptionKey::encrypt_with_aad_out`].
    ///
    /// # Errors
    /// As [`create_encryptor`](Self::create_encryptor), or
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short.
    fn encrypt_with_aad_out(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; NONCE_LEN]), SymmetricCipherError> {
        let (enc, nonce) = self.create_encryptor(rng, aad.len(), plaintext.len())?;
        let written = crate::provided::encrypt_inline(enc, aad, plaintext, ciphertext)?;
        Ok((written, nonce))
    }

    /// As [`AeadEncryptionKey::encrypt_with_aad`].
    ///
    /// # Errors
    /// As [`encrypt_with_aad_out`](Self::encrypt_with_aad_out).
    #[cfg(feature = "std")]
    fn encrypt_with_aad(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_out_len(plaintext.len())];
        let (written, nonce) = self.encrypt_with_aad_out(rng, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext))
    }

    /// As [`AeadEncryptionKey::encrypt_detached_out`].
    ///
    /// # Errors
    /// As [`encrypt_with_aad_out`](Self::encrypt_with_aad_out).
    fn encrypt_detached_out(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        let (enc, nonce) = self.create_encryptor(rng, aad.len(), plaintext.len())?;
        let (written, tag) = crate::provided::encrypt_detached(enc, aad, plaintext, ciphertext)?;
        Ok((written, nonce, tag))
    }

    /// As [`AeadEncryptionKey::encrypt_detached`].
    ///
    /// # Errors
    /// As [`encrypt_detached_out`](Self::encrypt_detached_out).
    #[cfg(feature = "std")]
    fn encrypt_detached(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<AEADEncryptedTuple<NONCE_LEN, TAG_LEN>, SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_detached_out_len(plaintext.len())];
        let (written, nonce, tag) =
            self.encrypt_detached_out(rng, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext, tag))
    }

    /// As [`AeadEncryptionKey::encrypt_detached_in_place`].
    ///
    /// # Errors
    /// As [`create_encryptor`](Self::create_encryptor), or any error of the encryptor's
    /// streaming methods.
    fn encrypt_detached_in_place(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        let (enc, nonce) = self.create_encryptor(rng, aad.len(), buf.len())?;
        let tag = crate::provided::encrypt_detached_in_place(enc, aad, buf)?;
        Ok((nonce, tag))
    }

    /// As [`AeadEncryptionKey::encrypt_with_aad_nonce_out`].
    ///
    /// # Errors
    /// As [`create_encryptor_nonce`](Self::create_encryptor_nonce), or
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short.
    fn encrypt_with_aad_nonce_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let enc = self.create_encryptor_nonce(nonce, aad.len(), plaintext.len())?;
        crate::provided::encrypt_inline(enc, aad, plaintext, ciphertext)
    }

    /// As [`AeadEncryptionKey::encrypt_with_aad_nonce`].
    ///
    /// # Errors
    /// As [`encrypt_with_aad_nonce_out`](Self::encrypt_with_aad_nonce_out).
    #[cfg(feature = "std")]
    fn encrypt_with_aad_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_out_len(plaintext.len())];
        let written = self.encrypt_with_aad_nonce_out(nonce, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok(ciphertext)
    }

    /// As [`AeadEncryptionKey::encrypt_detached_nonce_out`].
    ///
    /// # Errors
    /// As [`encrypt_with_aad_nonce_out`](Self::encrypt_with_aad_nonce_out).
    fn encrypt_detached_nonce_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let enc = self.create_encryptor_nonce(nonce, aad.len(), plaintext.len())?;
        crate::provided::encrypt_detached(enc, aad, plaintext, ciphertext)
    }

    /// As [`AeadEncryptionKey::encrypt_detached_nonce`].
    ///
    /// # Errors
    /// As [`encrypt_detached_nonce_out`](Self::encrypt_detached_nonce_out).
    #[cfg(feature = "std")]
    fn encrypt_detached_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_LEN]), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_detached_out_len(plaintext.len())];
        let (written, tag) =
            self.encrypt_detached_nonce_out(nonce, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((ciphertext, tag))
    }

    /// As [`AeadEncryptionKey::encrypt_detached_in_place_nonce`].
    ///
    /// # Errors
    /// As [`create_encryptor_nonce`](Self::create_encryptor_nonce), or any error of the
    /// encryptor's streaming methods.
    fn encrypt_detached_in_place_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        let enc = self.create_encryptor_nonce(nonce, aad.len(), buf.len())?;
        crate::provided::encrypt_detached_in_place(enc, aad, buf)
    }
}

/// The decryption half of an AEAD key whose mode must know the lengths up front; see
/// [`AeadPacketEncryptionKey`]. For the inline layout the payload length is the ciphertext less
/// its tag, and a ciphertext too short for a tag is malformed.
pub trait AeadPacketDecryptionKey<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming decryptor this key produces.
    type Decryptor: AeadDecryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins the decryption of `payload_len` bytes of ciphertext under `aad_len` bytes of AAD,
    /// encrypted under `nonce`.
    ///
    /// # Errors
    /// The mode's refusal of a length it cannot encode.
    fn create_decryptor(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Decryptor, SymmetricCipherError>;

    /// As [`AeadDecryptionKey::decrypt_with_aad_out`].
    ///
    /// # Errors
    /// As [`AeadDecryptionKey::decrypt_with_aad_out`], and
    /// [`SymmetricCipherError::DecryptionFailed`] if `ciphertext` is too short for a tag.
    fn decrypt_with_aad_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let payload_len = crate::provided::inline_payload_len::<TAG_LEN>(ciphertext.len())?;
        let dec = self.create_decryptor(nonce, aad.len(), payload_len)?;
        crate::provided::decrypt_inline(dec, aad, ciphertext, plaintext)
    }

    /// As [`AeadDecryptionKey::decrypt_with_aad`].
    ///
    /// # Errors
    /// As [`decrypt_with_aad_out`](Self::decrypt_with_aad_out).
    #[cfg(feature = "std")]
    fn decrypt_with_aad(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::Decryptor::decrypt_out_len(ciphertext.len())];
        let written = self.decrypt_with_aad_out(nonce, aad, ciphertext, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// As [`AeadDecryptionKey::decrypt_detached_out`].
    ///
    /// # Errors
    /// As [`AeadDecryptionKey::decrypt_detached_out`], or
    /// [`create_decryptor`](Self::create_decryptor)'s.
    fn decrypt_detached_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let dec = self.create_decryptor(nonce, aad.len(), ciphertext.len())?;
        crate::provided::decrypt_detached(dec, aad, ciphertext, tag, plaintext)
    }

    /// As [`AeadDecryptionKey::decrypt_detached`].
    ///
    /// # Errors
    /// As [`decrypt_detached_out`](Self::decrypt_detached_out).
    #[cfg(feature = "std")]
    fn decrypt_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::Decryptor::decrypt_detached_out_len(ciphertext.len())];
        let written = self.decrypt_detached_out(nonce, aad, ciphertext, tag, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// As [`AeadDecryptionKey::decrypt_detached_in_place`]; `buf` is untouched if construction
    /// refuses the lengths, and zeroized on any error after that.
    ///
    /// # Errors
    /// As [`AeadDecryptionKey::decrypt_detached_in_place`], or
    /// [`create_decryptor`](Self::create_decryptor)'s.
    fn decrypt_detached_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        let dec = self.create_decryptor(nonce, aad.len(), buf.len())?;
        crate::provided::decrypt_detached_in_place(dec, aad, buf, tag)
    }
}

/// A key that can begin an unauthenticated encryption of data of any length: the encryption
/// half of a key for padded CBC, CFB, CFB8 or CTR. The encryptor is the mode's ordinary worker, a
/// [`SymmetricCipherEncryptor`]; this trait adds where it comes from, and the one-shots are
/// provided over [`create_encryptor`](Self::create_encryptor) and the worker's streaming methods.
///
/// The init data (an IV or nonce) is drawn from the RNG the key is given and returned; there is
/// no form that takes one, since these modes need it unpredictable (SP 800-38A Appendix C).
pub trait SymmetricEncryptionKey<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming encryptor this key produces.
    type Encryptor: SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>;

    /// Begins an encryption under init data drawn from `rng`, which is returned alongside the
    /// encryptor and must reach the recipient, who passes it to
    /// [`SymmetricDecryptionKey::create_decryptor`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the draw fails; nothing else can.
    fn create_encryptor(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; INIT_DATA_LEN]), SymmetricCipherError>;

    /// One-shot: encrypts `plaintext` into `ciphertext`, which needs `encrypt_out_len` bytes of
    /// the encryptor type, and returns the number of bytes written with the generated init data.
    /// The entire output buffer is zeroized before the ciphertext is written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, or any error
    /// of [`create_encryptor`](Self::create_encryptor) and the encryptor's streaming methods.
    fn encrypt_out(
        &self,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let (enc, init_data) = self.create_encryptor(rng)?;
        let written = crate::provided::symmetric_encrypt_out(enc, plaintext, ciphertext)?;
        Ok((written, init_data))
    }

    /// As [`encrypt_out`](Self::encrypt_out), allocating the ciphertext.
    ///
    /// # Errors
    /// As [`encrypt_out`](Self::encrypt_out).
    #[cfg(feature = "std")]
    fn encrypt(
        &self,
        rng: &mut dyn RNG,
        plaintext: &[u8],
    ) -> Result<([u8; INIT_DATA_LEN], Vec<u8>), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; Self::Encryptor::encrypt_out_len(plaintext.len())];
        let (written, init_data) = self.encrypt_out(rng, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((init_data, ciphertext))
    }

    /// One-shot in place, for a mode whose encryptor is a stream cipher: encrypts `data` in its
    /// own buffer under init data drawn from `rng`, and returns the number of bytes written with
    /// the init data.
    ///
    /// # Errors
    /// As [`create_encryptor`](Self::create_encryptor), or
    /// [`StreamCipherEncryptor::do_encrypt_inplace`]'s.
    fn encrypt_inplace(
        &self,
        rng: &mut dyn RNG,
        data: &mut [u8],
    ) -> Result<(usize, [u8; INIT_DATA_LEN]), SymmetricCipherError>
    where
        Self::Encryptor: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
    {
        let (mut enc, init_data) = self.create_encryptor(rng)?;
        let written = StreamCipherEncryptor::do_encrypt_inplace(&mut enc, data)?;
        Ok((written, init_data))
    }
}

/// A key that can begin an unauthenticated decryption of data of any length; see
/// [`SymmetricEncryptionKey`]. Construction is infallible: the key is already validated and the
/// init data length is in the type.
pub trait SymmetricDecryptionKey<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming decryptor this key produces.
    type Decryptor: SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>;

    /// Begins the decryption of a message whose encryptor returned `init_data`.
    fn create_decryptor(&self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor;

    /// One-shot: decrypts `ciphertext` under `init_data` into `plaintext`, which needs
    /// `decrypt_out_len(ciphertext.len())` bytes of the decryptor type, and returns the number
    /// of plaintext bytes written. The entire output buffer is zeroized before the plaintext is
    /// written, and again before an error is returned.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short, or any error
    /// of the decryptor's streaming methods: a malformed ciphertext or bad padding.
    fn decrypt_out(
        &self,
        init_data: &[u8; INIT_DATA_LEN],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        crate::provided::symmetric_decrypt_out(
            self.create_decryptor(init_data),
            ciphertext,
            plaintext,
        )
    }

    /// As [`decrypt_out`](Self::decrypt_out), allocating the plaintext.
    ///
    /// # Errors
    /// As [`decrypt_out`](Self::decrypt_out).
    #[cfg(feature = "std")]
    fn decrypt(
        &self,
        init_data: &[u8; INIT_DATA_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; Self::Decryptor::decrypt_out_len(ciphertext.len())];
        let written = self.decrypt_out(init_data, ciphertext, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// One-shot in place, for a mode whose decryptor is a stream cipher: decrypts `data` in its
    /// own buffer under `init_data`, and returns the number of bytes written.
    ///
    /// # Errors
    /// [`StreamCipherDecryptor::do_decrypt_inplace`]'s.
    fn decrypt_inplace(
        &self,
        init_data: &[u8; INIT_DATA_LEN],
        data: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>
    where
        Self::Decryptor: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
    {
        let mut dec = self.create_decryptor(init_data);
        StreamCipherDecryptor::do_decrypt_inplace(&mut dec, data)
    }
}

/// A key that can begin a whole-block encryption: the encryption half of a key for CBC without
/// a padding layer. The encryptor is a [`BlockCipherEncryptor`], whose buffers are
/// block-aligned arrays checked at compile time; data of arbitrary length goes through a padded
/// mode and [`SymmetricEncryptionKey`] instead.
pub trait BlockEncryptionKey<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
>
{
    /// The streaming encryptor this key produces.
    type Encryptor: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>;

    /// Begins an encryption under init data drawn from `rng`, which is returned alongside the
    /// encryptor and must reach the recipient, who passes it to
    /// [`BlockDecryptionKey::create_decryptor`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the draw fails; nothing else can.
    fn create_encryptor(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; INIT_DATA_LEN]), SymmetricCipherError>;

    /// One-shot: encrypts `LEN` bytes, a whole number of blocks, in place under init data drawn
    /// from `rng`, and returns the number of bytes written with the init data. `LEN % BLOCK_LEN
    /// == 0` is checked at compile time, as for [`BlockCipherEncryptor::do_encrypt_inplace`].
    ///
    /// # Errors
    /// As [`create_encryptor`](Self::create_encryptor), or the encryptor's own refusals.
    fn encrypt_inplace(
        &self,
        rng: &mut dyn RNG,
        data: &mut [u8],
    ) -> Result<(usize, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let (blocks, []) = data.as_chunks_mut::<BLOCK_LEN>() else {
            return Err(SymmetricCipherError::DataNotBlockAligned);
        };
        let (mut enc, init_data) = self.create_encryptor(rng)?;
        let written = enc.do_encrypt_blocks_inplace(blocks)?;
        Ok((written, init_data))
    }
}

/// A key that can begin a whole-block decryption; see [`BlockEncryptionKey`]. Construction is
/// infallible: the key is already validated and the init data length is in the type.
pub trait BlockDecryptionKey<
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
>
{
    /// The streaming decryptor this key produces.
    type Decryptor: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>;

    /// Begins the decryption of a message whose encryptor returned `init_data`.
    fn create_decryptor(&self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor;

    /// One-shot: decrypts `LEN` bytes, a whole number of blocks, in place under `init_data`, and
    /// returns the number of bytes written. `LEN % BLOCK_LEN == 0` is checked at compile time.
    ///
    /// # Errors
    /// The decryptor's own refusals.
    fn decrypt_inplace(
        &self,
        init_data: &[u8; INIT_DATA_LEN],
        data: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let (blocks, []) = data.as_chunks_mut::<BLOCK_LEN>() else {
            return Err(SymmetricCipherError::DataNotBlockAligned);
        };
        self.create_decryptor(init_data).do_decrypt_blocks_inplace(blocks)
    }
}

// The MAC worker is bounded on `MAC` as a whole for now: splitting its finals into `MACGenerator`
// and `MACVerifier` while `MAC` still carries them would put the same method names on two traits,
// which is ambiguous at every call site that has both in scope (`do_update` is on `MAC`, `do_final`
// would be on both). The split happens when `MAC` loses its constructors and finals.

/// A key that can generate MACs. Each call to [`create_generator`](Self::create_generator) clones
/// the key's per-key state into a fresh worker, so any number of generators can be in flight from
/// one key and finish in any order; the key is never changed by use.
pub trait MacGenerationKey {
    /// The streaming worker this key produces for generation.
    type Generator: MAC;

    /// Begins a MAC over a new message. Infallible: there is nothing to draw and nothing left to
    /// check.
    fn create_generator(&self) -> Self::Generator;

    /// One-shot: the MAC of `data` into `out`, which is zeroized first; returns the number of
    /// bytes written.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `out` is shorter than the worker's minimum output.
    fn mac_out(&self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        let mut generator = self.create_generator();
        generator.do_update(data);
        generator.do_final_out(out)
    }

    /// One-shot: the full-length MAC of `data`.
    #[cfg(feature = "std")]
    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut generator = self.create_generator();
        generator.do_update(data);
        generator.do_final()
    }
}

/// A key that can verify MACs; see [`MacGenerationKey`] for the lifetime of the workers. A key
/// may implement this and not [`MacGenerationKey`], which is what a verify-only token key is.
pub trait MacVerificationKey {
    /// The streaming worker this key produces for verification.
    type Verifier: MAC;

    /// Begins the verification of a new message. Infallible.
    fn create_verifier(&self) -> Self::Verifier;

    /// One-shot: whether `mac` is the MAC of `data`, compared in constant time.
    fn verify(&self, data: &[u8], mac: &[u8]) -> bool {
        let mut ver = self.create_verifier();
        ver.do_update(data);
        ver.do_verify_final(mac)
    }
}
