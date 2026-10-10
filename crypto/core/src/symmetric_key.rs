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
//! * **Roles**, one trait per direction: [`AeadEncryptionKey`] / [`AeadDecryptionKey`] and
//!   [`MacGenerationKey`] / [`MacVerificationKey`]. A key type implements the sides it is allowed
//!   to use, so a decrypt-only or verify-only key refuses the other side at compile time. The
//!   one-shots are provided methods over `create_*` and the worker's streaming methods.
//!
//! Which role a cipher key carries is decided by its mode type through the mode traits in
//! [`crate::hazmat`] ([`Mode`], [`AeadEncryptMode`], [`AeadDecryptMode`]); the permutation crate
//! connects the two with a forwarding impl per role.
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
    AEADCipherDecryptor, AEADCipherEncryptor, MAC, RNG, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
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
// argument (the `Encryptor` bound) nor size an array from one (the returned nonce). `KEY_LEN` is
// here only while the cipher traits still carry it; it goes when their constructors do.

/// A key that can begin an authenticated encryption: the encryption half of an AEAD key.
///
/// The encryptor is the mode's ordinary type, so everything in [`AEADCipherEncryptor`] applies to
/// it unchanged; this trait adds where it comes from. The one-shots are provided over
/// [`create_encryptor`](Self::create_encryptor) and the streaming methods, and return the same
/// bytes as streaming the message by hand.
pub trait AeadEncryptionKey<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>
{
    /// The streaming encryptor this key produces.
    type Encryptor: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>;

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
    type Decryptor: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>;

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
        plaintext.fill(0);
        let needed = Self::Decryptor::decrypt_out_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let mut dec = self.create_decryptor(nonce);
        dec.do_update_aad(aad)?;
        let written = dec.do_decrypt_out(ciphertext, plaintext)?;
        match dec.do_decrypt_final() {
            Ok((last, data_len)) => {
                // `decrypt_out_len` bounds `written + data_len`, so this fits in
                // `plaintext[..needed]`.
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
        plaintext.fill(0);
        let needed = Self::Decryptor::decrypt_detached_out_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let mut dec = self.create_decryptor(nonce);
        dec.do_update_aad(aad)?;
        let written = dec.do_decrypt_out(ciphertext, plaintext)?;
        let mut final_buf = [0u8; FINAL_LEN];
        match dec.do_decrypt_final_detached_out(tag, &mut final_buf) {
            Ok(final_len) => {
                // `decrypt_detached_out_len` bounds `written + final_len`.
                plaintext[written..written + final_len].copy_from_slice(&final_buf[..final_len]);
                Ok(written + final_len)
            }
            Err(e) => {
                // As in `decrypt_with_aad_out`.
                plaintext[..written].fill(0);
                Err(e)
            }
        }
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
