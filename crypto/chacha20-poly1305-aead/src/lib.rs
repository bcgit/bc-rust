//! ChaCha20-Poly1305 AEAD from [RFC 8439, section 2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8).
//!
//! [`ChaCha20Poly1305Key`] is the key object: built once from 32 bytes of key material through
//! [`FromKeyMaterial`], it hands out [`ChaCha20_Poly1305<Encrypting>`] /
//! [`ChaCha20_Poly1305<Decrypting>`] workers through [`AeadEncryptionKey`] /
//! [`AeadDecryptionKey`], whose one-shots and the workers' [`AEADCipherEncryptor`] /
//! [`AEADCipherDecryptor`] streaming methods take the 16-byte tag inline or detached. Keys are 32
//! bytes and nonces 12 bytes. Encryption draws the nonce from the RNG it is given; protocols that
//! supply their own may use [`AeadEncryptionKey::create_encryptor_nonce`], taking responsibility
//! for nonce uniqueness. A key/nonce may encrypt at most `64 * (2^32 - 1)` bytes. AAD must precede
//! all data updates, including empty updates. Empty AAD is always a no-op. Secret state is
//! zeroized on drop; streaming and output-buffer methods do not allocate. This is the IETF
//! construction, not the original 64-bit-nonce variant or XChaCha20.
//!
//! # Usage Examples
//!
//! One-shot, with a detached tag:
//!
//! ```
//! use bouncycastle_chacha20_poly1305_aead::ChaCha20Poly1305Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let key = ChaCha20Poly1305Key::from_key_material(&material).unwrap();
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let mut ciphertext = [0u8; 7];
//! let (n, nonce, tag) = key.encrypt_detached_out(&mut rng, b"header", b"message", &mut ciphertext).unwrap();
//! let mut plaintext = [0u8; 7];
//! key.decrypt_detached_out(&nonce, b"header", &ciphertext[..n], &tag, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, b"message");
//! ```
//!
//! Streaming, with the tag inline after the ciphertext:
//!
//! ```
//! use bouncycastle_chacha20_poly1305_aead::ChaCha20Poly1305Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let key = ChaCha20Poly1305Key::from_key_material(&material).unwrap();
//! let (mut enc, nonce) = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! enc.do_update_aad(b"header").unwrap();
//! let mut sealed = Vec::new();
//! for piece in [&b"first part, "[..], &b"second part"[..]] {
//!     let mut out = [0u8; 32];
//!     let n = enc.do_encrypt_out(piece, &mut out).unwrap();
//!     sealed.extend_from_slice(&out[..n]);
//! }
//! let (tag, _) = enc.do_encrypt_final().unwrap();
//! sealed.extend_from_slice(&tag);
//!
//! let mut dec = key.create_decryptor(&nonce);
//! dec.do_update_aad(b"header").unwrap();
//! let mut plaintext = vec![0u8; sealed.len()];
//! let n = dec.do_decrypt_out(&sealed, &mut plaintext).unwrap();
//! // Only once do_decrypt_final succeeds is plaintext[..n] authenticated.
//! let (_, m) = dec.do_decrypt_final().unwrap();
//! assert_eq!(&plaintext[..n + m], b"first part, second part");
//! ```
//!
//! # Memory Usage
//!
//! | Type | In-memory size (bytes) |
//! |------|------------------------|
//! | [`ChaCha20Poly1305Key`] | 32 |
//! | [`ChaCha20_Poly1305<Encrypting>`] | 344 |
//! | [`ChaCha20_Poly1305<Decrypting>`] | 344 |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target. There are no heap allocations and
//! no message-sized buffers, so this crate has no `mem_usage_benches` harness.
//!
//! # 🚨 Security Considerations 🚨
//!
//! - Never reuse a nonce under the same key. The key's `create_encryptor` and its one-shots draw
//!   one; a caller of [`AeadEncryptionKey::create_encryptor_nonce`] or the `_nonce` one-shots is
//!   responsible for uniqueness. Reuse exposes the XOR of the plaintexts and lets an attacker forge
//!   tags.
//! - Streaming decryption releases **unauthenticated** bytes: do not use them until finalization
//!   succeeds, and erase them on failure. The key's one-shots erase their output on tag failure.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_chacha20::ChaCha20;
use bouncycastle_chacha20::hazmat::{ChaCha20KeyState, ChaCha20KeyStream};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, MAC, RNG, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_poly1305::Poly1305;
use bouncycastle_poly1305::hazmat::key_from_bytes;
use bouncycastle_utils::{ct, secret::Secret};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// Tag length, also the streaming final-buffer length, in bytes.
pub const TAG_LEN: usize = 16;
/// Maximum plaintext or ciphertext length (excluding the tag) per key/nonce.
pub const MAX_MESSAGE_LEN: u64 = u32::MAX as u64 * 64;

/// ChaCha20-Poly1305 (RFC 8439 Sec 2.8) in one direction: `Dir` is [`Encrypting`] or
/// [`Decrypting`], and only that direction's methods exist on the type, so the wrong direction is a
/// compile error. One instance performs one operation under one (key, nonce) pair, and is made by
/// a [`ChaCha20Poly1305Key`].
///
/// The encrypting side holds nothing back: `FINAL_LEN` is `TAG_LEN`, so the inline
/// [`SymmetricCipherEncryptor::do_encrypt_final`] writes only the tag. The decrypting side holds
/// back the last `TAG_LEN` bytes of ciphertext until the final, since until the stream ends they
/// may be the inline tag.
///
/// ```compile_fail
/// # use bouncycastle_chacha20_poly1305_aead::ChaCha20Poly1305Key;
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};
/// # use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// # let material = KeyMaterial::<32>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap();
/// # let key = ChaCha20Poly1305Key::from_key_material(&material).unwrap();
/// let mut dec = key.create_decryptor(&[0u8; 12]);
/// dec.do_encrypt_out(&[0u8; 4], &mut [0u8; 4]); // no such method on the decrypting type
/// ```
///
/// A worker borrows its key for `'k`, and cannot be cloned, since two copies of one encryptor
/// would encrypt two messages under one nonce:
///
/// ```compile_fail
/// # use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
/// # use bouncycastle_cipher::Encrypting;
/// fn cloneable<T: Clone>() {}
/// cloneable::<ChaCha20_Poly1305<'static, Encrypting>>();
/// ```
///
/// which compiles without its last line:
///
/// ```
/// # use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
/// # use bouncycastle_cipher::Encrypting;
/// fn cloneable<T: Clone>() {}
/// let _ = core::mem::size_of::<ChaCha20_Poly1305<'static, Encrypting>>();
/// ```
#[allow(non_camel_case_types)]
pub struct ChaCha20_Poly1305<'k, Dir> {
    // The data keystream, from block counter 1. Decrypting, it is RFC 8439 Sec 2.8's "ChaCha20
    // encryption function ... applied to the ciphertext": both directions are the same XOR.
    cipher: ChaCha20<'k, Dir>,
    mac: Poly1305,
    aad_len: u64,
    data_len: u64,
    data_started: bool,
    // Decrypting only: the newest up to `TAG_LEN` bytes of ciphertext, not yet released because
    // they may be the inline tag. Ciphertext, so not a `Secret`; the encrypting side carries them
    // unused, as `Gcm` and `Ascon_AEAD128` do.
    held: [u8; TAG_LEN],
    held_len: usize,
}

impl<Dir> Algorithm for ChaCha20_Poly1305<'_, Dir> {
    const ALG_NAME: &'static str = "ChaCha20-Poly1305";
    // The cipher key has 256-bit strength; authentication is limited by the 128-bit tag.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

impl<'k, Dir> ChaCha20_Poly1305<'k, Dir> {
    /// The setup of both directions under `nonce`, from a key its key object has validated.
    fn new(key: &'k ChaCha20KeyState, nonce: &[u8; NONCE_LEN]) -> Self {
        // RFC 8439 Sec 2.8: the one-time key is the first 32 bytes of block 0 (Sec 2.6.1,
        // poly1305_key_gen), and the data is encrypted "with the initial counter set to 1".
        // Taking block 0 leaves the keystream at counter 1, so the same keystream carries the data.
        let mut keystream = ChaCha20KeyStream::start_at(key, nonce, 0);
        let mut block: Secret<[[u8; 64]; 1]> = Secret::new();
        keystream.apply_blocks(&mut *block);
        // infallible: the slice is exactly the 32 bytes of the one-time key.
        let one_time_key: &[u8; 32] = block[0][..32].try_into().unwrap();
        // This is a derived one-time key, including the (possible) all-zero value. Key strength
        // was already enforced on the parent cipher key; no entropy heuristic applies here.
        let mac = key_from_bytes(one_time_key).into_generator();
        Self {
            cipher: ChaCha20::from_keystream(keystream),
            mac,
            aad_len: 0,
            data_len: 0,
            data_started: false,
            held: [0u8; TAG_LEN],
            held_len: 0,
        }
    }

    fn absorb_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if aad.is_empty() {
            return Ok(());
        }
        if self.data_started {
            return Err(SymmetricCipherError::StateError(
                "AAD must precede ciphertext or plaintext",
            ));
        }
        let length = self
            .aad_len
            .checked_add(aad.len() as u64)
            .ok_or(SymmetricCipherError::StateError("ChaCha20-Poly1305 AAD length overflow"))?;
        self.mac.do_update(aad);
        self.aad_len = length;
        Ok(())
    }

    // The cipher started at counter 1 and has processed exactly `data_len` bytes, so this is its
    // own limit. Checking it here, before the MAC absorbs anything or the AAD phase ends, is what
    // keeps a refused call free of side effects.
    fn check_data_len(&self, length: usize) -> Result<(), SymmetricCipherError> {
        if length as u64 > MAX_MESSAGE_LEN - self.data_len {
            return Err(SymmetricCipherError::DataLimitExceeded);
        }
        Ok(())
    }

    fn start_data(&mut self) {
        if !self.data_started {
            self.mac.do_update(&[0u8; 15][..padding_len(self.aad_len)]);
            self.data_started = true;
        }
    }

    fn finish_tag(mut self) -> [u8; TAG_LEN] {
        self.start_data();
        self.mac.do_update(&[0u8; 15][..padding_len(self.data_len)]);
        self.mac.do_update(&self.aad_len.to_le_bytes());
        self.mac.do_update(&self.data_len.to_le_bytes());
        self.mac.finalize()
    }
}

impl ChaCha20_Poly1305<'_, Encrypting> {
    fn encrypt_bytes(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.check_data_len(data.len())?;
        self.start_data();
        self.cipher.do_encrypt_inplace(data)?;
        self.mac.do_update(data);
        self.data_len += data.len() as u64;
        Ok(())
    }
}

impl ChaCha20_Poly1305<'_, Decrypting> {
    fn decrypt_bytes(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.check_data_len(data.len())?;
        self.start_data();
        self.mac.do_update(data);
        self.cipher.do_decrypt_inplace(data)?;
        self.data_len += data.len() as u64;
        Ok(())
    }

    fn verify_tag(self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        if ct::ct_eq_bytes(&self.finish_tag(), tag) {
            Ok(())
        } else {
            Err(SymmetricCipherError::AEADTagCheckFailed)
        }
    }
}

fn padding_len(length: u64) -> usize {
    ((16 - (length & 15)) & 15) as usize
}

impl SymmetricCipherEncryptor<NONCE_LEN, TAG_LEN> for ChaCha20_Poly1305<'_, Encrypting> {
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        self.check_data_len(plaintext.len())?;
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.encrypt_bytes(out)?;
        Ok(plaintext.len())
    }

    fn do_encrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        Ok((self.finish_tag(), TAG_LEN))
    }

    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len.saturating_add(TAG_LEN)
    }
}

impl AEADCipherEncryptor<NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20_Poly1305<'_, Encrypting> {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// Nothing is ever held back to flush, so `ciphertext` is left zeroed.
    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        ciphertext.fill(0);
        Ok((0, self.finish_tag()))
    }
}

impl SymmetricCipherDecryptor<NONCE_LEN, TAG_LEN> for ChaCha20_Poly1305<'_, Decrypting> {
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len.saturating_sub(TAG_LEN - self.held_len)
    }

    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let release = self.do_decrypt_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        self.check_data_len(release)?;
        let from_held = release.min(self.held_len);
        let from_input = release - from_held;
        let out = &mut plaintext[..release];
        out[..from_held].copy_from_slice(&self.held[..from_held]);
        out[from_held..].copy_from_slice(&ciphertext[..from_input]);
        // Even a zero-length update ends the AAD phase, as required by the core traits.
        self.decrypt_bytes(out)?;
        let kept = self.held_len - from_held;
        self.held.copy_within(from_held..self.held_len, 0);
        let new_len = kept + ciphertext.len() - from_input;
        self.held[kept..new_len].copy_from_slice(&ciphertext[from_input..]);
        self.held_len = new_len;
        Ok(release)
    }

    fn do_decrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.held_len != TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let tag = self.held;
        self.verify_tag(&tag)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

impl AEADCipherDecryptor<NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20_Poly1305<'_, Decrypting> {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    fn do_decrypt_final_detached_out(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let n = self.held_len;
        // Decrypted aside and copied out only once the tag verifies, so a failed check never
        // writes unauthenticated bytes to `plaintext`.
        let mut last: Secret<[u8; TAG_LEN]> = Secret::new();
        last[..n].copy_from_slice(&self.held[..n]);
        self.decrypt_bytes(&mut last[..n])?;
        self.verify_tag(tag)?;
        plaintext[..n].copy_from_slice(&last[..n]);
        Ok(n)
    }
}

/// A ChaCha20-Poly1305 key: the 256-bit key of RFC 8439 Sec 2.8, validated once, from which the
/// encryptor and decryptor for each message are made. Built through [`FromKeyMaterial`] from
/// material tagged [`KeyType::SymmetricCipherKey`], unbound or bound to this AEAD's
/// [`Algorithm::ALG_NAME`], of 256-bit strength; material bound to plain ChaCha20 is refused. The
/// key words live in a `Secret`, zeroized on drop; there is no `Debug` and no way to read them
/// back.
#[derive(Clone)]
pub struct ChaCha20Poly1305Key {
    state: ChaCha20KeyState,
}

impl FromKeyMaterial<KEY_LEN> for ChaCha20Poly1305Key {
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`](bouncycastle_core::errors::KeyMaterialError::InvalidKeyType)
    ///   if the key is bound to another algorithm (`KeyMaterialTrait::set_algorithm`), or is not
    ///   a `SymmetricCipherKey`.
    /// * As [`ChaCha20KeyState::new`] otherwise.
    fn from_key_material(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        // The key is bound, if at all, to this AEAD. The key state, which the ChaCha20 key builds
        // on too, leaves that check to its caller, as an AES key's permutation does.
        key.check_algorithm(ChaCha20_Poly1305::<Encrypting>::ALG_NAME)?;
        Ok(Self { state: ChaCha20KeyState::new(key)? })
    }
}

impl AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20Poly1305Key {
    type Encryptor<'k>
        = ChaCha20_Poly1305<'k, Encrypting>
    where
        Self: 'k;

    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((ChaCha20_Poly1305::new(&self.state, &nonce), nonce))
    }

    /// Under a nonce the caller supplies, who takes on the obligation that it never repeat under
    /// this key: RFC 8439 Sec 2.8's nonce is "different for each invocation with the same key".
    fn create_encryptor_nonce<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Encryptor<'k> {
        ChaCha20_Poly1305::new(&self.state, nonce)
    }
}

impl AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20Poly1305Key {
    type Decryptor<'k>
        = ChaCha20_Poly1305<'k, Decrypting>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor<'k> {
        ChaCha20_Poly1305::new(&self.state, nonce)
    }
}

#[cfg(test)]
mod tests {
    //! The message and AAD length limits. Reaching them through the public API means processing
    //! 256 GiB of data, or 2^64 bytes of AAD, so these position the private state next to the
    //! boundary instead: the "cannot be tested from integration tests" case QUALITY_AND_STYLE.md
    //! carves out for unit tests.

    use super::*;

    fn key() -> ChaCha20KeyState {
        let material =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey);
        ChaCha20KeyState::new(&material.unwrap()).unwrap()
    }

    fn fresh<Dir>(key: &ChaCha20KeyState) -> ChaCha20_Poly1305<'_, Dir> {
        ChaCha20_Poly1305::new(key, &[9; 12])
    }

    /// One block of data left: the keystream at its last counter, and `data_len` to match.
    fn near_limit<Dir>(key: &ChaCha20KeyState) -> ChaCha20_Poly1305<'_, Dir> {
        let mut cipher = fresh(key);
        // `check_data_len` relies on MAX_MESSAGE_LEN being exactly the data keystream's capacity.
        assert_eq!(cipher.cipher.keystream().remaining_blocks() * 64, MAX_MESSAGE_LEN);
        cipher.cipher =
            ChaCha20::from_keystream(ChaCha20KeyStream::start_at(key, &[9; 12], u32::MAX));
        cipher.data_len = MAX_MESSAGE_LEN - 64;
        cipher
    }

    #[test]
    fn encryption_limit_errors_leave_state_and_output_untouched() {
        let key = key();
        let mut enc = near_limit::<Encrypting>(&key);
        let mut out = [0xa5; 65];
        assert!(matches!(
            enc.do_encrypt_out(&[0; 65], &mut out),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
        assert_eq!(out, [0; 65], "a refused call zeroizes its output buffer");
        assert!(!enc.data_started);
        enc.do_update_aad(b"aad").unwrap();
        enc.do_encrypt_out(&[0; 63], &mut out[..63]).unwrap();
        assert_eq!(MAX_MESSAGE_LEN - enc.data_len, 1);
        let mut short = [0xa5; 2];
        assert!(matches!(
            enc.do_encrypt_out(&[0; 2], &mut short),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
        assert_eq!(short, [0; 2]);
        enc.do_encrypt_out(&[0], &mut out[63..64]).unwrap();
        assert_eq!(enc.data_len, MAX_MESSAGE_LEN);
        enc.do_encrypt_out(&[], &mut []).unwrap();
        let mut reference = near_limit::<Encrypting>(&key);
        reference.do_update_aad(b"aad").unwrap();
        let mut expected = [0; 64];
        reference.do_encrypt_out(&[0; 64], &mut expected).unwrap();
        assert_eq!(out[..64], expected);
        assert_eq!(enc.do_encrypt_final().unwrap(), reference.do_encrypt_final().unwrap());
    }

    #[test]
    fn inline_decryption_allows_the_last_ciphertext_block_plus_tag() {
        let key = key();
        let mut enc = near_limit::<Encrypting>(&key);
        let mut inline = [0; 80];
        enc.do_encrypt_out(&[0x42; 64], &mut inline[..64]).unwrap();
        inline[64..].copy_from_slice(&enc.do_encrypt_final().unwrap().0);
        let mut dec = near_limit::<Decrypting>(&key);
        let mut out = [0xa5; 65];
        assert!(matches!(
            dec.do_decrypt_out(&[0; 81], &mut out),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
        assert_eq!(out, [0; 65], "a refused call zeroizes its output buffer");
        assert_eq!(dec.held_len, 0);
        assert!(!dec.data_started);
        assert_eq!(dec.do_decrypt_out(&inline, &mut out).unwrap(), 64);
        assert_eq!(dec.data_len, MAX_MESSAGE_LEN);
        assert_eq!(dec.do_decrypt_final().unwrap().1, 0);
        assert_eq!(&out[..64], &[0x42; 64]);
        assert_eq!(out[64], 0, "bytes past the returned count are zero");
    }

    #[test]
    fn detached_final_checks_the_limit_and_clears_its_buffer() {
        let key = key();
        let mut dec = near_limit::<Decrypting>(&key);
        // The update must reserve a possible inline tag. Only detached finalization can know
        // that these extra 16 bytes are actually ciphertext exceeding the counter limit.
        dec.do_decrypt_out(&[0; 80], &mut [0; 64]).unwrap();
        let mut out = [0xa5; 16];
        assert!(matches!(
            dec.do_decrypt_final_detached_out(&[0; 16], &mut out),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
        assert_eq!(out, [0; 16]);
    }

    #[test]
    fn aad_length_overflow_is_rejected_before_absorption() {
        let key = key();
        let mut cipher = fresh::<Encrypting>(&key);
        let mut reference = fresh::<Encrypting>(&key);
        cipher.aad_len = u64::MAX - 1;
        reference.aad_len = u64::MAX - 1;
        assert!(matches!(cipher.absorb_aad(&[1, 2]), Err(SymmetricCipherError::StateError(_))));
        assert_eq!(cipher.aad_len, u64::MAX - 1);
        cipher.absorb_aad(&[1]).unwrap();
        reference.absorb_aad(&[1]).unwrap();
        cipher.absorb_aad(&[]).unwrap();
        assert_eq!(cipher.aad_len, u64::MAX);
        assert_eq!(cipher.finish_tag(), reference.finish_tag());
    }
}
