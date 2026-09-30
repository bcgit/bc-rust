//! ChaCha20-Poly1305 AEAD from [RFC 8439, section 2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8).
//!
//! The core [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] traits support streaming and
//! one-shot operations with either an inline or detached 16-byte tag. Keys are 32 bytes and
//! nonces 12 bytes. Encryption generates a nonce; protocols that supply their own may use
//! [`ChaCha20Poly1305Encryptor::new_with_nonce`], taking responsibility for nonce uniqueness.
//! A key/nonce may encrypt at most `64 * (2^32 - 1)` bytes. AAD must precede all data updates,
//! including empty updates. Empty AAD is always a no-op.
//!
//! Streaming decryption releases **unauthenticated** bytes: do not use them until finalization
//! succeeds, and erase them on failure. The one-shot trait methods erase their output on tag
//! failure. Secret state is zeroized on drop; streaming and output-buffer methods do not allocate.
//! This is the IETF construction, not the original 64-bit-nonce variant or XChaCha20.
//!
//! ```
//! use bouncycastle_chacha20_poly1305_aead::{ChaCha20Poly1305Encryptor as Enc, ChaCha20Poly1305Decryptor as Dec};
//! use bouncycastle_core::{key_material::{KeyMaterial, KeyType}, traits::{AEADCipherEncryptor, AEADCipherDecryptor}};
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let mut ciphertext = [0u8; 7];
//! let (nonce, n, tag) = Enc::encrypt_out_detached(&key, b"header", b"message", &mut ciphertext).unwrap();
//! let mut plaintext = [0u8; 7];
//! Dec::decrypt_out_detached(&key, &nonce, b"header", &ciphertext[..n], &tag, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, b"message");
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_chacha20::ChaCha20;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, MAC, RNG, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_poly1305::Poly1305;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::{ct, secret::Secret};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// Tag length, also the streaming final-buffer length, in bytes.
pub const TAG_LEN: usize = 16;
/// Maximum plaintext or ciphertext length (excluding the tag) per key/nonce.
pub const MAX_MESSAGE_LEN: u64 = u32::MAX as u64 * 64;

struct State {
    cipher: ChaCha20,
    mac: Poly1305,
    aad_len: u64,
    data_len: u64,
    data_started: bool,
}

impl State {
    fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        let mut cipher = ChaCha20::new(key, nonce, 0)?;
        let mut block: Secret<[u8; 64]> = Secret::new();
        cipher.apply_keystream(&mut *block)?;
        let mac_key = KeyMaterial::<32>::from_bytes_as_type(&block[..32], KeyType::MACKey)?;
        // This is a derived one-time key, including the (possible) all-zero value. Key strength
        // was already enforced on the parent cipher key; no entropy heuristic applies here.
        let mac = Poly1305::new_allow_weak_key(&mac_key)
            .expect("ChaCha20 supplies exactly 32 bytes of one-time MAC key");
        Ok(Self { cipher, mac, aad_len: 0, data_len: 0, data_started: false })
    }

    fn update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
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

    fn check_data_len(&self, length: usize) -> Result<(), SymmetricCipherError> {
        if length as u64 > self.cipher.remaining_bytes() {
            return Err(SymmetricCipherError::StateError(
                "ChaCha20-Poly1305 message limit exceeded",
            ));
        }
        Ok(())
    }

    fn start_data(&mut self) {
        if !self.data_started {
            self.mac.do_update(&[0u8; 15][..padding_len(self.aad_len)]);
            self.data_started = true;
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.check_data_len(data.len())?;
        self.start_data();
        self.cipher.apply_keystream(data)?;
        self.mac.do_update(data);
        self.data_len += data.len() as u64;
        Ok(())
    }

    fn decrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.check_data_len(data.len())?;
        self.start_data();
        self.mac.do_update(data);
        self.cipher.apply_keystream(data)?;
        self.data_len += data.len() as u64;
        Ok(())
    }

    fn tag(mut self) -> [u8; TAG_LEN] {
        self.start_data();
        self.mac.do_update(&[0u8; 15][..padding_len(self.data_len)]);
        self.mac.do_update(&self.aad_len.to_le_bytes());
        self.mac.do_update(&self.data_len.to_le_bytes());
        self.mac.finalize()
    }

    fn verify(self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        if ct::ct_eq_bytes(&self.tag(), tag) {
            Ok(())
        } else {
            Err(SymmetricCipherError::AEADTagCheckFailed)
        }
    }
}

fn padding_len(length: u64) -> usize {
    ((16 - (length & 15)) & 15) as usize
}

// Private-state boundary tests live beside the integration tests. They position the
// counter near exhaustion without processing a 256 GiB message or exposing a test API.
#[cfg(test)]
#[path = "../tests/internal/limits.rs"]
mod limits;

/// ChaCha20-Poly1305 encryption, with inline and detached tags through the core traits.
pub struct ChaCha20Poly1305Encryptor(State);

impl ChaCha20Poly1305Encryptor {
    /// Starts encryption using a protocol-supplied nonce.
    ///
    /// **Never reuse this nonce under the same key.** Prefer the trait constructors, which
    /// generate nonces. Reuse exposes plaintext relationships and compromises authentication.
    /// The key must have the cipher-key type, length 32, and 256-bit tagged security strength.
    pub fn new_with_nonce(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self(State::new(key, nonce)?))
    }
}

impl Algorithm for ChaCha20Poly1305Encryptor {
    const ALG_NAME: &'static str = "ChaCha20-Poly1305";
    // The cipher key has 256-bit strength; authentication is limited by the 128-bit tag.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20Poly1305Encryptor {
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        Self::do_encrypt_init_rng(key, &mut DefaultRNG::default())
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((Self::new_with_nonce(key, &nonce)?, nonce))
    }

    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        self.0.check_data_len(plaintext.len())?;
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.0.encrypt(out)?;
        Ok(plaintext.len())
    }

    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        Ok((self.0.tag(), TAG_LEN))
    }

    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len.saturating_add(TAG_LEN)
    }
}

impl AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20Poly1305Encryptor {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.0.update_aad(aad)
    }

    fn do_final_out_detached(
        self,
        _ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        Ok((0, self.0.tag()))
    }
}

/// ChaCha20-Poly1305 decryption. Holds back the last 16 bytes until the tag layout is known.
///
/// Treat all streaming output as untrusted until finalization succeeds. One-shot methods
/// provided by the core traits erase recovered plaintext when authentication fails.
pub struct ChaCha20Poly1305Decryptor {
    state: State,
    held: [u8; TAG_LEN],
    held_len: usize,
}

impl Algorithm for ChaCha20Poly1305Decryptor {
    const ALG_NAME: &'static str = ChaCha20Poly1305Encryptor::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        ChaCha20Poly1305Encryptor::MAX_SECURITY_STRENGTH;
}

impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20Poly1305Decryptor {
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self { state: State::new(key, nonce)?, held: [0u8; TAG_LEN], held_len: 0 })
    }

    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len.saturating_sub(TAG_LEN - self.held_len)
    }

    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let release = self.do_decrypt_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        self.state.check_data_len(release)?;
        let from_held = release.min(self.held_len);
        let from_input = release - from_held;
        let out = &mut plaintext[..release];
        out[..from_held].copy_from_slice(&self.held[..from_held]);
        out[from_held..].copy_from_slice(&ciphertext[..from_input]);
        // Even a zero-length update ends the AAD phase, as required by the core traits.
        self.state.decrypt(out)?;
        let kept = self.held_len - from_held;
        self.held.copy_within(from_held..self.held_len, 0);
        let new_len = kept + ciphertext.len() - from_input;
        self.held[kept..new_len].copy_from_slice(&ciphertext[from_input..]);
        self.held_len = new_len;
        Ok(release)
    }

    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.held_len != TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        self.state.verify(&self.held)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20Poly1305Decryptor {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.state.update_aad(aad)
    }

    fn do_final_out_detached(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let n = self.held_len;
        let mut last: Secret<[u8; TAG_LEN]> = Secret::new();
        last[..n].copy_from_slice(&self.held[..n]);
        plaintext.fill(0);
        self.state.decrypt(&mut last[..n])?;
        self.state.verify(tag)?;
        plaintext[..n].copy_from_slice(&last[..n]);
        Ok(n)
    }
}
