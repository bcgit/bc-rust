//! IETF ChaCha20, as specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
//!
//! [`ChaCha20Encryptor`] and [`ChaCha20Decryptor`] implement the core stream-cipher traits
//! and their symmetric-cipher supertraits. Generated nonces start the counter at zero.
//! [`ChaCha20::new`] accepts an explicit nonce and counter for protocols and test vectors.
//! Never reuse a nonce under the same key, or overlap counter ranges for that key/nonce.
//! This cipher provides no authentication; use ChaCha20-Poly1305 for authenticated encryption.
//! Only the RFC's 32-byte key and 12-byte nonce variant is supported.
//!
//! ```
//! use bouncycastle_chacha20::{ChaCha20Encryptor, ChaCha20Decryptor};
//! use bouncycastle_core::{key_material::{KeyMaterial, KeyType}, traits::{StreamCipherEncryptor, StreamCipherDecryptor}};
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let mut message = *b"message";
//! let (_, nonce) = ChaCha20Encryptor::encrypt_in_place(&key, &mut message).unwrap();
//! ChaCha20Decryptor::decrypt_in_place(&key, &nonce, &mut message).unwrap();
//! assert_eq!(&message, b"message");
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::stream_cipher::{stream_do_final, stream_update_out};
use bouncycastle_core::traits::{
    Algorithm, RNG, StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::secret::Secret;

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// Keystream block length in bytes.
pub const BLOCK_LEN: usize = 64;

/// Stateful IETF ChaCha20 with an explicit nonce and initial block counter.
///
/// Each call continues the same keystream, including unused bytes of a partial block.
/// Secret state and buffered keystream are zeroized on drop. There is no reset or clone API.
pub struct ChaCha20 {
    state: Secret<[u32; 16]>,
    keystream: Secret<[u8; BLOCK_LEN]>,
    position: usize,
    // A u64 represents the exhausted sentinel 2^32 without wrapping into the nonce.
    next_counter: u64,
}

impl Algorithm for ChaCha20 {
    const ALG_NAME: &'static str = "ChaCha20";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

impl ChaCha20 {
    /// Initializes a stream at `initial_counter` with caller-supplied nonce bytes.
    ///
    /// The caller must ensure the key/nonce is unique for encryption. In particular, do not
    /// use this raw stream with the key/nonce of an AEAD message: block zero contains its MAC key.
    /// Rejects keys of the wrong length, type, or less than 256-bit tagged security strength.
    pub fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        initial_counter: u32,
    ) -> Result<Self, SymmetricCipherError> {
        if key.key_len() != KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "ChaCha20 requires a symmetric cipher key",
            )
            .into());
        }
        if key.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(
                KeyMaterialError::SecurityStrength("ChaCha20 requires a 256-bit key").into()
            );
        }
        let mut state: Secret<[u32; 16]> = Secret::new();
        state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
        for (word, bytes) in state[4..12].iter_mut().zip(key.ref_to_bytes().chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        for (word, bytes) in state[13..].iter_mut().zip(nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        Ok(Self {
            state,
            keystream: Secret::new(),
            position: BLOCK_LEN,
            next_counter: u64::from(initial_counter),
        })
    }

    /// Number of bytes still available before the 32-bit counter is exhausted.
    pub fn remaining_bytes(&self) -> u64 {
        ((1u64 << 32) - self.next_counter) * BLOCK_LEN as u64 + (BLOCK_LEN - self.position) as u64
    }

    /// Encrypts or decrypts in place, continuing from the previous call.
    ///
    /// Returns `data.len()`. A call exceeding [`Self::remaining_bytes`] returns
    /// [`SymmetricCipherError::StateError`] without changing either the buffer or the stream.
    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        if data.len() as u64 > self.remaining_bytes() {
            return Err(SymmetricCipherError::StateError("ChaCha20 counter exhausted"));
        }
        let mut offset = 0;
        while offset < data.len() {
            if self.position == BLOCK_LEN {
                self.generate_block();
            }
            let n = (BLOCK_LEN - self.position).min(data.len() - offset);
            for (byte, mask) in data[offset..offset + n]
                .iter_mut()
                .zip(&self.keystream[self.position..self.position + n])
            {
                *byte ^= mask;
            }
            self.position += n;
            offset += n;
        }
        Ok(data.len())
    }

    fn generate_block(&mut self) {
        self.state[12] = self.next_counter as u32;
        let mut working = self.state.clone();
        for _ in 0..10 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }
        for i in 0..16 {
            self.keystream[4 * i..4 * i + 4]
                .copy_from_slice(&working[i].wrapping_add(self.state[i]).to_le_bytes());
        }
        self.next_counter += 1;
        self.position = 0;
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// ChaCha20 encryption with a generated 96-bit nonce and initial counter zero.
pub struct ChaCha20Encryptor(ChaCha20);

/// ChaCha20 decryption with the encryption nonce and initial counter zero.
pub struct ChaCha20Decryptor(ChaCha20);

impl Algorithm for ChaCha20Encryptor {
    const ALG_NAME: &'static str = ChaCha20::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ChaCha20::MAX_SECURITY_STRENGTH;
}

impl Algorithm for ChaCha20Decryptor {
    const ALG_NAME: &'static str = ChaCha20::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ChaCha20::MAX_SECURITY_STRENGTH;
}

impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, 0> for ChaCha20Encryptor {
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
        Ok((Self(ChaCha20::new(key, &nonce, 0)?), nonce))
    }

    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        stream_update_out(plaintext, ciphertext, |data| self.do_encrypt(data))
    }

    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        stream_do_final()
    }

    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

impl StreamCipherEncryptor<KEY_LEN, NONCE_LEN> for ChaCha20Encryptor {
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        self.0.apply_keystream(data)
    }
}

impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, 0> for ChaCha20Decryptor {
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self(ChaCha20::new(key, nonce, 0)?))
    }

    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        stream_update_out(ciphertext, plaintext, |data| self.do_decrypt(data))
    }

    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        stream_do_final()
    }

    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

impl StreamCipherDecryptor<KEY_LEN, NONCE_LEN> for ChaCha20Decryptor {
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        self.0.apply_keystream(data)
    }
}
