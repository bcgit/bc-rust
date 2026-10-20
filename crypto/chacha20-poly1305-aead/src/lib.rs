//! ChaCha20-Poly1305 AEAD from [RFC 8439, section 2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8).
//!
//! [`ChaCha20_Poly1305<Encrypting>`] / [`ChaCha20_Poly1305<Decrypting>`] is the cipher with the
//! direction in its type, implementing the core [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`]
//! traits for streaming and one-shot operations with either an inline or detached 16-byte tag.
//! Keys are 32 bytes and nonces 12 bytes. Encryption generates a nonce; protocols that supply
//! their own may use [`AEADCipherEncryptor::do_encrypt_init_nonce`], taking responsibility for
//! nonce uniqueness. A key/nonce may encrypt at most `64 * (2^32 - 1)` bytes. AAD must precede all
//! data updates, including empty updates. Empty AAD is always a no-op. Secret state is zeroized on
//! drop; streaming and output-buffer methods do not allocate. This is the IETF construction, not
//! the original 64-bit-nonce variant or XChaCha20.
//!
//! # Usage Examples
//!
//! One-shot, with a detached tag:
//!
//! ```
//! use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_core::{key_material::{KeyMaterial, KeyType}, traits::{AEADCipherEncryptor, AEADCipherDecryptor}};
//!
//! type Enc = ChaCha20_Poly1305<Encrypting>;
//! type Dec = ChaCha20_Poly1305<Decrypting>;
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let mut ciphertext = [0u8; 7];
//! let (nonce, n, tag) = Enc::encrypt_detached_out(&key, b"header", b"message", &mut ciphertext).unwrap();
//! let mut plaintext = [0u8; 7];
//! Dec::decrypt_detached_out(&key, &nonce, b"header", &ciphertext[..n], &tag, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, b"message");
//! ```
//!
//! Streaming, with the tag inline after the ciphertext:
//!
//! ```
//! use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//!
//! type Enc = ChaCha20_Poly1305<Encrypting>;
//! type Dec = ChaCha20_Poly1305<Decrypting>;
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let (mut enc, nonce) = Enc::do_encrypt_init(&key).unwrap();
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
//! let mut dec = Dec::do_decrypt_init(&key, &nonce).unwrap();
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
//! | [`ChaCha20_Poly1305<Encrypting>`] | 384 |
//! | [`ChaCha20_Poly1305<Decrypting>`] | 384 |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target. There are no heap allocations and
//! no message-sized buffers, so this crate has no `mem_usage_benches` harness.
//!
//! # 🚨 Security Considerations 🚨
//!
//! - Never reuse a nonce under the same key. The trait constructors generate one; a caller of
//!   [`AEADCipherEncryptor::do_encrypt_init_nonce`] is responsible for uniqueness. Reuse exposes
//!   the XOR of the plaintexts and lets an attacker forge tags.
//! - Streaming decryption releases **unauthenticated** bytes: do not use them until finalization
//!   succeeds, and erase them on failure. The one-shot trait methods erase their output on tag
//!   failure.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_chacha20::ChaCha20;
use bouncycastle_chacha20::hazmat::ChaCha20KeyStream;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, MAC, RNG, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
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

/// ChaCha20-Poly1305 (RFC 8439 Sec 2.8) in one direction: `Dir` is [`Encrypting`] or
/// [`Decrypting`], and only that direction's methods exist on the type, so the wrong direction is a
/// compile error. One instance performs one operation under one (key, nonce) pair.
///
/// Both directions take a [`KeyType::SymmetricCipherKey`] of 256-bit strength that is unbound or
/// bound to this type's [`Algorithm::ALG_NAME`]; a key bound to any other algorithm, plain
/// ChaCha20 included, is refused.
///
/// The encrypting side holds nothing back: `FINAL_LEN` is `TAG_LEN`, so the inline
/// [`SymmetricCipherEncryptor::do_encrypt_final`] writes only the tag. The decrypting side holds
/// back the last `TAG_LEN` bytes of ciphertext until the final, since until the stream ends they
/// may be the inline tag.
///
/// ```compile_fail
/// # use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
/// # use bouncycastle_cipher::Decrypting;
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// # let key = KeyMaterial::<32>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap();
/// let mut dec = ChaCha20_Poly1305::<Decrypting>::do_decrypt_init(&key, &[0u8; 12]).unwrap();
/// dec.do_encrypt_out(&[0u8; 4], &mut [0u8; 4]); // no such method on the decrypting type
/// ```
#[allow(non_camel_case_types)]
pub struct ChaCha20_Poly1305<Dir> {
    // The data keystream, from block counter 1. Decrypting, it is RFC 8439 Sec 2.8's "ChaCha20
    // encryption function ... applied to the ciphertext": both directions are the same XOR.
    cipher: ChaCha20<Dir>,
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

impl<Dir> Algorithm for ChaCha20_Poly1305<Dir> {
    const ALG_NAME: &'static str = "ChaCha20-Poly1305";
    // The cipher key has 256-bit strength; authentication is limited by the 128-bit tag.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

impl<Dir> ChaCha20_Poly1305<Dir> {
    /// The setup of both directions, under the caller's or a generated `nonce`.
    fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        // The key is bound, if at all, to this AEAD; `start_at` is the keystream constructor that
        // leaves that check to its caller, as GCM does with its CTR keystream.
        key.check_algorithm(Self::ALG_NAME)?;
        // RFC 8439 Sec 2.8: the one-time key is the first 32 bytes of block 0 (Sec 2.6.1,
        // poly1305_key_gen), and the data is encrypted "with the initial counter set to 1".
        // Taking block 0 leaves the keystream at counter 1, so the same keystream carries the data.
        let mut keystream = ChaCha20KeyStream::start_at(key, nonce, 0)?;
        let mut block: Secret<[[u8; 64]; 1]> = Secret::new();
        keystream.apply_blocks(&mut *block);
        let mac_key = KeyMaterial::<32>::from_bytes_as_type(&block[0][..32], KeyType::MACKey)?;
        // This is a derived one-time key, including the (possible) all-zero value. Key strength
        // was already enforced on the parent cipher key; no entropy heuristic applies here.
        let mac = Poly1305::new_allow_weak_key(&mac_key)
            .expect("ChaCha20 supplies exactly 32 bytes of one-time MAC key");
        Ok(Self {
            cipher: ChaCha20::from_keystream(keystream),
            mac,
            aad_len: 0,
            data_len: 0,
            data_started: false,
            held: [0u8; TAG_LEN],
            held_len: 0,
        })
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

impl ChaCha20_Poly1305<Encrypting> {
    fn encrypt_bytes(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.check_data_len(data.len())?;
        self.start_data();
        self.cipher.do_encrypt_inplace(data)?;
        self.mac.do_update(data);
        self.data_len += data.len() as u64;
        Ok(())
    }
}

impl ChaCha20_Poly1305<Decrypting> {
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

impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20_Poly1305<Encrypting> {
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
        Ok((Self::new(key, &nonce)?, nonce))
    }

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

impl AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20_Poly1305<Encrypting> {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    fn do_encrypt_init_nonce(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::new(key, nonce)
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

impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20_Poly1305<Decrypting> {
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::new(key, nonce)
    }

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

impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ChaCha20_Poly1305<Decrypting> {
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

#[cfg(test)]
mod tests {
    //! The message and AAD length limits. Reaching them through the public API means processing
    //! 256 GiB of data, or 2^64 bytes of AAD, so these position the private state next to the
    //! boundary instead: the "cannot be tested from integration tests" case QUALITY_AND_STYLE.md
    //! carves out for unit tests.

    use super::*;

    fn key() -> KeyMaterial<KEY_LEN> {
        KeyMaterial::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap()
    }

    fn fresh<Dir>() -> ChaCha20_Poly1305<Dir> {
        ChaCha20_Poly1305::new(&key(), &[9; 12]).unwrap()
    }

    /// One block of data left: the keystream at its last counter, and `data_len` to match.
    fn near_limit<Dir>() -> ChaCha20_Poly1305<Dir> {
        let mut cipher = fresh();
        // `check_data_len` relies on MAX_MESSAGE_LEN being exactly the data keystream's capacity.
        assert_eq!(cipher.cipher.keystream().remaining_blocks() * 64, MAX_MESSAGE_LEN);
        cipher.cipher = ChaCha20::from_keystream(
            ChaCha20KeyStream::start_at(&key(), &[9; 12], u32::MAX).unwrap(),
        );
        cipher.data_len = MAX_MESSAGE_LEN - 64;
        cipher
    }

    #[test]
    fn encryption_limit_errors_leave_state_and_output_untouched() {
        let mut enc = near_limit::<Encrypting>();
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
        let mut reference = near_limit::<Encrypting>();
        reference.do_update_aad(b"aad").unwrap();
        let mut expected = [0; 64];
        reference.do_encrypt_out(&[0; 64], &mut expected).unwrap();
        assert_eq!(out[..64], expected);
        assert_eq!(enc.do_encrypt_final().unwrap(), reference.do_encrypt_final().unwrap());
    }

    #[test]
    fn inline_decryption_allows_the_last_ciphertext_block_plus_tag() {
        let mut enc = near_limit::<Encrypting>();
        let mut inline = [0; 80];
        enc.do_encrypt_out(&[0x42; 64], &mut inline[..64]).unwrap();
        inline[64..].copy_from_slice(&enc.do_encrypt_final().unwrap().0);
        let mut dec = near_limit::<Decrypting>();
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
        let mut dec = near_limit::<Decrypting>();
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
        let mut cipher = fresh::<Encrypting>();
        let mut reference = fresh::<Encrypting>();
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
