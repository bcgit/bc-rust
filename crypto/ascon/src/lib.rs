//! Ascon-based lightweight cryptography (NIST SP 800-232).
//!
//! This crate implements the four Ascon functions standardized in NIST SP 800-232 (August 2025):
//!
//! - [`ascon_aead128::AsconAead128`] — Ascon-AEAD128 authenticated encryption (128-bit
//!   key/nonce/tag, 128-bit single-key security).
//! - [`ascon_hash256::AsconHash256`] — Ascon-Hash256 hash function (256-bit digest, 128-bit
//!   security).
//! - [`ascon_xof128::AsconXof128`] — Ascon-XOF128 extendable-output function.
//! - [`ascon_cxof128::AsconCXof128`] — Ascon-CXOF128 customized extendable-output function.
//!
//! # Usage Examples
//!
//! Hashing (one-shot and streaming):
//! ```
//! use bouncycastle_ascon::ascon_hash256::AsconHash256;
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_core::traits::XOF;
//!
//! // One-shot:
//! let digest = AsconHash256::digest(b"hello world");
//! assert_eq!(digest.len(), 32);
//!
//! // Streaming:
//! let mut h = AsconHash256::new();
//! h.do_update(b"hello ");
//! h.do_update(b"world");
//! let mut out = [0u8; 32];
//! h.do_final_out(&mut out);
//! assert_eq!(out, digest);
//! ```
//!
//! Authenticated encryption (one-shot):
//! ```
//! use bouncycastle_ascon::ascon_aead128::AsconAead128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//! let nonce = [1u8; 16];           // MUST be unique per encryption under a given key
//! let ad = b"associated data";
//! let plaintext = b"secret message";
//!
//! let mut ct = vec![0u8; plaintext.len() + 16]; // ciphertext || 16-byte tag
//! let n = AsconAead128::encrypt(&key, &nonce, Some(ad), plaintext, &mut ct).unwrap();
//! ct.truncate(n);
//!
//! let mut pt = vec![0u8; ct.len() - 16];
//! let m = AsconAead128::decrypt(&key, &nonce, Some(ad), &ct, &mut pt).unwrap();
//! pt.truncate(m);
//! assert_eq!(&pt, plaintext);
//! ```
//!
//! Authenticated encryption (streaming, detached tag). The decryptor holds back the last 16
//! bytes it has seen, in case they are an inline tag, so `do_final_out_detached` is where they come out:
//! ```
//! use bouncycastle_ascon::ascon_aead128::{AsconAead128Decryptor, AsconAead128Encryptor};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! let plaintext = b"secret message!!";
//! let (mut enc, nonce) = AsconAead128Encryptor::do_encrypt_init(&key).unwrap();
//! enc.do_update_aad(b"associated data").unwrap();
//! let mut ciphertext = [0u8; 16];
//! enc.do_update_out(plaintext, &mut ciphertext).unwrap();
//! let mut final_buf = [0u8; 16];
//! let (_, tag) = enc.do_final_out_detached(&mut final_buf).unwrap();
//!
//! let mut dec = AsconAead128Decryptor::do_decrypt_init(&key, &nonce).unwrap();
//! dec.do_update_aad(b"associated data").unwrap();
//! let mut recovered = [0u8; 16];
//! let n = dec.do_update_out(&ciphertext, &mut recovered).unwrap(); // 0: all 16 held back
//! let m = dec.do_final_out_detached(&tag, &mut final_buf).unwrap(); // now authenticated
//! recovered[n..n + m].copy_from_slice(&final_buf[..m]);
//! assert_eq!(&recovered, plaintext);
//! ```
//!
//! For the inline `ciphertext || tag` layout that most wire formats and files use, the pair is
//! also a [`bouncycastle_core::traits::SymmetricCipherEncryptor`] /
//! [`bouncycastle_core::traits::SymmetricCipherDecryptor`], which covers the no-AAD case --
//! streaming, or through its `encrypt_out` / `decrypt_out` one-shots -- and
//! [`bouncycastle_core::traits::AEADCipherEncryptor::encrypt_out_with_aad`] /
//! [`bouncycastle_core::traits::AEADCipherDecryptor::decrypt_out_with_aad`] are the one-shots with AAD:
//! ```
//! use bouncycastle_ascon::ascon_aead128::{AsconAead128Decryptor, AsconAead128Encryptor};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//! let plaintext = b"secret message!!";
//!
//! // No AAD: just a symmetric cipher.
//! let mut inline = [0u8; 32]; // AsconAead128Encryptor::encrypt_out_len(16)
//! let (nonce, len) = AsconAead128Encryptor::encrypt_out(&key, plaintext, &mut inline).unwrap();
//! assert_eq!(len, plaintext.len() + 16); // ciphertext || tag
//! let mut recovered = [0u8; 16];
//! let n = AsconAead128Decryptor::decrypt_out(&key, &nonce, &inline[..len], &mut recovered).unwrap();
//! assert_eq!(&recovered[..n], plaintext);
//!
//! // With AAD.
//! let (nonce, len) = AsconAead128Encryptor::encrypt_out_with_aad(&key, b"aad", plaintext, &mut inline).unwrap();
//! let n = AsconAead128Decryptor::decrypt_out_with_aad(&key, &nonce, b"aad", &inline[..len], &mut recovered).unwrap();
//! assert_eq!(&recovered[..n], plaintext);
//! ```
//!
//! Extendable output:
//! ```
//! use bouncycastle_ascon::ascon_xof128::AsconXof128;
//! use bouncycastle_core::traits::XOF;
//!
//! let out = AsconXof128::new().xof(b"input", 64);
//! assert_eq!(out.len(), 64);
//! ```
//!
//! # Memory Usage
//!
//! Ascon is a lightweight, permutation-based design intended for constrained devices. The internal
//! permutation state is 320 bits (40 bytes), held as five `u64` words, shared by all four
//! functions. There are no heap allocations in the streaming/`*_out` APIs, and stack usage is
//! small and constant; consequently this crate has no dedicated `mem_usage_benches` harness.
//!
//! | Type | In-memory size (bytes) | Suspended state size (bytes) |
//! |------|-------------------------|-------------------------------|
//! | [`ascon_aead128::AsconAead128`] | 72 | [`ascon_aead128::SUSPENDED_ASCON_AEAD128_STATE_LEN`] (46) |
//! | [`ascon_hash256::AsconHash256`] | 64 | [`ascon_hash256::SUSPENDED_ASCON_HASH256_STATE_LEN`] (53) |
//! | [`ascon_xof128::AsconXof128`] | 64 | [`ascon_xof128::SUSPENDED_ASCON_XOF128_STATE_LEN`] (54) |
//! | [`ascon_cxof128::AsconCXof128`] | 64 | [`ascon_cxof128::SUSPENDED_ASCON_CXOF128_STATE_LEN`] (54) |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target.
//!
//! # Security Considerations
//!
//! - **Nonce uniqueness (SP 800-232 R3):** a (key, nonce) pair must never be reused for two
//!   different Ascon-AEAD128 encryptions. Nonce reuse breaks confidentiality.
//! - **Tag length:** this crate always produces and verifies the full 128-bit tag. Truncated tags
//!   (SP 800-232 §4.2.1) are not exposed.
//! - **No partial-byte input:** Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 are byte-oriented;
//!   their `do_final_partial_bits`/`do_final_partial_bits_out` (and the equivalent XOF methods)
//!   always return `HashError::InvalidInput`, including when reached through `HashFactory`. A
//!   caller that needs a partial-byte final block should reach for SHA-3, which supports one.
//! - **Decryption tag check failure:** a ciphertext decryption whose finalization returns
//!   `Err(SymmetricCipherError::AEADTagCheckFailed)` must be treated as tampered, and the entire
//!   plaintext rejected. The one-shot APIs ([`ascon_aead128::AsconAead128::decrypt`],
//!   [`bouncycastle_core::traits::AEADCipherDecryptor::decrypt_out_detached`],
//!   [`bouncycastle_core::traits::AEADCipherDecryptor::decrypt_out_with_aad`] and
//!   [`bouncycastle_core::traits::SymmetricCipherDecryptor::decrypt_out`]) zeroize their output
//!   buffer before returning that error. The streaming API
//!   ([`ascon_aead128::AsconAead128::do_decrypt_update`] /
//!   [`ascon_aead128::AsconAead128::do_decrypt_final`], or `do_update_out` followed by
//!   [`bouncycastle_core::traits::AEADCipherDecryptor::do_final_out_detached`] or
//!   [`bouncycastle_core::traits::SymmetricCipherDecryptor::do_final`]) does not: plaintext
//!   bytes are necessarily written to the caller's buffer *before* the tag can be checked, so an
//!   application streaming a large plaintext must have a way to cancel the operation or
//!   transaction if finalization returns an error.

// `bouncycastle-core` still uses `Vec` internally (see the TODO at the top of
// crypto/core/src/lib.rs), which blocks this crate from being `#![no_std]` as long as it depends
// on core's `std`-gated APIs.
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod permutation;
mod sponge;

pub mod ascon_aead128;
pub use ascon_aead128::Ascon_AEAD128;
pub mod ascon_cxof128;
pub mod ascon_hash256;
pub mod ascon_xof128;

/// Algorithm name for Ascon-AEAD128.
pub const ASCON_AEAD128_NAME: &str = "Ascon-AEAD128";
/// Algorithm name for Ascon-Hash256.
pub const ASCON_HASH256_NAME: &str = "Ascon-Hash256";
/// Algorithm name for Ascon-XOF128.
pub const ASCON_XOF128_NAME: &str = "Ascon-XOF128";
/// Algorithm name for Ascon-CXOF128.
pub const ASCON_CXOF128_NAME: &str = "Ascon-CXOF128";
