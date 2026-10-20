//! Ascon-based lightweight cryptography (NIST SP 800-232).
//!
//! Ascon is a family of lightweight cryptographic algorithms designed for constrained
//! environments where conventional cryptographic standards such as AES-GCM, SHA-2,
//! and SHA-3 may be comparatively resource-intensive.
//!
//! NIST selected the Ascon family for lightweight cryptography standardization in 2023.
//! The standardized algorithms are based on, but are not compatible with, the earlier
//! Ascon algorithms selected for the final portfolio of the CAESAR competition in 2019.
//!
//! The Ascon family uses common underlying permutations across authenticated encryption,
//! hashing, and extendable-output functions. This allows implementations to share logic
//! between the different primitives. The algorithms are also single-pass and inverse-free;
//! Ascon-AEAD128 additionally supports online processing.
//!
//! This crate implements the four Ascon functions standardized in NIST SP 800-232
//! (August 2025), which can be found here: <https://doi.org/10.6028/NIST.SP.800-232>
//!
//! - [`Ascon-AEAD128`](Ascon_AEAD128) — authenticated encryption (128-bit key/nonce/tag, 128-bit
//!   single-key security), used through [`AsconAEAD128Key`].
//! - [`Ascon-Hash256`](AsconHash256) — hash function (256-bit digest, 128-bit security).
//! - [`Ascon-XOF128`](AsconXof128) — extendable-output function.
//! - [`Ascon-CXOF128`](AsconCXof128) — customized extendable-output function.
//!
//! # Usage Examples
//!
//! Hashing (one-shot and streaming):
//! ```
//! use bouncycastle_ascon::AsconHash256;
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_core::traits::XOF;
//!
//! // One-shot:
//! let digest = AsconHash256::new().hash(b"hello world");
//! assert_eq!(digest.len(), 32);
//!
//! // Streaming:
//! let mut h = AsconHash256::new();
//! h.do_update(b"hello ");
//! h.do_update(b"world");
//! let mut out = [0u8; 32];
//! h.do_final_out(&mut out);
//! assert_eq!(&out[..], &digest[..]);
//! ```
//!
//! Authenticated encryption (one-shot, under a nonce the caller manages), through the key:
//! ```
//! use bouncycastle_ascon::AsconAEAD128Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//!
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AsconAEAD128Key::from_key_material(&material).unwrap();
//! let nonce = [1u8; 16];           // MUST be unique per encryption under a given key
//! let ad = b"associated data";
//! let plaintext = b"secret message";
//!
//! let mut ct = vec![0u8; plaintext.len() + 16]; // ciphertext || 16-byte tag
//! let n = key.encrypt_with_aad_nonce_out(&nonce, ad, plaintext, &mut ct).unwrap();
//! ct.truncate(n);
//!
//! let mut pt = vec![0u8; ct.len() - 16];
//! let m = key.decrypt_with_aad_out(&nonce, ad, &ct, &mut pt).unwrap();
//! pt.truncate(m);
//! assert_eq!(&pt, plaintext);
//! ```
//!
//! Authenticated encryption (streaming, detached tag), with the nonce drawn from the caller's
//! RNG. The decryptor holds back the last 16 bytes it has seen, in case they are an inline tag,
//! so `do_decrypt_final_detached_out` is where they come out:
//! ```
//! use bouncycastle_ascon::AsconAEAD128Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AsconAEAD128Key::from_key_material(&material).unwrap();
//!
//! let plaintext = b"secret message!!";
//! let (mut enc, nonce) = key.create_encryptor(&mut rng).unwrap();
//! enc.do_update_aad(b"associated data").unwrap();
//! let mut ciphertext = [0u8; 16];
//! enc.do_encrypt_out(plaintext, &mut ciphertext).unwrap();
//! let mut final_buf = [0u8; 16];
//! let (_, tag) = enc.do_encrypt_final_detached_out(&mut final_buf).unwrap();
//!
//! let mut dec = key.create_decryptor(&nonce);
//! dec.do_update_aad(b"associated data").unwrap();
//! let mut recovered = [0u8; 16];
//! let n = dec.do_decrypt_out(&ciphertext, &mut recovered).unwrap(); // 0: all 16 held back
//! let m = dec.do_decrypt_final_detached_out(&tag, &mut final_buf).unwrap(); // authenticated
//! recovered[n..n + m].copy_from_slice(&final_buf[..m]);
//! assert_eq!(&recovered, plaintext);
//! ```
//!
//! For the inline `ciphertext || tag` layout that most wire formats and files use, the key's
//! `encrypt_with_aad_out` / `decrypt_with_aad_out` are the one-shots, with an empty AAD when
//! there is none, and the workers are also a
//! [`bouncycastle_core::traits::SymmetricCipherEncryptor`] /
//! [`bouncycastle_core::traits::SymmetricCipherDecryptor`] pair for streaming it:
//! ```
//! use bouncycastle_ascon::AsconAEAD128Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AsconAEAD128Key::from_key_material(&material).unwrap();
//! let plaintext = b"secret message!!";
//!
//! let mut inline = [0u8; 32]; // plaintext.len() + 16
//! let (len, nonce) = key.encrypt_with_aad_out(&mut rng, b"aad", plaintext, &mut inline).unwrap();
//! assert_eq!(len, plaintext.len() + 16); // ciphertext || tag
//! let mut recovered = [0u8; 16];
//! let n = key.decrypt_with_aad_out(&nonce, b"aad", &inline[..len], &mut recovered).unwrap();
//! assert_eq!(&recovered[..n], plaintext);
//! ```
//!
//! Extendable output:
//! ```
//! use bouncycastle_ascon::AsconXof128;
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
//! functions. There are no lookup tables and no heap allocations in the streaming/`*_out` APIs.
//! The persistent state, held between calls, does not depend on how much data has been processed:
//!
//! | Type | In-memory size (bytes) | Suspended state size (bytes) |
//! |------|-------------------------|-------------------------------|
//! | [`AsconAEAD128Key`] | 16 | |
//! | [`Ascon_AEAD128<Encrypting>`] | 96 | [`SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN`] (46) |
//! | [`Ascon_AEAD128<Decrypting>`] | 96 | [`SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN`] (63) |
//! | [`AsconHash256`] | 64 | [`SUSPENDED_ASCON_HASH256_STATE_LEN`] (53) |
//! | [`AsconXof128`] | 64 | [`SUSPENDED_ASCON_XOF128_STATE_LEN`] (54) |
//! | [`AsconCXof128`] | 64 | [`SUSPENDED_ASCON_CXOF128_STATE_LEN`] (54) |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target. Both directions carry the 16 bytes
//! the decrypting side holds back in case they are the inline tag, and their count; the encrypting
//! side leaves them unused.
//!
//! Per-call stack usage is separate from that and does not depend on the data length either.
//! Measured as the deepest frame chain below each entry point in the release build (x86-64 Linux,
//! rustc 1.97.0-nightly, return addresses included; `bench_ascon_mem_usage` has the harness and
//! the method):
//!
//! | Ascon-AEAD128 entry point | Encrypting | Decrypting |
//! |---|---|---|
//! | `AsconAEAD128Key::from_key_material` (the key check, once per key) | 24 B | 24 B |
//! | `create_encryptor` / `create_decryptor` | 120 B | 48 B |
//! | `do_update_aad` | 48 B | 48 B |
//! | `do_encrypt_out` / `do_decrypt_out` | 176 B | 208 B |
//! | `do_encrypt_final` / `do_decrypt_final` (tag inline) | 112 B | 256 B |
//! | `do_encrypt_final_detached_out` / `do_decrypt_final_detached_out` | 112 B | 288 B |
//! | `encrypt_with_aad_out` / `decrypt_with_aad_out` (one-shot) | 520 B | 640 B |
//!
//! The encrypting `create_encryptor` figure includes the call into the caller's RNG but not the
//! RNG's own stack; the one-shots are the role traits' provided bodies, which copy the message
//! through a 64-byte chunk on the stack, and the decrypting one holds the tag back as well.
//!
//! | Sponge entry point | Ascon-Hash256 | Ascon-XOF128 | Ascon-CXOF128 |
//! |---|---|---|---|
//! | `with_customization` | | | 192 B |
//! | `do_update` | 64 B | 64 B | 64 B |
//! | `do_final_out` / `do_output_out` | 144 B | 96 B | 96 B |
//! | `hash_out` / `xof_out` (one-shot) | 144 B | 160 B | 160 B |
//!
//! The sponges' `new` copies a precomputed state and runs no permutation.
//!
//! # 🚨 Security Considerations 🚨
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
//!   plaintext rejected. The key's one-shots
//!   ([`bouncycastle_core::symmetric_key::AeadDecryptionKey::decrypt_detached_out`] and
//!   [`bouncycastle_core::symmetric_key::AeadDecryptionKey::decrypt_with_aad_out`]) zeroize
//!   their output buffer before returning that error. The streaming API (`do_decrypt_out` followed by
//!   [`bouncycastle_core::traits::AEADCipherDecryptor::do_decrypt_final_detached_out`] or
//!   [`bouncycastle_core::traits::SymmetricCipherDecryptor::do_decrypt_final`]) does not: plaintext
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

mod ascon_aead128;
mod ascon_cxof128;
mod ascon_hash256;
mod ascon_xof128;

pub use ascon_aead128::{
    Ascon_AEAD128, AsconAEAD128Key, KEY_LEN, NONCE_LEN,
    SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN, SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN,
    TAG_LEN,
};
pub use ascon_cxof128::{AsconCXof128, AsconCXof128Squeezer, SUSPENDED_ASCON_CXOF128_STATE_LEN};
pub use ascon_hash256::{AsconHash256, SUSPENDED_ASCON_HASH256_STATE_LEN};
pub use ascon_xof128::{AsconXof128, AsconXof128Squeezer, SUSPENDED_ASCON_XOF128_STATE_LEN};

/// Algorithm name for Ascon-AEAD128.
pub const ASCON_AEAD128_NAME: &str = "Ascon-AEAD128";
/// Algorithm name for Ascon-Hash256.
pub const ASCON_HASH256_NAME: &str = "Ascon-Hash256";
/// Algorithm name for Ascon-XOF128.
pub const ASCON_XOF128_NAME: &str = "Ascon-XOF128";
/// Algorithm name for Ascon-CXOF128.
pub const ASCON_CXOF128_NAME: &str = "Ascon-CXOF128";
