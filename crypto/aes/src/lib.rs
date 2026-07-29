//! This crate implements the Advanced Encryption Standard (AES) block cipher engine as per
//! FIPS 197 (updated May 2023).
//!
//! All three key sizes of the Standard are provided: [`AES128`], [`AES192`] and [`AES256`].
//!
//! # What a block cipher engine is (and is not)
//!
//! A block cipher is "a family of permutations of blocks that is parameterized by a sequence of
//! bits called the key" (FIPS 197 Section 1). This crate provides exactly that permutation, on one
//! 128-bit block at a time:
//!
//! * [`AESEngine::encrypt_block`] is `CIPHER()`, FIPS 197 Algorithm 1.
//! * [`AESEngine::decrypt_block`] is `INVCIPHER()`, FIPS 197 Algorithm 3.
//!
//! It is a building block, not something you should encrypt a message with directly. Encrypting
//! data requires a **mode of operation** layered on top -- CBC, CTR, GCM and so on -- which is what
//! turns a 16-byte permutation into something that can safely handle a message of any length. FIPS
//! 197 itself is explicit about this: "The algorithm shall be used in conjunction with a
//! FIPS-approved or NIST-recommended mode of operation" (announcement section 8), and the modes are
//! specified separately in the NIST SP 800-38 series.
//!
//! Consequently this crate deliberately does **not** implement the library's
//! [`SymmetricCipher`](bouncycastle_core::traits::SymmetricCipher),
//! [`BlockCipher`](bouncycastle_core::traits::BlockCipher) or
//! [`AEADCipher`](bouncycastle_core::traits::AEADCipher) traits, and there is no `bc-rust` CLI
//! subcommand for it. Those interfaces are about encrypting *data*: they generate and carry
//! initialization vectors, handle padding, and authenticate. Those are properties of a mode, not of
//! the permutation, and the only mode that a raw engine can offer -- ECB -- must not be presented
//! as a general-purpose way to encrypt (see "Security Considerations" below). When the
//! mode-of-operation crates land, they will be the types that implement those traits, take the CLI
//! subcommands, and carry the per-mode algorithm OIDs.
//!
//! # Usage Examples
//!
//! ## Encrypting and decrypting a single block
//!
//! ```rust
//! use bouncycastle_aes::{AES128, AES128Key, AESEngine};
//! use bouncycastle_core::key_material::KeyType;
//!
//! // The key and plaintext from the worked example in FIPS 197 Appendix B.
//! let key = AES128Key::from_bytes_as_type(
//!     &[
//!         0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
//!     ],
//!     KeyType::SymmetricCipherKey,
//! )
//! .unwrap();
//!
//! // Expanding the key is the expensive part, so do it once...
//! let engine = AES128::new(&key).unwrap();
//!
//! // ... then use the engine for as many blocks as you like.
//! let plaintext = [
//!     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
//! ];
//! let ciphertext = engine.encrypt_block(&plaintext);
//!
//! assert_eq!(
//!     ciphertext,
//!     [
//!         0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
//!         0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
//!     ]
//! );
//! assert_eq!(engine.decrypt_block(&ciphertext), plaintext);
//! ```
//!
//! ## The one-shot API
//!
//! For a single block there is a static take-data-return-result form that expands the key, uses it,
//! and scrubs it again:
//!
//! ```rust
//! use bouncycastle_aes::{AES256, AES256Key};
//! use bouncycastle_core::key_material::KeyType;
//! use bouncycastle_hex as hex;
//!
//! let key = AES256Key::from_bytes_as_type(
//!     &hex::decode("603deb1015ca71be2b73aef0857d7781
//!                   1f352c073b6108d72d9810a30914dff4")
//!         .unwrap(),
//!     KeyType::SymmetricCipherKey,
//! )
//! .unwrap();
//!
//! let plaintext: [u8; 16] =
//!     hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap().try_into().unwrap();
//!
//! let ciphertext = AES256::encrypt_single_block(&key, &plaintext).unwrap();
//! assert_eq!(hex::encode(&ciphertext), "f3eed1bdb5d2a03c064b5a7e3db181f8");
//! ```
//!
//! ## Writing into a caller-owned buffer
//!
//! Every operation has an `_out` form that writes into a buffer you provide, for callers that want
//! to control where the bytes land:
//!
//! ```rust
//! use bouncycastle_aes::{AES192, AES192Key, AESEngine, AES_BLOCK_LEN};
//! use bouncycastle_core::key_material::KeyType;
//! use bouncycastle_hex as hex;
//!
//! let key = AES192Key::from_bytes_as_type(
//!     &hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
//!     KeyType::SymmetricCipherKey,
//! )
//! .unwrap();
//! let engine = AES192::new(&key).unwrap();
//!
//! let plaintext: [u8; AES_BLOCK_LEN] =
//!     hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap().try_into().unwrap();
//!
//! let mut ciphertext = [0u8; AES_BLOCK_LEN];
//! let bytes_written = engine.encrypt_block_out(&plaintext, &mut ciphertext);
//!
//! assert_eq!(bytes_written, AES_BLOCK_LEN);
//! assert_eq!(hex::encode(&ciphertext), "bd334f1d6e45f25ff712a214571fa5cc");
//! ```
//!
//! ## Writing code that is generic over the key size
//!
//! [`AESEngine`] is implemented by all three variants, so code that only needs the block
//! permutation -- a mode of operation, for instance -- can be written once:
//!
//! ```rust
//! use bouncycastle_aes::{AES128, AES128Key, AESEngine, AES_BLOCK_LEN};
//! use bouncycastle_core::key_material::KeyType;
//! use bouncycastle_core::traits::Algorithm;
//!
//! /// Encrypts each block of `blocks` in place. (This is ECB mode: see the security notes!)
//! fn encrypt_all<E: AESEngine>(engine: &E, blocks: &mut [[u8; AES_BLOCK_LEN]]) {
//!     for block in blocks.iter_mut() {
//!         *block = engine.encrypt_block(block);
//!     }
//! }
//!
//! let key = AES128Key::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
//! let engine = AES128::new(&key).unwrap();
//!
//! let mut blocks = [[0u8; AES_BLOCK_LEN]; 4];
//! encrypt_all(&engine, &mut blocks);
//!
//! assert_eq!(AES128::ALG_NAME, "AES-128");
//! assert_eq!(<AES128 as AESEngine>::NUM_ROUNDS, 10);
//! ```
//!
//! # Memory Usage
//!
//! An engine holds nothing but its expanded key schedule: `4 * (Nr + 1)` 32-bit words
//! (FIPS 197 Section 5.2). There is no other state, so an engine costs the same whether it has
//! encrypted no blocks or a billion.
//!
//! | Engine    | Key schedule | Struct size (`size_of`) |
//! |-----------|--------------|-------------------------|
//! | [`AES128`] | 44 words     | 176 bytes               |
//! | [`AES192`] | 52 words     | 208 bytes               |
//! | [`AES256`] | 60 words     | 240 bytes               |
//!
//! Those sizes are asserted by a test in `tests/aes_tests.rs`, so this table cannot drift away from
//! the code.
//!
//! Stack usage of the block operations is a small constant: one 16-byte working state plus the
//! 16-byte output block, no heap allocation, no recursion, and no variable-length buffers. It does
//! not vary with the key size, the number of blocks processed, or anything an attacker controls.
//! That is why this crate has no harness in `/mem_usage_benches`: there is nothing to measure that
//! the table above does not already tell you. A mode of operation that buffers partial blocks will
//! be a different story.
//!
//! For the same reason there is no
//! [`Suspendable`](bouncycastle_core::traits::Suspendable) or
//! [`SuspendableKeyed`](bouncycastle_core::traits::SuspendableKeyed) implementation: those exist so
//! that an algorithm carrying state across a `do_update()`/`do_final()` sequence can be paused and
//! resumed. An engine carries no such state -- every block operation takes `&self` and completes --
//! so the only thing there would be to serialize is the key schedule, and serializing key material
//! is exactly what those traits are designed to avoid. A streaming mode of operation, which does
//! carry state between calls, is where that becomes relevant.
//!
//! # Security Considerations
//!
//! ## Do not use a raw block cipher to encrypt data
//!
//! Calling [`AESEngine::encrypt_block`] once per block *is* ECB mode. ECB encrypts equal plaintext
//! blocks to equal ciphertext blocks, which leaks the structure of the plaintext (this is the
//! famous "ECB penguin"), and it provides no integrity protection whatsoever, so an attacker can
//! reorder, duplicate or splice your blocks undetected. Use an authenticated mode of operation.
//!
//! If you find yourself reaching for this crate directly to protect data, that is the signal that
//! you want a mode instead.
//!
//! ## Key hygiene
//!
//! Keys are passed as [`KeyMaterial`](bouncycastle_core::key_material::KeyMaterial) so that the
//! library can check that the bytes you handed over really are a full-entropy symmetric cipher key
//! of the right length, and so that they are scrubbed from memory when dropped. [`AES::new`]
//! rejects a key that is too short, tagged for a different algorithm, tagged at a lower security
//! strength than the variant needs, or all-zero (which arrives tagged
//! [`KeyType::Zeroized`](bouncycastle_core::key_material::KeyType::Zeroized)). Every one of those
//! rejections corresponds to a real, repeatedly-made deployment bug.
//!
//! The expanded key schedule is as sensitive as the key itself: the expansion is invertible, so any
//! four consecutive words of it recover the cipher key. It is held in a
//! [`Secret`](bouncycastle_utils::secret::Secret), which volatile-scrubs it when the engine drops
//! and refuses to print it in [`Debug`](core::fmt::Debug) output. The per-block working state is
//! scrubbed the same way.
//!
//! ## Cache-timing side channels
//!
//! This is a table-driven implementation: SUBBYTES() and the key expansion index a 256-byte S-box
//! with values derived from the key and the data. On a processor with a data cache, *which* cache
//! lines that touches depends on those secret values, and an attacker who can observe cache state
//! -- typically a process co-resident on the same machine -- may be able to recover key material.
//! FIPS 197 Section 6.4 names this attack explicitly, and it applies to every table-driven AES.
//!
//! What this crate does about it:
//!
//! * The GF(2^8) arithmetic and the state permutations are branch-free and table-free: no
//!   secret-dependent branches, no secret-dependent indices (see the module docs in `gf.rs`).
//! * Only the 256-byte S-box is used. The common 4 KiB "T-table" optimization, which folds
//!   MIXCOLUMNS() into the lookup, is faster but spreads each lookup across many more cache lines
//!   and measurably widens this side channel.
//! * The key expansion's control flow depends only on public parameters (`Nk` and the word index),
//!   never on key bytes.
//!
//! What it does not do: eliminate the S-box lookups. Doing so requires either a bitsliced
//! implementation or the CPU's AES instructions (AES-NI, ARMv8 Crypto Extensions), the latter being
//! unavailable to us since this library contains no assembly or intrinsics and forbids
//! `unsafe`. If you need resistance to a co-resident attacker, that is the direction to look.
//!
//! As with the rest of bc-rust: the constant-time properties claimed here are a best effort in safe
//! Rust, and Rust makes no guarantee that the optimizer preserves them.
//!
//! ## Keying restrictions
//!
//! There are none, beyond using a properly generated key: "When a cryptographic key has been
//! generated appropriately ... no restriction is imposed when the resulting key is used for the AES
//! algorithm" (FIPS 197 Section 6.2). There are no weak keys to avoid, and no key check values to
//! compute.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod aes;
mod gf;
mod key_schedule;
mod state;
mod tables;

/*** Exported types ***/
pub use aes::{AES, AES128, AES192, AES256, AESEngine};
pub use aes::{AES128Key, AES192Key, AES256Key};

/*** Exported constants ***/
pub use aes::{AES_128_NAME, AES_192_NAME, AES_256_NAME};
pub use aes::{AES128_KEY_LEN, AES192_KEY_LEN, AES256_KEY_LEN};
pub use aes::{AES128_KEY_SCHEDULE_WORDS, AES192_KEY_SCHEDULE_WORDS, AES256_KEY_SCHEDULE_WORDS};
pub use aes::{AES128_NUM_ROUNDS, AES192_NUM_ROUNDS, AES256_NUM_ROUNDS};
pub use state::AES_BLOCK_LEN;
