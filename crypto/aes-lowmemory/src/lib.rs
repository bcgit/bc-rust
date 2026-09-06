//! A constant-time, table-free AES block cipher implementation according to NIST FIPS 197.
//!
//! This crate provides the raw AES keyed permutation -- [`AES_128`], [`AES_192`] and [`AES_256`] --
//! implemented as a Boolean circuit over bit-planes rather than as byte substitutions through a
//! lookup table. That makes it both smaller and constant-time; see [Design](#design).
//!
//! It is a *permutation*, not a cipher you can encrypt data with. See
//! [Security Considerations](#security-considerations).
//!
//! # Usage Examples
//!
//! ## Encrypting and decrypting a single block
//!
//! 🚨 Security Note 🚨 : This crate exposes only the single-block primitive (equivalent to ECB mode)
//! and is not generally secure to use on its own, but instead is a building block for higher-level
//! constructions such as AES_CBC or AES_GCM.
//!
//! ```
//! use bouncycastle_aes_lowmemory::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! // Instantiate the key schedule and create an object ready to encrypt or decrypt.
//! let aes = AES_128::new(&key).expect("a valid AES-128 key");
//!
//! // This is not quite a "plaintext" since it has to be exactly one block (16 bytes) wide.
//! // Example from FIPS 197 Appendix B.
//! let mut block = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!                  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
//! aes.encrypt_block(&mut block);
//! assert_eq!(block, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
//!                    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);
//!
//! // The same value decrypts, from the same schedule -- there is no separate decryptor.
//! aes.decrypt_block(&mut block);
//! assert_eq!(block, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!                    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
//! ```
//!
//! ## Two blocks at a time
//!
//! The bit-sliced state holds two blocks, so two independent blocks cost barely more than one.
//! Where a caller has two, [`AES::encrypt_2blocks`] is roughly twice the throughput of two
//! [`AES::encrypt_block`] calls:
//!
//! ```
//! use bouncycastle_aes_lowmemory::AES_256;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let aes = AES_256::new(&key).expect("a valid AES-256 key");
//!
//! let mut blocks = [[0u8; 16], [1u8; 16]];
//! aes.encrypt_2blocks(&mut blocks);
//! aes.decrypt_2blocks(&mut blocks);
//! assert_eq!(blocks, [[0u8; 16], [1u8; 16]]);
//! ```
//!
//! # Design
//!
//! ## No lookup table!
//!
//! FIPS 197 Sec 5.1.1 presents the S-box as a table (Table 4), and most software AES
//! implementation store it as one. The trouble is that a table indexed by a byte of the state is
//! indexed by secret data, so on any CPU with a data cache the memory access pattern, and hence the
//! timing, depends on the key. That is a practical, repeatedly-demonstrated attack, and it is not
//! fixable with a lookup table-based implementation.
//!
//! This implementation uses instead the 113-gate straight-line S-box circuit `SLP_AES_113.txt` from
//! Peralta's circuit collection, described in J. Boyar and R. Peralta, "A new combinational logic
//! minimization technique with applications to cryptology", <https://eprint.iacr.org/2009/191.pdf>.
//!
//! See [Constant Time](#constant-time-properties) for more discussion.
//!
//! # Memory Usage
//!
//! This is an all-stack, no-heap implementation. The only persistent state within the [`AES`] struct
//! is the key schedule, which is `4 * (Nr + 1)` 32-bit words.
//!
//! | Type | Key | AES struct |
//! |---|---|---|---|---|
//! | [`AES_128`] | 16 B | 176 B |
//! | [`AES_192`] | 24 B | 208 B |
//! | [`AES_256`] | 32 B | 240 B |
//!
//! Measured with `cargo run --release -p mem_usage_benches --bin bench_aes_mem_usage`.
// dev todo: if we can improve our testing framework to measure stack usages this small,
//           it would be nice to add columns for stack usage of the encrypt and decrypt functions.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## A block permutation is not a cipher
//!
//! The [`AES`] function implemented in this crate is a building block for safe and secure AES
//! constructions, **but it must not be used directly to encrypt data**.
//!
//! It transforms exactly 16 bytes where the same input
//! block always gives the same output block; a mode called Electronic Code Book (ECB).
//! This by itself offers almost no security because even though the permutation is unique per key,
//! once an attacker who knows the structure or partial content of the plaintext message con relatively
//! easily build a dictionary of plaintext blocks to ciphertext blocks and fully decrypt the message.
//!
//! ## Constant-time properties
//!
//! By construction there is no secret-dependent memory access and no secret-dependent branch,
//! in the cipher *or* in the key schedule.
//! The only branches are the round loops, which count over the public value `Nr`.
//!
//! As with all cryptography written in pure safe rust, the Rust compiler makes no guarantee it will
//! preserve constant-time behaviours through its optimizations.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// `AesParams` is deliberately sealed with a private supertrait so that no fourth parameter set can
// be added outside this crate; that is what triggers this lint.
#![allow(private_bounds)]
// Turn off clippy on names because we want names to match exactly FIPS 197, even if that goes against
// Rust convention.
#![allow(non_camel_case_types)]

mod aes;
mod bitslice;
mod round;
mod sbox;
mod schedule;

pub use aes::{AES, AES_128, AES_192, AES_256, BLOCK_LEN, Block};
pub use schedule::{AES128Params, AES192Params, AES256Params, AESParams};
