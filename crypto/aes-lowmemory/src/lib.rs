//! A constant-time, table-free AES block cipher engine (NIST FIPS 197).
//!
//! This crate provides the raw AES keyed permutation -- [`Aes128`], [`Aes192`] and [`Aes256`] --
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
//! ```
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let aes = Aes128::new(&key).expect("a valid AES-128 key");
//!
//! // FIPS 197 Appendix B.
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
//! Where a caller has two, [`Aes::encrypt_blocks2`] is roughly twice the throughput of two
//! [`Aes::encrypt_block`] calls:
//!
//! ```
//! use bouncycastle_aes_lowmemory::Aes256;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let aes = Aes256::new(&key).expect("a valid AES-256 key");
//!
//! let mut blocks = [[0u8; 16], [1u8; 16]];
//! aes.encrypt_blocks2(&mut blocks);
//! aes.decrypt_blocks2(&mut blocks);
//! assert_eq!(blocks, [[0u8; 16], [1u8; 16]]);
//! ```
//!
//! ## CBC mode
//!
//! To encrypt more than one block, use a mode of operation from `bouncycastle-modes`. This crate
//! provides [`AES_CBC_128`], [`AES_CBC_192`] and [`AES_CBC_256`] as aliases that fill in the const
//! parameters, with the direction left as the type parameter:
//!
//! ```
//! use bouncycastle_aes_lowmemory::AES_CBC_256;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let plaintext = [[0u8; 16], [1u8; 16], [2u8; 16]];
//!
//! // The IV is generated for you and returned; there is no API for supplying one.
//! let (iv, ciphertext) = AES_CBC_256::<Encrypting>::encrypt_blocks(&key, &plaintext).unwrap();
//! let recovered = AES_CBC_256::<Decrypting>::decrypt_blocks(&key, &iv, &ciphertext).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! There is no one-shot static on the permutation, because `Aes128::new(&key)?.encrypt_block(..)`
//! already *is* the one shot. Data-level one-shots belong to the modes of operation, which take
//! arbitrary-length input and generate their own initialisation data.
//!
//! # Design
//!
//! ## Why not a lookup table
//!
//! FIPS 197 Sec 5.1.1 presents the S-box as a table (Table 4), and almost every AES
//! implementation stores it as one -- 256 bytes, or 2-8 KiB for the "T-table" variants that fold
//! MIXCOLUMNS() in. The trouble is that a table indexed by a byte of the state is indexed by
//! secret data, so on any CPU with a data cache the memory access pattern, and hence the timing,
//! depends on the key. That is a practical, repeatedly-demonstrated attack, and it is not fixable
//! while the lookup remains.
//!
//! Bouncy Castle's `AESLightEngine` in the Java and C# ports keeps two 256-byte S-box tables for
//! exactly this reason -- to be *small*, not to be constant-time -- and leaks through both the
//! cipher and the key schedule.
//!
//! ## Bit-slicing
//!
//! This crate has no tables at all. The state is transposed so that each of eight `u32` words
//! holds one *bit position* of every byte: word `q[k]` collects bit `k` of all the bytes. In that
//! form the S-box becomes a fixed Boolean circuit -- 32 AND, 77 XOR and 4 XNOR gates, the
//! 113-gate straight-line program of Boyar and Peralta -- and one `&` or `^` applies a gate to
//! every byte position at once. Nothing is ever indexed by a secret, and nothing branches on one.
//!
//! Eight 32-bit words hold 32 bytes, which is two AES blocks, so blocks are processed in pairs.
//! SHIFTROWS() and MIXCOLUMNS() become masks and rotations in the same representation, and the
//! key schedule is stored bit-sliced too, so no transposition happens inside the round loop. The
//! exact bit layout, and the derivation of every mask from it, is documented in the `bitslice`
//! and `round` modules -- those two module docs are the place to start when reading the source.
//!
//! Decryption follows FIPS 197 Algorithm 3, the straight inverse cipher, rather than the
//! equivalent inverse cipher of Sec 5.3.5. Algorithm 3 puts INVMIXCOLUMNS() after ADDROUNDKEY(),
//! so it uses the *unmodified* key schedule; the equivalent inverse cipher would need a second
//! schedule with each round key transformed. One [`Aes`] value therefore encrypts and decrypts
//! from one stored schedule.
//!
//! # Memory Usage
//!
//! There are no lookup tables and no heap allocation. The only persistent state is the key
//! schedule, which is `4 * (Nr + 1)` words -- exactly the size FIPS 197 Sec 5.2 defines, with the
//! bit-sliced form compressed so that bit-slicing costs nothing in space:
//!
//! | Type | Key | `Nr` | Schedule (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`Aes128`] | 16 B | 10 | 176 B | 0 B |
//! | [`Aes192`] | 24 B | 12 | 208 B | 0 B |
//! | [`Aes256`] | 32 B | 14 | 240 B | 0 B |
//!
//! Per-call stack usage is independent of key length: 32 bytes of bit-sliced state for the two
//! blocks, 32 bytes for the round key expanded from its compressed form, plus the S-box circuit's
//! temporaries, most of which the compiler keeps in registers.
//!
//! For comparison, `AESLightEngine` carries 512 bytes of tables and a T-table implementation
//! carries 2-8 KiB, in both cases *on top of* a key schedule of this same size.
//!
//! Measure with `cargo run --release -p mem_usage_benches --bin bench_aes_mem_usage`.
//!
//! # Security Considerations
//!
//! ## A block permutation is not a cipher
//!
//! [`Aes128`] and friends transform exactly 16 bytes. Using them directly on data means ECB,
//! which is not confidential: identical plaintext blocks produce identical ciphertext blocks, so
//! structure in the plaintext survives encryption. **Do not do it.** Use a mode of operation, and
//! prefer an authenticated one so that ciphertext tampering is detected.
//!
//! ## Constant-time properties
//!
//! By construction there is no secret-dependent memory access and no secret-dependent branch,
//! in the cipher *or* in the key schedule -- SUBWORD() goes through the same circuit as
//! SUBBYTES(). The only branches are the round loops, which count over the public `Nr`.
//!
//! Caveats worth stating plainly:
//!
//! * The Rust compiler makes no guarantee it will preserve this. The code is written so that the
//!   natural code generation is straight-line, and `#![forbid(unsafe_code)]` rules out the usual
//!   ways of forcing the issue, but the property is not contractual.
//! * The 32-byte working state is not scrubbed after a block. Only the key schedule is wrapped in
//!   `Secret`, and so only it is guaranteed to be zeroized on drop.
//! * Constant-time execution says nothing about power or electromagnetic side channels.
//!
//! # Provenance
//!
//! * Normative reference: **NIST FIPS 197** (Advanced Encryption Standard), including Update 1.
//!   Every transformation cites its section, algorithm and equation numbers.
//! * The S-box circuit is the 113-gate straight-line program `SLP_AES_113.txt` from Peralta's
//!   circuit collection, described in J. Boyar and R. Peralta, "A new combinational logic
//!   minimization technique with applications to cryptology",
//!   <https://eprint.iacr.org/2009/191.pdf>.
//! * The bit-sliced two-block structure, the transpose, and the SHIFTROWS()/MIXCOLUMNS() mask and
//!   rotation constants are translated from BearSSL's `aes_ct` implementation by Thomas Pornin
//!   (MIT licence). Each constant is re-derived from the documented bit layout in the comments,
//!   and each is pinned by a test against a byte-wise reference written from the FIPS 197
//!   equations.
//! * Verified against FIPS 197 Appendix A (all three key expansions, every word), FIPS 197
//!   Appendix B, NIST SP 800-38A Appendix F.1 (ECB, all three key lengths, both directions), and
//!   the NIST ACVP `ACVP-AES-ECB` vectors.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// `AesParams` is deliberately sealed with a private supertrait so that no fourth parameter set can
// be added outside this crate; that is what triggers this lint.
#![allow(private_bounds)]

mod aes;
mod bitslice;
mod cbc;
mod round;
mod sbox;
mod schedule;

pub use aes::{Aes, Aes128, Aes192, Aes256, BLOCK_LEN};
pub use bitslice::Block;
pub use cbc::{AES_CBC_128, AES_CBC_192, AES_CBC_256};
pub use schedule::{Aes128Params, Aes192Params, Aes256Params, AesParams};
