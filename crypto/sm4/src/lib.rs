//! A constant-time, table-free SM4 block cipher engine (GB/T 32907-2016), ported from Bouncy
//! Castle Java's `SM4Engine`.
//!
//! This crate provides the raw SM4 keyed permutation -- [`SM4`] -- a 128-bit block cipher with a
//! single 128-bit key length, standardised by the State Cryptography Administration of China as
//! GB/T 32907-2016 and described in English in the CFRG document `draft-ribose-cfrg-sm4-10`, which
//! is the specification every comment in this crate cites. The S-box is evaluated as a Boolean
//! circuit over bit-planes rather than looked up in a table, so the engine is constant-time; see
//! [Design](#design).
//!
//! It is a *permutation*, not a cipher you can encrypt data with. See
//! [Security Considerations](#security-considerations).
//!
//! # Usage Examples
//!
//! ## Encrypting and decrypting a single block
//!
//! ```
//! use bouncycastle_sm4::SM4;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! // GB/T 32907-2016 Example 1 (draft-ribose-cfrg-sm4-10 Appendix A.1.1).
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let sm4 = SM4::new(&key).expect("a valid SM4 key");
//!
//! let mut block = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!                  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
//! sm4.encrypt_block(&mut block);
//! assert_eq!(block, [0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
//!                    0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46]);
//!
//! // The same value decrypts, from the same round keys -- there is no separate decryptor.
//! sm4.decrypt_block(&mut block);
//! assert_eq!(block, [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);
//! ```
//!
//! ## Eight blocks at a time
//!
//! The bit-sliced S-box substitutes 32 bytes per pass, and a round substitutes four bytes per
//! block, so eight independent blocks cost the same as one. Where a caller has eight,
//! [`SM4::encrypt_8blocks`] is eight times the throughput of eight [`SM4::encrypt_block`] calls:
//!
//! ```
//! use bouncycastle_sm4::{SM4, LANES};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let sm4 = SM4::new(&key).expect("a valid SM4 key");
//!
//! let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [i as u8; 16]);
//! let original = blocks;
//! sm4.encrypt_8blocks(&mut blocks);
//! sm4.decrypt_8blocks(&mut blocks);
//! assert_eq!(blocks, original);
//! ```
//!
//! ## CBC mode
//!
//! To encrypt more than one block, use a mode of operation from `bouncycastle-modes`. This crate
//! provides [`SM4_CBC`] as an alias that fills in the const parameters, with the direction left as
//! the type parameter:
//!
//! ```
//! use bouncycastle_sm4::SM4_CBC;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! // 48 bytes: three whole blocks. A length that is not a multiple of 16 would not compile.
//! let plaintext = [0x5Au8; 48];
//!
//! // Encryption is in place. The IV is generated for you and returned; there is no API for
//! // supplying one.
//! let mut data = plaintext;
//! let iv = SM4_CBC::<Encrypting>::encrypt(&key, &mut data).unwrap();
//! assert_ne!(data, plaintext);
//! SM4_CBC::<Decrypting>::decrypt(&key, &iv, &mut data).unwrap();
//! assert_eq!(data, plaintext);
//! ```
//!
//! There is no one-shot static on the permutation, because `SM4::new(&key)?.encrypt_block(..)`
//! already *is* the one shot. Data-level one-shots belong to the modes of operation, which take
//! arbitrary-length input and generate their own initialisation data.
//!
//! # Design
//!
//! SM4 is a 32-round unbalanced Feistel network over four 32-bit words (Sec 4). Each round
//! replaces the oldest word with `X_0 xor T(X_1 xor X_2 xor X_3 xor rk_i)` (Sec 6.1), where `T`
//! is four parallel S-box lookups followed by a fixed linear map of five rotations (Sec 6.2).
//! Decryption is the same 32 rounds with the round keys in reverse order (Sec 7.2), and the key
//! schedule (Sec 7.3) is the same recurrence again with a different linear map and a constant
//! added each round.
//!
//! ## Why not a lookup table
//!
//! Sec 6.2.3 presents the S-box as a table (Figure 1), and BC Java's `SM4Engine` stores it as one.
//! A table indexed by a byte of the state is indexed by secret data, so on any CPU with a data
//! cache the memory access pattern, and hence the timing, depends on the key and the data. That
//! is the classic cache-timing attack on table-driven block ciphers, and it is not fixable while
//! the lookup remains -- in the cipher or in the key schedule, whose `T'` also goes through the
//! S-box.
//!
//! ## The S-box as a circuit
//!
//! This crate has no table outside its tests. The S-box has the same algebraic shape as the AES
//! one -- an affine map, inversion in GF(2^8) (modulo `x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1`
//! rather than the AES polynomial), and another affine map -- a decomposition found here by
//! exhaustive search against the Figure 1 table, not taken from recall. A field isomorphism into
//! the AES representation then lets the 62-gate non-linear section of the Boyar-Peralta AES
//! circuit, copied verbatim from `bouncycastle-aes`, do the inversion, with new affine
//! top and bottom layers derived by linear algebra and pinned by an exhaustive 256-input test.
//! The whole S-box is 127 gates: 32 AND, 82 XOR, 12 XNOR, 1 NOT. The `sbox` module docs give the
//! full derivation.
//!
//! A round substitutes only four bytes per block, and the circuit's eight `u32` planes hold 32
//! byte positions, so the engine works on **eight blocks at once**: each round forms the argument
//! of `T` for every block, transposes the eight words into planes, runs the circuit once,
//! transposes back, and finishes the round per block. The blocks never mix. Everything else in
//! the round -- the XORs, the five rotations of `L` -- is already constant-time on words, so the
//! rest of the engine is the straightforward word-oriented port of BC Java, with the roles of the
//! four state words rotating instead of the words moving (BC Java's `F0`..`F3`).
//!
//! Beyond the S-box, the port differs from the Java engine in three ways: one stored schedule
//! serves both directions (Java expands the key in reverse when initialised for decryption); the
//! block methods are infallible (the run-time buffer and initialisation checks are compile-time
//! facts here); and [`SM4::new`] requires a key tagged as a symmetric cipher key of at least
//! 128-bit strength, as every cipher in this workspace does.
//!
//! # Memory Usage
//!
//! No heap allocation and no lookup tables. The persistent state is the 32 round keys of Sec 7.3:
//!
//! | Type | Key | Rounds | Schedule (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`SM4`] | 16 B | 32 | 128 B | 0 B |
//!
//! Per-call stack usage is the eight-block working state -- four words per block, 128 bytes --
//! plus the eight planes of the S-box argument (32 bytes) and the circuit's temporaries, most of
//! which the compiler keeps in registers. Measure with
//! `cargo run --release -p mem_usage_benches --bin bench_sm4_mem_usage`.
//!
//! For comparison, BC Java's `SM4Engine` carries a 256-byte table on top of the same schedule.
//!
//! # Security Considerations
//!
//! ## A block permutation is not a cipher
//!
//! [`SM4`] transforms exactly 16 bytes. Using it directly on data means ECB, which is not
//! confidential: identical plaintext blocks produce identical ciphertext blocks, so structure in
//! the plaintext survives encryption (the specification's own Sec 12 says SM4-ECB "SHOULD NOT be
//! used in most cases"). **Do not do it.** Use a mode of operation, and prefer an authenticated
//! one so that ciphertext tampering is detected.
//!
//! ## Constant-time properties
//!
//! By construction there is no secret-dependent memory access and no secret-dependent branch, in
//! the cipher *or* in the key schedule: `T'` goes through the same circuit as `T`. The only
//! branches are the round loop and the lane loops, which count over public constants.
//!
//! Caveats worth stating plainly:
//!
//! * The Rust compiler makes no guarantee it will preserve this. The code is written so that the
//!   natural code generation is straight-line, and `#![forbid(unsafe_code)]` rules out the usual
//!   ways of forcing the issue, but the property is not contractual.
//! * The eight-block working state is not scrubbed after a call. Only the round keys are wrapped
//!   in `Secret`, and so only they are guaranteed to be zeroized on drop.
//! * Constant-time execution says nothing about power or electromagnetic side channels, which
//!   Sec 12 of the specification specifically raises for SM4 hardware.
//!
//! ## Regulatory note
//!
//! SM4 is a Chinese national standard. Sec 12 of the specification notes that products using
//! cryptography are regulated by the State Cryptography Administration and must be approved before
//! sale or use in China. Nothing in this crate addresses that.
//!
//! # Provenance
//!
//! * **Source implementation: Bouncy Castle Java `org.bouncycastle.crypto.engines.SM4Engine`**,
//!   whose `FK` and `CK` tables, round structure and key schedule this crate reproduces, and
//!   whose S-box table is the reference the circuit is verified against. A direct transcription
//!   of the Java engine lives in the tests (`tests/common/mod.rs`) and the engine is checked
//!   against it on thousands of inputs.
//! * **Normative reference: GB/T 32907-2016**, read via `draft-ribose-cfrg-sm4-10`, "The SM4
//!   Blockcipher Algorithm And Its Modes Of Operations" (Tse, Wong, Saarinen; CFRG, April 2018).
//!   Every function cites its section. The S-box and `CK` tables were extracted mechanically from
//!   the text of the draft and found byte-for-byte identical to BC Java's; `CK` is additionally
//!   re-derived from its defining formula in a test.
//! * **The non-linear section of the S-box circuit** is from the 113-gate straight-line program
//!   `SLP_AES_113.txt` in Peralta's circuit collection, described in J. Boyar and R. Peralta, "A
//!   new combinational logic minimization technique with applications to cryptology",
//!   <https://eprint.iacr.org/2009/191.pdf>, as transcribed in `bouncycastle-aes`. The
//!   algebraic structure of the SM4 S-box that makes the reuse possible is analysed in Liu, Ji,
//!   Hu, Ding and Lv, "Analysis of the SMS4 Block Cipher" (ACISP 2007); here it was re-derived by
//!   search and verified exhaustively.
//! * **The bit-plane transpose** is translated from BearSSL's `aes_ct` by Thomas Pornin (MIT
//!   licence), as in the AES crate.
//! * Verified against every value in the draft's Appendix A.1 -- Examples 1 through 6, including
//!   all 32 round keys and all 32 per-round outputs of Examples 1 and 4, and the two 1,000,000-fold
//!   iterated ciphertexts -- the SM4-ECB and SM4-CBC vectors of Appendix A.2.1 and A.2.2, and the
//!   vectors of BC Java's `SM4Test` (core and provider), which are GB/T 32907-2016's own two
//!   examples as republished at <https://eprint.iacr.org/2008/329.pdf>.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod bitslice;
mod cbc;
mod sbox;
mod schedule;
mod sm4;

pub use cbc::SM4_CBC;
pub use sm4::{BLOCK_LEN, Block, KEY_LEN, LANES, SM4};
