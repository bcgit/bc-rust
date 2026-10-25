//! A constant-time, table-free, low-memory SM4 block cipher engine (GB/T 32907-2016), ported from
//! Bouncy Castle Java's `SM4Engine`.
//!
//! This crate provides SM4 -- a 128-bit block cipher with a single 128-bit key length,
//! standardised by the State Cryptography Administration of China as GB/T 32907-2016 and described
//! in English in the CFRG document `draft-ribose-cfrg-sm4-10`, which is the specification every
//! comment in this crate cites -- under the library's key objects: [`SM4Key<M>`], a key bound to
//! one mode `M`, validated and expanded once, handing out that mode's encryptors and decryptors.
//! The engine underneath, [`SM4Internal`], evaluates the S-box as a Boolean circuit over
//! bit-planes rather than looking it up in a table, so it is constant-time and carries no table at
//! all; the planes are 16 bits wide so that the working set stays small, which is what "lowmemory"
//! means here. See [Design](#design).
//!
//! The engine is a *permutation*, not a cipher you can encrypt data with, which is why it lives
//! under [`hazmat`]. See [Security Considerations](#security-considerations).
//!
//! # Usage Examples
//!
//! ## Modes of operation
//!
//! A key is built once, under a mode from `bouncycastle_cipher::modes`, and used for as many
//! messages as needed: `CBC<PKCS7>` for CBC (Sec 8.4; NIST SP 800-38A Sec 6.2) with PKCS#7
//! padding, `CFB` for SM4-CFB-128 (Sec 8.5.1), `CFB8` for SM4-CFB-8, the `s = 8` segment size,
//! which is a different and non-interoperable mode costing one SM4 call per byte, and `CTR` for
//! CTR (Sec 8.7) with a 12-byte nonce and a 4-byte counter. The aliases [`SM4_CBC`], [`SM4_CFB`],
//! [`SM4_CFB8`] and [`SM4_CTR`] name the workers the key hands out.
//!
//! CBC is a block cipher, so it is defined only on whole blocks and the key's mode carries a
//! padding scheme to bridge the difference; the CFB modes and CTR are stream ciphers and take any
//! length with no padding at all. See the `bouncycastle_cipher::modes` crate docs for the
//! comparison, and [`SM4_CBC`] for why the scheme is named in the type.
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = SM4Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid SM4 key");
//!
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // The IV is drawn from `rng` and returned; there is no API for supplying one.
//! let (iv, ciphertext) = key.encrypt(&mut rng, &plaintext).expect("encryption");
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! The stream modes take any length and return the initialisation data the same way:
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::CTR;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = SM4Key::<CTR>::from_key_material(&material).expect("a valid SM4 key");
//!
//! // 50 bytes, and the ciphertext is 50 bytes: no padding anywhere.
//! let plaintext = [0x5Au8; 50];
//! let mut data = plaintext;
//! let (_, nonce) = key.encrypt_inplace(&mut rng, &mut data).expect("encryption");
//! assert_ne!(data, plaintext);
//!
//! key.decrypt_inplace(&nonce, &mut data).expect("decryption");
//! assert_eq!(data, plaintext);
//! ```
//!
//! For the block-aligned API -- whole blocks in place, through the block role pair -- make the
//! key under `CBC<Blocks>`; the padded alias wraps the same worker.
//!
//! ## The raw permutation
//!
//! The engine transforms one block, and `ElectronicCodeBook::new` on it is the one-shot:
//!
//! ```
//! use bouncycastle_sm4::hazmat::SM4Internal;
//! use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! // GB/T 32907-2016 Example 1 (draft-ribose-cfrg-sm4-10 Appendix A.1.1).
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let sm4 = SM4Internal::new(&key).expect("a valid SM4 key");
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
//! ## Four blocks at a time
//!
//! The bit-sliced S-box substitutes 16 bytes per pass, and a round substitutes four bytes per
//! block, so four independent blocks cost the same as one. Where a caller has four,
//! [`SM4Internal::encrypt_4blocks`] is four times the throughput of four [`BlockPermutation::encrypt_block`](bouncycastle_core::hazmat::BlockPermutation::encrypt_block) calls, and it
//! is also the four-block batch [`BlockPermutation::encrypt_4blocks`](bouncycastle_core::hazmat::BlockPermutation::encrypt_4blocks) offers to modes:
//!
//! ```
//! use bouncycastle_sm4::hazmat::SM4Internal;
//! use bouncycastle_sm4::LANES;
//! use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let sm4 = SM4Internal::new(&key).expect("a valid SM4 key");
//!
//! let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [i as u8; 16]);
//! let original = blocks;
//! sm4.encrypt_4blocks(&mut blocks);
//! sm4.decrypt_4blocks(&mut blocks);
//! assert_eq!(blocks, original);
//! ```
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
//! Sec 6.2.3 presents the S-box as a table (Figure 1), and a straightforward implementation
//! stores it as one. A table indexed by a byte of the state is indexed by secret data, so on any
//! CPU with a data cache the memory access pattern, and hence the timing, depends on the key and
//! the data. That is the classic cache-timing attack on table-driven block ciphers, and it is not
//! fixable while the lookup remains -- in the cipher or in the key schedule, whose `T'` also goes
//! through the S-box.
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
//! A round substitutes only four bytes per block, and the circuit's eight `u16` planes hold 16
//! byte positions, so the engine works on **four blocks at once**: each round forms the argument
//! of `T` for every block, splits the four words into eight 16-bit halves, transposes them into
//! planes, runs the circuit once,
//! transposes back, and finishes the round per block. The blocks never mix. Everything else in
//! the round -- the XORs, the five rotations of `L` -- is already constant-time on words, so the
//! rest of the engine is a straightforward word-oriented implementation, with the roles of the
//! four state words rotating each round rather than the words themselves moving.
//!
//! Beyond the S-box, this port stores one schedule that serves both directions (a direction-aware
//! engine typically expands the key in reverse when initialised for decryption); the block methods
//! are infallible (the run-time buffer and initialisation checks are compile-time facts here); and
//! the constructors require a key tagged as a symmetric cipher key of at least 128-bit strength, as
//! every cipher in this workspace does.
//!
//! ## Why "lowmemory"
//!
//! Two things. First, no table: a table-driven engine typically carries a 256-byte S-box indexed
//! by secret data; here the S-box is code. Second, the working set. Eight `u32` planes would take
//! eight blocks per pass and double the throughput, but every per-call buffer -- the block state
//! and the planes -- would double with them. Four lanes over `u16` planes keep the whole per-call
//! working state near 100 bytes.
//!
//! # Memory Usage
//!
//! No heap allocation and no lookup tables. The persistent state is the 32 round keys of Sec 7.3,
//! held once in the key; a worker adds the mode's own state and a reference to the key:
//!
//! | Type | Key | Rounds | Schedule (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`SM4Internal`] | 16 B | 32 | 128 B | 0 B |
//!
//! Per-call stack usage is the four-block working state -- four words per block, 64 bytes --
//! plus the four `T` arguments (16 bytes), the eight `u16` planes of the S-box argument (16
//! bytes) and the circuit's temporaries, most of
//! which the compiler keeps in registers. Measure with
//! `cargo run --release -p mem_usage_benches --bin bench_sm4_mem_usage`.
//!
//! For comparison, a table-driven engine carries a 256-byte table on top of the same schedule.
//!
//! # Security Considerations
//!
//! ## A block permutation is not a cipher
//!
//! [`SM4Internal`] transforms exactly 16 bytes. Using it directly on data means ECB, which is not
//! confidential: identical plaintext blocks produce identical ciphertext blocks, so structure in
//! the plaintext survives encryption (the specification's own Sec 12 says SM4-ECB "SHOULD NOT be
//! used in most cases"). **Do not do it.** Use a mode of operation, and prefer an authenticated
//! one so that ciphertext tampering is detected.
//! That is why [`SM4Internal`] lives under [`hazmat`]; [`bouncycastle_core::hazmat`] lists the supported
//! uses.
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
//! * The four-block working state is not scrubbed after a call. Only the round keys are wrapped
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
//! * **Source engine.** The `FK` and `CK` tables, round structure and key schedule this crate
//!   reproduces, and the S-box table the circuit is verified against, come from the reference
//!   engine named at the top of this page. A direct transcription of it lives in the tests
//!   (`tests/common/mod.rs` and `tests/bc_java_tests.rs`), and this engine is checked against it on
//!   thousands of inputs.
//! * **Normative reference: GB/T 32907-2016**, read via `draft-ribose-cfrg-sm4-10`, "The SM4
//!   Blockcipher Algorithm And Its Modes Of Operations" (Tse, Wong, Saarinen; CFRG, April 2018).
//!   Every function cites its section. The S-box and `CK` tables were extracted mechanically from
//!   the text of the draft; `CK` is additionally re-derived from its defining formula in a test.
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
//!   iterated ciphertexts -- the SM4-ECB, SM4-CBC and SM4-CFB vectors of Appendix A.2.1, A.2.2 and
//!   A.2.4, the SM4-CTR vectors of Appendix A.2.5 (through a reference built from the Sec 8.7.1
//!   equations, which the `CTR` key is then held to -- see `tests/stream_mode_tests.rs` for
//!   why the published counter blocks are not ones it produces), plus GB/T 32907-2016's own
//!   two examples as republished at <https://eprint.iacr.org/2008/329.pdf>.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod bitslice;
mod cbc;
mod cfb;
mod cfb8;
mod ctr;
pub mod hazmat;
mod key;
mod sbox;
mod schedule;

/// The SM4 block length in bytes: 16 (Sec 4, "block size of 128 bits").
pub const BLOCK_LEN: usize = 16;

/// The SM4 key length in bytes: 16 (Sec 4, "key length of 128 bits"). There is only one.
pub const KEY_LEN: usize = 16;

/// The number of blocks the bit-sliced S-box substitutes at once. See
/// [`SM4Internal::encrypt_4blocks`].
pub const LANES: usize = 4;

pub use cbc::SM4_CBC;
pub use cfb::SM4_CFB;
pub use cfb8::SM4_CFB8;
pub use ctr::{CTR_NONCE_LEN, SM4_CTR};
pub use key::SM4Key;

// Imports needed for docs
#[allow(unused_imports)]
use hazmat::SM4Internal;
// end of imports needed for docs
