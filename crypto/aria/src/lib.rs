//! A constant-time, table-free, low-memory ARIA block cipher engine (RFC 5794), ported from
//! Bouncy Castle Java's `ARIAEngine`.
//!
//! This crate provides the raw ARIA keyed permutation -- [`ARIA_128`], [`ARIA_192`] and [`ARIA_256`]
//! -- a 128-bit block cipher with 128-, 192- and 256-bit keys, the Korean standard block cipher
//! (KS X 1213:2004) described in RFC 5794, which is the specification every comment in this crate
//! cites. The four S-boxes are evaluated as Boolean circuits over bit-planes rather than looked up
//! in tables, so the engine is constant-time and carries no tables at all; the planes are 16 bits
//! wide so that the working set stays small, which is what "lowmemory" means here. See
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
//! use bouncycastle_aria::ARIA_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! // RFC 5794 Appendix A.1, "128-Bit Key".
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let aria = ARIA_128::new(&key).expect("a valid ARIA-128 key");
//!
//! let mut block = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
//! aria.encrypt_block(&mut block);
//! assert_eq!(block, [0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73,
//!                    0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78]);
//!
//! // The same value decrypts, from the same round keys -- there is no separate decryptor.
//! aria.decrypt_block(&mut block);
//! assert_eq!(block, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
//! ```
//!
//! The 192- and 256-bit variants are [`ARIA_192`] and [`ARIA_256`], constructed from a
//! `KeyMaterial<24>` and a `KeyMaterial<32>`; a key of the wrong length does not compile.
//!
//! ## Four blocks at a time
//!
//! Each S-box circuit substitutes 16 bytes per pass and a substitution layer sends four bytes of
//! every block through each of the four S-boxes, so four independent blocks cost the same as one.
//! Where a caller has four, [`ARIA::encrypt_4blocks`] is four times the throughput of four
//! [`ARIA::encrypt_block`] calls, and it is also the four-block batch the `ElectronicCodeBook`
//! trait offers to modes:
//!
//! ```
//! use bouncycastle_aria::{ARIA_256, LANES};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let aria = ARIA_256::new(&key).expect("a valid ARIA-256 key");
//!
//! let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [i as u8; 16]);
//! let original = blocks;
//! aria.encrypt_4blocks(&mut blocks);
//! aria.decrypt_4blocks(&mut blocks);
//! assert_eq!(blocks, original);
//! ```
//!
//! ## CBC mode
//!
//! To encrypt more than one block, use a mode of operation from `bouncycastle-modes`. This crate
//! provides [`ARIA_CBC_128`], [`ARIA_CBC_192`] and [`ARIA_CBC_256`] as aliases that fill in the
//! const parameters, with the direction left as the type parameter:
//!
//! ```
//! use bouncycastle_aria::ARIA_CBC_256;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! // 48 bytes: three whole blocks. A length that is not a multiple of 16 would not compile.
//! let plaintext = [0x5Au8; 48];
//!
//! // Encryption is in place. The IV is generated for you and returned; there is no API for
//! // supplying one.
//! let mut data = plaintext;
//! let iv = ARIA_CBC_256::<Encrypting>::encrypt(&key, &mut data).unwrap();
//! assert_ne!(data, plaintext);
//! ARIA_CBC_256::<Decrypting>::decrypt(&key, &iv, &mut data).unwrap();
//! assert_eq!(data, plaintext);
//! ```
//!
//! There is no one-shot static on the permutation, because `ARIA_128::new(&key)?.encrypt_block(..)`
//! already *is* the one shot. Data-level one-shots belong to the modes of operation, which take
//! arbitrary-length input and generate their own initialisation data.
//!
//! # Design
//!
//! ARIA is a substitution-permutation network of 12, 14 or 16 rounds (Sec 2.3). A round XORs a
//! 128-bit round key into the state, puts each of the 16 bytes through one of four 8-bit S-boxes
//! -- `SB1`, `SB2` and their inverses `SB3`, `SB4`, assigned by byte position and alternating
//! between two patterns in odd and even rounds (Sec 2.4.2) -- and mixes the bytes with the
//! diffusion layer `A`, a 16x16 binary matrix in which every output byte is the XOR of seven input
//! bytes (Sec 2.4.3). The last round substitutes without diffusing and adds an extra round key. The
//! key schedule (Sec 2.2) runs three rounds of the same functions over the key with fixed
//! constants derived from `1/pi`, then takes every round key as an XOR of two rotated results.
//! Decryption is the same network with the round keys reversed and passed through `A`.
//!
//! ## Why not a lookup table
//!
//! Sec 2.4.2 presents the S-boxes as tables, and BC Java's `ARIAEngine` stores the four 256-byte
//! tables. A table indexed by a byte of the state is indexed by secret data, so on any CPU with a
//! data cache the memory access pattern, and hence the timing, depends on the key and the data.
//! That is the classic cache-timing attack on table-driven block ciphers, and it is not fixable
//! while the lookup remains -- in the cipher or in the key schedule, whose three `FO`/`FE` calls go
//! through the S-boxes too.
//!
//! ## The S-boxes as circuits
//!
//! This crate has no table outside its tests. `SB1` is the AES S-box, and every one of the four
//! S-boxes is inversion in GF(2^8) between two affine maps -- for `SB2` a fact **found by
//! exhaustive search** against the Sec 2.4.2 table, not taken from recall: of the 256 possible
//! input constants exactly one admits such a decomposition, and it is unique up to the inverse's
//! own symmetries. So the 62-gate non-linear section of the Boyar-Peralta AES circuit does the
//! inversion in all four, with generated affine top and bottom layers pinned by exhaustive
//! 256-input tests; `SB1` uses the Boyar-Peralta program verbatim. Each S-box is a circuit of
//! roughly 120 gates; the `sbox` module docs give the exact counts and the derivation.
//!
//! A substitution layer sends four bytes of each block through each S-box -- the four bytes of one
//! *class word*, the column of the 4x4 byte matrix -- and each circuit's eight `u16` planes hold 16
//! byte positions, so the engine works on **four blocks at once**: each round transposes every
//! block's rows into class words, runs each of the four circuits once on that class word from all
//! four blocks, transposes back, and diffuses per block. The blocks never mix. The diffusion layer
//! is computed in the word-level form the 32-bit implementations use (a per-word byte parity, six
//! word XORs, three fixed byte permutations, six word XORs again), a decomposition verified against
//! the sixteen equations of Sec 2.4.3 rather than recalled; see the `round` module.
//!
//! Beyond the S-boxes, the port differs from the Java engine in three ways: one stored schedule
//! serves both directions (Java lays the keys out for the direction requested at `init`; here the
//! decryption keys of Sec 2.2 are derived from the stored encryption keys as each round needs
//! them); the block methods are infallible (the run-time buffer and initialisation checks are
//! compile-time facts here); and the constructors require a key tagged as a symmetric cipher key
//! of at least the strength its length implies, as every cipher in this workspace does.
//!
//! ## Why "lowmemory"
//!
//! Two things. First, no tables: BC Java's `ARIAEngine` carries four 256-byte S-boxes indexed by
//! secret data (and OpenSSL's `aria.c` 4 KiB of combined tables); here the S-boxes are code.
//! Second, the working set. Eight `u32` planes would take eight blocks per pass and double the
//! throughput, but every per-call buffer -- the block state, the planes -- would double with them.
//! Four lanes over `u16` planes keep the whole per-call working state near 100 bytes.
//!
//! # Memory Usage
//!
//! No heap allocation and no lookup tables. The persistent state is the encryption round keys of
//! Sec 2.2, one more than the number of rounds, 16 bytes each:
//!
//! | Type | Key | Rounds | Round keys (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`ARIA_128`] | 16 B | 12 | 13 x 16 = 208 B | 0 B |
//! | [`ARIA_192`] | 24 B | 14 | 15 x 16 = 240 B | 0 B |
//! | [`ARIA_256`] | 32 B | 16 | 17 x 16 = 272 B | 0 B |
//!
//! Per-call stack usage is the four-block working state -- four words per block, 64 bytes -- plus
//! the four class words being substituted (16 bytes), the eight `u16` planes (16 bytes), one round
//! key (16 bytes) and the circuits' temporaries, most of which the compiler keeps in registers.
//! Measure with `cargo run --release -p mem_usage_benches --bin bench_aria_mem_usage`.
//!
//! For comparison, BC Java's `ARIAEngine` carries 1 KiB of S-box tables on top of a round-key
//! array of the same size as here (plus 256 bytes of diffusion masks).
//!
//! # Security Considerations
//!
//! ## A block permutation is not a cipher
//!
//! [`ARIA_128`] and its siblings transform exactly 16 bytes. Using one directly on data means ECB,
//! which is not confidential: identical plaintext blocks produce identical ciphertext blocks, so
//! structure in the plaintext survives encryption. **Do not do it.** Use a mode of operation, and
//! prefer an authenticated one so that ciphertext tampering is detected. RFC 5794 Appendix B
//! assigns object identifiers to ARIA in ECB, CBC, CFB, OFB, CTR, CMAC, OCB2, GCM, CCM and key-wrap
//! modes; the ECB one exists for completeness, not as a recommendation.
//!
//! ## Constant-time properties
//!
//! By construction there is no secret-dependent memory access and no secret-dependent branch, in
//! the cipher *or* in the key schedule: the three `FO`/`FE` calls of Sec 2.2 go through the same
//! circuits as the rounds. The only branches are the round loop and the lane loops, which count
//! over public constants, and the odd/even test on the public round counter.
//!
//! Caveats worth stating plainly:
//!
//! * The Rust compiler makes no guarantee it will preserve this. The code is written so that the
//!   natural code generation is straight-line, and `#![forbid(unsafe_code)]` rules out the usual
//!   ways of forcing the issue, but the property is not contractual.
//! * The four-block working state is not scrubbed after a call. Only the round keys (and, during
//!   expansion, `KL`, `KR` and `W0 .. W3`) are wrapped in `Secret`, and so only they are guaranteed
//!   to be zeroized on drop.
//! * Constant-time execution says nothing about power or electromagnetic side channels.
//!
//! ## Security strength
//!
//! RFC 5794 Sec 3 reports ARIA "designed to be resistant to all known attacks on block ciphers",
//! with an independent analysis by the COSIC group finding no flaw. Each variant's
//! `MAX_SECURITY_STRENGTH` is its key length: 128, 192 or 256 bits.
//!
//! # Provenance
//!
//! * **Source implementation: Bouncy Castle Java `org.bouncycastle.crypto.engines.ARIAEngine`**,
//!   whose constants, byte-array `A`, `SL1`/`SL2`, `FO`/`FE` and key schedule this crate
//!   reproduces, and whose S-box tables are the reference the circuits are verified against. A
//!   direct transcription of the Java engine, including its fused multiply-broadcast round, lives
//!   in the tests (`tests/common/mod.rs`) and the engine is checked against it on thousands of
//!   inputs.
//! * **Normative reference: RFC 5794**, "A Description of the ARIA Encryption Algorithm" (Lee,
//!   Lee, Kim, Kwon, Kim; March 2010). Every function cites its section. The S-box tables, the
//!   diffusion equations and the constants were extracted mechanically from the text of the RFC
//!   and found identical to BC Java's.
//! * **The non-linear section of the S-box circuits** is from the 113-gate straight-line program
//!   `SLP_AES_113.txt` in Peralta's circuit collection, described in J. Boyar and R. Peralta, "A
//!   new combinational logic minimization technique with applications to cryptology",
//!   <https://eprint.iacr.org/2009/191.pdf>, as transcribed in `bouncycastle-aes`.
//! * **The bit-plane transpose** is translated from BearSSL's `aes_ct` by Thomas Pornin (MIT
//!   licence), as in the AES, SM4 and Camellia crates.
//! * Verified against RFC 5794 Appendix A -- the three ciphertexts, and for the 128-bit key every
//!   round key `ek1 .. ek13` and every intermediate value `P1 .. P11`; the ECB and CBC vectors of
//!   OpenSSL's `evpciph_aria.txt`, which are KISA's published ARIA test vectors (10 blocks under
//!   each key length); the vectors and invariants of BC Java's `ARIATest`; and the transcription
//!   of `ARIAEngine` on thousands of keys and blocks in every lane, both directions.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod aria;
mod bitslice;
mod cbc;
mod round;
mod sbox;
mod schedule;

pub use aria::{ARIA, ARIA_128, ARIA_192, ARIA_256, BLOCK_LEN, Block, LANES};
pub use cbc::{ARIA_CBC_128, ARIA_CBC_192, ARIA_CBC_256};
pub use schedule::{ARIA128Params, ARIA192Params, ARIA256Params, ARIAParams};
