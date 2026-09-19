//! A constant-time, table-free, low-memory Camellia block cipher engine (RFC 3713), ported from
//! Bouncy Castle Java's `CamelliaEngine` / `CamelliaLightEngine`.
//!
//! This crate provides the raw Camellia keyed permutation -- [`Camellia_128`], [`Camellia_192`] and
//! [`Camellia_256`] -- a 128-bit block cipher with 128-, 192- and 256-bit keys, designed by NTT and
//! Mitsubishi Electric, selected by the EU NESSIE project and Japan's CRYPTREC, and described in
//! RFC 3713, which is the specification every comment in this crate cites. The S-boxes are
//! evaluated as a Boolean circuit over bit-planes rather than looked up in tables, so the engine is
//! constant-time and carries no tables at all; the planes are 32 bits wide so that the working set
//! stays small, which is what "lowmemory" means here. See [Design](#design).
//!
//! It is a *permutation*, not a cipher you can encrypt data with. See
//! [Security Considerations](#security-considerations).
//!
//! # Usage Examples
//!
//! ## Encrypting and decrypting a single block
//!
//! ```
//! use bouncycastle_camellia::Camellia_128;
//! use bouncycastle_core::traits::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! // RFC 3713 Appendix A, "128-bit key".
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let camellia = Camellia_128::new(&key).expect("a valid Camellia-128 key");
//!
//! let mut block = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
//! camellia.encrypt_block(&mut block);
//! assert_eq!(block, [0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
//!                    0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43]);
//!
//! // The same value decrypts, from the same subkeys -- there is no separate decryptor.
//! camellia.decrypt_block(&mut block);
//! assert_eq!(block, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
//! ```
//!
//! The 192- and 256-bit variants are [`Camellia_192`] and [`Camellia_256`], constructed from a
//! `KeyMaterial<24>` and a `KeyMaterial<32>`; a key of the wrong length does not compile.
//!
//! ## Four blocks at a time
//!
//! The bit-sliced S-box layer substitutes 32 bytes per pass, and a round substitutes eight bytes
//! per block, so four independent blocks cost the same as one. Where a caller has four,
//! [`Camellia::encrypt_4blocks`] is four times the throughput of four [`ElectronicCodeBook::encrypt_block`](bouncycastle_core::traits::ElectronicCodeBook::encrypt_block)
//! calls, and it is also the four-block batch [`ElectronicCodeBook::encrypt_4blocks`](bouncycastle_core::traits::ElectronicCodeBook::encrypt_4blocks)
//! offers to modes:
//!
//! ```
//! use bouncycastle_camellia::{Camellia_256, LANES};
//! use bouncycastle_core::traits::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let camellia = Camellia_256::new(&key).expect("a valid Camellia-256 key");
//!
//! let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [i as u8; 16]);
//! let original = blocks;
//! camellia.encrypt_4blocks(&mut blocks);
//! camellia.decrypt_4blocks(&mut blocks);
//! assert_eq!(blocks, original);
//! ```
//!
//! ## CBC mode
//!
//! To encrypt more than one block, use a mode of operation from `bouncycastle-modes`. This crate
//! provides [`Camellia_CBC_128`], [`Camellia_CBC_192`] and [`Camellia_CBC_256`] as aliases that
//! fill in the const parameters, with the direction left as the type parameter:
//!
//! ```
//! use bouncycastle_camellia::Camellia_CBC_256;
//! use bouncycastle_core::traits::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//! use bouncycastle_padding::PKCS7;
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // The IV is generated for you and returned; there is no API for supplying one.
//! let (iv, ciphertext) =
//!     Camellia_CBC_256::<Encrypting, PKCS7>::encrypt(&key, &plaintext).expect("encryption");
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! let recovered =
//!     Camellia_CBC_256::<Decrypting, PKCS7>::decrypt(&key, &iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! For the block-aligned API -- whole blocks in place, with the length checked at compile time --
//! name `bouncycastle_modes::Cbc` directly; that is what these aliases wrap.
//!
//! There is no one-shot static on the permutation, because `Camellia_128::new(&key)?.encrypt_block(..)`
//! already *is* the one shot. Data-level one-shots belong to the modes of operation, which take
//! arbitrary-length input and generate their own initialisation data.
//!
//! # Design
//!
//! Camellia is an 18-round (128-bit key) or 24-round (192- and 256-bit key) Feistel network over
//! two 64-bit halves, with a key-dependent linear `FL`/`FLINV` layer inserted every six rounds
//! (Sec 2.3) and 64-bit whitening keys XORed in before and after. The round function `F`
//! (Sec 2.4.1) XORs a subkey into the half, puts its eight bytes through four S-boxes -- `SBOX1`
//! and three one-bit rotations of it -- and mixes them with a byte-wise linear map `P`. The key
//! schedule (Sec 2.2) derives two or three 128-bit intermediate keys with six applications of `F`
//! under fixed constants, then takes every subkey as half of a rotation of one of them, so it is
//! cheap: Camellia's "key agility" is one of its design goals. Decryption is the same network with
//! the subkeys in reverse (Sec 2.3.3).
//!
//! ## Why not a lookup table
//!
//! Sec 2.4.1 presents `SBOX1` as a table, and a table-driven implementation stores one -- some
//! fold `P` into four 1 KiB tables, others use a single 256-byte table. A table indexed
//! by a byte of the state is indexed by secret data, so on any CPU with a data cache the memory
//! access pattern, and hence the timing, depends on the key and the data. That is the classic
//! cache-timing attack on table-driven block ciphers, and it is not fixable while the lookup
//! remains -- in the cipher or in the key schedule, whose `F` calls go through the S-boxes too.
//!
//! ## The S-box as a circuit
//!
//! This crate has no table outside its tests. `SBOX1` has the same algebraic shape as the AES
//! S-box -- an affine map, inversion in GF(2^8), and another affine map -- a decomposition found
//! here by exhaustive search against the Sec 2.4.1 table, not taken from recall: of the 256
//! possible input constants exactly one admits such a decomposition, and it is unique up to the
//! inverse's own symmetries. The search was carried out in the AES representation of the field,
//! so the 62-gate non-linear section of the Boyar-Peralta AES circuit, copied verbatim from
//! `bouncycastle-aes`, does the inversion, with generated affine top and bottom layers
//! pinned by an exhaustive 256-input test. The whole S-box is 121 gates: 32 AND, 74 XOR, 9 XNOR,
//! 6 NOT. The `sbox` module docs give the full derivation.
//!
//! `SBOX2`, `SBOX3` and `SBOX4` are `SBOX1` with the output byte rotated left by one, rotated
//! right by one, and the input byte rotated left by one (Sec 2.4.1). On bit-planes a byte rotation
//! is a renumbering of the planes, so the one circuit serves all four: the rotations are applied
//! only at the byte positions that need them, selected by compile-time masks.
//!
//! A round substitutes eight bytes per block, and the circuit's eight `u32` planes hold 32 byte
//! positions, so the engine works on **four blocks at once**: each round forms the argument of `F`
//! for every block, splits the four 64-bit words into eight 32-bit halves, transposes them into
//! planes, runs the circuit once, transposes back, and finishes the round per block. The blocks
//! never mix. Everything else in
//! the cipher -- `P`, `FL`, `FLINV`, the whitening -- is XOR, AND and OR with key words, and
//! rotations, all already constant-time on words, so the rest of the engine is a direct,
//! spec-literal implementation: 64-bit halves as the RFC defines them, and `P` computed with a
//! five-rotation form that is checked against the RFC's byte formulas in a test.
//!
//! Beyond the S-box, this crate stores one schedule that serves both directions (a
//! direction-aware engine typically lays the subkeys out differently per direction at
//! initialisation); the block methods are infallible (the run-time buffer and initialisation
//! checks are compile-time facts here); and the constructors require a key tagged as a symmetric
//! cipher key of at least the strength its length implies, as every cipher in this workspace does.
//!
//! ## Why "lowmemory"
//!
//! Two things. First, no tables: a table-driven implementation carries anywhere from 256 bytes to
//! 4 KiB of them, indexed by secret data; here the S-box is code. Second,
//! the working set. Eight `u64` planes would take eight blocks per pass and double the throughput
//! on a 64-bit machine, but every per-call buffer -- the block state, the planes, their copy during
//! the byte rotations -- would double with them. Four lanes over `u32` planes keep the whole
//! per-call working state near 160 bytes, and cost nothing on a 32-bit target, where a `u64`
//! operation is two instructions anyway.
//!
//! # Memory Usage
//!
//! No heap allocation and no lookup tables. The persistent state is the subkeys of Sec 2.2 --
//! four whitening keys, one round key per round, and two `FL`/`FLINV` keys per `FL` layer, 64 bits
//! each:
//!
//! | Type | Key | Rounds | Subkeys (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`Camellia_128`] | 16 B | 18 | 26 x 8 = 208 B | 0 B |
//! | [`Camellia_192`] | 24 B | 24 | 34 x 8 = 272 B | 0 B |
//! | [`Camellia_256`] | 32 B | 24 | 34 x 8 = 272 B | 0 B |
//!
//! Per-call stack usage is the four-block working state -- two 64-bit halves per block, 64
//! bytes -- plus the eight `u32` planes of the S-box argument (32 bytes), their copy during the
//! rotations (32 bytes), and the circuit's temporaries, most of which the compiler keeps in
//! registers.
//! Measure with `cargo run --release -p mem_usage_benches --bin bench_camellia_mem_usage`.
//!
//! For comparison, a table-driven implementation carries anywhere from 256 bytes to 4 KiB of
//! tables on top of a 272-byte subkey array sized for the largest key.
//!
//! # Security Considerations
//!
//! ## A block permutation is not a cipher
//!
//! [`Camellia_128`] and its siblings transform exactly 16 bytes. Using one directly on data means
//! ECB, which is not confidential: identical plaintext blocks produce identical ciphertext blocks,
//! so structure in the plaintext survives encryption. **Do not do it.** Use a mode of operation,
//! and prefer an authenticated one so that ciphertext tampering is detected. RFC 3713 Sec 3 itself
//! assigns object identifiers only to Camellia in CBC mode.
//!
//! ## Constant-time properties
//!
//! By construction there is no secret-dependent memory access and no secret-dependent branch, in
//! the cipher *or* in the key schedule: the six `F` calls of Sec 2.2 go through the same circuit
//! as the rounds. The only branches are the round loop and the lane loops, which count over public
//! constants, and the odd/even and every-sixth-round tests on the public round counter.
//!
//! Caveats worth stating plainly:
//!
//! * The Rust compiler makes no guarantee it will preserve this. The code is written so that the
//!   natural code generation is straight-line, and `#![forbid(unsafe_code)]` rules out the usual
//!   ways of forcing the issue, but the property is not contractual.
//! * The four-block working state is not scrubbed after a call. Only the subkeys (and, during
//!   expansion, `KL`, `KR`, `KA`, `KB` and the `D1`/`D2` temporaries) are wrapped in `Secret`, and
//!   so only they are guaranteed to be zeroized on drop.
//! * Constant-time execution says nothing about power or electromagnetic side channels.
//!
//! ## Security strength
//!
//! RFC 3713 Sec 4 reports no differential or linear characteristic with probability above
//! `2^-128` for the full 18 rounds. Each variant's `MAX_SECURITY_STRENGTH` is its key length:
//! 128, 192 or 256 bits.
//!
//! # Provenance
//!
//! * **Source engine.** The `SIGMA` constants, `camelliaF2` linear layer, `camelliaFLs` and
//!   subkey layout this crate reproduces, and the `SBOX1` table the circuit is verified against,
//!   come from Bouncy Castle Java's `CamelliaEngine` and `CamelliaLightEngine`. A direct
//!   transcription of `CamelliaLightEngine` lives in the tests (`tests/common/mod.rs`) and this
//!   engine is checked against it on thousands of inputs.
//! * **Normative reference: RFC 3713**, "A Description of the Camellia Encryption Algorithm"
//!   (Matsui, Nakajima, Moriai; April 2004). Every function cites its section. The `SBOX1` table
//!   and the `Sigma` constants were extracted mechanically from the text of the RFC.
//! * **The non-linear section of the S-box circuit** is from the 113-gate straight-line program
//!   `SLP_AES_113.txt` in Peralta's circuit collection, described in J. Boyar and R. Peralta, "A
//!   new combinational logic minimization technique with applications to cryptology",
//!   <https://eprint.iacr.org/2009/191.pdf>, as transcribed in `bouncycastle-aes`.
//! * **The bit-plane transpose** is translated from BearSSL's `aes_ct` by Thomas Pornin (MIT
//!   licence), as in the AES and SM4 crates.
//! * Verified against the three vectors of RFC 3713 Appendix A; all 3840 vectors of NTT's
//!   CRYPTREC test-vector file `t_camellia.txt` (ten keys per key length, 128 single-bit
//!   plaintexts each), both directions; the nine vectors of `tests/bc_java_tests.rs` (RFC 3713
//!   and NESSIE); the CBC vectors of OpenSSL's `evpciph_camellia.txt` through the CBC aliases;
//!   and the transcription of `CamelliaLightEngine` on thousands of keys and blocks in every lane.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod bitslice;
mod camellia;
mod cbc;
mod round;
mod sbox;
mod schedule;

pub use camellia::{BLOCK_LEN, Camellia, Camellia_128, Camellia_192, Camellia_256, LANES};
pub use cbc::{Camellia_CBC_128, Camellia_CBC_192, Camellia_CBC_256};
pub use schedule::CamelliaParams;
