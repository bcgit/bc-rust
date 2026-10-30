//! A constant-time, table-free, low-memory Camellia block cipher engine (RFC 3713), ported from
//! Bouncy Castle Java's `CamelliaEngine` / `CamelliaLightEngine`.
//!
//! This crate provides Camellia -- a 128-bit block cipher with 128-, 192- and 256-bit keys,
//! designed by NTT and Mitsubishi Electric, selected by the EU NESSIE project and Japan's CRYPTREC,
//! and described in RFC 3713, which is the specification every comment in this crate cites --
//! under the library's key objects: [`Camellia128Key<M>`], [`Camellia192Key<M>`] and
//! [`Camellia256Key<M>`], a key bound to one mode `M`, validated and expanded once, handing out
//! that mode's encryptors and decryptors. The engines underneath, [`Camellia128Internal`] and
//! friends, evaluate the S-boxes as a Boolean circuit over bit-planes rather than looking them up
//! in tables, so they are constant-time and carry no tables at all; the planes are 32 bits wide so
//! that the working set stays small, which is what "lowmemory" means here. See [Design](#design).
//!
//! An engine is a *permutation*, not a cipher you can encrypt data with, which is why it lives
//! under [`hazmat`]. See [Security Considerations](#-security-considerations-).
//!
//! # Usage Examples
//!
//! ## Modes of operation
//!
//! A key is built once, under a mode from `bouncycastle_cipher::modes`, and used for as many
//! messages as needed: `CBC<PKCS7>` for CBC (NIST SP 800-38A Sec 6.2) with PKCS#7 padding, `CFB`
//! for CFB128 (Sec 6.3), `CFB8` for the `s = 8` segment size, a different and non-interoperable
//! mode costing one Camellia call per byte, and `CTR` for CTR (Sec 6.5) with a 12-byte nonce and
//! a 4-byte counter. The aliases [`Camellia_CBC_128`], [`Camellia_CFB_128`], [`Camellia_CFB8_128`],
//! [`Camellia_CTR_128`] and their `_192` / `_256` siblings name the workers the keys hand out.
//!
//! CBC is a block cipher, so it is defined only on whole blocks and the key's mode carries a
//! padding scheme to bridge the difference; the CFB modes and CTR are stream ciphers and take any
//! length with no padding at all. See the `bouncycastle_cipher::modes` crate docs for the
//! comparison.
//!
//! ```
//! use bouncycastle_camellia::Camellia256Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = Camellia256Key::<CBC<PKCS7>>::from_key_material(&material)
//!     .expect("a valid Camellia-256 key");
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
//! use bouncycastle_camellia::Camellia256Key;
//! use bouncycastle_cipher::modes::CTR;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = Camellia256Key::<CTR>::from_key_material(&material)
//!     .expect("a valid Camellia-256 key");
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
//! key under `CBC<Blocks>`; the padded aliases wrap the same worker.
//!
//! ## The raw permutation
//!
//! The engine transforms one block, and `ElectronicCodeBook::new` on it is the one-shot:
//!
//! ```
//! use bouncycastle_camellia::hazmat::Camellia128Internal;
//! use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! // RFC 3713 Appendix A, "128-bit key".
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let camellia = Camellia128Internal::new(&key).expect("a valid Camellia-128 key");
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
//! The 192- and 256-bit variants are [`Camellia192Internal`] and [`Camellia256Internal`],
//! constructed from a `KeyMaterial<24>` and a `KeyMaterial<32>`; a key of the wrong length does
//! not compile.
//!
//! ## Four blocks at a time
//!
//! The bit-sliced S-box layer substitutes 32 bytes per pass, and a round substitutes eight bytes
//! per block, so four independent blocks cost the same as one. Where a caller has four,
//! [`CamelliaInternal::encrypt_4blocks`] is four times the throughput of four `encrypt_block`
//! calls, and it is also the four-block batch `BlockPermutation::encrypt_4blocks` offers to modes:
//!
//! ```
//! use bouncycastle_camellia::hazmat::Camellia256Internal;
//! use bouncycastle_camellia::LANES;
//! use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let camellia = Camellia256Internal::new(&key).expect("a valid Camellia-256 key");
//!
//! let mut blocks: [[u8; 16]; LANES] = core::array::from_fn(|i| [i as u8; 16]);
//! let original = blocks;
//! camellia.encrypt_4blocks(&mut blocks);
//! camellia.decrypt_4blocks(&mut blocks);
//! assert_eq!(blocks, original);
//! ```
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
//! each -- held once in the key; a worker adds the mode's own state and a reference to the key:
//!
//! | Type | Key | Rounds | Subkeys (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`Camellia128Internal`] | 16 B | 18 | 26 x 8 = 208 B | 0 B |
//! | [`Camellia192Internal`] | 24 B | 24 | 34 x 8 = 272 B | 0 B |
//! | [`Camellia256Internal`] | 32 B | 24 | 34 x 8 = 272 B | 0 B |
//!
//! Per-call stack usage is the four-block working state -- two 64-bit halves per block, 64
//! bytes -- plus the eight `u32` planes of the S-box argument (32 bytes), their copy during the
//! rotations (32 bytes), and the circuit's spills. Every entry point runs the same four-lane
//! circuit, so the one-, two- and four-block calls cost the same working state, and only key
//! expansion depends on the key length. Measured as the deepest frame chain below each entry
//! point's `measure` closure in `mem_usage_benches/src/bench_camellia_mem_usage.rs`: the
//! closure, then the out-of-line `encrypt_4blocks` (or the schedule's `expand`), `f` and
//! `ortho` frames under it, from the compiler's frame-layout remarks and the disassembly of the
//! release build (x86-64, rustc 1.97 nightly, return addresses included):
//!
//! | Entry point | Camellia-128 | Camellia-192 | Camellia-256 |
//! |---|---|---|---|
//! | `new` (key expansion) | 720 B | 1120 B | 1120 B |
//! | `encrypt_block` / `decrypt_block` | 496 B | 496 B | 496 B |
//! | `encrypt_2blocks` / `decrypt_2blocks` | 512 B | 512 B | 512 B |
//! | `encrypt_4blocks` | 528 B | 528 B | 528 B |
//! | `decrypt_4blocks` | 512 B | 512 B | 512 B |
//!
//! For comparison, a table-driven implementation carries anywhere from 256 bytes to 4 KiB of
//! tables on top of a 272-byte subkey array sized for the largest key.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## A block permutation is not a cipher
//!
//! [`Camellia128Internal`] and its siblings transform exactly 16 bytes. Using one directly on
//! data means ECB, which is not confidential: identical plaintext blocks produce identical
//! ciphertext blocks, so structure in the plaintext survives encryption. **Do not do it.** Use a
//! mode of operation, and prefer an authenticated one so that ciphertext tampering is detected.
//! RFC 3713 Sec 3 itself assigns object identifiers only to Camellia in CBC mode. That is why the
//! permutation lives under [`hazmat`]; [`bouncycastle_core::hazmat`] lists the supported uses.
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
//!   and NESSIE); the CBC and CFB128 vectors of OpenSSL's `evpciph_camellia.txt` through the CBC
//!   and CFB aliases; RFC 5528's nine Camellia-CTR vectors, through a reference built from the
//!   SP 800-38A Sec 6.5 equations which the CTR keys are then held to (see
//!   `tests/stream_mode_tests.rs` for why RFC 5528's counter blocks are not ones they produce);
//!   and the transcription of `CamelliaLightEngine` on thousands of keys and blocks in every lane.
//!   Project Wycheproof's `camellia_cbc_pkcs5_test.json` runs through the padded CBC keys and
//!   its `camellia_ccm_test.json` through the `CCM` mode traits over the engines.

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
mod round;
mod sbox;
mod schedule;

/// The Camellia block length in bytes: 16 (RFC 3713 Sec 1.1, "128-bit block size").
pub const BLOCK_LEN: usize = 16;

/// The number of blocks the bit-sliced S-box layer substitutes at once. See
/// [`CamelliaInternal::encrypt_4blocks`].
pub const LANES: usize = 4;

pub use cbc::{Camellia_CBC_128, Camellia_CBC_192, Camellia_CBC_256};
pub use cfb::{Camellia_CFB_128, Camellia_CFB_192, Camellia_CFB_256};
pub use cfb8::{Camellia_CFB8_128, Camellia_CFB8_192, Camellia_CFB8_256};
pub use ctr::{CTR_NONCE_LEN, Camellia_CTR_128, Camellia_CTR_192, Camellia_CTR_256};
pub use key::{Camellia128Key, Camellia192Key, Camellia256Key, CamelliaKey};
pub use schedule::CamelliaParams;

// Imports needed for docs
#[allow(unused_imports)]
use hazmat::{Camellia128Internal, Camellia192Internal, Camellia256Internal, CamelliaInternal};
// end of imports needed for docs
