//! A constant-time, table-free Triple DES block cipher engine (NIST SP 800-67 Rev 2, TDEA).
//!
//! This crate provides the raw three-key TDEA keyed permutation, [`TDES`], and a decryption-only
//! two-key one, [`TDES2Key`], implemented as a Boolean circuit over bit-planes rather than by
//! lookups in S-box tables. That makes them constant-time; see [Design](#design). They are
//! *permutations*, not ciphers you can encrypt data with, and TDEA is a **legacy algorithm**: see
//! [Security Considerations](#security-considerations) before using it for anything new.
//!
//! # Usage Examples
//!
//! ## Encrypting and decrypting a single block
//!
//! ```
//! use bouncycastle_tdes::TDES;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::ElectronicCodeBook;
//!
//! // NIST CAVP TECBMMT3.rsp, [ENCRYPT] COUNT = 0: KEY1 || KEY2 || KEY3.
//! let key = KeyMaterial::<24>::from_bytes_as_type(
//!     &[0xe9, 0x7c, 0x83, 0x13, 0xba, 0x26, 0x5d, 0x43,
//!       0x25, 0x4c, 0xbf, 0x9e, 0x8f, 0x7c, 0x2a, 0xa8,
//!       0xa7, 0x54, 0xd6, 0x5e, 0x8a, 0xe9, 0x97, 0xe3],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 24-byte symmetric cipher key");
//!
//! let tdes = TDES::new(&key).expect("a valid TDES key bundle");
//!
//! let mut block = [0x46, 0x56, 0xed, 0x81, 0xa8, 0xbc, 0x58, 0xa9];
//! tdes.encrypt_block(&mut block);
//! assert_eq!(block, [0x42, 0x6a, 0x0a, 0xc2, 0x65, 0x86, 0xbf, 0x6c]);
//!
//! // The same value decrypts, from the same schedule -- there is no separate decryptor.
//! tdes.decrypt_block(&mut block);
//! assert_eq!(block, [0x46, 0x56, 0xed, 0x81, 0xa8, 0xbc, 0x58, 0xa9]);
//! ```
//!
//! ## Modes of operation
//!
//! To encrypt more than one block, use a mode of operation from `bouncycastle-modes`. This crate
//! provides aliases that fill in the const parameters, leaving only the choices a caller actually
//! makes: [`TDES_CBC`] for CBC (SP 800-38A Sec 6.2), which takes the direction **and a padding
//! scheme**, and [`TDES_CFB`] for CFB64 (Sec 6.3), which takes only the direction. [`TDES_CFB8`]
//! gives CFB8, the `s = 8` segment size, a different and non-interoperable mode costing one TDES
//! call per byte. [`TDES_CTR`] gives CTR (Sec 6.5) with a 6-byte nonce and a 2-byte counter.
//! [`TDES_ECB`] gives ECB (Sec 6.1), which takes a padding scheme like CBC and has no IV, for
//! interoperability and test vectors only -- see
//! [A block permutation is not a cipher](#a-block-permutation-is-not-a-cipher).
//!
//! SP 800-38A Appendix E is what makes these the standard TDEA modes: TECB, TCBC and TCFB of ANSI
//! X9.52 "are equivalent to" ECB, CBC and CFB "with the TDEA as the underlying block cipher", and
//! CTR with TDEA is explicitly allowed as well.
//!
//! CBC is a block cipher, so it is defined only on whole blocks and the alias carries a padding
//! scheme to bridge the difference; the CFB modes and CTR are stream ciphers and take any length
//! with no padding at all. See the `bouncycastle-modes` crate docs for the comparison, and
//! [`TDES_CBC`] for why the scheme is named in the type.
//!
//! ```
//! use bouncycastle_tdes::TDES_CBC;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//! use bouncycastle_padding::PKCS7;
//!
//! // Three distinct component keys; see `TDES::new` for what a key bundle must satisfy.
//! let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
//! let key = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
//!     .expect("a 24-byte symmetric cipher key");
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // The IV is generated for you and returned; there is no API for supplying one.
//! let (iv, ciphertext) =
//!     TDES_CBC::<Encrypting, PKCS7>::encrypt(&key, &plaintext).expect("encryption");
//! assert_eq!(ciphertext.len(), 56, "50 bytes padded out to seven 8-byte blocks");
//!
//! let recovered =
//!     TDES_CBC::<Decrypting, PKCS7>::decrypt(&key, &iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! For the block-aligned API -- whole blocks in place, with the length checked at compile time --
//! name `bouncycastle_modes::Cbc` directly; that is what these aliases wrap.
//!
//! There is no one-shot static on the permutation, because `TDES::new(&key)?.encrypt_block(..)`
//! already *is* the one shot. Data-level one-shots belong to the modes of operation, which take
//! arbitrary-length input and generate their own initialisation data.
//!
//! ## What a key bundle must satisfy
//!
//! `TDES::new` takes a 24-byte `Key1 || Key2 || Key3` and rejects it if the three component keys
//! are not pairwise distinct (SP 800-67r2 Sec 3.1) or if any of them is one of the 64 weak,
//! semi-weak or possibly weak DES keys (Sec 3.3.2). Parity bits are ignored throughout, as the
//! algorithm ignores them.
//!
//! ## Two-key TDEA: decryption only
//!
//! [`TDES2Key`] takes the 16-byte `Key1 || Key2` of two-key TDEA (`Key3 = Key1`), which
//! SP 800-131A Rev 2 Table 1 lists as "Disallowed" for encryption and "Legacy use" for decryption.
//! It sets `ElectronicCodeBook::ENCRYPTION_APPROVED` to `false`, so the `Encrypting` direction of
//! every mode refuses to compile over it, while the `Decrypting` direction works. The aliases
//! [`TDES2_CBC`], [`TDES2_CFB`], [`TDES2_CFB8`], [`TDES2_CTR`] and [`TDES2_ECB`] are those
//! decryptors, with the IV or nonce supplied by the caller as it was received:
//!
//! ```
//! use bouncycastle_tdes::TDES2_CBC;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::SymmetricCipherDecryptor;
//! use bouncycastle_padding::NoPadding;
//!
//! // NIST CAVP TCBCMMT2.rsp, [DECRYPT] COUNT = 0.
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0xbc, 0xfe, 0x7f, 0x25, 0xf2, 0xb0, 0xa7, 0x2c,
//!       0x62, 0x76, 0xae, 0x1f, 0x38, 0x9d, 0x8a, 0xe9],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//! let iv = [0xf2, 0x9d, 0x4b, 0xa5, 0x17, 0x2f, 0xd2, 0x97];
//! let ciphertext = [0x1b, 0x38, 0x89, 0xc9, 0xdb, 0xe1, 0x0d, 0x03];
//!
//! let plaintext = TDES2_CBC::<NoPadding>::decrypt(&key, &iv, &ciphertext).expect("decryption");
//! assert_eq!(plaintext, [0x06, 0x11, 0xa4, 0x74, 0xfb, 0x09, 0x09, 0x78]);
//! ```
//!
//! # Design
//!
//! ## Why not a lookup table
//!
//! The DEA's eight selection functions S1..S8 are given as tables (SP 800-67r2 Appendix A), and
//! nearly every implementation, Bouncy Castle's `DESEngine` in the Java and C# ports among them,
//! stores them as such -- usually pre-combined with the permutation `P` into eight 64-entry word
//! tables. A table indexed by six bits of `K xor E(R)` is indexed by secret data, so on any CPU
//! with a data cache the memory access pattern, and hence the timing, depends on the key.
//!
//! ## An S-box layer with no table
//!
//! This crate has no tables at run time. The eight S-boxes are treated as thirty-two 6-to-1-bit
//! Boolean functions, and each of those has an algebraic normal form: an XOR of ANDs of its inputs.
//! The ANF coefficients are derived from the spec's tables at compile time, in a `const fn`, and
//! the round function evaluates all thirty-two ANFs at once by Horner's scheme -- 63 ANDs and 63
//! XORs on `u32` words, with the six input bits of every S-box held one per word, replicated
//! across the four bit positions of the S-box's output nibble. Nothing is ever indexed by a
//! secret, and nothing branches on one. The `sbox` and `des` module docs give the full derivation
//! and the bit layout; they are the place to start when reading the source.
//!
//! The rest of the round is masks and rotations: `E` is never materialised as a 48-bit value but
//! read straight out of `R`'s nibbles and their neighbours, and `P` is nineteen mask-and-rotate
//! groups. The key schedule stores each round key in two words shaped to be XORed into that
//! layout, so no PC-2 or rearrangement happens per round.
//!
//! ## One schedule, both directions
//!
//! SP 800-67r2 Sec 2.2: the inverse transformation is "the very same algorithm" with the round
//! keys used in the opposite order. So the inverse cipher operation reads the same stored schedule
//! backwards, and one [`TDES`] value encrypts and decrypts. TDEA's `IP^-1` at the end of one DEA
//! transformation and `IP` at the start of the next cancel, and are skipped, which changes no
//! intermediate value the spec defines.
//!
//! # Memory Usage
//!
//! There are no lookup tables and no heap allocation. The only persistent state is the three DEA
//! key schedules:
//!
//! | Type | Key | Rounds | Schedule (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`TDES`] | 24 B | 3 x 16 | 384 B | 0 B |
//! | [`TDES2Key`] | 16 B | 3 x 16 | 256 B | 0 B |
//!
//! Each round key is 48 bits stored as two 32-bit words (see the `schedule` module for the
//! packing), so 128 bytes per DEA key. Per-call stack usage is a few words of block state, the
//! six 4-byte input planes, and a 128-byte working array for the ANF evaluation, most of which the
//! compiler keeps in registers.
//!
//! For comparison, the table-driven `DESEngine` carries 2 KiB of combined S/P tables.
//!
//! Measure with `cargo run --release -p mem_usage_benches --bin bench_tdes_mem_usage`.
//!
//! # Security Considerations
//!
//! ## TDEA is a legacy algorithm
//!
//! NIST withdrew SP 800-67 Rev 2 on 1 January 2024: "This signifies that TDEA is no longer an
//! approved block cipher. ... TDEA will continue to be allowed for the decryption, key
//! unwrapping, and verification of Message Authentication Codes (MACs) of already-protected data."
//! SP 800-131A Rev 2, Table 1, gives the transition: three-key TDEA encryption "Deprecated through
//! 2023, Disallowed after 2023", three-key decryption "Legacy use", two-key encryption
//! "Disallowed". SP 800-57 Part 1 Rev 5, Table 2, rates 3TDEA at 112 bits of security, which is
//! what [`TDES`] reports as its maximum strength.
//!
//! This crate exists so that data and protocols that still depend on TDEA can be handled. Do not
//! choose it for a new design; use AES from `bouncycastle-aes`.
//!
//! ## The 64-bit block, and the data limit
//!
//! SP 800-67r2 Sec 3.4: "One key bundle shall not be used to apply cryptographic protection (e.g.,
//! encrypt) more than 2^20 64-bit data blocks" -- 8 MiB per key bundle, in total, across all
//! messages. The limit exists because a 64-bit block cipher in CBC or CFB leaks plaintext
//! relationships once about 2^32 blocks have been seen under one key (the birthday bound). This
//! crate cannot count blocks across the uses of a key, so the limit has to be enforced by whoever
//! manages the key.
//!
//! The CTR alias has a further constraint from the small block, explained at [`TDES_CTR`].
//!
//! ## A block permutation is not a cipher
//!
//! [`TDES`] transforms exactly 8 bytes. Using it directly on data means ECB, which is not
//! confidential: identical plaintext blocks produce identical ciphertext blocks, so structure in the
//! plaintext survives encryption. **Do not do it.** Use a mode of operation, and prefer an
//! authenticated one so that ciphertext tampering is detected.
//!
//! The [`TDES_ECB`] alias gives that same block-by-block operation the mode API, so that systems and
//! specifications which require ECB -- and test-vector harnesses -- can use it through the same
//! interface as the other modes. Like the CBC alias it carries a padding scheme, which is what lets
//! it accept data of any length. Neither the mode API nor the padding makes ECB confidential.
//!
//! ## Constant-time properties
//!
//! By construction there is no secret-dependent memory access and no secret-dependent branch, in
//! the cipher *or* in the key schedule (PC-1 and PC-2 iterate over public tables and shift the key
//! by public amounts) *or* in the weak-key check (a structural test on `C0` and `D0`, not a table
//! comparison). The only branches are the round loops and the public direction flag.
//!
//! Caveats worth stating plainly:
//!
//! * The Rust compiler makes no guarantee it will preserve this. The code is written so that the
//!   natural code generation is straight-line, and `#![forbid(unsafe_code)]` rules out the usual
//!   ways of forcing the issue, but the property is not contractual.
//! * The working state of a block is not scrubbed after the call. Only the key schedule is wrapped
//!   in `Secret`, and so only it is guaranteed to be zeroized on drop; the three 64-bit key words
//!   examined during construction are ordinary locals.
//! * Constant-time execution says nothing about power or electromagnetic side channels.
//!
//! # Provenance
//!
//! * Normative reference: **NIST SP 800-67 Rev 2** (withdrawn January 2024), for the DEA engine
//!   (Sec 2, Appendix A), TDEA (Sec 3.1), the key requirements (Sec 3.3) and the data limit (Sec
//!   3.4). Every table is transcribed from it and cross-checked against **FIPS 46-3**, whose
//!   Appendix 1 is identical. Modes: **NIST SP 800-38A**, Appendix E for TDEA. Status: **SP
//!   800-131A Rev 2** Table 1; strength: **SP 800-57 Part 1 Rev 5** Table 2.
//! * The view of the S-boxes as thirty-two "T-boxes" evaluated in parallel by a tree of
//!   `a ^ (x & b)` steps is from Thomas Pornin's `des_ct.c` in BearSSL (MIT licence). This crate
//!   derives the tree's constants from the spec tables at compile time rather than hard-coding
//!   them. The `IP` / `IP^-1` swap network is Richard Outerbridge's, via Crypto++ (public domain)
//!   and BearSSL's `des_support.c`; the rotation groups of `P` were regenerated from Table 3.
//!   Each is pinned to the spec's table by a unit-vector test, which for a bit permutation is
//!   exhaustive.
//! * Behavioural cross-reference: Bouncy Castle Java's `DESedeEngine` and `DESedeParameters`.
//!   Where this crate is stricter -- it rejects the 48 possibly-weak keys as well as the 16 weak
//!   and semi-weak ones, requires distinct component keys, and confines two-key TDEA to a
//!   decryption-only type -- the crate docs say so and cite the SP 800-67r2 and SP 800-131A Rev 2
//!   text that motivates it.
//! * Verified against the NIST CAVP TDES Multi-block Message Test vectors `TECBMMT{2,3}`,
//!   `TCBCMMT{2,3}`, `TCFB64MMT{2,3}` and `TCFB8MMT{2,3}`, from the `bc-test-data` repository.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod cbc;
mod cfb;
mod cfb8;
mod ctr;
mod des;
mod ecb;
mod padded_mode;
mod sbox;
mod schedule;
mod tdes;
mod tdes2;

pub use cbc::{TDES_CBC, TDES2_CBC};
pub use cfb::{TDES_CFB, TDES2_CFB};
pub use cfb8::{TDES_CFB8, TDES2_CFB8};
pub use ctr::{CTR_NONCE_LEN, TDES_CTR, TDES2_CTR};
pub use ecb::{TDES_ECB, TDES2_ECB};
pub use tdes::{BLOCK_LEN, KEY_LEN, TDES};
pub use tdes2::{KEY_LEN_2KEY, TDES2Key};
