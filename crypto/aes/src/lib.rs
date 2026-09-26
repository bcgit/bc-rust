//! A constant-time, table-free AES block cipher engine (NIST FIPS 197).
//!
//! This crate provides the raw AES keyed permutation
//! implemented as a Boolean circuit over bit-planes rather than as byte substitutions through a
//! lookup table. That makes it both smaller and constant-time; see [Design](#design).
//!
//! # Usage Examples
//!
//! The raw AES permutation (as exposed by the [`AESInternal`](aes_internal::AESInternal) struct) is not secure to use by itself.
//! For why, see [A block permutation is not a cipher](#a-block-permutation-is-not-a-cipher) below.
//!
//! For ready-to-use primitives, see the documentation for one of the provided modes of operation:
//!
//! * [AES_CBC](crate::cbc)
//! * [AES_CFB](crate::cfb)
//! * [AES_CFB8](crate::cfb8)
//! * [AES_CTR](crate::ctr)
//! * [AES_ECB](crate::ecb)
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
//! with a lookup-table-based implementation.
//!
//! ## Bit-slicing
//!
//! The SBox implementation is borrowed from J. Boyar and R. Peralta,
//! "A new combinational logic minimization technique with applications to cryptology",
//! <https://eprint.iacr.org/2009/191.pdf> and the accompanying `SLP_AES_113.txt`.
//!
//! It is "bit-sliced" in the sense that the state is transposed so that each of eight words holds
//! one *bit position* of every byte: word `q[k]` collects bit `k` of all the bytes. In that form
//! the S-box becomes a fixed Boolean circuit -- 32 AND, 77 XOR and 4 XNOR gates, the 113-gate
//! straight-line program of Boyar and Peralta -- and one `&` or `^` applies a gate to every byte
//! position at once. Nothing is ever indexed by a secret, and nothing branches on one.
//!
//! Multiple blocks at once:
//! A single block bitslices into a `[u16; 8]` planes object. Since XOR and XNOR of two u16's, two u32's, or two u64's
//! is still a single operation (at least on a 64-bit machine), we can process two blocks at a time as a `[u32; 8]`
//! or 4 blocks at a time as a `[u64; 8]` for approximately the same cost as a single block.
//! The circuit and the masks cost about the same at every width, so the batched entry points
//! multiply throughput. Measured with the crate's criterion benches on x86-64, 16 KiB per run,
//! relative to the single-block entry point:
//!
//! | Entry point | Encrypt | Decrypt |
//! |---|---|---|
//! | `encrypt_block` / `decrypt_block` (`u16` planes) | 1.0x | 1.0x |
//! | `encrypt_2blocks` / `decrypt_2blocks` (`u32` planes) | 1.75x | 1.95x |
//! | `encrypt_4blocks` / `decrypt_4blocks` (`u64` planes) | 3.0x | 3.7x |
//!
//! The ratios hold for all three key lengths to within a few percent; in absolute terms AES-128
//! single-block encryption is about 240 us per 16 KiB and decryption about 330 us. That multiplier
//! is what the modes of operation batch through wherever their blocks are independent.
//! This does not benefit modes such as CBC or GCM which, by construction, must process each block sequentially block,
//! but does accelerate other modes where blocks can be parallelized.
//!
//! SHIFTROWS() and MIXCOLUMNS() become masks and rotations in the same representation, and the
//! key schedule is stored bit-sliced too, so no transposition happens inside the round loop. The
//! exact bit layout, and the derivation of every mask from it, is documented in the source code of the `bitslice`
//! and `round` modules.
//!
//! Decryption follows FIPS 197 Algorithm 3, the straight inverse cipher, rather than the
//! equivalent inverse cipher of Sec 5.3.5. Algorithm 3 puts INVMIXCOLUMNS() after ADDROUNDKEY(),
//! so it uses the *unmodified* key schedule; the equivalent inverse cipher would need a second
//! schedule with each round key transformed. One [`AES128Internal`](aes_internal::AES128Internal) value therefore encrypts and decrypts
//! from one stored schedule.
//!
//! # Memory Usage
//!
//! There are no lookup tables and no heap allocation. The only persistent state is the key
//! schedule, which is `4 * (Nr + 1)` words -- exactly the size FIPS 197 Sec 5.2 defines, with the
//! bit-sliced form stored at the one-block width so that bit-slicing costs nothing in space:
//!
//! | Type | Key | `Nr` | Schedule (persistent) | Tables |
//! |---|---|---|---|---|
//! | [`AES128Internal`](aes_internal::AES128Internal) | 16 B | 10 | 176 B | 0 B |
//! | [`AES192Internal`](aes_internal::AES192Internal) | 24 B | 12 | 208 B | 0 B |
//! | [`AES256Internal`](aes_internal::AES256Internal) | 32 B | 14 | 240 B | 0 B |
//!
//! Per-call stack usage is independent of key length and set by the plane width: 16, 32 or 64
//! bytes of bit-sliced state for one, two or four blocks, the same again for the round key widened
//! from its stored one-block form, plus the S-box circuit's spills. Measured as the deepest frame
//! chain below each entry point in the release build (x86-64, return addresses included):
//!
//! | Entry point | Stack (bytes) |
//! |---|---|
//! | `new` (key expansion), AES-128 / 192 / 256 | 312 / 344 / 376 |
//! | `encrypt_block` / `decrypt_block` (`u16` planes) | 208 / 208 |
//! | `encrypt_2blocks` / `decrypt_2blocks` (`u32` planes) | 240 / 224 |
//! | `encrypt_4blocks` / `decrypt_4blocks` (`u64` planes) | 320 / 352 |
//!
//! # Security Considerations
//!
//! ## A block permutation is not a cipher
//!
//! [`AES128Internal`](aes_internal::AES128Internal) and friends transform exactly 16 bytes. Using them directly on data means ECB,
//! which is not confidential: identical plaintext blocks produce identical ciphertext blocks, so
//! structure in the plaintext survives encryption. **Do not do it.** Use a mode of operation, and
//! prefer an authenticated one so that ciphertext tampering is detected.
//!
//! The [`AES_ECB_128`] / [`AES_ECB_192`] / [`AES_ECB_256`] aliases give that same block-by-block
//! operation the mode API, so that systems and specifications which require ECB -- and test-vector
//! harnesses -- can use it through the same interface as the other modes. Like the CBC aliases they
//! carry a padding scheme, which is what lets them accept data of any length. Neither the mode API
//! nor the padding makes ECB confidential; the warning above applies to them unchanged.
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
//! * The working state (16, 32 or 64 bytes, by the entry point) is not scrubbed after a call.
//!   Only the key schedule is wrapped in `Secret`, and so only it is guaranteed to be zeroized on
//!   drop.
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
//! * The bit-sliced structure, the transpose, and the shape of the SHIFTROWS()/MIXCOLUMNS()
//!   mask-and-rotation code are translated from BearSSL's `aes_ct` implementation by Thomas
//!   Pornin (MIT licence). The bit layout is not BearSSL's -- blocks sit side by side in 16-bit
//!   lanes rather than interleaved bit by bit, so that one set of masks serves every width -- and
//!   every constant is derived from the documented layout in the comments and pinned by a test
//!   against a byte-wise reference written from the FIPS 197 equations.
//! * Verified against FIPS 197 Appendix A (all three key expansions, every word), FIPS 197
//!   Appendix B, NIST SP 800-38A Appendix F.1 (ECB, all three key lengths, both directions), and
//!   the NIST ACVP `ACVP-AES-ECB` vectors.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// `AESParams` is deliberately sealed with a private supertrait so that no fourth parameter set can
// be added outside this crate; that is what triggers this lint.
#![allow(private_bounds)]

pub mod aes_internal;
mod bitslice;
pub mod cbc;
pub mod cfb;
pub mod cfb8;
pub mod ctr;
pub mod ecb;
mod padded_mode;
mod round;
mod sbox;
mod schedule;

pub use aes_internal::BLOCK_LEN;
pub use cbc::{AES_CBC_128, AES_CBC_192, AES_CBC_256};
pub use cfb::{AES_CFB_128, AES_CFB_192, AES_CFB_256};
pub use cfb8::{AES_CFB8_128, AES_CFB8_192, AES_CFB8_256};
pub use ctr::{AES_CTR_128, AES_CTR_192, AES_CTR_256, CTR_NONCE_LEN};
pub use ecb::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
