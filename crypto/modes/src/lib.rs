//! Block cipher modes of operation (NIST SP 800-38A).
//!
//! A mode turns a keyed block permutation -- `bouncycastle-aes-lowmemory`'s `Aes128` and friends,
//! or anything else implementing [`BlockPermutation`] -- into something that can encrypt more than
//! one block. This crate provides:
//!
//! | Mode | Type | Spec | Notes |
//! |---|---|---|---|
//! | Cipher Block Chaining | [`Cbc`] | Sec 6.2 | Uses both directions of the permutation. |
//! | Cipher Feedback | [`Cfb`] | Sec 6.3 | Full-block segment (`s = b`) only, i.e. "CFB128" for AES. Uses the **forward** direction in both directions of the mode. |
//!
//! The crate is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! trait. Define a one-line alias for the combination you use:
//!
//! ```
//! use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
//! use bouncycastle_modes::{Cbc, Cfb};
//!
//! type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, 16>;
//! type Aes192Cbc<Dir> = Cbc<Aes192, Dir, 24, 16>;
//! type Aes256Cbc<Dir> = Cbc<Aes256, Dir, 32, 16>;
//!
//! type Aes128Cfb<Dir> = Cfb<Aes128, Dir, 16, 16>;
//! type Aes192Cfb<Dir> = Cfb<Aes192, Dir, 24, 16>;
//! type Aes256Cfb<Dir> = Cfb<Aes256, Dir, 32, 16>;
//! ```
//!
//! Both types have the same shape and the same API, so swapping one for the other is a one-word
//! change. The differences that matter are in
//! [Security Considerations](#security-considerations): CFB's malleability is more directly
//! exploitable than CBC's.
//!
//! # Usage Examples
//!
//! The direction is part of the type: [`Cbc<P, Encrypting, ..>`](Cbc) implements
//! [`BlockCipherEncryptor`] and nothing else, and [`Cbc<P, Decrypting, ..>`](Cbc) implements
//! [`BlockCipherDecryptor`] and nothing else. The IV is generated for you and returned; there is no
//! API for supplying your own (see [Security Considerations](#security-considerations)).
//!
//! ```
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
//!
//! type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! let plaintext = [[0u8; 16], [1u8; 16], [2u8; 16]];
//!
//! // One shot: encrypts under a freshly generated IV, which is returned alongside the ciphertext.
//! let (iv, ciphertext) =
//!     Aes128Cbc::<Encrypting>::encrypt_blocks(&key, &plaintext).expect("encryption");
//!
//! let recovered =
//!     Aes128Cbc::<Decrypting>::decrypt_blocks(&key, &iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! Streaming, for data that arrives in pieces. A sequence of calls is equivalent to one call over
//! the concatenation:
//!
//! ```
//! use bouncycastle_aes_lowmemory::Aes256;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
//!
//! type Aes256Cbc<Dir> = Cbc<Aes256, Dir, 32, 16>;
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x07; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//!
//! let (mut encryptor, iv) =
//!     Aes256Cbc::<Encrypting>::do_encrypt_init(&key).expect("encrypt init");
//! let first = encryptor.do_encrypt_blocks(&[[0xAAu8; 16]]).expect("block 1");
//! let rest = encryptor.do_encrypt_blocks(&[[0xBBu8; 16], [0xCCu8; 16]]).expect("blocks 2-3");
//!
//! let mut decryptor = Aes256Cbc::<Decrypting>::do_decrypt_init(&key, &iv).expect("decrypt init");
//! assert_eq!(decryptor.do_decrypt_blocks(&first).unwrap(), [[0xAAu8; 16]]);
//! assert_eq!(decryptor.do_decrypt_blocks(&rest).unwrap(), [[0xBBu8; 16], [0xCCu8; 16]]);
//! ```
//!
//! [`Cfb`] is a drop-in substitution -- same API, same IV handling:
//!
//! ```
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Cfb, Decrypting, Encrypting};
//!
//! type Aes128Cfb<Dir> = Cfb<Aes128, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! let plaintext = [[0u8; 16], [1u8; 16], [2u8; 16]];
//!
//! let (iv, ciphertext) =
//!     Aes128Cfb::<Encrypting>::encrypt_blocks(&key, &plaintext).expect("encryption");
//!
//! let recovered =
//!     Aes128Cfb::<Decrypting>::decrypt_blocks(&key, &iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! Using the wrong direction does not compile:
//!
//! ```compile_fail
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::BlockCipherDecryptor;
//! use bouncycastle_modes::{Cbc, Encrypting};
//!
//! type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, 16>;
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // `Encrypting` does not implement `BlockCipherDecryptor`.
//! let _ = Aes128Cbc::<Encrypting>::do_decrypt_init(&key, &[0u8; 16]);
//! ```
//!
//! ...and the same for [`Cfb`], since the guarantee is per-type rather than crate-wide:
//!
//! ```compile_fail
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::BlockCipherEncryptor;
//! use bouncycastle_modes::{Cfb, Decrypting};
//!
//! type Aes128Cfb<Dir> = Cfb<Aes128, Dir, 16, 16>;
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // `Decrypting` does not implement `BlockCipherEncryptor`.
//! let _ = Aes128Cfb::<Decrypting>::do_encrypt_init(&key);
//! ```
//!
//! # Block alignment
//!
//! These types are **strictly block-aligned**: whole blocks in, whole blocks out, no finalization
//! step. SP 800-38A Sec 5.2 requires exactly that of CBC ("the total number of bits in the
//! plaintext must be a multiple of the block size"), and Appendix A puts the formatting of
//! non-aligned data outside the scope of the recommendation.
//!
//! For CFB, Sec 5.2 requires the plaintext length to be a multiple of the *segment* size `s`
//! rather than the block size. Since [`Cfb`] is the `s = b` variant, the two coincide and it is
//! block-aligned for the same reason. (A sub-block CFB would not be, which is one of the reasons
//! CFB1 and CFB8 do not fit these traits -- see [Not yet implemented](#not-yet-implemented).)
//!
//! Arbitrary-length data therefore needs a padding layer on top. That layer is *not* in this
//! crate, and at the time of writing is not in the workspace at all -- see
//! [Not yet implemented](#not-yet-implemented).
//!
//! # Memory Usage
//!
//! No heap allocation, and no lookup tables of its own. A mode value is the permutation plus one
//! block of chaining value, for both modes:
//!
//! ```text
//! size_of::<Cbc<P, Dir, KEY_LEN, BLOCK_LEN>>() == size_of::<P>() + BLOCK_LEN
//! size_of::<Cfb<P, Dir, KEY_LEN, BLOCK_LEN>>() == size_of::<P>() + BLOCK_LEN
//! ```
//!
//! | Combination | Permutation | Chain | Total |
//! |---|---|---|---|
//! | AES-128 CBC or CFB | 176 B | 16 B | 192 B |
//! | AES-192 CBC or CFB | 208 B | 16 B | 224 B |
//! | AES-256 CBC or CFB | 240 B | 16 B | 256 B |
//!
//! The two modes are the same size because they hold the same thing: one block that is an IV to
//! begin with and a ciphertext block thereafter. What differs is only what it is *used* for -- an
//! XOR operand in CBC, the cipher input in CFB.
//!
//! `do_*_blocks_out::<N>` adds nothing; the by-value `do_*_blocks::<N>` adds `N * BLOCK_LEN` of
//! stack for the returned array. CFB additionally uses one block of stack per call for the
//! keystream (two for the pair path), which does not scale with `N`. [`Encrypting`] and
//! [`Decrypting`] are zero-sized and held in a `PhantomData`, so encoding the direction in the type
//! is free. The table is pinned by `sizes_match_the_documented_memory_table` in `tests/cbc_tests.rs`
//! and `tests/cfb_tests.rs`.
//!
//! # Security Considerations
//!
//! ## Neither mode is authenticated
//!
//! Both provide confidentiality only. Neither detects tampering, and both are malleable in
//! specific, exploitable ways. **Authenticate the ciphertext.** Prefer an AEAD; if you must use
//! one of these, MAC the ciphertext *and* the IV, and verify before decrypting.
//!
//! SP 800-38A Appendix D, Table D.2, gives the exact malleability, and the two modes differ in a
//! way that matters. Writing SBE for "specific bit errors, i.e., bit errors occur in the same bit
//! position(s) as the original bit error(s)" and RBE for "random bit errors":
//!
//! | Flipping a bit of `Cj` gives | CBC | CFB (`s = b`) |
//! |---|---|---|
//! | in the decryption of `Cj` | RBE | **SBE** |
//! | in the decryption of `Cj+1` | SBE | RBE |
//! | in later blocks | none | none |
//!
//! The rows are swapped, and the consequence is that **CFB is the more directly attackable of the
//! two**: flipping bit `k` of a CFB ciphertext block flips exactly bit `k` of *that same block's*
//! plaintext, so an attacker who knows the plaintext can set it to anything they choose, exactly as
//! with a stream cipher. In CBC the targeted flip lands in the *following* block, and the block
//! attacked is randomised.
//!
//! Appendix D also notes the detection side: "for every ciphertext segment except the last one, the
//! existence of such bit errors may be detected by their randomizing effect on the decryption of
//! the succeeding ciphertext segment". Read the exception. **For the final CFB block there is no
//! succeeding block to be randomised**, so a bit flip there produces a precisely chosen plaintext
//! change with no structural trace whatsoever. Do not rely on garbling to notice tampering.
//!
//! Combining a mode's decryption with a padding check is the classic padding-oracle setup. Do not
//! report padding failures distinguishably, and do not decrypt unauthenticated ciphertext.
//!
//! ## The IV must be unpredictable, and this crate generates it
//!
//! SP 800-38A Sec 5.3 requires that "for the CBC and CFB modes, the IV for any particular execution
//! of the encryption process must be unpredictable" -- not merely unique. Appendix C spells out
//! that "for any given plaintext, it must not be possible to predict the IV that will be associated
//! to the plaintext in advance of the generation of the IV".
//!
//! Rather than accept an IV and hope, [`BlockCipherEncryptor::do_encrypt_init`] generates one from
//! the library's default OS-backed DRBG and returns it. There is deliberately **no** API for
//! supplying your own. Known-answer tests drive [`BlockCipherEncryptor::do_encrypt_init_rng`] with
//! a fixed-output test RNG instead.
//!
//! ## IV integrity
//!
//! Appendix D: "for the CBC mode, the decryption of the first ciphertext block is vulnerable to the
//! (deliberate) introduction of bit errors in specific bit positions of the IV if the integrity of
//! the IV is not protected". A flipped IV bit flips exactly that bit of `P1`.
//!
//! For CFB the IV is an input to the cipher rather than an XOR operand, so Table D.2 gives RBE
//! instead: a flipped IV bit randomises the whole of `P1` (and, at `s = b`, nothing further). Less
//! of a targeted-modification vector than CBC's, but still a tampering vector.
//!
//! Either way the IV need not be secret, but it must be authenticated along with the ciphertext.
//!
//! ## Key and IV reuse
//!
//! Nothing here stops one key being used for many messages, which is fine for either mode provided
//! each gets a fresh unpredictable IV. It is the IV, not the key, that must not repeat.
//!
//! **Repeating an IV is worse in CFB than in CBC.** CFB at `s = b` XORs the plaintext with
//! `O1 = CIPH_K(IV)`, so two messages under the same key and IV have the same first keystream
//! block, and `C1 XOR C1' = P1 XOR P1'` -- a two-time pad, leaking the XOR of the plaintexts
//! outright, and continuing into later blocks for as long as the ciphertexts agree. Under CBC an
//! IV repeat leaks only whether the messages share a prefix.
//!
//! # Not yet implemented
//!
//! * **Padding.** There is no `Padding` trait, `PKCS7`, `PaddedEncryptor` or `PaddedDecryptor` in
//!   this workspace yet, so arbitrary-length CBC and CFB are not available. When that layer lands,
//!   both get it for free by being wrapped -- no padding logic belongs in this crate.
//! * **Sub-block CFB segments** (CFB1, CFB8, and any other `s < b`). Sec 6.3 allows any
//!   `1 <= s <= b`, but only `s = b` is block-aligned, and `BlockCipherEncryptor` /
//!   `BlockCipherDecryptor` are block-aligned by contract. A sub-block CFB is a stream cipher in
//!   shape -- it consumes `s` bits at a time and holds a partially-used input block between calls
//!   -- so it belongs behind a `StreamCipher` trait, not this one. Note that a CFB with `s < b`
//!   also invokes the block cipher once per `s` bits, so CFB1 costs 128 AES calls per block.
//! * **ECB, OFB and CTR**, the remaining three modes of the recommendation. ECB is a mode in name
//!   only and should not be added as an encryption API.
//!
//! # Command line
//!
//! The `bc-rust` CLI exposes both modes for all three AES key lengths -- `aes128-cbc`,
//! `aes192-cbc`, `aes256-cbc`, `aes128-cfb`, `aes192-cfb`, `aes256-cfb` -- each taking `encrypt` or
//! `decrypt` and streaming stdin to stdout. Because there is no API for a caller-supplied IV,
//! `encrypt` writes the generated IV as the first block of its output and `decrypt` reads it back
//! from the first block of its input, so the two compose:
//!
//! ```text
//! bc-rust aes256-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cbc decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//!
//! bc-rust aes128-cfb encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes128-cfb decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//! ```
//!
//! Input must be block-aligned there too, for the reason given above. The CFB subcommands are the
//! `s = b` variant, i.e. CFB128.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod cbc;
mod cfb;
mod iv;

pub use cbc::Cbc;
pub use cfb::Cfb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation};
// end of imports needed for docs

/// Direction marker for a mode that encrypts. See [`Cbc`] and [`Cfb`].
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encrypting;

/// Direction marker for a mode that decrypts. See [`Cbc`] and [`Cfb`].
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decrypting;
