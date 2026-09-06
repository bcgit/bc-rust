//! Block cipher modes of operation (NIST SP 800-38A).
//!
//! A mode turns a keyed block permutation -- `bouncycastle-aes-lowmemory`'s `Aes128` and friends,
//! or anything else implementing [`BlockPermutation`] -- into something that can encrypt more than
//! one block. This crate currently provides **CBC** ([`Cbc`], SP 800-38A Sec 6.2).
//!
//! The crate is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! trait. Define a one-line alias for the combination you use:
//!
//! ```
//! use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
//! use bouncycastle_modes::Cbc;
//!
//! type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, 16>;
//! type Aes192Cbc<Dir> = Cbc<Aes192, Dir, 24, 16>;
//! type Aes256Cbc<Dir> = Cbc<Aes256, Dir, 32, 16>;
//! ```
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
//! # Block alignment
//!
//! These types are **strictly block-aligned**: whole blocks in, whole blocks out, no finalization
//! step. SP 800-38A Sec 5.2 requires exactly that of CBC ("the total number of bits in the
//! plaintext must be a multiple of the block size"), and Appendix A puts the formatting of
//! non-aligned data outside the scope of the recommendation.
//!
//! Arbitrary-length data therefore needs a padding layer on top. That layer is *not* in this
//! crate, and at the time of writing is not in the workspace at all -- see
//! [Not yet implemented](#not-yet-implemented).
//!
//! # Memory Usage
//!
//! No heap allocation, and no lookup tables of its own. A mode value is the permutation plus one
//! block of chaining value:
//!
//! ```text
//! size_of::<Cbc<P, Dir, KEY_LEN, BLOCK_LEN>>() == size_of::<P>() + BLOCK_LEN
//! ```
//!
//! | Combination | Permutation | Chain | Total |
//! |---|---|---|---|
//! | AES-128 CBC | 176 B | 16 B | 192 B |
//! | AES-192 CBC | 208 B | 16 B | 224 B |
//! | AES-256 CBC | 240 B | 16 B | 256 B |
//!
//! `do_*_blocks_out::<N>` adds nothing; the by-value `do_*_blocks::<N>` adds `N * BLOCK_LEN` of
//! stack for the returned array. [`Encrypting`] and [`Decrypting`] are zero-sized and held in a
//! `PhantomData`, so encoding the direction in the type is free. The table is pinned by
//! `sizes_match_the_documented_memory_table` in `tests/cbc_tests.rs`.
//!
//! # Security Considerations
//!
//! ## CBC is not authenticated
//!
//! CBC provides confidentiality only. It does not detect tampering, and it is malleable in
//! specific, exploitable ways -- SP 800-38A Appendix D: flipping a bit of `Cj` flips the same bit
//! of the decryption of `Cj+1`, and randomises the decryption of `Cj` itself. **Authenticate the
//! ciphertext.** Prefer an AEAD; if you must use CBC, MAC the ciphertext *and* the IV, and verify
//! before decrypting.
//!
//! Combining CBC decryption with a padding check is the classic padding-oracle setup. Do not
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
//! the IV is not protected". A flipped IV bit flips exactly that bit of `P1`. The IV need not be
//! secret, but it must be authenticated along with the ciphertext.
//!
//! ## Key and IV reuse
//!
//! Nothing here stops one key being used for many messages, which is fine for CBC provided each
//! gets a fresh unpredictable IV. It is the IV, not the key, that must not repeat.
//!
//! # Not yet implemented
//!
//! * **Padding.** There is no `Padding` trait, `PKCS7`, `PaddedEncryptor` or `PaddedDecryptor` in
//!   this workspace yet, so arbitrary-length CBC is not available. When that layer lands, CBC gets
//!   it for free by being wrapped -- no padding logic belongs in this crate.
//! * **CFB** (SP 800-38A Sec 6.3), and the other three modes of the recommendation (ECB, OFB, CTR).
//!
//! # Command line
//!
//! The `bc-rust` CLI exposes CBC as `aes128-cbc`, `aes192-cbc` and `aes256-cbc`, each taking
//! `encrypt` or `decrypt` and streaming stdin to stdout. Because there is no API for a
//! caller-supplied IV, `encrypt` writes the generated IV as the first block of its output and
//! `decrypt` reads it back from the first block of its input, so the two compose:
//!
//! ```text
//! bc-rust aes256-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cbc decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//! ```
//!
//! Input must be block-aligned there too, for the reason given above.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod cbc;
mod iv;

pub use cbc::Cbc;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation};
// end of imports needed for docs

/// Direction marker for a mode that encrypts. See [`Cbc`].
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encrypting;

/// Direction marker for a mode that decrypts. See [`Cbc`].
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decrypting;
