//! Block cipher modes of operation (NIST SP 800-38A).
//!
//! A mode turns a keyed block permutation -- `bouncycastle-aes-lowmemory`'s `Aes128` and friends,
//! or anything else implementing [`BlockPermutation`] -- into something that can encrypt more than
//! one block. This crate provides:
//!
//! | Mode | Type | Spec | Notes |
//! |---|---|---|---|
//! | CBC | [`Cbc`] | SP 800-38A Sec 6.2 | Cipher Block Chaining |
//! | CFB | [`Cfb`] | SP 800-38A Sec 6.3 | Cipher Feedback, full-block segment (`s = b`) only |
//!
//! Both are strictly block-aligned and both generate their own IV; they differ only in how the
//! block permutation is wired up, and the two types have identical APIs and identical size. See
//! [Choosing between CBC and CFB](#choosing-between-cbc-and-cfb).
//!
//! The crate is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! trait. Define a one-line alias for the combination you use -- or use the ready-made
//! `AES_CBC_128` / `AES_CFB_128` and friends from `bouncycastle-aes-lowmemory`:
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
//! # Usage Examples
//!
//! The direction is part of the type: [`Cbc<P, Encrypting, ..>`](Cbc) implements
//! [`BlockCipherEncryptor`] and nothing else, and [`Cbc<P, Decrypting, ..>`](Cbc) implements
//! [`BlockCipherDecryptor`] and nothing else. [`Cfb`] is the same. The IV is generated for you and
//! returned; there is no API for supplying your own (see
//! [Security Considerations](#security-considerations)).
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
//! // 48 bytes: three whole blocks. A length that is not a multiple of 16 would not compile.
//! let plaintext: [u8; 48] = *b"The quick brown fox jumps over the lazy dog. OK!";
//!
//! // One shot, in place: encrypts under a freshly generated IV, which is returned.
//! let mut data = plaintext;
//! let iv = Aes128Cbc::<Encrypting>::encrypt(&key, &mut data).expect("encryption");
//! assert_ne!(data, plaintext);
//!
//! Aes128Cbc::<Decrypting>::decrypt(&key, &iv, &mut data).expect("decryption");
//! assert_eq!(data, plaintext);
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
//! let mut first = [0xAAu8; 16];
//! let mut rest = [0xBBu8; 32];
//! encryptor.do_encrypt(&mut first).expect("block 1");
//! encryptor.do_encrypt(&mut rest).expect("blocks 2-3");
//!
//! let mut decryptor = Aes256Cbc::<Decrypting>::do_decrypt_init(&key, &iv).expect("decrypt init");
//! decryptor.do_decrypt(&mut first).unwrap();
//! decryptor.do_decrypt(&mut rest).unwrap();
//! assert_eq!(first, [0xAAu8; 16]);
//! assert_eq!(rest, [0xBBu8; 32]);
//! ```
//!
//! CFB is a drop-in swap for CBC -- same methods, same IV convention, same block alignment. The
//! only visible difference is the ciphertext:
//!
//! ```
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Cfb, Decrypting, Encrypting};
//!
//! type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, 16>;
//! type Aes128Cfb<Dir> = Cfb<Aes128, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let plaintext = [0x5Au8; 32];
//!
//! let mut ciphertext = plaintext;
//! let iv = Aes128Cfb::<Encrypting>::encrypt(&key, &mut ciphertext).expect("encryption");
//! let mut recovered = ciphertext;
//! Aes128Cfb::<Decrypting>::decrypt(&key, &iv, &mut recovered).expect("decryption");
//! assert_eq!(recovered, plaintext);
//!
//! // The modes are not interchangeable: a ciphertext must be decrypted with the mode that
//! // produced it, and nothing at the type level stops you getting that wrong.
//! let mut as_if_cbc = ciphertext;
//! Aes128Cbc::<Decrypting>::decrypt(&key, &iv, &mut as_if_cbc).expect("decryption");
//! assert_ne!(as_if_cbc, plaintext);
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
//! # Choosing between CBC and CFB
//!
//! Neither is authenticated, so the honest answer for new designs is "neither -- use an AEAD".
//! Between the two:
//!
//! * **Error propagation differs**, and it is the sharpest practical difference. SP 800-38A
//!   Appendix D, Table D.2: a bit error in `Cj` gives CBC a *randomised* `Pj` plus the **same bit**
//!   flipped in `Pj+1`, and gives CFB the **same bit** flipped in `Pj` plus a randomised `Pj+1`.
//!   So under CFB an attacker who can flip a ciphertext bit flips the corresponding plaintext bit
//!   directly, in the block they targeted. Both are malleable; authenticate the ciphertext.
//! * **CFB needs only the forward cipher function**, in both directions (Sec 6.3). That halves what
//!   a permutation has to provide, and where the inverse costs more than the forward direction it
//!   makes CFB decryption faster: with `bouncycastle-aes-lowmemory` this crate's benches measure CFB
//!   decryption at about 1.37x CBC decryption (AES-128, 16 KiB, `N = 8`). Encryption is the same
//!   speed in both, since both are serial and both use only the forward function.
//! * **"CFB" alone is ambiguous.** SP 800-38A's `s = 8` and `s = 1` variants are also called CFB and
//!   are *not* interoperable with [`Cfb`], which is `s = b`. If you are matching an existing system,
//!   check which segment size it means before assuming this one. CBC has no such ambiguity.
//! * Both encrypt serially and decrypt in parallel, so their scaling with `N` matches.
//!
//! # Block alignment
//!
//! These types are **strictly block-aligned**: whole blocks in, whole blocks out, no finalization
//! step. SP 800-38A Sec 5.2 requires exactly that of CBC ("the total number of bits in the
//! plaintext must be a multiple of the block size"); for CFB it requires the total to be a multiple
//! of the segment size `s`, and this crate fixes `s = b`, so the requirement is the same. Appendix
//! A puts the formatting of non-aligned data outside the scope of the recommendation.
//!
//! Arbitrary-length data therefore needs a padding layer on top. That layer is *not* in this crate:
//! it is `bouncycastle-padding`, whose `PaddedEncryptor` / `PaddedDecryptor` wrap any
//! [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] pair, so both modes get arbitrary-length
//! support by being wrapped rather than by growing padding logic of their own.
//!
//! ```
//! use bouncycastle_aes_lowmemory::Aes128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_modes::{Cfb, Decrypting, Encrypting};
//! use bouncycastle_padding::{PKCS7, PaddedDecryptor, PaddedEncryptor};
//!
//! type Enc = PaddedEncryptor<Cfb<Aes128, Encrypting, 16, 16>, PKCS7, 16, 16, 16>;
//! type Dec = PaddedDecryptor<Cfb<Aes128, Decrypting, 16, 16>, PKCS7, 16, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // 5 bytes: not a whole block, which the bare mode would refuse to compile.
//! let message = b"hello";
//! let mut ciphertext = [0u8; 16];
//! let (iv, written) = Enc::encrypt_out(&key, message, &mut ciphertext).expect("encryption");
//! assert_eq!(written, 16);
//!
//! let mut plaintext = [0u8; 16];
//! let n = Dec::decrypt_out(&key, &iv, &ciphertext, &mut plaintext).expect("decryption");
//! assert_eq!(&plaintext[..n], message);
//! ```
//!
//! # Memory Usage
//!
//! No heap allocation, and no lookup tables of its own. A mode value is the permutation plus one
//! block of chaining value:
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
//! CFB is the same size as CBC because it stores the same thing: one block of input to the next
//! cipher call. Its keystream block `Oj` is recomputed per call and lives only in a local, so it
//! costs `BLOCK_LEN` of transient stack and nothing persistent.
//!
//! The data methods work in place. The pair path in either mode's decryptor adds one
//! `[[u8; BLOCK_LEN]; 2]` copy of the ciphertext it needs for the chaining value. [`Encrypting`] and [`Decrypting`] are zero-sized and held in a
//! `PhantomData`, so encoding the direction in the type is free. The table is pinned by
//! `sizes_match_the_documented_memory_table` in `tests/cbc_tests.rs` and `tests/cfb_tests.rs`.
//!
//! # Security Considerations
//!
//! ## Neither mode is authenticated
//!
//! Both provide confidentiality only. Neither detects tampering, and both are malleable in
//! specific, exploitable ways -- SP 800-38A Appendix D, Table D.2:
//!
//! * **CBC:** flipping a bit of `Cj` flips the same bit of the decryption of `Cj+1`, and randomises
//!   the decryption of `Cj` itself.
//! * **CFB:** flipping a bit of `Cj` flips the same bit of the decryption of `Cj` -- the block the
//!   attacker aimed at -- and randomises the decryption of `Cj+1`. So the controlled flip lands in
//!   the targeted block rather than the next one.
//!
//! **Authenticate the ciphertext.** Prefer an AEAD; if you must use either of these, MAC the
//! ciphertext *and* the IV, and verify before decrypting.
//!
//! Combining decryption with a padding check is the classic padding-oracle setup, for either mode.
//! Do not report padding failures distinguishably, and do not decrypt unauthenticated ciphertext.
//! `bouncycastle-padding`'s `unpad` is constant-time for exactly this reason, but constant-time
//! unpadding is not a substitute for authentication.
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
//! the IV is not protected". Under CBC a flipped IV bit flips exactly that bit of `P1`.
//!
//! CFB damages `P1` too, but unpredictably rather than controllably: the IV is the first thing fed
//! to the cipher, so Table D.2 gives *random* bit errors in the decryption of `C1` -- and, because
//! this crate fixes `s = b`, in `C1` only (Appendix D's "the first `i/s` (rounding up) ciphertext
//! segments" is one segment when `s = b`). Later blocks are unaffected in both modes.
//!
//! Either way the IV need not be secret, but it must be authenticated along with the ciphertext.
//!
//! ## Key and IV reuse
//!
//! Nothing here stops one key being used for many messages, which is fine for either mode provided
//! each gets a fresh unpredictable IV. It is the IV, not the key, that must not repeat.
//!
//! Repeating one matters more for CFB. CFB XORs a keystream, so two messages encrypted under the
//! same key *and* IV satisfy `C1 XOR C1' == P1 XOR P1'` -- the plaintext XOR leaks directly, the
//! classic two-time-pad failure, and it continues into later blocks for as long as the two
//! ciphertexts agree. CBC under a repeated IV leaks only whether the blocks were equal, not their
//! XOR. Since [`BlockCipherEncryptor::do_encrypt_init`] draws every IV from the DRBG, neither case
//! arises through this API; it is a reason not to add an IV-accepting one.
//!
//! # Not yet implemented
//!
//! * **The CFB segment sizes below the block size** (`s = 1` and `s = 8`, for which SP 800-38A
//!   Appendix F.3 also gives vectors). They are not block-aligned, so they need a
//!   `StreamCipher`-shaped API rather than [`BlockCipherEncryptor`].
//! * **ECB, OFB and CTR**, the other three modes of the recommendation. ECB is a raw permutation
//!   applied per block and is not confidential; OFB and CTR are keystream modes and, like CFB1/8,
//!   do not require block alignment.
//!
//! # Command line
//!
//! The `bc-rust` CLI exposes both modes for all three AES key lengths: `aes128-cbc`, `aes192-cbc`,
//! `aes256-cbc`, `aes128-cfb`, `aes192-cfb` and `aes256-cfb`, each taking `encrypt` or `decrypt`
//! and streaming stdin to stdout. Because there is no API for a caller-supplied IV, `encrypt`
//! writes the generated IV as the first block of its output and `decrypt` reads it back from the
//! first block of its input, so the two compose:
//!
//! ```text
//! bc-rust aes256-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cbc decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//!
//! bc-rust aes256-cfb encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cfb decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//! ```
//!
//! The `-cfb` commands are CFB128, matching [`Cfb`]. Input must be block-aligned there too, for the
//! reason given above.

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
