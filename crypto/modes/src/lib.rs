//! Block cipher modes of operation (NIST SP 800-38A).
//!
//! A mode turns a keyed block permutation -- `bouncycastle-aes`'s `AES_128` and friends,
//! or anything else implementing [`ElectronicCodeBook`] -- into something that can encrypt more than
//! one block. This crate provides:
//!
//! | Mode | Type | Spec | Notes |
//! |---|---|---|---|
//! | ECB | [`Ecb`] | SP 800-38A Sec 6.1 | Electronic Codebook. **Not confidential for data**; interoperability and test vectors only |
//! | CBC | [`Cbc`] | SP 800-38A Sec 6.2 | Cipher Block Chaining |
//! | CFB | [`Cfb`] | SP 800-38A Sec 6.3 | Cipher Feedback, full-block segment (`s = b`), i.e. CFB128 for AES |
//! | CFB8 | [`Cfb8`] | SP 800-38A Sec 6.3 | Cipher Feedback, 8-bit segment (`s = 8`) |
//! | CTR | [`Ctr`] | SP 800-38A Sec 6.5 | Counter. Nonce plus counter, both directions parallel |
//!
//! They divide two ways. **ECB and CBC are block ciphers** ([`BlockCipherEncryptor`] /
//! [`BlockCipherDecryptor`]): whole blocks in, whole blocks out, and arbitrary-length data needs
//! the padding layer. **CFB, CFB8 and CTR are stream ciphers** ([`StreamCipherEncryptor`] /
//! [`StreamCipherDecryptor`]): any length in, the same length out, no padding, no finalization --
//! see [Block alignment, and which modes need it](#block-alignment-and-which-modes-need-it).
//!
//! **All five reach the same arbitrary-length API**, so code can be written against one trait and
//! handed any mode. A block mode gets there by being wrapped in `bouncycastle-padding`'s adapters,
//! which are [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] with the padded block as
//! their final output; a stream mode implements those traits directly, with `FINAL_LEN = 0` because
//! it has no final output at all. The `bouncycastle-aes` aliases show the difference in
//! one line each: `AES_CBC_128<Encrypting, PKCS7>` names a padding scheme, `AES_CTR_128<Encrypting>`
//! has nothing to name.
//!
//! CBC, CFB, CFB8 and CTR all generate their own init data: an IV for the first three, a nonce for
//! CTR, which is shorter than a block because the rest of the counter block is the counter. ECB has
//! none at all (`INIT_DATA_LEN = 0`) and is the raw permutation applied block by block -- see
//! [ECB is not a confidentiality mode for data](#ecb-is-not-a-confidentiality-mode-for-data) and
//! [Choosing between the modes](#choosing-between-the-modes).
//!
//! [`Cfb`] and [`Cfb8`] are the same construction at two segment sizes, but they are **different,
//! non-interoperable modes** whose ciphertexts differ from the first byte. "CFB" unqualified is
//! ambiguous between them; see [`Cfb8`] for the cost difference, which is a factor of 16 on AES.
//!
//! The crate is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! trait. Define a one-line alias for the combination you use -- or use the ready-made
//! `AES_CBC_128` / `AES_CFB_128` / `AES_CFB8_128` / `AES_CTR_128` / `AES_ECB_128` and friends from
//! `bouncycastle-aes`. Those aliases are not all the same shape: the two block modes take
//! a padding scheme as well as a direction, since neither is usable on data of arbitrary length
//! without one, while the three stream modes take only the direction:
//!
//! ```
//! use bouncycastle_aes::{AES_128, AES_192, AES_256};
//! use bouncycastle_modes::{Cbc, Cfb, Cfb8, Ctr, Ecb};
//!
//! type Aes128Cbc<Dir> = Cbc<AES_128, Dir, 16, 16>;
//! type Aes192Cbc<Dir> = Cbc<AES_192, Dir, 24, 16>;
//! type Aes256Cbc<Dir> = Cbc<AES_256, Dir, 32, 16>;
//!
//! type Aes128Cfb<Dir> = Cfb<AES_128, Dir, 16, 16>;
//! type Aes192Cfb<Dir> = Cfb<AES_192, Dir, 24, 16>;
//! type Aes256Cfb<Dir> = Cfb<AES_256, Dir, 32, 16>;
//!
//! type Aes128Cfb8<Dir> = Cfb8<AES_128, Dir, 16, 16>;
//!
//! // CTR takes one more parameter: the nonce length, which fixes the counter width at
//! // `BLOCK_LEN - NONCE_LEN`. 12 bytes of nonce leaves the maximum 4-byte counter.
//! type Aes128Ctr<Dir> = Ctr<AES_128, Dir, 16, 16, 12>;
//!
//! type Aes128Ecb<Dir> = Ecb<AES_128, Dir, 16, 16>;
//! ```
//!
//! # Usage Examples
//!
//! The direction is part of the type: [`Cbc<P, Encrypting, ..>`](Cbc) implements
//! [`BlockCipherEncryptor`] and nothing else, and [`Cbc<P, Decrypting, ..>`](Cbc) implements
//! [`BlockCipherDecryptor`] and nothing else. [`Cfb`] and [`Cfb8`] are the same, with
//! [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`] in place of the block traits. The IV is
//! generated for you and returned; there is no API for supplying your own (see
//! [Security Considerations](#security-considerations)).
//!
//! ```
//! use bouncycastle_aes::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
//!
//! type Aes128Cbc<Dir> = Cbc<AES_128, Dir, 16, 16>;
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
//! use bouncycastle_aes::AES_256;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
//!
//! type Aes256Cbc<Dir> = Cbc<AES_256, Dir, 32, 16>;
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
//! CFB and CFB8 have the same shape and the same IV convention, but they take a `&mut [u8]` of any
//! length rather than a block-aligned array, so there is no padding layer and the ciphertext is
//! exactly as long as the plaintext:
//!
//! ```
//! use bouncycastle_aes::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_modes::{Cfb, Cfb8, Decrypting, Encrypting};
//!
//! type Aes128Cfb<Dir> = Cfb<AES_128, Dir, 16, 16>;
//! type Aes128Cfb8<Dir> = Cfb8<AES_128, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! // 21 bytes: not a whole number of blocks, which a stream cipher does not care about.
//! let plaintext = *b"the quick brown fox!!";
//!
//! let mut ciphertext = plaintext;
//! let iv = Aes128Cfb::<Encrypting>::encrypt(&key, &mut ciphertext).expect("encryption");
//! assert_eq!(ciphertext.len(), plaintext.len());
//!
//! let mut recovered = ciphertext;
//! Aes128Cfb::<Decrypting>::decrypt(&key, &iv, &mut recovered).expect("decryption");
//! assert_eq!(recovered, plaintext);
//!
//! // CFB8 is a *different mode*, not a variant: nothing at the type level stops you pairing it
//! // with a CFB ciphertext, and it will not recover the plaintext.
//! let mut as_if_cfb8 = ciphertext;
//! Aes128Cfb8::<Decrypting>::decrypt(&key, &iv, &mut as_if_cfb8).expect("decryption");
//! assert_ne!(as_if_cfb8, plaintext);
//! ```
//!
//! Streaming works at any byte boundary, and the chunking is not visible in the output:
//!
//! ```
//! use bouncycastle_aes::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_modes::{Cfb, Decrypting, Encrypting};
//!
//! type Aes128Cfb<Dir> = Cfb<AES_128, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let plaintext = [0x5Au8; 40];
//!
//! let (mut encryptor, iv) = Aes128Cfb::<Encrypting>::do_encrypt_init(&key).expect("init");
//! let mut chunked = plaintext;
//! // 7 bytes, then 33: neither is a whole block, and the second call finishes the segment the
//! // first one left open.
//! encryptor.do_encrypt(&mut chunked[..7]).expect("first chunk");
//! encryptor.do_encrypt(&mut chunked[7..]).expect("the rest");
//!
//! // A single call under the same key and IV gives the identical ciphertext.
//! let (mut encryptor, _) = Aes128Cfb::<Encrypting>::do_encrypt_init(&key).expect("init");
//! let mut decryptor = Aes128Cfb::<Decrypting>::do_decrypt_init(&key, &iv).expect("init");
//! let mut recovered = chunked;
//! // Decrypting in yet another chunking must also agree.
//! decryptor.do_decrypt(&mut recovered[..19]).expect("first chunk");
//! decryptor.do_decrypt(&mut recovered[19..]).expect("the rest");
//! assert_eq!(recovered, plaintext);
//! let _ = &mut encryptor;
//! ```
//!
//! ECB has the same shape with no IV: `encrypt` returns an empty array and `decrypt` takes one.
//! The codebook property that makes it unsuitable for data is visible in the ciphertext:
//!
//! ```
//! use bouncycastle_aes::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Ecb, Encrypting};
//!
//! type Aes128Ecb<Dir> = Ecb<AES_128, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let plaintext = [0x5Au8; 32]; // two equal blocks
//!
//! let mut data = plaintext;
//! let no_iv: [u8; 0] = Aes128Ecb::<Encrypting>::encrypt(&key, &mut data).expect("encryption");
//! assert_eq!(data[..16], data[16..], "equal plaintext blocks give equal ciphertext blocks");
//!
//! Aes128Ecb::<Decrypting>::decrypt(&key, &no_iv, &mut data).expect("decryption");
//! assert_eq!(data, plaintext);
//! ```
//!
//! Using the wrong direction does not compile:
//!
//! ```compile_fail
//! use bouncycastle_aes::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::BlockCipherDecryptor;
//! use bouncycastle_modes::{Cbc, Encrypting};
//!
//! type Aes128Cbc<Dir> = Cbc<AES_128, Dir, 16, 16>;
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // `Encrypting` does not implement `BlockCipherDecryptor`.
//! let _ = Aes128Cbc::<Encrypting>::do_decrypt_init(&key, &[0u8; 16]);
//! ```
//!
//! # Choosing between the modes
//!
//! None is authenticated, so the honest answer for new designs is "none of them -- use an AEAD".
//! ECB is not a candidate for data at all (below). Between the rest:
//!
//! * **Only CBC needs padding.** CFB and CFB8 are stream ciphers: any length in, the same length
//!   out. CBC needs the data padded to a whole number of blocks, which means a padding layer and
//!   the padding-oracle care that comes with it.
//! * **Error propagation differs**, and it is the sharpest practical difference. SP 800-38A
//!   Appendix D, Table D.2: a bit error in `Cj` gives CBC a *randomised* `Pj` plus the **same bit**
//!   flipped in `Pj+1`, and gives CFB the **same bit** flipped in `Pj` plus a randomised `Pj+1`.
//!   So under CFB an attacker who can flip a ciphertext bit flips the corresponding plaintext bit
//!   directly, in the segment they targeted. All are malleable; authenticate the ciphertext.
//! * **CFB and CFB8 need only the forward cipher function**, in both directions (Sec 6.3). That
//!   halves what a permutation has to provide, and where the inverse costs more than the forward
//!   direction it makes CFB decryption faster: with `bouncycastle-aes` this crate's
//!   benches measure CFB decryption at about 1.37x CBC decryption (AES-128, 16 KiB, `N = 8`).
//!   Encryption is the same speed in CBC and CFB, since both are serial and both use only the
//!   forward function.
//! * **CFB8 costs a full cipher call per byte** -- 16x the work of CFB on AES, since `MSB_8(Oj)`
//!   keeps one byte of each output block and discards the other fifteen. Choose it only when a
//!   byte-granular self-synchronising stream is required or an existing format demands it.
//! * **"CFB" alone is ambiguous.** [`Cfb`] is `s = b` (CFB128 on AES) and [`Cfb8`] is `s = 8`; they
//!   are different, non-interoperable modes, and SP 800-38A's `s = 1` variant is a third. If you
//!   are matching an existing system, check which segment size it means. CBC has no such ambiguity.
//! * CBC, CFB and CFB8 all encrypt serially and decrypt in parallel, so their scaling with `N`
//!   matches.
//! * **CTR is parallel in both directions**, the only one here that is. Its counter blocks depend
//!   on nothing but the nonce and the index (Sec 6.5), so encryption batches exactly as decryption
//!   does and the two run at the same speed -- roughly what the feedback modes reach only when
//!   decrypting. It needs only the forward cipher function, like the CFB modes.
//! * **CTR has a per-message limit and enforces it.** The counter is `BLOCK_LEN - NONCE_LEN` bytes,
//!   capped at 4, so a message is at most `2^(8 * counter bytes)` blocks; past that [`Ctr`] returns
//!   an error rather than repeating keystream. None of the other modes can fail on a data method.
//! * **CTR is the most malleable.** A flipped ciphertext bit flips exactly the corresponding
//!   plaintext bit and disturbs nothing else, so tampering leaves no garbling behind at all; the
//!   feedback modes at least randomise a neighbouring block. Authenticate the ciphertext.
//!
//! # Block alignment, and which modes need it
//!
//! SP 800-38A Sec 5.2 sets the requirement per mode, and this crate follows it exactly:
//!
//! * **ECB and CBC** -- "the total number of bits in the plaintext must be a multiple of the block
//!   size, b". [`Ecb`] and [`Cbc`] are therefore **strictly block-aligned**: whole blocks in, whole
//!   blocks out, no finalization step, and a misaligned length is a compile error at the call site.
//! * **CFB and CFB8** -- "the total number of bits in the plaintext must be a multiple of a
//!   parameter, denoted s". For [`Cfb8`], `s = 8`, so every byte string qualifies and there is
//!   nothing to align. For [`Cfb`], `s = b`, so strictly the message should be a whole number of
//!   blocks; [`Cfb`] accepts any length anyway and treats a short final segment as `s = 8r` for
//!   that segment only, which is what every streaming CFB128 implementation does and what makes
//!   the ciphertexts interoperate. Its module docs derive that from the Sec 6.3 equations.
//! * **CTR** -- "the plaintext need not be a multiple of the block size", and Sec 6.5 says what to
//!   do with the last, possibly partial, block: XOR it with `MSB_u(On)` and discard the rest of the
//!   output block. So [`Ctr`] has no alignment requirement at all, by the recommendation's own
//!   terms rather than by extension.
//!
//! Appendix A puts the formatting of non-aligned data outside the scope of the recommendation.
//!
//! So arbitrary-length data needs a padding layer **for CBC only**. That layer is not in this
//! crate: it is `bouncycastle-padding`, whose `PaddedEncryptor` / `PaddedDecryptor` wrap any
//! [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] pair, so a block mode gets arbitrary-length
//! support by being wrapped rather than by growing padding logic of its own. The same adapters
//! over `bouncycastle-padding`'s `NoPadding` give the opposite guarantee -- an unaligned message is
//! an error at `do_final` rather than something padded -- for formats defined on whole blocks.
//!
//! ```
//! use bouncycastle_aes::AES_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
//! use bouncycastle_padding::{PKCS7, PaddedDecryptor, PaddedEncryptor};
//!
//! type Enc = PaddedEncryptor<Cbc<AES_128, Encrypting, 16, 16>, PKCS7, 16, 16, 16>;
//! type Dec = PaddedDecryptor<Cbc<AES_128, Decrypting, 16, 16>, PKCS7, 16, 16, 16>;
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
//! No heap allocation, and no lookup tables of its own. A CBC or CFB8 value is the permutation plus
//! one block of chaining value; a CFB value adds a `usize` to that; a CTR value carries the nonce,
//! a counter and a keystream block; an ECB value is just the permutation, since nothing chains:
//!
//! ```text
//! size_of::<Cbc<P, Dir, KEY_LEN, BLOCK_LEN>>()  == size_of::<P>() + BLOCK_LEN
//! size_of::<Cfb8<P, Dir, KEY_LEN, BLOCK_LEN>>() == size_of::<P>() + BLOCK_LEN
//! size_of::<Cfb<P, Dir, KEY_LEN, BLOCK_LEN>>()  == size_of::<P>() + BLOCK_LEN + size_of::<usize>()
//! size_of::<Ecb<P, Dir, KEY_LEN, BLOCK_LEN>>()  == size_of::<P>()
//!
//! // CTR, rounded up to the counter's 8-byte alignment:
//! size_of::<Ctr<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN>>()
//!     == align8(size_of::<P>() + NONCE_LEN + 8 + BLOCK_LEN + 8)
//! ```
//!
//! | Combination | Permutation | Chain | Count | Total |
//! |---|---|---|---|---|
//! | AES-128 CBC or CFB8 | 176 B | 16 B | -- | 192 B |
//! | AES-192 CBC or CFB8 | 208 B | 16 B | -- | 224 B |
//! | AES-256 CBC or CFB8 | 240 B | 16 B | -- | 256 B |
//! | AES-128 CFB | 176 B | 16 B | 8 B | 200 B |
//! | AES-192 CFB | 208 B | 16 B | 8 B | 232 B |
//! | AES-256 CFB | 240 B | 16 B | 8 B | 264 B |
//! | AES-128 CTR | 176 B | 12 B nonce + 16 B keystream | 8 B | 224 B |
//! | AES-192 CTR | 208 B | 12 B nonce + 16 B keystream | 8 B | 256 B |
//! | AES-256 CTR | 240 B | 12 B nonce + 16 B keystream | 8 B | 288 B |
//! | AES-128 ECB | 176 B | 0 B | -- | 176 B |
//! | AES-192 ECB | 208 B | 0 B | -- | 208 B |
//! | AES-256 ECB | 240 B | 0 B | -- | 240 B |
//!
//! CFB8 is the same size as CBC because it stores the same thing: one block of input to the next
//! cipher call. CFB adds one `usize` because its segment is a whole block and a call may end
//! part-way through one, so it records how much of the current segment has been used; its single
//! block does triple duty as the input block, the output block and the next input block, which is
//! why there is no second buffer. (The 8 B figure is a 64-bit `usize`.)
//!
//! CTR is the largest because it is the only mode that must keep a keystream block *and* the state
//! that generates it: the nonce and the counter cannot be recovered from the keystream, and the
//! keystream cannot be recomputed without them. Its counter is a `u64` rather than the 1-to-4
//! counter bytes so that exhaustion is representable -- the counter field itself wraps, and a mode
//! that read its position back out of those bytes could not tell "just started" from "used up".
//! The keystream block is the one buffer in this crate held in a `Secret`: unlike a chaining value
//! it is live key material for the bytes not yet consumed.
//!
//! The data methods work in place. The batch paths in a decryptor are the transient cost: a
//! `[[u8; BLOCK_LEN]; 4]` of stack for the four-block path -- 64 B on AES -- and a
//! `[[u8; BLOCK_LEN]; 2]` for the pair path. CFB8's batch paths hold input blocks it builds itself;
//! CBC's and CFB's hold a copy of the ciphertext they need for the chaining value.
//! [`Encrypting`] and [`Decrypting`] are zero-sized and held in a `PhantomData`, so encoding the
//! direction in the type is free. The table is pinned by
//! `sizes_match_the_documented_memory_table` in `tests/cbc_tests.rs`, `tests/cfb_tests.rs`,
//! `tests/cfb8_tests.rs` and `tests/ecb_tests.rs`.
//!
//! # Security Considerations
//!
//! ## ECB is not a confidentiality mode for data
//!
//! SP 800-38A Sec 6.1: "In the ECB mode, under a given key, any given plaintext block always gets
//! encrypted to the same ciphertext block. If this property is undesirable in a particular
//! application, the ECB mode should not be used." It is undesirable for data: equal plaintext
//! blocks give equal ciphertext blocks, so patterns in the plaintext show through the ciphertext;
//! the same message encrypts to the same ciphertext every time, so an observer learns when a message
//! repeats; and with nothing tying blocks together, ciphertext blocks can be reordered, duplicated or
//! deleted, or spliced in from another message under the same key, and the result decrypts to
//! plaintext that looks valid block by block.
//!
//! [`Ecb`] is in this crate because ECB is what some specifications and existing systems require --
//! a raw permutation exposed through the same mode API as the others, so that a key-wrapping scheme,
//! a legacy protocol or a test-vector harness can use it -- and because it is the natural way to
//! drive an [`ElectronicCodeBook`] implementation's known-answer tests. Do not use it to encrypt
//! data. If you find yourself reaching for it because it needs no IV, that is the problem the IV
//! solves.
//!
//! ## None of the modes is authenticated
//!
//! All four provide, at best, confidentiality only. None detects tampering, and each is malleable
//! in specific, exploitable ways -- SP 800-38A Appendix D, Table D.2, whose CFB row is
//! "SBE in the decryption of `Cj`" plus "RBE in the decryption of `Cj+1`,...,`Cj+b/s`" (SBE =
//! specific bit errors, the same positions; RBE = random bit errors):
//!
//! * **ECB:** flipping a bit of `Cj` randomises the decryption of `Cj` and nothing else, and whole
//!   blocks can be reordered, repeated or dropped undetectably (above).
//! * **CBC:** flipping a bit of `Cj` flips the same bit of the decryption of `Cj+1`, and randomises
//!   the decryption of `Cj` itself.
//! * **CFB:** flipping a bit of `Cj` flips the same bit of the decryption of `Cj` -- the segment
//!   the attacker aimed at -- and randomises the decryption of `Cj+1`, `b/s` being 1 here. So the
//!   controlled flip lands in the targeted block rather than the next one.
//! * **CTR:** flipping a bit of `Cj` flips the same bit of the decryption of `Cj` and affects
//!   **nothing else at all** -- Table D.2's CTR row is "SBE in the decryption of Cj" with no second
//!   clause. That makes it the most malleable of the five: an attacker can edit any plaintext bit
//!   they can locate, leaving no garbled block anywhere to betray the change.
//! * **CFB8:** the same controlled flip in the targeted byte, but `b/s` is 16 on a 16-byte block,
//!   so the randomised run is the **next 16 bytes** rather than the next one. After that the shift
//!   register has flushed and decryption resynchronises, which is the self-synchronising property
//!   CFB8 is chosen for -- and it also means a tampered byte damages a bounded, predictable window
//!   rather than the rest of the message.
//!
//! **Authenticate the ciphertext.** Prefer an AEAD; if you must use one of these, MAC the
//! ciphertext *and* the IV, and verify before decrypting.
//!
//! Combining decryption with a padding check is the classic padding-oracle setup. It applies to CBC
//! here, the one mode that needs padding; do not report padding failures distinguishably, and do
//! not decrypt unauthenticated ciphertext. `bouncycastle-padding`'s `unpad` is constant-time for
//! exactly this reason, but constant-time unpadding is not a substitute for authentication.
//!
//! ## The IV must be unpredictable, and this crate generates it
//!
//! (ECB has no IV; Table D.2 lists its IV column as "Not applicable". This section is about CBC,
//! CFB and CFB8.)
//!
//! SP 800-38A Sec 5.3 requires that "for the CBC and CFB modes, the IV for any particular execution
//! of the encryption process must be unpredictable" -- not merely unique. Appendix C spells out
//! that "for any given plaintext, it must not be possible to predict the IV that will be associated
//! to the plaintext in advance of the generation of the IV".
//!
//! Rather than accept an IV and hope, `do_encrypt_init` generates one from the library's default
//! OS-backed DRBG and returns it, in both the block traits and the stream traits. There is
//! deliberately **no** API for supplying your own. Known-answer tests drive `do_encrypt_init_rng`
//! with a fixed-output test RNG instead.
//!
//! ## IV integrity
//!
//! Appendix D: "for the CBC mode, the decryption of the first ciphertext block is vulnerable to the
//! (deliberate) introduction of bit errors in specific bit positions of the IV if the integrity of
//! the IV is not protected". Under CBC a flipped IV bit flips exactly that bit of `P1`.
//!
//! CFB damages `P1` too, but unpredictably rather than controllably: the IV is the first thing fed
//! to the cipher, so Table D.2 gives *random* bit errors in the decryption of `C1` -- and, because
//! [`Cfb`] fixes `s = b`, in `C1` only (Appendix D's "a bit error in the ith most significant bit
//! position affects the decryptions of the first `i/s` (rounding up) ciphertext segments" is one
//! segment for every `i` when `s = b`). Later blocks are unaffected.
//!
//! Under CFB8 that same rule reaches further: with `s = 8` it randomises up to the first 16
//! segments, the count depending on the position of the rightmost corrupted bit, because a byte
//! near the end of the IV stays in the shift register for 16 steps while the leading byte is shifted
//! out after one.
//!
//! Either way the IV need not be secret, but it must be authenticated along with the ciphertext.
//!
//! ## Key and IV reuse
//!
//! Nothing here stops one key being used for many messages, which is fine for any of them provided
//! each gets a fresh unpredictable IV. It is the IV, not the key, that must not repeat.
//!
//! For **CTR** a repeated nonce is not merely unwise, it is fatal, and in a way the IV modes are
//! not: the counter blocks are a pure function of the nonce and the index, so the same nonce under
//! the same key reproduces the *entire keystream* from the first byte, and two messages encrypted
//! under it differ by exactly the XOR of their plaintexts. Sec 6.5 states the requirement as an
//! absolute: "across all of the messages that are encrypted under the given key, all of the
//! counters must be distinct". [`Ctr`] draws its nonce from the DRBG and enforces the within-message
//! half of that by refusing to run past the counter's last value; the across-message half is what
//! the nonce is for.
//!
//! Repeating one matters more for CFB and CFB8. Both XOR a keystream, so two messages encrypted
//! under the same key *and* IV satisfy `C1 XOR C1' == P1 XOR P1'` -- the plaintext XOR leaks
//! directly, the classic two-time-pad failure, and it continues for as long as the two ciphertexts
//! agree. CBC under a repeated IV leaks only whether the blocks were equal, not their XOR. Since
//! every mode's `do_encrypt_init` draws its IV from the DRBG, neither case arises through this API;
//! it is a reason not to add an IV-accepting one.
//!
//! # Not yet implemented
//!
//! * **CFB1**, the `s = 1` segment size (SP 800-38A Appendix F.3.1-F.3.6). Its segment is a single
//!   *bit*, so unlike [`Cfb`] and [`Cfb8`] it does not fit a byte-oriented API at all: a message is
//!   a bit string whose length need not be a multiple of 8, which this crate has no type for.
//! * **OFB**, the one remaining mode of the recommendation. It is a keystream mode and, like CFB,
//!   CFB8 and CTR, would implement [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`].
//!
//! # Command line
//!
//! The `bc-rust` CLI exposes all five modes for all three AES key lengths: `aes{128,192,256}-cbc`,
//! `-cfb`, `-cfb8`, `-ctr` and `-ecb`, each taking `encrypt` or `decrypt` and streaming stdin to
//! stdout. There is no API for caller-supplied init data anywhere, so `encrypt` writes what it
//! generated at the front of its output and `decrypt` reads it back, and the two compose. That is
//! one block for CBC, CFB and CFB8, **12 bytes** for CTR, and nothing at all for `-ecb`:
//!
//! ```text
//! bc-rust aes256-cbc encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cbc decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//!
//! bc-rust aes256-cfb encrypt --key-file k.bin < plain.bin > cipher.bin
//! bc-rust aes256-cfb decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//!
//! bc-rust aes256-ctr encrypt --key-file k.bin < plain.bin > cipher.bin   # 12-byte nonce first
//! bc-rust aes256-ctr decrypt --key-file k.bin < cipher.bin | cmp - plain.bin
//!
//! bc-rust aes128-ecb encrypt --key-file k.bin < plain.bin > cipher.bin   # same length out as in
//! ```
//!
//! The `-cfb` commands are CFB128, matching [`Cfb`], and the `-cfb8` commands are CFB8, matching
//! [`Cfb8`]; the two are not interoperable. The `-ctr` commands use a 12-byte nonce and so a 4-byte
//! counter, matching `AES_CTR_*`. Input must be block-aligned for the `-cbc` and `-ecb` commands,
//! and may be any length for `-cfb`, `-cfb8` and `-ctr`, for the reason given above.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod cbc;
mod cfb;
mod cfb8;
mod ctr;
mod ecb;
mod iv;

pub use cbc::Cbc;
pub use cfb::Cfb;
pub use cfb8::Cfb8;
pub use ctr::Ctr;
pub use ecb::Ecb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
// end of imports needed for docs

/// Direction marker for a mode that encrypts. See [`Cbc`], [`Cfb`], [`Cfb8`], [`Ctr`] and [`Ecb`].
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encrypting;

/// Direction marker for a mode that decrypts. See [`Cbc`], [`Cfb`], [`Cfb8`], [`Ctr`] and [`Ecb`].
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decrypting;
