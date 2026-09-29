//! Block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//!
//! The crate is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! trait.
//!
//! A mode turns a keyed block permutation -- `bouncycastle-aes`'s `AES128Internal` and friends,
//! or anything else implementing [`ElectronicCodeBook`] -- into something that can encrypt more than
//! one block.
//!
//! This crate provides:
//!
//! | Mode | Mod | Spec | Notes |
//! |---|---|---|---|
//! | ECB | [`ecb`] | SP 800-38A Sec 6.1 | Electronic Codebook. **Not confidential for data**; interoperability and test vectors only |
//! | CBC | [`cbc`] | SP 800-38A Sec 6.2 | Cipher Block Chaining |
//! | CFB | [`cfb`] | SP 800-38A Sec 6.3 | Cipher Feedback, full-block segment (`s = b`), i.e. CFB128 for AES |
//! | CFB8 | [`cfb8`] | SP 800-38A Sec 6.3 | Cipher Feedback, 8-bit segment (`s = 8`) |
//! | CTR | [`ctr`] | SP 800-38A Sec 6.5 | Counter. Nonce plus counter, both directions parallel |
//! | CCM | [`ccm`] | SP 800-38C | Counter with CBC-MAC. **Authenticated**: CTR plus CBC-MAC, with a tag and AAD |
//! | GCM | [`gcm`] | SP 800-38D | **Authenticated**: 96-bit nonce, 96-128-bit tag, no padding; AAD before data |
//!
//! They divide three ways.
//!
//! **ECB and CBC are block ciphers** ([`BlockCipherEncryptor`] / [`BlockCipherDecryptor`]): whole
//! blocks in, whole blocks out, and arbitrary-length data needs the padding layer.
//!
//! **CFB, CFB8 and CTR are stream ciphers** ([`StreamCipherEncryptor`] / [`StreamCipherDecryptor`]):
//! any length in, the same length out, no padding, no finalization -- see
//! [Block alignment, and which modes need it](#block-alignment-and-which-modes-need-it).
//!
//! **CCM and GCM are AEADs**: they authenticate the ciphertext to detect ciphertext tampering, and
//! can also take additional (non-encrypted) data (AAD) that is protected by the same
//! authentication tag. The traits above have nowhere to put the AAD or the tag, so both implement
//! [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] instead, and through them
//! [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] with no option to provide AAD, and
//! the tag inline.
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
//! # Notes on CCM Mode
//!
//! CCM reaches the AEAD traits through [`CcmEncryptor`] / [`CcmDecryptor`]; its own inherent API is
//! the one to reach for. Two other things set it apart:
//!
//! * **There is an extra input and an extra output.** The AAD is authenticated but not encrypted,
//!   and the tag has to travel with the ciphertext; `Ccm` offers both the spec's inline
//!   `ciphertext || tag` layout and a detached-tag pair.
//! * **The nonce is supplied, not generated.** CCM requires the nonce to be unique but *not*
//!   unpredictable (SP 800-38C Sec 5.3), which is the opposite of the IV requirement the other
//!   modes have, so a caller with a counter can do better than this crate's DRBG.
//!
//! # Notes on GCM Mode
//!
//! GCM is built from CTR and a universal hash (GHASH), where CCM uses a CBC-MAC.
//! [`Gcm`] implements the AEAD traits itself, with `FINAL_LEN = TAG_LEN`: the traits are
//! its whole API, the inline `ciphertext || tag` view through the symmetric-cipher methods and the
//! spec's detached `(C, T)` pair through the `*_detached` methods. It differs from CCM in the other
//! direction on both counts above -- its 12-byte nonce is generated from the library's default RNG
//! rather than supplied, because a repeated GCM nonce gives away the hash subkey (SP 800-38D
//! Appendix A), and it streams. See [`Gcm`].
//!
//! [Choosing between the modes](#choosing-between-the-modes) covers when each is the right answer
//! -- which, for a new design, one of them usually is.
//!
//! # Usage Examples
//!
//! These usage examples are for implementing a concrete cipher on top of a mode, and use AES-128 as
//! the example. They are intended for library developers, not end-users.
//!
//! ## Defining type aliases
//!
//! Define a one-line alias for the combination you use -- or use the ready-made
//! `AES_CBC_128` / `AES_CCM_128` / `AES_CFB_128` / `AES_CFB8_128` / `AES_CTR_128` / `AES_ECB_128` /
//! `AES_GCM_128` and friends from `bouncycastle-aes`. Those aliases are not all the same shape: the
//! two block modes take a padding scheme as well as a direction, since neither is usable on data of
//! arbitrary length without one, the three stream modes take only the direction, CCM takes the
//! direction too, plus its nonce and tag lengths, and GCM takes the direction and its tag length:
//!
//! ```
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_modes::{Cbc, Ccm, Cfb, Cfb8, Ctr, Gcm};
//!
//! // CBC, CFB, and CFB8 take a permutation, a direction, key length, and a block length.
//! type Aes128Cbc<Dir> = Cbc<AES128Internal, Dir, 16, 16>;
//! type Aes128Cfb<Dir> = Cfb<AES128Internal, Dir, 16, 16>;
//! type Aes128Cfb8<Dir> = Cfb8<AES128Internal, Dir, 16, 16>;
//!
//! // CTR takes one more parameter: the nonce length, which fixes the counter width at
//! // `BLOCK_LEN - NONCE_LEN`. 12 bytes of nonce leaves the maximum 4-byte counter.
//! type Aes128Ctr<Dir> = Ctr<AES128Internal, Dir, 16, 16, 12>;
//!
//! // CCM takes the permutation, a direction, key length, and a block length like the rest,
//! // plus the nonce length and the tag length -- both CCM-specific choices rather than AES params.
//! // The nonce length caps the payload (SP 800-38C A.1: `n + q = 15`, `p < 2^8q`) and the tag
//! // length is the forgery bound; 12 and 16 are the usual pair.
//! type Aes128Ccm<Dir> = Ccm<AES128Internal, Dir, 16, 16, 12, 16>;
//!
//! // GCM mode is specified in NIST SP 800-38D. `Gcm` fixes the nonce at 12 bytes (Sec 5.2.1.1
//! // recommends restricting support to 96 bits), and the block is always 16, so neither is a
//! // parameter.
//! type Aes128Gcm<Dir> = Gcm<AES128Internal, Dir, 16, 16>;
//! ```
//!
//! ## Encrypting and decrypting
//!
//! See each sub-module for usage docs on that mode.
//!
//!
//! GCM gives the same guarantee through the AEAD traits, with the nonce generated and returned
//! like the other modes' IVs; see [`Gcm`] for the detached and streaming forms:
//!
//! ```
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting, Gcm};
//!
//! type Aes128Gcm<Dir> = Gcm<AES128Internal, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let header = b"authenticated, not encrypted";
//! let message = b"any length: GCM needs no padding";
//!
//! let mut ciphertext = [0u8; 32];
//! let (nonce, _, tag) =
//!     Aes128Gcm::<Encrypting>::encrypt_out_detached(&key, header, message, &mut ciphertext)
//!         .expect("encryption");
//!
//! let mut opened = [0u8; 32];
//! Aes128Gcm::<Decrypting>::decrypt_out_detached(&key, &nonce, header, &ciphertext, &tag, &mut opened)
//!     .expect("decryption");
//! assert_eq!(&opened, message);
//!
//! let mut tampered = ciphertext;
//! tampered[0] ^= 1;
//! assert!(Aes128Gcm::<Decrypting>::decrypt_out_detached(&key, &nonce, header, &tampered, &tag, &mut opened).is_err());
//! ```
//!
//! Using the wrong direction does not compile:
//!
//! ```compile_fail
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::BlockCipherDecryptor;
//! use bouncycastle_modes::{Cbc, Encrypting};
//!
//! type Aes128Cbc<Dir> = Cbc<AES128Internal, Dir, 16, 16>;
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // `Encrypting` does not implement `BlockCipherDecryptor`.
//! let _ = Aes128Cbc::<Encrypting>::do_decrypt_init(&key, &[0u8; 16]);
//! ```
//!
//! # Choosing between the modes
//!
//! **For a new design, use [`Gcm`] or [`Ccm`].** Both are authenticated, and an unauthenticated
//! mode is almost never what a new protocol wants: the other five leave the ciphertext malleable in
//! the specific, exploitable ways set out in
//! [None of the other modes is authenticated](#none-of-the-other-modes-is-authenticated), and
//! bolting a MAC on afterwards is a design most people get wrong.
//!
//! GCM is the more widely deployed of the two and the one that streams. Its costs:
//!
//! * **The nonce is generated, and a repeat is catastrophic.** Reusing a nonce under a key gives
//!   away the hash subkey, and with it the ability to forge (SP 800-38D Appendix A). [`Gcm`] never
//!   takes a nonce from the caller, which removes the accident but also the option of a counter.
//! * **At most 2^32 messages per key** with a random nonce (Sec 8.3), a limit the caller has to
//!   enforce, since no value here sees every message under a key.
//! * **Streaming decryption releases plaintext before the tag is checked.** The one-shots do not;
//!   see [`Gcm`].
//!
//! CCM's costs, so that the choice between them is informed rather than reflexive:
//!
//! * **Two cipher calls per block, only one of which batches.** CCM runs both CTR and a CBC-MAC
//!   over the same data (Sec 5.2). The CBC-MAC is serial by construction (Sec 6.1 step 3: `Yi`
//!   depends on `Yi-1`), so it cannot use the permutation's pair or four path, but the CTR half
//!   can and does, exactly as [`Ctr`] does. This crate's benches measure roughly two thirds of
//!   CTR's unbatched throughput and a third of CTR's batched -- better than a naive "two full
//!   passes" would suggest, because only one of the two passes pays the unbatched cost.
//! * **It does not stream.** SP 800-38C Sec 3: "CCM is not designed to support partial processing
//!   or stream processing", because the payload length is inside the first block the MAC covers.
//!   `Ccm` handles that by taking the length up front, which costs nothing. The generic AEAD
//!   adapters do the same for one-shots and buffer only genuinely streaming calls. See [`Ccm`].
//! * **The payload is capped** by the nonce length, at `2^(8 * (15 - NONCE_LEN)) - 1` bytes.
//! * **The nonce must be unique.** Reuse is worse than for CTR: it loses confidentiality *and*
//!   enables forgery.
//!
//! For a genuinely streaming multi-gigabyte input, choose GCM, or `bouncycastle-ascon`'s
//! Ascon-AEAD128, which also streams. Choosing an unauthenticated
//! mode from this crate should be a deliberate decision, made because an existing format or spec
//! requires it, and paired with separate authentication.
//!
//! ECB is not a candidate for data at all (below). Between the five unauthenticated modes:
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
//! crate: it is `bouncycastle-padding`, whose `PaddedBlockCipherEncryptor` /
//! `PaddedBlockCipherDecryptor` wrap any [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] pair,
//! so a block mode gets arbitrary-length support by being wrapped rather than by growing padding
//! logic of its own. The same adapters over `bouncycastle-padding`'s `NoPadding` give the opposite
//! guarantee -- an unaligned message is an error at `do_final` rather than something padded -- for
//! formats defined on whole blocks.
//!
//! ```
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
//! use bouncycastle_padding::{PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
//!
//! type Enc = PaddedBlockCipherEncryptor<Cbc<AES128Internal, Encrypting, 16, 16>, PKCS7, 16, 16, 16>;
//! type Dec = PaddedBlockCipherDecryptor<Cbc<AES128Internal, Decrypting, 16, 16>, PKCS7, 16, 16, 16>;
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
//! a counter and a keystream block; an ECB value is just the permutation, since nothing chains; a
//! CCM value carries three blocks (the CBC-MAC chaining value, the counter template and the
//! keystream) plus four counters, because it runs two mechanisms at once:
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
//!
//! // CCM. Independent of NONCE_LEN and TAG_LEN: the nonce lives inside the counter template and
//! // the tag is built at finalization, so neither adds a field. `Dir` is zero-sized.
//! size_of::<Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>>()
//!     == align8(size_of::<P>() + 3 * BLOCK_LEN + 4 * size_of::<usize>() + 8)
//!
//! // The buffering AEAD-trait adapter values used by the streaming API: an AAD_LEN array and a
//! // FINAL_LEN = DATA_LEN + TAG_LEN one. Their one-shots bypass these values and use Ccm directly.
//! size_of::<CcmEncryptor<P, .., AAD_LEN, DATA_LEN, FINAL_LEN>>()
//!     == align8(size_of::<P>() + AAD_LEN + FINAL_LEN + NONCE_LEN + 2 * size_of::<usize>() + 1)
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
//! | AES-128 CCM | 176 B | 16 B MAC + 16 B counter template + 16 B keystream | 40 B | 264 B |
//! | AES-192 CCM | 208 B | 48 B, as above | 40 B | 296 B |
//! | AES-256 CCM | 240 B | 48 B, as above | 40 B | 328 B |
//!
//! CCM is the largest of the streaming values, because it is the only mode running two mechanisms
//! at once: the CBC-MAC needs its chaining value, and the CTR half needs both a keystream block and
//! the counter template that generates it. It is **independent of `NONCE_LEN` and `TAG_LEN`** --
//! `Ccm<AES128Internal, Encrypting, .., 7, 4>` and `Ccm<AES128Internal, Encrypting, .., 13, 16>` are both 264 B --
//! because the nonce is stored inside the counter template rather than separately, and the tag is
//! assembled at finalization rather than held.
//!
//! **Streaming [`CcmEncryptor`] and [`CcmDecryptor`] values are a different order of magnitude**,
//! and that is the one memory figure in this crate worth thinking about before choosing an API.
//! They buffer the whole message, so with 64 bytes of AAD and 2 KiB of payload
//! (`AAD_LEN = 64`, `DATA_LEN = 2048`) an AES-128 adapter is **2336 B**.
//! Their one-shots override the trait defaults and use [`Ccm`] directly, costing 264 B for AES-128
//! (the table above) regardless of the buffer sizes; the like-for-like benchmark compares that path
//! with [`Ccm::encrypt_out_detached`]. See [`Ccm`] for why only the open-ended streaming methods must
//! buffer.
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
//! The keystream block is held in a `Secret`: unlike a chaining value it is live key material for
//! the bytes not yet consumed. The transient keystream blocks of its batch paths are `Secret`s for
//! the same reason: one per batch width, held for the whole call and zeroized once at its end.
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
//! ## None of the other modes is authenticated
//!
//! This section is about the five SP 800-38A modes. **[`Ccm`] and [`Gcm`] are exempt**: they are
//! AEADs, their tags cover the payload, the AAD and the nonce, and decryption returns `Err` rather
//! than plaintext if any of them has been altered. (GCM's streaming decryptor releases plaintext
//! before that `Err`; see [`Gcm`].) Everything below is a description of what you give up by
//! choosing one of the other five, and the reason
//! [Choosing between the modes](#choosing-between-the-modes) starts with the AEADs.
//!
//! Those five provide, at best, confidentiality only. None detects tampering, and each is malleable
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
//! **Authenticate the ciphertext.** Prefer an AEAD -- [`Gcm`] and [`Ccm`] are in this crate, and
//! need no separate MAC, no key-separation decision and no encrypt-then-MAC ordering care. If you must use
//! one of the five, MAC the ciphertext *and* the IV, and verify before decrypting.
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
//! * **OFB**, the one remaining mode of SP 800-38A. It is a keystream mode and, like CFB,
//!   CFB8 and CTR, would implement [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`].
//! * **GCM with a nonce other than 96 bits** (SP 800-38D Algorithm 4 step 2's `len(IV) != 96`
//!   branch, which derives `J0` by GHASHing the IV). Sec 5.2.1.1 recommends restricting support to
//!   96 bits, and [`Gcm`] does.
//! * **GCM with a 32- or 64-bit tag** (Sec 5.2.1.2, Appendix C). Those need the controlling
//!   protocol to bound packet sizes and invocation counts, which this crate cannot enforce.
//! * **CCM with a formatting function other than Appendix A's.** SP 800-38C Sec 5.4 allows
//!   alternatives and says "Alternative formatting functions may be developed in the future";
//!   Appendix A's is the only one that exists in practice and the only one [`Ccm`] implements.
//!
//! # Command line
//!
//! The `bc-rust` CLI exposes all seven modes for all three AES key lengths: `aes{128,192,256}-cbc`,
//! `-ccm`, `-cfb`, `-cfb8`, `-ctr`, `-ecb` and `-gcm`, each taking `encrypt` or `decrypt`. All but
//! `-ccm` stream stdin to stdout; see below for why CCM cannot.
//!
//! For the five unauthenticated modes there is no API for caller-supplied init data anywhere, so
//! `encrypt` writes what it generated at the front of its output and `decrypt` reads it back, and
//! the two compose. That is one block for CBC, CFB and CFB8, **12 bytes** for CTR, and nothing at
//! all for `-ecb`:
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
//!
//! **`-ccm` is different in three visible ways**, all of them following from CCM being an AEAD:
//!
//! ```text
//! # The nonce is a flag, and the same one is needed to decrypt: CCM needs it unique, not
//! # unpredictable (SP 800-38C Sec 5.3), so the caller chooses it.
//! bc-rust aes256-ccm encrypt --key-file k.bin --nonce 000102030405060708090a0b \
//!     --aad cafebabe < plain.bin > sealed.bin
//! bc-rust aes256-ccm decrypt --key-file k.bin --nonce 000102030405060708090a0b \
//!     --aad cafebabe < sealed.bin | cmp - plain.bin
//! ```
//!
//! 1. **`--nonce` / `--nonce-file` is required and is not written to the output**, unlike every
//!    other mode's generated IV. `--aad` adds data that is authenticated but not encrypted, and
//!    must match on both sides. `--tag-len` selects the tag length, defaulting to 16.
//! 2. **The output is `--tag-len` bytes longer than the input** (`ciphertext || tag`, Sec 6.1
//!    step 8), and `decrypt` **fails with a non-zero exit** rather than emitting rubbish if
//!    anything has been altered.
//! 3. **It does not stream**: it reads all of stdin before doing any work, so memory use is
//!    proportional to the input. That is Sec 3's "CCM is not designed to support partial processing
//!    or stream processing", not a limitation of this implementation. It does buy something,
//!    though -- no plaintext is written until the tag has verified, so a failed `decrypt` leaves
//!    nothing to discard. For a streaming AEAD use `-gcm` or `bc-rust ascon-aead128`.
//!
//! **`-gcm` streams, and frames its output like the unauthenticated modes**: `encrypt` writes the
//! generated 12-byte nonce first, then the ciphertext, then the 16-byte tag, and `decrypt` reads
//! the same layout back. `--aad` (hex, as for `-ccm`) or `--aad-file` supplies the AAD. The cost
//! of streaming is that a failed `decrypt` has **already written plaintext** by the time it reaches
//! the tag and exits non-zero, so check the exit code before using the output:
//!
//! ```text
//! bc-rust aes256-gcm encrypt --key-file k.bin --aad cafebabe < plain.bin > sealed.bin
//! bc-rust aes256-gcm decrypt --key-file k.bin --aad cafebabe < sealed.bin > out.bin && cmp out.bin plain.bin
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod cbc;
pub mod ccm;
pub mod cfb;
pub mod cfb8;
pub mod ctr;
pub mod ecb;
pub mod gcm;
mod ghash;
mod iv;

pub use cbc::Cbc;
pub use ccm::{CCM_MAX_BUFFER_LEN, Ccm, CcmDecryptor, CcmEncryptor};
pub use cfb::Cfb;
pub use cfb8::Cfb8;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use gcm::{GCM_NONCE_LEN, Gcm};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor,
    ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
// end of imports needed for docs

/// The direction markers, defined in `bouncycastle-core` so that a stream cipher built there with
/// [`bouncycastle_core::stream_cipher::StreamCipher`] and a mode built here share them. See [`Cbc`],
/// [`Ccm`], [`Cfb`], [`Cfb8`], [`Ctr`], [`Ecb`] and [`Gcm`].
pub use bouncycastle_core::stream_cipher::{Decrypting, Encrypting};
