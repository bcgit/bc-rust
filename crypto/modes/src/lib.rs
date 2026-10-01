//! Block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//!
//! The crate is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! trait.
//!
//! A mode turns a keyed block permutation -- `bouncycastle-aes`'s `ToyBlockCipher` and friends,
//! or anything else implementing [`ElectronicCodeBook`] -- into something that can encrypt more than
//! one block.
//!
//! This crate provides:
//!
//! | Mode | Mod | Spec | Notes |
//! |---|---|---|---|
//! | CBC | [`cbc`] | SP 800-38A Sec 6.2 | Cipher Block Chaining |
//! | CCM | [`ccm`] | SP 800-38C | Counter with CBC-MAC. **Authenticated**: CTR plus CBC-MAC, with a tag and AAD |
//! | CFB | [`cfb`] | SP 800-38A Sec 6.3 | Cipher Feedback, full-block segment (`s = b`), i.e. CFB128 for AES |
//! | CFB8 | [`cfb8`] | SP 800-38A Sec 6.3 | Cipher Feedback, 8-bit segment (`s = 8`) |
//! | CTR | [`ctr`] | SP 800-38A Sec 6.5 | Counter. Nonce plus counter, both directions parallel |
//! | ECB | [`hazmat`] | SP 800-38A Sec 6.1 | Electronic Codebook. **Not confidential for data**; interoperability and test vectors only |
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
//! none at all (`INIT_DATA_LEN = 0`) and is the raw permutation applied block by block, which is
//! why it lives under [`hazmat`] -- see [`hazmat::Ecb`] and
//! [Choosing between the modes](#choosing-between-the-modes).
//!
//! [Choosing between the modes](#choosing-between-the-modes) covers when each is the right answer
//! -- which, for a new design, one of them usually is.
//!
//! # Usage Examples
//!
//! These usage examples are for implementing a concrete cipher on top of a mode. They are intended
//! for library developers, not end-users.
//!
//! They are written over `bouncycastle_core_test_framework::ToyBlockCipher`, a deliberately
//! insecure stand-in with AES-128's key and block sizes that the test-framework crate exports for
//! exactly this purpose, so that this crate's documentation does not depend on any real cipher
//! crate (which would be a dependency cycle: the cipher crates depend on this one). Substitute
//! any [`ElectronicCodeBook`] implementor, such as `bouncycastle_aes::hazmat::AES128Internal`;
//! the `bouncycastle-aes` crate's aliases carry runnable examples over the real thing.
//!
//! [`ElectronicCodeBook`]: bouncycastle_core::hazmat::ElectronicCodeBook
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
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_modes::{Cbc, Ccm, Cfb, Cfb8, Ctr, Gcm};
//!
//! // CBC, CFB, and CFB8 take a permutation, a direction, key length, and a block length.
//! type ToyCbc<Dir> = Cbc<ToyBlockCipher, Dir, 16, 16>;
//! type ToyCfb<Dir> = Cfb<ToyBlockCipher, Dir, 16, 16>;
//! type ToyCfb8<Dir> = Cfb8<ToyBlockCipher, Dir, 16, 16>;
//!
//! // CTR takes one more parameter: the nonce length, which fixes the counter width at
//! // `BLOCK_LEN - NONCE_LEN`. 12 bytes of nonce leaves the maximum 4-byte counter.
//! type ToyCtr<Dir> = Ctr<ToyBlockCipher, Dir, 16, 16, 12>;
//!
//! // CCM takes the permutation, a direction, key length, and a block length like the rest,
//! // plus the nonce length and the tag length -- both CCM-specific choices rather than cipher params.
//! // The nonce length caps the payload (SP 800-38C A.1: `n + q = 15`, `p < 2^8q`) and the tag
//! // length is the forgery bound; 12 and 16 are the usual pair.
//! type ToyCcm<Dir> = Ccm<ToyBlockCipher, Dir, 16, 16, 12, 16>;
//!
//! // GCM mode is specified in NIST SP 800-38D. `Gcm` fixes the nonce at 12 bytes (Sec 5.2.1.1
//! // recommends restricting support to 96 bits), and the block is always 16, so neither is a
//! // parameter.
//! type ToyGcm<Dir> = Gcm<ToyBlockCipher, Dir, 16, 16>;
//! ```
//!
//! ## Encrypting and decrypting
//!
//! See each sub-module for usage docs.
//!
//! # Choosing between the modes
//!
//! **For a new design, use [`gcm`].** It is authenticated, and an unauthenticated
//! mode is almost never what a new protocol wants: the other five leave the ciphertext malleable in
//! specific, exploitable ways. While it is possible to bolt a MAC on afterwards,
//! this design has some subtleties that most people get wrong.
//!
//! [`ccm`] is also authenticated, however its design predates GCM.
//! CCM is designed to be a packet cipher where the size of data is fixed at compile-time, which does
//! not generalize well to encrypting arbitrary messages. As such, CCM's streaming modes and memory
//! footprint perform worse than GCM's.
//!
//! ECB is not a candidate for data at all (below). Between the five unauthenticated modes:
//!
//! The block cipher modes: [`cbc`], [`ctr`], [`cfb`] and [`cfb8`], while they do provide reasonable
//! confidentiality, do not provide ciphertext authentication, meaning that they do not protect against
//! ciphertext malleability attacks where an active attacker will manipulate the ciphertext and then
//! hand it to a decryption oracle to see how the oracle behaves. As such, these modes should be
//! considered antiquated and only used when a protocol requires them.
//!
//! # 🚨 Security Considerations 🚨
//!
//! See sub-modules for mode-specific security considerations.
//!
//! ## The IV must be unpredictable
//!
//! Modes that require an Initialisation Vector (IV) or a nonce typically require that it be
//! unpredictable -- ie not guessable by an attacker prior to the honest party performing the
//! encryption -- and that it be unique per encryption invocation.
//!
//! Generally, the best-practice is to pull it from a cryptographic RNG as part of the `encrypt()`
//! operation, which most of the provided modes offer and do automatically. However, some modes
//! allow the user to provide the IV / nonce, in which case they become responsible for its
//! randomness.
//!
//! ## Key, IV reuse and content limits
//!
//! In general, it is acceptable for the same key being used for many messages, which is fine provided
//! each encryption gets a fresh unpredictable IV / nonce. IV / nonce reuse often leads
//! to immediate total loss of security.
//!
//! Additionally, some ciphers and modes will specify a
//! maximum amount of data that can be encrypted under a given key / IV before there is a risk that
//! blocks start repeating.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod cbc;
pub mod ccm;
pub mod cfb;
pub mod cfb8;
pub mod ctr;
pub mod gcm;
mod ghash;
pub mod hazmat;
mod iv;

pub use cbc::Cbc;
pub use ccm::{CCM_MAX_BUFFER_LEN, Ccm, CcmDecryptor, CcmEncryptor};
pub use cfb::Cfb;
pub use cfb8::Cfb8;
pub use ctr::Ctr;
pub use gcm::{GCM_NONCE_LEN, Gcm};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::hazmat::ElectronicCodeBook;
#[allow(unused_imports)]
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor,
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
// end of imports needed for docs

/// The direction markers, defined in `bouncycastle-core` so that a stream cipher built there with
/// [`bouncycastle_core::stream_cipher::StreamCipher`] and a mode built here share them. See [`Cbc`],
/// [`Ccm`], [`Cfb`], [`Cfb8`], [`Ctr`], [`Ecb`](hazmat::Ecb) and [`Gcm`].
pub use bouncycastle_core::stream_cipher::{Decrypting, Encrypting};
