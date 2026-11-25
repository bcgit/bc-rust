//! Block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//!
//! The module is deliberately cipher-agnostic: it depends on no concrete block cipher, only on the
//! traits.
//!
//! A mode turns a keyed block permutation -- `bouncycastle_symmetric::aes`'s `AES128Internal` and friends, or
//! anything else implementing [`ElectronicCodeBook`] and [`ModeNames`] -- into something that can
//! encrypt more than one block.
//!
//! This module provides:
//!
//! | Mode | Mod | Spec | Notes |
//! |---|---|---|---|
//! | CBC | [`cbc`] | SP 800-38A Sec 6.2 | Cipher Block Chaining |
//! | CBC-CS1, CBC-CS2, CBC-CS3 | [`cbc_cs`] | SP 800-38A Addendum (October 2010) | CBC with ciphertext stealing: any length from one block up, the ciphertext as long as the plaintext; [`CTS`] is CBC-CS3 |
//! | CCM | [`ccm`] | SP 800-38C | Counter with CBC-MAC. **Authenticated**: CTR plus CBC-MAC, with a tag and AAD |
//! | CMAC | [`cmac`] | SP 800-38B | A MAC ([`MACGenerator`] / [`MACVerifier`]), not a cipher: 64- or 128-bit block ciphers, one block of tag |
//! | CFB | [`cfb`] | SP 800-38A Sec 6.3 | Cipher Feedback, full-block segment (`s = b`), i.e. CFB128 for AES |
//! | CFB8 | [`cfb8`] | SP 800-38A Sec 6.3 | Cipher Feedback, 8-bit segment (`s = 8`) |
//! | CTR | [`ctr`] | SP 800-38A Sec 6.5 | Counter. Nonce plus counter, both directions parallel |
//! | ECB | [`hazmat`] | SP 800-38A Sec 6.1 | Electronic Codebook. **Not confidential for data**; interoperability and test vectors only |
//! | GCM | [`gcm`] | SP 800-38D | **Authenticated**: 96-bit nonce, 96-128-bit tag, no padding; AAD before data |
//! | GCM-SIV | [`gcm_siv`] | RFC 8452 | **Authenticated**, nonce misuse-resistant: AES-128 and AES-256 only, 96-bit nonce, 128-bit tag; whole message in place |
//! | GMAC | [`gmac`] | SP 800-38D Sec 5.2 | A MAC, not a cipher: GCM with no plaintext, so the tag is bound to a 96-bit nonce |
//! | OFB | [`ofb`] | SP 800-38A Sec 6.4 | Output Feedback. Keystream from the IV alone, serial in both directions |
//! | KW | [`kw`] | SP 800-38F Sec 6.2 | Key Wrap (RFC 3394). **Authenticated**, deterministic, no IV; whole 8-byte semiblocks only |
//! | KWP | [`kwp`] | SP 800-38F Sec 6.3 | Key Wrap with Padding (RFC 5649). As KW, for data of any length |
//! | TKW | [`tkw`] | SP 800-38F Sec 7 | TDEA Key Wrap: KW at 64-bit blocks and 32-bit semiblocks. **Legacy only** |
//! | XTS | [`xts`] | SP 800-38E (IEEE Std 1619-2007) | XEX with ciphertext stealing, for storage: one data unit at a time under a tweak, no expansion |
//!
//! They divide three ways, plus ciphertext stealing, the key-wrap trio and XTS.
//!
//! **ECB and CBC are block ciphers** ([`BlockCipherEncryptor`] / [`BlockCipherDecryptor`]): whole
//! blocks in, whole blocks out, and arbitrary-length data needs the padding layer.
//!
//! **CBC-CS1, CBC-CS2 and CBC-CS3 are CBC with ciphertext stealing** ([`SymmetricCipherEncryptor`]
//! / [`SymmetricCipherDecryptor`]): data of any length of at least one block, with no padding, so
//! the ciphertext is exactly as long as the plaintext. The three differ only in the order of the
//! last two portions of the ciphertext; see [`cbc_cs`].
//!
//! **CFB, CFB8, OFB and CTR are stream ciphers** ([`StreamCipherEncryptor`] /
//! [`StreamCipherDecryptor`]): any length in, the same length out, no padding, no finalization --
//! see [Block alignment, and which modes need it](#block-alignment-and-which-modes-need-it).
//!
//! **CCM and GCM are AEADs**: they authenticate the ciphertext to detect ciphertext tampering, and
//! can also take additional (non-encrypted) data (AAD) that is protected by the same
//! authentication tag. The traits above have nowhere to put the AAD or the tag, so both implement
//! [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] instead, and through them
//! [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] with no option to provide AAD, and
//! the tag inline.
//!
//! **KW, KWP and TKW are key-wrap algorithms** ([`KeyWrapper`] / [`KeyUnwrapper`]): one-shot,
//! deterministic and authenticated, with no IV and no streaming API, for wrapping a key (or a
//! small, non-repeating secret) under a key encryption key. SP 800-38F Sec 3.1 approves them for
//! general data as well, but they are deterministic, so for data that may repeat an AEAD is the
//! better fit (see the [`kw`] security notes).
//!
//! **XTS is a storage mode** ([`XTSKey`]): it encrypts one data unit, such as a disk sector, in
//! place under a tweak naming its position, and its ciphertext is no longer than the plaintext.
//! It is unauthenticated and has no streaming API; see the [`xts`] security notes.
//!
//! CBC, CBC-CS, CFB, CFB8, OFB and CTR all generate their own init data, or take the caller's
//! through the key's `_nonce` forms: an IV for the first five, a nonce for CTR, which is shorter than a block
//! because the rest of the counter block is the counter. ECB has
//! none at all (`INIT_DATA_LEN = 0`) and is the raw permutation applied block by block, which is
//! why it lives under [`hazmat`] -- see [`hazmat::ecb::Ecb`] and
//! [Choosing between the modes](#choosing-between-the-modes).
//!
//! Each mode is also a **mode type** -- [`CBC`], [`CBC_CS1`], [`CBC_CS2`], [`CBC_CS3`] (and its
//! other name [`CTS`]), [`CCM`], [`CCM_Packet`], [`CFB`], [`CFB8`],
//! [`CTR`], [`GCM`], [`GCM_SIV`], [`OFB`], [`hazmat::ecb::ECB`], the MACs [`CMAC`] and [`GMAC`], and the key
//! wraps [`KW`], [`KWP`] and [`TKW`] -- the `M` a mode-bound key such as
//! `bouncycastle_symmetric::aes::AES128Key<M>` is parameterised by. The mode type implements the hazmat mode
//! traits of [`bouncycastle_core::hazmat`], which is how a key hands out the mode's encryptors and
//! decryptors through the role traits of `bouncycastle_core::symmetric_key`; a key is bound to one
//! mode, and which role traits it carries follow from that mode. The modes with a padded and a
//! whole-block form, CBC and ECB, take the padding scheme or [`Blocks`] as a parameter, and the two
//! forms are two key types.
//!
//! [Choosing between the modes](#choosing-between-the-modes) covers when each is the right answer
//! -- which, for a new design, one of them usually is.
//!
//! # Usage Examples
//!
//! These usage examples are for implementing a concrete cipher on top of a mode. They are intended
//! for library developers, not end-users.
//!
//! They are written over `ToyBlockCipher`, a deliberately insecure stand-in with AES-128's key and
//! block sizes, defined in hidden lines from this crate's `tests/common/toy_block_cipher.rs`, so
//! that this module's documentation does not depend on any real cipher (`bouncycastle_symmetric::aes`
//! and the like are built on this module; only the unit tests of [`gcm_siv`] use AES). Substitute
//! any [`ElectronicCodeBook`] implementor, such as
//! `bouncycastle_symmetric::aes::hazmat::AES128Internal`; the `bouncycastle_symmetric::aes`
//! aliases carry runnable examples over the real thing.
//!
//! [`ElectronicCodeBook`]: bouncycastle_core::hazmat::ElectronicCodeBook
//!
//! ## Defining type aliases
//!
//! Define a one-line alias for the combination you use -- or use the ready-made `AES_CBC_128` /
//! `AES_CCM_128` / `AES_CFB_128` / `AES_CFB8_128` / `AES_CTR_128` / `AES_ECB_128` / `AES_GCM_128` /
//! `AES_OFB_128` and friends from `bouncycastle_symmetric::aes`. Those aliases are not all the same shape: the
//! two block modes take a padding scheme as well as a direction, since neither is usable on data of
//! arbitrary length without one, the four stream modes take only the direction, CCM takes the
//! direction in its type name, plus its nonce and tag lengths, its AAD capacity and its frame
//! length, and GCM takes the direction and its tag length:
//!
//! ```
//! # mod toy { include!("../../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_symmetric::modes::{Cbc, CcmPacketDecryptor, CcmPacketEncryptor, Cfb, Cfb8, Ctr, Gcm, Ofb};
//!
//! // Every worker borrows its key state for `'k`. CBC, CFB, CFB8 and OFB then take a permutation,
//! // a direction and a block length; the key length is the key's business, not the worker's.
//! type ToyCbc<'k, Dir> = Cbc<'k, ToyBlockCipher, Dir, 16>;
//! type ToyCfb<'k, Dir> = Cfb<'k, ToyBlockCipher, Dir, 16>;
//! type ToyCfb8<'k, Dir> = Cfb8<'k, ToyBlockCipher, Dir, 16>;
//! type ToyOfb<'k, Dir> = Ofb<'k, ToyBlockCipher, Dir, 16>;
//!
//! // CTR takes one more parameter: the nonce length, which fixes the counter width at
//! // `BLOCK_LEN - NONCE_LEN`. 12 bytes of nonce leaves the maximum 4-byte counter.
//! type ToyCtr<'k, Dir> = Ctr<'k, ToyBlockCipher, Dir, 16, 12>;
//!
//! // CCM takes the permutation and block length like the rest, plus the nonce length and the
//! // tag length -- both CCM-specific choices rather than cipher params.
//! // The nonce length caps the payload (SP 800-38C A.1: `n + q = 15`, `p < 2^8q`) and the tag
//! // length is the forgery bound; 12 and 16 are the usual pair.
//! // Each direction is its own type here, and the frame follows: `AAD_LEN` of AAD capacity and
//! // frames of exactly `DATA_LEN` bytes, since CCM commits to the payload length up front.
//! type ToyCcmEnc<'k> = CcmPacketEncryptor<'k, ToyBlockCipher, 16, 12, 16, 64, 1024>;
//! type ToyCcmDec<'k> = CcmPacketDecryptor<'k, ToyBlockCipher, 16, 12, 16, 64, 1024>;
//!
//! // GCM mode is specified in NIST SP 800-38D. `Gcm` fixes the nonce at 12 bytes (Sec 5.2.1.1
//! // recommends restricting support to 96 bits), and the block is always 16, so neither is a
//! // parameter.
//! type ToyGcm<'k, Dir> = Gcm<'k, ToyBlockCipher, Dir, 16>;
//! ```
//!
//! ## Encrypting and decrypting
//!
//! See each sub-module for usage docs.
//!
//! # Choosing between the modes
//!
//! **For a new design, use [`gcm`].** It is authenticated, and an unauthenticated
//! mode is almost never what a new protocol wants: the unauthenticated ones leave the ciphertext malleable in
//! specific, exploitable ways. While it is possible to bolt a MAC on afterwards,
//! this design has some subtleties that most people get wrong.
//!
//! [`ccm`] is also authenticated, however its design predates GCM. CCM must know the payload
//! length before it starts, so it suits a packet protocol whose frame is fixed or declared up
//! front and cannot stream a message of unknown length the way GCM can.
//!
//! [`gcm_siv`] is authenticated too, and unlike the other two it survives a repeated nonce, which
//! then reveals only that two messages were equal. It is the mode for a system that cannot
//! guarantee unique nonces; it is defined over AES only and takes each message whole, in memory.
//!
//! ECB is not a candidate for data at all (below). Between the unauthenticated modes:
//!
//! The block cipher modes: [`cbc`], [`cbc_cs`], [`ctr`], [`cfb`], [`cfb8`] and [`ofb`], while they do provide
//! reasonable confidentiality, do not provide ciphertext authentication, meaning that they do not
//! protect against ciphertext malleability attacks where an active attacker will manipulate the
//! ciphertext and then hand it to a decryption oracle to see how the oracle behaves. As such, these
//! modes should be considered antiquated and only used when a protocol requires them.
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

pub mod cbc;
pub mod cbc_cs;
pub mod ccm;
pub mod cfb;
pub mod cfb8;
pub mod cmac;
pub mod ctr;
pub mod gcm;
pub mod gcm_siv;
pub mod gmac;
pub mod hazmat;
mod iv;
pub mod kw;
pub mod kwp;
/// The toys the `tests/modes` integration tests use, shared with the unit tests in this module's
/// files rather than copied.
#[cfg(test)]
#[path = "../../../tests/modes/common/mod.rs"]
pub(in crate::framework::modes) mod modes_common;
pub mod ofb;
mod polyval;
pub mod tkw;
pub mod xts;

// `#[doc(no_inline)]` on each: the targets are below the private `framework`, so rustdoc would
// otherwise inline them and document every one twice, here and in its own module.
#[doc(no_inline)]
pub use cbc::{CBC, Cbc};
#[doc(no_inline)]
pub use cbc_cs::{
    CBC_CS, CBC_CS_FINAL_LEN, CBC_CS1, CBC_CS2, CBC_CS3, CS1, CS2, CS3, CTS, CbcCs, CsVariant,
};
#[doc(no_inline)]
pub use ccm::{
    CCM, CCM_Packet, CcmDecryptor, CcmEncryptor, CcmPacketDecryptor, CcmPacketEncryptor,
};
#[doc(no_inline)]
pub use cfb::{CFB, Cfb};
#[doc(no_inline)]
pub use cfb8::{CFB8, Cfb8};
#[doc(no_inline)]
pub use cmac::{CMAC, Cmac, CmacKeyState};
#[doc(no_inline)]
pub use ctr::{CTR, Ctr};
#[doc(no_inline)]
pub use gcm::{GCM, GCM_NONCE_LEN, Gcm, GcmKeyState};
#[doc(no_inline)]
pub use gcm_siv::{GCM_SIV, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN};
#[doc(no_inline)]
pub use gmac::{GMAC, Gmac};
#[doc(no_inline)]
pub use kw::{KW, KW_BLOCK_LEN, Kw, SEMIBLOCK_LEN};
#[doc(no_inline)]
pub use kwp::{KWP, Kwp};
#[doc(no_inline)]
pub use ofb::{OFB, Ofb};
#[doc(no_inline)]
pub use tkw::{TKW, TKW_BLOCK_LEN, TKW_SEMIBLOCK_LEN, Tkw};
#[doc(no_inline)]
pub use xts::{XTS_MAX_DATA_UNIT_LEN, XTS_MIN_DATA_UNIT_LEN, XTS_TWEAK_LEN, XTSKey};

/// Selects the whole-block form of a mode that also has a padded form: `CBC<Blocks>` is a key
/// for the block-aligned [`Cbc`] itself, on the block key path, where `CBC<PKCS7>` is one for
/// the padded adapter over it, on the symmetric path. Likewise `ECB<Blocks>` under
/// [`hazmat`]. Not a padding scheme: it adds nothing, and the lengths it accepts are checked at
/// compile time rather than refused at the final as `NoPadding` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blocks;

/// A table of algorithm names used to populate [`Algorithm`] for each Mode-Permutation-Size combination.
///
/// For permutations that do not implement all modes, simply leave the NAME for that mode as the empty-string.
pub trait ModeNames {
    /// Reported by [`Cbc`].
    const CBC_ALG_NAME: &'static str;
    /// Reported by [`CbcCs`] under [`CBC_CS1`].
    const CBC_CS1_ALG_NAME: &'static str;
    /// Reported by [`CbcCs`] under [`CBC_CS2`].
    const CBC_CS2_ALG_NAME: &'static str;
    /// Reported by [`CbcCs`] under [`CBC_CS3`], and so under [`CTS`].
    const CBC_CS3_ALG_NAME: &'static str;
    /// Reported by [`CcmPacketEncryptor`] and [`CcmPacketDecryptor`].
    const CCM_ALG_NAME: &'static str;
    /// Reported by [`Cfb`].
    const CFB_ALG_NAME: &'static str;
    /// Reported by [`Cfb8`].
    const CFB8_ALG_NAME: &'static str;
    /// Reported by [`Cmac`].
    const CMAC_ALG_NAME: &'static str;
    /// Reported by [`Ctr`], through its keystream.
    const CTR_ALG_NAME: &'static str;
    /// Reported by [`hazmat::ecb::Ecb`].
    const ECB_ALG_NAME: &'static str;
    /// Reported by [`Gcm`].
    const GCM_ALG_NAME: &'static str;
    /// Reported by [`Gmac`].
    const GMAC_ALG_NAME: &'static str;
    /// Reported by [`Kw`] over a 128-bit block and by [`Tkw`] over a 64-bit one: a permutation
    /// has one block length, so one key-wrap algorithm.
    const KW_ALG_NAME: &'static str;
    /// Reported by [`Kwp`].
    const KWP_ALG_NAME: &'static str;
    /// Reported by [`Ofb`], through its keystream.
    const OFB_ALG_NAME: &'static str;
}

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::hazmat::ElectronicCodeBook;
#[allow(unused_imports)]
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, BlockCipherDecryptor,
    BlockCipherEncryptor, KeyUnwrapper, KeyWrapper, MACGenerator, MACVerifier,
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
// end of imports needed for docs
