//! Type aliases for AES in CCM mode (NIST SP 800-38C).
//!
//! See [`bouncycastle_cipher::modes::ccm`] for details on the Counter with CBC-MAC construction.
//!
//! The aliases here are authenticated ciphers: encryption produces a tag as well as a ciphertext,
//! and decryption either returns the plaintext or fails the tag check. `Dir` is [`Encrypting`] or
//! [`Decrypting`]; the wrong direction is a compile error, not a runtime check.
//!
//! CCM must know the payload length before it starts (Sec 3), and the generic AEAD pair's
//! `create_encryptor` is handed no lengths, so [`AES_CCM_128`] and friends fix the payload length
//! in the type as the const parameter `DATA_LEN` -- the fixed frame of a packet protocol -- hold
//! back nothing but up to `AAD_LEN` bytes of AAD, and refuse any other amount of payload. They
//! come from a key, [`AES128Key`]`<CCM_Packet<NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>>` and friends,
//! through the [`AeadEncryptionKey`] / [`AeadDecryptionKey`] pair, whose one-shots take the
//! frame length too. The nonce is drawn from the caller's RNG unless supplied through the
//! `_nonce` forms, which CCM permits because it requires the nonce to be unique but not random
//! (Sec 5.3), so a caller with a counter can do better than a draw from a DRBG.
//!
//! A message of any length goes through the other key, [`AES128Key`]`<CCM<NONCE_LEN, TAG_LEN>>`
//! and friends: its [`AeadDeclaredEncryptionKey`] / [`AeadDeclaredDecryptionKey`] constructors take
//! the AAD and payload lengths, so its workers hold nothing back, and its in-place one-shots
//! take any length with no second buffer.
//!
//! # The nonce and tag length are parametrizable
//!
//! Unlike the other aliases in this crate, these do not pin everything: `NONCE_LEN` and `TAG_LEN`
//! are exposed as parameters.
//!
//! * **`NONCE_LEN` (the spec's `n`) fixes the maximum payload.** NIST SP 800-38C A.1 requires
//!   `n + q = 15`, and `q` bounds the payload at `2^8q - 1` bytes. So a 13-byte nonce caps a message
//!   at 64 KiB - 1, and a 7-byte nonce lifts the cap entirely at the cost of nonce space.
//! * **`TAG_LEN` (the spec's `t`) is the forgery bound.** Sec B.2: "a value of Tlen that is less
//!   than 64 shall not be used without a careful analysis of the risks of accepting inauthentic
//!   data as authentic".
//!
//! Both are still checked at compile time against A.1's permitted sets, so a wrong value is a
//! compile error rather than a runtime `Err`. A drawn nonce needs `NONCE_LEN` of at least 12;
//! a supplied one any A.1 length.
//!
//! [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] are the default pair -- a 12-byte nonce and a
//! 16-byte tag, which is what the NIST ACVP vectors and most protocols use -- for callers who have
//! no reason to choose otherwise:
//!
//! ```text
//! // 12-byte nonce, 16-byte tag, up to 64 bytes of AAD, 2 KiB frames
//! AES128Key<CCM_Packet<CCM_NONCE_LEN, CCM_TAG_LEN, 64, 2048>>
//! ```
//!
//! Though some alternative choices do exist, for example:
//! ```text
//! // IEEE 802.11 CCMP's 13 byte nonce and 8 byte tag
//! AES128Key<CCM_Packet<13, 8, 64, 2048>>
//! ```
//!
//! # Usage Examples
//!
//! ## Fixed frames, through the generic AEAD pair
//!
//! For code written against [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], the `CCM_Packet`
//! key draws the nonce and returns it. Its streaming methods and one-shots take exactly
//! `DATA_LEN` bytes of payload:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::CCM_Packet;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! // Up to 64 bytes of AAD, and frames of exactly 2 KiB -- comfortably above an 802.11 frame,
//! // the packet size CCM was designed for.
//! let key = AES128Key::<CCM_Packet<12, 16, 64, 2048>>::from_key_material(&material)
//!     .expect("a valid AES-128 key");
//!
//! let frame = [0x5Au8; 2048];
//!
//! // The one-shots: a frame.
//! let (nonce, ciphertext, tag) = key.encrypt_detached(&mut rng, b"header", &frame).expect("encryption");
//! let plaintext = key.decrypt_detached(&nonce, b"header", &ciphertext, &tag).expect("decryption");
//! assert_eq!(&plaintext[..], &frame[..]);
//!
//! // The streaming methods: exactly one frame, released as it is processed.
//! let (mut enc, nonce) = key.create_encryptor(&mut rng).expect("nonce draw");
//! enc.do_update_aad(b"header").expect("aad");
//! let mut sealed = vec![0u8; 2048];
//! let n = enc.do_encrypt_out(&frame, &mut sealed).expect("the whole frame comes out");
//! assert_eq!(n, 2048);
//! let (_, _, tag) = enc.do_encrypt_final_detached().expect("the tag");
//!
//! let mut dec = key.create_decryptor(&nonce);
//! dec.do_update_aad(b"header").expect("aad");
//! let mut opened = vec![0u8; 2048];
//! dec.do_decrypt_out(&sealed, &mut opened).expect("released, but not yet authenticated");
//! dec.do_decrypt_final_detached(&tag).expect("...until the tag verifies");
//! assert_eq!(opened, frame);
//! ```
//!
//! ## Any length, a supplied nonce, in the spec's own layout
//!
//! The `CCM` key's `_nonce` one-shots take the caller's nonce and any length, and the inline
//! forms produce and consume the spec's own ciphertext layout, `ciphertext || tag` (Sec 6.1
//! step 8):
//!
//! ```
//! use bouncycastle_aes::{AES256Key, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_cipher::modes::CCM;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, FromKeyMaterial};
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<CCM<CCM_NONCE_LEN, CCM_TAG_LEN>>::from_key_material(&material)
//!     .expect("a valid AES-256 key");
//!
//! // Supplied, not drawn. It is the caller's responsibility that it never repeat under this key.
//! let nonce = [0x01u8; CCM_NONCE_LEN];
//!
//! // The associated data is authenticated but not encrypted; the message is both.
//! let aad = b"header, sent in the clear";
//! let message = b"a message of no particular length";
//!
//! let sealed = key.encrypt_with_aad_nonce(&nonce, aad, message).expect("encryption");
//! assert_eq!(sealed.len(), message.len() + CCM_TAG_LEN, "the ciphertext plus the tag");
//!
//! let opened = key.decrypt_with_aad(&nonce, aad, &sealed).expect("decryption");
//! assert_eq!(&opened[..], message);
//!
//! // Tampering with either the ciphertext or the associated data fails the tag check.
//! let mut tampered = sealed.clone();
//! tampered[0] ^= 1;
//! assert!(key.decrypt_with_aad(&nonce, aad, &tampered).is_err());
//! assert!(key.decrypt_with_aad(&nonce, b"other header", &sealed).is_err());
//! ```
//!
//! ## In place
//!
//! A message already in a buffer of its own is sealed and opened there, with no second buffer:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::CCM;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, FromKeyMaterial};
//!
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! // Validated and expanded once, for any number of messages.
//! let key = AES128Key::<CCM<12, 16>>::from_key_material(&material).expect("a usable key");
//! let nonce = [0x02u8; 12];
//!
//! let mut buf = *b"a short packet";
//! let tag = key.encrypt_detached_in_place_nonce(&nonce, &[], &mut buf).expect("encryption");
//! key.decrypt_detached_in_place(&nonce, &[], &mut buf, &tag).expect("decryption");
//! assert_eq!(&buf, b"a short packet");
//! ```
//!
//! # Memory Usage
//!
//! The value held between calls:
//!
//! | Type | AES-128 | AES-192 | AES-256 |
//! |---|---|---|---|
//! | [`AES128Key`]`<CCM<..>>` and friends: the key schedule | 176 B | 208 B | 240 B |
//! | its workers, encrypting / decrypting | 96 B / 120 B | 96 B / 120 B | 96 B / 120 B |
//! | [`AES_CCM_128`] and friends, encrypting, `AAD_LEN = 64` | 176 B | 176 B | 176 B |
//! | [`AES_CCM_128`] and friends, decrypting, `AAD_LEN = 64` | 200 B | 200 B | 200 B |
//!
//! The difference between the key sizes is the key schedule, which the workers borrow rather
//! than copy; the pair adds the mode's state, the `AAD_LEN`-byte AAD buffer and, on the
//! decrypting side, the held-back tag. Peak stack over a
//! 16 KiB frame with AES-128, measured with massif on x86-64 in release mode by
//! `mem_usage_benches/src/bench_ccm_mem_usage.rs`, including the caller's own 16 KiB arrays:
//!
//! | Path | Peak stack |
//! |---|---|
//! | process start-up alone | 7 680 B |
//! | `AES128Key<CCM<..>>` in place, one array | 18 608 B |
//! | `AES_CCM_128` streaming encrypt, two arrays | 36 216 B |
//! | `AES_CCM_128` streaming decrypt, two arrays | 35 424 B |
//! | `AES_CCM_128` one-shot, two arrays | 35 880 B |
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::ccm`] apply. Above all, a nonce
//! the caller supplies must never repeat under one key.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::{CcmPacketDecryptor, CcmPacketEncryptor};

// Imports needed for docs
#[allow(unused_imports)]
use crate::AES128Key;
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
};
#[allow(unused_imports)]
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
// end of imports needed for docs

/// The nonce length to use unless there is a reason not to: 12 bytes, which is what the NIST ACVP
/// `ACVP-AES-CCM` vectors use in every group. It leaves `q = 3`, so a payload of up to
/// 16 MiB - 1 bytes.
pub const CCM_NONCE_LEN: usize = 12;

/// The tag length to use unless there is a reason not to: the full 16 bytes, the largest A.1
/// permits. See the module docs on Sec B.2.
pub const CCM_TAG_LEN: usize = 16;

/// AES-128 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`, for
/// frames of exactly `DATA_LEN` payload bytes.
///
/// This is the fixed-frame pair, for code written against the generic AEAD traits: the streaming
/// methods accept exactly `DATA_LEN` bytes of payload and up to `AAD_LEN` of AAD. It comes from
/// an [`AES128Key`]`<CCM_Packet<NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>>`, whose `create_encryptor`
/// draws the nonce and whose `create_encryptor_nonce` and `_nonce` one-shots take the caller's;
/// a drawn nonce needs `NONCE_LEN` of at least 12, a supplied one any A.1 length. `NONCE_LEN` must be 7..=13
/// and `TAG_LEN` one of 4, 6, 8, 10, 12, 14, 16 (A.1); anything else is a compile error. Use
/// [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] if you have no reason to choose. See [`CcmPacketEncryptor`]
/// for the rules.
#[allow(non_camel_case_types)]
pub type AES_CCM_128<
    'k,
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmPacketEncryptor<
        'k,
        AES128Internal,
        16,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
    CcmPacketDecryptor<
        'k,
        AES128Internal,
        16,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
>;

/// AES-192 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192<
    'k,
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmPacketEncryptor<
        'k,
        AES192Internal,
        24,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
    CcmPacketDecryptor<
        'k,
        AES192Internal,
        24,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
>;

/// AES-256 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256<
    'k,
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmPacketEncryptor<
        'k,
        AES256Internal,
        32,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
    CcmPacketDecryptor<
        'k,
        AES256Internal,
        32,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
>;
