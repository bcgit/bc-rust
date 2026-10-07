//! Type aliases for AES in CCM mode (NIST SP 800-38C).
//!
//! See [`bouncycastle_cipher::modes::ccm`] for details on the Counter with CBC-MAC construction.
//!
//! The aliases here are authenticated ciphers: encryption produces a tag as well as a ciphertext,
//! and decryption either returns the plaintext or fails the tag check. `Dir` is [`Encrypting`] or
//! [`Decrypting`]; the wrong direction is a compile error, not a runtime check.
//!
//! There are two families, because CCM must know the payload length before it starts (Sec 3),
//! and the two learn that length from different places:
//!
//! * [`AES_CCM_128`] and friends are told the AAD and payload lengths per message: the one-shots
//!   read them off the slices they are given, and the streaming API takes both totals up front in
//!   `new` or `new_with_lengths`. The nonce is **supplied**, which CCM permits because it requires
//!   the nonce to be unique but not random (Sec 5.3), so a caller with a counter can do better
//!   than a draw from a DRBG.
//! * [`AES_CCM_128_Packet`] and friends fix the payload length in the type, as the const parameter
//!   `DATA_LEN`, and so implement [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] like every
//!   other mode in this crate: they stream, holding back nothing but up to `AAD_LEN` bytes of
//!   AAD, and their one-shots generate the nonce. Every entry point accepts exactly `DATA_LEN`
//!   bytes of payload, the fixed frame of a packet protocol, and refuses any other amount.
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
//! compile error rather than a runtime `Err`.
//!
//! [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] are the default pair -- a 12-byte nonce and a
//! 16-byte tag, which is what the NIST ACVP vectors and most protocols use -- for callers who have
//! no reason to choose otherwise:
//!
//! ```text
//! // 12-byte nonce, 16-byte tag, < 16 MiB
//! AES_CCM_128<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>
//! ```
//!
//! Though some alternative choices do exist, for example:
//! ```text
//! // IEEE 802.11 CCMP's 13 byte nonce and 8 byte tag
//! AES_CCM_128<Encrypting, 13, 8>
//! ```
//!
//! # Usage Examples
//!
//! ## Generic AEAD API for a fixed packet size
//!
//! For code written against [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], the fixed-frame
//! pair generates the nonce and returns it. Every entry point, one-shots included, takes exactly
//! `DATA_LEN` bytes of payload:
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_128_Packet, AES_CCM_128_Key};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor, SymmetricCipherKey};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Up to 64 bytes of AAD, and frames of exactly 2 KiB -- comfortably above an 802.11 frame,
//! // the packet size CCM was designed for.
//! type AESEnc = AES_CCM_128_Packet<Encrypting, 12, 16, 64, 2048>;
//! type AESDec = AES_CCM_128_Packet<Decrypting, 12, 16, 64, 2048>;
//!
//! let key = AES_CCM_128_Key::new_from_os().expect("a fresh key");
//!
//! let frame = [0x5Au8; 2048];
//!
//! // The one-shots: one frame.
//! let (nonce, ciphertext, tag) = AESEnc::encrypt_detached(&key, b"header", &frame).expect("encryption");
//! let plaintext = AESDec::decrypt_detached(&key, &nonce, b"header", &ciphertext, &tag).expect("decryption");
//! assert_eq!(&plaintext[..], &frame[..]);
//! // ...and nothing but a frame.
//! assert!(AESEnc::encrypt_detached(&key, b"header", b"message").is_err());
//!
//! // The streaming methods: the same frame, released as it is processed.
//! let (mut enc, nonce) = AESEnc::do_encrypt_init(&key).expect("init");
//! enc.do_update_aad(b"header").expect("aad");
//! let mut sealed = vec![0u8; 2048];
//! let n = enc.do_encrypt_out(&frame, &mut sealed).expect("the whole frame comes out");
//! assert_eq!(n, 2048);
//! let (_, _, tag) = enc.do_encrypt_final_detachedtag().expect("the tag");
//!
//! let mut dec = AESDec::do_decrypt_init(&key, &nonce).expect("init");
//! dec.do_update_aad(b"header").expect("aad");
//! let mut opened = vec![0u8; 2048];
//! dec.do_decrypt_out(&sealed, &mut opened).expect("released, but not yet authenticated");
//! dec.do_decrypt_final_detachedtag(&tag).expect("...until the tag verifies");
//! assert_eq!(opened, frame);
//! ```
//!
//! ## One-shot API
//!
//! [`Ccm`]'s inherent `encrypt_out` / `decrypt_out`, expose the CCM-specific parameters, specifically
//! the ability to provide the nonce, and to produce and consume the spec's own ciphertext layout,
//! `ciphertext || tag` (Sec 6.1 step 8):
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_256, CCM_NONCE_LEN, CCM_TAG_LEN, AES_CCM_256_Key};
//! use bouncycastle_core::traits::SymmetricCipherKey;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_256<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_256<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = AES_CCM_256_Key::new_from_os().expect("a fresh key");
//!
//! // Supplied, not generated. It is the caller's responsibility that it never repeat under this key.
//! let nonce = [0x01u8; CCM_NONCE_LEN];
//!
//! // The associated data is authenticated but not encrypted; the message is both.
//! let aad = b"header, sent in the clear";
//! let message = b"a message of no particular length";
//!
//! let mut sealed = vec![0u8; message.len() + CCM_TAG_LEN];
//! let n = AESEnc::encrypt_out(&key, &nonce, aad, message, &mut sealed).expect("encryption");
//! assert_eq!(n, sealed.len(), "the ciphertext plus the tag");
//!
//! let mut opened = vec![0u8; message.len()];
//! let n = AESDec::decrypt_out(&key, &nonce, aad, &sealed, &mut opened).expect("decryption");
//! assert_eq!(&opened[..n], message);
//!
//! // Tampering with either the ciphertext or the associated data fails the tag check.
//! let mut tampered = sealed.clone();
//! tampered[0] ^= 1;
//! assert!(AESDec::decrypt_out(&key, &nonce, aad, &tampered, &mut opened).is_err());
//! assert!(AESDec::decrypt_out(&key, &nonce, b"other header", &sealed, &mut opened).is_err());
//! ```
//!
//! ## Detached tag
//!
//! For a wire format that carries the tag separately, `encrypt_detached_out` / `decrypt_detached_out`
//! return and take it on its own:
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_128, CCM_NONCE_LEN, CCM_TAG_LEN, AES_CCM_128_Key};
//! use bouncycastle_core::traits::SymmetricCipherKey;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_128<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_128<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = AES_CCM_128_Key::new_from_os().expect("a fresh key");
//! let nonce = [0x02u8; CCM_NONCE_LEN];
//! let message = b"a short packet";
//!
//! let mut ciphertext = vec![0u8; message.len()];
//! let (n, tag) = AESEnc::encrypt_detached_out(&key, &nonce, &[], message, &mut ciphertext).expect("encryption");
//! assert_eq!(n, message.len(), "CCM never expands the payload");
//!
//! let mut plaintext = vec![0u8; message.len()];
//! AESDec::decrypt_detached_out(&key, &nonce, &[], &ciphertext, &tag, &mut plaintext).expect("decryption");
//! assert_eq!(&plaintext[..], message);
//! ```
//!
//! ## Streaming API
//!
//! CCM authenticates the payload length before any payload, so it cannot stream indefinitely
//! (SP 800-38C Sec 3). It can still process data that arrives in pieces, provided the total length
//! is declared up front to `new`; each piece is then encrypted in place, and the tag comes from
//! `do_encrypt_final`:
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_128, CCM_NONCE_LEN, CCM_TAG_LEN, AES_CCM_128_Key};
//! use bouncycastle_core::traits::SymmetricCipherKey;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_128<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_128<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = AES_CCM_128_Key::new_from_os().expect("a fresh key");
//! let nonce = [0x03u8; CCM_NONCE_LEN];
//! let aad = b"header";
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 7-byte pieces, each in place. The total length is declared up front.
//! let mut encryptor = AESEnc::new(&key, &nonce, aad, plaintext.len()).expect("encrypt init");
//! let mut ciphertext = plaintext;
//! for piece in ciphertext.chunks_mut(7) {
//!     encryptor.do_encrypt(piece).expect("encryption");
//! }
//! // The tag is computed over everything, so it is the last thing out.
//! let tag = encryptor.do_encrypt_final().expect("the tag");
//!
//! // Decrypt in 19-byte pieces: the boundaries need not match the encryptor's. The bytes
//! // written are not authenticated until `do_decrypt_final` accepts the tag.
//! let mut decryptor = AESDec::new(&key, &nonce, aad, ciphertext.len()).expect("decrypt init");
//! let mut recovered = ciphertext;
//! for piece in recovered.chunks_mut(19) {
//!     decryptor.do_decrypt_update(piece).expect("decryption");
//! }
//! decryptor.do_decrypt_final(&tag).expect("a valid tag");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! # Memory Usage
//!
//! The value held between calls:
//!
//! | Type | AES-128 | AES-192 | AES-256 |
//! |---|---|---|---|
//! | [`AES_CCM_128`] and friends, either direction | 264 B | 296 B | 328 B |
//! | [`AES_CCM_128_Packet`] and friends, encrypting, `AAD_LEN = 64` | 344 B | 376 B | 408 B |
//! | [`AES_CCM_128_Packet`] and friends, decrypting, `AAD_LEN = 64` | 368 B | 400 B | 432 B |
//!
//! The difference between the key sizes is the key schedule; the `_Packet` pair adds the
//! `AAD_LEN`-byte AAD buffer and, on the decrypting side, the held-back tag. Peak stack over a
//! 16 KiB frame with AES-128, measured with massif on x86-64 in release mode by
//! `mem_usage_benches/src/bench_ccm_mem_usage.rs`, including the caller's own 16 KiB arrays:
//!
//! | Path | Peak stack |
//! |---|---|
//! | process start-up alone | 7 696 B |
//! | `AES_CCM_128` one-shot, two arrays (message, ciphertext) | 35 944 B |
//! | `AES_CCM_128` streaming, one array encrypted in place | 19 112 B |
//! | `AES_CCM_128_Packet` streaming encrypt, two arrays | 37 400 B |
//! | `AES_CCM_128_Packet` streaming decrypt, two arrays | 36 168 B |
//! | `AES_CCM_128_Packet` one-shot, two arrays | 37 576 B |
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::ccm`] apply. Above all, the nonce that
//! [`AES_CCM_128`] and friends take must never repeat under one key.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::{Ccm, CcmDecryptor, CcmEncryptor};

use bouncycastle_core::errors::{KeyMaterialError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::SymmetricCipherKey;
use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512};
// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
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

/// AES-128 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. The AAD and
/// payload lengths are supplied per message: the one-shots read them off the slices they are
/// given, along with a caller-supplied nonce, and the streaming API takes both totals up front in
/// `new` or `new_with_lengths`. For a payload length fixed by the type, and the generic AEAD
/// traits, see [`AES_CCM_128_Packet`].
///
/// `NONCE_LEN` must be 7..=13 and `TAG_LEN` one of 4, 6, 8, 10, 12, 14, 16 (A.1); anything else is
/// a compile error. Use [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] if you have no reason to choose.
#[allow(non_camel_case_types)]
pub type AES_CCM_128<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES128Internal, Dir, AES_CCM_128_Key, 16, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// An AES-CCM-128 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CCM_128_Key(KeyMaterial<16>);

impl SymmetricCipherKey<16> for AES_CCM_128_Key {
    fn from_keymaterial(key: KeyMaterial<16>) -> Result<Self, KeyMaterialError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("Must be SymmetricCipherKey"));
        }
        if key.security_strength() < SecurityStrength::_128bit {
            return Err(KeyMaterialError::InvalidKeyType(
                "Key's Security strength must be at least 128bit",
            ));
        }
        Ok(Self(key))
    }

    fn get_key(&self) -> &KeyMaterial<16> {
        &self.0
    }

    fn new_from_os() -> Result<Self, RNGError> {
        Self::new_from_rng(&mut HashDRBG_SHA256::new_from_os())
    }
}

/// AES-192 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES192Internal, Dir, AES_CCM_192_Key, 24, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// An AES-CCM-192 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CCM_192_Key(KeyMaterial<24>);

impl SymmetricCipherKey<24> for AES_CCM_192_Key {
    fn from_keymaterial(key: KeyMaterial<24>) -> Result<Self, KeyMaterialError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("Must be SymmetricCipherKey"));
        }
        if key.security_strength() < SecurityStrength::_192bit {
            return Err(KeyMaterialError::InvalidKeyType(
                "Key's Security strength must be at least 192bit",
            ));
        }
        Ok(Self(key))
    }

    fn get_key(&self) -> &KeyMaterial<24> {
        &self.0
    }

    fn new_from_os() -> Result<Self, RNGError> {
        Self::new_from_rng(&mut HashDRBG_SHA512::new_from_os())
    }
}

/// AES-256 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES256Internal, Dir, AES_CCM_256_Key, 32, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// An AES-CCM-256 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CCM_256_Key(KeyMaterial<32>);

impl SymmetricCipherKey<32> for AES_CCM_256_Key {
    fn from_keymaterial(key: KeyMaterial<32>) -> Result<Self, KeyMaterialError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("Must be SymmetricCipherKey"));
        }
        if key.security_strength() < SecurityStrength::_256bit {
            return Err(KeyMaterialError::InvalidKeyType(
                "Key's Security strength must be at least 256bit",
            ));
        }
        Ok(Self(key))
    }

    fn get_key(&self) -> &KeyMaterial<32> {
        &self.0
    }

    fn new_from_os() -> Result<Self, RNGError> {
        Self::new_from_rng(&mut HashDRBG_SHA512::new_from_os())
    }
}

/// AES-128 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`, for
/// frames of exactly `DATA_LEN` payload bytes.
///
/// This is the fixed-frame pair, for code written against the generic AEAD traits: every entry
/// point accepts exactly `DATA_LEN` bytes of payload and up to `AAD_LEN` of AAD, and the
/// one-shots generate the nonce. `NONCE_LEN` must be at least 12 here, and `TAG_LEN` is as for
/// [`AES_CCM_128`]. See [`CcmEncryptor`] for the rules.
#[allow(non_camel_case_types)]
pub type AES_CCM_128_Packet<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<
        AES128Internal,
        AES_CCM_128_Key,
        16,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
    CcmDecryptor<
        AES128Internal,
        AES_CCM_128_Key,
        16,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
>;

/// AES-192 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128_Packet`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192_Packet<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<
        AES192Internal,
        AES_CCM_192_Key,
        24,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
    CcmDecryptor<
        AES192Internal,
        AES_CCM_192_Key,
        24,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
>;

/// AES-256 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128_Packet`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256_Packet<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<
        AES256Internal,
        AES_CCM_256_Key,
        32,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
    CcmDecryptor<
        AES256Internal,
        AES_CCM_256_Key,
        32,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
    >,
>;
