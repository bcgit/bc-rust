//! Type aliases for AES in CCM mode (NIST SP 800-38C).
//!
//! See [`bouncycastle_modes::ccm`] for details on the Counter with CBC-MAC construction.
//!
//! The aliases here are authenticated ciphers: encryption produces a tag as well as a ciphertext,
//! and decryption either returns the plaintext or fails the tag check. `Dir` is [`Encrypting`] or
//! [`Decrypting`]; the wrong direction is a compile error, not a runtime check.
//!
//! There are two families, because CCM must know the payload length before it starts (Sec 3):
//!
//! * [`AES_CCM_128`] and friends do not buffer. The nonce is **supplied**, which CCM permits
//!   because it requires the nonce to be unique but not random (Sec 5.3), so a caller with a
//!   counter can do better than a draw from a DRBG; and the streaming API takes the total lengths
//!   up front.
//! * [`AES_CCM_128_Buffered`] and friends implement [`AEADCipherEncryptor`] /
//!   [`AEADCipherDecryptor`], like every other mode in this crate. To fit the streaming traits
//!   they buffer the AAD and payload, up to the `AAD_LEN` and `DATA_LEN` capacities they take as
//!   parameters, and their one-shots generate the nonce.
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
//! Though same alternative choices do exist, for example:
//! ```text
//! // IEEE 802.11 CCMP's 13 byte nonce and 8 byte tag
//! AES_CCM_128<Encrypting, 13, 8>
//! ```
//!
//! # Usage Examples
//!
//! ## Generic AEAD API
//!
//! For code written against [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], the buffering
//! pair generates the nonce and returns it:
//!
//! ```
//! use bouncycastle_aes::AES_CCM_128_Buffered;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! // Up to 64 bytes of AAD and 2 KiB of message -- comfortably above an 802.11 frame, the packet
//! // size CCM was designed for -- and FINAL_LEN = 2 KiB plus the 16-byte tag.
//! type AESEnc = AES_CCM_128_Buffered<Encrypting, 12, 16, 64, 2048, { 2048 + 16 }>;
//! type AESDec = AES_CCM_128_Buffered<Decrypting, 12, 16, 64, 2048, { 2048 + 16 }>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! let (nonce, ciphertext, tag) = AESEnc::encrypt_detached(&key, b"header", b"message").expect("encryption");
//!
//! let plaintext = AESDec::decrypt_detached(&key, &nonce, b"header", &ciphertext, &tag).expect("decryption");
//! assert_eq!(plaintext, b"message");
//! ```
//!
//! ## One-shot API
//!
//! [`Ccm`]'s inherent `encrypt_out` / `decrypt_out`, expose the CCM-specific parameters, specifically
//! the ability to provide the nonce, and to produce and consume the spec's own ciphertext layout,
//! `ciphertext || tag` (Sec 6.1 step 8):
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_256, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_256<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_256<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
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
//! For a wire format that carries the tag separately, `encrypt_out_detached` / `decrypt_out_detached`
//! return and take it on its own:
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_128, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_128<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_128<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let nonce = [0x02u8; CCM_NONCE_LEN];
//! let message = b"a short packet";
//!
//! let mut ciphertext = vec![0u8; message.len()];
//! let (n, tag) = AESEnc::encrypt_out_detached(&key, &nonce, &[], message, &mut ciphertext).expect("encryption");
//! assert_eq!(n, message.len(), "CCM never expands the payload");
//!
//! let mut plaintext = vec![0u8; message.len()];
//! AESDec::decrypt_out_detached(&key, &nonce, &[], &ciphertext, &tag, &mut plaintext).expect("decryption");
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
//! use bouncycastle_aes::{AES_CCM_128, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_modes::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_128<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_128<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
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
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_modes::ccm`] apply. Above all, the nonce that
//! [`AES_CCM_128`] and friends take must never repeat under one key.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::stream_cipher::Direction;
use bouncycastle_modes::{Ccm, CcmDecryptor, CcmEncryptor};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
#[allow(unused_imports)]
use bouncycastle_modes::{Decrypting, Encrypting};
// end of imports needed for docs

/// The nonce length to use unless there is a reason not to: 12 bytes, which is what the NIST ACVP
/// `ACVP-AES-CCM` vectors use in every group. It leaves `q = 3`, so a payload of up to
/// 16 MiB - 1 bytes.
pub const CCM_NONCE_LEN: usize = 12;

/// The tag length to use unless there is a reason not to: the full 16 bytes, the largest A.1
/// permits. See the module docs on Sec B.2.
pub const CCM_TAG_LEN: usize = 16;

/// AES-128 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag, without the
/// buffering of [`AES_CCM_128_Buffered`]: the one-shots take a supplied nonce, and the streaming
/// API takes the total lengths up front.
///
/// `NONCE_LEN` must be 7..=13 and `TAG_LEN` one of 4, 6, 8, 10, 12, 14, 16 (A.1); anything else is
/// a compile error. Use [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] if you have no reason to choose.
#[allow(non_camel_case_types)]
pub type AES_CCM_128<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES128Internal, Dir, 16, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-192 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES192Internal, Dir, 24, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-256 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES256Internal, Dir, 32, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-128 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`.
///
/// This is the buffering pair, for code written against the generic AEAD traits; it holds up to
/// `AAD_LEN` bytes of AAD and `DATA_LEN` bytes of payload, and `FINAL_LEN` must be
/// `DATA_LEN + TAG_LEN`. `NONCE_LEN` and `TAG_LEN` are as for [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_128_Buffered<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<
        AES128Internal,
        16,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
        FINAL_LEN,
    >,
    CcmDecryptor<
        AES128Internal,
        16,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
        FINAL_LEN,
    >,
>;

/// AES-192 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128_Buffered`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192_Buffered<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<
        AES192Internal,
        24,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
        FINAL_LEN,
    >,
    CcmDecryptor<
        AES192Internal,
        24,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
        FINAL_LEN,
    >,
>;

/// AES-256 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128_Buffered`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256_Buffered<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<
        AES256Internal,
        32,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
        FINAL_LEN,
    >,
    CcmDecryptor<
        AES256Internal,
        32,
        AES_BLOCK_LEN,
        NONCE_LEN,
        TAG_LEN,
        AAD_LEN,
        DATA_LEN,
        FINAL_LEN,
    >,
>;
