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
//! * [`AES_CCM_128`] and friends implement [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`]
//!   like every other mode in this crate. Their one-shots, with the whole message in hand, take
//!   any payload and AAD length and generate the nonce unless the caller supplies one through
//!   the trait's `_nonce` forms. Their streaming methods, whose constructor is handed no lengths,
//!   fix the payload length in the type as the const parameter `DATA_LEN` -- the fixed frame of
//!   a packet protocol -- hold back nothing but up to `AAD_LEN` bytes of AAD, and refuse any
//!   other amount of payload.
//! * [`AES_CCM_128_Packet`] and friends are the inherent API for Sec 3's "packet environment",
//!   where "all of the data is available in storage before CCM is applied": they are told the AAD
//!   and payload lengths per message, read off the slices by the one-shots or declared up front
//!   to `new` or `new_with_lengths`, and then process the payload in place. The nonce is
//!   **supplied**, which CCM permits because it requires the nonce to be unique but not random
//!   (Sec 5.3), so a caller with a counter can do better than a draw from a DRBG. The trait
//!   family's one-shots are these under a generated nonce.
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
//! AES_CCM_128_Packet<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>
//! ```
//!
//! Though some alternative choices do exist, for example:
//! ```text
//! // IEEE 802.11 CCMP's 13 byte nonce and 8 byte tag
//! AES_CCM_128_Packet<Encrypting, 13, 8>
//! ```
//!
//! # Usage Examples
//!
//! ## Generic AEAD API
//!
//! For code written against [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], [`AES_CCM_128`]
//! generates the nonce and returns it. The streaming methods take exactly `DATA_LEN` bytes of
//! payload; the one-shots take any length:
//!
//! ```
//! use bouncycastle_aes::AES_CCM_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Up to 64 bytes of AAD, and frames of exactly 2 KiB -- comfortably above an 802.11 frame,
//! // the packet size CCM was designed for.
//! type AESEnc = AES_CCM_128<Encrypting, 12, 16, 64, 2048>;
//! type AESDec = AES_CCM_128<Decrypting, 12, 16, 64, 2048>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! let frame = [0x5Au8; 2048];
//!
//! // The one-shots: a frame, or any other length, since they have the whole message in hand.
//! let (nonce, ciphertext, tag) = AESEnc::encrypt_detached(&key, b"header", &frame).expect("encryption");
//! let plaintext = AESDec::decrypt_detached(&key, &nonce, b"header", &ciphertext, &tag).expect("decryption");
//! assert_eq!(&plaintext[..], &frame[..]);
//! let (nonce, ciphertext, tag) = AESEnc::encrypt_detached(&key, b"header", b"message").expect("encryption");
//! let plaintext = AESDec::decrypt_detached(&key, &nonce, b"header", &ciphertext, &tag).expect("decryption");
//! assert_eq!(&plaintext[..], b"message");
//!
//! // The streaming methods: exactly one frame, released as it is processed.
//! let (mut enc, nonce) = AESEnc::do_encrypt_init(&key).expect("init");
//! enc.do_update_aad(b"header").expect("aad");
//! let mut sealed = vec![0u8; 2048];
//! let n = enc.do_encrypt_out(&frame, &mut sealed).expect("the whole frame comes out");
//! assert_eq!(n, 2048);
//! let (_, _, tag) = enc.do_encrypt_final_detached().expect("the tag");
//!
//! let mut dec = AESDec::do_decrypt_init(&key, &nonce).expect("init");
//! dec.do_update_aad(b"header").expect("aad");
//! let mut opened = vec![0u8; 2048];
//! dec.do_decrypt_out(&sealed, &mut opened).expect("released, but not yet authenticated");
//! dec.do_decrypt_final_detached(&tag).expect("...until the tag verifies");
//! assert_eq!(opened, frame);
//! ```
//!
//! ## One-shot API
//!
//! [`CcmPacket`]'s inherent `encrypt_out` / `decrypt_out`, expose the CCM-specific parameters, specifically
//! the ability to provide the nonce, and to produce and consume the spec's own ciphertext layout,
//! `ciphertext || tag` (Sec 6.1 step 8):
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_256_Packet, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_256_Packet<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_256_Packet<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
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
//! For a wire format that carries the tag separately, `encrypt_detached_out` / `decrypt_detached_out`
//! return and take it on its own:
//!
//! ```
//! use bouncycastle_aes::{AES_CCM_128_Packet, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_128_Packet<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_128_Packet<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
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
//! use bouncycastle_aes::{AES_CCM_128_Packet, CCM_NONCE_LEN, CCM_TAG_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CCM_128_Packet<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
//! type AESDec = AES_CCM_128_Packet<Decrypting, CCM_NONCE_LEN, CCM_TAG_LEN>;
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
//! # Memory Usage
//!
//! The value held between calls:
//!
//! | Type | AES-128 | AES-192 | AES-256 |
//! |---|---|---|---|
//! | [`AES_CCM_128_Packet`] and friends, either direction | 264 B | 296 B | 328 B |
//! | [`AES_CCM_128`] and friends, encrypting, `AAD_LEN = 64` | 344 B | 376 B | 408 B |
//! | [`AES_CCM_128`] and friends, decrypting, `AAD_LEN = 64` | 368 B | 400 B | 432 B |
//!
//! The difference between the key sizes is the key schedule; the trait pair adds the
//! `AAD_LEN`-byte AAD buffer and, on the decrypting side, the held-back tag. Peak stack over a
//! 16 KiB frame with AES-128, measured with massif on x86-64 in release mode by
//! `mem_usage_benches/src/bench_ccm_mem_usage.rs`, including the caller's own 16 KiB arrays. The
//! `AES_CCM_128` one-shots call the `AES_CCM_128_Packet` ones, so they cost only the DRBG the
//! nonce is drawn from on top:
//!
//! | Path | Peak stack |
//! |---|---|
//! | process start-up alone | 7 680 B |
//! | `AES_CCM_128_Packet` one-shot, two arrays (message, ciphertext) | 35 888 B |
//! | `AES_CCM_128_Packet` streaming, one array encrypted in place | 19 088 B |
//! | `AES_CCM_128` streaming encrypt, two arrays | 37 304 B |
//! | `AES_CCM_128` streaming decrypt, two arrays | 36 144 B |
//! | `AES_CCM_128` one-shot, two arrays | 36 208 B |
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::ccm`] apply. Above all, the nonce that
//! [`AES_CCM_128_Packet`] and friends take must never repeat under one key.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::{CcmDecryptor, CcmEncryptor, CcmPacket};

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

/// AES-128 in CCM mode for Sec 3's packet environment, with a `NONCE_LEN`-byte nonce and a
/// `TAG_LEN`-byte tag: the AAD and payload lengths are supplied per message, read off the slices
/// by the one-shots or declared up front to `new` or `new_with_lengths`, along with a
/// caller-supplied nonce. For the generic AEAD traits see [`AES_CCM_128`].
///
/// `NONCE_LEN` must be 7..=13 and `TAG_LEN` one of 4, 6, 8, 10, 12, 14, 16 (A.1); anything else is
/// a compile error. Use [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] if you have no reason to choose.
#[allow(non_camel_case_types)]
pub type AES_CCM_128_Packet<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    CcmPacket<AES128Internal, Dir, 16, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-192 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. See [`AES_CCM_128_Packet`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192_Packet<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    CcmPacket<AES192Internal, Dir, 24, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-256 in CCM mode with a `NONCE_LEN`-byte nonce and a `TAG_LEN`-byte tag. See [`AES_CCM_128_Packet`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256_Packet<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    CcmPacket<AES256Internal, Dir, 32, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-128 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`, for
/// frames of exactly `DATA_LEN` payload bytes.
///
/// This is the fixed-frame pair, for code written against the generic AEAD traits: the streaming
/// methods accept exactly `DATA_LEN` bytes of payload and up to `AAD_LEN` of AAD, the one-shots
/// any amount of either. The nonce is generated unless the caller supplies one through
/// [`AEADCipherEncryptor::do_encrypt_init_nonce`] or the `_nonce` one-shots; a generated nonce
/// needs `NONCE_LEN` of at least 12, a supplied one any A.1 length, and `TAG_LEN` is as for
/// [`AES_CCM_128_Packet`]. See [`CcmEncryptor`] for the rules.
#[allow(non_camel_case_types)]
pub type AES_CCM_128<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<AES128Internal, 16, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    CcmDecryptor<AES128Internal, 16, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
>;

/// AES-192 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<AES192Internal, 24, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    CcmDecryptor<AES192Internal, 24, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
>;

/// AES-256 in CCM mode, as an [`AEADCipherEncryptor`] or [`AEADCipherDecryptor`] by `Dir`. See [`AES_CCM_128`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256<
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmEncryptor<AES256Internal, 32, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    CcmDecryptor<AES256Internal, 32, AES_BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
>;
