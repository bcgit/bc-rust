//! Type aliases for AES Key Wrap, KW (NIST SP 800-38F Sec 6.2; RFC 3394), and AES Key Wrap with
//! Padding, KWP (Sec 6.3; RFC 5649).
//!
//! `bouncycastle-modes` is deliberately cipher-agnostic, so `Kw` and `Kwp` take the permutation
//! and its key length. These aliases pin both:
//!
//! ```text
//! AES_KW_128      // AES-128 KW:  whole 8-byte semiblocks in, one semiblock more out
//! AES_KWP_256     // AES-256 KWP: any length in, rounded up to 8 plus 8 out
//! ```
//!
//! There is no direction parameter: wrapping and unwrapping are the separate [`KeyWrapper`] and
//! [`KeyUnwrapper`] traits, both implemented by each alias, and both consisting of associated
//! functions. See [`bouncycastle_modes::kw`] for the API, the in-place wrapping function and the
//! security notes, and [`bouncycastle_modes::kwp`] for what padding adds.
//!
//! # Which one
//!
//! **KW** is what RFC 3394, CMS (RFC 3565) and JOSE's `A128KW` family mean by "AES key wrap": it
//! wraps a symmetric key that is a whole number of 8 bytes, which every AES, HMAC and ChaCha key
//! is. **KWP** wraps anything from 1 byte up, at the cost of one extra semiblock when the input
//! was already aligned; it is what RFC 5649 and PKCS#11's `CKM_AES_KEY_WRAP_KWP` mean, and the
//! one to use for encoded private keys and other non-aligned data. Their ciphertexts are not
//! interchangeable: the integrity check values differ, so unwrapping one with the other fails.
//!
//! The RFC 3394 and RFC 5649 OIDs (`id-aes128-wrap` `{ aes 5 }`, `id-aes128-wrap-pad` `{ aes 8 }`,
//! and the 192- and 256-bit siblings at 25/28 and 45/48) are not attached to these aliases yet:
//! none of the AES mode aliases carries an [`AlgorithmOID`] on this branch, and a mode alias is not
//! a local type this crate could implement one for.

use crate::aes_internal::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_modes::{Kw, Kwp};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{AlgorithmOID, KeyUnwrapper, KeyWrapper};
// end of imports needed for docs

/// AES-128 Key Wrap (SP 800-38F KW; RFC 3394 with a 128-bit KEK).
///
/// This is RFC 3394 Sec 4.1, "Wrap 128 bits of Key Data with a 128-bit KEK", as a doctest:
///
/// ```
/// use bouncycastle_aes::AES_KW_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
///
/// // KEK 000102030405060708090A0B0C0D0E0F, key data 00112233445566778899AABBCCDDEEFF.
/// let kek_bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
/// let key_data: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);
/// let kek = KeyMaterial::<16>::from_bytes_as_type(&kek_bytes, KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
///
/// let wrapped: [u8; 24] = AES_KW_128::wrap_key(&kek, &key_data).expect("wrapping");
/// assert_eq!(
///     wrapped,
///     [
///         0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
///         0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
///     ]
/// );
/// let recovered = AES_KW_128::unwrap_key::<16, 24>(&kek, &wrapped).expect("unwrapping");
/// assert_eq!(*recovered, key_data);
/// ```
#[allow(non_camel_case_types)]
pub type AES_KW_128 = Kw<AES128Internal, 16>;

/// AES-192 Key Wrap (SP 800-38F KW; RFC 3394 with a 192-bit KEK). See [`AES_KW_128`].
#[allow(non_camel_case_types)]
pub type AES_KW_192 = Kw<AES192Internal, 24>;

/// AES-256 Key Wrap (SP 800-38F KW; RFC 3394 with a 256-bit KEK). See [`AES_KW_128`].
#[allow(non_camel_case_types)]
pub type AES_KW_256 = Kw<AES256Internal, 32>;

/// AES-128 Key Wrap with Padding (SP 800-38F KWP; RFC 5649 with a 128-bit KEK).
///
/// ```
/// use bouncycastle_aes::AES_KWP_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
///
/// let kek = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
///
/// // Any length: 13 bytes pad to 16, plus the 8-byte header.
/// let data = *b"thirteen bytes"; // 14, actually -- still 16 + 8.
/// let wrapped: [u8; 24] = AES_KWP_128::wrap_key(&kek, &data).expect("wrapping");
/// let recovered = AES_KWP_128::unwrap_key::<14, 24>(&kek, &wrapped).expect("unwrapping");
/// assert_eq!(*recovered, data);
/// ```
#[allow(non_camel_case_types)]
pub type AES_KWP_128 = Kwp<AES128Internal, 16>;

/// AES-192 Key Wrap with Padding (SP 800-38F KWP; RFC 5649 with a 192-bit KEK).
///
/// This is the second example of RFC 5649 Sec 6, which wraps 7 octets -- short enough that the
/// header and data fit one AES block, the case Algorithm 5 step 5 enciphers directly:
///
/// ```
/// use bouncycastle_aes::AES_KWP_192;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
///
/// let kek_bytes = [
///     0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
///     0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
/// ];
/// let kek = KeyMaterial::<24>::from_bytes_as_type(&kek_bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let key_data = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
///
/// let wrapped: [u8; 16] = AES_KWP_192::wrap_key(&kek, &key_data).expect("wrapping");
/// assert_eq!(
///     wrapped,
///     [
///         0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b,
///         0xb2, 0x4f,
///     ]
/// );
/// assert_eq!(*AES_KWP_192::unwrap_key::<7, 16>(&kek, &wrapped).expect("unwrapping"), key_data);
/// ```
#[allow(non_camel_case_types)]
pub type AES_KWP_192 = Kwp<AES192Internal, 24>;

/// AES-256 Key Wrap with Padding (SP 800-38F KWP; RFC 5649 with a 256-bit KEK). See
/// [`AES_KWP_128`].
#[allow(non_camel_case_types)]
pub type AES_KWP_256 = Kwp<AES256Internal, 32>;
