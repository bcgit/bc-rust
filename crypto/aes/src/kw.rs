//! Type aliases for AES Key Wrap, KW (NIST SP 800-38F Sec 6.2; RFC 3394), and AES Key Wrap with
//! Padding, KWP (Sec 6.3; RFC 5649).
//!
//! See [`bouncycastle_cipher::modes::kw`] for the construction, the in-place wrapping function and
//! the security notes, and [`bouncycastle_cipher::modes::kwp`] for what padding adds.
//! [`AES_KW_128`] and friends name the worker, which implements [`KeyWrapper`] and
//! [`KeyUnwrapper`]; it comes from a key, [`AES128Key<KW>`] or [`AES128Key<KWP>`], which takes
//! [`KeyType::SymmetricCipherKey`] material and hands the worker out through [`KeyWrappingKey`]
//! and [`KeyUnwrappingKey`], whose one-shots are the API in practice.
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
//! # Usage Examples
//!
//! RFC 3394 Sec 4.1, "Wrap 128 bits of Key Data with a 128-bit KEK", through the key:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::KW;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
//!
//! // KEK 000102030405060708090A0B0C0D0E0F, key data 00112233445566778899AABBCCDDEEFF.
//! let kek_bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
//! let key_data: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);
//! let material = KeyMaterial::<16>::from_bytes_as_type(&kek_bytes, KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let kek = AES128Key::<KW>::from_key_material(&material).expect("a valid AES-128 KEK");
//!
//! let wrapped: [u8; 24] = kek.wrap_key(&key_data).expect("wrapping");
//! assert_eq!(
//!     wrapped,
//!     [
//!         0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
//!         0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
//!     ]
//! );
//! let recovered = kek.unwrap_key::<16, 24>(&wrapped).expect("unwrapping");
//! assert_eq!(*recovered, key_data);
//! ```
//!
//! The second example of RFC 5649 Sec 6, which wraps 7 octets -- short enough that the header
//! and data fit one AES block, the case Algorithm 5 step 5 enciphers directly -- and a payload
//! whose length is only known at run time:
//!
//! ```
//! use bouncycastle_aes::AES192Key;
//! use bouncycastle_cipher::modes::KWP;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
//!
//! let kek_bytes = [
//!     0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
//!     0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
//! ];
//! let material = KeyMaterial::<24>::from_bytes_as_type(&kek_bytes, KeyType::SymmetricCipherKey)
//!     .expect("a 24-byte symmetric cipher key");
//! let kek = AES192Key::<KWP>::from_key_material(&material).expect("a valid AES-192 KEK");
//! let key_data = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
//!
//! let wrapped: [u8; 16] = kek.wrap_key(&key_data).expect("wrapping");
//! assert_eq!(
//!     wrapped,
//!     [
//!         0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b,
//!         0xb2, 0x4f,
//!     ]
//! );
//! assert_eq!(*kek.unwrap_key::<7, 16>(&wrapped).expect("unwrapping"), key_data);
//!
//! let payload = b"an encoded private key, of whatever length it happens to be";
//! let mut wrapped = vec![0u8; kek.wrap_out_len(payload.len())];
//! let n = kek.wrap_out(payload, &mut wrapped).expect("wrapping");
//! let mut recovered = vec![0u8; kek.unwrap_out_max_len(n)];
//! let m = kek.unwrap_out(&wrapped[..n], &mut recovered).expect("unwrapping");
//! assert_eq!(&recovered[..m], payload);
//! ```
//!
//! # Memory Usage
//!
//! A key is the expanded schedule: 176, 208 and 240 bytes for AES-128, -192 and -256. A worker
//! is the borrow of it, one pointer, and the wrapping function's scratch is one block on the
//! stack; the data is wrapped and unwrapped in the caller's buffers.
//!
//! [`AES128Key<KW>`]: crate::AES128Key
//! [`AES128Key<KWP>`]: crate::AES128Key
//! [`KeyWrapper`]: bouncycastle_core::traits::KeyWrapper
//! [`KeyUnwrapper`]: bouncycastle_core::traits::KeyUnwrapper
//! [`KeyWrappingKey`]: bouncycastle_core::symmetric_key::KeyWrappingKey
//! [`KeyUnwrappingKey`]: bouncycastle_core::symmetric_key::KeyUnwrappingKey
//! [`KeyType::SymmetricCipherKey`]: bouncycastle_core::key_material::KeyType::SymmetricCipherKey

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::{Kw, Kwp};

/// AES-128 Key Wrap (SP 800-38F KW; RFC 3394 with a 128-bit KEK): the worker an
/// `AES128Key<KW>` hands out.
#[allow(non_camel_case_types)]
pub type AES_KW_128<'k> = Kw<'k, AES128Internal>;

/// AES-192 Key Wrap (SP 800-38F KW; RFC 3394 with a 192-bit KEK). See [`AES_KW_128`].
#[allow(non_camel_case_types)]
pub type AES_KW_192<'k> = Kw<'k, AES192Internal>;

/// AES-256 Key Wrap (SP 800-38F KW; RFC 3394 with a 256-bit KEK). See [`AES_KW_128`].
#[allow(non_camel_case_types)]
pub type AES_KW_256<'k> = Kw<'k, AES256Internal>;

/// AES-128 Key Wrap with Padding (SP 800-38F KWP; RFC 5649 with a 128-bit KEK): the worker an
/// `AES128Key<KWP>` hands out.
#[allow(non_camel_case_types)]
pub type AES_KWP_128<'k> = Kwp<'k, AES128Internal>;

/// AES-192 Key Wrap with Padding (SP 800-38F KWP; RFC 5649 with a 192-bit KEK). See
/// [`AES_KWP_128`].
#[allow(non_camel_case_types)]
pub type AES_KWP_192<'k> = Kwp<'k, AES192Internal>;

/// AES-256 Key Wrap with Padding (SP 800-38F KWP; RFC 5649 with a 256-bit KEK). See
/// [`AES_KWP_128`].
#[allow(non_camel_case_types)]
pub type AES_KWP_256<'k> = Kwp<'k, AES256Internal>;
