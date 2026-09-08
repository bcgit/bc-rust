//! Type alias for TDES in ECB mode (NIST SP 800-38A Sec 6.1; "TECB" in SP 800-38A Appendix E),
//! with padding.
//!
//! `bouncycastle-modes` is deliberately cipher-agnostic, so `Ecb` takes the permutation, the
//! direction, and the `KEY_LEN` / `BLOCK_LEN` const parameters, and `bouncycastle-padding`'s
//! adapters take five more. This alias pins all of them except the two choices a caller actually
//! makes: the direction and the padding scheme.
//!
//! ```text
//! TDES_ECB<Encrypting, PKCS7>      // TDES, ECB, PKCS#7 padded, encrypting
//! TDES_ECB<Decrypting, NoPadding>
//! ```
//!
//! **ECB is not a confidentiality mode for data.** Under a given key every plaintext block maps to
//! the same ciphertext block (Sec 6.1), so the structure of the plaintext shows through, and blocks
//! can be reordered, repeated or removed undetectably. Padding does not change that in the least:
//! it makes ECB accept any length, not make it safe. This alias exists for interoperability with
//! systems that use ECB and for driving test vectors. See the crate docs, "A block permutation is
//! not a cipher".
//!
//! # Why the padding is part of the alias
//!
//! ECB is defined only on whole blocks (SP 800-38A Sec 5.2), so ECB on data of any other length is
//! always ECB *plus a padding scheme*, and the scheme changes the ciphertext. Naming it in the type
//! makes the choice explicit and makes a mismatched pair a compile error. [`PKCS7`] is the usual
//! one (this is Java's `DESede/ECB/PKCS5Padding`); [`NoPadding`] adds nothing and instead rejects a
//! message that is not a whole number of blocks.
//!
//! # This is the arbitrary-length API
//!
//! A padded alias implements [`SimpleCipherEncryptor`] / [`SimpleCipherDecryptor`], not the
//! block traits. The block-aligned API, with compile-time length checks and in-place data methods,
//! is `bouncycastle_modes::Ecb` itself, which this wraps. ECB has no IV, so `INIT_DATA_LEN` is 0:
//! encryption returns an empty array and decryption takes one, and the ciphertext is exactly the
//! padded plaintext with nothing prepended.
//!
//! # How one alias covers both directions
//!
//! See [`PaddedMode`], which is the projection that lets `Dir` select between the encryptor and the
//! decryptor adapter. `Dir` must be [`Encrypting`] or [`Decrypting`].

use crate::padded_mode::PaddedMode;
use crate::{BLOCK_LEN, KEY_LEN, KEY_LEN_2KEY, TDES, TDES2Key};
use bouncycastle_modes::{Decrypting, Ecb, Encrypting};
use bouncycastle_padding::PaddedDecryptor;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
#[allow(unused_imports)]
use bouncycastle_padding::{NoPadding, PKCS7};
// end of imports needed for docs

/// TDES in ECB mode with a padding scheme.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`] and `Pad` is [`PKCS7`] or [`NoPadding`]; the wrong
/// direction is a compile error, not a runtime check. There is no IV: encryption returns an empty
/// array and decryption takes one.
///
/// **Not confidential for data** -- see the module docs. Padding makes ECB accept any length; it
/// does not make it safe.
///
/// ```
/// use bouncycastle_tdes::TDES_ECB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
/// use bouncycastle_padding::PKCS7;
///
/// type Enc = TDES_ECB<Encrypting, PKCS7>;
/// type Dec = TDES_ECB<Decrypting, PKCS7>;
///
/// // Three distinct component keys; see `TDES` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let key = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
///
/// // 5 bytes: PKCS#7 pads it to one 8-byte block. The init data is empty, ECB having no IV.
/// let (no_iv, ciphertext) = Enc::encrypt(&key, b"hello").expect("encryption");
/// assert_eq!(no_iv, [0u8; 0]);
/// assert_eq!(ciphertext.len(), 8);
///
/// let recovered = Dec::decrypt(&key, &no_iv, &ciphertext).expect("decryption");
/// assert_eq!(recovered, b"hello");
/// ```
///
/// The codebook property survives padding, which is the whole objection to ECB: two identical
/// plaintext blocks still give two identical ciphertext blocks.
///
/// ```
/// use bouncycastle_tdes::TDES_ECB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SimpleCipherEncryptor;
/// use bouncycastle_modes::Encrypting;
/// use bouncycastle_padding::NoPadding;
///
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let key = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
///
/// // Two identical blocks in...
/// let (_, ciphertext) =
///     TDES_ECB::<Encrypting, NoPadding>::encrypt(&key, &[0x5Au8; 16]).expect("encryption");
/// // ...two identical blocks out. No mode here chains, so nothing hides the repetition.
/// assert_eq!(ciphertext[..8], ciphertext[8..]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES_ECB<Dir, Pad> = <Dir as PaddedMode<
    Ecb<TDES, Encrypting, KEY_LEN, BLOCK_LEN>,
    Ecb<TDES, Decrypting, KEY_LEN, BLOCK_LEN>,
    Pad,
    0,
>>::Mode;

/// Two-key TDES in ECB mode with a padding scheme, **decryption only**.
///
/// `Pad` is [`PKCS7`] or [`NoPadding`]. There is no direction parameter: two-key TDEA is disallowed
/// for encryption (SP 800-131A Rev 2 Table 1), so this is the [`PaddedDecryptor`] alone; see
/// [`TDES2Key`]. There is no IV, so decryption takes an empty array. The ECB warning in the module
/// docs applies unchanged.
///
/// ```
/// use bouncycastle_tdes::TDES2_ECB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SimpleCipherDecryptor;
/// use bouncycastle_padding::NoPadding;
///
/// // NIST CAVP TECBMMT2.rsp, [DECRYPT] COUNT = 0: KEY1 || KEY2 (KEY3 = KEY1).
/// let key = KeyMaterial::<16>::from_bytes_as_type(
///     &[0x15, 0x1f, 0x10, 0x38, 0x3d, 0x6d, 0x19, 0x9b,
///       0x4a, 0x76, 0x3b, 0xd5, 0x4a, 0x46, 0xa4, 0x45],
///     KeyType::SymmetricCipherKey,
/// ).expect("a 16-byte symmetric cipher key");
///
/// let ciphertext = [0x89, 0x32, 0x1b, 0xa7, 0x5b, 0xa5, 0x45, 0xdb];
/// let plaintext = TDES2_ECB::<NoPadding>::decrypt(&key, &[], &ciphertext).expect("decryption");
/// assert_eq!(plaintext, [0xd8, 0xda, 0x89, 0x29, 0x88, 0x78, 0xed, 0x7d]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_ECB<Pad> = PaddedDecryptor<
    Ecb<TDES2Key, Decrypting, KEY_LEN_2KEY, BLOCK_LEN>,
    Pad,
    KEY_LEN_2KEY,
    0,
    BLOCK_LEN,
>;
