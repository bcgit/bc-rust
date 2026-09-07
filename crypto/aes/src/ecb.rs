//! Type aliases for AES in ECB mode (NIST SP 800-38A Sec 6.1), with padding.
//!
//! `bouncycastle-modes` is deliberately cipher-agnostic, so `Ecb` takes the permutation, the
//! direction, and the `KEY_LEN` / `BLOCK_LEN` const parameters, and `bouncycastle-padding`'s
//! adapters take five more. These aliases pin all of them except the two choices a caller actually
//! makes: the direction and the padding scheme.
//!
//! ```text
//! AES_ECB_128<Encrypting, PKCS7>      // AES-128, ECB, PKCS#7 padded, encrypting
//! AES_ECB_256<Decrypting, NoPadding>
//! ```
//!
//! **ECB is not a confidentiality mode for data.** Under a given key every plaintext block maps to
//! the same ciphertext block (Sec 6.1), so the structure of the plaintext shows through, and blocks
//! can be reordered, repeated or removed undetectably. Padding does not change that in the least:
//! it makes ECB accept any length, not make it safe. These aliases exist for interoperability with
//! systems that use ECB and for driving test vectors; for data, use CBC or CFB under
//! authentication, or better an AEAD. See the crate docs, "A block permutation is not a cipher".
//!
//! # Why the padding is part of the alias
//!
//! ECB is defined only on whole blocks (SP 800-38A Sec 5.2), so ECB on data of any other length is
//! always ECB *plus a padding scheme*, and the scheme changes the ciphertext. Naming it in the type
//! makes the choice explicit and makes a mismatched pair a compile error. [`PKCS7`] is the usual
//! one (this is Java's `AES/ECB/PKCS5Padding`); [`NoPadding`] adds nothing and instead rejects a
//! message that is not a whole number of blocks.
//!
//! # These are the arbitrary-length API
//!
//! A padded alias implements [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`], not the
//! block traits. The block-aligned API, with compile-time length checks and in-place data methods,
//! is `bouncycastle_modes::Ecb` itself, which these wrap. ECB has no IV, so `INIT_DATA_LEN` is 0:
//! encryption returns an empty array and decryption takes one, and the ciphertext is exactly the
//! padded plaintext with nothing prepended.
//!
//! # How one alias covers both directions
//!
//! See [`PaddedMode`], which is the projection that lets `Dir` select between the encryptor and the
//! decryptor adapter. `Dir` must be [`Encrypting`] or [`Decrypting`], as before.

use crate::padded_mode::PaddedMode;
use crate::{Aes128, Aes192, Aes256, BLOCK_LEN};
use bouncycastle_modes::{Decrypting, Ecb, Encrypting};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
#[allow(unused_imports)]
use bouncycastle_padding::{NoPadding, PKCS7};
// end of imports needed for docs

/// AES-128 in ECB mode with a padding scheme.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`] and `Pad` is [`PKCS7`] or [`NoPadding`]; the wrong
/// direction is a compile error, not a runtime check. There is no IV: encryption returns an empty
/// array and decryption takes one.
///
/// **Not confidential for data** -- see the module docs. Padding makes ECB accept any length; it
/// does not make it safe.
///
/// ```
/// use bouncycastle_aes::AES_ECB_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
/// use bouncycastle_padding::PKCS7;
///
/// type Enc = AES_ECB_128<Encrypting, PKCS7>;
/// type Dec = AES_ECB_128<Decrypting, PKCS7>;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
///
/// // 5 bytes: PKCS#7 pads it to one block. The init data is empty, ECB having no IV.
/// let (no_iv, ciphertext) = Enc::encrypt(&key, b"hello").expect("encryption");
/// assert_eq!(no_iv, [0u8; 0]);
/// assert_eq!(ciphertext.len(), 16);
///
/// let recovered = Dec::decrypt(&key, &no_iv, &ciphertext).expect("decryption");
/// assert_eq!(recovered, b"hello");
/// ```
///
/// The codebook property survives padding, which is the whole objection to ECB: two identical
/// plaintext blocks still give two identical ciphertext blocks.
///
/// ```
/// use bouncycastle_aes::AES_ECB_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_modes::Encrypting;
/// use bouncycastle_padding::NoPadding;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
///
/// // Two identical blocks in...
/// let (_, ciphertext) =
///     AES_ECB_128::<Encrypting, NoPadding>::encrypt(&key, &[0x5Au8; 32]).expect("encryption");
/// // ...two identical blocks out. No mode here chains, so nothing hides the repetition.
/// assert_eq!(ciphertext[..16], ciphertext[16..]);
/// ```
#[allow(non_camel_case_types)]
pub type AES_ECB_128<Dir, Pad> = <Dir as PaddedMode<
    Ecb<Aes128, Encrypting, 16, BLOCK_LEN>,
    Ecb<Aes128, Decrypting, 16, BLOCK_LEN>,
    Pad,
    16,
    0,
>>::Mode;

/// AES-192 in ECB mode with a padding scheme. See [`AES_ECB_128`], and its warning.
///
/// ```
/// use bouncycastle_aes::AES_ECB_192;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
/// use bouncycastle_padding::PKCS7;
///
/// let key = KeyMaterial::<24>::from_bytes_as_type(&[0x42; 24], KeyType::SymmetricCipherKey).unwrap();
/// let message = b"a message of no particular length";
///
/// let (no_iv, ciphertext) =
///     AES_ECB_192::<Encrypting, PKCS7>::encrypt(&key, message).expect("encryption");
/// let recovered =
///     AES_ECB_192::<Decrypting, PKCS7>::decrypt(&key, &no_iv, &ciphertext).expect("decryption");
/// assert_eq!(recovered, message);
/// ```
#[allow(non_camel_case_types)]
pub type AES_ECB_192<Dir, Pad> = <Dir as PaddedMode<
    Ecb<Aes192, Encrypting, 24, BLOCK_LEN>,
    Ecb<Aes192, Decrypting, 24, BLOCK_LEN>,
    Pad,
    24,
    0,
>>::Mode;

/// AES-256 in ECB mode with a padding scheme. See [`AES_ECB_128`], and its warning.
///
/// ```
/// use bouncycastle_aes::AES_ECB_256;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
/// use bouncycastle_padding::PKCS7;
///
/// let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
/// let message = b"a message of no particular length";
///
/// let (no_iv, ciphertext) =
///     AES_ECB_256::<Encrypting, PKCS7>::encrypt(&key, message).expect("encryption");
/// let recovered =
///     AES_ECB_256::<Decrypting, PKCS7>::decrypt(&key, &no_iv, &ciphertext).expect("decryption");
/// assert_eq!(recovered, message);
/// ```
#[allow(non_camel_case_types)]
pub type AES_ECB_256<Dir, Pad> = <Dir as PaddedMode<
    Ecb<Aes256, Encrypting, 32, BLOCK_LEN>,
    Ecb<Aes256, Decrypting, 32, BLOCK_LEN>,
    Pad,
    32,
    0,
>>::Mode;
