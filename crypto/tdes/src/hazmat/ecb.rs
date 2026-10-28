//! Type aliases for TDES in ECB mode (NIST SP 800-38A Sec 6.1; "TECB" in SP 800-38A Appendix E),
//! with padding.
//!
//! See `bouncycastle_cipher::modes::hazmat::ecb` for the construction. The aliases name the
//! padded workers, handed out by a [`TDES3Key`](crate::TDES3Key) under `ECB<Pad>` through the
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; under `ECB<Blocks>` the key
//! hands out the unpadded `Ecb` through [`EcbEncryptionKey`] / [`EcbDecryptionKey`] instead, and
//! a [`TDES2Key`](crate::TDES2Key) hands out the decryptors alone.
//!
//! **ECB is not a confidentiality mode for data.** Under a given key every plaintext block maps to
//! the same ciphertext block (Sec 6.1), so the structure of the plaintext shows through, and blocks
//! can be reordered, repeated or removed undetectably. Padding does not change that in the least:
//! it makes ECB accept any length, not make it safe. These aliases exist for interoperability with
//! systems that use ECB and for driving test vectors. See the crate docs, "A block permutation is
//! not a cipher".
//!
//! ECB is defined only on whole blocks (SP 800-38A Sec 5.2), so ECB on data of any other length is
//! always ECB *plus a padding scheme*, and the scheme changes the ciphertext; it is part of the
//! key's mode for the reasons given at [`TDES_CBC`](crate::TDES_CBC). ECB has no IV, so
//! `INIT_DATA_LEN` is 0: encryption returns an empty array and decryption takes one, and the
//! ciphertext is exactly the padded plaintext with nothing prepended.

use crate::BLOCK_LEN;
use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::hazmat::ecb::Ecb;
use bouncycastle_cipher::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::hazmat::{EcbDecryptionKey, EcbEncryptionKey};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// TDES in ECB mode with a padding scheme: what a [`TDES3Key`](crate::TDES3Key) under
/// `ECB<Pad>` hands out.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`] and `Pad` is [`PKCS7`] or [`NoPadding`]; the wrong
/// direction is a compile error, not a runtime check. There is no IV: encryption returns an empty
/// array and decryption takes one.
///
/// **Not confidential for data** -- see the module docs. Padding makes ECB accept any length; it
/// does not make it safe.
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::hazmat::ecb::ECB;
/// use bouncycastle_cipher::padding::PKCS7;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// // Three distinct component keys; see `TDESInternal` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let key = TDES3Key::<ECB<PKCS7>>::from_key_material(&material).expect("a valid key bundle");
///
/// // 5 bytes: PKCS#7 pads it to one 8-byte block. The init data is empty, ECB having no IV.
/// let (no_iv, ciphertext) = key.encrypt(&mut rng, b"hello").expect("encryption");
/// assert_eq!(no_iv, [0u8; 0]);
/// assert_eq!(ciphertext.len(), 8);
///
/// let recovered = key.decrypt(&no_iv, &ciphertext).expect("decryption");
/// assert_eq!(recovered, b"hello");
/// ```
///
/// The codebook property survives padding, which is the whole objection to ECB: two identical
/// plaintext blocks still give two identical ciphertext blocks.
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::hazmat::ecb::ECB;
/// use bouncycastle_cipher::padding::NoPadding;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .unwrap();
/// let key = TDES3Key::<ECB<NoPadding>>::from_key_material(&material).unwrap();
///
/// // Two identical blocks in...
/// let (_, ciphertext) = key.encrypt(&mut HashDRBG_SHA512::new_from_os(), &[0x5Au8; 16]).unwrap();
/// // ...two identical blocks out. No mode here chains, so nothing hides the repetition.
/// assert_eq!(ciphertext[..8], ciphertext[8..]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES_ECB<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<Ecb<'k, TDESInternal, Encrypting, BLOCK_LEN>, Pad, 0, BLOCK_LEN>,
    PaddedBlockCipherDecryptor<Ecb<'k, TDESInternal, Decrypting, BLOCK_LEN>, Pad, 0, BLOCK_LEN>,
>;

/// Two-key TDES in ECB mode with a padding scheme, **decryption only**: what a
/// [`TDES2Key`](crate::TDES2Key) under `ECB<Pad>` hands out.
///
/// `Pad` is [`PKCS7`] or [`NoPadding`]. There is no direction parameter: two-key TDEA is disallowed
/// for encryption (SP 800-131A Rev 2 Table 1), so this is the [`PaddedBlockCipherDecryptor`] alone;
/// see [`TDES2Internal`]. There is no IV, so decryption takes an empty array. The ECB warning in
/// the module docs applies unchanged.
///
/// ```
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::hazmat::ecb::ECB;
/// use bouncycastle_cipher::padding::NoPadding;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
///
/// // NIST CAVP TECBMMT2.rsp, [DECRYPT] COUNT = 0: KEY1 || KEY2 (KEY3 = KEY1).
/// let material = KeyMaterial::<16>::from_bytes_as_type(
///     &[0x15, 0x1f, 0x10, 0x38, 0x3d, 0x6d, 0x19, 0x9b,
///       0x4a, 0x76, 0x3b, 0xd5, 0x4a, 0x46, 0xa4, 0x45],
///     KeyType::SymmetricCipherKey,
/// ).expect("a 16-byte symmetric cipher key");
/// let key = TDES2Key::<ECB<NoPadding>>::from_key_material(&material)
///     .expect("a valid two-key bundle");
///
/// let ciphertext = [0x89, 0x32, 0x1b, 0xa7, 0x5b, 0xa5, 0x45, 0xdb];
/// let plaintext = key.decrypt(&[], &ciphertext).expect("decryption");
/// assert_eq!(plaintext, [0xd8, 0xda, 0x89, 0x29, 0x88, 0x78, 0xed, 0x7d]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_ECB<'k, Pad> =
    PaddedBlockCipherDecryptor<Ecb<'k, TDES2Internal, Decrypting, BLOCK_LEN>, Pad, 0, BLOCK_LEN>;
