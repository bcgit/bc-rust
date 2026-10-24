//! Type aliases for TDES in CBC mode (NIST SP 800-38A Sec 6.2; "TCBC" in SP 800-38A Appendix E),
//! with padding.
//!
//! See `bouncycastle_cipher::modes::cbc` for the construction. The aliases name the padded
//! workers, which accept input of any size; `NoPadding` accepts only whole blocks but goes through
//! the same adapter. The workers come from a key: [`TDES3Key<CBC<PKCS7>>`](crate::TDES3Key) (or
//! `CBC<NoPadding>`) hands them out through the [`SymmetricEncryptionKey`] /
//! [`SymmetricDecryptionKey`] pair, `TDES3Key<CBC<Blocks>>` hands out the unpadded `Cbc` itself
//! through the block pair, and [`TDES2Key`](crate::TDES2Key) hands out the decryptor alone.
//!
//! # Why the padding is part of the key
//!
//! CBC is defined only on whole blocks (SP 800-38A Sec 5.2), and the recommendation puts the
//! formatting of anything else outside its scope (Appendix A). So CBC on real data is always CBC
//! *plus a padding scheme*, and the scheme is not an implementation detail: it changes the
//! ciphertext, and both ends must agree on it. Naming it in the key's mode makes that choice
//! explicit at every use, and makes a mismatched pair a compile error rather than a decryption
//! that returns plausible-looking rubbish.
//!
//! The two schemes `bouncycastle_cipher::padding` provides are [`PKCS7`], which is what almost
//! everyone means by "padded CBC" (RFC 5652 s. 6.3; Java's `DESede/CBC/PKCS5Padding`), and
//! [`NoPadding`], which adds nothing and instead *rejects* a message that is not a whole number
//! of blocks -- useful for formats already defined on block boundaries, where silently padding
//! would be wrong.

use crate::BLOCK_LEN;
use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::Cbc;
use bouncycastle_cipher::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// TDES in CBC mode with a padding scheme: what a [`TDES3Key`](crate::TDES3Key) under
/// `CBC<Pad>` hands out.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`] and `Pad` is [`PKCS7`] or [`NoPadding`]; the wrong
/// direction is a compile error, not a runtime check. The IV is drawn from the caller's RNG by
/// encryption and returned; it is never supplied. It is one block: 8 bytes.
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::PKCS7;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// // Three distinct component keys; see `TDESInternal` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let key = TDES3Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid key bundle");
///
/// // 5 bytes: PKCS#7 pads it to one block, so the padding does the work CBC cannot.
/// let (iv, ciphertext) = key.encrypt(&mut rng, b"hello").expect("encryption");
/// assert_eq!(ciphertext.len(), 8);
///
/// let plaintext = key.decrypt(&iv, &ciphertext).expect("decryption");
/// assert_eq!(plaintext, b"hello");
/// ```
///
/// With [`NoPadding`] nothing is added, and a message that is not a whole number of blocks is an
/// error at `do_encrypt_final` rather than something silently padded:
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::NoPadding;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
/// let key = TDES3Key::<CBC<NoPadding>>::from_key_material(&material).unwrap();
///
/// // A whole block is fine, and comes out the same length.
/// let mut out = [0u8; 8];
/// let (written, _iv) = key.encrypt_out(&mut rng, &[0u8; 8], &mut out).expect("aligned");
/// assert_eq!(written, 8);
///
/// // Five bytes is not, and is refused rather than padded.
/// assert!(key.encrypt_out(&mut rng, b"hello", &mut out).is_err());
/// ```
///
/// The padding scheme is part of the key type, so the two schemes' workers are different types
/// and cannot be interchanged. A value built with one will not satisfy a binding annotated with
/// the other:
///
/// ```compile_fail
/// use bouncycastle_tdes::{TDES_CBC, TDES3Key};
/// use bouncycastle_cipher::Encrypting;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::{NoPadding, PKCS7};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
/// let key = TDES3Key::<CBC<NoPadding>>::from_key_material(&material).unwrap();
///
/// // Built from a NoPadding key, annotated as PKCS7: mismatched types.
/// let (enc, _iv) = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
/// let _mismatched: TDES_CBC<Encrypting, PKCS7> = enc;
/// ```
#[allow(non_camel_case_types)]
pub type TDES_CBC<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, TDESInternal, Encrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, TDESInternal, Decrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
>;

/// Two-key TDES in CBC mode with a padding scheme, **decryption only**: what a
/// [`TDES2Key`](crate::TDES2Key) under `CBC<Pad>` hands out.
///
/// `Pad` is [`PKCS7`] or [`NoPadding`]. There is no direction parameter: two-key TDEA is disallowed
/// for encryption (SP 800-131A Rev 2 Table 1), so this is the [`PaddedBlockCipherDecryptor`] alone,
/// and the key's `create_encryptor` does not compile; see [`TDES2Internal`]. The IV is one 8-byte
/// block, supplied by the caller as it was received.
///
/// ```
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::NoPadding;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
///
/// // NIST CAVP TCBCMMT2.rsp, [DECRYPT] COUNT = 0: KEY1 || KEY2 (KEY3 = KEY1).
/// let material = KeyMaterial::<16>::from_bytes_as_type(
///     &[0xbc, 0xfe, 0x7f, 0x25, 0xf2, 0xb0, 0xa7, 0x2c,
///       0x62, 0x76, 0xae, 0x1f, 0x38, 0x9d, 0x8a, 0xe9],
///     KeyType::SymmetricCipherKey,
/// ).expect("a 16-byte symmetric cipher key");
/// let key = TDES2Key::<CBC<NoPadding>>::from_key_material(&material).expect("a valid two-key bundle");
/// let iv = [0xf2, 0x9d, 0x4b, 0xa5, 0x17, 0x2f, 0xd2, 0x97];
/// let ciphertext = [0x1b, 0x38, 0x89, 0xc9, 0xdb, 0xe1, 0x0d, 0x03];
///
/// let plaintext = key.decrypt(&iv, &ciphertext).expect("decryption");
/// assert_eq!(plaintext, [0x06, 0x11, 0xa4, 0x74, 0xfb, 0x09, 0x09, 0x78]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_CBC<'k, Pad> = PaddedBlockCipherDecryptor<
    Cbc<'k, TDES2Internal, Decrypting, BLOCK_LEN>,
    Pad,
    BLOCK_LEN,
    BLOCK_LEN,
>;
