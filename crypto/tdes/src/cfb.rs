//! Type aliases for TDES in CFB mode (NIST SP 800-38A Sec 6.3), full-block segment.
//!
//! See `bouncycastle_cipher::modes::cfb` for the construction. The aliases are stream ciphers:
//! the data is a `&mut [u8]` of any length, encrypted or decrypted in place. They come from a key,
//! [`TDES3Key<CFB>`](crate::TDES3Key), through the [`SymmetricEncryptionKey`] /
//! [`SymmetricDecryptionKey`] pair; the IV is one block (8 bytes), drawn from the caller's RNG by
//! encryption and returned, and there is no API for supplying one.
//!
//! The segment size is the full block, so this is **CFB64** -- the `s = 64` case of the TCFB mode
//! that SP 800-38A Appendix E says is "equivalent to the CFB mode in this recommendation, with the
//! TDEA as the underlying block cipher". SP 800-38A's `s = 8` variant is a different,
//! non-interoperable mode with its own alias, [`TDES_CFB8`](crate::TDES_CFB8); `s = 1` is not
//! implemented. See the `bouncycastle_cipher::modes::Cfb` docs.

use crate::BLOCK_LEN;
use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Decrypting;
use bouncycastle_cipher::modes::Cfb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// TDES in CFB64 mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime check.
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::CFB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
/// use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// // Three distinct component keys; see `TDESInternal` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let key = TDES3Key::<CFB>::from_key_material(&material).expect("a valid key bundle");
///
/// // 47 bytes: a stream cipher does not need a whole number of blocks.
/// let message = [0u8; 47];
/// let mut data = message;
/// let (_, iv) = key.encrypt_inplace(&mut rng, &mut data).unwrap();
/// assert_ne!(data, message);
/// key.decrypt_inplace(&iv, &mut data).unwrap();
/// assert_eq!(data, message);
///
/// // Streaming, at any byte boundary:
/// let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
/// let mut first = [0u8; 5];
/// let mut rest = [1u8; 30];
/// enc.do_encrypt_inplace(&mut first).unwrap();
/// enc.do_encrypt_inplace(&mut rest).unwrap();
/// let mut dec = key.create_decryptor(&iv);
/// dec.do_decrypt_inplace(&mut first).unwrap();
/// dec.do_decrypt_inplace(&mut rest).unwrap();
/// assert_eq!(first, [0u8; 5]);
/// assert_eq!(rest, [1u8; 30]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES_CFB<'k, Dir> = Cfb<'k, TDESInternal, Dir, BLOCK_LEN>;

/// Two-key TDES in CFB64 mode, **decryption only** (SP 800-131A Rev 2 Table 1). No direction
/// parameter: this is the `Decrypting` direction, and the key's `create_encryptor` does not
/// compile; see [`TDES2Internal`]. The IV is one 8-byte block, supplied by the caller as received.
///
/// ```
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::CFB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
///
/// // NIST CAVP TCFB64MMT2.rsp, [DECRYPT] COUNT = 0: KEY1 || KEY2 (KEY3 = KEY1).
/// let material = KeyMaterial::<16>::from_bytes_as_type(
///     &[0x9e, 0xe0, 0xb5, 0x9b, 0x25, 0x86, 0x51, 0x54,
///       0x58, 0x85, 0x51, 0x34, 0x1c, 0x4f, 0xef, 0x9e],
///     KeyType::SymmetricCipherKey,
/// ).expect("a 16-byte symmetric cipher key");
/// let key = TDES2Key::<CFB>::from_key_material(&material).expect("a valid two-key bundle");
/// let iv = [0x6e, 0x37, 0xd1, 0x97, 0x37, 0x6d, 0xb5, 0x95];
/// let mut data = [0x63, 0xca, 0xd5, 0x22, 0x60, 0xe0, 0xa1, 0xcd];
///
/// key.decrypt_inplace(&iv, &mut data).expect("decryption");
/// assert_eq!(data, [0xdc, 0xd3, 0xcf, 0x97, 0x46, 0xd6, 0xe4, 0x2b]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_CFB<'k> = Cfb<'k, TDES2Internal, Decrypting, BLOCK_LEN>;
