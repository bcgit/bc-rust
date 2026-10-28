//! Type aliases for TDES in CFB8 mode (NIST SP 800-38A Sec 6.3, `s = 8`).
//!
//! See `bouncycastle_cipher::modes::cfb8` for the construction. The aliases are stream ciphers
//! with a one-byte segment, and come from a key, [`TDES3Key<CFB8>`](crate::TDES3Key), through the
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the IV is one block (8 bytes),
//! drawn from the caller's RNG by encryption and returned.
//!
//! CFB8 is a **different, non-interoperable mode** from CFB64, not a variant of it: their
//! ciphertexts differ from the second byte, and it costs a full TDES call per byte, eight times
//! the work of [`TDES_CFB`](crate::TDES_CFB). It is the `s = 8` case of the TCFB mode of SP 800-38A
//! Appendix E. See the `bouncycastle_cipher::modes::Cfb8` docs for when that is the right trade.

use crate::BLOCK_LEN;
use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Decrypting;
use bouncycastle_cipher::modes::Cfb8;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// TDES in CFB8 mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime
/// check.
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::{CFB, CFB8};
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
/// let cfb8_key = TDES3Key::<CFB8>::from_key_material(&material).expect("a valid key bundle");
///
/// // 5 bytes: CFB8's segment is one byte, so any length at all is fine.
/// let message = *b"hello";
/// let mut data = message;
/// let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut data).unwrap();
/// assert_ne!(data, message);
/// cfb8_key.decrypt_inplace(&iv, &mut data).unwrap();
/// assert_eq!(data, message);
///
/// // CFB8 and CFB64 are not interchangeable: same key bundle, same IV, different ciphertext.
/// let cfb64_key = TDES3Key::<CFB>::from_key_material(&material).unwrap();
/// let mut as_cfb8 = message;
/// let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut as_cfb8).unwrap();
/// let mut as_cfb64 = as_cfb8;
/// cfb64_key.decrypt_inplace(&iv, &mut as_cfb64).unwrap();
/// assert_ne!(as_cfb64, message);
/// ```
#[allow(non_camel_case_types)]
pub type TDES_CFB8<'k, Dir> = Cfb8<'k, TDESInternal, Dir, BLOCK_LEN>;

/// Two-key TDES in CFB8 mode, **decryption only** (SP 800-131A Rev 2 Table 1). No direction
/// parameter: this is the `Decrypting` direction, and the key's `create_encryptor` does not
/// compile; see [`TDES2Internal`]. The IV is one 8-byte block, supplied by the caller as received.
///
/// ```
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::CFB8;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
///
/// // NIST CAVP TCFB8MMT2.rsp, [DECRYPT] COUNT = 0: KEY1 || KEY2 (KEY3 = KEY1).
/// let material = KeyMaterial::<16>::from_bytes_as_type(
///     &[0xfb, 0x97, 0x8a, 0x0b, 0x6d, 0xc2, 0xc4, 0x67,
///       0xe3, 0xcb, 0x52, 0x32, 0x9d, 0xe9, 0x51, 0x61],
///     KeyType::SymmetricCipherKey,
/// ).expect("a 16-byte symmetric cipher key");
/// let key = TDES2Key::<CFB8>::from_key_material(&material).expect("a valid two-key bundle");
/// let iv = [0x8b, 0x97, 0x57, 0x9e, 0xa5, 0xac, 0x30, 0x0f];
/// let mut data = [0x05];
///
/// key.decrypt_inplace(&iv, &mut data).expect("decryption");
/// assert_eq!(data, [0x80]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_CFB8<'k> = Cfb8<'k, TDES2Internal, Decrypting, BLOCK_LEN>;
