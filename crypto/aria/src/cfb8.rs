//! Type aliases for ARIA (RFC 5794, KS X 1213-1) in CFB8 mode (NIST SP 800-38A Sec 6.3, `s = 8`).
//!
//! See `bouncycastle_cipher::modes::cfb8` for the construction. The aliases are stream ciphers
//! with a one-byte segment, and come from a key, [`ARIA128Key<CFB8>`](crate::ARIA128Key) and
//! friends, through the [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the IV is
//! one block, drawn from the caller's RNG by encryption and returned.
//!
//! CFB8 is a **different, non-interoperable mode** from CFB128, not a variant of it: their
//! ciphertexts differ from the second byte, and it costs a full ARIA call per byte, sixteen times
//! the work of [`ARIA_CFB_128`](crate::ARIA_CFB_128). See the `bouncycastle_cipher::modes::Cfb8`
//! docs for when that is the right trade.
//!
//! ```
//! use bouncycastle_aria::ARIA128Key;
//! use bouncycastle_cipher::modes::{CFB, CFB8};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let cfb8_key = ARIA128Key::<CFB8>::from_key_material(&material).expect("a valid ARIA-128 key");
//!
//! // 5 bytes: CFB8's segment is one byte, so any length at all is fine.
//! let message = *b"hello";
//! let mut data = message;
//! let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut data).unwrap();
//! assert_ne!(data, message);
//! cfb8_key.decrypt_inplace(&iv, &mut data).unwrap();
//! assert_eq!(data, message);
//!
//! // CFB8 and CFB128 are not interchangeable: same key material, same IV, different ciphertext.
//! let cfb_key = ARIA128Key::<CFB>::from_key_material(&material).unwrap();
//! let mut as_cfb8 = message;
//! let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut as_cfb8).unwrap();
//! let mut as_cfb128 = as_cfb8;
//! cfb_key.decrypt_inplace(&iv, &mut as_cfb128).unwrap();
//! assert_ne!(as_cfb128, message);
//! ```

use crate::BLOCK_LEN;
use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::modes::Cfb8;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// ARIA-128 in CFB8 mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime check.
#[allow(non_camel_case_types)]
pub type ARIA_CFB8_128<'k, Dir> = Cfb8<'k, ARIA128Internal, Dir, BLOCK_LEN>;

/// ARIA-192 in CFB8 mode. See [`ARIA_CFB8_128`].
#[allow(non_camel_case_types)]
pub type ARIA_CFB8_192<'k, Dir> = Cfb8<'k, ARIA192Internal, Dir, BLOCK_LEN>;

/// ARIA-256 in CFB8 mode. See [`ARIA_CFB8_128`].
#[allow(non_camel_case_types)]
pub type ARIA_CFB8_256<'k, Dir> = Cfb8<'k, ARIA256Internal, Dir, BLOCK_LEN>;
