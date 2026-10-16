//! Type aliases for AES in CMAC (NIST SP 800-38B), and the `CMAC` mode impls that make
//! [`AES128Key<CMAC>`] and friends MAC keys.
//!
//! See [`bouncycastle_cipher::modes::cmac`] for the construction, the key requirements,
//! truncation and security considerations. [`AES_CMAC_128`] and friends name the worker, which
//! implements [`MAC`]; it comes from a key, [`AES128Key<CMAC>`], which takes
//! [`KeyType::MACKey`] material, derives the subkeys once and hands out the worker through
//! [`MacGenerationKey`] and [`MacVerificationKey`].
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::CMAC;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
//! use bouncycastle_core::traits::MAC;
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
//! let key = AES256Key::<CMAC>::from_key_material(&material).expect("a valid AES-256 MAC key");
//!
//! // A message that arrives in pieces, through the worker.
//! let mut generator = key.create_generator();
//! generator.do_update(b"a message that arrives ");
//! generator.do_update(b"in pieces");
//! let mut tag = [0u8; 16];
//! assert_eq!(generator.do_final_out(&mut tag).unwrap(), 16);
//!
//! // One-shots on the key.
//! assert!(key.verify(b"a message that arrives in pieces", &tag));
//! assert_eq!(key.mac(b"a message that arrives in pieces"), tag);
//! ```
//!
//! # Memory Usage
//!
//! A key is the expanded schedule plus the two 16-byte subkeys: 208, 240 and 272 bytes for
//! AES-128, -192 and -256, or 176, 208 and 240 bytes more with the `Arm` engine, the default on
//! an AArch64 build with the Crypto Extensions, for the second schedule it holds (see the crate
//! docs). A worker borrows that and adds the running `C_i`, the pending block and its length:
//! 48 bytes at every key length.
//!
//! [`AES128Key<CMAC>`]: crate::AES128Key
//! [`MAC`]: bouncycastle_core::traits::MAC
//! [`MacGenerationKey`]: bouncycastle_core::symmetric_key::MacGenerationKey
//! [`MacVerificationKey`]: bouncycastle_core::symmetric_key::MacVerificationKey
//! [`KeyType::MACKey`]: bouncycastle_core::key_material::KeyType::MACKey

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Cmac;

/// AES-128 in CMAC.
#[allow(non_camel_case_types)]
pub type AES_CMAC_128<'k> = Cmac<'k, AES128Internal, 16>;

/// AES-192 in CMAC. See [`AES_CMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_CMAC_192<'k> = Cmac<'k, AES192Internal, 16>;

/// AES-256 in CMAC. See [`AES_CMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_CMAC_256<'k> = Cmac<'k, AES256Internal, 16>;
