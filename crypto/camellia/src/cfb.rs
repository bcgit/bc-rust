//! Type aliases for Camellia (RFC 3713) in CFB mode (NIST SP 800-38A Sec 6.3).
//!
//! See `bouncycastle_cipher::modes::cfb` for the construction. The aliases are stream ciphers:
//! the data is a `&mut [u8]` of any length, encrypted or decrypted in place. They come from a key,
//! [`Camellia128Key<CFB>`](crate::Camellia128Key) and friends, through the
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the IV is one block, drawn from
//! the caller's RNG by encryption and returned, and there is no API for supplying one.
//!
//! The segment size is the full block, so these are **CFB128**. SP 800-38A's `s = 8` variant is a
//! different, non-interoperable mode with its own aliases --
//! [`Camellia_CFB8_128`](crate::Camellia_CFB8_128) and friends -- and `s = 1` is not implemented;
//! see the `bouncycastle_cipher::modes::Cfb` docs.
//!
//! ```
//! use bouncycastle_camellia::Camellia128Key;
//! use bouncycastle_cipher::modes::CFB;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = Camellia128Key::<CFB>::from_key_material(&material)
//!     .expect("a valid Camellia-128 key");
//!
//! // 47 bytes: a stream cipher does not need a whole number of blocks.
//! let message = [0u8; 47];
//! let mut data = message;
//! let (_, iv) = key.encrypt_inplace(&mut rng, &mut data).unwrap();
//! assert_ne!(data, message);
//! key.decrypt_inplace(&iv, &mut data).unwrap();
//! assert_eq!(data, message);
//!
//! // Streaming, at any byte boundary:
//! let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
//! let mut first = [0u8; 5];
//! let mut rest = [1u8; 30];
//! enc.do_encrypt_inplace(&mut first).unwrap();
//! enc.do_encrypt_inplace(&mut rest).unwrap();
//! let mut dec = key.create_decryptor(&iv);
//! dec.do_decrypt_inplace(&mut first).unwrap();
//! dec.do_decrypt_inplace(&mut rest).unwrap();
//! assert_eq!(first, [0u8; 5]);
//! assert_eq!(rest, [1u8; 30]);
//! ```

use crate::BLOCK_LEN;
use crate::hazmat::{Camellia128Internal, Camellia192Internal, Camellia256Internal};
use bouncycastle_cipher::modes::Cfb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// Camellia-128 in CFB128 mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime
/// check.
#[allow(non_camel_case_types)]
pub type Camellia_CFB_128<'k, Dir> = Cfb<'k, Camellia128Internal, Dir, BLOCK_LEN>;

/// Camellia-192 in CFB128 mode. See [`Camellia_CFB_128`].
#[allow(non_camel_case_types)]
pub type Camellia_CFB_192<'k, Dir> = Cfb<'k, Camellia192Internal, Dir, BLOCK_LEN>;

/// Camellia-256 in CFB128 mode. See [`Camellia_CFB_128`].
#[allow(non_camel_case_types)]
pub type Camellia_CFB_256<'k, Dir> = Cfb<'k, Camellia256Internal, Dir, BLOCK_LEN>;
