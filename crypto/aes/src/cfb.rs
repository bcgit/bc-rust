//! Type aliases for AES in CFB mode (NIST SP 800-38A Sec 6.3).
//!
//! See [`bouncycastle_cipher::modes::cfb`] for details on the CipherFeedback construction.
//!
//! The aliases here are stream ciphers: the data is a `&mut [u8]` of any length, encrypted or
//! decrypted in place, and the ciphertext is exactly as long as the plaintext. The IV is generated
//! by encryption and returned; there is no API for supplying one. `Dir` is [`Encrypting`] or
//! [`Decrypting`]; the wrong direction is a compile error, not a runtime check.
//!
//! The segment size is the full block, so the constructions used here are equivalent to **CFB128**.
//! SP 800-38A's `s = 8` variant is a different, non-interoperable mode with its own aliases,
//! [`AES_CFB8_128`](crate::AES_CFB8_128) and friends, and `s = 1` is not implemented.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! Basic usage can be obtained via the [`StreamCipherEncryptor`] and [`StreamCipherDecryptor`] API:
//!
//! ```
//! use bouncycastle_aes::{AES_CFB_256, AES_CFB_256_Key};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherKey};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CFB_256<Encrypting>;
//! type AESDec = AES_CFB_256<Decrypting>;
//!
//! let key = AES_CFB_256_Key::new_from_os().expect("a fresh key");
//!
//! // An arbitrary plaintext to encrypt.
//! // Any length: a stream cipher does not need a whole number of blocks.
//! let plaintext = [0x5Au8; 47];
//!
//! // Encryption works in place. The IV is generated for you and returned; there is no API for
//! // supplying one.
//! let mut data = plaintext;
//! let (_, iv) = AESEnc::encrypt_inplace(&key, &mut data).expect("encryption");
//!
//! AESDec::decrypt_inplace(&key, &iv, &mut data).expect("decryption");
//! assert_eq!(data, plaintext);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the following APIs can be used. A stream cipher processes
//! every byte it is given, so nothing is held back between calls and the pieces can be of any
//! length:
//!
//! ```
//! use bouncycastle_aes::{AES_CFB_128, AES_CFB_128_Key};
//! use bouncycastle_core::traits::{
//!     StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
//!     SymmetricCipherEncryptor,
//!     SymmetricCipherKey,
//! };
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CFB_128<Encrypting>;
//! type AESDec = AES_CFB_128<Decrypting>;
//!
//! let key = AES_CFB_128_Key::new_from_os().expect("a fresh key");
//!
//! // An arbitrary plaintext to encrypt
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 7-byte pieces, each in place.
//! let (mut encryptor, iv) = AESEnc::do_encrypt_init(&key).expect("encrypt init");
//! let mut ciphertext = plaintext;
//! for piece in ciphertext.chunks_mut(7) {
//!     encryptor.do_encrypt_inplace(piece).expect("encryption");
//! }
//!
//! // Decrypt in 19-byte pieces: the boundaries need not match the encryptor's.
//! let mut decryptor = AESDec::do_decrypt_init(&key, &iv).expect("decrypt init");
//! let mut recovered = ciphertext;
//! for piece in recovered.chunks_mut(19) {
//!     decryptor.do_decrypt_inplace(piece).expect("decryption");
//! }
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::cfb`] apply.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Cfb;

use bouncycastle_core::errors::{KeyMaterialError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::SymmetricCipherKey;
use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512};
// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
// end of imports needed for docs

/// AES-128 in CFB128 mode.
#[allow(non_camel_case_types)]
pub type AES_CFB_128<Dir> = Cfb<AES128Internal, Dir, AES_CFB_128_Key, 16, AES_BLOCK_LEN>;

/// An AES-CFB-128 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CFB_128_Key(KeyMaterial<16>);

impl SymmetricCipherKey<16> for AES_CFB_128_Key {
    fn from_keymaterial(key: KeyMaterial<16>) -> Result<Self, KeyMaterialError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("Must be SymmetricCipherKey"));
        }
        if key.security_strength() < SecurityStrength::_128bit {
            return Err(KeyMaterialError::InvalidKeyType(
                "Key's Security strength must be at least 128bit",
            ));
        }
        Ok(Self(key))
    }

    fn get_key(&self) -> &KeyMaterial<16> {
        &self.0
    }

    fn new_from_os() -> Result<Self, RNGError> {
        Self::new_from_rng(&mut HashDRBG_SHA256::new_from_os())
    }
}

/// AES-192 in CFB128 mode.
#[allow(non_camel_case_types)]
pub type AES_CFB_192<Dir> = Cfb<AES192Internal, Dir, AES_CFB_192_Key, 24, AES_BLOCK_LEN>;

/// An AES-CFB-192 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CFB_192_Key(KeyMaterial<24>);

impl SymmetricCipherKey<24> for AES_CFB_192_Key {
    fn from_keymaterial(key: KeyMaterial<24>) -> Result<Self, KeyMaterialError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("Must be SymmetricCipherKey"));
        }
        if key.security_strength() < SecurityStrength::_192bit {
            return Err(KeyMaterialError::InvalidKeyType(
                "Key's Security strength must be at least 192bit",
            ));
        }
        Ok(Self(key))
    }

    fn get_key(&self) -> &KeyMaterial<24> {
        &self.0
    }

    fn new_from_os() -> Result<Self, RNGError> {
        Self::new_from_rng(&mut HashDRBG_SHA512::new_from_os())
    }
}

/// AES-256 in CFB128 mode. See [`AES_CFB_128`].
#[allow(non_camel_case_types)]
pub type AES_CFB_256<Dir> = Cfb<AES256Internal, Dir, AES_CFB_256_Key, 32, AES_BLOCK_LEN>;

/// An AES-CFB-256 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CFB_256_Key(KeyMaterial<32>);

impl SymmetricCipherKey<32> for AES_CFB_256_Key {
    fn from_keymaterial(key: KeyMaterial<32>) -> Result<Self, KeyMaterialError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("Must be SymmetricCipherKey"));
        }
        if key.security_strength() < SecurityStrength::_256bit {
            return Err(KeyMaterialError::InvalidKeyType(
                "Key's Security strength must be at least 256bit",
            ));
        }
        Ok(Self(key))
    }

    fn get_key(&self) -> &KeyMaterial<32> {
        &self.0
    }

    fn new_from_os() -> Result<Self, RNGError> {
        Self::new_from_rng(&mut HashDRBG_SHA512::new_from_os())
    }
}
