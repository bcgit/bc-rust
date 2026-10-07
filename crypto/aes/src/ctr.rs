//! Type aliases for AES in CTR mode (NIST SP 800-38A Sec 6.5).
//!
//! See [`bouncycastle_cipher::modes::ctr`] for details on the Counter construction.
//!
//! The aliases here are stream ciphers: the data is a `&mut [u8]` of any length, encrypted or
//! decrypted in place since ciphertext is exactly as long as the plaintext. The nonce is generated
//! by encryption and returned; there is no API for supplying one. `Dir` is [`Encrypting`] or [`Decrypting`];
//! the wrong direction is a compile error, not a runtime check.
//!
//! # Nonce and counter length
//!
//! **The nonce length is 12 bytes, the counter is 4 bytes.**
//!
//! These aliases fix a **12-byte nonce** ([`CTR_NONCE_LEN`]), leaving the remainder of each block to
//! be a 4-byte counter. That allows 2^32 blocks -- 64 GiB -- in one message, and past it the
//! mode errors rather than repeating the keystream. A shorter message limit in exchange for more nonce
//! bits is available by using `Ctr` directly with a 13, 14 or 15-byte nonce.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! Basic usage can be obtained via the [`StreamCipherEncryptor`] and [`StreamCipherDecryptor`] API:
//!
//! ```
//! use bouncycastle_aes::{AES_CTR_256, AES_CTR_256_Key};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherKey};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CTR_256<Encrypting>;
//! type AESDec = AES_CTR_256<Decrypting>;
//!
//! let key = AES_CTR_256_Key::new_from_os().expect("a fresh key");
//!
//! // An arbitrary plaintext to encrypt.
//! // Any length: a stream cipher does not need a whole number of blocks.
//! let plaintext = [0x5Au8; 47];
//!
//! // Encryption works in place. The nonce is generated for you and returned; there is no API for
//! // supplying one.
//! let mut data = plaintext;
//! let (_, nonce) = AESEnc::encrypt_inplace(&key, &mut data).expect("encryption");
//!
//! AESDec::decrypt_inplace(&key, &nonce, &mut data).expect("decryption");
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
//! use bouncycastle_aes::{AES_CTR_128, AES_CTR_128_Key};
//! use bouncycastle_core::traits::{
//!     StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
//!     SymmetricCipherEncryptor,
//!     SymmetricCipherKey,
//! };
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CTR_128<Encrypting>;
//! type AESDec = AES_CTR_128<Decrypting>;
//!
//! let key = AES_CTR_128_Key::new_from_os().expect("a fresh key");
//!
//! // An arbitrary plaintext to encrypt
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 7-byte pieces, each in place.
//! let (mut encryptor, nonce) = AESEnc::do_encrypt_init(&key).expect("encrypt init");
//! let mut ciphertext = plaintext;
//! for piece in ciphertext.chunks_mut(7) {
//!     encryptor.do_encrypt_inplace(piece).expect("encryption");
//! }
//!
//! // Decrypt in 19-byte pieces: the boundaries need not match the encryptor's.
//! let mut decryptor = AESDec::do_decrypt_init(&key, &nonce).expect("decrypt init");
//! let mut recovered = ciphertext;
//! for piece in recovered.chunks_mut(19) {
//!     decryptor.do_decrypt_inplace(piece).expect("decryption");
//! }
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::ctr`] apply.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Ctr;

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

/// The nonce length these aliases use, leaving a 4-byte counter.
pub const CTR_NONCE_LEN: usize = 12;

/// AES-128 in CTR mode with a 12-byte nonce.
#[allow(non_camel_case_types)]
pub type AES_CTR_128<Dir> =
    Ctr<AES128Internal, Dir, AES_CTR_128_Key, 16, AES_BLOCK_LEN, CTR_NONCE_LEN>;

/// An AES-CTR-128 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CTR_128_Key(KeyMaterial<16>);

impl SymmetricCipherKey<16> for AES_CTR_128_Key {
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

/// AES-192 in CTR mode with a 12-byte nonce.
#[allow(non_camel_case_types)]
pub type AES_CTR_192<Dir> =
    Ctr<AES192Internal, Dir, AES_CTR_192_Key, 24, AES_BLOCK_LEN, CTR_NONCE_LEN>;

/// An AES-CTR-192 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CTR_192_Key(KeyMaterial<24>);

impl SymmetricCipherKey<24> for AES_CTR_192_Key {
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

/// AES-256 in CTR mode with a 12-byte nonce. See [`AES_CTR_128`].
#[allow(non_camel_case_types)]
pub type AES_CTR_256<Dir> =
    Ctr<AES256Internal, Dir, AES_CTR_256_Key, 32, AES_BLOCK_LEN, CTR_NONCE_LEN>;

/// An AES-CTR-256 key.
#[derive(Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct AES_CTR_256_Key(KeyMaterial<32>);

impl SymmetricCipherKey<32> for AES_CTR_256_Key {
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
