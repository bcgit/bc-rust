//! Type aliases for AES in CTR mode (NIST SP 800-38A Sec 6.5).
//!
//! See [`bouncycastle_cipher::modes::ctr`] for details on the Counter construction.
//!
//! The aliases here are stream ciphers: the data is a `&mut [u8]` of any length, encrypted or
//! decrypted in place since ciphertext is exactly as long as the plaintext. They come from a key,
//! [`AES128Key<CTR>`](crate::AES128Key) and friends, through the [`SymmetricEncryptionKey`] /
//! [`SymmetricDecryptionKey`] pair. The nonce is drawn from the caller's RNG by encryption and
//! returned; there is no API for supplying one. `Dir` is [`Encrypting`] or [`Decrypting`]; the
//! wrong direction is a compile error, not a runtime check.
//!
//! # Nonce and counter length
//!
//! **The nonce length is 12 bytes, the counter is 4 bytes.**
//!
//! These aliases, and the key's mode `CTR` with its defaults, fix a **12-byte nonce**
//! ([`CTR_NONCE_LEN`]), leaving the remainder of each block to be a 4-byte counter. That allows
//! 2^32 blocks -- 64 GiB -- in one message, and past it the mode errors rather than repeating
//! the keystream. A shorter message limit in exchange for more nonce bits is available by naming
//! `CTR<13>`, `CTR<14>` or `CTR<15>` as the key's mode.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::CTR;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<CTR>::from_key_material(&material).expect("a valid AES-256 key");
//!
//! // Any length: a stream cipher does not need a whole number of blocks.
//! let plaintext = [0x5Au8; 47];
//!
//! // Encryption works in place. The nonce is drawn from `rng` and returned.
//! let mut data = plaintext;
//! let (_, nonce) = key.encrypt_inplace(&mut rng, &mut data).expect("encryption");
//!
//! key.decrypt_inplace(&nonce, &mut data).expect("decryption");
//! assert_eq!(data, plaintext);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the workers' streaming methods can be used. A stream cipher
//! processes every byte it is given, so nothing is held back between calls and the pieces can be
//! of any length:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::CTR;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = AES128Key::<CTR>::from_key_material(&material).expect("a valid AES-128 key");
//!
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 7-byte pieces, each in place.
//! let (mut encryptor, nonce) = key.create_encryptor(&mut rng).expect("nonce draw");
//! let mut ciphertext = plaintext;
//! for piece in ciphertext.chunks_mut(7) {
//!     encryptor.do_encrypt_inplace(piece).expect("encryption");
//! }
//!
//! // Decrypt in 19-byte pieces: the boundaries need not match the encryptor's.
//! let mut decryptor = key.create_decryptor(&nonce);
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

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// The nonce length these aliases use, leaving a 4-byte counter.
pub const CTR_NONCE_LEN: usize = 12;

/// AES-128 in CTR mode with a 12-byte nonce.
#[allow(non_camel_case_types)]
pub type AES_CTR_128<Dir> = Ctr<AES128Internal, Dir, 16, AES_BLOCK_LEN, CTR_NONCE_LEN>;

/// AES-192 in CTR mode with a 12-byte nonce.
#[allow(non_camel_case_types)]
pub type AES_CTR_192<Dir> = Ctr<AES192Internal, Dir, 24, AES_BLOCK_LEN, CTR_NONCE_LEN>;

/// AES-256 in CTR mode with a 12-byte nonce. See [`AES_CTR_128`].
#[allow(non_camel_case_types)]
pub type AES_CTR_256<Dir> = Ctr<AES256Internal, Dir, 32, AES_BLOCK_LEN, CTR_NONCE_LEN>;
