//! Type aliases for AES in CFB8 mode (NIST SP 800-38A Sec 6.3, `s = 8`).
//!
//! See [`bouncycastle_cipher::modes::cfb8`] for details on the CipherFeedback construction with an 8-bit segment.
//!
//! The aliases here are stream ciphers: the data is a `&mut [u8]` of any length, encrypted or
//! decrypted in-place since the ciphertext is exactly as long as the plaintext. They come from a
//! key, [`AES128Key<CFB8>`](crate::AES128Key) and friends, through the [`SymmetricEncryptionKey`]
//! / [`SymmetricDecryptionKey`] pair. The IV is drawn from the caller's RNG by encryption and
//! returned; there is no API for supplying one. `Dir` is [`Encrypting`] or [`Decrypting`]; the
//! wrong direction is a compile error, not a runtime check.
//!
//! CFB8 is a **different, non-interoperable mode** from CFB, not a variant of it: their
//! ciphertexts differ from the second byte, and it costs a full AES call per byte, sixteen times
//! the work of [`AES_CFB_128`](crate::AES_CFB_128). See [`bouncycastle_cipher::modes::cfb8`] for when
//! that is the right trade.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::CFB8;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<CFB8>::from_key_material(&material).expect("a valid AES-256 key");
//!
//! // 5 bytes: CFB8's segment is one byte, so any length at all is fine.
//! let plaintext = *b"hello";
//!
//! // Encryption works in place. The IV is drawn from `rng` and returned.
//! let mut data = plaintext;
//! let (_, iv) = key.encrypt_inplace(&mut rng, &mut data).expect("encryption");
//!
//! key.decrypt_inplace(&iv, &mut data).expect("decryption");
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
//! use bouncycastle_cipher::modes::CFB8;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = AES128Key::<CFB8>::from_key_material(&material).expect("a valid AES-128 key");
//!
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 3-byte pieces, each in place.
//! let (mut encryptor, iv) = key.create_encryptor(&mut rng).expect("IV draw");
//! let mut ciphertext = plaintext;
//! for piece in ciphertext.chunks_mut(3) {
//!     encryptor.do_encrypt_inplace(piece).expect("encryption");
//! }
//!
//! // Decrypt in 20-byte pieces: the boundaries need not match the encryptor's.
//! let mut decryptor = key.create_decryptor(&iv);
//! let mut recovered = ciphertext;
//! for piece in recovered.chunks_mut(20) {
//!     decryptor.do_decrypt_inplace(piece).expect("decryption");
//! }
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## Not interoperable with CFB
//!
//! CFB and CFB8 are not interchangeable: the same key and IV give a different ciphertext, so
//! a message encrypted with one does not decrypt with the other.
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::{CFB, CFB8};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let cfb8_key = AES128Key::<CFB8>::from_key_material(&material).unwrap();
//! let cfb_key = AES128Key::<CFB>::from_key_material(&material).unwrap();
//! let plaintext = *b"hello";
//!
//! let mut data = plaintext;
//! let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut data).unwrap();
//!
//! // Decrypting CFB8 output as CFB128 does not recover the plaintext.
//! cfb_key.decrypt_inplace(&iv, &mut data).unwrap();
//! assert_ne!(data, plaintext);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::cfb8`] apply.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Cfb8;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// AES-128 in CFB8 mode.
#[allow(non_camel_case_types)]
pub type AES_CFB8_128<Dir> = Cfb8<AES128Internal, Dir, 16, AES_BLOCK_LEN>;

/// AES-192 in CFB8 mode.
#[allow(non_camel_case_types)]
pub type AES_CFB8_192<Dir> = Cfb8<AES192Internal, Dir, 24, AES_BLOCK_LEN>;

/// AES-256 in CFB8 mode. See [`AES_CFB8_128`].
#[allow(non_camel_case_types)]
pub type AES_CFB8_256<Dir> = Cfb8<AES256Internal, Dir, 32, AES_BLOCK_LEN>;
