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
//! use bouncycastle_aes::AES_CFB_256;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CFB_256<Encrypting>;
//! type AESDec = AES_CFB_256<Decrypting>;
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
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
//! use bouncycastle_aes::AES_CFB_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{
//!     StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
//!     SymmetricCipherEncryptor,
//! };
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CFB_128<Encrypting>;
//! type AESDec = AES_CFB_128<Decrypting>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
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

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
// end of imports needed for docs

/// AES-128 in CFB128 mode.
#[allow(non_camel_case_types)]
pub type AES_CFB_128<Dir> = Cfb<AES128Internal, Dir, 16, AES_BLOCK_LEN>;

/// AES-192 in CFB128 mode.
#[allow(non_camel_case_types)]
pub type AES_CFB_192<Dir> = Cfb<AES192Internal, Dir, 24, AES_BLOCK_LEN>;

/// AES-256 in CFB128 mode. See [`AES_CFB_128`].
#[allow(non_camel_case_types)]
pub type AES_CFB_256<Dir> = Cfb<AES256Internal, Dir, 32, AES_BLOCK_LEN>;
