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
//! use bouncycastle_aes::AES_CTR_256;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CTR_256<Encrypting>;
//! type AESDec = AES_CTR_256<Decrypting>;
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//!
//! // An arbitrary plaintext to encrypt.
//! // Any length: a stream cipher does not need a whole number of blocks.
//! let plaintext = [0x5Au8; 47];
//!
//! // Encryption works in place. The nonce is generated for you and returned; there is no API for
//! // supplying one.
//! let mut data = plaintext;
//! let (_, nonce) = AESEnc::encrypt_in_place(&key, &mut data).expect("encryption");
//!
//! AESDec::decrypt_in_place(&key, &nonce, &mut data).expect("decryption");
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
//! use bouncycastle_aes::AES_CTR_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{
//!     StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
//!     SymmetricCipherEncryptor,
//! };
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CTR_128<Encrypting>;
//! type AESDec = AES_CTR_128<Decrypting>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // An arbitrary plaintext to encrypt
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 7-byte pieces, each in place.
//! let (mut encryptor, nonce) = AESEnc::do_encrypt_init(&key).expect("encrypt init");
//! let mut ciphertext = plaintext;
//! for piece in ciphertext.chunks_mut(7) {
//!     encryptor.do_encrypt(piece).expect("encryption");
//! }
//!
//! // Decrypt in 19-byte pieces: the boundaries need not match the encryptor's.
//! let mut decryptor = AESDec::do_decrypt_init(&key, &nonce).expect("decrypt init");
//! let mut recovered = ciphertext;
//! for piece in recovered.chunks_mut(19) {
//!     decryptor.do_decrypt(piece).expect("decryption");
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
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
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
