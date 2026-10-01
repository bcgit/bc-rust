//! Type aliases for AES in CBC mode (NIST SP 800-38A §6.2), with padding.
//!
//! See [`bouncycastle_cipher::modes::cbc`] for details on the CipherBlockChaining construction.
//!
//! The aliases here are padded block ciphers that accept input of any size; `NoPadding` accepts
//! only whole blocks but goes through the same adapter. The unpadded mode underneath them, which
//! implements the block-cipher traits directly, is [`Cbc`] and is not re-exported from this crate.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! Basic usage can be obtained via the [`SymmetricCipherEncryptor`] and [`SymmetricCipherDecryptor`] API:
//!
//! ```
//! use bouncycastle_aes::AES_CBC_256;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_cipher::modes::{Decrypting, Encrypting};
//! use bouncycastle_cipher::padding::PKCS7;
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CBC_256<Encrypting, PKCS7>;
//! type AESDec = AES_CBC_256<Decrypting, PKCS7>;
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//!
//! // An arbitrary plaintext to encrypt
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // The IV is generated for you and returned; there is no API for supplying one.
//! let (iv, ciphertext) = AESEnc::encrypt(&key, &plaintext).expect("encryption");
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! let recovered = AESDec::decrypt(&key, &iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the following APIs can be used:
//!
//! ```
//! use bouncycastle_aes::{AES_CBC_128, AES_BLOCK_LEN};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_cipher::modes::{Decrypting, Encrypting};
//! use bouncycastle_cipher::padding::PKCS7;
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_CBC_128<Encrypting, PKCS7>;
//! type AESDec = AES_CBC_128<Decrypting, PKCS7>;
//!
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // An arbitrary plaintext to encrypt
//! let plaintext = [0x5Au8; 50];
//!
//! // The streaming (chunked) API allows for data to be handed to the cipher as it arrives, in chunks
//! // of any length, but it will only be processed once a full block has been received.
//! // Here, we will use 7-byte chunks
//! let (mut encryptor, iv) = AESEnc::do_encrypt_init(&key).expect("encrypt init");
//!
//! let mut ciphertext = Vec::new();
//!
//! for piece in plaintext.chunks(7) {
//!     // Since AES
//!     let mut out = [0u8; AES_BLOCK_LEN];
//!     let bytes_written = encryptor.do_encrypt_out(piece, &mut out).expect("encryption");
//!
//!     // If that doesn't complete a block, then nothing is written.
//!     if bytes_written != 0 {
//!         ciphertext.extend_from_slice(&out[..bytes_written]);
//!     }
//! }
//! let (last_block, last_len) = encryptor.do_final().expect("padding the final block");
//! ciphertext.extend_from_slice(&last_block[..last_len]);
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! // Decrypt the ciphertext in 19-byte chunks.
//! let mut decryptor = AESDec::do_decrypt_init(&key, &iv).expect("decrypt init");
//! let mut recovered = Vec::new();
//! for piece in ciphertext.chunks(19) {
//!     let mut out = [0u8; AES_BLOCK_LEN];
//!     let bytes_written = decryptor.do_decrypt_out(piece, &mut out).expect("decryption");
//!     if bytes_written != 0 {
//!         recovered.extend_from_slice(&out[..bytes_written]);
//!     }
//! }
//! let (last_block, last_len) = decryptor.do_final().expect("a valid final block");
//! recovered.extend_from_slice(&last_block[..last_len]);
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## With no padding scheme
//!
//! With [`NoPadding`] nothing is added, and a message that is not a whole number of blocks is an
//! error at `do_final` rather than something silently padded:
//!
//! ```
//! use bouncycastle_aes::AES_CBC_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::SymmetricCipherEncryptor;
//! use bouncycastle_cipher::modes::Encrypting;
//! use bouncycastle_cipher::padding::NoPadding;
//!
//! // Define ourselves a convenience type for the encryption direction with no padding.
//! type Enc = AES_CBC_128<Encrypting, NoPadding>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // A whole block is fine, and comes out the same length.
//! let mut out = [0u8; 16];
//! let (_iv, written) = Enc::encrypt_out(&key, &[0u8; 16], &mut out).expect("aligned");
//! assert_eq!(written, 16);
//!
//! // Five bytes is not, and is refused rather than padded.
//! let mut out = [0u8; 16];
//! assert!(Enc::encrypt_out(&key, b"hello", &mut out).is_err());
//! ```
//!
//! The padding scheme is part of the type, so the two schemes are different types and cannot be
//! interchanged. A value built with one will not satisfy a binding annotated with the other.
//!
//! ```compile_fail
//! use bouncycastle_aes::AES_CBC_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::SymmetricCipherEncryptor;
//! use bouncycastle_cipher::modes::Encrypting;
//! use bouncycastle_cipher::padding::{NoPadding, PKCS7};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // Built as NoPadding, annotated as PKCS7: mismatched types.
//! let (enc, _iv) = AES_CBC_128::<Encrypting, NoPadding>::do_encrypt_init(&key).unwrap();
//! let _mismatched: AES_CBC_128<Encrypting, PKCS7> = enc;
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::cbc`] apply.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::{Cbc, Decrypting, Encrypting};
use bouncycastle_cipher::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_core::stream_cipher::Direction;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::modes::cbc;
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
// end of imports needed for docs

/// AES-128 in CBC mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_CBC_128<Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<AES128Internal, Encrypting, 16, AES_BLOCK_LEN>,
        Pad,
        16,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<AES128Internal, Decrypting, 16, AES_BLOCK_LEN>,
        Pad,
        16,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
>;

/// AES-192 in CBC mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_CBC_192<Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<AES192Internal, Encrypting, 24, AES_BLOCK_LEN>,
        Pad,
        24,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<AES192Internal, Decrypting, 24, AES_BLOCK_LEN>,
        Pad,
        24,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
>;

/// AES-256 in CBC mode with a padding scheme. See [`AES_CBC_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_256<Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<AES256Internal, Encrypting, 32, AES_BLOCK_LEN>,
        Pad,
        32,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<AES256Internal, Decrypting, 32, AES_BLOCK_LEN>,
        Pad,
        32,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
>;
