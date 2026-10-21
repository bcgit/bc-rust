//! Type aliases for AES in CBC mode (NIST SP 800-38A §6.2), with padding.
//!
//! See [`bouncycastle_cipher::modes::cbc`] for details on the CipherBlockChaining construction.
//!
//! The aliases here name the padded workers, which accept input of any size; `NoPadding` accepts
//! only whole blocks but goes through the same adapter. The unpadded mode underneath them, which
//! implements the block-cipher traits directly, is [`Cbc`] and is not re-exported from this crate.
//! The workers come from a key: [`AES128Key<CBC<PKCS7>>`](crate::AES128Key) (or `CBC<NoPadding>`)
//! hands them out through the [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair, and
//! `AES128Key<CBC<Blocks>>` hands out [`Cbc`] itself through the block pair.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid AES-256 key");
//!
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // The IV is drawn from `rng` and returned; there is no API for supplying one.
//! let (iv, ciphertext) = key.encrypt(&mut rng, &plaintext).expect("encryption");
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the workers' streaming methods can be used:
//!
//! ```
//! use bouncycastle_aes::{AES128Key, AES_BLOCK_LEN};
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = AES128Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid AES-128 key");
//!
//! let plaintext = [0x5Au8; 50];
//!
//! // Data can be handed to the encryptor as it arrives, in pieces of any length, but a block is
//! // only written out once it is complete. Here, 7-byte pieces.
//! let (mut encryptor, iv) = key.create_encryptor(&mut rng).expect("IV draw");
//!
//! let mut ciphertext = Vec::new();
//! for piece in plaintext.chunks(7) {
//!     let mut out = [0u8; AES_BLOCK_LEN];
//!     let bytes_written = encryptor.do_encrypt_out(piece, &mut out).expect("encryption");
//!     // If that doesn't complete a block, then nothing is written.
//!     ciphertext.extend_from_slice(&out[..bytes_written]);
//! }
//! let (last_block, last_len) = encryptor.do_encrypt_final().expect("padding the final block");
//! ciphertext.extend_from_slice(&last_block[..last_len]);
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! // Decrypt the ciphertext in 19-byte pieces; the decryptor is infallible to set up.
//! let mut decryptor = key.create_decryptor(&iv);
//! let mut recovered = Vec::new();
//! for piece in ciphertext.chunks(19) {
//!     let mut out = [0u8; AES_BLOCK_LEN];
//!     let bytes_written = decryptor.do_decrypt_out(piece, &mut out).expect("decryption");
//!     recovered.extend_from_slice(&out[..bytes_written]);
//! }
//! let (last_block, last_len) = decryptor.do_decrypt_final().expect("a valid final block");
//! recovered.extend_from_slice(&last_block[..last_len]);
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## With no padding scheme
//!
//! With [`NoPadding`] nothing is added, and a message that is not a whole number of blocks is an
//! error at `do_encrypt_final` rather than something silently padded:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::NoPadding;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AES128Key::<CBC<NoPadding>>::from_key_material(&material).unwrap();
//!
//! // A whole block is fine, and comes out the same length.
//! let mut out = [0u8; 16];
//! let (written, _iv) = key.encrypt_out(&mut rng, &[0u8; 16], &mut out).expect("aligned");
//! assert_eq!(written, 16);
//!
//! // Five bytes is not, and is refused rather than padded.
//! assert!(key.encrypt_out(&mut rng, b"hello", &mut out).is_err());
//! ```
//!
//! The padding scheme is part of the key type, so the two schemes' workers are different types
//! and cannot be interchanged. A value built with one will not satisfy a binding annotated with
//! the other.
//!
//! ```compile_fail
//! use bouncycastle_aes::{AES_CBC_128, AES128Key};
//! use bouncycastle_cipher::Encrypting;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::{NoPadding, PKCS7};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AES128Key::<CBC<NoPadding>>::from_key_material(&material).unwrap();
//!
//! // Built from a NoPadding key, annotated as PKCS7: mismatched types.
//! let (enc, _iv) = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! let _mismatched: AES_CBC_128<Encrypting, PKCS7> = enc;
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::cbc`] apply.

use crate::AES_BLOCK_LEN;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::Cbc;
use bouncycastle_cipher::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::modes::cbc;
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// AES-128 in CBC mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_CBC_128<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, AES128Internal, Encrypting, AES_BLOCK_LEN>,
        Pad,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, AES128Internal, Decrypting, AES_BLOCK_LEN>,
        Pad,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
>;

/// AES-192 in CBC mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_CBC_192<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, AES192Internal, Encrypting, AES_BLOCK_LEN>,
        Pad,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, AES192Internal, Decrypting, AES_BLOCK_LEN>,
        Pad,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
>;

/// AES-256 in CBC mode with a padding scheme. See [`AES_CBC_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_256<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, AES256Internal, Encrypting, AES_BLOCK_LEN>,
        Pad,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, AES256Internal, Decrypting, AES_BLOCK_LEN>,
        Pad,
        AES_BLOCK_LEN,
        AES_BLOCK_LEN,
    >,
>;
