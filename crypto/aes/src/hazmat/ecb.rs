//! Type aliases for AES in ECB mode (NIST SP 800-38A Sec 6.1), with padding.
//!
//! **🚨 Security note: 🚨 ECB is not a confidentiality mode for data.** That is why these are
//! under [`hazmat`](crate::hazmat); see [`bouncycastle_core::hazmat`] for the supported uses.
//!
//! See [`bouncycastle_cipher::modes::hazmat::Ecb`] for details on the ElectronicCodebook construction.
//!
//! The aliases here are padded block ciphers that accept input of any size; `NoPadding` accepts
//! only whole blocks but goes through the same adapter. The unpadded mode underneath them, which
//! implements the block-cipher traits directly, is [`Ecb`] and is not re-exported from this crate.
//!
//! ECB has no IV, so its `INIT_DATA_LEN` is 0: encryption returns an empty array, decryption takes
//! one, and the ciphertext is exactly the padded plaintext with nothing prepended. The RNG-taking
//! constructors, `do_encrypt_init_rng` and `encrypt_rng_out`, panic, as
//! [`SymmetricCipherEncryptor::do_encrypt_init_rng`] requires of a cipher with no init data to
//! generate; use the plain `do_encrypt_init` / `encrypt_out`.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! Basic usage can be obtained via the [`SymmetricCipherEncryptor`] and [`SymmetricCipherDecryptor`] API:
//!
//! ```
//! use bouncycastle_aes::hazmat::AES_ECB_256;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_cipher::padding::PKCS7;
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_ECB_256<Encrypting, PKCS7>;
//! type AESDec = AES_ECB_256<Decrypting, PKCS7>;
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//!
//! // An arbitrary plaintext to encrypt
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // ECB has no IV, so the init data that comes back is empty.
//! let (no_iv, ciphertext) = AESEnc::encrypt(&key, &plaintext).expect("encryption");
//! assert_eq!(no_iv, [0u8; 0]);
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! let recovered = AESDec::decrypt(&key, &no_iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the following APIs can be used:
//!
//! ```
//! use bouncycastle_aes::AES_BLOCK_LEN;
//! use bouncycastle_aes::hazmat::AES_ECB_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_cipher::padding::PKCS7;
//!
//! // Define ourselves convenience types.
//! type AESEnc = AES_ECB_128<Encrypting, PKCS7>;
//! type AESDec = AES_ECB_128<Decrypting, PKCS7>;
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
//! let (mut encryptor, no_iv) = AESEnc::do_encrypt_init(&key).expect("encrypt init");
//!
//! let mut ciphertext = Vec::new();
//!
//! for piece in plaintext.chunks(7) {
//!     let mut out = [0u8; AES_BLOCK_LEN];
//!     let bytes_written = encryptor.do_encrypt_out(piece, &mut out).expect("encryption");
//!
//!     // If that doesn't complete a block, then nothing is written.
//!     if bytes_written != 0 {
//!         ciphertext.extend_from_slice(&out[..bytes_written]);
//!     }
//! }
//! let (last_block, last_len) = encryptor.do_encrypt_final().expect("padding the final block");
//! ciphertext.extend_from_slice(&last_block[..last_len]);
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! // Decrypt the ciphertext in 19-byte chunks.
//! let mut decryptor = AESDec::do_decrypt_init(&key, &no_iv).expect("decrypt init");
//! let mut recovered = Vec::new();
//! for piece in ciphertext.chunks(19) {
//!     let mut out = [0u8; AES_BLOCK_LEN];
//!     let bytes_written = decryptor.do_decrypt_out(piece, &mut out).expect("decryption");
//!     if bytes_written != 0 {
//!         recovered.extend_from_slice(&out[..bytes_written]);
//!     }
//! }
//! let (last_block, last_len) = decryptor.do_decrypt_final().expect("a valid final block");
//! recovered.extend_from_slice(&last_block[..last_len]);
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## With no padding scheme
//!
//! With [`NoPadding`] nothing is added, and a message that is not a whole number of blocks is an
//! error rather than something silently padded:
//!
//! ```
//! use bouncycastle_aes::hazmat::AES_ECB_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::SymmetricCipherEncryptor;
//! use bouncycastle_cipher::Encrypting;
//! use bouncycastle_cipher::padding::NoPadding;
//!
//! // Define ourselves a convenience type for the encryption direction with no padding.
//! type Enc = AES_ECB_128<Encrypting, NoPadding>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // A whole block is fine, and comes out the same length.
//! let mut out = [0u8; 16];
//! let (_no_iv, written) = Enc::encrypt_out(&key, &[0u8; 16], &mut out).expect("aligned");
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
//! use bouncycastle_aes::hazmat::AES_ECB_128;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::SymmetricCipherEncryptor;
//! use bouncycastle_cipher::Encrypting;
//! use bouncycastle_cipher::padding::{NoPadding, PKCS7};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // Built as NoPadding, annotated as PKCS7: mismatched types.
//! let (enc, _no_iv) = AES_ECB_128::<Encrypting, NoPadding>::do_encrypt_init(&key).unwrap();
//! let _mismatched: AES_ECB_128<Encrypting, PKCS7> = enc;
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::hazmat::Ecb`] apply. Above all, **ECB is not a
//! confidentiality mode for data**: under a given key every plaintext block maps to the same
//! ciphertext block, so the structure of the plaintext shows through, and padding does not change
//! that in the least. It makes ECB accept any length; it does not make it safe.
//!
//! ```
//! use bouncycastle_aes::hazmat::AES_ECB_128;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::SymmetricCipherEncryptor;
//! use bouncycastle_cipher::Encrypting;
//! use bouncycastle_cipher::padding::NoPadding;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//!
//! // Two identical blocks in...
//! let (_, ciphertext) =
//!     AES_ECB_128::<Encrypting, NoPadding>::encrypt(&key, &[0x5Au8; 32]).expect("encryption");
//! // ...two identical blocks out. Nothing here chains, so nothing hides the repetition.
//! assert_eq!(ciphertext[..16], ciphertext[16..]);
//! ```

use crate::AES_BLOCK_LEN;
use crate::AESParams;
use crate::bitslice::Block;
use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::hazmat::Ecb;
use bouncycastle_cipher::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
// end of imports needed for docs

/// AES-128 in ECB mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_ECB_128<Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Ecb<AES128Internal, Encrypting, 16, AES_BLOCK_LEN>,
        Pad,
        16,
        0,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Ecb<AES128Internal, Decrypting, 16, AES_BLOCK_LEN>,
        Pad,
        16,
        0,
        AES_BLOCK_LEN,
    >,
>;

/// AES-192 in ECB mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_ECB_192<Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Ecb<AES192Internal, Encrypting, 24, AES_BLOCK_LEN>,
        Pad,
        24,
        0,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Ecb<AES192Internal, Decrypting, 24, AES_BLOCK_LEN>,
        Pad,
        24,
        0,
        AES_BLOCK_LEN,
    >,
>;

/// AES-256 in ECB mode with a padding scheme. See [`AES_ECB_128`].
#[allow(non_camel_case_types)]
pub type AES_ECB_256<Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Ecb<AES256Internal, Encrypting, 32, AES_BLOCK_LEN>,
        Pad,
        32,
        0,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Ecb<AES256Internal, Decrypting, 32, AES_BLOCK_LEN>,
        Pad,
        32,
        0,
        AES_BLOCK_LEN,
    >,
>;

impl ElectronicCodeBook<16, AES_BLOCK_LEN> for AES128Internal {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        AES128Internal::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Self::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Self::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Self::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Self::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        Self::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        Self::decrypt_4blocks(self, blocks)
    }
}

impl ElectronicCodeBook<24, AES_BLOCK_LEN> for AES192Internal {
    fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        AES192Internal::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Self::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Self::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Self::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Self::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        Self::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        Self::decrypt_4blocks(self, blocks)
    }
}

impl ElectronicCodeBook<32, AES_BLOCK_LEN> for AES256Internal {
    fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        AES256Internal::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Self::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Self::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Self::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Self::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        Self::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        Self::decrypt_4blocks(self, blocks)
    }
}

impl<P: AESParams> core::fmt::Debug for AESInternal<P> {
    /// Prints the algorithm name only. The key schedule is secret and is never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(P::ALG_NAME)
    }
}
