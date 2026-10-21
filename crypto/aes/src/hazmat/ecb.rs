//! Type aliases for AES in ECB mode (NIST SP 800-38A Sec 6.1), with padding.
//!
//! **🚨 Security note: 🚨 ECB is not a confidentiality mode for data.** That is why these are
//! under [`hazmat`](crate::hazmat); see [`bouncycastle_core::hazmat`] for the supported uses.
//!
//! See [`bouncycastle_cipher::modes::hazmat::Ecb`] for details on the ElectronicCodebook construction.
//!
//! The aliases here name the padded workers, which accept input of any size; `NoPadding` accepts
//! only whole blocks but goes through the same adapter. The unpadded mode underneath them, which
//! implements the block-cipher traits directly, is [`Ecb`] and is not re-exported from this crate.
//! The workers come from a key: [`AES128Key<ECB<PKCS7>>`](crate::AES128Key) (or `ECB<NoPadding>`)
//! hands them out through the [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair, and
//! `AES128Key<ECB<Blocks>>` hands out [`Ecb`] itself through the [`EcbEncryptionKey`] /
//! [`EcbDecryptionKey`] pair.
//!
//! ECB has no IV, so its `INIT_DATA_LEN` is 0: the padded pair's encryption returns an empty
//! array, its decryption takes one, and the ciphertext is exactly the padded plaintext with
//! nothing prepended. The RNG that pair's `create_encryptor` and one-shots take is never drawn
//! from, and the `ECB<Blocks>` pair takes none at all.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::hazmat::ECB;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<ECB<PKCS7>>::from_key_material(&material).expect("a valid AES-256 key");
//!
//! // Any length: PKCS#7 pads it out to whole blocks, so 50 bytes is as good as 48.
//! let plaintext = [0x5Au8; 50];
//!
//! // ECB has no IV, so the init data that comes back is empty.
//! let (no_iv, ciphertext) = key.encrypt(&mut rng, &plaintext).expect("encryption");
//! assert_eq!(no_iv, [0u8; 0]);
//! assert_eq!(ciphertext.len(), 64, "50 bytes padded out to four blocks");
//!
//! let recovered = key.decrypt(&no_iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the workers' streaming methods can be used:
//!
//! ```
//! use bouncycastle_aes::{AES128Key, AES_BLOCK_LEN};
//! use bouncycastle_cipher::modes::hazmat::ECB;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = AES128Key::<ECB<PKCS7>>::from_key_material(&material).expect("a valid AES-128 key");
//!
//! let plaintext = [0x5Au8; 50];
//!
//! // Data can be handed to the encryptor as it arrives, in pieces of any length, but a block is
//! // only written out once it is complete. Here, 7-byte pieces.
//! let (mut encryptor, no_iv) = key.create_encryptor(&mut rng).expect("nothing is drawn");
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
//! let mut decryptor = key.create_decryptor(&no_iv);
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
//! error rather than something silently padded:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::hazmat::ECB;
//! use bouncycastle_cipher::padding::NoPadding;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AES128Key::<ECB<NoPadding>>::from_key_material(&material).unwrap();
//!
//! // A whole block is fine, and comes out the same length.
//! let mut out = [0u8; 16];
//! let (written, _no_iv) = key.encrypt_out(&mut rng, &[0u8; 16], &mut out).expect("aligned");
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
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_aes::hazmat::AES_ECB_128;
//! use bouncycastle_cipher::Encrypting;
//! use bouncycastle_cipher::modes::hazmat::ECB;
//! use bouncycastle_cipher::padding::{NoPadding, PKCS7};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AES128Key::<ECB<NoPadding>>::from_key_material(&material).unwrap();
//!
//! // Built from a NoPadding key, annotated as PKCS7: mismatched types.
//! let (enc, _no_iv) = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
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
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::Blocks;
//! use bouncycastle_cipher::modes::hazmat::ECB;
//! use bouncycastle_core::hazmat::EcbEncryptionKey;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::FromKeyMaterial;
//!
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AES128Key::<ECB<Blocks>>::from_key_material(&material).unwrap();
//!
//! // Two identical blocks in...
//! let mut blocks = [0x5Au8; 32];
//! key.encrypt_inplace(&mut blocks).expect("encryption");
//! // ...two identical blocks out. Nothing here chains, so nothing hides the repetition.
//! assert_eq!(blocks[..16], blocks[16..]);
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
use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle_core::key_material::KeyMaterial;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::hazmat::{EcbDecryptionKey, EcbEncryptionKey};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// AES-128 in ECB mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_ECB_128<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Ecb<'k, AES128Internal, Encrypting, AES_BLOCK_LEN>,
        Pad,
        0,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Ecb<'k, AES128Internal, Decrypting, AES_BLOCK_LEN>,
        Pad,
        0,
        AES_BLOCK_LEN,
    >,
>;

/// AES-192 in ECB mode with a padding scheme.
#[allow(non_camel_case_types)]
pub type AES_ECB_192<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Ecb<'k, AES192Internal, Encrypting, AES_BLOCK_LEN>,
        Pad,
        0,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Ecb<'k, AES192Internal, Decrypting, AES_BLOCK_LEN>,
        Pad,
        0,
        AES_BLOCK_LEN,
    >,
>;

/// AES-256 in ECB mode with a padding scheme. See [`AES_ECB_128`].
#[allow(non_camel_case_types)]
pub type AES_ECB_256<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Ecb<'k, AES256Internal, Encrypting, AES_BLOCK_LEN>,
        Pad,
        0,
        AES_BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Ecb<'k, AES256Internal, Decrypting, AES_BLOCK_LEN>,
        Pad,
        0,
        AES_BLOCK_LEN,
    >,
>;

impl ElectronicCodeBook<16, AES_BLOCK_LEN> for AES128Internal {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        AES128Internal::new(key)
    }
}

impl BlockPermutation<AES_BLOCK_LEN> for AES128Internal {
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
}

impl BlockPermutation<AES_BLOCK_LEN> for AES192Internal {
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
}

impl BlockPermutation<AES_BLOCK_LEN> for AES256Internal {
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
