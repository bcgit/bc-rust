// A copy of `bouncycastle_core_test_framework::ToyBlockCipher` for this crate's doctests and tests:
// the deliberately insecure 16-byte-block permutation (each byte `rotate_left(1)` then XOR with
// the key byte; the inverse undoes both). **Never use it for anything but tests and examples.**
//
// Pulled in with `mod toy { include!("<path to this file>"); }` from doctests and unit tests, and
// with `#[path]` from integration tests, so it carries no inner attributes or `//!` docs.

use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;

/// Key and block length of [`ToyBlockCipher`]: the same as AES-128, so the toy exercises the same
/// shapes a real cipher would.
pub const TOY_BLOCK_LEN: usize = 16;

/// A per-byte, key-validating, insecure permutation with a 16-byte key and block. See the header
/// comment above, and the test framework's original, for what it is and is not good for.
#[derive(Clone)]
pub struct ToyBlockCipher {
    key: [u8; TOY_BLOCK_LEN],
}

impl Algorithm for ToyBlockCipher {
    const ALG_NAME: &'static str = "ToyBlockCipher";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl ModeNames for ToyBlockCipher {
    const CBC_ALG_NAME: &'static str = "ToyBlockCipher_CBC";
    const CCM_ALG_NAME: &'static str = "ToyBlockCipher_CCM";
    const CFB_ALG_NAME: &'static str = "ToyBlockCipher_CFB";
    const CFB8_ALG_NAME: &'static str = "ToyBlockCipher_CFB8";
    const CTR_ALG_NAME: &'static str = "ToyBlockCipher_CTR";
    const ECB_ALG_NAME: &'static str = "ToyBlockCipher_ECB";
    const GCM_ALG_NAME: &'static str = "ToyBlockCipher_GCM";
}

impl ElectronicCodeBook<TOY_BLOCK_LEN, TOY_BLOCK_LEN> for ToyBlockCipher {
    /// Rejects the same keys a real permutation would, so that key-policy checks are meaningful.
    fn new(key: &KeyMaterial<TOY_BLOCK_LEN>) -> Result<Self, SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "ToyBlockCipher needs a SymmetricCipherKey",
            )
            .into());
        }
        if key.key_len() != TOY_BLOCK_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.security_strength() < SecurityStrength::_128bit {
            return Err(
                KeyMaterialError::SecurityStrength("ToyBlockCipher needs a 128-bit key").into()
            );
        }
        let mut bytes = [0u8; TOY_BLOCK_LEN];
        bytes.copy_from_slice(key.ref_to_bytes());
        Ok(Self { key: bytes })
    }

    fn encrypt_block(&self, block: &mut [u8; TOY_BLOCK_LEN]) {
        for (b, k) in block.iter_mut().zip(self.key.iter()) {
            *b = b.rotate_left(1) ^ *k;
        }
    }

    fn decrypt_block(&self, block: &mut [u8; TOY_BLOCK_LEN]) {
        for (b, k) in block.iter_mut().zip(self.key.iter()) {
            *b = (*b ^ *k).rotate_right(1);
        }
    }

    fn encrypt_2blocks(&self, blocks: &mut [[u8; TOY_BLOCK_LEN]; 2]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }

    fn decrypt_2blocks(&self, blocks: &mut [[u8; TOY_BLOCK_LEN]; 2]) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }

    fn encrypt_4blocks(&self, blocks: &mut [[u8; TOY_BLOCK_LEN]; 4]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }

    fn decrypt_4blocks(&self, blocks: &mut [[u8; TOY_BLOCK_LEN]; 4]) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }
}
