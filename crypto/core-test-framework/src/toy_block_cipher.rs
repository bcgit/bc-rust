//! A deliberately insecure block "cipher" for exercising the code that is built on top of one.
//!
//! [`ToyBlockCipher`] implements [`ElectronicCodeBook`] with a 16-byte key and a 16-byte block, so
//! it slots in wherever AES-128 would, and it validates its key the way a real permutation does:
//! it wants a [`KeyType::SymmetricCipherKey`] of the right length and at least 128-bit strength.
//! That is what lets the conformance suites' key-policy checks run against it. Everything else
//! about it is chosen for testability, not security:
//!
//! * **Each byte is permuted on its own**, as `rotate_left(1)` then XOR with the corresponding key
//!   byte. A one-bit change in a block therefore moves exactly one bit of the output, one place to
//!   the left, in the same byte -- which makes a mode's error propagation exact arithmetic instead
//!   of a statistical claim about diffusion. The flip side is that anything that *depends* on
//!   diffusion (a "random bit errors" claim, a collision argument) cannot be shown with it.
//! * **Encryption and decryption are genuinely different functions.** The obvious toy,
//!   `block ^= key`, is its own inverse and would let a mode that called the wrong direction
//!   round-trip regardless. Here the inverse is XOR then `rotate_right(1)`, so a decryptor that
//!   used the forward function, or vice versa, produces the wrong answer.
//! * The batch methods are plain loops over the single-block ones, so a mode driven through them
//!   gets the same answer as one driven block by block.
//!
//! It exists so that a crate generic over a block cipher -- a mode of operation, say -- can have
//! runnable documentation examples and unit tests without depending on a real cipher crate, which
//! would be a dependency cycle when that cipher crate depends on the mode. **Never use it for
//! anything but tests and examples.** It is included in this crate's public API for the same
//! reason [`FixedSeedRNG`](crate::FixedSeedRNG) is: it is a test double, and this crate is only
//! ever a dev-dependency.

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;

/// Key and block length of [`ToyBlockCipher`]: the same as AES-128, so the toy exercises the same
/// shapes a real cipher would.
pub const TOY_BLOCK_LEN: usize = 16;

/// A per-byte, key-validating, insecure permutation with a 16-byte key and block. See the module
/// docs for what it is and is not good for.
#[derive(Clone)]
pub struct ToyBlockCipher {
    key: [u8; TOY_BLOCK_LEN],
}

impl Algorithm for ToyBlockCipher {
    const ALG_NAME: &'static str = "ToyBlockCipher";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
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
