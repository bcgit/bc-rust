//! Toy [`BlockPermutation`] implementations, for testing the mode independently of any real cipher.
//!
//! These are **not** cryptography. They exist so the structural properties of a mode -- chaining,
//! sequencing, the pair/remainder split, direction typing -- can be tested without an AES
//! dependency and without a real cipher's vectors getting in the way. The real known-answer tests
//! are in `sp800_38a_tests.rs`.
//!
//! # Why not XOR
//!
//! The obvious toy, `block[i] ^= key[i]`, is its own inverse. That would make `encrypt_block` and
//! `decrypt_block` the same function, which hides exactly the bugs these tests are for: a CBC
//! decryptor that called the forward function, or an encryptor that called the inverse, would still
//! round-trip. [`Toy`] is therefore asymmetric: it rotates before XOR-ing, so the two directions are
//! genuinely different functions.

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, BlockPermutation, SecurityStrength};

/// Block and key length of the toy ciphers, chosen to match AES so the tests exercise the same
/// shapes the real thing will.
pub const TOY_LEN: usize = 16;

/// Shared key validation, so the toys reject the same keys a real permutation would and the
/// framework's key-handling checks are meaningful.
fn validate(key: &dyn KeyMaterialTrait) -> Result<(), SymmetricCipherError> {
    if key.key_type() != KeyType::SymmetricCipherKey {
        return Err(
            KeyMaterialError::InvalidKeyType("toy cipher needs a SymmetricCipherKey").into()
        );
    }
    if key.key_len() != TOY_LEN {
        return Err(KeyMaterialError::InvalidLength.into());
    }
    if key.security_strength() < SecurityStrength::_128bit {
        return Err(KeyMaterialError::SecurityStrength("toy cipher needs a 128-bit key").into());
    }
    Ok(())
}

/// An asymmetric toy permutation: `encrypt` is `rotate_left(1)` then XOR with the key byte.
///
/// A true permutation on each byte, so it is a true permutation on the block, and its inverse is
/// distinctly different code (XOR then `rotate_right(1)`).
pub struct Toy {
    key: [u8; TOY_LEN],
}

impl Algorithm for Toy {
    const ALG_NAME: &'static str = "Toy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl BlockPermutation<TOY_LEN, TOY_LEN> for Toy {
    fn new(key: &KeyMaterial<TOY_LEN>) -> Result<Self, SymmetricCipherError> {
        validate(key)?;
        let mut bytes = [0u8; TOY_LEN];
        bytes.copy_from_slice(key.ref_to_bytes());
        Ok(Self { key: bytes })
    }

    fn encrypt_block(&self, block: &mut [u8; TOY_LEN]) {
        for (b, k) in block.iter_mut().zip(self.key.iter()) {
            *b = b.rotate_left(1) ^ *k;
        }
    }

    fn decrypt_block(&self, block: &mut [u8; TOY_LEN]) {
        for (b, k) in block.iter_mut().zip(self.key.iter()) {
            *b = (*b ^ *k).rotate_right(1);
        }
    }
}

/// A deliberately broken toy whose pair methods **swap** their two results.
///
/// Used to prove that the mode really does take the pair path: with this permutation, a CBC
/// decryptor that uses `decrypt_blocks2` must produce something other than the correct plaintext.
/// If a test using this still round-trips, the pair path is dead code and the coverage claimed for
/// it is false.
///
/// Its single-block methods are identical to [`Toy`]'s, so the two agree on odd-length input.
pub struct SwappedPairToy {
    inner: Toy,
}

impl Algorithm for SwappedPairToy {
    const ALG_NAME: &'static str = "SwappedPairToy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl BlockPermutation<TOY_LEN, TOY_LEN> for SwappedPairToy {
    fn new(key: &KeyMaterial<TOY_LEN>) -> Result<Self, SymmetricCipherError> {
        Ok(Self { inner: Toy::new(key)? })
    }

    fn encrypt_block(&self, block: &mut [u8; TOY_LEN]) {
        self.inner.encrypt_block(block);
    }

    fn decrypt_block(&self, block: &mut [u8; TOY_LEN]) {
        self.inner.decrypt_block(block);
    }

    fn encrypt_blocks2(&self, blocks: &mut [[u8; TOY_LEN]; 2]) {
        self.inner.encrypt_block(&mut blocks[0]);
        self.inner.encrypt_block(&mut blocks[1]);
        blocks.swap(0, 1);
    }

    fn decrypt_blocks2(&self, blocks: &mut [[u8; TOY_LEN]; 2]) {
        self.inner.decrypt_block(&mut blocks[0]);
        self.inner.decrypt_block(&mut blocks[1]);
        blocks.swap(0, 1);
    }
}

/// Builds a `KeyMaterial` for the toys from a fixed non-zero pattern.
pub fn toy_key() -> KeyMaterial<TOY_LEN> {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid toy key")
}
