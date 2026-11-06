//! The [`BlockPermutation`] trait, a keyed block permutation, and [`ElectronicCodeBook`], which
//! adds its construction from key material.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyMaterial;
use crate::traits::Algorithm;

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

/// A keyed block permutation: the `CIPH_K` / `CIPH^-1_K` of NIST SP 800-38A Sec 5.1, already
/// keyed. A key object builds it through [`ElectronicCodeBook::new`]; the modes in
/// `bouncycastle_cipher::modes` bound on this trait alone.
///
/// # 🚨 Security Considerations 🚨
/// A permutation applied to data block by block is ECB: equal plaintext blocks give equal
/// ciphertext blocks, so the structure of the plaintext survives. This is the primitive under
/// CBC, CTR, GCM and the rest of `bouncycastle_cipher::modes`, not a cipher for data; see the
/// [module docs](crate::hazmat) for the supported uses.
///
/// Implementors are expected to hold the key schedule in a zeroize-on-drop wrapper
/// (`bouncycastle_utils::secret::Secret`), so it is scrubbed when the value is dropped.
///
/// # Why the block methods are infallible
///
/// Every length here is fixed by a type, and a constructed value is always ready to use, so there
/// is nothing a caller can get wrong once [`ElectronicCodeBook::new`] has returned; that
/// constructor is the one fallible step, and only because of the key.
pub trait BlockPermutation<const BLOCK_LEN: usize>: Algorithm + Sized {
    /// The forward cipher function, in place.
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// The inverse cipher function, in place.
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// Whether this library allows the permutation to decrypt only: no encrypting worker may be
    /// made over it, by a key's `create_encryptor` or by any other constructor of one, a key
    /// wrapper included. A mode checks this in an inline `const` in every such constructor, so
    /// the refusal is a compile error (reported after monomorphization, so by `cargo build` or
    /// `cargo test` rather than `cargo check`).
    ///
    /// This records the library's policy, not a standard's status. It is `true` for two-key TDEA
    /// alone, which NIST SP 800-131A Rev 2 Table 1 lists as "Disallowed" for encryption and
    /// "Legacy use" for decryption, and whose key wrapping its Table 6 lists as "Disallowed"
    /// too. Three-key TDEA encryption, which Table 1 disallows
    /// after 2023, keeps `false` because the OpenSSL provider this library serves still exposes
    /// it; the tdes crate's Security Considerations say so.
    ///
    /// The block methods themselves are not gated: a decrypting CFB or CTR needs the forward
    /// cipher function, and a raw permutation is not something to encrypt data with in any case
    /// (see the trait docs). Those decryptors are therefore an encryption capability in a
    /// determined caller's hands, which the tdes crate's docs spell out.
    const DECRYPT_ONLY: bool = false;

    /// The forward cipher function on two *independent* blocks, in place.
    ///
    /// Required, with no default, so that every implementor decides for itself how to run a pair.
    /// A bit-sliced engine whose natural unit is a pair (see `bouncycastle-aes`) runs both blocks
    /// in one pass for barely more than the cost of one; an engine with no unit wider than a block
    /// makes two [`BlockPermutation::encrypt_block`] calls. A default of two single-block calls
    /// would be right only for the second kind, and silently wrong -- twice the work, with nothing
    /// failing -- for a wider engine that forgot to override it.
    ///
    /// Must be indistinguishable from two [`BlockPermutation::encrypt_block`] calls, including
    /// the order of the two results. `TestFrameworkElectronicCodeBook` pins that.
    ///
    /// Modes whose structure is parallel -- CBC decryption, CFB decryption, CTR -- should prefer
    /// this. CBC and CFB *encryption* cannot use it: each input block depends on the previous
    /// output.
    fn encrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]);

    /// The inverse cipher function on two *independent* blocks, in place.
    /// See [`BlockPermutation::encrypt_2blocks`].
    fn decrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]);

    /// The forward cipher function on four *independent* blocks, in place.
    ///
    /// Required for the same reason as [`BlockPermutation::encrypt_2blocks`]. An engine whose
    /// natural unit is a pair runs the four as two pair calls; a bit-sliced engine whose S-box
    /// circuit substitutes four blocks per pass runs them as one full pass rather than two
    /// half-empty pair calls. Four is the unit because it is the widest any engine in this library
    /// fills: AES fills a pair, and the `u16`- and `u32`-plane engines (SM4, Camellia, ARIA) fill
    /// four.
    /// Must be indistinguishable from four [`BlockPermutation::encrypt_block`] calls, including
    /// the order of the four results. `TestFrameworkElectronicCodeBook` pins that.
    ///
    /// Modes with parallel structure chunk their data into fours first, then pairs, then single
    /// blocks; see CBC decryption in `bouncycastle_cipher::modes`.
    fn encrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]);

    /// The inverse cipher function on four *independent* blocks, in place.
    /// See [`BlockPermutation::encrypt_4blocks`].
    fn decrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]);
}

/// A [`BlockPermutation`] that can be built from `KEY_LEN` bytes of key material: what a key
/// object does once, when it is made.
pub trait ElectronicCodeBook<const KEY_LEN: usize, const BLOCK_LEN: usize>:
    BlockPermutation<BLOCK_LEN>
{
    /// Expands the key.
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError>;
}
