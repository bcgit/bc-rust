//! The [`ElectronicCodeBook`] trait: a keyed block permutation.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyMaterial;
use crate::traits::Algorithm;

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

/// A keyed block permutation: the `CIPH_K` / `CIPH^-1_K` of NIST SP 800-38A Sec 5.1.
///
/// # 🚨 Security 🚨
/// A permutation applied to data block by block is ECB: equal plaintext blocks give equal
/// ciphertext blocks, so the structure of the plaintext survives. This is the primitive under
/// CBC, CTR, GCM and the rest of `bouncycastle-modes`, not a cipher for data; see the
/// [module docs](crate::hazmat) for the supported uses.
///
/// Implementors are expected to hold the key schedule in a zeroize-on-drop wrapper
/// (`bouncycastle_utils::secret::Secret`), so it is scrubbed when the value is dropped.
///
/// # Why the block methods are infallible
///
/// Every length here is fixed by a type, and a constructed value is always ready to use, so there
/// is nothing a caller can get wrong once [`ElectronicCodeBook::new`] has returned. Only `new` can
/// fail, and only because of the key.
pub trait ElectronicCodeBook<const KEY_LEN: usize, const BLOCK_LEN: usize>:
    Algorithm + Sized
{
    /// Expands the key.
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError>;

    /// Whether this permutation may be used to *apply* cryptographic protection, i.e. as the
    /// cipher of an encrypting mode.
    ///
    /// `true` for every current cipher. `false` marks a permutation kept only to process data that
    /// was protected in the past -- two-key TDEA, which NIST SP 800-131A Rev 2 Table 1 lists as
    /// "Disallowed" for encryption and "Legacy use" for decryption. A mode of operation checks this
    /// in an inline `const` when its `Encrypting` direction is constructed, so encrypting with such
    /// a permutation is a compile error at the call site, while its `Decrypting` direction is
    /// unaffected. The block methods themselves are not gated: a decrypting CFB or CTR needs the
    /// forward cipher function, and a raw permutation is not something to encrypt data with in any
    /// case (see the trait docs).
    const ENCRYPTION_APPROVED: bool = true;

    /// The forward cipher function, in place.
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// The inverse cipher function, in place.
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// The forward cipher function on two *independent* blocks, in place.
    ///
    /// Required, with no default, so that every implementor decides for itself how to run a pair.
    /// A bit-sliced engine whose natural unit is a pair (see `bouncycastle-aes`) runs both blocks
    /// in one pass for barely more than the cost of one; an engine with no unit wider than a block
    /// makes two [`ElectronicCodeBook::encrypt_block`] calls. A default of two single-block calls
    /// would be right only for the second kind, and silently wrong -- twice the work, with nothing
    /// failing -- for a wider engine that forgot to override it.
    ///
    /// Must be indistinguishable from two [`ElectronicCodeBook::encrypt_block`] calls, including
    /// the order of the two results. `TestFrameworkElectronicCodeBook` pins that.
    ///
    /// Modes whose structure is parallel -- CBC decryption, CFB decryption, CTR -- should prefer
    /// this. CBC and CFB *encryption* cannot use it: each input block depends on the previous
    /// output.
    fn encrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]);

    /// The inverse cipher function on two *independent* blocks, in place.
    /// See [`ElectronicCodeBook::encrypt_2blocks`].
    fn decrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]);

    /// The forward cipher function on four *independent* blocks, in place.
    ///
    /// Required for the same reason as [`ElectronicCodeBook::encrypt_2blocks`]. An engine whose
    /// natural unit is a pair runs the four as two pair calls; a bit-sliced engine whose S-box
    /// circuit substitutes four blocks per pass runs them as one full pass rather than two
    /// half-empty pair calls. Four is the unit because it is the widest any engine in this library
    /// fills: AES fills a pair, and the `u16`- and `u32`-plane engines (SM4, Camellia, ARIA) fill
    /// four.
    /// Must be indistinguishable from four [`ElectronicCodeBook::encrypt_block`] calls, including
    /// the order of the four results. `TestFrameworkElectronicCodeBook` pins that.
    ///
    /// Modes with parallel structure chunk their data into fours first, then pairs, then single
    /// blocks; see CBC decryption in `bouncycastle-modes`.
    fn encrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]);

    /// The inverse cipher function on four *independent* blocks, in place.
    /// See [`ElectronicCodeBook::encrypt_4blocks`].
    fn decrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]);
}
